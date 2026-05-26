/*
 *-----------------------------------------------------------
 * parallel_encrypt.cpp
 *-----------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Facultad de Ingenieria
 * Departamento de Ciencia de la Computacion
 * CC3086 Programacion de Microprocesadores - Ciclo 1 2026
 *
 * Laboratorio 10 - Sincronizacion con Variables de Condicion
 *
 * Descripcion:
 *   Encripta y desencripta archivos de forma paralela
 *   utilizando Pthreads, mutex y variables de condicion.
 *   Algoritmo: AES-256-CBC (OpenSSL EVP).
 *   Cada bloque del archivo se procesa independientemente
 *   con su propio IV, y la escritura ordenada se garantiza
 *   mediante variables de condicion.
 *-----------------------------------------------------------
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <chrono>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;
using namespace std::chrono;

// ============================================================
// Constantes
// ============================================================
// Tamano de bloque: 1 MB
// Justificacion: 1 MB ofrece un buen balance entre granularidad
// de paralelismo (suficientes bloques para distribuir entre hilos)
// y eficiencia (cada bloque es lo bastante grande para amortizar
// el overhead de creacion de contexto AES y sincronizacion).
// Bloques mas pequenos generarian demasiado overhead de sync;
// bloques mas grandes reducirian el paralelismo disponible.
static const size_t BLOCK_SIZE = 1048576; // 1 MB

// Numero magico para identificar nuestro formato de archivo
static const uint32_t MAGIC = 0x4B525942; // "KRYB" (Kirby)

// ============================================================
// Estructuras
// ============================================================

// Informacion de un bloque encriptado
struct EncryptedBlock {
    vector<unsigned char> iv;         // 16 bytes
    vector<unsigned char> ciphertext; // datos encriptados
    size_t originalSize;              // tamano original del bloque
};

// Datos compartidos entre hilos para encriptacion
struct EncryptSharedData {
    // Datos de entrada
    const vector<unsigned char>* fileData;
    size_t numBlocks;
    size_t blockSize;
    unsigned char key[32];

    // Resultados por bloque (cada hilo escribe su propio slot)
    vector<EncryptedBlock> results;

    // Sincronizacion para escritura ordenada
    pthread_mutex_t writeMutex;
    pthread_cond_t  writeCond;
    int nextBlockToWrite;
    ofstream* outFile;

    // Configuracion de hilos
    int numThreads;
};

// Datos compartidos entre hilos para desencriptacion
struct DecryptSharedData {
    // Bloques encriptados de entrada
    vector<EncryptedBlock>* encBlocks;
    unsigned char key[32];

    // Resultados desencriptados por bloque
    vector<vector<unsigned char>> results;

    // Sincronizacion para escritura ordenada
    pthread_mutex_t writeMutex;
    pthread_cond_t  writeCond;
    int nextBlockToWrite;
    ofstream* outFile;

    // Configuracion
    int numThreads;
    size_t numBlocks;
};

// Argumento individual para cada hilo
struct ThreadArg {
    int threadId;
    void* sharedData; // EncryptSharedData* o DecryptSharedData*
};

// ============================================================
// Funciones de encriptacion/desencriptacion de un solo bloque
// ============================================================

// Encripta un bloque de datos con AES-256-CBC
// Cada bloque tiene su propio IV generado aleatoriamente
bool encryptBlock(const unsigned char* plaintext, size_t plainLen,
                  const unsigned char* key,
                  unsigned char* ivOut,
                  vector<unsigned char>& cipherOut)
{
    // Generar IV aleatorio para este bloque
    if (!RAND_bytes(ivOut, 16)) {
        cerr << "Error generando IV" << endl;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, ivOut) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    cipherOut.resize(plainLen + EVP_MAX_BLOCK_LENGTH);
    int len = 0, totalLen = 0;

    if (EVP_EncryptUpdate(ctx, cipherOut.data(), &len,
                          plaintext, plainLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    totalLen = len;

    if (EVP_EncryptFinal_ex(ctx, cipherOut.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    totalLen += len;

    cipherOut.resize(totalLen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Desencripta un bloque de datos con AES-256-CBC
bool decryptBlock(const unsigned char* ciphertext, size_t cipherLen,
                  const unsigned char* key, const unsigned char* iv,
                  vector<unsigned char>& plainOut)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    plainOut.resize(cipherLen + EVP_MAX_BLOCK_LENGTH);
    int len = 0, totalLen = 0;

    if (EVP_DecryptUpdate(ctx, plainOut.data(), &len,
                          ciphertext, cipherLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    totalLen = len;

    if (EVP_DecryptFinal_ex(ctx, plainOut.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    totalLen += len;

    plainOut.resize(totalLen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// ============================================================
// Funciones de hilos
// ============================================================

// Hilo de encriptacion
// Cada hilo procesa los bloques que le corresponden (distribucion ciclica)
// Despues de encriptar cada bloque, espera su turno para escribir en orden
void* encryptThread(void* arg) {
    ThreadArg* targ = (ThreadArg*)arg;
    EncryptSharedData* shared = (EncryptSharedData*)targ->sharedData;
    int tid = targ->threadId;

    // Distribucion ciclica: hilo 0 toma bloques 0, N, 2N, ...
    // hilo 1 toma bloques 1, N+1, 2N+1, ...
    for (size_t b = tid; b < shared->numBlocks; b += shared->numThreads) {
        // Calcular offset y tamano de este bloque
        size_t offset = b * shared->blockSize;
        size_t thisBlockSize = shared->blockSize;
        if (offset + thisBlockSize > shared->fileData->size()) {
            thisBlockSize = shared->fileData->size() - offset;
        }

        // Encriptar el bloque
        EncryptedBlock& result = shared->results[b];
        result.iv.resize(16);
        result.originalSize = thisBlockSize;

        bool ok = encryptBlock(
            shared->fileData->data() + offset, thisBlockSize,
            shared->key,
            result.iv.data(),
            result.ciphertext
        );

        if (!ok) {
            cerr << "Error encriptando bloque " << b << endl;
            continue;
        }

        // --- ESCRITURA ORDENADA CON VARIABLE DE CONDICION ---
        // Esperar hasta que sea nuestro turno de escribir
        pthread_mutex_lock(&shared->writeMutex);

        // Mientras no sea mi turno, espero en la variable de condicion
        while (shared->nextBlockToWrite != (int)b) {
            pthread_cond_wait(&shared->writeCond, &shared->writeMutex);
        }

        // Es mi turno: escribir este bloque al archivo
        uint32_t origSize = (uint32_t)result.originalSize;
        uint32_t encSize  = (uint32_t)result.ciphertext.size();

        shared->outFile->write((char*)&origSize, sizeof(origSize));
        shared->outFile->write((char*)&encSize, sizeof(encSize));
        shared->outFile->write((char*)result.iv.data(), 16);
        shared->outFile->write((char*)result.ciphertext.data(), encSize);

        // Avanzar al siguiente bloque y notificar a todos
        shared->nextBlockToWrite++;
        pthread_cond_broadcast(&shared->writeCond);
        pthread_mutex_unlock(&shared->writeMutex);
    }

    return nullptr;
}

// Hilo de desencriptacion
void* decryptThread(void* arg) {
    ThreadArg* targ = (ThreadArg*)arg;
    DecryptSharedData* shared = (DecryptSharedData*)targ->sharedData;
    int tid = targ->threadId;

    for (size_t b = tid; b < shared->numBlocks; b += shared->numThreads) {
        EncryptedBlock& enc = (*shared->encBlocks)[b];

        // Desencriptar el bloque
        bool ok = decryptBlock(
            enc.ciphertext.data(), enc.ciphertext.size(),
            shared->key, enc.iv.data(),
            shared->results[b]
        );

        if (!ok) {
            cerr << "Error desencriptando bloque " << b << endl;
            continue;
        }

        // --- ESCRITURA ORDENADA CON VARIABLE DE CONDICION ---
        pthread_mutex_lock(&shared->writeMutex);

        while (shared->nextBlockToWrite != (int)b) {
            pthread_cond_wait(&shared->writeCond, &shared->writeMutex);
        }

        // Escribir bloque desencriptado al archivo de salida
        shared->outFile->write(
            (char*)shared->results[b].data(),
            shared->results[b].size()
        );

        shared->nextBlockToWrite++;
        pthread_cond_broadcast(&shared->writeCond);
        pthread_mutex_unlock(&shared->writeMutex);
    }

    return nullptr;
}

// ============================================================
// Encriptacion secuencial (para comparacion de tiempos)
// ============================================================
double encryptSequential(const vector<unsigned char>& fileData,
                         const unsigned char* key,
                         const char* outputPath)
{
    auto start = high_resolution_clock::now();

    size_t numBlocks = (fileData.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;

    ofstream outFile(outputPath, ios::binary);
    uint32_t magic = MAGIC;
    uint32_t nBlocks = (uint32_t)numBlocks;
    uint32_t totalSize = (uint32_t)fileData.size();
    outFile.write((char*)&magic, sizeof(magic));
    outFile.write((char*)&nBlocks, sizeof(nBlocks));
    outFile.write((char*)&totalSize, sizeof(totalSize));

    for (size_t b = 0; b < numBlocks; b++) {
        size_t offset = b * BLOCK_SIZE;
        size_t thisBlockSize = BLOCK_SIZE;
        if (offset + thisBlockSize > fileData.size())
            thisBlockSize = fileData.size() - offset;

        unsigned char iv[16];
        vector<unsigned char> ciphertext;
        encryptBlock(fileData.data() + offset, thisBlockSize, key, iv, ciphertext);

        uint32_t origSize = (uint32_t)thisBlockSize;
        uint32_t encSize  = (uint32_t)ciphertext.size();
        outFile.write((char*)&origSize, sizeof(origSize));
        outFile.write((char*)&encSize, sizeof(encSize));
        outFile.write((char*)iv, 16);
        outFile.write((char*)ciphertext.data(), encSize);
    }
    outFile.close();

    auto end = high_resolution_clock::now();
    return duration_cast<microseconds>(end - start).count() / 1000.0;
}

// ============================================================
// Encriptacion paralela
// ============================================================
double encryptParallel(const vector<unsigned char>& fileData,
                       const unsigned char* key,
                       const char* outputPath,
                       int numThreads)
{
    auto start = high_resolution_clock::now();

    size_t numBlocks = (fileData.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;

    // Preparar archivo de salida con encabezado
    ofstream outFile(outputPath, ios::binary);
    uint32_t magic = MAGIC;
    uint32_t nBlocks = (uint32_t)numBlocks;
    uint32_t totalSize = (uint32_t)fileData.size();
    outFile.write((char*)&magic, sizeof(magic));
    outFile.write((char*)&nBlocks, sizeof(nBlocks));
    outFile.write((char*)&totalSize, sizeof(totalSize));

    // Preparar datos compartidos
    EncryptSharedData shared;
    shared.fileData = &fileData;
    shared.numBlocks = numBlocks;
    shared.blockSize = BLOCK_SIZE;
    memcpy(shared.key, key, 32);
    shared.results.resize(numBlocks);
    shared.nextBlockToWrite = 0;
    shared.outFile = &outFile;
    shared.numThreads = numThreads;

    pthread_mutex_init(&shared.writeMutex, NULL);
    pthread_cond_init(&shared.writeCond, NULL);

    // Crear hilos
    vector<pthread_t> threads(numThreads);
    vector<ThreadArg> args(numThreads);

    for (int i = 0; i < numThreads; i++) {
        args[i].threadId = i;
        args[i].sharedData = &shared;
        pthread_create(&threads[i], NULL, encryptThread, &args[i]);
    }

    // Esperar a que todos terminen
    for (int i = 0; i < numThreads; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&shared.writeMutex);
    pthread_cond_destroy(&shared.writeCond);
    outFile.close();

    auto end = high_resolution_clock::now();
    return duration_cast<microseconds>(end - start).count() / 1000.0;
}

// ============================================================
// Leer archivo encriptado
// ============================================================
bool readEncryptedFile(const char* path, vector<EncryptedBlock>& blocks,
                       uint32_t& totalOriginalSize)
{
    ifstream inFile(path, ios::binary);
    if (!inFile) {
        cerr << "No se pudo abrir archivo encriptado: " << path << endl;
        return false;
    }

    uint32_t magic, nBlocks;
    inFile.read((char*)&magic, sizeof(magic));
    if (magic != MAGIC) {
        cerr << "Error: formato de archivo no reconocido." << endl;
        return false;
    }
    inFile.read((char*)&nBlocks, sizeof(nBlocks));
    inFile.read((char*)&totalOriginalSize, sizeof(totalOriginalSize));

    blocks.resize(nBlocks);
    for (uint32_t i = 0; i < nBlocks; i++) {
        uint32_t origSize, encSize;
        inFile.read((char*)&origSize, sizeof(origSize));
        inFile.read((char*)&encSize, sizeof(encSize));

        blocks[i].originalSize = origSize;
        blocks[i].iv.resize(16);
        inFile.read((char*)blocks[i].iv.data(), 16);

        blocks[i].ciphertext.resize(encSize);
        inFile.read((char*)blocks[i].ciphertext.data(), encSize);
    }

    inFile.close();
    return true;
}

// ============================================================
// Desencriptacion secuencial (para comparacion)
// ============================================================
double decryptSequential(vector<EncryptedBlock>& blocks,
                         const unsigned char* key,
                         const char* outputPath)
{
    auto start = high_resolution_clock::now();

    ofstream outFile(outputPath, ios::binary);
    for (size_t b = 0; b < blocks.size(); b++) {
        vector<unsigned char> plaintext;
        decryptBlock(blocks[b].ciphertext.data(), blocks[b].ciphertext.size(),
                     key, blocks[b].iv.data(), plaintext);
        outFile.write((char*)plaintext.data(), plaintext.size());
    }
    outFile.close();

    auto end = high_resolution_clock::now();
    return duration_cast<microseconds>(end - start).count() / 1000.0;
}

// ============================================================
// Desencriptacion paralela
// ============================================================
double decryptParallel(vector<EncryptedBlock>& blocks,
                       const unsigned char* key,
                       const char* outputPath,
                       int numThreads)
{
    auto start = high_resolution_clock::now();

    size_t numBlocks = blocks.size();

    ofstream outFile(outputPath, ios::binary);

    DecryptSharedData shared;
    shared.encBlocks = &blocks;
    memcpy(shared.key, key, 32);
    shared.results.resize(numBlocks);
    shared.nextBlockToWrite = 0;
    shared.outFile = &outFile;
    shared.numThreads = numThreads;
    shared.numBlocks = numBlocks;

    pthread_mutex_init(&shared.writeMutex, NULL);
    pthread_cond_init(&shared.writeCond, NULL);

    vector<pthread_t> threads(numThreads);
    vector<ThreadArg> args(numThreads);

    for (int i = 0; i < numThreads; i++) {
        args[i].threadId = i;
        args[i].sharedData = &shared;
        pthread_create(&threads[i], NULL, decryptThread, &args[i]);
    }

    for (int i = 0; i < numThreads; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&shared.writeMutex);
    pthread_cond_destroy(&shared.writeCond);
    outFile.close();

    auto end = high_resolution_clock::now();
    return duration_cast<microseconds>(end - start).count() / 1000.0;
}

// ============================================================
// Leer clave hexadecimal del usuario
// ============================================================
bool readHexKey(unsigned char* key) {
    string hexKey;
    cout << "Ingresa la clave en formato hexadecimal (64 caracteres): ";
    cin >> hexKey;

    if (hexKey.length() != 64) {
        cerr << "Error: la clave debe tener 64 caracteres hexadecimales." << endl;
        return false;
    }

    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        sscanf(hexKey.c_str() + 2 * i, "%02x", &byte);
        key[i] = (unsigned char)byte;
    }
    return true;
}

// ============================================================
// Verificar integridad comparando archivos
// ============================================================
bool verifyIntegrity(const char* file1, const char* file2) {
    ifstream f1(file1, ios::binary);
    ifstream f2(file2, ios::binary);

    if (!f1 || !f2) return false;

    // Comparar tamano
    f1.seekg(0, ios::end);
    f2.seekg(0, ios::end);
    if (f1.tellg() != f2.tellg()) return false;

    f1.seekg(0);
    f2.seekg(0);

    // Comparar contenido bloque a bloque
    const size_t bufSize = 8192;
    char buf1[bufSize], buf2[bufSize];
    while (f1.read(buf1, bufSize)) {
        f2.read(buf2, bufSize);
        if (memcmp(buf1, buf2, f1.gcount()) != 0) return false;
    }
    // Comparar ultimo fragmento
    f2.read(buf2, f1.gcount());
    if (memcmp(buf1, buf2, f1.gcount()) != 0) return false;

    return true;
}

// ============================================================
// Mostrar clave en hexadecimal
// ============================================================
void printKeyHex(const unsigned char* key) {
    for (int i = 0; i < 32; i++)
        printf("%02x", key[i]);
    printf("\n");
}

// ============================================================
// Menu principal
// ============================================================
int main() {
    cout << "========================================================" << endl;
    cout << "  KIRBY CLASSIC - Encriptacion/Desencriptacion Paralela" << endl;
    cout << "  CC3086 - Laboratorio 10" << endl;
    cout << "  Sincronizacion con Variables de Condicion" << endl;
    cout << "========================================================" << endl;
    cout << endl;
    cout << "  Tamano de bloque: " << BLOCK_SIZE / 1024 << " KB (" << BLOCK_SIZE << " bytes)" << endl;
    cout << endl;
    cout << "  1. Encriptar archivo" << endl;
    cout << "  2. Desencriptar archivo previamente encriptado" << endl;
    cout << "  3. Benchmark completo (encriptar con 1,2,4,8 hilos)" << endl;
    cout << endl;
    cout << "Selecciona una opcion: ";

    int opcion;
    cin >> opcion;

    if (opcion == 1) {
        // ---- ENCRIPTACION ----
        string inputPath;
        cout << "Archivo de entrada (ej: input.txt): ";
        cin >> inputPath;

        int numThreads;
        cout << "Numero de hilos: ";
        cin >> numThreads;
        if (numThreads < 1) numThreads = 1;

        // Leer archivo
        ifstream inFile(inputPath, ios::binary);
        if (!inFile) {
            cerr << "No se pudo abrir: " << inputPath << endl;
            return 1;
        }
        vector<unsigned char> fileData(
            (istreambuf_iterator<char>(inFile)),
            istreambuf_iterator<char>()
        );
        inFile.close();

        size_t numBlocks = (fileData.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;
        cout << "\nArchivo: " << inputPath << " (" << fileData.size()
             << " bytes, " << numBlocks << " bloques)" << endl;

        // Generar clave
        unsigned char key[32];
        if (!RAND_bytes(key, sizeof(key))) {
            cerr << "Error generando clave" << endl;
            return 1;
        }

        // Encriptar secuencial para comparacion
        cout << "\n--- Encriptacion secuencial ---" << endl;
        double seqTime = encryptSequential(fileData, key, "output_seq.enc");
        cout << "Tiempo secuencial: " << seqTime << " ms" << endl;

        // Encriptar paralelo
        cout << "\n--- Encriptacion paralela (" << numThreads << " hilos) ---" << endl;
        double parTime = encryptParallel(fileData, key, "output.enc", numThreads);
        cout << "Tiempo paralelo:   " << parTime << " ms" << endl;

        // Speedup
        cout << "\nSpeedup: " << seqTime / parTime << "x" << endl;

        // Mostrar clave
        cout << "\n*** CLAVE GENERADA (guardar para desencriptar) ***" << endl;
        cout << "Clave: ";
        printKeyHex(key);
        cout << "\nArchivo encriptado guardado en: output.enc" << endl;

    } else if (opcion == 2) {
        // ---- DESENCRIPTACION ----
        string encPath;
        cout << "Archivo encriptado (ej: output.enc): ";
        cin >> encPath;

        string origPath;
        cout << "Archivo original para verificacion (ej: input.txt): ";
        cin >> origPath;

        int numThreads;
        cout << "Numero de hilos: ";
        cin >> numThreads;
        if (numThreads < 1) numThreads = 1;

        // Leer clave
        unsigned char key[32];
        if (!readHexKey(key)) return 1;

        // Leer archivo encriptado
        vector<EncryptedBlock> blocks;
        uint32_t totalSize;
        if (!readEncryptedFile(encPath.c_str(), blocks, totalSize)) return 1;

        cout << "\nArchivo encriptado: " << blocks.size() << " bloques, "
             << totalSize << " bytes originales" << endl;

        // Desencriptar secuencial para comparacion
        cout << "\n--- Desencriptacion secuencial ---" << endl;
        double seqTime = decryptSequential(blocks, key, "decrypted_seq.txt");
        cout << "Tiempo secuencial: " << seqTime << " ms" << endl;

        // Desencriptar paralelo
        cout << "\n--- Desencriptacion paralela (" << numThreads << " hilos) ---" << endl;
        double parTime = decryptParallel(blocks, key, "decrypted.txt", numThreads);
        cout << "Tiempo paralelo:   " << parTime << " ms" << endl;

        cout << "\nSpeedup: " << seqTime / parTime << "x" << endl;

        // Verificar integridad
        cout << "\n--- Verificacion de integridad ---" << endl;
        if (verifyIntegrity(origPath.c_str(), "decrypted.txt")) {
            cout << "EXITO: El archivo desencriptado es identico al original." << endl;
        } else {
            cout << "ERROR: El archivo desencriptado NO coincide con el original." << endl;
        }
        cout << "\nArchivo desencriptado guardado en: decrypted.txt" << endl;

    } else if (opcion == 3) {
        // ---- BENCHMARK COMPLETO ----
        string inputPath;
        cout << "Archivo de entrada (ej: input.txt): ";
        cin >> inputPath;

        // Leer archivo
        ifstream inFile(inputPath, ios::binary);
        if (!inFile) {
            cerr << "No se pudo abrir: " << inputPath << endl;
            return 1;
        }
        vector<unsigned char> fileData(
            (istreambuf_iterator<char>(inFile)),
            istreambuf_iterator<char>()
        );
        inFile.close();

        size_t numBlocks = (fileData.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;
        cout << "\nArchivo: " << inputPath << " (" << fileData.size()
             << " bytes, " << numBlocks << " bloques)" << endl;

        // Generar clave
        unsigned char key[32];
        if (!RAND_bytes(key, sizeof(key))) {
            cerr << "Error generando clave" << endl;
            return 1;
        }

        cout << "\n============================================" << endl;
        cout << "  BENCHMARK DE ENCRIPTACION" << endl;
        cout << "============================================" << endl;

        // Secuencial
        double seqTime = encryptSequential(fileData, key, "bench_seq.enc");
        cout << "Secuencial:    " << seqTime << " ms" << endl;

        // Paralelo con diferentes cantidades de hilos
        int threadCounts[] = {1, 2, 4, 8};
        double parTimes[4];

        for (int t = 0; t < 4; t++) {
            char outName[64];
            snprintf(outName, sizeof(outName), "bench_%d.enc", threadCounts[t]);
            parTimes[t] = encryptParallel(fileData, key, outName, threadCounts[t]);
            cout << threadCounts[t] << " hilo(s):      "
                 << parTimes[t] << " ms  (speedup: "
                 << seqTime / parTimes[t] << "x)" << endl;
        }

        // Ahora benchmark de desencriptacion
        cout << "\n============================================" << endl;
        cout << "  BENCHMARK DE DESENCRIPTACION" << endl;
        cout << "============================================" << endl;

        vector<EncryptedBlock> blocks;
        uint32_t totalSize;
        readEncryptedFile("bench_seq.enc", blocks, totalSize);

        double seqDecTime = decryptSequential(blocks, key, "bench_dec_seq.txt");
        cout << "Secuencial:    " << seqDecTime << " ms" << endl;

        for (int t = 0; t < 4; t++) {
            char outName[64];
            snprintf(outName, sizeof(outName), "bench_dec_%d.txt", threadCounts[t]);
            double dt = decryptParallel(blocks, key, outName, threadCounts[t]);
            cout << threadCounts[t] << " hilo(s):      "
                 << dt << " ms  (speedup: "
                 << seqDecTime / dt << "x)" << endl;
        }

        // Verificar integridad del ultimo
        cout << "\n--- Verificacion de integridad ---" << endl;
        if (verifyIntegrity(inputPath.c_str(), "bench_dec_8.txt")) {
            cout << "EXITO: Archivo desencriptado con 8 hilos es identico al original." << endl;
        } else {
            cout << "ERROR: Archivo desencriptado NO coincide." << endl;
        }

        // Mostrar clave
        cout << "\nClave generada: ";
        printKeyHex(key);

    } else {
        cout << "Opcion no valida." << endl;
        return 1;
    }

    return 0;
}
