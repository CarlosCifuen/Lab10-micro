/*
 * generate_log.cpp
 * Genera un archivo de log de eventos del juego Kirby Classic
 * para usar como entrada del laboratorio de encriptacion paralela.
 */
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <cstring>

using namespace std;

int main() {
    srand(time(NULL));
    ofstream out("input.txt");
    if (!out) { cerr << "Error abriendo archivo" << endl; return 1; }

    out << "========================================================\n";
    out << "  KIRBY CLASSIC - REGISTRO DE EVENTOS DEL VIDEOJUEGO\n";
    out << "  Universidad del Valle de Guatemala - CC3086\n";
    out << "  Proyecto 02 - Simulacion con Pthreads\n";
    out << "========================================================\n\n";

    const char* acciones[] = {
        "IDLE", "CAMINANDO", "SALTANDO", "CAYENDO",
        "DOBLE_SALTO", "TRIPLE_SALTO", "ATERRIZAJE",
        "COLISION_PLATAFORMA", "CAIDA_VACIO", "RESPAWN"
    };
    const char* plataformas[] = {
        "PLAT_PRINCIPAL_0", "PLAT_FLOTANTE_1", "PLAT_LARGA_2",
        "PLAT_ELEVADA_3", "PLAT_CORTA_4", "PLAT_MEDIA_5",
        "PLAT_ALTA_6", "PLAT_FINAL_7"
    };
    const char* hilos[] = {
        "INPUT_THREAD", "PHYSICS_THREAD", "RENDER_THREAD"
    };
    const char* estados_mutex[] = {
        "LOCK_ADQUIRIDO", "LOCK_LIBERADO", "ESPERANDO_LOCK"
    };

    int eventId = 1;
    // Generar ~5 MB de logs
    // Each line is roughly 200 bytes, so ~25000 lines = ~5MB
    int targetLines = 30000;

    for (int i = 0; i < targetLines; i++) {
        int hora = rand() % 24;
        int min  = rand() % 60;
        int seg  = rand() % 60;
        int ms   = rand() % 1000;

        float worldX = (float)(rand() % 20000) / 100.0f;
        float worldY = (float)(rand() % 3000) / 100.0f;
        float velY   = (float)(rand() % 1000 - 500) / 100.0f;
        float camX   = (float)(rand() % 10000) / 100.0f;

        int accion = rand() % 10;
        int plat   = rand() % 8;
        int hilo   = rand() % 3;
        int mutex  = rand() % 3;
        int fps    = 28 + rand() % 5;
        int jumpCount = rand() % 6;
        bool onGround = rand() % 2;

        out << "[" << eventId++ << "] ";
        out << hora << ":" << (min < 10 ? "0" : "") << min << ":"
            << (seg < 10 ? "0" : "") << seg << "."
            << (ms < 100 ? "0" : "") << (ms < 10 ? "0" : "") << ms;
        out << " | HILO: " << hilos[hilo];
        out << " | MUTEX: " << estados_mutex[mutex];
        out << " | ACCION: " << acciones[accion];
        out << " | POS: (" << worldX << ", " << worldY << ")";
        out << " | VEL_Y: " << velY;
        out << " | CAM_X: " << camX;
        out << " | PLATAFORMA: " << plataformas[plat];
        out << " | EN_SUELO: " << (onGround ? "SI" : "NO");
        out << " | SALTOS: " << jumpCount;
        out << " | FPS: " << fps;
        out << "\n";

        // Cada ~500 lineas, agregar un bloque de estadisticas
        if (i > 0 && i % 500 == 0) {
            out << "\n--- ESTADISTICAS PARCIALES (frame " << i << ") ---\n";
            out << "  Tiempo de juego acumulado: " << (i / 30) << " segundos\n";
            out << "  Saltos totales: " << (rand() % 1000 + 100) << "\n";
            out << "  Caidas al vacio: " << (rand() % 50) << "\n";
            out << "  Respawns: " << (rand() % 30) << "\n";
            out << "  Distancia recorrida: " << (float)(rand() % 100000) / 10.0f << " unidades\n";
            out << "  FPS promedio: " << 29 + (rand() % 3) << "\n";
            out << "  Colisiones detectadas: " << (rand() % 500 + 50) << "\n";
            out << "  Locks de mutex adquiridos: " << (rand() % 10000 + 1000) << "\n";
            out << "  Contenciones de mutex: " << (rand() % 100) << "\n";
            out << "--- FIN ESTADISTICAS ---\n\n";
        }
    }

    out << "\n========================================================\n";
    out << "  FIN DEL REGISTRO - Total eventos: " << (eventId - 1) << "\n";
    out << "========================================================\n";

    out.close();

    // Verificar tamano
    ifstream check("input.txt", ios::ate);
    long size = check.tellg();
    check.close();
    cout << "Archivo input.txt generado: " << size << " bytes ("
         << (size / 1024.0 / 1024.0) << " MB)" << endl;

    return 0;
}
