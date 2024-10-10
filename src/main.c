// main.c
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "util.h"
#include "raw_socket.h"

int main(int argc, char *argv[]) {
    // Initialisiere die Raw-Sockets für ens18 und upfgtp
    int ens18_sock = create_raw_socket("ens18");
    int upfgtp_sock = create_raw_socket("upfgtp");

    // Überprüfen, ob das Argument "once" übergeben wurde
    if (argc > 1 && strcmp(argv[1], "once") == 0) {
        printf("Starte Einzeldurchlauf...\n");
        
        // Einmal den Header von ens18 und upfgtp anzeigen und vergleichen
        monitor_interface(&ens18_sock);
        monitor_interface(&upfgtp_sock);
        
        printf("Vergleich der Pakete abgeschlossen.\n");
        
        close(ens18_sock);
        close(upfgtp_sock);
        return 0;
    }

    // Ständig laufender Modus (ohne oder mit anderen Parametern als "once")
    printf("Starte Dauermodus...\n");
    
    pthread_t thread1, thread2;
    
    // Threads erstellen und Raw-Sockets an die Threads übergeben
    pthread_create(&thread1, NULL, (void *)monitor_interface, &ens18_sock);
    pthread_create(&thread2, NULL, (void *)monitor_interface, &upfgtp_sock);

    // Warte auf die Beendigung der Threads (dieser Zustand endet nie, da die Threads ständig laufen)
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    return 0;
}
