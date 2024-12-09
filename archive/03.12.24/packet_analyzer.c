#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <math.h>


/* Hashmap-Struktur */
#define HASHMAP_SIZE 1024

/* GTP-U Header-Länge (Minimal) */
#define GTPU_HEADER_LEN 8

/* Ältester erlaubter Paket-Offset in Sekunden */
#define MAX_AGE 2

/* Cleanup-Intervall in Sekunden (0.5 Sekunden) */
#define CLEANUP_INTERVAL 0.5

/* Filter für N3-Pakete: Nur Quell-IP 10.2.2.154 */
static const char *N3_FILTER = "src host 10.2.2.154 and udp port 2152";
/* Für N6 kann ggf. ein anderer Filter verwendet werden */
static const char *N6_FILTER = "ip"; // Beispielhaft alle IP-Pakete

/* Datenstrukturen */

// Paketstruktur in der Liste
typedef struct packet_node {
    unsigned char *payload;
    size_t payload_len;
    struct timeval timestamp; 
    struct packet_node *next;
} packet_node_t;

// Jeder Hashmap-Eintrag hat eine Liste von packet_node_t
typedef struct {
    packet_node_t *head;
} packet_list_t;

// Hashmap
static packet_list_t g_hashmap[HASHMAP_SIZE];

// Mutex für Thread-Synchronisation (Hashmap)
static pthread_mutex_t g_hashmap_lock = PTHREAD_MUTEX_INITIALIZER;

// Statistiken
static unsigned long total_n3_packets = 0;
static unsigned long total_n6_packets = 0;
static unsigned long matched_packets = 0;
static unsigned long lost_packets = 0;
static unsigned long discarded_n6 = 0;

// Für Latenz/Jitter-Berechnung
// Hier sehr vereinfacht, in Realität komplexere Datenhaltung
static double total_latency = 0.0;
static double total_latency_square = 0.0;
static unsigned long latency_count = 0;
static double avg_latency = 0.0;
static double jitter = 0.0;

// Laufvariablen
static volatile int running = 1;

/* Hilfsfunktionen */

// Einfache Hash-Funktion für Payload
// Diese ist sehr rudimentär und sollte in der Praxis durch etwas Robusteres ersetzt werden.
unsigned int simple_hash(const unsigned char *data, size_t len) {
    unsigned int hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i]; 
    }
    return hash % HASHMAP_SIZE;
}

// Hole aktuelle Zeit
static inline void get_current_time(struct timeval *tv) {
    gettimeofday(tv, NULL);
}

// Berechnet Zeitdifferenz in Sekunden zwischen zwei Timestamps
double time_diff(const struct timeval *start, const struct timeval *end) {
    double sec = (double)(end->tv_sec - start->tv_sec);
    double usec = (double)(end->tv_usec - start->tv_usec) / 1000000.0;
    return sec + usec;
}

// GTP-U Header entfernen (vereinfachte Annahme, dass Header immer GTP-U ist und mindestens GTPU_HEADER_LEN groß)
unsigned char* remove_gtpu_header(const unsigned char *packet, size_t len, size_t *new_len) {
    if (len <= GTPU_HEADER_LEN) {
        *new_len = 0;
        return NULL;
    }
    unsigned char *new_payload = malloc(len - GTPU_HEADER_LEN);
    if(!new_payload) return NULL;
    memcpy(new_payload, packet + GTPU_HEADER_LEN, len - GTPU_HEADER_LEN);
    *new_len = len - GTPU_HEADER_LEN;
    return new_payload;
}

/* Einfügen eines N3-Pakets in die Hashmap */
void insert_n3_packet(const unsigned char *payload, size_t payload_len, struct timeval *timestamp) {
    unsigned int idx = simple_hash(payload, payload_len);

    packet_node_t *node = malloc(sizeof(packet_node_t));
    if (!node) return;
    node->payload = malloc(payload_len);
    if (!node->payload) {
        free(node);
        return;
    }
    memcpy(node->payload, payload, payload_len);
    node->payload_len = payload_len;
    node->timestamp = *timestamp;

    pthread_mutex_lock(&g_hashmap_lock);
    node->next = g_hashmap[idx].head;
    g_hashmap[idx].head = node;
    pthread_mutex_unlock(&g_hashmap_lock);
}

/* Suchen und Entfernen eines passenden Pakets (für N6-Paket) */
int match_and_remove_n3_packet(const unsigned char *payload, size_t payload_len, struct timeval *n6_timestamp) {
    unsigned int idx = simple_hash(payload, payload_len);
    int found = 0;
    struct timeval now;
    get_current_time(&now);

    pthread_mutex_lock(&g_hashmap_lock);
    packet_node_t *prev = NULL;
    packet_node_t *cur = g_hashmap[idx].head;

    while(cur) {
        if (cur->payload_len == payload_len && memcmp(cur->payload, payload, payload_len) == 0) {
            // Passendes Paket gefunden
            double latency = time_diff(&cur->timestamp, n6_timestamp);
            total_latency += latency;
            total_latency_square += (latency * latency);
            latency_count++;
            matched_packets++;

            // Liste anpassen
            if (prev) {
                prev->next = cur->next;
            } else {
                g_hashmap[idx].head = cur->next;
            }

            free(cur->payload);
            free(cur);
            found = 1;
            break;
        }
        prev = cur;
        cur = cur->next;
    }
    pthread_mutex_unlock(&g_hashmap_lock);
    return found;
}

/* Periodisches Cleanup */
void *cleanup_thread(void *arg) {
    while (running) {
        usleep((int)(CLEANUP_INTERVAL * 1000000));
        struct timeval now;
        get_current_time(&now);

        pthread_mutex_lock(&g_hashmap_lock);
        for (int i = 0; i < HASHMAP_SIZE; i++) {
            packet_node_t *prev = NULL;
            packet_node_t *cur = g_hashmap[i].head;
            while (cur) {
                double age = time_diff(&cur->timestamp, &now);
                if (age > MAX_AGE) {
                    // Zu alt, entfernen
                    lost_packets++;
                    packet_node_t *tmp = cur;
                    if (prev) {
                        prev->next = cur->next;
                    } else {
                        g_hashmap[i].head = cur->next;
                    }
                    cur = cur->next;
                    free(tmp->payload);
                    free(tmp);
                } else {
                    prev = cur;
                    cur = cur->next;
                }
            }
        }
        pthread_mutex_unlock(&g_hashmap_lock);
    }
    return NULL;
}

/* N3 Packet Callback (vor der UPF) */
void n3_packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    // Hier sollte das Paket als GTP-U erkannt werden, GTP-U Header entfernen
    // Für Vereinfachung: Wir nehmen an, dass das Paket ein GTP-U encapsulated IP-Paket ist.
    // Normalerweise müsste man hier erst den IP/UDP Header parsen, dann GTP-U.
    size_t new_len = 0;
    unsigned char *decap_payload = remove_gtpu_header(bytes, h->len, &new_len);
    if (!decap_payload || new_len == 0) {
        // Kein gültiges GTP-U Paket oder Fehler beim Decap.
        if (decap_payload) free(decap_payload);
        return;
    }

    struct timeval ts = h->ts;
    insert_n3_packet(decap_payload, new_len, &ts);
    total_n3_packets++;

    free(decap_payload);
}

/* N6 Packet Callback (nach der UPF) */
void n6_packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    // Hier wird direkt die Payload verwendet (z. B. IP-Paket)
    // In einer echten Umgebung müsste ggf. noch der L2 Header entfernt werden.
    // Für Einfachheit nehmen wir an, dass bytes bereits ab IP-Header beginnen.
    struct timeval ts = h->ts;

    // Suchen nach passendem N3-Paket
    if (!match_and_remove_n3_packet(bytes, h->len, &ts)) {
        // Nichts passendes gefunden -> discard
        discarded_n6++;
    } else {
        total_n6_packets++;
    }
}

/* Signalfang für CTRL+C */
void sigint_handler(int signum) {
    (void)signum;
    running = 0;
}

/* CSV Ausgabe am Ende */
void write_csv() {
    FILE *f = fopen("analysis.csv", "w");
    if (!f) return;

    // Metriken berechnen
    if (latency_count > 0) {
        avg_latency = total_latency / (double)latency_count;
        double avg_sq = total_latency_square / (double)latency_count;
        jitter = avg_sq - (avg_latency * avg_latency);
        if (jitter < 0) jitter = 0;
        jitter = sqrt(jitter);
    }

    double packet_loss_rate = 0.0;
    if (total_n3_packets > 0) {
        packet_loss_rate = ((double)lost_packets / (double)total_n3_packets) * 100.0;
    }

    double throughput = (double)matched_packets; // hier sehr vereinfacht, müsste über Zeitfenster gerechnet werden
    double packet_rate = (double)matched_packets; // ebenfalls stark vereinfacht

    fprintf(f, "Total_N3,Total_N6,Matched,Lost,Discarded_N6,Avg_Latency_ms,Jitter_ms,Loss_Rate%%,Throughput,Packet_Rate\n");
    fprintf(f, "%lu,%lu,%lu,%lu,%lu,%.6f,%.6f,%.3f,%.3f,%.3f\n",
            total_n3_packets, total_n6_packets, matched_packets, lost_packets,
            discarded_n6, avg_latency * 1000.0, jitter * 1000.0, packet_loss_rate, throughput, packet_rate);
    fclose(f);
}

/* Hauptprogramm */
int main() {
    signal(SIGINT, sigint_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle_n3, *handle_n6;

    // N3 Interface (ens18)
    handle_n3 = pcap_open_live("ens18", BUFSIZ, 1, 1000, errbuf);
    if (!handle_n3) {
        fprintf(stderr, "Fehler beim Öffnen von ens18: %s\n", errbuf);
        return 1;
    }
    struct bpf_program fp_n3;
    if (pcap_compile(handle_n3, &fp_n3, N3_FILTER, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Fehler bei pcap_compile N3: %s\n", pcap_geterr(handle_n3));
        pcap_close(handle_n3);
        return 1;
    }
    if (pcap_setfilter(handle_n3, &fp_n3) == -1) {
        fprintf(stderr, "Fehler bei pcap_setfilter N3: %s\n", pcap_geterr(handle_n3));
        pcap_freecode(&fp_n3);
        pcap_close(handle_n3);
        return 1;
    }
    pcap_freecode(&fp_n3);

    // N6 Interface (upfgtp)
    handle_n6 = pcap_open_live("upfgtp", BUFSIZ, 1, 1000, errbuf);
    if (!handle_n6) {
        fprintf(stderr, "Fehler beim Öffnen von upfgtp: %s\n", errbuf);
        pcap_close(handle_n3);
        return 1;
    }
    struct bpf_program fp_n6;
    if (pcap_compile(handle_n6, &fp_n6, N6_FILTER, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Fehler bei pcap_compile N6: %s\n", pcap_geterr(handle_n6));
        pcap_close(handle_n3);
        pcap_close(handle_n6);
        return 1;
    }
    if (pcap_setfilter(handle_n6, &fp_n6) == -1) {
        fprintf(stderr, "Fehler bei pcap_setfilter N6: %s\n", pcap_geterr(handle_n6));
        pcap_freecode(&fp_n6);
        pcap_close(handle_n3);
        pcap_close(handle_n6);
        return 1;
    }
    pcap_freecode(&fp_n6);

    // Cleanup Thread starten
    pthread_t cleanup_tid;
    pthread_create(&cleanup_tid, NULL, cleanup_thread, NULL);

    // Capture Loops in eigenen Threads
    // Wir nutzen hier zwei separate Threads: einen für N3 und einen für N6
    // Alternativ könnte man auch select/poll auf den File Deskriptoren von PCAP anwenden oder pcap_loop in main laufen lassen.
    pthread_t n3_tid, n6_tid;

    // Wrapper Funktionen für pcap_loop
    void *n3_loop(void *arg) {
        pcap_loop((pcap_t *)arg, 0, n3_packet_handler, NULL);
        return NULL;
    }
    void *n6_loop(void *arg) {
        pcap_loop((pcap_t *)arg, 0, n6_packet_handler, NULL);
        return NULL;
    }

    pthread_create(&n3_tid, NULL, n3_loop, handle_n3);
    pthread_create(&n6_tid, NULL, n6_loop, handle_n6);

    // Warten bis SIGINT kommt
    while(running) {
        sleep(1);
    }

    // Stoppe Capture
    pcap_breakloop(handle_n3);
    pcap_breakloop(handle_n6);

    pthread_join(n3_tid, NULL);
    pthread_join(n6_tid, NULL);

    // Cleanup Thread stoppen
    pthread_cancel(cleanup_tid);
    pthread_join(cleanup_tid, NULL);

    // CSV schreiben
    write_csv();

    // Ressourcen aufräumen
    pcap_close(handle_n3);
    pcap_close(handle_n6);

    // Hashmap leeren
    for (int i = 0; i < HASHMAP_SIZE; i++) {
        packet_node_t *cur = g_hashmap[i].head;
        while (cur) {
            packet_node_t *tmp = cur;
            cur = cur->next;
            free(tmp->payload);
            free(tmp);
        }
    }

    return 0;
}