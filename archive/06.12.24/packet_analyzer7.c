#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <signal.h>
#include <math.h>

#define HASHMAP_SIZE 1024
#define TIMEOUT_SECONDS 2
#define CLEANUP_INTERVAL_MS 500

// Datenstruktur für gespeicherte Pakete
typedef struct packet_entry {
    struct packet_entry *next;
    unsigned char *payload;
    size_t payload_len;
    struct timeval timestamp;
} packet_entry_t;

// Hashmap Slot
typedef struct {
    packet_entry_t *head;
} hash_slot_t;

// Globale Hashmap
static hash_slot_t hashmap[HASHMAP_SIZE];

// Statistikstrukturen
static int total_n3_packets = 0;
static int total_n6_packets = 0;
static int matched_packets = 0;
static int lost_packets = 0;

// Für Latenzberechnung (zur Jitter-Berechnung sammeln wir alle Latenzen)
static double sum_latency = 0.0;       // Summe der Latenzen
static double sum_latency_sq = 0.0;    // Summe der quadrierten Latenzen
static int latency_count = 0;          // Anzahl gemessener Latenzen

// Für Throughput-Berechnung (Summe aller Payloadgrößen von gematchten Paketen)
static size_t sum_matched_payload = 0;

// Startzeit des Programms
static struct timeval start_time;

// Flag für Hauptloop-Beenden
static volatile int running = 1;

// Lock für Hashmap und Statistiken
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

// Beispielhafte Hashfunktion
static unsigned int simple_hash(const unsigned char *data, size_t len) {
    unsigned int hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash % HASHMAP_SIZE;
}

// Payload extrahieren (vereinfachte Annahme)
// Bitte anpassen an die tatsächlichen Headerformate!
static unsigned char* extract_payload(const u_char *packet, const struct pcap_pkthdr *hdr, size_t *payload_len) {
    // Beispiel: Ethernet(14) + IPv4(20) + UDP(8) -> 42 Bytes Header
    // GTP Header ggf. weitere 8-12 Byte. Hier nur ein Beispiel.
    int header_length = 42; 
    if (hdr->caplen <= (u_int)header_length) {
        *payload_len = 0;
        return NULL;
    }

    *payload_len = hdr->caplen - header_length;
    unsigned char *pl = malloc(*payload_len);
    if (!pl) return NULL;
    memcpy(pl, packet + header_length, *payload_len);
    return pl;
}

// N3-Paket in Hashmap einfügen
static void insert_n3_packet(const unsigned char *payload, size_t len, const struct timeval *ts) {
    unsigned int key = simple_hash(payload, len);

    packet_entry_t *entry = malloc(sizeof(packet_entry_t));
    if (!entry) return;
    entry->payload = malloc(len);
    if (!entry->payload) {
        free(entry);
        return;
    }
    memcpy(entry->payload, payload, len);
    entry->payload_len = len;
    entry->timestamp = *ts;

    pthread_mutex_lock(&lock);
    entry->next = hashmap[key].head;
    hashmap[key].head = entry;
    total_n3_packets++;
    pthread_mutex_unlock(&lock);
}

// Passendes N3-Paket für N6-Paket suchen
static void match_n6_packet(const unsigned char *payload, size_t len, const struct timeval *ts_n6) {
    unsigned int key = simple_hash(payload, len);

    pthread_mutex_lock(&lock);
    packet_entry_t *prev = NULL;
    packet_entry_t *curr = hashmap[key].head;

    while (curr) {
        if (curr->payload_len == len && memcmp(curr->payload, payload, len) == 0) {
            // Match gefunden, Latenz berechnen
            struct timeval diff;
            timersub(ts_n6, &curr->timestamp, &diff);
            double latency_ms = diff.tv_sec * 1000.0 + diff.tv_usec / 1000.0;

            // Aus der Liste entfernen
            if (prev) {
                prev->next = curr->next;
            } else {
                hashmap[key].head = curr->next;
            }

            matched_packets++;
            sum_latency += latency_ms;
            sum_latency_sq += (latency_ms * latency_ms);
            latency_count++;
            sum_matched_payload += len; // Payloadgröße zum Throughput-Calc hinzufügen

            free(curr->payload);
            free(curr);
            pthread_mutex_unlock(&lock);
            return;
        }
        prev = curr;
        curr = curr->next;
    }

    // Kein Match -> Paket verwerfen, kein direkter increment von lost hier, 
    // weil "lost" zählt nur N3-Pakete die nie ein N6-Pendant finden und ablaufen.
    pthread_mutex_unlock(&lock);
}

// Thread-Funktion zur regelmäßigen Bereinigung
static void *cleanup_thread_func(void *arg) {
    (void)arg;
    while (running) {
        usleep(CLEANUP_INTERVAL_MS * 1000);
        struct timeval now;
        gettimeofday(&now, NULL);

        pthread_mutex_lock(&lock);
        for (int i = 0; i < HASHMAP_SIZE; i++) {
            packet_entry_t *prev = NULL;
            packet_entry_t *curr = hashmap[i].head;
            while (curr) {
                double elapsed = (now.tv_sec - curr->timestamp.tv_sec) +
                                 (now.tv_usec - curr->timestamp.tv_usec)/1000000.0;
                if (elapsed > TIMEOUT_SECONDS) {
                    // Eintrag verwerfen -> lost
                    lost_packets++;
                    if (prev) {
                        prev->next = curr->next;
                    } else {
                        hashmap[i].head = curr->next;
                    }
                    free(curr->payload);
                    free(curr);
                    if (prev) {
                        curr = prev->next;
                    } else {
                        curr = hashmap[i].head;
                    }
                } else {
                    prev = curr;
                    curr = curr->next;
                }
            }
        }
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

// Callback für N3 Interface
void callback_n3(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    size_t payload_len;
    unsigned char *pl = extract_payload(bytes, h, &payload_len);
    if (!pl || payload_len == 0) {
        if (pl) free(pl);
        return;
    }
    insert_n3_packet(pl, payload_len, &h->ts);
    free(pl);
}

// Callback für N6 Interface
void callback_n6(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    size_t payload_len;
    unsigned char *pl = extract_payload(bytes, h, &payload_len);
    if (!pl || payload_len == 0) {
        if (pl) free(pl);
        return;
    }
    pthread_mutex_lock(&lock);
    total_n6_packets++;
    pthread_mutex_unlock(&lock);
    match_n6_packet(pl, payload_len, &h->ts);
    free(pl);
}

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle_n3, *handle_n6;

    // Signal Handler für Ctrl+C
    signal(SIGINT, handle_sigint);

    gettimeofday(&start_time, NULL);

    // N3 Interface öffnen (ens18), Filter auf src host 10.2.2.154
    handle_n3 = pcap_open_live("ens18", BUFSIZ, 1, 1000, errbuf);
    if (!handle_n3) {
        fprintf(stderr, "Fehler pcap_open_live N3: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle_n3, &fp, "src host 10.2.2.154", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Fehler pcap_compile N3\n");
        return 1;
    }
    if (pcap_setfilter(handle_n3, &fp) == -1) {
        fprintf(stderr, "Fehler pcap_setfilter N3\n");
        return 1;
    }
    pcap_freecode(&fp);

    // N6 Interface öffnen (upfgtp)
    handle_n6 = pcap_open_live("upfgtp", BUFSIZ, 1, 1000, errbuf);
    if (!handle_n6) {
        fprintf(stderr, "Fehler pcap_open_live N6: %s\n", errbuf);
        return 1;
    }

    // Cleanup Thread starten
    pthread_t cleanup_thread;
    pthread_create(&cleanup_thread, NULL, cleanup_thread_func, NULL);

    // Non-Blocking setzen, um beide Interfaces abwechselnd lesen zu können
    if (pcap_setnonblock(handle_n3, 1, errbuf) == -1) {
        fprintf(stderr, "Fehler pcap_setnonblock N3: %s\n", errbuf);
    }
    if (pcap_setnonblock(handle_n6, 1, errbuf) == -1) {
        fprintf(stderr, "Fehler pcap_setnonblock N6: %s\n", errbuf);
    }

    // Hauptloop: läuft bis Ctrl+C
    while (running) {
        pcap_dispatch(handle_n3, -1, callback_n3, NULL);
        pcap_dispatch(handle_n6, -1, callback_n6, NULL);
        usleep(10000); // 10ms Pause, um CPU-Last zu reduzieren
    }

    // Beenden: Cleanup Thread beenden
    pthread_cancel(cleanup_thread);
    pthread_join(cleanup_thread, NULL);

    // Zeitspanne berechnen
    struct timeval end_time;
    gettimeofday(&end_time, NULL);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) +
                     (end_time.tv_usec - start_time.tv_usec)/1000000.0;
    if (elapsed <= 0) elapsed = 1.0; // nur zur Sicherheit

    // Metriken berechnen
    double packet_loss_rate = 0.0;
    if (total_n3_packets > 0) {
        packet_loss_rate = (double)lost_packets / (double)total_n3_packets;
    }

    double avg_latency = 0.0;
    double jitter = 0.0;
    if (latency_count > 0) {
        avg_latency = sum_latency / latency_count;
        // Varianz = E[L²] - (E[L])²
        double mean = avg_latency;
        double mean_sq = sum_latency_sq / latency_count;
        double variance = mean_sq - (mean * mean);
        if (variance < 0) variance = 0; // numerische Stabilität
        jitter = sqrt(variance);
    }

    double throughput = 0.0; // Bytes pro Sekunde
    if (elapsed > 0) {
        throughput = sum_matched_payload / elapsed;
    }

    double packet_rate = 0.0; // Pakete pro Sekunde
    if (elapsed > 0) {
        packet_rate = (double)matched_packets / elapsed;
    }

    // CSV schreiben
    FILE *fp_csv = fopen("results.csv", "w");
    if (fp_csv) {
        fprintf(fp_csv, "total_n3_packets,total_n6_packets,matched_packets,lost_packets,packet_loss_rate,avg_latency_ms,jitter_ms,throughput_Bps,packet_rate_pps\n");
        fprintf(fp_csv, "%d,%d,%d,%d,%f,%f,%f,%f,%f\n",
                total_n3_packets,
                total_n6_packets,
                matched_packets,
                lost_packets,
                packet_loss_rate,
                avg_latency,
                jitter,
                throughput,
                packet_rate);
        fclose(fp_csv);
    } else {
        fprintf(stderr, "Konnte results.csv nicht öffnen zum Schreiben.\n");
    }

    pcap_close(handle_n3);
    pcap_close(handle_n6);

    return 0;
}
