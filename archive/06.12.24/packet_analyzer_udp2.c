/**
 * monitoring_module_udp.c
 * Ein Programm zur Überwachung und Analyse von UDP-Paketverkehr mithilfe von Raw Sockets.
 *
 * Dieses Programm analysiert GTP-U-UDP-Paketflüsse auf den N3- und N6-Schnittstellen in einem 5G-Netz.
 * Es ordnet entsprechende Pakete zu, berechnet Latenz, Jitter, Durchsatz und Verlustraten
 * und protokolliert diese Metriken in Echtzeit.
 *
 * Funktionen:
 * - Paketextraktion und Parsing für N3- und N6-UDP-Pakete.
 * - Hashmap-basiertes Paket-Matching mit Timeout-Handling.
 * - Periodische Statistiksammlung zur Durchsatz- und Latenzanalyse.
 * - CSV-Protokollierung zur späteren Überprüfung.
 */

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

// Konstanten
#define HASHMAP_SIZE 4096 // Erhöhte Größe zur Minimierung von Kollisionen
#define TIMEOUT_SECONDS 5
#define CLEANUP_INTERVAL_MS 500

typedef struct packet_entry {
    struct packet_entry *next;
    unsigned char *payload;
    size_t payload_len;
    struct timeval timestamp;
} packet_entry_t;

typedef struct {
    packet_entry_t *head;
} hash_slot_t;

static hash_slot_t hashmap[HASHMAP_SIZE];

static int total_n3_packets = 0;
static int total_n6_packets = 0;
static int matched_packets = 0;
static int lost_packets = 0;
static double sum_latency = 0.0;
static double sum_latency_sq = 0.0;
static int latency_count = 0;
static size_t sum_matched_payload = 0;

// Gesamt N3-Payload erfassen für "normalen Durchsatz"
static size_t total_n3_payload = 0;

static struct timeval start_time;
static volatile int running = 1;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * Signal-Handler, um das Programm bei SIGINT (Ctrl+C) sauber zu beenden.
 * @param sig Signalnummer (nicht verwendet).
 */
static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

/**
 * Berechnet einen einfachen Hash für ein gegebenes Datenarray.
 * @param data Zeiger auf das Datenarray.
 * @param len Länge des Datenarrays.
 * @return Ein Hash-Wert im Bereich [0, HASHMAP_SIZE-1].
 */
static unsigned int simple_hash(const unsigned char *data, size_t len) {
    unsigned int hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash % HASHMAP_SIZE;
}

/**
 * Parsen des IP-Headers eines Pakets, um dessen Länge zu bestimmen.
 * @param data Zeiger auf die Paketdaten.
 * @param len Länge der Paketdaten.
 * @return Länge des IP-Headers bei Erfolg, -1 bei Fehler.
 */
static int parse_ip_header(const unsigned char *data, size_t len) {
    if (len < 20) return -1;
    unsigned char ihl = data[0] & 0x0F; 
    int ip_header_len = ihl * 4;
    if (ip_header_len < 20 || ip_header_len > (int)len) return -1;
    return ip_header_len;
}

/**
 * Parsen des UDP-Headers eines Pakets, um dessen Länge zu bestimmen.
 * @param data Zeiger auf die UDP-Header-Daten.
 * @param len Länge der verbleibenden Paketdaten.
 * @return Länge des UDP-Headers bei Erfolg, -1 bei Fehler.
 */
static int parse_udp_header(const unsigned char *data, size_t len) {
    if (len < 8) return -1; // Mindestlänge des UDP-Headers
    return 8; // Feste Länge für UDP-Header
}

/**
 * Parsen des GTP-U-Headers eines Pakets, um dessen Länge zu bestimmen.
 * @param data Zeiger auf die GTP-U-Daten.
 * @param len Länge der GTP-U-Daten.
 * @return Länge des GTP-U-Headers bei Erfolg, -1 bei Fehler.
 */
static int parse_gtp_header(const unsigned char *data, size_t len) {
    if (len < 8) return -1;
    unsigned char flags = data[0];
    int e_flag = (flags & 0x04) >> 2;
    int offset = 8; 
    if (e_flag) {
        unsigned char next_ext_type;
        if ((int)len < offset+1) return -1;
        next_ext_type = data[offset];
        offset++;
        while (next_ext_type != 0) {
            if ((int)len < offset+1) return -1;
            unsigned char ext_len = data[offset];
            offset++;
            if ((int)len < offset+ext_len+1) return -1;
            offset += ext_len;
            next_ext_type = data[offset]; 
            offset++;
        }
    }
    return offset;
}

/**
 * Extrahiert die Payload aus einem N3-Paket.
 * @param packet Zeiger auf die Paketdaten.
 * @param hdr Paketmetadaten (pcap Header).
 * @param payload_len Zeiger zum Speichern der extrahierten Payload-Länge.
 * @return Zeiger auf die extrahierte Payload bei Erfolg, NULL bei Fehler.
 */
static unsigned char* extract_payload_n3(const u_char *packet, const struct pcap_pkthdr *hdr, size_t *payload_len) {
    size_t remaining = hdr->caplen;
    const unsigned char *p = packet;

    // Ethernet
    if (remaining < 14) return NULL;
    p += 14;
    remaining -= 14;

    // IP
    int ip_len = parse_ip_header(p, remaining);
    if (ip_len < 0) return NULL;
    p += ip_len;
    remaining -= ip_len;

    // UDP
    int udp_len = parse_udp_header(p, remaining);
    if (udp_len < 0) return NULL;
    p += udp_len;
    remaining -= udp_len;

    // GTP-U
    int gtp_len = parse_gtp_header(p, remaining);
    if (gtp_len < 0) return NULL;
    p += gtp_len;
    remaining -= gtp_len;

    // Inneres IP
    int inner_ip_len = parse_ip_header(p, remaining);
    if (inner_ip_len < 0) return NULL;
    p += inner_ip_len;
    remaining -= inner_ip_len;

    // Inneres UDP
    int inner_udp_len = parse_udp_header(p, remaining);
    if (inner_udp_len < 0) return NULL;
    p += inner_udp_len;
    remaining -= inner_udp_len;

    if (remaining == 0) {
        *payload_len = 0;
        return NULL;
    }

    unsigned char *pl = malloc(remaining);
    if (!pl) return NULL;
    memcpy(pl, p, remaining);
    *payload_len = remaining;
    return pl;
}

/**
 * Extrahiert die Payload aus einem N6-Paket.
 * @param packet Zeiger auf die Paketdaten.
 * @param hdr Paketmetadaten (pcap Header).
 * @param payload_len Zeiger zum Speichern der extrahierten Payload-Länge.
 * @return Zeiger auf die extrahierte Payload bei Erfolg, NULL bei Fehler.
 */
static unsigned char* extract_payload_n6(const u_char *packet, const struct pcap_pkthdr *hdr, size_t *payload_len) {
    size_t remaining = hdr->caplen;
    const unsigned char *p = packet;

    // IP
    int ip_len = parse_ip_header(p, remaining);
    if (ip_len < 0) return NULL;
    p += ip_len;
    remaining -= ip_len;

    // UDP
    int udp_len = parse_udp_header(p, remaining);
    if (udp_len < 0) return NULL;
    p += udp_len;
    remaining -= udp_len;

    if (remaining == 0) {
        *payload_len = 0;
        return NULL;
    }

    unsigned char *pl = malloc(remaining);
    if (!pl) return NULL;
    memcpy(pl, p, remaining);
    *payload_len = remaining;
    return pl;
}

/**
 * Fügt ein N3-Paket in die Hashmap ein basierend auf seinem Payload-Hash.
 * @param payload Zeiger auf die Paket-Payload.
 * @param len Länge der Paket-Payload.
 * @param ts Timestamp des Pakets.
 */
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
    total_n3_payload += len; // Gesamt N3-Payload erhöhen
    pthread_mutex_unlock(&lock);
}

/**
 * Versucht, ein N6-Paket mit einem N3-Paket in der Hashmap zu matchen.
 * @param payload Zeiger auf die N6-Paket-Payload.
 * @param len Länge der N6-Paket-Payload.
 * @param ts_n6 Timestamp des N6-Pakets.
 */
static void match_n6_packet(const unsigned char *payload, size_t len, const struct timeval *ts_n6) {
    unsigned int key = simple_hash(payload, len);

    pthread_mutex_lock(&lock);
    packet_entry_t *prev = NULL;
    packet_entry_t *curr = hashmap[key].head;

    while (curr) {
        if (curr->payload_len == len && memcmp(curr->payload, payload, len) == 0) {
            struct timeval diff;
            timersub(ts_n6, &curr->timestamp, &diff);
            double latency_ms = diff.tv_sec * 1000.0 + diff.tv_usec / 1000.0;

            if (prev) {
                prev->next = curr->next;
            } else {
                hashmap[key].head = curr->next;
            }

            matched_packets++;
            sum_latency += latency_ms;
            sum_latency_sq += (latency_ms * latency_ms);
            latency_count++;
            sum_matched_payload += len;

            free(curr->payload);
            free(curr);
            pthread_mutex_unlock(&lock);
            return;
        }
        prev = curr;
        curr = curr->next;
    }
    pthread_mutex_unlock(&lock);
}

/**
 * Cleanup-Thread-Funktion zum Entfernen abgelaufener Pakete aus der Hashmap.
 * @param arg Unbenutzter Parameter.
 * @return NULL.
 */
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

// Sekundenintervall-Statistiken speichern
typedef struct {
    double elapsed;
    int total_n3_packets;
    int total_n6_packets;
    int matched_packets;
    int lost_packets;
    size_t total_n3_payload;
    size_t sum_matched_payload;
} second_stats_t;

static second_stats_t *stats_per_second = NULL;
static int stats_count = 0;
static int stats_alloc = 0;

/**
 * Nimmt aktuelle Statistiken auf (einmal pro Sekunde) für Durchsatz- und Latenzanalyse.
 */
static void record_stats() {
    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (now.tv_sec - start_time.tv_sec) + (now.tv_usec - start_time.tv_usec)/1000000.0;
    if (stats_count == stats_alloc) {
        stats_alloc = stats_alloc == 0 ? 128 : stats_alloc*2;
        stats_per_second = realloc(stats_per_second, stats_alloc * sizeof(second_stats_t));
        if (!stats_per_second) {
            fprintf(stderr, "Fehler beim Realloc der stats_per_second\n");
            exit(1);
        }
    }
    pthread_mutex_lock(&lock);
    stats_per_second[stats_count].elapsed = elapsed;
    stats_per_second[stats_count].total_n3_packets = total_n3_packets;
    stats_per_second[stats_count].total_n6_packets = total_n6_packets;
    stats_per_second[stats_count].matched_packets = matched_packets;
    stats_per_second[stats_count].lost_packets = lost_packets;
    stats_per_second[stats_count].total_n3_payload = total_n3_payload;
    stats_per_second[stats_count].sum_matched_payload = sum_matched_payload;
    pthread_mutex_unlock(&lock);
    stats_count++;
}

/**
 * Callback-Funktion zum Verarbeiten von N3-Paketen während der Live-Erfassung.
 * @param user Unbenutzter Parameter.
 * @param h Paketmetadaten (pcap Header).
 * @param bytes Zeiger auf die Paketdaten.
 */
void callback_n3(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    size_t payload_len;
    unsigned char *pl = extract_payload_n3(bytes, h, &payload_len);
    if (!pl || payload_len == 0) {
        if (pl) free(pl);
        return;
    }
    insert_n3_packet(pl, payload_len, &h->ts);
    // Optional: Debugging-Ausgabe
    // printf("N3: Paket eingefügt, Payload-Länge: %zu Bytes\n", payload_len);
    free(pl);
}

/**
 * Callback-Funktion zum Verarbeiten von N6-Paketen während der Live-Erfassung.
 * @param user Unbenutzter Parameter.
 * @param h Paketmetadaten (pcap Header).
 * @param bytes Zeiger auf die Paketdaten.
 */
void callback_n6(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    size_t payload_len;
    unsigned char *pl = extract_payload_n6(bytes, h, &payload_len);
    if (!pl || payload_len == 0) {
        if (pl) free(pl);
        return;
    }
    pthread_mutex_lock(&lock);
    total_n6_packets++;
    pthread_mutex_unlock(&lock);
    match_n6_packet(pl, payload_len, &h->ts);
    // Optional: Debugging-Ausgabe
    // printf("N6: Paket verarbeitet, Payload-Länge: %zu Bytes\n", payload_len);
    free(pl);
}

/**
 * Hauptfunktion zur Initialisierung der Paketerfassung und des Überwachungsprozesses.
 * @param argc Argumentanzahl.
 * @param argv Argumentvektor.
 * @return 0 bei Erfolg, sonst Fehlercode.
 */
int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle_n3, *handle_n6;
    struct bpf_program fp_n3; 
    struct bpf_program fp_n6; 

    // Signal-Handler für SIGINT setzen
    signal(SIGINT, handle_sigint);
    gettimeofday(&start_time, NULL);

    // N3 Interface: host 10.2.2.154, nur Uplink (src host)
    handle_n3 = pcap_open_live("ens18", BUFSIZ, 1, 1000, errbuf);
    if (!handle_n3) {
        fprintf(stderr, "Fehler beim pcap_open_live N3: %s\n", errbuf);
        return 1;
    }
    if (pcap_compile(handle_n3, &fp_n3, "src host 10.2.2.154 and udp port 2152", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Fehler beim pcap_compile N3: %s\n", pcap_geterr(handle_n3));
        pcap_close(handle_n3);
        return 1;
    }
    if (pcap_setfilter(handle_n3, &fp_n3) == -1) {
        fprintf(stderr, "Fehler beim pcap_setfilter N3: %s\n", pcap_geterr(handle_n3));
        pcap_freecode(&fp_n3);
        pcap_close(handle_n3);
        return 1;
    }
    pcap_freecode(&fp_n3);

    // N6 Interface: host 10.2.2.157, nur Uplink (dst host)
    handle_n6 = pcap_open_live("upfgtp", BUFSIZ, 1, 1000, errbuf);
    if (!handle_n6) {
        fprintf(stderr, "Fehler beim pcap_open_live N6: %s\n", errbuf);
        pcap_close(handle_n3);
        return 1;
    }

    if (pcap_compile(handle_n6, &fp_n6, "dst host 10.2.2.157 and udp port 5201", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Fehler beim pcap_compile N6: %s\n", pcap_geterr(handle_n6));
        pcap_close(handle_n3);
        pcap_close(handle_n6);
        return 1;
    }
    if (pcap_setfilter(handle_n6, &fp_n6) == -1) {
        fprintf(stderr, "Fehler beim pcap_setfilter N6: %s\n", pcap_geterr(handle_n6));
        pcap_freecode(&fp_n6);
        pcap_close(handle_n3);
        pcap_close(handle_n6);
        return 1;
    }
    pcap_freecode(&fp_n6);

    // Cleanup-Thread starten
    pthread_t cleanup_thread;
    if (pthread_create(&cleanup_thread, NULL, cleanup_thread_func, NULL) != 0) {
        fprintf(stderr, "Fehler beim Erstellen des Cleanup-Threads.\n");
        pcap_close(handle_n3);
        pcap_close(handle_n6);
        return 1;
    }

    // Non-Blockierender Modus setzen
    if (pcap_setnonblock(handle_n3, 1, errbuf) == -1) {
        fprintf(stderr, "Fehler beim pcap_setnonblock N3: %s\n", errbuf);
    }
    if (pcap_setnonblock(handle_n6, 1, errbuf) == -1) {
        fprintf(stderr, "Fehler beim pcap_setnonblock N6: %s\n", errbuf);
    }

    // Hauptloop: alle 100 ms Polling und jede Sekunde Statistiken aufzeichnen
    while (running) {
        pcap_dispatch(handle_n3, -1, callback_n3, NULL);
        pcap_dispatch(handle_n6, -1, callback_n6, NULL);
        usleep(100000); // alle 100 ms Polling

        static double last_sec = 0;
        struct timeval now;
        gettimeofday(&now, NULL);
        double elapsed = (now.tv_sec - start_time.tv_sec) + (now.tv_usec - start_time.tv_usec)/1000000.0;
        if (floor(elapsed) > last_sec) {
            last_sec = floor(elapsed);
            record_stats();
        }
    }

    // Cleanup-Thread beenden
    pthread_cancel(cleanup_thread);
    pthread_join(cleanup_thread, NULL);

    // Letzte Statistiken aufnehmen
    record_stats();

    struct timeval end_time;
    gettimeofday(&end_time, NULL);
    double total_elapsed = (end_time.tv_sec - start_time.tv_sec) +
                           (end_time.tv_usec - start_time.tv_usec)/1000000.0;
    if (total_elapsed <= 0) total_elapsed = 1.0;

    double packet_loss_rate = 0.0;
    if (total_n3_packets > 0) {
        packet_loss_rate = (double)lost_packets / (double)total_n3_packets;
    }

    double avg_latency = 0.0;
    double jitter = 0.0;
    if (latency_count > 0) {
        avg_latency = sum_latency / latency_count;
        double mean = avg_latency;
        double mean_sq = sum_latency_sq / latency_count;
        double variance = mean_sq - (mean * mean);
        if (variance < 0) variance = 0;
        jitter = sqrt(variance);
    }

    double matched_throughput = 0.0; 
    if (total_elapsed > 0) {
        matched_throughput = sum_matched_payload / total_elapsed; // B/s
    }

    double n3_throughput = 0.0;
    if (total_elapsed > 0) {
        n3_throughput = total_n3_payload / total_elapsed; // B/s
    }

    printf("\n==== Ergebnisse ====\n");
    printf("Gesamte Messzeit: %.2f s\n", total_elapsed);
    printf("N3 Pakete: %d\n", total_n3_packets);
    printf("N6 Pakete: %d\n", total_n6_packets);
    printf("Gematchte Pakete: %d\n", matched_packets);
    printf("Verlorene Pakete: %d\n", lost_packets);
    printf("Paketverlustrate: %.2f %%\n", packet_loss_rate*100.0);
    printf("Durchschnittliche Latenz: %.2f ms\n", avg_latency);
    printf("Jitter: %.2f ms\n", jitter);
    printf("Gematchter Durchsatz: %.2f B/s (ca. %.2f Mbit/s)\n", matched_throughput, matched_throughput*8/1e6);
    printf("N3 Durchsatz: %.2f B/s (ca. %.2f Mbit/s)\n", n3_throughput, n3_throughput*8/1e6);
    printf("====================\n");

    // CSV schreiben (Sekundenintervall-Daten)
    FILE *fp_csv = fopen("results.csv", "w");
    if (fp_csv) {
        fprintf(fp_csv, "time_s,total_n3_packets,total_n6_packets,matched_packets,lost_packets,total_n3_payload,sum_matched_payload,n3_throughput_Bps,matched_throughput_Bps\n");
        for (int i = 0; i < stats_count; i++) {
            double dt = (i == 0) ? stats_per_second[i].elapsed : (stats_per_second[i].elapsed - stats_per_second[i-1].elapsed);
            // Durchsatz für dieses Intervall berechnen:
            int delta_n3_packets = (i == 0) ? stats_per_second[i].total_n3_packets : (stats_per_second[i].total_n3_packets - stats_per_second[i-1].total_n3_packets);
            int delta_n6_packets = (i == 0) ? stats_per_second[i].total_n6_packets : (stats_per_second[i].total_n6_packets - stats_per_second[i-1].total_n6_packets);
            int delta_matched = (i == 0) ? stats_per_second[i].matched_packets : (stats_per_second[i].matched_packets - stats_per_second[i-1].matched_packets);
            int delta_lost = (i == 0) ? stats_per_second[i].lost_packets : (stats_per_second[i].lost_packets - stats_per_second[i-1].lost_packets);
            size_t delta_n3_payload = (i == 0) ? stats_per_second[i].total_n3_payload : (stats_per_second[i].total_n3_payload - stats_per_second[i-1].total_n3_payload);
            size_t delta_matched_payload = (i == 0) ? stats_per_second[i].sum_matched_payload : (stats_per_second[i].sum_matched_payload - stats_per_second[i-1].sum_matched_payload);

            double interval_n3_throughput = (dt > 0) ? (double)delta_n3_payload / dt : 0.0;
            double interval_matched_throughput = (dt > 0) ? (double)delta_matched_payload / dt : 0.0;

            fprintf(fp_csv, "%.2f,%d,%d,%d,%d,%zu,%zu,%.2f,%.2f\n",
                    stats_per_second[i].elapsed,
                    stats_per_second[i].total_n3_packets,
                    stats_per_second[i].total_n6_packets,
                    stats_per_second[i].matched_packets,
                    stats_per_second[i].lost_packets,
                    stats_per_second[i].total_n3_payload,
                    stats_per_second[i].sum_matched_payload,
                    interval_n3_throughput,
                    interval_matched_throughput);
        }
        fclose(fp_csv);
    } else {
        fprintf(stderr, "Konnte results.csv nicht öffnen.\n");
    }

    pcap_close(handle_n3);
    pcap_close(handle_n6);
    free(stats_per_second);
    return 0;
}
