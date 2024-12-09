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
static size_t total_n3_payload = 0; 

static struct timeval start_time;
static volatile int running = 1;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

// Einfache Hashfunktion
static unsigned int simple_hash(const unsigned char *data, size_t len) {
    unsigned int hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash % HASHMAP_SIZE;
}

// Dynamische Parsing-Funktionen

// IP-Header parsen (IPv4), keine Optionen außer IHL, kein VLAN etc.
static int parse_ip_header(const unsigned char *data, size_t len) {
    if (len < 20) return -1;
    // Achtung: Prüfen ob wirklich IPv4! (Version = 4)
    unsigned char version = (data[0] & 0xF0) >> 4;
    if (version != 4) return -1;

    unsigned char ihl = data[0] & 0x0F; 
    int ip_header_len = ihl * 4;
    if (ip_header_len < 20 || ip_header_len > (int)len) return -1;

    // Optional: Weitere Checks auf Total Length, etc. mittels data[2..3]
    return ip_header_len;
}

// TCP-Header parsen, inklusive Optionen
static int parse_tcp_header(const unsigned char *data, size_t len) {
    if (len < 20) return -1; 
    unsigned char data_offset = (data[12] & 0xF0) >> 4; 
    int tcp_header_len = data_offset * 4;
    if (tcp_header_len < 20 || tcp_header_len > (int)len) return -1;
    return tcp_header_len;
}

// GTP-U Header parsen
// Dieser Code geht von GTPv1-U aus, MsgType = 0xFF für T-PDU
// Passen Sie dies an Ihre GTP-Header an, falls Extensions oder andere MsgTypes auftauchen
static int parse_gtp_header(const unsigned char *data, size_t len) {
    if (len < 8) return -1;
    unsigned char flags = data[0];
    int e_flag = (flags & 0x04) >> 2;
    // length-Feld könnte genutzt werden, um zu prüfen, ob genug Daten vorhanden sind
    // TEID lesen, etc. 

    int offset = 8;
    if (e_flag) {
        // GTP Extension Headers parsen
        // Im echten Traffic per Wireshark analysieren, hier nur Beispiel:
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

// Payload-Extraktion für N3:
// Entfernen Sie alle Filter, um gesamten Traffic zu sehen.
// Falls VLAN oder MPLS tags vorhanden, müssen Sie diese ebenfalls entfernen.
// Falls IPv6-Traffic existiert, brauchen Sie ein parse_ipv6_header.
// Wenn UDP nicht der Träger ist oder andere Header existieren (z.B. GRE, VXLAN),
// müssen diese berücksichtigt werden.
static unsigned char* extract_payload_n3(const u_char *packet, const struct pcap_pkthdr *hdr, size_t *payload_len) {
    size_t remaining = hdr->caplen;
    const unsigned char *p = packet;

    // Ethernet-Header annehmen (14 Bytes)
    // Falls VLAN: zusätzliche 4 Bytes.
    // Prüfen Sie mit Wireshark, ob VLAN-Tags existieren, dann len+4 usw.
    if (remaining < 14) return NULL;
    p += 14;
    remaining -= 14;

    // Jetzt IP (Outer IP)
    int ip_len = parse_ip_header(p, remaining);
    if (ip_len < 0) return NULL;
    p += ip_len;
    remaining -= ip_len;

    // UDP (8 Bytes) - falls GTP über UDP läuft
    // Prüfen Sie in Wireshark, ob GTP über UDP (Port 2152) läuft
    if (remaining < 8) return NULL;
    p += 8;
    remaining -= 8;

    // GTP
    int gtp_len = parse_gtp_header(p, remaining);
    if (gtp_len < 0) return NULL;
    p += gtp_len;
    remaining -= gtp_len;

    // Inner IP (vom UE)
    int inner_ip_len = parse_ip_header(p, remaining);
    if (inner_ip_len < 0) return NULL;
    p += inner_ip_len;
    remaining -= inner_ip_len;

    // TCP
    int tcp_len = parse_tcp_header(p, remaining);
    if (tcp_len < 0) return NULL;
    p += tcp_len;
    remaining -= tcp_len;

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

// Payload-Extraktion für N6 ist ähnlich, aber kein GTP.
// Falls VLAN oder IPv6? Anpassen!
// Hier kein GTP, direkt IP + TCP.
static unsigned char* extract_payload_n6(const u_char *packet, const struct pcap_pkthdr *hdr, size_t *payload_len) {
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

    // TCP
    int tcp_len = parse_tcp_header(p, remaining);
    if (tcp_len < 0) return NULL;
    p += tcp_len;
    remaining -= tcp_len;

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
    total_n3_payload += len;
    pthread_mutex_unlock(&lock);
}

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

static void record_stats() {
    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (now.tv_sec - start_time.tv_sec) + (now.tv_usec - start_time.tv_usec)/1000000.0;
    if (stats_count == stats_alloc) {
        stats_alloc = stats_alloc == 0 ? 128 : stats_alloc*2;
        stats_per_second = realloc(stats_per_second, stats_alloc * sizeof(second_stats_t));
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

void callback_n3(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    size_t payload_len;
    unsigned char *pl = extract_payload_n3(bytes, h, &payload_len);
    if (!pl || payload_len == 0) {
        if (pl) free(pl);
        return;
    }
    insert_n3_packet(pl, payload_len, &h->ts);
    free(pl);
}

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
    free(pl);
}

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle_n3, *handle_n6;

    signal(SIGINT, handle_sigint);
    gettimeofday(&start_time, NULL);

    // N3 Interface, ohne Filter
    handle_n3 = pcap_open_live("ens18", BUFSIZ, 1, 1000, errbuf);
    if (!handle_n3) {
        fprintf(stderr, "Fehler pcap_open_live N3: %s\n", errbuf);
        return 1;
    }

    // N6 Interface, ohne Filter
    handle_n6 = pcap_open_live("upfgtp", BUFSIZ, 1, 1000, errbuf);
    if (!handle_n6) {
        fprintf(stderr, "Fehler pcap_open_live N6: %s\n", errbuf);
        return 1;
    }

    pthread_t cleanup_thread;
    pthread_create(&cleanup_thread, NULL, cleanup_thread_func, NULL);

    if (pcap_setnonblock(handle_n3, 1, errbuf) == -1) {
        fprintf(stderr, "Fehler pcap_setnonblock N3: %s\n", errbuf);
    }
    if (pcap_setnonblock(handle_n6, 1, errbuf) == -1) {
        fprintf(stderr, "Fehler pcap_setnonblock N6: %s\n", errbuf);
    }

    double last_sec = 0;
    while (running) {
        pcap_dispatch(handle_n3, -1, callback_n3, NULL);
        pcap_dispatch(handle_n6, -1, callback_n6, NULL);
        usleep(100000);
        struct timeval now;
        gettimeofday(&now, NULL);
        double elapsed = (now.tv_sec - start_time.tv_sec) + (now.tv_usec - start_time.tv_usec)/1000000.0;
        if (floor(elapsed) > last_sec) {
            last_sec = floor(elapsed);
            record_stats();
        }
    }

    pthread_cancel(cleanup_thread);
    pthread_join(cleanup_thread, NULL);
    record_stats();

    struct timeval end_time;
    gettimeofday(&end_time, NULL);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) +
                     (end_time.tv_usec - start_time.tv_usec)/1000000.0;
    if (elapsed <= 0) elapsed = 1.0;

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

    double matched_throughput = (elapsed > 0) ? sum_matched_payload / elapsed : 0.0;
    double normal_throughput = (elapsed > 0) ? total_n3_payload / elapsed : 0.0;

    printf("\n==== Ergebnisse ====\n");
    printf("Gesamte Messdauer: %.2f s\n", elapsed);
    printf("N3 Packete: %d\n", total_n3_packets);
    printf("N6 Packete: %d\n", total_n6_packets);
    printf("Matched Packets: %d\n", matched_packets);
    printf("Lost Packets: %d\n", lost_packets);
    printf("Packet Loss Rate: %.2f %%\n", packet_loss_rate*100.0);
    printf("Average Latency: %.2f ms\n", avg_latency);
    printf("Jitter: %.2f ms\n", jitter);
    printf("Matched Throughput: %.2f B/s (ca. %.2f Mbit/s)\n", matched_throughput, matched_throughput*8/1e6);
    printf("Normal Throughput (N3 gesamt): %.2f B/s (ca. %.2f Mbit/s)\n", normal_throughput, normal_throughput*8/1e6);
    printf("====================\n");

    FILE *fp_csv = fopen("results.csv", "w");
    if (fp_csv) {
        fprintf(fp_csv, "time_s,total_n3_packets,total_n6_packets,matched_packets,lost_packets,total_n3_payload,sum_matched_payload,normal_throughput_Bps,matched_throughput_Bps\n");
        for (int i = 0; i < stats_count; i++) {
            double dt = (i == 0) ? stats_per_second[i].elapsed : (stats_per_second[i].elapsed - stats_per_second[i-1].elapsed);
            int delta_n3_packets = (i == 0) ? stats_per_second[i].total_n3_packets : (stats_per_second[i].total_n3_packets - stats_per_second[i-1].total_n3_packets);
            int delta_n6_packets = (i == 0) ? stats_per_second[i].total_n6_packets : (stats_per_second[i].total_n6_packets - stats_per_second[i-1].total_n6_packets);
            int delta_matched = (i == 0) ? stats_per_second[i].matched_packets : (stats_per_second[i].matched_packets - stats_per_second[i-1].matched_packets);
            int delta_lost = (i == 0) ? stats_per_second[i].lost_packets : (stats_per_second[i].lost_packets - stats_per_second[i-1].lost_packets);
            size_t delta_n3_payload = (i == 0) ? stats_per_second[i].total_n3_payload : (stats_per_second[i].total_n3_payload - stats_per_second[i-1].total_n3_payload);
            size_t delta_matched_payload = (i == 0) ? stats_per_second[i].sum_matched_payload : (stats_per_second[i].sum_matched_payload - stats_per_second[i-1].sum_matched_payload);

            double interval_normal_throughput = (dt > 0) ? (double)delta_n3_payload / dt : 0.0;
            double interval_matched_throughput = (dt > 0) ? (double)delta_matched_payload / dt : 0.0;

            fprintf(fp_csv, "%.2f,%d,%d,%d,%d,%zu,%zu,%.2f,%.2f\n",
                    stats_per_second[i].elapsed,
                    stats_per_second[i].total_n3_packets,
                    stats_per_second[i].total_n6_packets,
                    stats_per_second[i].matched_packets,
                    stats_per_second[i].lost_packets,
                    stats_per_second[i].total_n3_payload,
                    stats_per_second[i].sum_matched_payload,
                    interval_normal_throughput,
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
