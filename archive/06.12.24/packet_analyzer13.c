/**
 * monitoring_module.c
 * A program to monitor and analyze packet traffic using raw sockets.
 *
 * This program analyzes GTP-U packet flows on N3 and N6 interfaces in a 5G network.
 * It matches corresponding packets based on GTP-U TEID, calculates latency, jitter, throughput, and loss rates,
 * and logs these metrics in real time.
 *
 * Features:
 * - Packet extraction and parsing for N3 and N6 packets.
 * - Hashmap-based packet matching using GTP-U TEID with timeout handling.
 * - Periodic statistics collection for throughput and latency analysis.
 * - CSV logging for later review.
 * - Configurable inner transport protocol (TCP or UDP).
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
#include <getopt.h>
#include <ctype.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// Wie bisher
#define HASHMAP_SIZE 1024
#define TIMEOUT_SECONDS 5
#define CLEANUP_INTERVAL_MS 500

typedef struct packet_entry {
    struct packet_entry *next;
    unsigned int teid;          // GTP-U TEID als Schlüssel
    struct in_addr src_ip;
    struct in_addr dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
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

// Neu: Gesamt N3-Payload erfassen für "normalen Durchsatz"
static size_t total_n3_payload = 0; 

static struct timeval start_time;
static volatile int running = 1;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

// Inneres Transportprotokoll (6 für TCP, 17 für UDP), Standard UDP
static int inner_transport_protocol = 17;

// Link-Layer Typen für N3 und N6
static int datalink_n3 = 0;
static int datalink_n6 = 0;

// Funktionsprototypen
static int parse_tcp_header(const unsigned char *data, size_t len);
static int parse_udp_header(const unsigned char *data, size_t len);
static int parse_ip_header(const unsigned char *data, size_t len, unsigned char *protocol);
static int parse_gtp_header(const unsigned char *data, size_t len, unsigned int *teid);
static int extract_flow_info_n3(const u_char *packet, const struct pcap_pkthdr *hdr, unsigned int *teid, struct in_addr *src_ip, struct in_addr *dst_ip, unsigned short *src_port, unsigned short *dst_port);
static unsigned int hash_flow(struct in_addr src_ip, struct in_addr dst_ip, unsigned short src_port, unsigned short dst_port);
static void insert_n3_packet(unsigned int teid, struct in_addr src_ip, struct in_addr dst_ip, unsigned short src_port, unsigned short dst_port, const struct timeval *ts);
static void match_n6_packet(struct in_addr src_ip, struct in_addr dst_ip, unsigned short src_port, unsigned short dst_port, const struct timeval *ts_n6);
static void *cleanup_thread_func(void *arg);
static void record_stats();
static void callback_n3(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
static void callback_n6(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
static void print_usage(const char *prog_name);

/**
 * Signal handler to gracefully stop the program on SIGINT.
 * @param sig Signal number (unused).
 */
static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

/**
 * Calculates a simple hash for a given TEID.
 * @param teid GTP-U TEID.
 * @return A hash value within the range [0, HASHMAP_SIZE-1].
 */
static unsigned int hash_teid(unsigned int teid) {
    return teid % HASHMAP_SIZE;
}

/**
 * Calculates a hash based on the 4-tuple (src_ip, dst_ip, src_port, dst_port).
 * @param src_ip Source IP address.
 * @param dst_ip Destination IP address.
 * @param src_port Source port.
 * @param dst_port Destination port.
 * @return A hash value within the range [0, HASHMAP_SIZE-1].
 */
static unsigned int hash_flow(struct in_addr src_ip, struct in_addr dst_ip, unsigned short src_port, unsigned short dst_port) {
    unsigned int hash = 5381;
    hash = ((hash << 5) + hash) + src_ip.s_addr;
    hash = ((hash << 5) + hash) + dst_ip.s_addr;
    hash = ((hash << 5) + hash) + src_port;
    hash = ((hash << 5) + hash) + dst_port;
    return hash % HASHMAP_SIZE;
}

/**
 * Parses the IP header of a packet to determine its length and extract the protocol.
 * @param data Pointer to the packet data.
 * @param len Length of the packet data.
 * @param protocol Pointer to store the IP protocol number.
 * @return Length of the IP header on success, -1 on failure.
 */
static int parse_ip_header(const unsigned char *data, size_t len, unsigned char *protocol) {
    if (len < 20) return -1;
    unsigned char ihl = data[0] & 0x0F; 
    int ip_header_len = ihl * 4;
    if (ip_header_len < 20 || ip_header_len > (int)len) return -1;
    *protocol = data[9]; // Das Protokollfeld im IPv4-Header
    return ip_header_len;
}

/**
 * Parses the TCP header of a packet to determine its length.
 * @param data Pointer to the TCP header data.
 * @param len Length of the remaining packet data.
 * @return Length of the TCP header on success, -1 on failure.
 */
static int parse_tcp_header(const unsigned char *data, size_t len) {
    if (len < 20) return -1; 
    unsigned char data_offset = (data[12] & 0xF0) >> 4; 
    int tcp_header_len = data_offset * 4;
    if (tcp_header_len < 20 || tcp_header_len > (int)len) return -1;
    return tcp_header_len;
}

/**
 * Parses the UDP header of a packet. UDP header is always 8 bytes.
 * @param data Pointer to the UDP header data.
 * @param len Length of the remaining packet data.
 * @return Length of the UDP header on success, -1 on failure.
 */
static int parse_udp_header(const unsigned char *data, size_t len) {
    if (len < 8) return -1;
    return 8; 
}

/**
 * Parses the GTP-U header of a packet to extract the TEID and determine its length.
 * @param data Pointer to the GTP header data.
 * @param len Length of the remaining packet data.
 * @param teid Pointer to store the extracted TEID.
 * @return Length of the GTP header on success, -1 on failure.
 */
static int parse_gtp_header(const unsigned char *data, size_t len, unsigned int *teid) {
    if (len < 8) return -1;
    unsigned char flags = data[0];
    int e_flag = (flags & 0x04) >> 2;
    int offset = 8; 

    // TEID ist in den Bytes 4-7 des GTP-U-Headers
    *teid = ntohl(*(unsigned int *)(data + 4));

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
            if ((int)len <= offset) return -1; // Verhindert Out-of-Bounds
            next_ext_type = data[offset]; 
            offset++;
        }
    }
    return offset;
}

/**
 * Extracts Flow Information from an N3 packet.
 * @param packet Pointer to the packet data.
 * @param hdr Packet metadata (pcap header).
 * @param teid Pointer to store the extracted TEID.
 * @param src_ip Pointer to store die Quell-IP.
 * @param dst_ip Pointer to store die Ziel-IP.
 * @param src_port Pointer to store den Quell-Port.
 * @param dst_port Pointer to store den Ziel-Port.
 * @return 0 on success, -1 on failure.
 */
static int extract_flow_info_n3(const u_char *packet, const struct pcap_pkthdr *hdr, unsigned int *teid, struct in_addr *src_ip, struct in_addr *dst_ip, unsigned short *src_port, unsigned short *dst_port) {
    size_t remaining = hdr->caplen;
    const unsigned char *p = packet;

    // Link-Layer Header
    size_t link_header_len = 0;
    if (datalink_n3 == DLT_EN10MB) { // Ethernet
        link_header_len = 14;
    } else if (datalink_n3 == DLT_RAW) { // Raw IP
        link_header_len = 0;
    } else {
        // Nicht unterstützter Link-Layer-Typ
        return -1;
    }

    if (remaining < link_header_len) {
        return -1;
    }
    p += link_header_len;
    remaining -= link_header_len;

    // IP
    unsigned char outer_protocol;
    int ip_len = parse_ip_header(p, remaining, &outer_protocol);
    if (ip_len < 0) {
        return -1;
    }

    // Extrahiere Quell- und Ziel-IP
    struct iphdr *ip_hdr = (struct iphdr *)p;
    src_ip->s_addr = ip_hdr->saddr;
    dst_ip->s_addr = ip_hdr->daddr;

    p += ip_len;
    remaining -= ip_len;

    // Äußeres Transportprotokoll muss UDP für GTP-U sein
    if (outer_protocol != 17) { // 17 = UDP
        return -1;
    }

    // Äußere UDP
    int transport_len = parse_udp_header(p, remaining);
    if (transport_len < 0) {
        return -1;
    }

    // Äußere UDP-Header
    struct udphdr *udp_hdr = (struct udphdr *)p;
    *src_port = ntohs(udp_hdr->source);
    *dst_port = ntohs(udp_hdr->dest);

    p += transport_len;
    remaining -= transport_len;

    // GTP-U Header
    unsigned int teid_extracted;
    int gtp_len = parse_gtp_header(p, remaining, &teid_extracted);
    if (gtp_len < 0) {
        return -1;
    }

    p += gtp_len;
    remaining -= gtp_len;

    *teid = teid_extracted;
    return 0;
}

/**
 * Inserts a packet into the hashmap based on its TEID and Flow Information.
 * @param teid GTP-U TEID.
 * @param src_ip Source IP address.
 * @param dst_ip Destination IP address.
 * @param src_port Source port.
 * @param dst_port Destination port.
 * @param ts Timestamp of the packet.
 */
static void insert_n3_packet(unsigned int teid, struct in_addr src_ip, struct in_addr dst_ip, unsigned short src_port, unsigned short dst_port, const struct timeval *ts) {
    unsigned int key = hash_flow(src_ip, dst_ip, src_port, dst_port);

    packet_entry_t *entry = malloc(sizeof(packet_entry_t));
    if (!entry) return;
    entry->teid = teid;
    entry->src_ip = src_ip;
    entry->dst_ip = dst_ip;
    entry->src_port = src_port;
    entry->dst_port = dst_port;
    entry->timestamp = *ts;

    pthread_mutex_lock(&lock);
    entry->next = hashmap[key].head;
    hashmap[key].head = entry;
    total_n3_packets++;
    // Optional: Summe des Payloads könnte auf TEID basieren oder anders gehandhabt werden
    pthread_mutex_unlock(&lock);
}

/**
 * Matches an N6 packet with an N3 packet in the hashmap based on the 4-tuple.
 * @param src_ip Source IP address of N6 packet.
 * @param dst_ip Destination IP address of N6 packet.
 * @param src_port Source port of N6 packet.
 * @param dst_port Destination port of N6 packet.
 * @param ts_n6 Timestamp of the N6 packet.
 */
static void match_n6_packet(struct in_addr src_ip, struct in_addr dst_ip, unsigned short src_port, unsigned short dst_port, const struct timeval *ts_n6) {
    unsigned int key = hash_flow(src_ip, dst_ip, src_port, dst_port);

    pthread_mutex_lock(&lock);
    packet_entry_t *prev = NULL;
    packet_entry_t *curr = hashmap[key].head;

    while (curr) {
        if (curr->src_ip.s_addr == src_ip.s_addr &&
            curr->dst_ip.s_addr == dst_ip.s_addr &&
            curr->src_port == src_port &&
            curr->dst_port == dst_port) {

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
            // sum_matched_payload += len; // Anpassung je nach Bedarf

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
 * Cleanup thread function to remove expired packets from the hashmap.
 * @param arg Unused parameter.
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

// Neu: Sekundenintervall-Statistiken speichern
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
 * Records current statistics (once every second) for throughput and latency analysis.
 */
static void record_stats() {
    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (now.tv_sec - start_time.tv_sec) + (now.tv_usec - start_time.tv_usec)/1000000.0;
    if (stats_count == stats_alloc) {
        stats_alloc = stats_alloc == 0 ? 128 : stats_alloc*2;
        stats_per_second = realloc(stats_per_second, stats_alloc * sizeof(second_stats_t));
        if (!stats_per_second) {
            fprintf(stderr, "Memory allocation failed for stats_per_second\n");
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
 * Callback function for handling N3 packets during live capture.
 * @param user Unused parameter.
 * @param h Packet metadata (pcap header).
 * @param bytes Pointer to the packet data.
 */
void callback_n3(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    unsigned int teid;
    struct in_addr src_ip, dst_ip;
    unsigned short src_port, dst_port;

    if (extract_flow_info_n3(bytes, h, &teid, &src_ip, &dst_ip, &src_port, &dst_port) == 0) {
        // Optional Debugging-Ausgabe
        // printf("N3: TEID=%u, Src IP=%s, Dst IP=%s, Src Port=%u, Dst Port=%u\n",
        //        teid, inet_ntoa(src_ip), inet_ntoa(dst_ip), src_port, dst_port);
        insert_n3_packet(teid, src_ip, dst_ip, src_port, dst_port, &h->ts);
    }
}

/**
 * Callback function für N6-Pakete während der Live-Erfassung.
 * @param user Unused parameter.
 * @param h Packet metadata (pcap header).
 * @param bytes Pointer zu den Paketen Daten.
 */
void callback_n6(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    size_t remaining = h->caplen;
    const unsigned char *p = bytes;

    // Link-Layer Header
    size_t link_header_len = 0;
    if (datalink_n6 == DLT_EN10MB) { // Ethernet
        link_header_len = 14;
    } else if (datalink_n6 == DLT_RAW) { // Raw IP
        link_header_len = 0;
    } else {
        // Nicht unterstützter Link-Layer-Typ
        return;
    }

    if (remaining < link_header_len) {
        return;
    }
    p += link_header_len;
    remaining -= link_header_len;

    // IP
    unsigned char protocol;
    int ip_len = parse_ip_header(p, remaining, &protocol);
    if (ip_len < 0) {
        return;
    }

    struct iphdr *ip_hdr = (struct iphdr *)p;
    struct in_addr src_ip, dst_ip;
    src_ip.s_addr = ip_hdr->saddr;
    dst_ip.s_addr = ip_hdr->daddr;

    p += ip_len;
    remaining -= ip_len;

    // Inneres Transportprotokoll prüfen
    if (protocol != inner_transport_protocol) {
        return;
    }

    // Inneres Transportprotokoll
    unsigned short src_port, dst_port;
    if (inner_transport_protocol == 6) { // TCP
        if (remaining < 20) return; // Mindestgröße für TCP-Header
        struct tcphdr *tcp_hdr = (struct tcphdr *)p;
        src_port = ntohs(tcp_hdr->source);
        dst_port = ntohs(tcp_hdr->dest);
    } else { // UDP
        if (remaining < 8) return; // Mindestgröße für UDP-Header
        struct udphdr *udp_hdr = (struct udphdr *)p;
        src_port = ntohs(udp_hdr->source);
        dst_port = ntohs(udp_hdr->dest);
    }

    // Optional Debugging-Ausgabe
    // printf("N6: Src IP=%s, Dst IP=%s, Src Port=%u, Dst Port=%u\n",
    //        inet_ntoa(src_ip), inet_ntoa(dst_ip), src_port, dst_port);

    // Matching durchführen
    match_n6_packet(src_ip, dst_ip, src_port, dst_port, &h->ts);
}

/**
 * Prints usage information.
 */
void print_usage(const char *prog_name) {
    printf("Usage: %s [-p tcp|udp]\n", prog_name);
    printf("Options:\n");
    printf("  -p, --protocol   Inneres Transportprotokoll: tcp oder udp (Standard: udp)\n");
    printf("  -h, --help       Anzeige dieser Hilfe\n");
}

/**
 * Main function to initialize the packet capture and monitoring process.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success, non-zero on failure.
 */
int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle_n3, *handle_n6;
    struct bpf_program fp_n3; 
    struct bpf_program fp_n6; 

    // Kommandozeilenargumente parsen
    int opt;
    static struct option long_options[] = {
        {"protocol", required_argument, 0, 'p'},
        {"help",     no_argument,       0, 'h'},
        {0,          0,                 0,  0 }
    };

    while ((opt = getopt_long(argc, argv, "p:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                if (strcasecmp(optarg, "tcp") == 0) {
                    inner_transport_protocol = 6;
                } else if (strcasecmp(optarg, "udp") == 0) {
                    inner_transport_protocol = 17;
                } else {
                    fprintf(stderr, "Ungültiges Protokoll: %s\n", optarg);
                    print_usage(argv[0]);
                    return 1;
                }
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    // Anzeige der gewählten Konfiguration
    printf("Gewähltes inneres Transportprotokoll: %s\n", inner_transport_protocol == 6 ? "TCP" : "UDP");

    // Signalhandler registrieren
    signal(SIGINT, handle_sigint);
    gettimeofday(&start_time, NULL);

    // N3 Interface: Filter auf GTP-U (UDP port 2152) setzen
    handle_n3 = pcap_open_live("ens18", BUFSIZ, 1, 1000, errbuf);
    if (!handle_n3) {
        fprintf(stderr, "Error pcap_open_live N3: %s\n", errbuf);
        return 1;
    }

    datalink_n3 = pcap_datalink(handle_n3);
    // printf("N3 Link-Layer-Typ: %d\n", datalink_n3);

    // N3 Filter: GTP-U (UDP port 2152)
    const char *filter_n3 = "udp port 2152";
    if (pcap_compile(handle_n3, &fp_n3, filter_n3, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error pcap_compile N3: %s\n", pcap_geterr(handle_n3));
        pcap_close(handle_n3);
        return 1;
    }
    if (pcap_setfilter(handle_n3, &fp_n3) == -1) {
        fprintf(stderr, "Error pcap_setfilter N3: %s\n", pcap_geterr(handle_n3));
        pcap_freecode(&fp_n3);
        pcap_close(handle_n3);
        return 1;
    }
    pcap_freecode(&fp_n3);

    // N6 Interface: Filter auf iperf3 (UDP port 5201 oder TCP port 5201) setzen
    handle_n6 = pcap_open_live("upfgtp", BUFSIZ, 1, 1000, errbuf);
    if (!handle_n6) {
        fprintf(stderr, "Error pcap_open_live N6: %s\n", errbuf);
        pcap_close(handle_n3);
        return 1;
    }

    datalink_n6 = pcap_datalink(handle_n6);
    // printf("N6 Link-Layer-Typ: %d\n", datalink_n6);

    char filter_n6[256];
    if (inner_transport_protocol == 6) { // TCP
        // Beispiel: TCP Port 5201 (iperf3 standardmäßig verwendet 5201)
        snprintf(filter_n6, sizeof(filter_n6), "port 5201");
    } else { // UDP
        snprintf(filter_n6, sizeof(filter_n6), "port 5201");
    }

    if (pcap_compile(handle_n6, &fp_n6, filter_n6, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error pcap_compile N6: %s\n", pcap_geterr(handle_n6));
        pcap_close(handle_n3);
        pcap_close(handle_n6);
        return 1;
    }
    if (pcap_setfilter(handle_n6, &fp_n6) == -1) {
        fprintf(stderr, "Error pcap_setfilter N6: %s\n", pcap_geterr(handle_n6));
        pcap_freecode(&fp_n6);
        pcap_close(handle_n3);
        pcap_close(handle_n6);
        return 1;
    }
    pcap_freecode(&fp_n6);

    // Start des Cleanup-Threads
    pthread_t cleanup_thread;
    if (pthread_create(&cleanup_thread, NULL, cleanup_thread_func, NULL) != 0) {
        fprintf(stderr, "Fehler beim Erstellen des Cleanup-Threads\n");
        pcap_close(handle_n3);
        pcap_close(handle_n6);
        return 1;
    }

    // Setzen auf non-blocking Mode
    if (pcap_setnonblock(handle_n3, 1, errbuf) == -1) {
        fprintf(stderr, "Error pcap_setnonblock N3: %s\n", errbuf);
    }
    if (pcap_setnonblock(handle_n6, 1, errbuf) == -1) {
        fprintf(stderr, "Error pcap_setnonblock N6: %s\n", errbuf);
    }

    // Hauptschleife: Pcap-Dispatch und Statistiken sammeln
    while (running) {
        int ret_n3 = pcap_dispatch(handle_n3, -1, callback_n3, NULL);
        if (ret_n3 == -1) {
            fprintf(stderr, "Error pcap_dispatch N3: %s\n", pcap_geterr(handle_n3));
            break;
        }

        int ret_n6 = pcap_dispatch(handle_n6, -1, callback_n6, NULL);
        if (ret_n6 == -1) {
            fprintf(stderr, "Error pcap_dispatch N6: %s\n", pcap_geterr(handle_n6));
            break;
        }

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

    // Beenden des Cleanup-Threads
    pthread_cancel(cleanup_thread);
    pthread_join(cleanup_thread, NULL);

    // Letzte Statistikaufzeichnung
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
        double mean_sq = sum_latency_sq / latency_count;
        double variance = mean_sq - (avg_latency * avg_latency);
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

    printf("\n==== Results ====\n");
    printf("Total measuring time: %.2f s\n", total_elapsed);
    printf("N3 Packets: %d\n", total_n3_packets);
    printf("N6 Packets: %d\n", total_n6_packets);
    printf("Matched Packets: %d\n", matched_packets);
    printf("Lost Packets: %d\n", lost_packets);
    printf("Packet Loss Rate: %.2f %%\n", packet_loss_rate*100.0);
    printf("Average Latency: %.2f ms\n", avg_latency);
    printf("Jitter: %.2f ms\n", jitter);
    printf("Matched Throughput: %.2f B/s (ca. %.2f Mbit/s)\n", matched_throughput, matched_throughput*8/1e6);
    printf("N3 Throughput: %.2f B/s (ca. %.2f Mbit/s)\n", n3_throughput, n3_throughput*8/1e6);
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
