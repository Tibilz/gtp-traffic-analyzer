#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <uthash.h>
#include <math.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>

// Konfigurationsstruktur
struct config {
    char n3_interface[32];
    char n6_interface[32];
    char source_ip[16];
    uint16_t gtp_port;
    uint32_t timeout_sec;
    uint32_t cleanup_interval_ms;
} config = {
    .n3_interface = "ens18",
    .n6_interface = "upfgtp",
    .source_ip = "10.2.2.154",
    .gtp_port = 2152,
    .timeout_sec = 10,              // Timeout auf 10 Sekunden gesetzt
    .cleanup_interval_ms = 500
};

#define LOG_ERROR   0
#define LOG_WARNING 1
#define LOG_INFO    2
#define LOG_DEBUG   3

// Aktuelles Log-Level (kann über Kommandozeile gesetzt werden)
int current_log_level = LOG_DEBUG;

// Logging-Makro
#define LOG(level, fmt, ...) \
    do { \
        if (level <= current_log_level) { \
            fprintf(stderr, "%s:%d: [%s] " fmt "\n", \
                __func__, __LINE__, \
                (level == LOG_ERROR) ? "ERROR" : \
                (level == LOG_WARNING) ? "WARN" : \
                (level == LOG_INFO) ? "INFO" : "DEBUG", \
                ##__VA_ARGS__); \
        } \
    } while (0)

// GTPv1-Header-Struktur
struct gtpv1_header {
    uint8_t flags;
    uint8_t message_type;
    uint16_t length;
    uint32_t teid;
} __attribute__((packed));

// Struktur für einzelne Pakete
struct packet_info {
    struct timeval timestamp;
    uint8_t *payload;
    size_t payload_len;
    struct packet_info *next;
};

// Hash-Tabellen-Eintrag
struct hash_entry {
    uint32_t hash;           // Schlüssel für uthash
    struct packet_info *packets;
    UT_hash_handle hh;
};

// Struktur für Metriken
struct metrics {
    uint64_t total_n3;
    uint64_t total_n6;
    uint64_t matched;
    uint64_t lost;
    double total_latency;
    double total_jitter;
    double last_latency;
} stats = {0};

// Globale Variablen
struct hash_entry *packets_table = NULL;
pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;
FILE *csv_file = NULL;
volatile sig_atomic_t keep_running = 1;

// Variable zur Verfolgung der letzten Paketempfangszeit
struct timeval last_packet_time;
pthread_mutex_t last_packet_mutex = PTHREAD_MUTEX_INITIALIZER;

// Funktion zur Behandlung von Terminationssignalen
void handle_signal(int sig) {
    LOG(LOG_INFO, "Received signal %d, terminating...", sig);
    keep_running = 0;
}

// Funktion zur Freigabe von packet_info
static void free_packet_info(struct packet_info *pinfo) {
    if (pinfo) {
        free(pinfo->payload);
        free(pinfo);
    }
}

// Funktion zur Allokierung und Initialisierung von packet_info
static int allocate_packet_info(struct packet_info **pinfo, const u_char *payload, size_t payload_len) {
    *pinfo = calloc(1, sizeof(struct packet_info));
    if (!*pinfo) {
        LOG(LOG_ERROR, "Memory allocation failed for packet_info: %s", strerror(errno));
        return -1;
    }

    (*pinfo)->payload = malloc(payload_len);
    if (!(*pinfo)->payload) {
        LOG(LOG_ERROR, "Memory allocation failed for payload: %s", strerror(errno));
        free(*pinfo);
        *pinfo = NULL;
        return -1;
    }

    memcpy((*pinfo)->payload, payload, payload_len);
    (*pinfo)->payload_len = payload_len;
    gettimeofday(&(*pinfo)->timestamp, NULL);
    (*pinfo)->next = NULL;
    return 0;
}

// DJB2 Hash-Funktion
uint32_t hash_payload(const uint8_t *payload, size_t len) {
    if (!payload || len == 0) {
        LOG(LOG_WARNING, "Invalid payload or length");
        return 0;
    }

    uint32_t hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + payload[i];
    }
    return hash;
}

// Aktualisiert die letzte Paketempfangszeit
void update_last_packet_time() {
    struct timeval now;
    gettimeofday(&now, NULL);
    pthread_mutex_lock(&last_packet_mutex);
    last_packet_time = now;
    pthread_mutex_unlock(&last_packet_mutex);
}

// Funktion zur Berechnung der tatsächlichen GTPv1-Header-Länge basierend auf den Flags
size_t calculate_gtp_header_length(struct gtpv1_header *gtp) {
    size_t header_len = sizeof(struct gtpv1_header);
    
    // Bit 5 (0x20) ist das Extension Header Flag
    if (gtp->flags & 0x20) {
        // Beispiel: Annahme, dass das Erweiterungsfeld 4 Bytes lang ist
        // Dies muss entsprechend den tatsächlichen Erweiterungsfeldern angepasst werden
        header_len += 4;
        LOG(LOG_DEBUG, "Extension Header Flag gesetzt. Erweiterte Header-Länge um 4 Bytes.");
    }

    // Bit 6 (0x40) ist das Sequence Number Flag
    if (gtp->flags & 0x40) {
        header_len += 2; // Sequenznummer ist 2 Bytes
        LOG(LOG_DEBUG, "Sequence Number Flag gesetzt. Erweiterte Header-Länge um 2 Bytes.");
    }

    // Bit 7 (0x80) ist das N-PDU Number Flag
    if (gtp->flags & 0x80) {
        header_len += 1; // N-PDU-Nummer ist 1 Byte
        LOG(LOG_DEBUG, "N-PDU Number Flag gesetzt. Erweiterte Header-Länge um 1 Byte.");
    }

    return header_len;
}

// Prozessiert N3-Pakete
void process_n3_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    // Aktualisiere die letzte Paketempfangszeit unabhängig von der Validität
    update_last_packet_time();

    if (!header || !packet) {
        LOG(LOG_ERROR, "Invalid packet or header");
        return;
    }

    // Mindestgröße des Pakets überprüfen
    if (header->caplen < (sizeof(struct ether_header) + sizeof(struct iphdr) + 
                         sizeof(struct udphdr) + sizeof(struct gtpv1_header))) {
        LOG(LOG_WARNING, "Packet too small: %d bytes", header->caplen);
        return;
    }

    const struct ether_header *eth = (struct ether_header *)packet;
    const struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));

    if (ip->version != 4) {
        LOG(LOG_DEBUG, "Not IPv4 packet");
        return;
    }

    // IP-Header-Länge berücksichtigen (ip->ihl gibt die Anzahl der 32-Bit-Wörter an)
    size_t ip_header_len = ip->ihl * 4;
    if (header->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr) + sizeof(struct gtpv1_header)) {
        LOG(LOG_WARNING, "Incomplete packet headers");
        return;
    }

    const struct udphdr *udp = (struct udphdr *)((u_char *)ip + ip_header_len);
    if (ntohs(udp->dest) != config.gtp_port) {
        LOG(LOG_DEBUG, "Not GTP packet");
        return;
    }

    const struct gtpv1_header *gtp = (struct gtpv1_header *)((u_char *)udp + sizeof(struct udphdr));

    // Berechne die tatsächliche GTPv1-Header-Länge basierend auf den Flags
    size_t gtp_header_len = calculate_gtp_header_length((struct gtpv1_header *)gtp);

    // Überprüfe, ob der Header innerhalb der caplen liegt
    size_t headers_len = sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr) + gtp_header_len;
    if (header->caplen < headers_len) {
        LOG(LOG_WARNING, "Incomplete GTPv1 header");
        LOG(LOG_DEBUG, "Packet details - caplen: %d, headers_len: %zu", header->caplen, headers_len);
        return;
    }

    // GTPv1 Length-Feld korrekt interpretieren
    size_t payload_len = ntohs(gtp->length);

    // Berechne die verbleibende Kapazität für den Payload
    size_t remaining_caplen = header->caplen - headers_len;

    if (payload_len == 0) {
        LOG(LOG_WARNING, "Invalid payload length: %zu (zero)", payload_len);
        return;
    }

    if (payload_len > remaining_caplen) {
        LOG(LOG_WARNING, "Invalid payload length: %zu > remaining caplen: %zu", payload_len, remaining_caplen);
        LOG(LOG_DEBUG, "Packet details - caplen: %d, headers_len: %zu, remaining_caplen: %zu", header->caplen, headers_len, remaining_caplen);
        return;
    }

    const u_char *payload = packet + headers_len;

    uint32_t hash = hash_payload(payload, payload_len);
    if (hash == 0) {
        LOG(LOG_WARNING, "Failed to generate hash");
        return;
    }

    struct packet_info *pinfo;
    if (allocate_packet_info(&pinfo, payload, payload_len) < 0) {
        return;
    }

    pthread_mutex_lock(&hash_mutex);
    struct hash_entry *entry;
    HASH_FIND_INT(packets_table, &hash, entry);
    
    if (!entry) {
        entry = calloc(1, sizeof(struct hash_entry));
        if (!entry) {
            LOG(LOG_ERROR, "Memory allocation failed for hash entry: %s", strerror(errno));
            free_packet_info(pinfo);
            pthread_mutex_unlock(&hash_mutex);
            return;
        }
        entry->hash = hash;
        entry->packets = NULL;
        HASH_ADD_INT(packets_table, hash, entry);
    }
    
    pinfo->next = entry->packets;
    entry->packets = pinfo;
    stats.total_n3++;
    pthread_mutex_unlock(&hash_mutex);

    LOG(LOG_INFO, "Processed N3 packet: len=%zu hash=%u", payload_len, hash);
}

// Prozessiert N6-Pakete
void process_n6_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    // Aktualisiere die letzte Paketempfangszeit unabhängig von der Validität
    update_last_packet_time();

    if (!header || !packet) {
        LOG(LOG_ERROR, "Invalid packet or header");
        return;
    }

    // Mindestgröße des Pakets überprüfen
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct iphdr)) {
        LOG(LOG_WARNING, "Packet too small for eth and IP header: %d bytes", header->caplen);
        return;
    }

    const struct ether_header *eth = (struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        LOG(LOG_DEBUG, "Not an IP packet");
        return;
    }

    const struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
    if (ip->version != 4) {
        LOG(LOG_DEBUG, "Not IPv4 packet");
        return;
    }

    // IP-Header-Länge berücksichtigen
    size_t ip_header_len = ip->ihl * 4;
    if (header->caplen < sizeof(struct ether_header) + ip_header_len) {
        LOG(LOG_WARNING, "Incomplete IP header");
        return;
    }

    const u_char *payload = packet + sizeof(struct ether_header) + ip_header_len;
    size_t payload_len = ntohs(ip->tot_len) - ip_header_len;

    if (payload_len == 0) {
        LOG(LOG_WARNING, "Invalid payload length: %zu (zero)", payload_len);
        return;
    }

    if (payload_len > (header->caplen - sizeof(struct ether_header) - ip_header_len)) {
        LOG(LOG_WARNING, "Invalid payload length: %zu > remaining caplen: %zu", payload_len, header->caplen - sizeof(struct ether_header) - ip_header_len);
        LOG(LOG_DEBUG, "Packet details - caplen: %d, ip_header_len: %zu, remaining_caplen: %zu", header->caplen, ip_header_len, header->caplen - sizeof(struct ether_header) - ip_header_len);
        return;
    }

    uint32_t hash = hash_payload(payload, payload_len);
    if (hash == 0) {
        LOG(LOG_WARNING, "Failed to generate hash");
        return;
    }

    pthread_mutex_lock(&hash_mutex);
    struct hash_entry *entry;
    HASH_FIND_INT(packets_table, &hash, entry);
    
    if (entry) {
        struct packet_info *curr = entry->packets;
        struct packet_info *prev = NULL;
        
        while (curr) {
            if (curr->payload_len == payload_len && 
                memcmp(curr->payload, payload, payload_len) == 0) {
                
                struct timeval now;
                gettimeofday(&now, NULL);
                
                double latency = (now.tv_sec - curr->timestamp.tv_sec) * 1000.0 +
                               (now.tv_usec - curr->timestamp.tv_usec) / 1000.0;
                
                stats.total_latency += latency;
                stats.matched++;
                
                double jitter = (stats.matched > 1) ? fabs(latency - stats.last_latency) : 0.0;
                stats.total_jitter += jitter;
                stats.last_latency = latency;

                // Entferne das passende Paket aus der Liste
                if (prev) {
                    prev->next = curr->next;
                } else {
                    entry->packets = curr->next;
                }
                
                free_packet_info(curr);
                break;
            }
            prev = curr;
            curr = curr->next;
        }
    }
    
    stats.total_n6++;
    pthread_mutex_unlock(&hash_mutex);

    LOG(LOG_INFO, "Processed N6 packet: len=%zu hash=%u", payload_len, hash);
}

// Cleanup-Thread-Funktion
void *cleanup_thread_func(void *arg) {
    struct timeval now;
    while (keep_running) {
        usleep(config.cleanup_interval_ms * 1000); // Umrechnung von ms in µs

        gettimeofday(&now, NULL);
        
        pthread_mutex_lock(&hash_mutex);
        
        // Berechnung der Metriken
        double loss_rate = (stats.total_n3 > 0) ? 
            (double)stats.lost / stats.total_n3 * 100.0 : 0.0;
        double avg_latency = (stats.matched > 0) ? 
            stats.total_latency / stats.matched : 0.0;
        double avg_jitter = (stats.matched > 1) ? 
            stats.total_jitter / (stats.matched - 1) : 0.0;
        
        // Schreibe Metriken in die CSV
        if (csv_file) {
            fprintf(csv_file, "%ld.%06ld,%.2f,%.2f,%.2f,%lu,%lu\n",
                    now.tv_sec, now.tv_usec,
                    loss_rate, avg_latency, avg_jitter,
                    stats.total_n3, stats.matched);
            fflush(csv_file);
        }

        // Durchlaufe die Hash-Tabelle und entferne alte Pakete
        struct hash_entry *entry, *tmp;
        HASH_ITER(hh, packets_table, entry, tmp) {
            struct packet_info *curr = entry->packets;
            struct packet_info *prev = NULL;
            
            while (curr) {
                if ((now.tv_sec - curr->timestamp.tv_sec) >= config.timeout_sec) {
                    stats.lost++;
                    // Entferne das Paket aus der Liste
                    if (prev) {
                        prev->next = curr->next;
                        free_packet_info(curr);
                        curr = prev->next;
                    } else {
                        entry->packets = curr->next;
                        free_packet_info(curr);
                        curr = entry->packets;
                    }
                } else {
                    prev = curr;
                    curr = curr->next;
                }
            }

            // Wenn keine Pakete mehr in diesem Hash-Eintrag sind, lösche den Eintrag
            if (entry->packets == NULL) {
                HASH_DEL(packets_table, entry);
                free(entry);
            }
        }
        
        pthread_mutex_unlock(&hash_mutex);

        // Überprüfe, ob seit dem letzten Paketempfang mehr als timeout_sec Sekunden vergangen sind
        pthread_mutex_lock(&last_packet_mutex);
        struct timeval last = last_packet_time;
        pthread_mutex_unlock(&last_packet_mutex);

        double time_diff = (now.tv_sec - last.tv_sec) + 
                           (now.tv_usec - last.tv_usec) / 1000000.0;

        if (time_diff >= config.timeout_sec) {
            LOG(LOG_INFO, "No packets received in the last %.0f seconds. Terminating...", time_diff);
            keep_running = 0;
            break;
        }
    }
    return NULL;
}

// N6 Capture-Thread-Funktion
void *n6_capture_thread_func(void *arg) {
    pcap_t *handle = (pcap_t *)arg;
    if (!handle) {
        LOG(LOG_ERROR, "Invalid pcap handle for N6");
        return NULL;
    }

    while (keep_running) {
        int ret = pcap_dispatch(handle, 10, process_n6_packet, NULL);
        if (ret < 0) {
            if (keep_running) {
                LOG(LOG_ERROR, "pcap_dispatch error: %s", pcap_geterr(handle));
            }
            break;
        }
    }

    return NULL;
}

// Funktion zum Parsen von Kommandozeilenargumenten
static void parse_args(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"n3-interface", required_argument, 0, '3'},
        {"n6-interface", required_argument, 0, '6'},
        {"source-ip", required_argument, 0, 's'},
        {"gtp-port", required_argument, 0, 'p'},
        {"timeout", required_argument, 0, 't'},
        {"cleanup-interval", required_argument, 0, 'c'},
        {"log-level", required_argument, 0, 'l'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "3:6:s:p:t:c:l:", long_options, NULL)) != -1) {
        switch (opt) {
            case '3':
                strncpy(config.n3_interface, optarg, sizeof(config.n3_interface) - 1);
                config.n3_interface[sizeof(config.n3_interface) - 1] = '\0';
                break;
            case '6':
                strncpy(config.n6_interface, optarg, sizeof(config.n6_interface) - 1);
                config.n6_interface[sizeof(config.n6_interface) - 1] = '\0';
                break;
            case 's':
                strncpy(config.source_ip, optarg, sizeof(config.source_ip) - 1);
                config.source_ip[sizeof(config.source_ip) - 1] = '\0';
                break;
            case 'p':
                config.gtp_port = (uint16_t)atoi(optarg);
                break;
            case 't':
                config.timeout_sec = (uint32_t)atoi(optarg);
                break;
            case 'c':
                config.cleanup_interval_ms = (uint32_t)atoi(optarg);
                break;
            case 'l':
                if (strcmp(optarg, "ERROR") == 0) {
                    current_log_level = LOG_ERROR;
                } else if (strcmp(optarg, "WARN") == 0) {
                    current_log_level = LOG_WARNING;
                } else if (strcmp(optarg, "INFO") == 0) {
                    current_log_level = LOG_INFO;
                } else if (strcmp(optarg, "DEBUG") == 0) {
                    current_log_level = LOG_DEBUG;
                } else {
                    fprintf(stderr, "Unknown log level: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                fprintf(stderr, "Usage: %s [options]\n", argv[0]);
                fprintf(stderr, "Options:\n");
                fprintf(stderr, "  --n3-interface, -3 <interface>    N3 Netzwerk-Schnittstelle (default: ens18)\n");
                fprintf(stderr, "  --n6-interface, -6 <interface>    N6 Netzwerk-Schnittstelle (default: upfgtp)\n");
                fprintf(stderr, "  --source-ip, -s <ip>               Quell-IP für N3 (default: 10.2.2.154)\n");
                fprintf(stderr, "  --gtp-port, -p <port>              GTP Port für N3 (default: 2152)\n");
                fprintf(stderr, "  --timeout, -t <seconds>            Timeout für keine Pakete (default: 10)\n");
                fprintf(stderr, "  --cleanup-interval, -c <ms>        Cleanup Intervall in ms (default: 500)\n");
                fprintf(stderr, "  --log-level, -l <level>            Log Level (ERROR, WARN, INFO, DEBUG; default: DEBUG)\n");
                exit(EXIT_FAILURE);
        }
    }
}

// Funktion zum Setzen von pcap Filtern
static int set_pcap_filter(pcap_t *handle, const char *filter_exp) {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        LOG(LOG_ERROR, "Could not compile filter '%s': %s", filter_exp, pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        LOG(LOG_ERROR, "Could not set filter '%s': %s", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }
    pcap_freecode(&fp);
    return 0;
}

int main(int argc, char *argv[]) {
    // Parse Kommandozeilenargumente
    parse_args(argc, argv);

    // Initialisiere die letzte Paketempfangszeit
    gettimeofday(&last_packet_time, NULL);

    // Signal-Handler für eine saubere Beendigung einrichten
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1 ||
        sigaction(SIGTERM, &sa, NULL) == -1) {
        LOG(LOG_ERROR, "Failed to set up signal handlers: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *n3_handle = pcap_open_live(config.n3_interface, BUFSIZ, 1, 1000, errbuf);
    if (!n3_handle) {
        LOG(LOG_ERROR, "Failed to open N3 interface '%s': %s", config.n3_interface, errbuf);
        return EXIT_FAILURE;
    }

    pcap_t *n6_handle = pcap_open_live(config.n6_interface, BUFSIZ, 1, 1000, errbuf);
    if (!n6_handle) {
        LOG(LOG_ERROR, "Failed to open N6 interface '%s': %s", config.n6_interface, errbuf);
        pcap_close(n3_handle);
        return EXIT_FAILURE;
    }

    // Setze Filter für die N3-Schnittstelle
    char filter_exp_n3[128];
    snprintf(filter_exp_n3, sizeof(filter_exp_n3), "src host %s and udp port %u", config.source_ip, config.gtp_port);
    if (set_pcap_filter(n3_handle, filter_exp_n3) < 0) {
        pcap_close(n3_handle);
        pcap_close(n6_handle);
        return EXIT_FAILURE;
    }

    // Setze Filter für die N6-Schnittstelle
    if (set_pcap_filter(n6_handle, "ip") < 0) {
        pcap_close(n3_handle);
        pcap_close(n6_handle);
        return EXIT_FAILURE;
    }

    // Öffne CSV-Datei für die Metriken
    csv_file = fopen("upf_metrics.csv", "w");
    if (!csv_file) {
        LOG(LOG_ERROR, "Failed to open CSV file: %s", strerror(errno));
        pcap_close(n3_handle);
        pcap_close(n6_handle);
        return EXIT_FAILURE;
    }
    fprintf(csv_file, "Timestamp,LossRate,Latency(ms),Jitter(ms),TotalPackets,MatchedPackets\n");
    fflush(csv_file);

    // Erstelle Threads für N6-Capture und Cleanup
    pthread_t n6_thread, cleanup_thread_id;
    if (pthread_create(&cleanup_thread_id, NULL, cleanup_thread_func, NULL) != 0) {
        LOG(LOG_ERROR, "Failed to create cleanup thread: %s", strerror(errno));
        fclose(csv_file);
        pcap_close(n3_handle);
        pcap_close(n6_handle);
        return EXIT_FAILURE;
    }
    if (pthread_create(&n6_thread, NULL, n6_capture_thread_func, n6_handle) != 0) {
        LOG(LOG_ERROR, "Failed to create N6 capture thread: %s", strerror(errno));
        keep_running = 0;
        pthread_join(cleanup_thread_id, NULL);
        fclose(csv_file);
        pcap_close(n3_handle);
        pcap_close(n6_handle);
        return EXIT_FAILURE;
    }

    // Starte das Erfassen von N3-Paketen
    while (keep_running) {
        int ret = pcap_dispatch(n3_handle, 10, process_n3_packet, NULL);
        if (ret == -1) {
            LOG(LOG_ERROR, "pcap_dispatch error on N3: %s", pcap_geterr(n3_handle));
            break;
        }
    }

    // Warte auf die Beendigung der Threads
    pthread_join(n6_thread, NULL);
    pthread_join(cleanup_thread_id, NULL);

    // Schließe die pcap-Handles
    pcap_close(n3_handle);
    pcap_close(n6_handle);

    // Befreie die Hash-Tabelle
    pthread_mutex_lock(&hash_mutex);
    struct hash_entry *entry, *tmp;
    HASH_ITER(hh, packets_table, entry, tmp) {
        struct packet_info *curr = entry->packets;
        while (curr) {
            struct packet_info *next = curr->next;
            free_packet_info(curr);
            curr = next;
        }
        HASH_DEL(packets_table, entry);
        free(entry);
    }
    pthread_mutex_unlock(&hash_mutex);

    // Schließe die CSV-Datei
    if (csv_file) {
        fclose(csv_file);
    }

    LOG(LOG_INFO, "Program terminated gracefully.");
    return EXIT_SUCCESS;
}
