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

// Configuration structure
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
    .timeout_sec = 2,
    .cleanup_interval_ms = 500
};

#define LOG_ERROR   0
#define LOG_WARNING 1
#define LOG_INFO    2
#define LOG_DEBUG   3

#define LOG(level, fmt, ...) \
    do { fprintf(stderr, "%s:%d: [%s] " fmt "\n", \
        __func__, __LINE__, \
        (level == LOG_ERROR) ? "ERROR" : \
        (level == LOG_WARNING) ? "WARN" : \
        (level == LOG_INFO) ? "INFO" : "DEBUG", \
        ##__VA_ARGS__); } while (0)

// GTPv1 header structure
struct gtpv1_header {
    uint8_t flags;
    uint8_t message_type;
    uint16_t length;
    uint32_t teid;
} __attribute__((packed));

// Single packet structure for both N3 and N6
struct packet_info {
    struct timeval timestamp;
    uint8_t *payload;
    size_t payload_len;
    struct packet_info *next;
};

// Hash table entry
struct hash_entry {
    uint32_t hash;           // key for uthash
    struct packet_info *packets;
    UT_hash_handle hh;
};

// Metrics structure
struct metrics {
    uint64_t total_n3;
    uint64_t total_n6;
    uint64_t matched;
    uint64_t lost;
    double total_latency;
    double total_jitter;
    double last_latency;
} stats = {0};

// Global variables
struct hash_entry *packets_table = NULL;
pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;
FILE *csv_file = NULL;
volatile sig_atomic_t keep_running = 1;

// Function to handle termination signals
void handle_signal(int sig) {
    LOG(LOG_INFO, "Received signal %d, terminating...", sig);
    keep_running = 0;
}

// Function to free packet_info
static void free_packet_info(struct packet_info *pinfo) {
    if (pinfo) {
        free(pinfo->payload);
        free(pinfo);
    }
}

// Function to allocate and initialize packet_info
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

// DJB2 hash function
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

// Process N3 packet
void process_n3_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    if (!header || !packet) {
        LOG(LOG_ERROR, "Invalid packet or header");
        return;
    }

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

    const struct udphdr *udp = (struct udphdr *)((u_char *)ip + (ip->ihl * 4));
    if (ntohs(udp->dest) != config.gtp_port) {
        LOG(LOG_DEBUG, "Not GTP packet");
        return;
    }

    const struct gtpv1_header *gtp = (struct gtpv1_header *)((u_char *)udp + sizeof(struct udphdr));
    const u_char *payload = (u_char *)gtp + sizeof(struct gtpv1_header);
    size_t payload_len = ntohs(gtp->length);

    if (payload_len == 0 || payload_len > (header->caplen - sizeof(struct ether_header) - (ip->ihl * 4) - sizeof(struct udphdr) - sizeof(struct gtpv1_header))) {
        LOG(LOG_WARNING, "Invalid payload length: %zu", payload_len);
        return;
    }

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

// Process N6 packet
void process_n6_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    if (!header || !packet) {
        LOG(LOG_ERROR, "Invalid packet or header");
        return;
    }

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

    const u_char *payload = (u_char *)ip + (ip->ihl * 4);
    size_t payload_len = ntohs(ip->tot_len) - (ip->ihl * 4);

    if (payload_len == 0 || payload_len > (header->caplen - sizeof(struct ether_header) - (ip->ihl * 4))) {
        LOG(LOG_WARNING, "Invalid payload length: %zu", payload_len);
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

                // Remove the matched packet from the list
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

// Cleanup thread function
void *cleanup_thread_func(void *arg) {
    struct timeval now;
    while (keep_running) {
        usleep(config.cleanup_interval_ms * 1000); // Convert ms to us

        gettimeofday(&now, NULL);
        
        pthread_mutex_lock(&hash_mutex);
        
        // Calculate metrics
        double loss_rate = (stats.total_n3 > 0) ? 
            (double)stats.lost / stats.total_n3 * 100.0 : 0.0;
        double avg_latency = (stats.matched > 0) ? 
            stats.total_latency / stats.matched : 0.0;
        double avg_jitter = (stats.matched > 1) ? 
            stats.total_jitter / (stats.matched - 1) : 0.0;
        
        // Write metrics to CSV
        if (csv_file) {
            fprintf(csv_file, "%ld.%06ld,%.2f,%.2f,%.2f,%lu,%lu\n",
                    now.tv_sec, now.tv_usec,
                    loss_rate, avg_latency, avg_jitter,
                    stats.total_n3, stats.matched);
            fflush(csv_file);
        }

        // Iterate through the hash table and remove old packets
        struct hash_entry *entry, *tmp;
        HASH_ITER(hh, packets_table, entry, tmp) {
            struct packet_info *curr = entry->packets;
            struct packet_info *prev = NULL;
            
            while (curr) {
                if ((now.tv_sec - curr->timestamp.tv_sec) >= config.timeout_sec) {
                    stats.lost++;
                    // Remove the packet from the list
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

            // If no more packets in this hash entry, delete the entry
            if (entry->packets == NULL) {
                HASH_DEL(packets_table, entry);
                free(entry);
            }
        }
        
        pthread_mutex_unlock(&hash_mutex);
    }
    return NULL;
}

// N6 capture thread function
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

// Function to parse command-line arguments
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
                // Implement log level setting if needed
                break;
            default:
                fprintf(stderr, "Usage: %s [options]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
}

// Function to set pcap filters
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
    // Parse command-line arguments
    parse_args(argc, argv);

    // Setup signal handling for graceful termination
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

    // Set filter for N3 interface
    char filter_exp_n3[128];
    snprintf(filter_exp_n3, sizeof(filter_exp_n3), "src host %s and udp port %u", config.source_ip, config.gtp_port);
    if (set_pcap_filter(n3_handle, filter_exp_n3) < 0) {
        pcap_close(n3_handle);
        pcap_close(n6_handle);
        return EXIT_FAILURE;
    }

    // Set filter for N6 interface
    if (set_pcap_filter(n6_handle, "ip") < 0) {
        pcap_close(n3_handle);
        pcap_close(n6_handle);
        return EXIT_FAILURE;
    }

    // Open CSV file
    csv_file = fopen("upf_metrics.csv", "w");
    if (!csv_file) {
        LOG(LOG_ERROR, "Failed to open CSV file: %s", strerror(errno));
        pcap_close(n3_handle);
        pcap_close(n6_handle);
        return EXIT_FAILURE;
    }
    fprintf(csv_file, "Timestamp,LossRate,Latency(ms),Jitter(ms),TotalPackets,MatchedPackets\n");
    fflush(csv_file);

    // Create threads
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

    // Start capturing N3 packets
    while (keep_running) {
        int ret = pcap_dispatch(n3_handle, 10, process_n3_packet, NULL);
        if (ret == -1) {
            LOG(LOG_ERROR, "pcap_dispatch error on N3: %s", pcap_geterr(n3_handle));
            break;
        }
    }

    // Wait for threads to finish
    pthread_join(n6_thread, NULL);
    pthread_join(cleanup_thread_id, NULL);

    // Cleanup
    pcap_close(n3_handle);
    pcap_close(n6_handle);

    // Free hash table
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

    // Close CSV file
    if (csv_file) {
        fclose(csv_file);
    }

    LOG(LOG_INFO, "Program terminated gracefully.");
    return EXIT_SUCCESS;
}
