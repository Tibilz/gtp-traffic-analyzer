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

#define DEBUG 1
#define LOG(fmt, ...) \
    do { if (DEBUG) fprintf(stderr, "%s:%d: " fmt "\n", \
        __func__, __LINE__, ##__VA_ARGS__); } while (0)

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

// Global variables
struct hash_entry *packets_table = NULL;
pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;
FILE *csv_file;

struct metrics {
    uint64_t total_n3;
    uint64_t total_n6;
    uint64_t matched;
    uint64_t lost;
    double total_latency;
    double total_jitter;
    double last_latency;
} stats = {0};

uint32_t hash_payload(const uint8_t *payload, size_t len) {
    if (!payload || len == 0) {
        LOG("Invalid payload or length");
        return 0;
    }

    uint32_t hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + payload[i];
    }
    return hash;
}

void process_n3_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    if (!header || !packet) {
        LOG("Invalid packet or header");
        return;
    }

    if (header->caplen < (sizeof(struct ether_header) + sizeof(struct iphdr) + 
                         sizeof(struct udphdr) + sizeof(struct gtpv1_header))) {
        LOG("Packet too small: %d bytes", header->caplen);
        return;
    }

    const struct ether_header *eth = (struct ether_header *)packet;
    const struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
    const struct udphdr *udp = (struct udphdr *)((u_char *)ip + (ip->ihl * 4));
    const struct gtpv1_header *gtp = (struct gtpv1_header *)((u_char *)udp + sizeof(struct udphdr));
    
    const u_char *payload = (u_char *)gtp + sizeof(struct gtpv1_header);
    size_t payload_len = ntohs(gtp->length);

    uint32_t hash = hash_payload(payload, payload_len);
    
    struct packet_info *pinfo = calloc(1, sizeof(struct packet_info));
    pinfo->payload = malloc(payload_len);
    memcpy(pinfo->payload, payload, payload_len);
    pinfo->payload_len = payload_len;
    gettimeofday(&pinfo->timestamp, NULL);

    pthread_mutex_lock(&hash_mutex);
    struct hash_entry *entry;
    HASH_FIND_INT(packets_table, &hash, entry);
    if (!entry) {
        entry = calloc(1, sizeof(struct hash_entry));
        entry->hash = hash;
        entry->packets = NULL;
        HASH_ADD_INT(packets_table, hash, entry);
    }
    pinfo->next = entry->packets;
    entry->packets = pinfo;
    stats.total_n3++;
    pthread_mutex_unlock(&hash_mutex);

    LOG("Processed N3 packet: len=%zu hash=%u", payload_len, hash);
}

void process_n6_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    if (!header || !packet) {
        LOG("Invalid packet or header");
        return;
    }

    LOG("Got N6 packet, len=%d", header->caplen);

    const struct ether_header *eth = (struct ether_header *)packet;
    LOG("Ethertype: 0x%04x", ntohs(eth->ether_type));

    if (header->caplen < sizeof(struct ether_header)) {
        LOG("Packet too small for eth header: %d bytes", header->caplen);
        return;
    }

    if (header->caplen < (sizeof(struct ether_header) + sizeof(struct iphdr))) {
        LOG("Packet too small: %d bytes", header->caplen);
        return;
    }

    const struct ether_header *eth = (struct ether_header *)packet;
    const struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
    
    const u_char *payload = (u_char *)ip + (ip->ihl * 4);
    size_t payload_len = ntohs(ip->tot_len) - (ip->ihl * 4);

    uint32_t hash = hash_payload(payload, payload_len);

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
                
                double jitter = fabs(latency - stats.last_latency);
                stats.total_jitter += jitter;
                stats.last_latency = latency;

                if (prev) {
                    prev->next = curr->next;
                } else {
                    entry->packets = curr->next;
                }
                
                free(curr->payload);
                free(curr);
                break;
            }
            prev = curr;
            curr = curr->next;
        }
    }
    
    stats.total_n6++;
    pthread_mutex_unlock(&hash_mutex);
}

void *cleanup_thread(void *arg) {
    while (1) {
        struct timeval now;
        gettimeofday(&now, NULL);
        
        pthread_mutex_lock(&hash_mutex);
        
        double loss_rate = (stats.total_n3 > 0) ? 
            (double)stats.lost / stats.total_n3 * 100.0 : 0;
        double avg_latency = (stats.matched > 0) ? 
            stats.total_latency / stats.matched : 0;
        double avg_jitter = (stats.matched > 0) ? 
            stats.total_jitter / stats.matched : 0;
        
        fprintf(csv_file, "%ld.%06ld,%.2f,%.2f,%.2f,%lu,%lu\n",
                now.tv_sec, now.tv_usec,
                loss_rate, avg_latency, avg_jitter,
                stats.total_n3, stats.matched);
        fflush(csv_file);
        
        struct hash_entry *entry, *tmp;
        HASH_ITER(hh, packets_table, entry, tmp) {
            struct packet_info *curr = entry->packets;
            struct packet_info *prev = NULL;
            
            while (curr) {
                if (now.tv_sec - curr->timestamp.tv_sec >= 2) {
                    stats.lost++;
                    if (prev) {
                        prev->next = curr->next;
                        free(curr->payload);
                        free(curr);
                        curr = prev->next;
                    } else {
                        entry->packets = curr->next;
                        free(curr->payload);
                        free(curr);
                        curr = entry->packets;
                    }
                } else {
                    prev = curr;
                    curr = curr->next;
                }
            }
        }
        
        pthread_mutex_unlock(&hash_mutex);
        usleep(500000); // 500ms
    }
    return NULL;
}

void *n6_capture_thread(void *arg) {
    pcap_t *handle = (pcap_t *)arg;
    if (!handle) {
        LOG("Invalid pcap handle");
        return NULL;
    }
    pcap_loop(handle, -1, process_n6_packet, NULL);
    return NULL;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *n3_handle = pcap_open_live("ens18", BUFSIZ, 1, 1000, errbuf);
    pcap_t *n6_handle = pcap_open_live("upfgtp", BUFSIZ, 1, 1000, errbuf);

    if (!n3_handle || !n6_handle) {
        LOG("Failed to open interfaces: %s", errbuf);
        return 1;
    }

    struct bpf_program fp;

    // Set filter for N3 interface
    char filter_exp[100];
    sprintf(filter_exp, "src host %s and udp port 2152", "10.2.2.154"); 
    if (pcap_compile(n3_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        LOG("Could not compile N3 filter: %s", pcap_geterr(n3_handle));
        return 1;
    }
    if (pcap_setfilter(n3_handle, &fp) == -1) {
        LOG("Could not set N3 filter: %s", pcap_geterr(n3_handle));
        return 1;
    }
    pcap_freecode(&fp);

    // Set filter for N6 interface - adjust IP range as needed
    if (pcap_compile(n6_handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        LOG("Could not compile N6 filter: %s", pcap_geterr(n6_handle));
        return 1;
    }
    if (pcap_setfilter(n6_handle, &fp) == -1) {
        LOG("Could not set N6 filter: %s", pcap_geterr(n6_handle));
        return 1;
    }
    pcap_freecode(&fp);

    csv_file = fopen("upf_metrics.csv", "w");
    fprintf(csv_file, "Timestamp,LossRate,Latency,Jitter,TotalPackets,MatchedPackets\n");

    pthread_t n6_thread, cleanup_thread_id;
    pthread_create(&cleanup_thread_id, NULL, cleanup_thread, NULL);
    pthread_create(&n6_thread, NULL, n6_capture_thread, n6_handle);

    pcap_loop(n3_handle, -1, process_n3_packet, NULL);

    pcap_close(n3_handle);
    pcap_close(n6_handle);
    fclose(csv_file);
    
    return 0;
}