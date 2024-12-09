#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#define HASHMAP_SIZE 1024
#define GTPU_HEADER_LEN 8
#define PACKET_LIFETIME 2
#define CSV_FILE "metrics.csv"

// Packet structure
typedef struct {
    char payload[1500];
    struct timespec timestamp;
} Packet;

// Hashmap entry
typedef struct {
    Packet* packets;
    int packet_count;
    pthread_mutex_t lock;
} HashmapEntry;

// Global variables
HashmapEntry hashmap[HASHMAP_SIZE];
uint64_t total_n3_packets = 0;
uint64_t total_n6_packets = 0;
uint64_t matched_packets = 0;
uint64_t lost_packets = 0;
double total_latency = 0.0;
double last_latency = 0.0;
double total_jitter = 0.0;
uint64_t processed_payload_bits = 0;
pthread_mutex_t metrics_lock;

// Hash function
unsigned int hash_payload(const char* payload, size_t len) {
    unsigned int hash = 5381;
    for (size_t i = 0; i < len; ++i) {
        hash = ((hash << 5) + hash) + payload[i];
    }
    return hash % HASHMAP_SIZE;
}

void remove_gtpu_header(const char* packet, char* payload, size_t len) {
    // Minimum Länge: Ethernet (14) + IP (20) + UDP (8) + GTP-U (8) = 50 Bytes
    if (len <= 50) {
        fprintf(stderr, "Packet too small for GTP-U header. Dropping packet.\n");
        payload[0] = '\0';
        return;
    }

    // Entferne Header und kopiere Payload
    memcpy(payload, packet + 50, len - 50);
}

// Update metrics (thread-safe)
void update_metrics(double latency, size_t payload_size) {
    pthread_mutex_lock(&metrics_lock);

    matched_packets++;
    total_latency += latency;
    double jitter = fabs(latency - last_latency);
    total_jitter += jitter;
    last_latency = latency;
    processed_payload_bits += payload_size * 8;

    pthread_mutex_unlock(&metrics_lock);
}

// Calculate and log metrics
void calculate_metrics() {
    pthread_mutex_lock(&metrics_lock);

    double packet_loss_rate = (total_n3_packets > 0) ? 
                              ((double)lost_packets / total_n3_packets) * 100 : 0;
    double average_latency = (matched_packets > 0) ? total_latency / matched_packets : 0;
    double average_jitter = (matched_packets > 1) ? total_jitter / (matched_packets - 1) : 0;
    double throughput = (processed_payload_bits / 1e6);  // Mbps
    double packet_rate = (double)matched_packets;

    // Write to CSV
    FILE* csv = fopen(CSV_FILE, "a");
    if (csv) {
        fprintf(csv, "%.2f,%.2f,%.2f,%.2f,%.2f\n",
                packet_loss_rate, average_latency, average_jitter, throughput, packet_rate);
        fclose(csv);
    }

    // Reset counters for the next interval
    total_latency = 0.0;
    total_jitter = 0.0;
    processed_payload_bits = 0;
    matched_packets = 0;

    pthread_mutex_unlock(&metrics_lock);
}

void n3_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    total_n3_packets++;

    // Überprüfe die Paketgröße
    if (header->len > 1500) {
        fprintf(stderr, "Packet size exceeds buffer size. Dropping packet.\n");
        return;
    }

    // Dynamische Speicherzuweisung
    char* payload = malloc(1500);
    if (!payload) {
        fprintf(stderr, "Memory allocation failed.\n");
        return;
    }

    // Entferne GTP-U-Header
    remove_gtpu_header((const char*)packet, payload, header->len);
    if (payload[0] == '\0') {
        fprintf(stderr, "Invalid GTP-U packet. Dropping packet.\n");
        free(payload);
        return;
    }

    // Timestamp erstellen
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Hash und Speicher in der Hashmap
    unsigned int hash = hash_payload(payload, strlen(payload));
    HashmapEntry* entry = &hashmap[hash];
    pthread_mutex_lock(&entry->lock);

    entry->packets = realloc(entry->packets, sizeof(Packet) * (entry->packet_count + 1));
    if (!entry->packets) {
        fprintf(stderr, "Memory allocation failed for packets.\n");
        pthread_mutex_unlock(&entry->lock);
        free(payload);
        return;
    }

    strcpy(entry->packets[entry->packet_count].payload, payload);
    entry->packets[entry->packet_count].timestamp = ts;
    entry->packet_count++;

    pthread_mutex_unlock(&entry->lock);
    free(payload);
}


// Callback for libpcap (N6 listener)
void n6_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    total_n6_packets++;

    // Directly process payload
    char payload[1500];
    memcpy(payload, packet, header->len);

    // Timestamp the packet
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Match with N3 packets
    unsigned int hash = hash_payload(payload, strlen(payload));
    HashmapEntry* entry = &hashmap[hash];
    pthread_mutex_lock(&entry->lock);

    int found = 0;
    for (int i = 0; i < entry->packet_count; ++i) {
        if (strcmp(entry->packets[i].payload, payload) == 0) {
            // Packet matched
            double latency = difftime(ts.tv_sec, entry->packets[i].timestamp.tv_sec) +
                             (ts.tv_nsec - entry->packets[i].timestamp.tv_nsec) / 1e9;
            update_metrics(latency, header->len);

            // Remove matched packet
            for (int j = i; j < entry->packet_count - 1; ++j) {
                entry->packets[j] = entry->packets[j + 1];
            }
            entry->packet_count--;

            found = 1;
            break;
        }
    }

    if (!found) {
        lost_packets++;
        printf("No match found for N6 packet.\n");
    }

    pthread_mutex_unlock(&entry->lock);
}

// Periodic metric calculation
void* metric_thread(void* arg) {
    while (1) {
        sleep(1);  // Calculate metrics every second
        calculate_metrics();
    }
    return NULL;
}

// Initialize hashmap
void init_hashmap() {
    for (int i = 0; i < HASHMAP_SIZE; ++i) {
        hashmap[i].packets = NULL;
        hashmap[i].packet_count = 0;
        pthread_mutex_init(&hashmap[i].lock, NULL);
    }
    pthread_mutex_init(&metrics_lock, NULL);
}

// Cleanup hashmap
void cleanup_hashmap() {
    for (int i = 0; i < HASHMAP_SIZE; ++i) {
        pthread_mutex_lock(&hashmap[i].lock);
        free(hashmap[i].packets);
        hashmap[i].packets = NULL;
        hashmap[i].packet_count = 0;
        pthread_mutex_unlock(&hashmap[i].lock);
    }
}

// Main
int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open pcap session for N3 interface
    pcap_t* n3_handle = pcap_open_live("ens18", BUFSIZ, 1, 1000, errbuf);
    if (!n3_handle) {
        fprintf(stderr, "Could not open ens18: %s\n", errbuf);
        return 1;
    }

    // Open pcap session for N6 interface
    pcap_t* n6_handle = pcap_open_live("upfgtp", BUFSIZ, 1, 1000, errbuf);
    if (!n6_handle) {
        fprintf(stderr, "Could not open upfgtp: %s\n", errbuf);
        pcap_close(n3_handle);
        return 1;
    }

    // Initialize hashmap
    init_hashmap();

    // Initialize CSV file
    FILE* csv = fopen(CSV_FILE, "w");
    if (csv) {
        fprintf(csv, "Packet Loss Rate,Average Latency (s),Jitter (s),Throughput (Mbps),Packet Rate (pps)\n");
        fclose(csv);
    }

    // Start metric calculation thread
    pthread_t metric_calc_thread;
    pthread_create(&metric_calc_thread, NULL, metric_thread, NULL);

    // Start packet capture
    printf("Listening on interfaces: ens18 (N3) and upfgtp (N6)...\n");
    pthread_t n3_thread, n6_thread;
    pthread_create(&n3_thread, NULL, (void*(*)(void*))pcap_loop, (void*)n3_handle);
    pthread_create(&n6_thread, NULL, (void*(*)(void*))pcap_loop, (void*)n6_handle);

    pthread_join(n3_thread, NULL);
    pthread_join(n6_thread, NULL);

    // Cleanup
    cleanup_hashmap();
    pcap_close(n3_handle);
    pcap_close(n6_handle);

    return 0;
}
