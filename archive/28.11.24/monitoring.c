#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <pthread.h>
#include <stdint.h>

#define HASHMAP_SIZE 1024
#define BUFFER_CAPACITY 100
#define PACKET_LIFETIME 2
#define MONITOR_INTERVAL 0.5
#define METRIC_INTERVAL 1.0
#define N3_IP "10.2.2.154"
#define CSV_FILE "metrics.csv"

// Packet structure
typedef struct {
    char payload[1500];
    struct timespec timestamp;
} Packet;

// Ring buffer for packet storage
typedef struct {
    Packet buffer[BUFFER_CAPACITY];
    int head, tail, size;
    pthread_mutex_t lock;
} RingBuffer;

// Hashmap entry
typedef struct {
    RingBuffer* ringBuffer;
    pthread_mutex_t lock;
} HashmapEntry;

// Global variables
HashmapEntry hashmap[HASHMAP_SIZE];
uint64_t n3_packets = 0;
uint64_t n6_packets = 0;
uint64_t matched_packets = 0;
uint64_t lost_packets = 0;
double total_latency = 0.0;
double last_latency = 0.0;
double total_jitter = 0.0;
uint64_t processed_payload_bits = 0;

// Hash function
unsigned int hash_payload(const char* payload, size_t len) {
    unsigned int hash = 5381;
    for (size_t i = 0; i < len; ++i) {
        hash = ((hash << 5) + hash) + payload[i];
    }
    return hash % HASHMAP_SIZE;
}

// Initialize ring buffer
RingBuffer* init_ring_buffer() {
    RingBuffer* rb = (RingBuffer*)malloc(sizeof(RingBuffer));
    rb->head = rb->tail = rb->size = 0;
    pthread_mutex_init(&rb->lock, NULL);
    return rb;
}

// Add packet to ring buffer
void add_to_ring_buffer(RingBuffer* rb, const char* payload, size_t len, struct timespec timestamp) {
    pthread_mutex_lock(&rb->lock);
    if (rb->size == BUFFER_CAPACITY) {
        rb->head = (rb->head + 1) % BUFFER_CAPACITY;
        rb->size--;
    }
    Packet* pkt = &rb->buffer[rb->tail];
    memcpy(pkt->payload, payload, len);
    pkt->timestamp = timestamp;
    rb->tail = (rb->tail + 1) % BUFFER_CAPACITY;
    rb->size++;
    pthread_mutex_unlock(&rb->lock);
}

// Match N6 packets and calculate metrics
void match_packet_and_calculate(const char* n6_payload, size_t len, struct timespec n6_timestamp) {
    unsigned int hash = hash_payload(n6_payload, len);
    HashmapEntry* entry = &hashmap[hash];

    pthread_mutex_lock(&entry->lock);
    if (!entry->ringBuffer) {
        pthread_mutex_unlock(&entry->lock);
        n6_packets++;
        printf("No match found, dropping N6 packet.\n");
        return;
    }

    RingBuffer* rb = entry->ringBuffer;
    pthread_mutex_lock(&rb->lock);

    for (int i = 0; i < rb->size; i++) {
        int index = (rb->head + i) % BUFFER_CAPACITY;
        Packet* pkt = &rb->buffer[index];
        if (memcmp(pkt->payload, n6_payload, len) == 0) {
            // Calculate latency
            double latency = difftime(n6_timestamp.tv_sec, pkt->timestamp.tv_sec) +
                             (n6_timestamp.tv_nsec - pkt->timestamp.tv_nsec) / 1e9;
            total_latency += latency;
            double jitter = fabs(latency - last_latency);
            total_jitter += jitter;
            last_latency = latency;

            matched_packets++;
            processed_payload_bits += len * 8;

            // Remove matched packet
            rb->head = (index + 1) % BUFFER_CAPACITY;
            rb->size--;

            pthread_mutex_unlock(&rb->lock);
            pthread_mutex_unlock(&entry->lock);
            return;
        }
    }

    pthread_mutex_unlock(&rb->lock);
    pthread_mutex_unlock(&entry->lock);
    lost_packets++;
    printf("No match found, dropping N6 packet.\n");
}

// Periodically calculate metrics
void* calculate_metrics(void* arg) {
    while (1) {
        sleep(METRIC_INTERVAL);

        double loss_rate = (n3_packets > 0) ? ((double)lost_packets / n3_packets) * 100 : 0;
        double throughput = (processed_payload_bits / 1e6) / METRIC_INTERVAL; // Mbps
        double packet_rate = (double)matched_packets / METRIC_INTERVAL;

        FILE* csv = fopen(CSV_FILE, "a");
        if (csv) {
            fprintf(csv, "%.2f,%.2f,%.2f,%.2f,%.2f\n",
                    loss_rate, total_latency / matched_packets, total_jitter / matched_packets,
                    throughput, packet_rate);
            fclose(csv);
        }

        // Reset counters
        total_latency = 0.0;
        total_jitter = 0.0;
        processed_payload_bits = 0;
        matched_packets = 0;
    }
    return NULL;
}

// Main
int main() {
    // Initialize hashmap
    for (int i = 0; i < HASHMAP_SIZE; ++i) {
        hashmap[i].ringBuffer = NULL;
        pthread_mutex_init(&hashmap[i].lock, NULL);
    }

    // Initialize CSV
    FILE* csv = fopen(CSV_FILE, "w");
    if (csv) {
        fprintf(csv, "Packet Loss Rate,Average Latency (s),Jitter (s),Throughput (Mbps),Packet Rate (pps)\n");
        fclose(csv);
    }

    // Create threads for N3 and N6 listeners, cleanup, and metric calculation
    pthread_t n3_thread, n6_thread, cleanup_thread, metrics_thread;
    pthread_create(&n3_thread, NULL, socket_listener, "N3");
    pthread_create(&n6_thread, NULL, socket_listener, "N6");
    pthread_create(&metrics_thread, NULL, calculate_metrics, NULL);

    // Wait for threads
    pthread_join(n3_thread, NULL);
    pthread_join(n6_thread, NULL);
    pthread_join(metrics_thread, NULL);

    return 0;
}
