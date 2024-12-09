#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>

#define HASHMAP_SIZE 1024
#define TIMEOUT_SECONDS 5
#define CLEANUP_INTERVAL_MS 100
#define TEST_DURATION_SECONDS 10
#define PACKETS_PER_SECOND 1000000

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

static unsigned int simple_hash(const unsigned char *data, size_t len) {
    unsigned int hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash % HASHMAP_SIZE;
}

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
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

/* Cleaner-Thread */
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

/* Simuliert die Erzeugung von N3-Paketen */
static void *n3_producer_thread(void *arg) {
    (void)arg;
    int packets_per_sec = PACKETS_PER_SECOND;
    int sleep_us = 1000000 / packets_per_sec;
    int packet_id = 0;
    while (running) {
        struct timeval now;
        gettimeofday(&now, NULL);
        // Generiere Payload: [4-Byte PacketID][Daten...]
        unsigned char payload[100];
        memset(payload, 0, sizeof(payload));
        // Packet ID in Payload
        payload[0] = (packet_id >> 24) & 0xFF;
        payload[1] = (packet_id >> 16) & 0xFF;
        payload[2] = (packet_id >> 8) & 0xFF;
        payload[3] = packet_id & 0xFF;

        insert_n3_packet(payload, sizeof(payload), &now);
        packet_id++;
        usleep(sleep_us);
    }
    return NULL;
}

/* Simuliert die verzögerte Ankunft entsprechender N6-Pakete */
static void *n6_consumer_thread(void *arg) {
    (void)arg;
    int expected_id = 0;
    // Wir simulieren, dass nach einiger Verzögerung dieselben PacketIDs ankommen
    // mit einer gewissen Rate.
    // Beispiel: N6 sieht dieselben IDs aber 200ms verzögert
    // Um das zu simulieren, warten wir nach dem Start erst mal eine Weile
    usleep(200000); // 200ms Delay bis erste N6 Pakete auftauchen

    int packets_per_sec = PACKETS_PER_SECOND;
    int sleep_us = 1000000 / packets_per_sec;
    while (running) {
        struct timeval now;
        gettimeofday(&now, NULL);

        unsigned char payload[100];
        memset(payload, 0, sizeof(payload));
        payload[0] = (expected_id >> 24) & 0xFF;
        payload[1] = (expected_id >> 16) & 0xFF;
        payload[2] = (expected_id >> 8) & 0xFF;
        payload[3] = expected_id & 0xFF;

        pthread_mutex_lock(&lock);
        total_n6_packets++;
        pthread_mutex_unlock(&lock);

        match_n6_packet(payload, sizeof(payload), &now);

        expected_id++;
        usleep(sleep_us);
    }
    return NULL;
}


int main() {
    signal(SIGINT, handle_sigint);
    gettimeofday(&start_time, NULL);

    pthread_t cleanup_thread;
    pthread_t n3_thread;
    pthread_t n6_thread;

    pthread_create(&cleanup_thread, NULL, cleanup_thread_func, NULL);
    pthread_create(&n3_thread, NULL, n3_producer_thread, NULL);
    pthread_create(&n6_thread, NULL, n6_consumer_thread, NULL);

    // Laufzeit der Simulation
    sleep(TEST_DURATION_SECONDS);
    running = 0;

    pthread_join(n3_thread, NULL);
    pthread_join(n6_thread, NULL);
    pthread_join(cleanup_thread, NULL);

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

    double matched_throughput = 0.0; 
    if (elapsed > 0) {
        matched_throughput = sum_matched_payload / elapsed; // B/s
    }

    double n3_throughput = 0.0;
    if (elapsed > 0) {
        n3_throughput = total_n3_payload / elapsed; // B/s
    }

    printf("\n==== Test Ergebnisse ====\n");
    printf("Gesamte Messdauer: %.2f s\n", elapsed);
    printf("N3 Packets: %d\n", total_n3_packets);
    printf("N6 Packets: %d\n", total_n6_packets);
    printf("Matched Packets: %d\n", matched_packets);
    printf("Lost Packets: %d\n", lost_packets);
    printf("Packet Loss Rate: %.2f %%\n", packet_loss_rate * 100.0);
    printf("Average Latency: %.2f ms\n", avg_latency);
    printf("Jitter: %.2f ms\n", jitter);
    printf("Matched Throughput: %.2f B/s (%.2f Mbit/s)\n",
           matched_throughput, matched_throughput * 8 / 1e6);
    printf("N3 Throughput: %.2f B/s (%.2f Mbit/s)\n",
           n3_throughput, n3_throughput * 8 / 1e6);
    printf("=========================\n");

    return 0;
}
