#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <math.h>
#include <unistd.h> // Included for usleep
#include <time.h>   // Included for clock_gettime

// Definitions and Structures
#define HASHMAP_SIZE 1024
#define TIMEOUT_SECONDS 2
#define CLEANUP_INTERVAL_MS 500

typedef enum {
    PROTOCOL_UDP,
    PROTOCOL_TCP
} protocol_t;

typedef struct packet_entry {
    unsigned char *payload;
    size_t payload_len;
    struct timespec timestamp; // Changed to timespec for higher accuracy
    struct packet_entry *next;
} packet_entry_t;

typedef struct {
    packet_entry_t *head;
} hashmap_bucket_t;

static hashmap_bucket_t hashmap[HASHMAP_SIZE];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int running = 1;

static struct timespec start_time; // Global declaration of start_time

// Statistics Variables
static int total_n3_packets = 0;
static int total_n6_packets = 0;
static int matched_packets = 0;
static int lost_packets = 0;
static size_t total_n3_payload = 0;
static size_t sum_matched_payload = 0;

static double sum_latency = 0.0;
static double sum_latency_sq = 0.0;
static int latency_count = 0;

// Protocol Mode
static protocol_t current_protocol = PROTOCOL_UDP;

// Function to Handle Program Termination
void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

/**
 * Simple hash function based on the payload.
 */
static unsigned int simple_hash(const unsigned char *data, size_t len) {
    unsigned int hash = 0;
    for (size_t i = 0; i < len; i++) {
        hash = (hash * 31) + data[i];
    }
    return hash % HASHMAP_SIZE;
}

/**
 * Calculates the difference between two timespec structures in milliseconds.
 * @param start Start time.
 * @param end End time.
 * @return Difference in milliseconds. If end < start, 0 is returned.
 */
static double timespec_diff_ms(const struct timespec *start, const struct timespec *end) {
    double diff_sec = end->tv_sec - start->tv_sec;
    double diff_nsec = end->tv_nsec - start->tv_nsec;
    
    if (diff_nsec < 0) {
        diff_sec -= 1;
        diff_nsec += 1000000000;
    }
    
    double latency_ms = diff_sec * 1000.0 + diff_nsec / 1e6;
    
    // Ensure latency is not negative
    if (latency_ms < 0.0) {
        return 0.0;
    }
    
    return latency_ms;
}


/**
 * Extracts the application payload from an N3 packet by skipping a specified number of bytes.
 * @param packet Pointer to the packet data.
 * @param hdr Packet metadata (pcap Header).
 * @param payload_len Pointer to store the extracted payload length.
 * @param skip_bytes Number of bytes to skip based on protocol.
 * @return Pointer to the extracted payload on success, NULL on error.
 */
static unsigned char* extract_payload_n3(const u_char *packet, const struct pcap_pkthdr *hdr, size_t *payload_len, int skip_bytes) {
    size_t remaining = hdr->caplen;
    const unsigned char *p = packet;

    // 1. Skip specified bytes for N3 packets
    if (remaining < (size_t)skip_bytes) {
        return NULL;
    }
    p += skip_bytes; 
    remaining -= skip_bytes;

    // 2. Check if Payload Exists
    if (remaining == 0) {
        *payload_len = 0;
        return NULL;
    }

    // 3. Extract Payload
    unsigned char *pl = malloc(remaining);
    if (!pl) {
        return NULL;
    }
    memcpy(pl, p, remaining);
    *payload_len = remaining;

    return pl;
}

/**
 * Extracts the application payload from an N6 packet by skipping a specified number of bytes.
 * @param packet Pointer to the packet data.
 * @param hdr Packet metadata (pcap Header).
 * @param payload_len Pointer to store the extracted payload length.
 * @param skip_bytes Number of bytes to skip based on protocol.
 * @return Pointer to the extracted payload on success, NULL on error.
 */
static unsigned char* extract_payload_n6(const u_char *packet, const struct pcap_pkthdr *hdr, size_t *payload_len, int skip_bytes) {
    size_t remaining = hdr->caplen;
    const unsigned char *p = packet;

    // 1. Skip specified bytes for N6 packets
    if (remaining < (size_t)skip_bytes) {
        return NULL;
    }
    p += skip_bytes;
    remaining -= skip_bytes;

    // 2. Check if Payload Exists
    if (remaining == 0) {
        *payload_len = 0;
        return NULL;
    }

    // 3. Extract Payload
    unsigned char *pl = malloc(remaining);
    if (!pl) {
        return NULL;
    }
    memcpy(pl, p, remaining);
    *payload_len = remaining;

    return pl;
}

/**
 * Inserts an N3 packet into the hashmap based on its payload hash.
 * @param payload Pointer to the packet payload.
 * @param len Length of the packet payload.
 * @param ts Timestamp of the packet.
 */
static void insert_n3_packet(const unsigned char *payload, size_t len, const struct timespec *ts) {
    unsigned int key = simple_hash(payload, len);

    packet_entry_t *entry = malloc(sizeof(packet_entry_t));
    if (!entry) {
        return;
    }
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
    total_n3_payload += len; // Increment total N3 payload
    pthread_mutex_unlock(&lock);
}

/**
 * Attempts to match an N6 packet with an N3 packet in the hashmap.
 * @param payload Pointer to the N6 packet payload.
 * @param len Length of the N6 packet payload.
 * @param ts_n6 Timestamp of the N6 packet.
 */
static void match_n6_packet(const unsigned char *payload, size_t len, const struct timespec *ts_n6) {
    unsigned int key = simple_hash(payload, len);

    pthread_mutex_lock(&lock);
    packet_entry_t *prev = NULL;
    packet_entry_t *curr = hashmap[key].head;

    while (curr) {
        if (curr->payload_len == len && memcmp(curr->payload, payload, len) == 0) {
            // Calculate latency in milliseconds
            double latency_ms = timespec_diff_ms(&curr->timestamp, ts_n6);

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
 * Cleanup thread function to remove expired packets from the hashmap.
 * @param arg Unused parameter.
 * @return NULL.
 */
static void *cleanup_thread_func(void *arg) {
    (void)arg;
    while (running) {
        usleep(CLEANUP_INTERVAL_MS * 1000); // 500 ms

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        pthread_mutex_lock(&lock);
        for (int i = 0; i < HASHMAP_SIZE; i++) {
            packet_entry_t *prev = NULL;
            packet_entry_t *curr = hashmap[i].head;
            while (curr) {
                double elapsed = (now.tv_sec - curr->timestamp.tv_sec) +
                                 (now.tv_nsec - curr->timestamp.tv_nsec) / 1e9;
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

    // Final Cleanup: Mark all remaining packets as lost
    pthread_mutex_lock(&lock);
    for (int i = 0; i < HASHMAP_SIZE; i++) {
        packet_entry_t *curr = hashmap[i].head;
        while (curr) {
            lost_packets++;
            packet_entry_t *next = curr->next;
            free(curr->payload);
            free(curr);
            curr = next;
        }
        hashmap[i].head = NULL;
    }
    pthread_mutex_unlock(&lock);
    return NULL;
}
 
// Second-by-Second Statistics Recording
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
 * Records current statistics (once per second) for throughput and latency analysis.
 */
static void record_stats() {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - start_time.tv_sec) + (now.tv_nsec - start_time.tv_nsec)/1e9;
    if (stats_count == stats_alloc) {
        stats_alloc = stats_alloc == 0 ? 128 : stats_alloc*2;
        stats_per_second = realloc(stats_per_second, stats_alloc * sizeof(second_stats_t));
        if (!stats_per_second) {
            fprintf(stderr, "Error reallocating stats_per_second\n");
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
 * Callback function to process N3 packets during live capture.
 * @param user Unused parameter.
 * @param h Packet metadata (pcap Header).
 * @param bytes Pointer to packet data.
 */
void callback_n3(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    size_t payload_len;
    int skip_bytes;

    // Determine the number of bytes to skip based on protocol
    if (current_protocol == PROTOCOL_UDP) {
        skip_bytes = 94; //remove Ethernet (14 Bytes), IP (20 B), UDP (8 B), GPRS (12 B), IP (20 B), UDP (8 B) and iPerf-Header (12 B)
    } else { // PROTOCOL_TCP
        skip_bytes = 106; //remove Ethernet (14 Bytes), IP (20 B), UDP (8 B), GPRS (12 B), IP (20 B) and TCP (32 B)
    }

    unsigned char *pl = extract_payload_n3(bytes, h, &payload_len, skip_bytes);
    if (!pl || payload_len == 0) {
        if (pl) free(pl);
        return;
    }

    // Convert timeval to timespec
    struct timespec ts;
    ts.tv_sec = h->ts.tv_sec;
    ts.tv_nsec = h->ts.tv_usec * 1000;

    insert_n3_packet(pl, payload_len, &ts);
    free(pl);
}

/**
 * Callback function to process N6 packets during live capture.
 * @param user Unused parameter.
 * @param h Packet metadata (pcap Header).
 * @param bytes Pointer to packet data.
 */
void callback_n6(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    size_t payload_len;
    int skip_bytes;

    // Determine the number of bytes to skip based on protocol
    if (current_protocol == PROTOCOL_UDP) {
        skip_bytes = 40; //remove IP-Header (20 Bytes), UDP-Header (8 Bytes) and iPerf3 Header (12 Bytes)
    } else { // PROTOCOL_TCP
        skip_bytes = 52; //remove IP-Header (20 Bytes) and TCP-Header (32 Bytes)
    }

    unsigned char *pl = extract_payload_n6(bytes, h, &payload_len, skip_bytes);
    if (!pl || payload_len == 0) {
        if (pl) free(pl);
        return;
    }
    pthread_mutex_lock(&lock);
    total_n6_packets++;
    pthread_mutex_unlock(&lock);

    // Convert timeval to timespec
    struct timespec ts;
    ts.tv_sec = h->ts.tv_sec;
    ts.tv_nsec = h->ts.tv_usec * 1000;

    match_n6_packet(pl, payload_len, &ts);
    free(pl);
}

/**
 * Prints usage information.
 */
void print_usage(const char *prog_name) {
    printf("Usage: %s [-tcp]\n", prog_name);
    printf("Options:\n");
    printf("  -tcp    Use TCP instead of UDP for payload extraction and filtering.\n");
    printf("  -h      Show this help message.\n");
}

/**
 * Main function to initialize packet capture and monitoring process.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success, otherwise error code.
 */
int main(int argc, char **argv) {
    // Manual Argument Parsing for simplicity
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-tcp") == 0) {
            current_protocol = PROTOCOL_TCP;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown Option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle_n3, *handle_n6;
    struct bpf_program fp_n3; 
    struct bpf_program fp_n6; 

    // Set up signal handler for SIGINT
    signal(SIGINT, handle_sigint);
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // Define BPF filter strings based on protocol
    char filter_n3[256];
    char filter_n6[256];
    if (current_protocol == PROTOCOL_UDP) {
        snprintf(filter_n3, sizeof(filter_n3), "src host 10.2.2.154 and udp port 2152");
        snprintf(filter_n6, sizeof(filter_n6), "dst host 10.2.2.157 and udp port 5201");
    } else { // PROTOCOL_TCP
        snprintf(filter_n3, sizeof(filter_n3), "src host 10.2.2.154");
        snprintf(filter_n6, sizeof(filter_n6), "dst host 10.2.2.157 and tcp port 5201");
    }

    // N3 Interface: host 10.2.2.154, only Uplink (source host)
    handle_n3 = pcap_open_live("ens18", BUFSIZ, 1, 1000, errbuf);
    if (!handle_n3) {
        fprintf(stderr, "Error opening N3 interface: %s\n", errbuf);
        return 1;
    }
    if (pcap_compile(handle_n3, &fp_n3, filter_n3, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling N3 filter: %s\n", pcap_geterr(handle_n3));
        pcap_close(handle_n3);
        return 1;
    }
    if (pcap_setfilter(handle_n3, &fp_n3) == -1) {
        fprintf(stderr, "Error setting N3 filter: %s\n", pcap_geterr(handle_n3));
        pcap_freecode(&fp_n3);
        pcap_close(handle_n3);
        return 1;
    }
    pcap_freecode(&fp_n3);

    // N6 Interface: host 10.2.2.157, only Uplink (destination host)
    handle_n6 = pcap_open_live("upfgtp", BUFSIZ, 1, 1000, errbuf);
    if (!handle_n6) {
        fprintf(stderr, "Error opening N6 interface: %s\n", errbuf);
        pcap_close(handle_n3);
        return 1;
    }

    if (pcap_compile(handle_n6, &fp_n6, filter_n6, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling N6 filter: %s\n", pcap_geterr(handle_n6));
        pcap_close(handle_n3);
        pcap_close(handle_n6);
        return 1;
    }
    if (pcap_setfilter(handle_n6, &fp_n6) == -1) {
        fprintf(stderr, "Error setting N6 filter: %s\n", pcap_geterr(handle_n6));
        pcap_freecode(&fp_n6);
        pcap_close(handle_n3);
        pcap_close(handle_n6);
        return 1;
    }
    pcap_freecode(&fp_n6);

    // Start Cleanup Thread
    pthread_t cleanup_thread;
    if (pthread_create(&cleanup_thread, NULL, cleanup_thread_func, NULL) != 0) {
        fprintf(stderr, "Error creating cleanup thread.\n");
        pcap_close(handle_n3);
        pcap_close(handle_n6);
        return 1;
    }

    // Set Non-Blocking Mode
    if (pcap_setnonblock(handle_n3, 1, errbuf) == -1) {
        fprintf(stderr, "Error setting non-blocking mode for N3: %s\n", errbuf);
    }
    if (pcap_setnonblock(handle_n6, 1, errbuf) == -1) {
        fprintf(stderr, "Error setting non-blocking mode for N6: %s\n", errbuf);
    }

    // Main Loop: Poll every 100 ms and record statistics every second
    while (running) {
        pcap_dispatch(handle_n3, -1, callback_n3, NULL);
        pcap_dispatch(handle_n6, -1, callback_n6, NULL);
        usleep(100000); // Poll every 100 ms

        static double last_sec = 0;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - start_time.tv_sec) + (now.tv_nsec - start_time.tv_nsec)/1e9;
        if (floor(elapsed) > last_sec) {
            last_sec = floor(elapsed);
            record_stats();
        }
    }

    // Terminate Cleanup Thread
    pthread_join(cleanup_thread, NULL);

    // Record Final Statistics
    record_stats();

    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double total_elapsed = (end_time.tv_sec - start_time.tv_sec) +
                           (end_time.tv_nsec - start_time.tv_nsec)/1e9;
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

    double upf_packet_rate = 0.0;
    if (total_elapsed > 0) {
        upf_packet_rate = (double)total_n6_packets / total_elapsed; // Packets/s
    }

    printf("\n==== Results ====\n");
    printf("Total Measurement Time: %.2f s\n", total_elapsed);
    printf("N3 Packets: %d\n", total_n3_packets);
    printf("N6 Packets: %d\n", total_n6_packets);
    printf("Matched Packets: %d\n", matched_packets);
    printf("Lost Packets: %d\n", lost_packets);
    printf("Packet Loss Rate: %.2f %%\n", packet_loss_rate*100.0);
    printf("Average Latency: %.2f ms\n", avg_latency);
    printf("Jitter: %.2f ms\n", jitter);
    printf("Matched Throughput: %.2f B/s (approx. %.2f Mbit/s)\n", matched_throughput, matched_throughput*8/1e6);
    printf("N3 Throughput: %.2f B/s (approx. %.2f Mbit/s)\n", n3_throughput, n3_throughput*8/1e6);
    printf("UPF Packet Rate: %.2f packets/s\n", upf_packet_rate);
    printf("====================\n");

    // Write CSV (Second-by-Second Data)
    FILE *fp_csv = fopen("results.csv", "w");
    if (fp_csv) {
        fprintf(fp_csv, "time_s,total_n3_packets,total_n6_packets,matched_packets,lost_packets,total_n3_payload,sum_matched_payload,n3_throughput_Bps,matched_throughput_Bps,upf_packet_rate_packets_s\n");
        for (int i = 0; i < stats_count; i++) {
            double dt = (i == 0) ? stats_per_second[i].elapsed : (stats_per_second[i].elapsed - stats_per_second[i-1].elapsed);
            // Calculate delta values for this interval:
            int delta_n3_packets = (i == 0) ? stats_per_second[i].total_n3_packets : (stats_per_second[i].total_n3_packets - stats_per_second[i-1].total_n3_packets);
            int delta_n6_packets = (i == 0) ? stats_per_second[i].total_n6_packets : (stats_per_second[i].total_n6_packets - stats_per_second[i-1].total_n6_packets);
            int delta_matched = (i == 0) ? stats_per_second[i].matched_packets : (stats_per_second[i].matched_packets - stats_per_second[i-1].matched_packets);
            int delta_lost = (i == 0) ? stats_per_second[i].lost_packets : (stats_per_second[i].lost_packets - stats_per_second[i-1].lost_packets);
            size_t delta_n3_payload = (i == 0) ? stats_per_second[i].total_n3_payload : (stats_per_second[i].total_n3_payload - stats_per_second[i-1].total_n3_payload);
            size_t delta_matched_payload = (i == 0) ? stats_per_second[i].sum_matched_payload : (stats_per_second[i].sum_matched_payload - stats_per_second[i-1].sum_matched_payload);

            double interval_n3_throughput = (dt > 0) ? (double)delta_n3_payload / dt : 0.0;
            double interval_matched_throughput = (dt > 0) ? (double)delta_matched_payload / dt : 0.0;
            double upf_packet_rate_s = (dt > 0) ? (double)delta_n6_packets / dt : 0.0;

            fprintf(fp_csv, "%.2f,%d,%d,%d,%d,%zu,%zu,%.2f,%.2f,%.2f\n",
                    stats_per_second[i].elapsed,
                    stats_per_second[i].total_n3_packets,
                    stats_per_second[i].total_n6_packets,
                    stats_per_second[i].matched_packets,
                    stats_per_second[i].lost_packets,
                    stats_per_second[i].total_n3_payload,
                    stats_per_second[i].sum_matched_payload,
                    interval_n3_throughput,
                    interval_matched_throughput,
                    upf_packet_rate_s);
        }
        fclose(fp_csv);
    } else {
        fprintf(stderr, "Could not open results.csv.\n");
    }

    pcap_close(handle_n3);
    pcap_close(handle_n6);
    free(stats_per_second);
    return 0;
}
