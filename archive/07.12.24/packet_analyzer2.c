#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define HASHMAP_SIZE 1024
#define TIMEOUT_SECONDS 2
#define CLEANUP_INTERVAL_MS 500
#define BUFFER_SIZE 65536

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

static unsigned int simple_hash(const unsigned char *data, size_t len) {
    if (!data || len == 0) {  // NULL-Überprüfung und leere Eingabe
        fprintf(stderr, "Error: Invalid input to simple_hash\n");
        return 0; // Rückgabe eines Standardwerts
    }

    unsigned int hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash % HASHMAP_SIZE;
}


static int parse_ip_header(const unsigned char *data, size_t len) {
    if (len < sizeof(struct iphdr)) return -1;
    struct iphdr *ip = (struct iphdr *)data;
    return ip->ihl * 4; // Header length in bytes
}

static int parse_tcp_header(const unsigned char *data, size_t len) {
    if (len < sizeof(struct tcphdr)) return -1;
    struct tcphdr *tcp = (struct tcphdr *)data;
    return tcp->doff * 4; // Header length in bytes
}

static void insert_n3_packet(const unsigned char *payload, size_t len, const struct timeval *ts) {
    if (!payload || len == 0) {
    fprintf(stderr, "Error: Invalid payload in insert_n3_packet\n");
    return;
    }

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

static void process_packet(const unsigned char *packet, size_t len, const char *interface_name) {
    struct timeval ts;
    gettimeofday(&ts, NULL);

    // Ethernet
    if (len < sizeof(struct ethhdr)) return;
    const unsigned char *p = packet + sizeof(struct ethhdr);
    len -= sizeof(struct ethhdr);

    // IP
    int ip_len = parse_ip_header(p, len);
    if (ip_len < 0) return;
    p += ip_len;
    len -= ip_len;

    // TCP
    int tcp_len = parse_tcp_header(p, len);
    if (tcp_len < 0) return;
    p += tcp_len;
    len -= tcp_len;

    if (strcmp(interface_name, "ens18") == 0) { // N3
        if (!p || len == 0) {
            fprintf(stderr, "Error: Invalid payload in process_packet\n");
            return;
        }

        insert_n3_packet(p, len, &ts);
    } else if (strcmp(interface_name, "upfgtp") == 0) { // N6
        match_n6_packet(p, len, &ts);
    }
}

void *capture_packets(void *arg) {
    char *interface_name = (char *)arg;
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket erstellen fehlgeschlagen");
        return NULL;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(interface_name);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Bind fehlgeschlagen");
        close(sock);
        return NULL;
    }

    unsigned char buffer[BUFFER_SIZE];
    while (running) {
        ssize_t packet_len = recvfrom(sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (packet_len > 0) {
            process_packet(buffer, packet_len, interface_name);
        }
    }

    close(sock);
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGINT, handle_sigint);
    gettimeofday(&start_time, NULL);

    pthread_t thread_n3, thread_n6;

    if (pthread_create(&thread_n3, NULL, capture_packets, "ens18") != 0) {
        fprintf(stderr, "Fehler beim Starten von N3-Thread\n");
        return 1;
    }

    if (pthread_create(&thread_n6, NULL, capture_packets, "upfgtp") != 0) {
        fprintf(stderr, "Fehler beim Starten von N6-Thread\n");
        return 1;
    }

    pthread_join(thread_n3, NULL);
    pthread_join(thread_n6, NULL);

    printf("Erfassung beendet. Ergebnisse:\n");
    printf("Total N3 Packets: %d\n", total_n3_packets);
    printf("Total N6 Packets: %d\n", total_n6_packets);
    printf("Matched Packets: %d\n", matched_packets);

    return 0;
}
