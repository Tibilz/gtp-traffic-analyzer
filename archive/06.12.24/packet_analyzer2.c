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

// Rest of structures remain the same

static void free_packet_info(struct packet_info *pinfo) {
    if (pinfo) {
        free(pinfo->payload);
        free(pinfo);
    }
}

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
    return 0;
}

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

    if (payload_len == 0 || payload_len > header->caplen) {
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
        HASH_ADD_INT(packets_table, hash, entry);
    }
    
    pinfo->next = entry->packets;
    entry->packets = pinfo;
    stats.total_n3++;
    pthread_mutex_unlock(&hash_mutex);

    LOG(LOG_INFO, "Processed N3 packet: len=%zu hash=%u", payload_len, hash);
}

// Similar improvements for process_n6_packet()...

static void parse_args(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"n3-interface", required_argument, 0, '3'},
        {"n6-interface", required_argument, 0, '6'},
        {"source-ip", required_argument, 0, 's'},
        {"gtp-port", required_argument, 0, 'p'},
        {"timeout", required_argument, 0, 't'},
        {"cleanup-interval", required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "3:6:s:p:t:c:", long_options, NULL)) != -1) {
        switch (opt) {
            case '3':
                strncpy(config.n3_interface, optarg, sizeof(config.n3_interface) - 1);
                break;
            case '6':
                strncpy(config.n6_interface, optarg, sizeof(config.n6_interface) - 1);
                break;
            case 's':
                strncpy(config.source_ip, optarg, sizeof(config.source_ip) - 1);
                break;
            case 'p':
                config.gtp_port = atoi(optarg);
                break;
            case 't':
                config.timeout_sec = atoi(optarg);
                break;
            case 'c':
                config.cleanup_interval_ms = atoi(optarg);
                break;
        }
    }
}

int main(int argc, char *argv[]) {
    parse_args(argc, argv);
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