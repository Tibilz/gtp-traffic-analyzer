#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <zlib.h> // Für CRC32-Berechnung

#define BUF_SIZE 65536
#define FILTER_IP "10.2.2.154"

// CRC32-Hashfunktion
unsigned int calculate_crc32(const unsigned char *data, int size) {
    return crc32(0, data, size);
}

// Funktion zur Initialisierung des Raw Sockets für ein Interface
int init_raw_socket(const char *interface) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket konnte nicht erstellt werden");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("Interface konnte nicht gefunden werden");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Bind fehlgeschlagen");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

// Funktion zum Extrahieren des Payloads aus dem IP-Paket
unsigned char* get_ip_payload(const unsigned char *packet, int packet_size, int *payload_size) {
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    int ip_header_length = ip_header->ihl * 4;  // Länge des IP-Headers

    // Berechnung der Größe des Payloads
    *payload_size = ntohs(ip_header->tot_len) - ip_header_length;
    return (unsigned char *)(packet + sizeof(struct ethhdr) + ip_header_length);
}

// Funktion zum Empfang und Hashing von Paketen
void capture_and_hash(int ens18_sock, int upfgtp_sock, int packet_count) {
    unsigned char buffer_ens18[BUF_SIZE], buffer_upfgtp[BUF_SIZE];
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);
    int received_ens18 = 0, received_upfgtp = 0;

    while (received_ens18 < packet_count && received_upfgtp < packet_count) {
        int packet_size_ens18 = recvfrom(ens18_sock, buffer_ens18, BUF_SIZE, 0, &saddr, &saddr_len);
        if (packet_size_ens18 > 0) {
            struct iphdr *ip_header = (struct iphdr *)(buffer_ens18 + sizeof(struct ethhdr));
            struct in_addr source_addr;
            source_addr.s_addr = ip_header->saddr;
            char src_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(source_addr), src_ip, INET_ADDRSTRLEN);

            if (strcmp(src_ip, FILTER_IP) == 0) {
                int payload_size_ens18;
                unsigned char *payload_ens18 = get_ip_payload(buffer_ens18, packet_size_ens18, &payload_size_ens18);
                unsigned int hash_ens18 = calculate_crc32(payload_ens18, payload_size_ens18);
                received_ens18++;

                int packet_size_upfgtp = recvfrom(upfgtp_sock, buffer_upfgtp, BUF_SIZE, 0, &saddr, &saddr_len);
                if (packet_size_upfgtp > 0) {
                    int payload_size_upfgtp;
                    unsigned char *payload_upfgtp = get_ip_payload(buffer_upfgtp, packet_size_upfgtp, &payload_size_upfgtp);
                    unsigned int hash_upfgtp = calculate_crc32(payload_upfgtp, payload_size_upfgtp);
                    received_upfgtp++;

                    if (hash_ens18 == hash_upfgtp) {
                        printf("Paket %d: true (Pakete sind gleich)\n", received_ens18);
                    } else {
                        printf("Paket %d: false (Pakete sind ungleich)\n", received_ens18);
                    }
                }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    int mode = 1;
    int packet_count = 1; // Standardmäßig ein Paket pro Interface

    if (argc > 1) {
        mode = atoi(argv[1]);
        if (mode == 2 && argc > 2) {
            packet_count = atoi(argv[2]);
        }
    }

    // Initialisierung der Raw Sockets für ens18 und upfgtp
    int ens18_sock = init_raw_socket("ens18");
    int upfgtp_sock = init_raw_socket("upfgtp");

    printf("Starte Paketaufzeichnung (Mode %d, %d Pakete)\n", mode, packet_count);
    capture_and_hash(ens18_sock, upfgtp_sock, packet_count);

    close(ens18_sock);
    close(upfgtp_sock);

    return 0;
}