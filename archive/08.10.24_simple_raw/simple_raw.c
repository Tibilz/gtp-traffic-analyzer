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

#define BUF_SIZE 65536

// Hardcodierte IP-Adresse für die Filterung
const char *FILTER_IP = "10.2.2.154";

void print_packet(const unsigned char *data, int size) {
    printf("\nPacket (%d bytes):\n", size);
    for (int i = 0; i < size; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

int main() {
    int sockfd;
    unsigned char buffer[BUF_SIZE];
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);
    char interface[10];

    // Interface Auswahl
    printf("Wähle ein Interface (ens18 oder upfgtp): ");
    scanf("%s", interface);

    // Erstellen eines Raw Sockets
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket konnte nicht erstellt werden");
        exit(EXIT_FAILURE);
    }

    // Interface auf das Raw Socket binden
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("Interface konnte nicht gefunden werden");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Socket an das Interface binden
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

    printf("Erfasse Pakete auf Interface: %s (Nur von IP: %s)...\n", interface, FILTER_IP);

    // Endloses Erfassen und Anzeigen des Bytestreams
    while (1) {
        // Pakete erfassen
        int packet_size = recvfrom(sockfd, buffer, BUF_SIZE, 0, &saddr, &saddr_len);
        if (packet_size < 0) {
            perror("Fehler beim Empfangen des Pakets");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // IP-Header analysieren
        struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr)); // IP-Header nach Ethernet-Header

        // Quell-IP-Adresse abrufen
        struct in_addr source_addr;
        source_addr.s_addr = ip_header->saddr;

        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(source_addr), src_ip, INET_ADDRSTRLEN);

        // Nur Pakete von der spezifischen IP-Adresse anzeigen
        if (strcmp(src_ip, FILTER_IP) == 0) {
            printf("Paket von %s empfangen\n", src_ip);
            print_packet(buffer, packet_size);
        }
    }

    close(sockfd);
    return 0;
}
