#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

int main() {
    int raw_socket;
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);
    unsigned char *buffer = (unsigned char *)malloc(65536); // Buffer für Pakete

    // Erstelle RAW Socket für das Abhören von Ethernet Paketen
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0) {
        perror("Socket konnte nicht erstellt werden");
        return 1;
    }

    // Netzwerkschnittstelle auswählen (Ens18)
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "Ens18", IFNAMSIZ - 1); // Name der Schnittstelle
    if (ioctl(raw_socket, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl Fehler");
        close(raw_socket);
        return 1;
    }

    // Bind the socket to the specific interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex; // Interface index
    sll.sll_protocol = htons(ETH_P_ALL); // Alle Protokolle

    if (bind(raw_socket, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Socket konnte nicht an die Schnittstelle gebunden werden");
        close(raw_socket);
        return 1;
    }

    while (1) {
        // Lese eingehende Pakete
        ssize_t packet_size = recvfrom(raw_socket, buffer, 65536, 0, &saddr, &saddr_len);
        if (packet_size < 0) {
            perror("Fehler beim Empfangen des Pakets");
            return 1;
        }

        // Ethernet Header
        struct ethhdr *eth = (struct ethhdr *)buffer;
        printf("\nEthernet Header:\n");
        printf(" |-Source Address      : %02X:%02X:%02X:%02X:%02X:%02X \n",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        printf(" |-Destination Address : %02X:%02X:%02X:%02X:%02X:%02X \n",
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        printf(" |-Protocol            : %u \n", ntohs(eth->h_proto));

        // IP Header
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        struct sockaddr_in source, dest;
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = ip->saddr;
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = ip->daddr;

        printf("\nIP Header:\n");
        printf(" |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
        printf(" |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
        printf(" |-Protocol         : %u\n", (unsigned int)ip->protocol);
    }

    close(raw_socket);
    free(buffer);
    return 0;
}
