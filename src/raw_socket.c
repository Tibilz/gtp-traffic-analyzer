// raw_socket.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include "raw_socket.h"
#include "util.h"


int create_raw_socket(char *interface) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Raw socket erstellen fehlgeschlagen");
        exit(1);
    }
    
    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface));
    return sock;
}

void mirror_packets(int sock) {
    char buffer[65536];
    
    while (1) {
        int packet_len = recvfrom(sock, buffer, 65536, 0, NULL, NULL);
        if (packet_len < 0) {
            perror("Packet Empfang fehlgeschlagen");
            continue;
        }
        
        printf("Packet erhalten: %d bytes\n", packet_len);
        // Paket zur weiteren Verarbeitung (Vergleich) weitergeben
        compare_packet(buffer, packet_len);
    }
}
