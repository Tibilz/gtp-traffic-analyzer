// util.c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "util.h"

// Beispiel-Header-Struktur für GTP
struct gtp_header {
    uint8_t flags;
    uint8_t message_type;
    uint16_t length;
    uint32_t teid;
};

// Beispiel-Header-Struktur für UPF-GTP (vereinfacht)
struct upfgtp_header {
    uint8_t version;
    uint8_t type;
    uint16_t length;
};

// Gibt die Header von GTP-Paketen aus
void print_gtp_header(const char *packet, int packet_len) {
    if (packet_len < sizeof(struct gtp_header)) {
        printf("Paket ist zu klein für einen GTP-Header\n");
        return;
    }

    struct gtp_header *header = (struct gtp_header *)packet;
    
    printf("GTP-Paket Header:\n");
    printf("Flags: %d\n", header->flags);
    printf("Message Type: %d\n", header->message_type);
    printf("Length: %d\n", ntohs(header->length));  // Netzwerk-Byte-Order beachten
    printf("TEID: %d\n", ntohl(header->teid));  // Netzwerk-Byte-Order beachten
}


// Gibt die Header von UPF-GTP-Paketen aus
void print_upfgtp_header(const char *packet, int packet_len) {
    struct upfgtp_header *header = (struct upfgtp_header *)packet;
    printf("UPF-GTP-Paket Header:\n");
    printf("Version: %d\n", header->version);
    printf("Type: %d\n", header->type);
    printf("Length: %d\n", ntohs(header->length));
}

// Vergleicht die Pakete (Placeholder für Vergleichslogik)
void compare_packet(const char *packet, int packet_len) {
    printf("Vergleiche Paket mit Länge %d\n", packet_len);

    // Debug: Paketinhalt anzeigen
    print_packet_hexdump(packet, packet_len);

    if (is_gtp_packet(packet)) {
        printf("GTP-Paket erkannt\n");
        print_gtp_header(packet, packet_len);  // GTP-Header anzeigen
    } else if (is_ipv4_packet(packet)) {
        printf("IPv4-Paket erkannt\n");
        print_ip_header(packet);  // IPv4-Header anzeigen
    } else {
        printf("Unbekanntes Paket\n");
    }
}



// Beispiel-Logik zur Erkennung von GTP-Paketen
int is_gtp_packet(const char *packet) {
    // Überprüfe, ob das erste Byte die erwartete Version und Art des GTP-Headers enthält
    uint8_t first_byte = packet[0];
    
    // GTPv1-Pakete haben die Version 1 und das "Protocol Type"-Bit gesetzt (0x30)
    return (first_byte >> 4) == 0x3;
}


// Beispiel-Logik zur Erkennung von UPF-GTP-Paketen
int is_upfgtp_packet(const char *packet) {
    // Platzhalter: Implementiere die Logik zum Erkennen eines UPF-GTP-Pakets
    return 0; // Angenommen, es ist kein UPF-GTP-Paket
}

// Filtert die Pakete (Placeholder für Filterlogik)
void filter_packet(const char *packet, int packet_len) {
    printf("Paket gefiltert.\n");
}

// Überwacht ein Interface und empfängt Pakete
void monitor_interface(void *sock_fd) {
    int sock = *(int *)sock_fd;
    char buffer[65536];

    int packet_len = recvfrom(sock, buffer, 65536, 0, NULL, NULL);
    if (packet_len < 0) {
        perror("Packet Empfang fehlgeschlagen");
        return;
    }
    printf("Packet erhalten: %d bytes\n", packet_len);
    
    // Filter anwenden
    filter_packet(buffer, packet_len);
    
    // Vergleich der Pakete
    compare_packet(buffer, packet_len);
}

void print_packet_hexdump(const char *packet, int packet_len) {
    printf("Packet Dump (hex):\n");
    for (int i = 0; i < packet_len; i++) {
        printf("%02x ", (unsigned char)packet[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

int is_ipv4_packet(const char *packet) {
    // Überprüfe den EtherType (Offset 12 im Ethernet-Frame) auf IPv4 (0x0800)
    uint16_t ether_type = (packet[12] << 8) | packet[13];
    return ether_type == 0x0800;
}

void print_ip_header(const char *packet) {
    printf("IPv4-Paket Header:\n");
    printf("Version: %d\n", (packet[14] >> 4) & 0xF);
    printf("IHL (Header Length): %d\n", packet[14] & 0xF);
    printf("Total Length: %d\n", ntohs(*(uint16_t *)&packet[16]));
}
