#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h> // Für die Funktion isprint()
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

// Funktion zum Schreiben eines Pakets in menschlich lesbarer Form in eine Datei
void write_packet_to_file(const unsigned char *data, int size, const char *src_ip) {
    FILE *file = fopen("packet_log.txt", "a"); // Datei im Anhängemodus öffnen
    if (file == NULL) {
        perror("Fehler beim Öffnen der Datei");
        return;
    }

    // IP-Header extrahieren
    struct iphdr *ip_header = (struct iphdr *)(data + sizeof(struct ethhdr));

    fprintf(file, "\n--- Paket von %s (%d Bytes) ---\n", src_ip, size);
    fprintf(file, "IP-Header:\n");
    fprintf(file, " - Version: %d\n", ip_header->version);
    fprintf(file, " - Headerlänge: %d\n", ip_header->ihl * 4);
    fprintf(file, " - Diensttyp: %d\n", ip_header->tos);
    fprintf(file, " - Gesamtlänge: %d\n", ntohs(ip_header->tot_len));
    fprintf(file, " - Identifikation: %d\n", ntohs(ip_header->id));
    fprintf(file, " - Flags: %d\n", ntohs(ip_header->frag_off) >> 13);
    fprintf(file, " - Fragment-Offset: %d\n", ntohs(ip_header->frag_off) & 0x1FFF);
    fprintf(file, " - TTL: %d\n", ip_header->ttl);
    fprintf(file, " - Protokoll: %d\n", ip_header->protocol);
    fprintf(file, " - Header-Prüfsumme: %d\n", ntohs(ip_header->check));

    struct in_addr src_addr, dest_addr;
    src_addr.s_addr = ip_header->saddr;
    dest_addr.s_addr = ip_header->daddr;
    fprintf(file, " - Quell-IP: %s\n", inet_ntoa(src_addr));
    fprintf(file, " - Ziel-IP: %s\n", inet_ntoa(dest_addr));

    // Payload anzeigen (als Hex und ASCII)
    fprintf(file, "\nPayload:\n");
    for (int i = ip_header->ihl * 4; i < size; i++) {
        if (i % 16 == 0) fprintf(file, "\n");
        fprintf(file, "%02X ", data[i]);

        // ASCII-Zeichen für druckbare Zeichen
        if (i % 16 == 15 || i == size - 1) {
            fprintf(file, " | ");
            for (int j = i - (i % 16); j <= i; j++) {
                fprintf(file, "%c", isprint(data[j]) ? data[j] : '.');
            }
        }
    }
    fprintf(file, "\n\n");
    fclose(file);
}

int main() {
    int sockfd;
    unsigned char buffer[BUF_SIZE];
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);
    char interface[10] = "upfgtp";  // Standardwert "upfgtp"
    char filter_choice[5] = "nein"; // Standardwert "nein"
    int use_filter = 0;

    // IP-Filterung Auswahl mit Standardwert "nein" bei Enter
    printf("IP-Filterung aktivieren? (ja/nein) [Standard: nein]: ");
    if (fgets(filter_choice, sizeof(filter_choice), stdin) != NULL) {
        filter_choice[strcspn(filter_choice, "\n")] = 0;
        if (strlen(filter_choice) == 0) {
            strcpy(filter_choice, "nein");
        }
    }

    // Interface Auswahl mit Standardwert "upfgtp" bei Enter
    printf("Wähle ein Interface (ens18 oder upfgtp) [Standard: upfgtp]: ");
    if (fgets(interface, sizeof(interface), stdin) != NULL) {
        interface[strcspn(interface, "\n")] = 0;
        if (strlen(interface) == 0) {
            strcpy(interface, "upfgtp");
        }
    }

    if (strcmp(filter_choice, "ja") == 0) {
        use_filter = 1;
    }

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

    printf("Erfasse Pakete auf Interface: %s", interface);
    if (use_filter) {
        printf(" (Nur von IP: %s)", FILTER_IP);
    }
    printf("...\n");

    // Endloses Erfassen und Anzeigen des Bytestreams
    while (1) {
        int packet_size = recvfrom(sockfd, buffer, BUF_SIZE, 0, &saddr, &saddr_len);
        if (packet_size < 0) {
            perror("Fehler beim Empfangen des Pakets");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));

        struct in_addr source_addr;
        source_addr.s_addr = ip_header->saddr;

        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(source_addr), src_ip, INET_ADDRSTRLEN);

        if (!use_filter || (use_filter && strcmp(src_ip, FILTER_IP) == 0)) {
            printf("Paket von %s empfangen\n", src_ip);
            write_packet_to_file(buffer, packet_size, src_ip);
        }
    }

    close(sockfd);
    return 0;
}