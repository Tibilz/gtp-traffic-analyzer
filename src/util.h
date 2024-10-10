// util.h
#ifndef UTIL_H
#define UTIL_H

void compare_packet(const char *packet, int packet_len);
int is_gtp_packet(const char *packet);
int is_upfgtp_packet(const char *packet);
void filter_packet(const char *packet, int packet_len);
void monitor_interface(void *sock_fd);

// Header-Druckfunktionen
void print_gtp_header(const char *packet, int packet_len);
void print_upfgtp_header(const char *packet, int packet_len);

int is_ipv4_packet(const char *packet);
// Funktion zur Anzeige des IPv4-Headers
void print_ip_header(const char *packet);

void print_packet_hexdump(const char *packet, int packet_len);


#endif
