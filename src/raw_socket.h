// raw_socket.h
#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

int create_raw_socket(char *interface);
void mirror_packets(int sock);

#endif
