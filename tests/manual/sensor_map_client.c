#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    printf("%d\n", getpid());
    fflush(stdout);
    if (getchar() == EOF) return 64;
    if (argc != 3) return 64;
    int fd = open(argv[2], O_RDONLY);
    if (fd < 0) return 65;
    char byte;
    if (read(fd, &byte, 1) < 0) return 66;
    close(fd);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[1]))};
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (sock < 0 || connect(sock, (struct sockaddr *)&address, sizeof(address)) < 0) return 67;
    const char request[] = "POST /map-tamper HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 17\r\nConnection: close\r\n\r\nizanagi-dummy-136";
    if (write(sock, request, sizeof(request) - 1) != sizeof(request) - 1) return 68;
    char response[128];
    if (read(sock, response, sizeof(response)) <= 0) return 69;
    close(sock);
    return 0;
}
