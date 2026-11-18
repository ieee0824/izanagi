#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 64;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[1]))};
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) return 65;
    char request[512];
    int length = snprintf(request, sizeof(request),
        "POST /%s HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 17\r\nConnection: close\r\n\r\nizanagi-dummy-136",
        argv[2]);
    if (write(fd, request, length) != length) return 66;
    char response[256];
    int received = read(fd, response, sizeof(response) - 1);
    if (received <= 0) return 67;
    response[received] = 0;
    if (!strstr(response, " 200 ")) return 68;
    struct sockaddr_in local;
    socklen_t local_length = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_length) != 0) return 69;
    printf("{\"pid\":%d,\"local_port\":%u,\"status\":200}\n", getpid(), ntohs(local.sin_port));
    close(fd);
    return 0;
}
