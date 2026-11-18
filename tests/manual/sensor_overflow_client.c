#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    uint64_t iterations = strtoull(argv[1], NULL, 10);
    for (uint64_t index = 0; index < iterations; index++) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) return 65;
        close(fd);
    }
    printf("%llu\n", (unsigned long long)iterations);
    return 0;
}
