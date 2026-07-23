#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

int main(int argc, char **argv) {
    if (argc != 6) {
        std::cerr << "usage: witness_client HOST PORT CHECK|COMMIT VAULT_ID VERSION\n"; return 2;
    }
    addrinfo hints{}, *result = nullptr; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(argv[1], argv[2], &hints, &result) != 0) return 2;
    int fd = -1;
    for (auto *p = result; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd >= 0 && connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        if (fd >= 0) close(fd); fd = -1;
    }
    freeaddrinfo(result);
    if (fd < 0) { std::cerr << "cannot connect to witness\n"; return 2; }
    const std::string request = std::string(argv[3]) + " " + argv[4] + " " + argv[5] + "\n";
    if (write(fd, request.data(), request.size()) != static_cast<ssize_t>(request.size())) return 2;
    std::string response; char buf[128]; ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) response.append(buf, static_cast<std::size_t>(n));
    close(fd); std::cout << response;
    return response.rfind("OK ", 0) == 0 ? 0 : (response.rfind("ROLLBACK ", 0) == 0 ? 10 : 11);
}

