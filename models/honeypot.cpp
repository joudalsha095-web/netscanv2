#include "honeypot.hpp"
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif
#include <ctime>

#define MAX_PENDING_CONNECTIONS 10

void run_honeypot(int port, const std::string& banner) {
    int listen_fd, conn_fd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t cli_len = sizeof(cli_addr);

    std::cout << "[*] Starting honeypot on port " << port << "...\n";

    // 1. Create socket file descriptor
    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        return;
    }

  int enable_reuse = 1;
int result = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, 
                        (const char*)&enable_reuse, sizeof(enable_reuse));

if (result < 0) {
    perror("Failed to set socket option SO_REUSEADDR");
    close(listen_fd);
    return;
}

    // 2. Prepare the sockaddr_in structure
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    // 3. Bind the socket to the specified port
    if (bind(listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind failed");
        close(listen_fd);
        return;
    }

    // 4. Listen for incoming connections
    if (listen(listen_fd, MAX_PENDING_CONNECTIONS) < 0) {
        perror("listen failed");
        close(listen_fd);
        return;
    }

    std::cout << "[*] Honeypot listening for connections...\n";

    while (true) {
        // 5. Accept an incoming connection
        conn_fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (conn_fd < 0) {
            perror("accept failed");
            continue;
        }

        // Get current time for logging
        time_t now = time(0);
        char* dt = ctime(&now);
        // Remove trailing newline from ctime output
        if (dt[strlen(dt) - 1] == '\n') {
            dt[strlen(dt) - 1] = '\0';
        }

        // Log the connection
        std::cout << "--------------------------------------------------\n";
        std::cout << "[!] Connection detected!\n";
        std::cout << "[*] Time: " << dt << "\n";
        std::cout << "[*] Source IP: " << inet_ntoa(cli_addr.sin_addr) << "\n";
        std::cout << "[*] Source Port: " << ntohs(cli_addr.sin_port) << "\n";
        std::cout << "[*] Target Port: " << port << "\n";
        
        // 6. Send the banner
        if (!banner.empty()) {
            std::string full_banner = banner + "\r\n";
            send(conn_fd, full_banner.c_str(), full_banner.length(), 0);
            std::cout << "[*] Sent banner: \"" << banner << "\"\n";
        }

        // 7. Read any data sent by the client (optional, for more logging)
        char buffer[1024] = {0};
        ssize_t valread = recv(conn_fd, buffer, 1024, 0);
        if (valread > 0) {
            std::cout << "[*] Received data: " << std::string(buffer, valread) << "\n";
        }

        // 8. Close the connection
        close(conn_fd);
        std::cout << "[*] Connection closed.\n";
        std::cout << "--------------------------------------------------\n";
    }

    // This part is unreachable in the current infinite loop, but good practice
    close(listen_fd);
}
