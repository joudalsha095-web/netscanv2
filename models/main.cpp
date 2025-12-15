#include "scanner.hpp"
#include "detector.hpp"
#include "honeypot.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

static void print_usage(const char *progName) {
    std::cout
        << "Usage:\n"
        << "  " << progName << " --scan <ip> -p <start>-<end> [--timeout <ms>]\n"
        << "  " << progName << " --detect [--log <path>]\n"
        << "  " << progName << " --honeypot -p <port> [--banner <message>]\n\n"
        << "Examples:\n"
        << "  " << progName << " --scan 127.0.0.1 -p 1-1000\n"
        << "  " << progName << " --detect\n"
        << "  " << progName << " --honeypot -p 22 --banner \"SSH-2.0-OpenSSH_8.2p1\"\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];

    // -------- SCAN MODE --------
    if (mode == "--scan") {
        if (argc < 5) {
            std::cerr << "[!] Not enough arguments for scan mode.\n\n";
            print_usage(argv[0]);
            return 1;
        }

        std::string targetIp = argv[2];

        if (std::string(argv[3]) != "-p") {
            std::cerr << "[!] Expected -p <start>-<end> for port range.\n\n";
            print_usage(argv[0]);
            return 1;
        }

        std::string range = argv[4];
        int dashPos = static_cast<int>(range.find('-'));
        if (dashPos == -1) {
            std::cerr << "[!] Port range must be in the form start-end (e.g. 1-1000).\n";
            return 1;
        }

        int startPort = std::atoi(range.substr(0, dashPos).c_str());
        int endPort   = std::atoi(range.substr(dashPos + 1).c_str());

        int timeoutMs = 3000; // default global timeout for epoll_wait

        if (argc >= 7 && std::string(argv[5]) == "--timeout") {
            timeoutMs = std::atoi(argv[6]);
        }

        run_scanner(targetIp, startPort, endPort, timeoutMs);
        return 0;
    }

    // -------- DETECT MODE --------
    //Joud part !!!
     if (mode == "--detect") {
    std::string logPath = "/var/log/syslog";

    if (argc > 2) {
        if (argc == 4 && std::string(argv[2]) == "--log") {
            logPath = argv[3];
        } else {
            std::cerr << "[!] Usage: --detect [--log <path>]\n";
            return 1;
        }
    }

    run_detector(logPath);   
    return 0;
}

    // -------- HONEYPOT MODE --------
    if (mode == "--honeypot") {
        if (argc < 4 || std::string(argv[2]) != "-p") {
            std::cerr << "[!] Expected -p <port> for honeypot mode.\n\n";
            print_usage(argv[0]);
            return 1;
        }

        int port = std::atoi(argv[3]);
        std::string banner = "";

        if (argc >= 6 && std::string(argv[4]) == "--banner") {
            banner = argv[5];
        }

        run_honeypot(port, banner);
        return 0;
    }

    // -------- UNKNOWN MODE --------
    std::cerr << "[!] Unknown mode: " << mode << "\n\n";
    print_usage(argv[0]);
    return 1;
}