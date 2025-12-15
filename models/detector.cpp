#include "detector.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <map>

void run_detector(const std::string& logPath) {
    std::cout << "[*] Starting detector on log file: " << logPath << std::endl;

    std::ifstream logFile(logPath);
    if (!logFile.is_open()) {
        std::cerr << "[!] Error: Could not open log file: " << logPath << std::endl;
        return;
    }

    std::string line;
    int total_entries = 0;
    std::map<std::string, int> ip_counts;

    while (std::getline(logFile, line)) {
        total_entries++;
        
        // Basic IP extraction: assume IP is the first word in the log line
        // This is a placeholder for a more robust log parser.
        size_t first_space = line.find(' ');
        if (first_space != std::string::npos) {
            std::string ip = line.substr(0, first_space);
            ip_counts[ip]++;
        }
    }

    logFile.close();

    std::cout << "[*] Log analysis complete." << std::endl;
    std::cout << "[*] Total log entries processed: " << total_entries << std::endl;

    // Simple scan detection logic: an IP with more than 5 connection attempts is suspicious
    int suspicious_threshold = 5;
    bool suspicious_activity_found = false;

    std::cout << "\n[*] Suspicious activity report (IPs with > " << suspicious_threshold << " entries):" << std::endl;
    for (const auto& pair : ip_counts) {
        if (pair.second > suspicious_threshold) {
            std::cout << "  [!] Potential Scanner IP: " << pair.first << " with " << pair.second << " entries." << std::endl;
            suspicious_activity_found = true;
        }
    }

    if (!suspicious_activity_found) {
        std::cout << "  [+] No suspicious activity detected based on the current threshold." << std::endl;
    }
    std::cout << "\n[*] Detector finished." << std::endl;
}