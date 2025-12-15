#ifndef HONEYPOT_HPP
#define HONEYPOT_HPP

#include <string>

/**
 * @brief Runs a simple TCP honeypot on the specified port.
 * 
 * When a connection is received, it sends the provided banner message
 * and logs the connection details before closing the socket.
 * 
 * @param port The TCP port to listen on.
 * @param banner The message to send to the connecting client.
 */
void run_honeypot(int port, const std::string& banner);

#endif // HONEYPOT_HPP
