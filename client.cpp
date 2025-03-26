#include <iostream>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <chrono>
#include <thread>

#define SERVER_IP "127.0.0.1"
#define SERVER_UDP_PORT 12345
#define SERVER_TCP_PORT 12346
#define HEARTBEAT_INTERVAL 1  // 秒
#define MAX_HEARTBEAT_TIMEOUT 5

#include <csignal>
#include <atomic>

std::atomic<bool> running{true};

void signal_handler(int signum) {
    running = false;
    std::cout << "Shutting down client..." << std::endl;
}

// 发送UDP心跳
void send_udp_heartbeat(int udp_socket, struct sockaddr_in &server_addr) {
    std::string client_id = "client_1";
    int heartbeat_count = 0;

    while (true) {
        // 发送UDP心跳
        std::string message = client_id + " heartbeat";
        sendto(udp_socket, message.c_str(), message.size(), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
        std::cout << "Sent heartbeat: " << message << std::endl;

        // 接收服务端确认
        char buffer[1024];
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);

        int n = recvfrom(udp_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&from_addr, &from_len);
        if (n < 0) {
            std::cerr << "UDP receive failed" << std::endl;
            heartbeat_count++;
        } else {
            buffer[n] = '\0';
            if (std::string(buffer) == "Heartbeat ACK from server") {
                std::cout << "Received heartbeat ACK from server" << std::endl;
                heartbeat_count = 0;  // 重置心跳计数器
            }
        }

        if (heartbeat_count >= MAX_HEARTBEAT_TIMEOUT) {
            std::cout << "Heartbeat timeout, client " << client_id << " is offline." << std::endl;
            break;
        }

        std::this_thread::sleep_for(std::chrono::seconds(HEARTBEAT_INTERVAL));
    }
}

// 发送TCP请求
void send_tcp_request(int tcp_socket) {
    std::string message = "Hello, server!";
    send(tcp_socket, message.c_str(), message.size(), 0);

    char buffer[1024];
    int n = read(tcp_socket, buffer, sizeof(buffer));
    if (n > 0) {
        buffer[n] = '\0';
        std::cout << "Received TCP response: " << buffer << std::endl;
    } else {
        std::cerr << "TCP read failed" << std::endl;
    }
}

int main() {
    signal(SIGINT, signal_handler);  // 处理 Ctrl+C
    signal(SIGTSTP, signal_handler); // 处理 Ctrl+Z
    // 创建UDP套接字
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0) {
        std::cerr << "UDP socket creation failed" << std::endl;
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(SERVER_UDP_PORT);

    // 启动UDP心跳发送线程
    std::thread udp_thread(send_udp_heartbeat, udp_socket, std::ref(server_addr));
    udp_thread.detach();  // Detach to run independently

    // 创建TCP套接字
    int tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_socket < 0) {
        std::cerr << "TCP socket creation failed" << std::endl;
        return 1;
    }

    server_addr.sin_port = htons(SERVER_TCP_PORT);
    if (connect(tcp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "TCP connection failed" << std::endl;
        return 1;
    }

    // 发送TCP请求
    send_tcp_request(tcp_socket);

    // 保持主程序运行
    std::cout << "Client running, press Ctrl+C to stop..." << std::endl;
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(10));  // 每10秒保持一次活动
    }

    // 关闭UDP和TCP套接字
    close(udp_socket);
    close(tcp_socket);

    return 0;
}
