#include <iostream>
#include <unordered_map>
#include <thread>
#include <chrono>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include<vector>

#define MAX_HEARTBEAT_TIMEOUT 5
#define HEARTBEAT_INTERVAL 1  // 秒
#define TCP_PORT 12346        // TCP端口
#define UDP_PORT 12345 

std::unordered_map<std::string,int> client_heartbeat;
// 存储客户端的套接字文件描述符
std::unordered_map<std::string, int> client_sockets;

void UdpHeartbeatHandler(int udpSocket)
{
    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    char buffer[1024];

    while(true)
    {
        int n = recvfrom(udpSocket,buffer,sizeof(buffer),0,(struct sockaddr*)&clientAddr,&addrLen);
        if(n<0)
        {
            std::cerr << "UDP receive failed" << std::endl;
            continue;
        }
        buffer[n] = '\0';
        std::string message(buffer);

        size_t spacePos = message.find(" ");
        if(spacePos == std::string::npos)
        {
            std::cerr << "Invalid heartbeat message: " << message << std::endl;
            continue;
        }

        std::string clientId = message.substr(0,spacePos);
        std::string msgType = message.substr(spacePos+1);

        if(msgType == "heartbeat")
        {
           // std::cout << "Received heartbeat from " << clientId << std::endl();
            // 重置心跳计数器
            client_heartbeat[clientId] = 0;

            // 发送心跳确认消息
            std::string ack_msg = "Heartbeat ACK from server";
            sendto(udpSocket,ack_msg.c_str(),ack_msg.size(),0,(struct sockaddr*)&clientAddr,addrLen);
        }

    } 
}

void HeartbeatCheck()
{
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(HEARTBEAT_INTERVAL));
        // 增加所有客户端的心跳计数器
        for (auto& entry : client_heartbeat) {
            entry.second++;  // 每次检查递增计数器
        }
        std::vector<std::string> toRemove;
        for(auto &entry:client_heartbeat)
        {
            if(entry.second >= MAX_HEARTBEAT_TIMEOUT)
            {
                std::cout << "Client " << entry.first << " timed out. Removing connection..." << std::endl;
                toRemove.push_back(entry.first);
            }
        }
        for(const auto&clientId : toRemove)
        {
            //关闭对应的套接字
            if(client_sockets.find(clientId)!=client_sockets.end())
            {
                close(client_sockets[clientId]);
                client_sockets.erase(clientId);
                std::cout << "Client " << clientId << " dadadadadan..." << std::endl;
            }
            client_heartbeat.erase(clientId);
        }
    }
    
}

void HandleTcpClient(int fd)
{
    char buffer[1024];
    std::string clientId = std::to_string(fd);

    client_heartbeat[clientId] = 0;
    client_sockets[clientId] = fd;

    while (true)
    {
         memset(buffer, 0, sizeof(buffer));
        int n = read(fd, buffer, sizeof(buffer));
        if (n <= 0) 
        {
            std::cout << "Client disconnected" << std::endl;
            break;
        }
        std::string message(buffer);
        std::cout << "Received TCP message: " << message << std::endl;
        // 每次接收到数据时重置客户端心跳计数
        client_heartbeat[clientId] = 0;

        // 回复客户端
        std::string reply = "TCP Response: " + message;
        send(fd, reply.c_str(), reply.size(), 0);
    }
        while (true) {
        int n = read(fd, buffer, sizeof(buffer));
        if (n <= 0) {
            std::cout << "Client disconnected" << std::endl;
            break;
        }
        // 每次接收到数据时重置心跳计数
        client_heartbeat[clientId] = 0;
    }
     // 断开连接后删除客户端心跳记录和套接字
    client_heartbeat.erase(clientId);
    close(fd);
    client_sockets.erase(clientId);
    
}

int main()
{
    int udpfd = socket(AF_INET,SOCK_DGRAM,0);
    if(udpfd<0)
    {
        std::cerr << "UDP socket creation failed" << std::endl;
        return 1;
    }

    struct sockaddr_in serverAddr;
     memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(UDP_PORT);

    if(bind(udpfd,(const struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        std::cerr << "UDP Bind failed" << std::endl;
        close(udpfd);
        return 1;
    }

    
    int tcpfd = socket(AF_INET, SOCK_STREAM, 0);
    if(tcpfd<0)
    {
        std::cerr << "TCP socket creation failed" << std::endl;
        return 1;
    }

    serverAddr.sin_port = htons(TCP_PORT);
    if(bind(tcpfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        std::cerr << "TCP socket creation failed" << std::endl;
        return 1;
    }

    if (listen(tcpfd, 5) < 0) {
        std::cerr << "TCP Listen failed" << std::endl;
        close(tcpfd);
        return 1;
    }

     // 启动心跳检查线程
    std::thread heartbeat_thread(HeartbeatCheck);
    heartbeat_thread.detach();

    // 启动UDP处理线程
    std::thread udp_thread(UdpHeartbeatHandler, udpfd);
    udp_thread.detach();

    std::cout << "Server is running. Waiting for client heartbeats and TCP requests..." << std::endl;

    // 处理TCP连接
    while (true) 
    {
        int client_socket = accept(tcpfd, nullptr, nullptr);
        if (client_socket < 0) 
        {
            std::cerr << "TCP accept failed" << std::endl;
            continue;
        }

        std::thread tcp_thread(HandleTcpClient, client_socket);
        tcp_thread.detach();
    }

    close(udpfd);
    close(tcpfd);
    return 0;
}

