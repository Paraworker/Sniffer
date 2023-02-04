#ifndef PACKET_STRUCT_H
#define PACKET_STRUCT_H

#include <cstdint>

enum Protocol{
    ALL  = 0,
    ICMP = 1,
    IGMP = 2,
    IP   = 4,
    TCP  = 6,
    UDP  = 17,
};

// MAC帧头结构
struct MacHeader {
    uint8_t  dest_adr[6];     // 目的地址
    uint8_t  source_adr[6];   // 源地址
    uint16_t type;            // 类型
};

// IP数据报固定部分结构
struct IpHeader {
    uint32_t header_len:4;      // 首部长度
    uint32_t versoin:4;         // 版本号
    uint8_t  service;           // 区分服务
    uint16_t tatol_len;         // 总长度      (需要进行字节调整)
    uint16_t ident;             // 标识        (需要进行字节调整)
    uint16_t flag_frag;         // 标志与片偏移 (需要进行字节调整)
    uint8_t  ttl;               // 生存时间
    uint8_t  protocol;          // 协议
    uint16_t check_sum;	        // 检验和      (需要进行字节调整)
    uint8_t  source_ip[4];		// 源地址
    uint8_t  dest_ip[4];        // 目的地址
};

// ICMP数据头结构
struct IcmpHeader {
    uint8_t type;       //类型
    uint8_t code;       //代码
    uint16_t check_sum; //检验和 (需要进行字节调整)
    uint16_t id;        //标识符 (需要进行字节调整)
    uint16_t seq;       //序列号	(需要进行字节调整)
};


struct UdpHeader {
    uint16_t source_port;   //源端口		 (需要进行字节调整)
    uint16_t dest_port;     //目的端口    (需要进行字节调整)
    uint16_t len;           //udp总长度   (需要进行字节调整)
    uint16_t check_sum;     //检验和      (需要进行字节调整)
};

struct TcpHeader {
    uint16_t source_port; //源端口		(需要进行字节调整)
    uint16_t dest_port;   //目的端口		(需要进行字节调整)
    uint32_t send_num;
    uint32_t recv_num;

    uint8_t  reserved1:4;
    uint8_t  offset:4;

    uint8_t  flag:6;
    uint8_t  reserved2:2;

    uint16_t window;
    uint16_t check_sum;
    uint16_t urg_pointer;
};

#endif // PACKET_STRUCT_H
