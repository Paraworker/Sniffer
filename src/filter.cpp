#include "filter.h"

Filter::Filter()
    : m_tcpCheck(true)
    , m_udpCheck(true)
    , m_icmpCheck(true)
    , m_othersCheck(true) {}

void Filter::inputData(char *data) {
    m_databuf   = data;
    m_macHeader = (struct MacHeader*)m_databuf;
    m_ipHeader  = (struct IpHeader*)(m_databuf + 14);
}

bool Filter::isIP() {
    if(m_macHeader->type == 8) {
        return true;
    }

    return false;
}

bool Filter::isAllowed() {
    switch (m_ipHeader->protocol) {
        case TCP:
            return m_tcpCheck;
        case UDP:
            return m_udpCheck;
        case ICMP:
            return m_icmpCheck;
        default:
            return m_othersCheck;
    }
}

/* 接收双字节的顺序网络序的，需要调整 */
void Filter::adjustOrder() {
    m_ipHeader->tatol_len = (m_ipHeader->tatol_len>>8) + (m_ipHeader->tatol_len<<8);
    m_ipHeader->ident = (m_ipHeader->ident>>8) + (m_ipHeader->ident<<8);
    m_ipHeader->flag_frag = (m_ipHeader->flag_frag>>8) + (m_ipHeader->flag_frag<<8);
    m_ipHeader->check_sum = (m_ipHeader->check_sum>>8) + (m_ipHeader->check_sum<<8);

    if(m_ipHeader->protocol == ICMP) {
        struct IcmpHeader *icmpheader = (struct IcmpHeader *)(m_databuf+14+m_ipHeader->header_len*4);
        //接收双字节的网络序的，需要调整
        icmpheader->check_sum = (icmpheader->check_sum>>8) + (icmpheader->check_sum<<8);
        icmpheader->id = (icmpheader->id>>8) + (icmpheader->id<<8);
        icmpheader->seq = (icmpheader->seq>>8) + (icmpheader->seq<<8);
    } else if(m_ipHeader->protocol == TCP) {
        struct TcpHeader *tcpheader = (struct TcpHeader *)(m_databuf+14+m_ipHeader->header_len*4);
        //接收双字节的网络序的，需要调整
        tcpheader->source_port = (tcpheader->source_port>>8) + (tcpheader->source_port<<8);
        tcpheader->dest_port = (tcpheader->dest_port>>8) + (tcpheader->dest_port<<8);
        tcpheader->window = (tcpheader->window>>8) + (tcpheader->window<<8);
        tcpheader->check_sum = (tcpheader->check_sum>>8) + (tcpheader->check_sum<<8);
        tcpheader->send_num = (tcpheader->send_num>>24) + ((tcpheader->send_num>>8)&0x00ff00)
                + ((tcpheader->send_num<<8)&0x00ff0000) + (tcpheader->send_num<<24);
        tcpheader->recv_num = (tcpheader->recv_num>>24) + ((tcpheader->recv_num>>8)&0x00ff00)
                + ((tcpheader->recv_num<<8)&0x00ff0000) + (tcpheader->recv_num<<24);
    }else if(m_ipHeader->protocol == UDP) {
        struct UdpHeader *udpheader = (struct UdpHeader *)(m_databuf+14+m_ipHeader->header_len*4);
        //接收双字节的是网络序的，需要调整
        udpheader->source_port = (udpheader->source_port>>8) + (udpheader->source_port<<8);
        udpheader->dest_port = (udpheader->dest_port>>8) + (udpheader->dest_port<<8);
        udpheader->len = (udpheader->len>>8) + (udpheader->len<<8);
        udpheader->check_sum = (udpheader->check_sum>>8) + (udpheader->check_sum<<8);
    }
}

void Filter::parsePackage(QString *information) {
    //协议类型 源ip 目的ip
    information[1] = getProtocolName(m_ipHeader->protocol);
    information[2] = QString("%1.%2.%3.%4")
            .arg(QString::number((int)m_ipHeader->source_ip[0])
            , QString::number((int)m_ipHeader->source_ip[1])
            , QString::number((int)m_ipHeader->source_ip[2])
            , QString::number((int)m_ipHeader->source_ip[3]));

    information[3] = QString("%1.%2.%3.%4")
            .arg(QString::number((int)m_ipHeader->dest_ip[0])
            , QString::number((int)m_ipHeader->dest_ip[1])
            , QString::number((int)m_ipHeader->dest_ip[2])
            , QString::number((int)m_ipHeader->dest_ip[3]));

}

QString Filter::getProtocolName(int protocol) {
    switch(protocol) {
        case ICMP:
            return "ICMP";
        case TCP:
            return "TCP";
        case UDP:
            return "UDP";
        default:
            return "UNKNOW";
    }
}

void Filter::setAllowIcmp(bool allow) {
    m_icmpCheck = allow;
}

void Filter::setAllowTcp(bool allow) {
    m_tcpCheck = allow;
}

void Filter::setAllowUdp(bool allow) {
    m_udpCheck = allow;
}

void Filter::setAllowOthers(bool allow) {
    m_othersCheck = allow;
}

bool Filter::isIcmpAllowed() {
    return m_icmpCheck;
}

bool Filter::isTcpAllowed() {
    return this->m_tcpCheck;
}

bool Filter::isUdpAllowed() {
    return m_udpCheck;
}

bool Filter::isOthersAllowed() {
    return m_othersCheck;
}
