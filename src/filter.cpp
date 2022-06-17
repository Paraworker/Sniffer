#include "filter.h"

Filter::Filter()
    : TCP_check(true)
    , UDP_check(true)
    , ICMP_check(true)
    , others_check(true) {}

void Filter::input_data(char *data) {
    this->databuf = data;
    mheader = (struct MacHeader *)databuf;
    ipheader = (struct IpHeader *)(databuf + 14);
}

bool Filter::check_weather_IP() {
    if(mheader->type == 8) {
        return true;
    }else {
        return false;
    }
}

bool Filter::check_allow_type() {
    if(ipheader->protocol == TCP) {
        if(TCP_check)
            return true;
    }else if (ipheader->protocol == UDP) {
        if(UDP_check)
            return true;
    }else if (ipheader->protocol == ICMP) {
        if(ICMP_check)
            return true;
    }else {
        if(others_check)
            return true;
    }
    
    return false;
}

/* 接收双字节的顺序网络序的，需要调整 */
void Filter::adjust_order() {
    ipheader->tatol_len = (ipheader->tatol_len>>8) + (ipheader->tatol_len<<8);
    ipheader->ident = (ipheader->ident>>8) + (ipheader->ident<<8);
    ipheader->flag_frag = (ipheader->flag_frag>>8) + (ipheader->flag_frag<<8);
    ipheader->check_sum = (ipheader->check_sum>>8) + (ipheader->check_sum<<8);

    if(ipheader->protocol == ICMP) {
        struct IcmpHeader *icmpheader = (struct IcmpHeader *)(databuf+14+ipheader->header_len*4);
        //接收双字节的网络序的，需要调整
        icmpheader->check_sum = (icmpheader->check_sum>>8) + (icmpheader->check_sum<<8);
        icmpheader->id = (icmpheader->id>>8) + (icmpheader->id<<8);
        icmpheader->seq = (icmpheader->seq>>8) + (icmpheader->seq<<8);
    } else if(ipheader->protocol == TCP) {
        struct TcpHeader *tcpheader = (struct TcpHeader *)(databuf+14+ipheader->header_len*4);
        //接收双字节的网络序的，需要调整
        tcpheader->source_port = (tcpheader->source_port>>8) + (tcpheader->source_port<<8);
        tcpheader->dest_port = (tcpheader->dest_port>>8) + (tcpheader->dest_port<<8);
        tcpheader->window = (tcpheader->window>>8) + (tcpheader->window<<8);
        tcpheader->check_sum = (tcpheader->check_sum>>8) + (tcpheader->check_sum<<8);
        tcpheader->send_num = (tcpheader->send_num>>24) + ((tcpheader->send_num>>8)&0x00ff00)
                + ((tcpheader->send_num<<8)&0x00ff0000) + (tcpheader->send_num<<24);
        tcpheader->recv_num = (tcpheader->recv_num>>24) + ((tcpheader->recv_num>>8)&0x00ff00)
                + ((tcpheader->recv_num<<8)&0x00ff0000) + (tcpheader->recv_num<<24);
    }else if(ipheader->protocol == UDP) {
        struct UdpHeader *udpheader = (struct UdpHeader *)(databuf+14+ipheader->header_len*4);
        //接收双字节的是网络序的，需要调整
        udpheader->source_port = (udpheader->source_port>>8) + (udpheader->source_port<<8);
        udpheader->dest_port = (udpheader->dest_port>>8) + (udpheader->dest_port<<8);
        udpheader->len = (udpheader->len>>8) + (udpheader->len<<8);
        udpheader->check_sum = (udpheader->check_sum>>8) + (udpheader->check_sum<<8);
    }
}

void Filter::parsing_package(QString *information) {
    //协议类型 源ip 目的ip
    information[1] = getProtocol_name(ipheader->protocol);
    information[2] = QString("%1.%2.%3.%4")
            .arg(QString::number((int)ipheader->source_ip[0])
            , QString::number((int)ipheader->source_ip[1])
            , QString::number((int)ipheader->source_ip[2])
            , QString::number((int)ipheader->source_ip[3]));

    information[3] = QString("%1.%2.%3.%4")
            .arg(QString::number((int)ipheader->dest_ip[0])
            , QString::number((int)ipheader->dest_ip[1])
            , QString::number((int)ipheader->dest_ip[2])
            , QString::number((int)ipheader->dest_ip[3]));

}

/* 把类型转成字符串 */
QString Filter::getProtocol_name(int protocol) {
    switch(protocol) {
        case ICMP:
            return "ICMP";
            break;
        case TCP:
            return "TCP";
            break;
        case UDP:
            return "UDP";
    }

    return "UNKNOW";
}

void Filter::set_ICMP_check(bool arg) {
    this->ICMP_check = arg;
}

void Filter::set_TCP_check(bool arg) {
    this->TCP_check = arg;
}

void Filter::set_UDP_check(bool arg) {
    this->UDP_check = arg;
}

void Filter::set_others_check(bool arg) {
    this->others_check = arg;
}

bool Filter::get_ICMP_check() {
    return this->ICMP_check;
}

bool Filter::get_TCP_check() {
    return this->TCP_check;
}

bool Filter::get_UDP_check() {
    return this->UDP_check;
}

bool Filter::get_others_check() {
    return this->others_check;
}
