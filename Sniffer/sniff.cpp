#include "sniff.h"

Sniff::Sniff(QObject *parent) :
    QThread(parent)
{
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    //设置网卡为混杂模式
    strncpy(ethreq.ifr_name,"eth0",IFNAMSIZ);
    ioctl(sock,SIOCGIFFLAGS,&ethreq);
    ethreq.ifr_flags|=IFF_PROMISC;
    ioctl(sock,SIOCSIFFLAGS,&ethreq);

    state = STOP;
    filter = ALL;
}

void Sniff::run()
{
    char databuf[2048];
    QString information;
    int i=0;
    while(1){
        if(state == START){
           bzero(databuf,2048);
           //开始抓包
           recvfrom(sock,databuf,2048,0,NULL,NULL);
           //获当前时间
           QDateTime current_date_time = QDateTime::currentDateTime();
           QString current_date = current_date_time.toString(" hh:mm:ss yyyy-MM-dd");
           mheader = (struct MacHeader *) databuf;
           if(mheader->type != 8)   continue;   //判断是否是IP数据报
           ipheader = (struct IpHeader *)( databuf + 14);
           if(ipheader->protocol != filter && filter != ALL) continue;  //检查过滤器
           //数据报完成检查


           if(i == 0)
               emit listclear();
           bzero(data_list[i], 2048);
           memcpy(data_list[i],databuf,2048);   //数据复制到data_list
           mheader = (struct MacHeader *) data_list[i];
           ipheader = (struct IpHeader *)( data_list[i] + 14);

           //接收双字节的顺序网络序的，需要调整
           ipheader->tatol_len = (ipheader->tatol_len>>8) + (ipheader->tatol_len<<8);
           ipheader->ident = (ipheader->ident>>8) + (ipheader->ident<<8);
           ipheader->flag_frag = (ipheader->flag_frag>>8) + (ipheader->flag_frag<<8);
           ipheader->check_sum = (ipheader->check_sum>>8) + (ipheader->check_sum<<8);

           if(ipheader->protocol == ICMP){
                    struct IcmpHeader *icmpheader = (struct IcmpHeader *)(data_list[i]+14+ipheader->header_len*4);
                    //接收双字节的网络序的，需要调整
                    icmpheader->check_sum = (icmpheader->check_sum>>8) + (icmpheader->check_sum<<8);
                    icmpheader->id = (icmpheader->id>>8) + (icmpheader->id<<8);
                    icmpheader->seq = (icmpheader->seq>>8) + (icmpheader->seq<<8);
           } else if(ipheader->protocol == TCP){
                    struct TcpHeader *tcpheader = (struct TcpHeader *)(data_list[i]+14+ipheader->header_len*4);
                    //接收双字节的网络序的，需要调整
                    tcpheader->source_port = (tcpheader->source_port>>8) + (tcpheader->source_port<<8);
                    tcpheader->dest_port = (tcpheader->dest_port>>8) + (tcpheader->dest_port<<8);
                    tcpheader->window = (tcpheader->window>>8) + (tcpheader->window<<8);
                    tcpheader->check_sum = (tcpheader->check_sum>>8) + (tcpheader->check_sum<<8);
                    tcpheader->send_num = (tcpheader->send_num>>24) + ((tcpheader->send_num>>8)&0x00ff00)
                                        + ((tcpheader->send_num<<8)&0x00ff0000) + (tcpheader->send_num<<24);
                    tcpheader->recv_num = (tcpheader->recv_num>>24) + ((tcpheader->recv_num>>8)&0x00ff00)
                                        + ((tcpheader->recv_num<<8)&0x00ff0000) + (tcpheader->recv_num<<24);
           }else if(ipheader->protocol == UDP){
                    struct UdpHeader *udpheader = (struct UdpHeader *)(data_list[i]+14+ipheader->header_len*4);
                    //接收双字节的是网络序的，需要调整
                    udpheader->source_port = (udpheader->source_port>>8) + (udpheader->source_port<<8);
                    udpheader->dest_port = (udpheader->dest_port>>8) + (udpheader->dest_port<<8);
                    udpheader->len = (udpheader->len>>8) + (udpheader->len<<8);
                    udpheader->check_sum = (udpheader->check_sum>>8) + (udpheader->check_sum<<8);
           }

           //显示 协议类型 源ip 目的ip
           information.append(QString("%1: %2.%3.%4.%5->").arg(getProtocol(ipheader->protocol))
                       .arg(QString::number((int)ipheader->source_ip[0]))
                       .arg(QString::number((int)ipheader->source_ip[1]))
                       .arg(QString::number((int)ipheader->source_ip[2]))
                       .arg(QString::number((int)ipheader->source_ip[3])));
           information.append(QString("%1.%2.%3.%4").arg(QString::number((int)ipheader->dest_ip[0]))
                       .arg(QString::number((int)ipheader->dest_ip[1]))
                       .arg(QString::number((int)ipheader->dest_ip[2]))
                       .arg(QString::number((int)ipheader->dest_ip[3])));

           //显示时间
           information.append(QString("\t  (%1)").arg(current_date));
           //显示
           emit newtext(information);
           information.clear();
           i++;

           //超最大抓取数，清0
           if(i >= MAXDATALIST){
               i = 0;
           }
           msleep(50);
        }
        else {
            sleep(1);
        }
    }
}

//把类型转成字符串
QString Sniff::getProtocol(int protocol){
    switch(protocol){
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

//开始抓包
void Sniff::startsniff(){
    state = START;
}
//停止抓包
void Sniff::pausesniff(){
    state = STOP;
}

//改变过滤器
void Sniff::setFilter(int i){
    switch (i) {
    case 0:
        filter = ALL; break;
    case 1:
        filter = ICMP; break;
    case 2:
        filter = TCP; break;
    case 3:
        filter = UDP; break;
    }
}