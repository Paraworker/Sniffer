#include "sniff.h"


Sniff::Sniff(QObject *parent) :
    QThread(parent){
    sock = -1;
    state = STOP;
}

Sniff::~Sniff(){
    if(this->isRunning()){
        requestInterruption();
        wait();
    }

    if(sock != -1)
        close(sock);
}

void Sniff::run()
{
    char databuf[2048];
    filter.input_data(databuf);
    QString* information;
    int line_number_now = 0;

    while(! isInterruptionRequested() ){
        if(state == START){
            memset(databuf,0,2048);
            //开始抓包
            recvfrom(sock,databuf,2048,0,NULL,NULL);
            //获当前时间
            QDateTime current_date_time = QDateTime::currentDateTime();
            QString current_date = current_date_time.toString(" hh:mm:ss yyyy-MM-dd");

            if(!filter.check_weather_IP()){     //判断是否是IP数据报
                continue;
            }

            if(!filter.check_allow_type()){     //检查过滤器
                continue;
            }

            if(line_number_now == 0)
                emit listclear();

            filter.adjust_order();

            //序号 协议类型 源ip 目的ip 时间
            information = new QString[5];

            information[0] = QString::number(line_number_now+1);
            information[4] = current_date;

            filter.parsing_package(information);

            memset(data_list[line_number_now],0,2048);
            memcpy(data_list[line_number_now],databuf,2048);   //数据复制到data_list

            //发出信号显示内容
            emit newtext(information);
            line_number_now++;

            //超最大抓取数，清0
            if(line_number_now >= MAXDATALIST){
                line_number_now = 0;
            }
            msleep(50);
        }
        else {
            sleep(1);
        }
    }
}

//开始抓包
void Sniff::startsniff(){
    state = START;
    if(!this->isRunning()){
        this->start();
    }
}

//停止抓包
void Sniff::pausesniff(){
    state = STOP;
}

    //设置网卡为混杂模式
void Sniff::set_promisc(std::string _eth){
    const char* eth_name = _eth.c_str();
    strncpy(ifr.ifr_name, eth_name, sizeof (ifr.ifr_name));
    ioctl(sock, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(sock, SIOCSIFFLAGS, &ifr);
}

    //接口绑定
void Sniff::bind_eth(std::string _eth){
    const char* eth_name = _eth.c_str();

    struct ifreq ifr_re;    // ifreq结构用于获取接口信息
    strncpy(ifr_re.ifr_name, eth_name, IFNAMSIZ);
    // 获取指定网卡接口的INDEX
    ioctl(sock, SIOCGIFINDEX, (char*)&ifr_re);

    struct sockaddr_ll RawHWAddr;
    memset(&RawHWAddr, 0, sizeof(RawHWAddr));
    RawHWAddr.sll_ifindex   = ifr_re.ifr_ifindex;
    RawHWAddr.sll_family    = AF_PACKET;
    RawHWAddr.sll_protocol  = htons(ETH_P_ALL);
    RawHWAddr.sll_hatype    = 0;
    RawHWAddr.sll_pkttype   = PACKET_HOST;
    RawHWAddr.sll_halen     = ETH_ALEN;

    bind(sock, (struct sockaddr*)&RawHWAddr, sizeof(RawHWAddr));
}

    //获取接口列表
std::vector<QString> Sniff::get_eth_list(){
    struct ifaddrs *ifa = NULL, *ifList;
    std::vector<QString> s;
    getifaddrs(&ifList);

    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next){
        if(ifa->ifa_addr->sa_family == PF_PACKET)
            s.push_back(ifa->ifa_name);
    }
    freeifaddrs(ifList);
    return s;
}

void Sniff::eth_setup(std::string s){
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    timeval tv = {3, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(timeval));     //设置阻塞超时3秒
    bind_eth(s);
    set_promisc(s);
}
