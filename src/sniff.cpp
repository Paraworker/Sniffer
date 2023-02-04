#include "sniff.h"
#include <QDateTime>


Sniff::Sniff(QObject *parent)
    : QThread(parent)
    , m_sock(-1)
    , m_state(STOP) {}

Sniff::~Sniff() {
    if(this->isRunning()) {
        requestInterruption();
        wait();
    }

    if(m_sock != -1) {
        close(m_sock);
    }
}

void Sniff::run() {
    char databuf[2048];
    m_filter.inputData(databuf);
    QString *information;
    int line_number_now = 0;

    while(!isInterruptionRequested()) {
        if (m_state != RUNNING) {
            sleep(1);
            continue;
        }

        memset(databuf, 0, 2048);

        // 开始抓包
        recvfrom(m_sock, databuf, 2048, 0, NULL, NULL);

        // 获当前时间
        QString time = QDateTime::currentDateTime().toString(" hh:mm:ss yyyy-MM-dd");

         // 判断是否是IP数据报
        if(!m_filter.isIP()) {
            continue;
        }

        // 检查过滤器
        if(!m_filter.isAllowed()) {
            continue;
        }

        if(line_number_now == 0) {
            emit listclear();
        }

        m_filter.adjustOrder();

        // 序号 协议类型 源ip 目的ip 时间
        information = new QString[5];

        information[0] = QString::number(line_number_now+1);
        information[4] = time;

        m_filter.parsePackage(information);

        memset(dataList[line_number_now],0,2048);
        memcpy(dataList[line_number_now],databuf,2048);   //数据复制到data_list

        // 发出信号显示内容
        emit newtext(information);
        line_number_now++;

        // 超最大抓取数，清0
        if(line_number_now >= DATALIST_MAX_NUM) {
            line_number_now = 0;
        }

        msleep(50);
    }
}

void Sniff::startSniff() {
    m_state = RUNNING;
    if(!this->isRunning()) {
        this->start();
    }
}

void Sniff::pauseSniff() {
    m_state = STOP;
}

void Sniff::setPromisc(std::string _eth) {
    struct ifreq ifr;
    const char *ethName = _eth.c_str();

    strncpy(ifr.ifr_name, ethName, sizeof(ifr.ifr_name));
    ioctl(m_sock, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(m_sock, SIOCSIFFLAGS, &ifr);
}

void Sniff::bindEth(std::string _eth) {
    const char *ethName = _eth.c_str();

    struct ifreq ifr_re;    // ifreq结构用于获取接口信息
    strncpy(ifr_re.ifr_name, ethName, IFNAMSIZ);
    // 获取指定网卡接口的INDEX
    ioctl(m_sock, SIOCGIFINDEX, (char*)&ifr_re);

    struct sockaddr_ll RawHWAddr;
    memset(&RawHWAddr, 0, sizeof(RawHWAddr));
    RawHWAddr.sll_ifindex   = ifr_re.ifr_ifindex;
    RawHWAddr.sll_family    = AF_PACKET;
    RawHWAddr.sll_protocol  = htons(ETH_P_ALL);
    RawHWAddr.sll_hatype    = 0;
    RawHWAddr.sll_pkttype   = PACKET_HOST;
    RawHWAddr.sll_halen     = ETH_ALEN;

    bind(m_sock, (struct sockaddr*)&RawHWAddr, sizeof(RawHWAddr));
}

void Sniff::getEthList(std::vector<QString>& ethList) {
    struct ifaddrs *ifa = NULL, *ifList;

    getifaddrs(&ifList);

    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next) {
        if(ifa->ifa_addr->sa_family == PF_PACKET)
            ethList.push_back(ifa->ifa_name);
    }
    
    freeifaddrs(ifList);
}

void Sniff::ethSetup(std::string s) {
    m_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    timeval tv = {3, 0};
    setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(timeval));     //设置阻塞超时3秒
    bindEth(s);
    setPromisc(s);
}

Filter *Sniff::getFilterAddress() {
    return &m_filter;
}
