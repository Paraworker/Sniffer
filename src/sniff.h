#ifndef SNIFF_H
#define SNIFF_H

#include <QThread>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <netpacket/packet.h>
#include "filter.h"

#define DATALIST_MAX_NUM 2048

class Sniff : public QThread {
    Q_OBJECT

public:
    enum State {
        STOP,
        RUNNING,
    };

public:
    explicit Sniff(QObject *parent = 0);
    ~Sniff();

    void run();

    /**
     * @brief 开始抓包
     */
    void startSniff();

    /**
     * @brief 停止抓包
     */
    void pauseSniff();

    char dataList[DATALIST_MAX_NUM][2048];

    void ethSetup(std::string s);

    /**
     * @brief 获取接口列表
     */
    void getEthList(std::vector<QString>& ethList);

    QString getProtocol(int protocol);

    Filter *getFilterAddress();

signals:
    void listclear();
    void newtext(QString *s);

private:
    /**
     * @brief 设置网卡为混杂模式
     */
    void setPromisc(std::string _eth);

    /**
     * @brief 接口绑定
     */
    void bindEth(std::string _eth);

private:
    int    m_sock;
    State  m_state;
    Filter m_filter;
};

#endif // SNIFF_H
