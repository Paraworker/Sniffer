#ifndef SNIFF_H
#define SNIFF_H

#include <QThread>
#include <QtWidgets/QListWidget>
#include <QLabel>
#include <QDateTime>
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

#define START 1
#define STOP  0
#define MAXDATALIST 2048


class Sniff : public QThread{
    Q_OBJECT
public:
    explicit Sniff(QObject *parent = 0);
    ~Sniff();
    void run();
    void startsniff();
    void pausesniff();
    char data_list[MAXDATALIST][2048];
    void eth_setup(std::string s);
    std::vector<QString> get_eth_list();
    QString getProtocol(int protocol);

signals:
    void listclear();
    void newtext(QString* s);

private:
    int sock;
    struct ifreq ifr;
    struct MacHeader *mheader;
    struct IpHeader *ipheader;
    int state;
    Filter filter;
    void set_promisc(std::string _eth);
    void bind_eth(std::string _eth);
};

#endif // SNIFF_H
