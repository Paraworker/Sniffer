#ifndef FILTER_H
#define FILTER_H

#include <QString>
#include "packet_struct.h"


class Filter {
public:
    Filter();
    void inputData(char *data);
    bool isIP();
    bool isAllowed();
    void adjustOrder();
    void parsePackage(QString *information);

    void setAllowTcp(bool allow);
    void setAllowUdp(bool allow);
    void setAllowIcmp(bool allow);
    void setAllowOthers(bool allow);

    bool isTcpAllowed();
    bool isUdpAllowed();
    bool isIcmpAllowed();
    bool isOthersAllowed();

private:
    QString getProtocolName(int protocol);

private:
    char*      m_databuf;
    MacHeader* m_macHeader;
    IpHeader*  m_ipHeader;

    bool       m_tcpCheck;
    bool       m_udpCheck;
    bool       m_icmpCheck;
    bool       m_othersCheck;
};

#endif // FILTER_H
