#ifndef FILTER_H
#define FILTER_H

#include <QString>
#include "packet_struct.h"


class Filter {
public:
    Filter();
    void input_data(char *data);
    bool check_weather_IP();
    bool check_allow_type();
    void adjust_order();
    void parsing_package(QString *information);

    void set_TCP_check(bool arg);
    void set_UDP_check(bool arg);
    void set_ICMP_check(bool arg);
    void set_others_check(bool arg);

    bool get_TCP_check();
    bool get_UDP_check();
    bool get_ICMP_check();
    bool get_others_check();

private:
    char *databuf;
    struct MacHeader *mheader;
    struct IpHeader *ipheader;

    bool TCP_check;
    bool UDP_check;
    bool ICMP_check;
    bool others_check;

    QString getProtocol_name(int protocol);

};

#endif // FILTER_H
