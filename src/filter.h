#ifndef FILTER_H
#define FILTER_H

#include <QString>
#include "packet_struct.h"


class Filter{
public:
    Filter();
    void input_data(char* data);
    bool check_weather_IP();
    bool check_allow_type();
    void parsing_package(QString* information);
    void adjust_order();
private:
    char* databuf;
    struct MacHeader *mheader;
    struct IpHeader *ipheader;

    bool TCP_check;
    bool UDP_check;
    bool ICMP_check;
    bool others_check;

    QString getProtocol_name(int protocol);

};

#endif // FILTER_H
