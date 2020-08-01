#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "sniff.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void showMac(struct MacHeader *mheader);
    void showIP(struct IpHeader *ipheader);
    void showIcmp(IcmpHeader *icmpheader);
    void showTcp(struct TcpHeader *tcpheader);
    void showUdp(struct UdpHeader *udpheader);

private slots:
    void on_pushButton_start_clicked();
    void on_pushButton_pause_clicked();
    void on_listWidget_list_clicked(const QModelIndex &index);
    void text_add(QString s);
    void clear_the_list();

private:
    Ui::MainWindow *ui;
    Sniff *sniff_thread;
};
#endif // MAINWINDOW_H
