#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "sniff.h"
#include "filterwindow.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void showMac(struct MacHeader *mheader);
    void showIP(struct IpHeader *ipheader);
    void showIcmp(IcmpHeader *icmpheader);
    void showTcp(struct TcpHeader *tcpheader);
    void showUdp(struct UdpHeader *udpheader);
    void select_interface();

private slots:
    void on_pushButton_start_pause_clicked();
    void on_tableWidget_list_clicked(const QModelIndex &index);
    void text_add(QString *s);
    void clear_the_list();


    void on_pushButton_filter_clicked();

private:
    Ui::MainWindow *ui;
    FilterWindow *filterwindow;
    int button_state;
    Sniff *sniff_thread;
    QString eth;
};

#endif // MAINWINDOW_H
