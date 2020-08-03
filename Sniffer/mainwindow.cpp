#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow){
    ui->setupUi(this);
    this->ui->pushButton_pause->setDisabled(true);
    this->ui->tableWidget_list->setVerticalScrollMode(QListWidget::ScrollPerPixel);
    this->ui->listWidget_detail->setVerticalScrollMode(QListWidget::ScrollPerPixel);
    ui->tableWidget_list->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tableWidget_list->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ui->tableWidget_list->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    ui->tableWidget_list->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    sniff_thread = new Sniff();
    connect(this->ui->comboBox_filter,SIGNAL(currentIndexChanged(int)),sniff_thread,SLOT(setFilter(int)));
    connect(sniff_thread,SIGNAL(newtext(QString*)),this,SLOT(text_add(QString*)));
    connect(sniff_thread,SIGNAL(listclear()),this,SLOT(clear_the_list()));
    sniff_thread->start();    //启动抓包线程
}

MainWindow::~MainWindow(){
    delete sniff_thread;
    delete ui;
}

void MainWindow::text_add(QString* s){
    int c = this->ui->tableWidget_list->rowCount();
    this->ui->tableWidget_list->insertRow(c);
    this->ui->tableWidget_list->setItem(c,0,new QTableWidgetItem(s[0]));
    this->ui->tableWidget_list->setItem(c,1,new QTableWidgetItem(s[1]));
    this->ui->tableWidget_list->setItem(c,2,new QTableWidgetItem(s[2]));
    this->ui->tableWidget_list->setItem(c,3,new QTableWidgetItem(s[3]));
    this->ui->tableWidget_list->setItem(c,4,new QTableWidgetItem(s[4]));
    this->ui->tableWidget_list->scrollToBottom();
    delete [] s;

}

void MainWindow::clear_the_list(){
    ui->tableWidget_list->setRowCount(0);
    ui->tableWidget_list->clearContents();
}

//开始
void MainWindow::on_pushButton_start_clicked(){
    sniff_thread->startsniff();
    this->ui->pushButton_start->setDisabled(true);
    this->ui->pushButton_pause->setEnabled(true);
    this->ui->label_title->setText("Sniffing...");
}

//停止
void MainWindow::on_pushButton_pause_clicked(){
    sniff_thread->pausesniff();
    this->ui->pushButton_pause->setDisabled(true);
    this->ui->pushButton_start->setEnabled(true);
    this->ui->label_title->setText("Paused");
}

void MainWindow::on_tableWidget_list_clicked(const QModelIndex &index)
{
    int i = index.row();
    ui->listWidget_detail->clear();
    char *p = sniff_thread->data_list[i];
    showMac((struct MacHeader *) p);
    struct IpHeader *ipheader = (struct IpHeader *)( p + 14);
    showIP(ipheader);

    switch (ipheader->protocol) {
    case ICMP:
        showIcmp((struct IcmpHeader *)(p+14+ipheader->header_len*4));
        break;
    case TCP:
        showTcp((struct TcpHeader *)(p+14+ipheader->header_len*4));
        break;
    case UDP:
        showUdp((struct UdpHeader *)(p+14+ipheader->header_len*4));
        break;
    default:
        break;
    }

}

void MainWindow::showMac(MacHeader *mheader){
    QString temp;
    ui->listWidget_detail->addItem("[MAC Header]");
    temp.append(QString("源 MAC 地址: %1-%2-%3-%4-%5-%6")
                .arg(QString::number((int)(mheader->source_adr[0]),16))
                .arg(QString::number((int)(mheader->source_adr[1]),16))
                .arg(QString::number((int)(mheader->source_adr[2]),16))
                .arg(QString::number((int)(mheader->source_adr[3]),16))
                .arg(QString::number((int)(mheader->source_adr[4]),16))
                .arg(QString::number((int)(mheader->source_adr[5]),16)));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("目的MAC地址: %1-%2-%3-%4-%5-%6")
                .arg(QString::number((int)mheader->dest_adr[0],16))
                .arg(QString::number((int)mheader->dest_adr[1],16))
                .arg(QString::number((int)mheader->dest_adr[2],16))
                .arg(QString::number((int)mheader->dest_adr[3],16))
                .arg(QString::number((int)mheader->dest_adr[4],16))
                .arg(QString::number((int)mheader->dest_adr[5],16)));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp = "类型：";
    temp.append(QString::number((int)(mheader->type)));
    ui->listWidget_detail->addItem(temp);
    ui->listWidget_detail->addItem("");
    temp.clear();
}

void MainWindow::showIP(struct IpHeader *ipheader){
    QString temp;
    ui->listWidget_detail->addItem("[IP Header]");

    temp.append(QString("版本号： %1")
                .arg(QString::number((ipheader->versoin))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("首部长度： %1")
                .arg(QString::number((ipheader->header_len*4))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();

    temp.append(QString("区分服务： %1")
                .arg(QString::number((ipheader->service))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();


    temp.append(QString("总长度： %1")
                .arg(QString::number((ipheader->tatol_len))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();

    temp.append(QString("标识: %1")
                .arg(QString::number((ipheader->ident))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();

    temp.append(QString("标志: %1")
                .arg(QString::number((ipheader->flag_frag>>13))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();

    temp.append(QString("片偏移:  %1")
                .arg(QString::number(( ipheader->flag_frag&0x1fff))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();

    temp.append(QString("生存时间: %1")
                .arg(QString::number(( ipheader->ttl))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();

    temp.append(QString("协议:  %1")
                .arg(QString::number((ipheader->protocol))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();

    temp.append(QString("检验和: %1")
                .arg(QString::number((ipheader->check_sum))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();

    temp.append(QString("源 IP: %1.%2.%3.%4")
                .arg(QString::number((int)ipheader->source_ip[0]))
                .arg(QString::number((int)ipheader->source_ip[1]))
                .arg(QString::number((int)ipheader->source_ip[2]))
                .arg(QString::number((int)ipheader->source_ip[3])));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("目的IP: %1.%2.%3.%4")
                .arg(QString::number((int)ipheader->dest_ip[0]))
                .arg(QString::number((int)ipheader->dest_ip[1]))
                .arg(QString::number((int)ipheader->dest_ip[2]))
                .arg(QString::number((int)ipheader->dest_ip[3])));
    ui->listWidget_detail->addItem(temp);
    ui->listWidget_detail->addItem("");
    temp.clear();
}

void MainWindow::showIcmp(IcmpHeader *icmpheader){
    QString temp;
    ui->listWidget_detail->addItem("[ICMP Header]");
    temp.append(QString("类型： %1")
                .arg(QString::number((icmpheader->type))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("代码： %1")
                .arg(QString::number((icmpheader->code))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("检验和： %1")
                .arg(QString::number((icmpheader->check_sum))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("标识符： %1")
                .arg(QString::number((icmpheader->id))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("序列号： %1")
                .arg(QString::number((icmpheader->seq))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
}

void MainWindow::showTcp(TcpHeader *tcpheader){
    QString temp;
    ui->listWidget_detail->addItem("[TCP Header]");
    temp.append(QString("源端口： %1")
                .arg(QString::number((tcpheader->source_port))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("目的端口： %1")
                .arg(QString::number((tcpheader->dest_port))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("序号： %1")
                .arg(QString::number((tcpheader->send_num))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("确认号： %1")
                .arg(QString::number((tcpheader->recv_num))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("数据偏移： %1")
                .arg(QString::number((tcpheader->offset*4))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("标志位：  URG:%1 ACK:%2 PSH:%3 RET:%4 SYN:%5 FIN:%6")
                .arg(QString::number((int)(tcpheader->flag>>5)&0x01))
                .arg(QString::number((int)(tcpheader->flag>>4)&0x01))
                .arg(QString::number((int)(tcpheader->flag>>3&0x01)))
                .arg(QString::number((int)(tcpheader->flag>>2)&0x01))
                .arg(QString::number((int)(tcpheader->flag>>1)&0x01))
                .arg(QString::number((int)(tcpheader->flag>>0)&0x01)));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("窗口： %1")
                .arg(QString::number((tcpheader->window))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("检验和： %1")
                .arg(QString::number((tcpheader->check_sum))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
}

void MainWindow::showUdp(UdpHeader *udpheader){
    QString temp;
    ui->listWidget_detail->addItem("[UDP Header]");
    temp.append(QString("源端口： %1")
                .arg(QString::number((udpheader->source_port))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("目的端口： %1")
                .arg(QString::number((udpheader->dest_port))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("长度： %1")
                .arg(QString::number((udpheader->len))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();
    temp.append(QString("检验和： %1")
                .arg(QString::number((udpheader->check_sum))));
    ui->listWidget_detail->addItem(temp);
    temp.clear();

}


