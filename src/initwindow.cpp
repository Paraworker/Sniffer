#include "initwindow.h"
#include "ui_initwindow.h"
#include "sniff.h"

InitWindow::InitWindow(QWidget *parent) :
    QDialog(parent,Qt::WindowTitleHint | Qt::CustomizeWindowHint),
    ui(new Ui::InitWindow)
{
    ui->setupUi(this);
}

InitWindow::~InitWindow()
{
    delete ui;
}

void InitWindow::combobox_add(std::vector<QString> list){
    std::vector<QString>::iterator itr1,itr2;
    itr1 = list.begin();
    itr2 = list.end();
    for (;itr1 != itr2;itr1++) {
        this->ui->comboBox->addItem(*itr1);
    }
}

void InitWindow::set_pointer(QString *s,Sniff* sn){
    eth = s;
    sniff = sn;
}

void InitWindow::closeEvent(QCloseEvent *event){
    QString s = this->ui->comboBox->currentText();
    *eth = s;
    sniff->eth_setup(s);
    event->accept();
}

void InitWindow::on_pushButton_clicked()
{
    this->close();
}
