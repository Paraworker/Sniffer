#include "initwindow.h"
#include "ui_initwindow.h"

InitWindow::InitWindow(QWidget *parent) :
    QDialog(parent),
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

void InitWindow::set_eth_pointer(QString *s){
    eth = s;
}

void InitWindow::closeEvent(QCloseEvent *event){
    *eth = this->ui->comboBox->currentText();
    event->accept();
}

void InitWindow::on_pushButton_clicked()
{
    this->close();
}
