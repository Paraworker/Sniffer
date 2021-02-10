#include "filterwindow.h"
#include "ui_filterwindow.h"

FilterWindow::FilterWindow(Filter* _filter, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::FilterWindow) {
    ui->setupUi(this);
    this->filter = _filter;
    this->ui->checkBox_ICMP->setChecked(filter->get_ICMP_check());
    this->ui->checkBox_TCP->setChecked(filter->get_TCP_check());
    this->ui->checkBox_UDP->setChecked(filter->get_UDP_check());
    this->ui->checkBox_others->setChecked(filter->get_others_check());
}

FilterWindow::~FilterWindow(){
    delete ui;
}

void FilterWindow::on_pushButton_ok_clicked(){
    this->close();
}

void FilterWindow::closeEvent( QCloseEvent * event){
    filter->set_ICMP_check(this->ui->checkBox_ICMP->isChecked());
    filter->set_TCP_check(this->ui->checkBox_TCP->isChecked());
    filter->set_UDP_check(this->ui->checkBox_UDP->isChecked());
    filter->set_others_check(this->ui->checkBox_others->isChecked());
    event->accept();
}
