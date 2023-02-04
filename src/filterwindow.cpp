#include "filterwindow.h"
#include "ui_filterwindow.h"

FilterWindow::FilterWindow(Filter *_filter, QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::FilterWindow) {
    ui->setupUi(this);
    this->filter = _filter;
    this->ui->checkBox_ICMP->setChecked(filter->isIcmpAllowed());
    this->ui->checkBox_TCP->setChecked(filter->isTcpAllowed());
    this->ui->checkBox_UDP->setChecked(filter->isUdpAllowed());
    this->ui->checkBox_others->setChecked(filter->isOthersAllowed());
}

FilterWindow::~FilterWindow() {
    delete ui;
}

void FilterWindow::on_pushButton_ok_clicked() {
    this->close();
}

void FilterWindow::closeEvent( QCloseEvent * event) {
    filter->setAllowIcmp(this->ui->checkBox_ICMP->isChecked());
    filter->setAllowTcp(this->ui->checkBox_TCP->isChecked());
    filter->setAllowUdp(this->ui->checkBox_UDP->isChecked());
    filter->setAllowOthers(this->ui->checkBox_others->isChecked());
    event->accept();
}
