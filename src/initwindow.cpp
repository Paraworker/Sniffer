#include "initwindow.h"
#include "ui_initwindow.h"
#include "sniff.h"

InitWindow::InitWindow(QWidget *parent)
    : QDialog(parent,Qt::WindowTitleHint | Qt::CustomizeWindowHint)
    , ui(new Ui::InitWindow) {
    ui->setupUi(this);
}

InitWindow::~InitWindow() {
    delete ui;
}

void InitWindow::combobox_add(std::vector<QString> const& list) {
    for (auto& i : list) {
        this->ui->comboBox->addItem(i);
    }
}

void InitWindow::set_pointer(QString *s,Sniff *sn) {
    eth = s;
    sniff = sn;
}

void InitWindow::closeEvent(QCloseEvent *event) {
    QString s = this->ui->comboBox->currentText();
    *eth = s;
    sniff->ethSetup(s.toStdString());
    event->accept();
}

void InitWindow::on_pushButton_clicked() {
    this->close();
}
