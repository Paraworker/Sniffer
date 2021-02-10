#include "filterwindow.h"
#include "ui_filterwindow.h"

FilterWindow::FilterWindow(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::FilterWindow)
{
    ui->setupUi(this);
}

FilterWindow::~FilterWindow()
{
    delete ui;
}

void FilterWindow::set_pointer(Filter *_filter){
    this->filter = _filter;
}
