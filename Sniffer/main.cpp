#include "mainwindow.h"
#include"initwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    w.select_interface();
    return a.exec();
}
