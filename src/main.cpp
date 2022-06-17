#include "mainwindow.h"
#include "initwindow.h"

#include <QApplication>

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    a.setApplicationName("com.github.Paraworker.Sniffer");

    QFont font = a.font();
    font.setPointSize(12);
    a.setFont(font);

    MainWindow w;
    w.show();
    w.select_interface();
    
    return a.exec();
}
