#ifndef INITWINDOW_H
#define INITWINDOW_H

#include <QDialog>
#include <QCloseEvent>
#include "sniff.h"

namespace Ui {
class InitWindow;
}

class InitWindow : public QDialog
{
    Q_OBJECT

public:
    explicit InitWindow(QWidget *parent = nullptr);
    void combobox_add(std::vector<QString> list);
    void set_pointer(QString* s,Sniff* sn);
    ~InitWindow();

private slots:
    void on_pushButton_clicked();

private:
    Ui::InitWindow *ui;
    QString* eth;
    Sniff* sniff;
    void closeEvent( QCloseEvent * event);
};

#endif // INITWINDOW_H
