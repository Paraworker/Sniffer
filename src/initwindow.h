#ifndef INITWINDOW_H
#define INITWINDOW_H

#include <QDialog>
#include <QCloseEvent>
#include "sniff.h"

namespace Ui {
class InitWindow;
}

class InitWindow: public QDialog {
    Q_OBJECT

public:
    explicit InitWindow(QWidget *parent = nullptr);
    ~InitWindow();

    void combobox_add(std::vector<QString> const& list);
    void set_pointer(QString *s,Sniff *sn);

private slots:
    void on_pushButton_clicked();

private:
    void closeEvent( QCloseEvent *event);

private:
    Ui::InitWindow *ui;
    QString        *eth;
    Sniff          *sniff;
};

#endif // INITWINDOW_H
