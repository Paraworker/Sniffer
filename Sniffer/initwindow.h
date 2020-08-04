#ifndef INITWINDOW_H
#define INITWINDOW_H

#include <QDialog>
#include <QCloseEvent>

namespace Ui {
class InitWindow;
}

class InitWindow : public QDialog
{
    Q_OBJECT

public:
    explicit InitWindow(QWidget *parent = nullptr);
    void combobox_add(std::vector<QString> list);
    void set_eth_pointer(QString* s);
    ~InitWindow();

private slots:
    void on_pushButton_clicked();

private:
    Ui::InitWindow *ui;
    QString* eth;
    void closeEvent( QCloseEvent * event);
};

#endif // INITWINDOW_H
