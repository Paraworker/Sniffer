#ifndef FILTERWINDOW_H
#define FILTERWINDOW_H

#include <QDialog>
#include "filter.h"
#include <QCloseEvent>

namespace Ui {
class FilterWindow;
}

class FilterWindow : public QDialog {
    Q_OBJECT

public:
    explicit FilterWindow(Filter* _filter, QWidget *parent = nullptr);
    ~FilterWindow();

private slots:
    void on_pushButton_ok_clicked();

private:
    Ui::FilterWindow *ui;
    Filter* filter;
    void closeEvent( QCloseEvent * event);
};

#endif // FILTERWINDOW_H
