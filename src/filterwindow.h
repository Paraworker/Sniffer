#ifndef FILTERWINDOW_H
#define FILTERWINDOW_H

#include <QDialog>
#include "filter.h"

namespace Ui {
class FilterWindow;
}

class FilterWindow : public QDialog
{
    Q_OBJECT

public:
    explicit FilterWindow(QWidget *parent = nullptr);
    ~FilterWindow();
    void set_pointer(Filter* _filter);

private:
    Ui::FilterWindow *ui;
    Filter* filter;
};

#endif // FILTERWINDOW_H
