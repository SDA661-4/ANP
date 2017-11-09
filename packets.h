#ifndef PACKETS_H
#define PACKETS_H

#include <QMainWindow>
#include "mainwindow.h"

namespace Ui {
class Packet;
}

class Start : public QMainWindow
{
    Q_OBJECT

public:
    explicit Start(QWidget *parent = 0);
    ~Start();

private:
    Ui::Start *ui;
private slots:
    void Open();
};

#endif // PACKETS_H
