#ifndef START_H
#define START_H

#include <QMainWindow>
#include "mainwindow.h"

namespace Ui {
class Start;
}

struct PcapHeader
{
    qint32 t1;
    qint32 t2;
    qint32 caplen;
    qint32 len;
};

class Start : public QMainWindow
{
    Q_OBJECT

public:
    explicit Start(QWidget *parent = 0);
    ~Start();

private:
    Ui::Start *ui;
private slots:
    void opeN();
    void opSniffer();
};

#endif // START_H
