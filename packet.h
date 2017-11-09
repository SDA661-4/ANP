#ifndef PACKET_H
#define PACKET_H

#include <QMainWindow>
#include <pcap.h>
#include <iostream>
#include <cstdio>

namespace Ui {
class Packet;
}

class Packet : public QMainWindow
{
    Q_OBJECT

public:
    explicit Packet(QWidget *parent = 0);
    ~Packet();

private slots:
    void on_Open_clicked();

private:
    Ui::Packet *ui;

    void Open();
};

#endif // PACKET_H
