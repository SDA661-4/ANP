#ifndef SNIFFER_H
#define SNIFFER_H

#include <QMainWindow>
#include <QObject>
#include <QVector>
#include <sdapacket.h>
#include <start.h>


namespace Ui {
class Sniffer;
}

class Sniffer : public QMainWindow
{
    Q_OBJECT

public:
    explicit Sniffer(QWidget *parent = 0);
    ~Sniffer();

private slots:
    on_Open_clicked();

    void on_pushButton_clicked();

private:
    Ui::Sniffer *ui;
};


class Pop
{
public:
    PcapHeader pHeader;
    unsigned char data[65000];
};

struct PcapFHeader
{
    qint32 magic;
    qint16 version_major;
    qint16 version_minor;
    qint32 thiszone;     /* gmt to local correction */
    qint32 sigfigs;    /* accuracy of timestamps */
    qint32 snaplen;    /* max length saved portion of each pkt */
    qint32 linktype;   /* data link type (LINKTYPE_*) */
};

class PacketStream
{

public:
    PcapFHeader fHeader;
    QList <Pop> ALLpackets;
};



#endif // SNIFFER_H
