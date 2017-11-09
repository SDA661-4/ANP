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

private:
    Ui::Sniffer *ui;
};


//struct PcapHeader
//{
//    qint32 t1;
//    qint32 t2;
//    qint32 caplen;
//    qint32 len;
//};

//class myPacket
//{
//public:

//    myPacket(const myPacket &p)
//        {
//         m_pHeader=p.m_pHeader;
//         m_data=new unsigned char[m_pHeader.caplen];
//         memcpy(p.m_data,m_data,m_pHeader.caplen);
//        };
//    myPacket()
//        {
//        m_data = NULL;
//        };
//    ~myPacket()
//        {
//         if(m_data!=NULL) delete []m_data;
//        };
//    void operator = (const myPacket &p)
//        {
//         m_pHeader=p.m_pHeader;
//         m_data=new unsigned char[m_pHeader.caplen];
//         memcpy(p.m_data,m_data,m_pHeader.caplen);
//        };

//    virtual void show();
//private:
//    PcapHeader m_pHeader;
//    unsigned char* m_data;
//};

class Den
{
public:
    PcapHeader pHeader;
    unsigned char data[2000];
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
    QVector <Den> VECpackets;
};


#endif // SNIFFER_H
