#include "sniffer.h"
#include "ui_sniffer.h"
#include "QDebug"
#include "QFile"
#include "QFileDialog"
#include <QTextStream>
#include "pcap.h"
#include <iostream>
#include <cstdio>
#include <sdapacket.h>
#include <start.h>


using namespace std;


PacketStream ps;
PcapHeader ph;
SDApacket pk;


Sniffer::Sniffer(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Sniffer)
{
    ui->setupUi(this);
}

Sniffer::~Sniffer()
{
    delete ui;
}



 Sniffer::on_Open_clicked()
{
    QString fName = QFileDialog::getOpenFileName(0,"Open File:","","CAP files (*.cap)");
    qDebug() << fName;
    if (fName=="")
        return 1;
    QFile file(fName);

    if (!file.open(QIODevice::ReadOnly))
    {
            qDebug() << "Error while opening file";
            return 1;
    }

    qDebug() << "Size = " << file.size();
    FILE *f;
    f=fopen("test.txt","w");
    file.read((char *)&ps.fHeader, 24);
    fprintf(f,"\t PCAP File Header: \n");
    fprintf(f,"Link type: %d\n",ps.fHeader.linktype);
    fprintf(f,"Max packet size: %d bytes\n",ps.fHeader.snaplen);
    fprintf(f,"Sigfigs: %d\n",ps.fHeader.sigfigs);
    fprintf(f,"Local correction to gmt: %d\n",ps.fHeader.thiszone);
    fprintf(f,"Minor: %d\n",ps.fHeader.version_minor);
    fprintf(f,"Major: %d\n",ps.fHeader.version_major);
    fprintf(f,"Magic number: %d\n",ps.fHeader.magic);
    fprintf(f,"\n\n");
    qDebug() << "pos" << file.pos();
    qDebug() << "size" << file.size();
    qDebug() << "1";
    int allpackets = 0;
    int minl = 99999999;
    int maxl = 0;
    int avrgl = 0;
    while (file.pos() < file.size())
    {
        allpackets++;
        qDebug() << "C";
        file.read((char *) &pk.m_pHeader, 16);
        fprintf(f,"Packets # %i\n",allpackets);
        fprintf(f, "\tt1: %d milisec\n",pk.m_pHeader.t1);
        fprintf(f, "\tt2: %d milisec\n",pk.m_pHeader.t2);
        fprintf(f,"\tPacket: %d bytes\n",pk.m_pHeader.len);
        if (pk.m_pHeader.caplen > maxl)
                    maxl = pk.m_pHeader.caplen;
                if (pk.m_pHeader.caplen < minl)
                    minl = pk.m_pHeader.caplen;
                avrgl=avrgl+pk.m_pHeader.caplen;
        fprintf(f, "\tPacket: %d bytes captured\n", pk.m_pHeader.caplen);
        fprintf(f,"\n");
        file.seek(file.pos()+ pk.m_pHeader.caplen);
        qDebug() << "2";
    }
    qDebug() << "3";
    avrgl=avrgl/allpackets;
    QFile f1("test.txt");
    if ((f1.exists())&&(f1.open(QIODevice::ReadOnly)))
        {
            ui->Text->setText(f1.readAll());
            ui->Avrg->setText(QString::number(avrgl));
            ui->Max->setText(QString::number(maxl));
            ui->Min->setText(QString::number(minl));
        };


//    FILE* f1= fopen("test.txt", "w");


//    ui->Text->setText(QString::number(file.size()));
//    ui->Text->setText(QString::number(ps.fHeader.snaplen));
   // ui->Text->setText(QString::number(ps.packets.caplen));
    //qDebug() << pck.pHeader.caplen;

    qDebug() << ps.fHeader.snaplen << "   " << ps.fHeader.linktype << " " << file.size();

    file.close();


}

// myPacket::myPacket()
// {
//     m_data = NULL;
// }

// myPacket::~myPacket()
// {
//     if(m_data!=NULL) delete []m_data;
// }

// myPacket::myPacket(const myPacket &p)
// {
//     m_pHeader=p.m_pHeader;
//     m_data=new unsigned char[m_pHeader.caplen];
//     memcpy(p.m_data,m_data,m_pHeader.caplen);
// }

// void myPacket::operator =(const myPacket &p)
// {
//     m_pHeader=p.m_pHeader;
//     m_data=new unsigned char[m_pHeader.caplen];
//     memcpy(p.m_data,m_data,m_pHeader.caplen);
// }




