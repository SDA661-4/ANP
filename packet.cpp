#include "packet.h"
#include "ui_packet.h"
#include <QFileDialog>
#include <QDebug>
#include <QFile>
#include "pcap.h"
#include <iostream>
#include <cstdio>

#define NULLPTR 0

Packet::Packet(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Packet)
{
    ui->setupUi(this);
}

Packet::~Packet()
{
    delete ui;
}

void Packet::on_Open_clicked()
{
//    QString fName = QFileDialog::getOpenFileName(0,"Open File:","","CAP files (*.cap)");
//    qDebug() << fName;
//    if (fName=="")
//        return;
    char* Path="C:\C++\pz2\PPP";
    pcap_t* LPacket;
    qDebug() << 1;
    LPacket=pcap_open_offline(Path,0);
    qDebug() << 2;
    struct pcap_pkthdr *header;
    const u_char *data;
    u_int packetCOUNT = 0;
    FILE *f;
    f=fopen("C:\HDR.txt", "w");
    u_int all_packets;
    while(int returnValue = pcap_next_ex(LPacket, &header, &data)>=0)
    {
        all_packets++;
        fprintf(f,"Packets: # %I\n", ++packetCOUNT);
        fprintf(f,"packet: %d bytes\n",header->caplen);
        fprintf(f,"packet: %d bytes\n", header->len);
        printf("\n\n");
    }
    pcap_close(LPacket);
    QFile file("C:\HDR.txt");

    if (file.open(QIODevice::ReadOnly));
    {
        qDebug() << "open";
        QByteArray block =file.readAll();
        ui->Text->setText(block);
        file.close();
        return;
    }

    if (!file.open(QIODevice::ReadOnly));
    {
        qDebug() << "error";
        return;
    }
}
