#include "sniffer.h"
#include "ui_sniffer.h"
#include "QDebug"
#include "QFile"
#include "QFileDialog"
#include <QTextStream>
#include <iostream>
#include <cstdio>
#include <sdapacket.h>
#include <start.h>


using namespace std;


PacketStream ps;
PcapHeader ph;
Pop pops;
QString fName;
int allpackets = 0;

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
    fName = QFileDialog::getOpenFileName(0,"Open File:","","CAP files (*.cap)");
    qDebug() << fName;
    if (fName=="")
        return 1;
    QFile file(fName);


    allpackets = 0;
    ui->Text->setText("");
    ui->Avrg->setText("");
    ui->Max->setText("");
    ui->Min->setText("");
    ui->Pack->setText("");

    if (!file.open(QIODevice::ReadOnly))
    {
            qDebug() << "Error while opening file";
            return 1;
    }

    qDebug() << "Size = " << file.size();
    file.read((char *)&ps.fHeader, 24);
    ui->Text->append("\t PCAP File Header: ");
    ui->Text->append("Link type: "+QString::number(ps.fHeader.linktype));
    ui->Text->append("Max packet size: "+QString::number(ps.fHeader.snaplen)+" bytes");
    ui->Text->append("Sigfigs: "+QString::number(ps.fHeader.sigfigs));
    ui->Text->append("Local correction to gmt: "+QString::number(ps.fHeader.thiszone));
    ui->Text->append("Minor: "+QString::number(ps.fHeader.version_minor));
    ui->Text->append("Major: "+QString::number(ps.fHeader.version_major));
    ui->Text->append("Magic number: "+QString::number(ps.fHeader.magic));
    ui->Text->append("");
    qDebug() << "pos" << file.pos();
    qDebug() << "size" << file.size();
    qDebug() << "1";
    int minl = 99999999;
    int maxl = 0;
    int avrgl = 0;

    while (file.pos() < file.size())
    {
        file.read((char *) &pops.pHeader, 16);
        file.read((char*) &pops.data,pops.pHeader.caplen);
        ui->Text->append("Packets # "+QString::number(allpackets));
        ui->Text->append("\tt1: "+QString::number(pops.pHeader.t1)+" milisec");
        ui->Text->append("\tt2: "+QString::number(pops.pHeader.t2)+" milisec");
        ui->Text->append("\tPacket: "+QString::number(pops.pHeader.len)+"bytes");
        if (pops.pHeader.caplen > maxl)
                    maxl = pops.pHeader.caplen;
                if (pops.pHeader.caplen < minl)
                    minl = pops.pHeader.caplen;
                avrgl=avrgl+pops.pHeader.caplen;
        ui->Text->append("\tPacket: "+QString::number(pops.pHeader.caplen)+" bytes captured");
//        for(int i=0; i<pops.pHeader.caplen; i++){
//        qDebug()<<hex<<(pops.data[i]&0xff);
//        };
        ui->Text->append("");
        ps.ALLpackets.append(pops);
       // ui->Text->setText(ps.ALLpackets.at(1));

//        for(int i=0; i<pops.pHeader.caplen;i++)
//        {
//            QString dq;
//            dq=QString::number(pops.data[i]);
//            int d=dq.toInt();
//            //d=QString::number(pops.data[i]);
//            QString s=QString::number(d,16).toUpper();
//            ui->Pack->insertPlainText(" "+s);
//            qDebug()<<hex<<(pops.data[i]&0xff);
//        }

        //file.seek(file.pos()+ pk.m_pHeader.caplen);
//        z=z+1;
        qDebug() << "2";
        qDebug() <<"data v 1: " << ps.ALLpackets[0].pHeader.caplen;
        allpackets++;
    }

            ui->Avrg->append(QString::number(avrgl/allpackets));
            ui->Max->append(QString::number(maxl));
            ui->Min->append(QString::number(minl));

    qDebug() << ps.fHeader.snaplen << "   " << ps.fHeader.linktype << " " << file.size();
    return 1;
}



void Sniffer::on_pushButton_clicked()
{
  //QFile file(fName);
  QString l;
  l=ui->Num->text();
  int n = l.toInt();
//  if (!file.open(QIODevice::ReadOnly))
//  {
//          qDebug() << "Error while opening file";
//          return ;
//  }
  if(n<allpackets)
  {
      //file.read((char *)&ps.fHeader, 24);
      ui->Text->setText("");
      ui->Text->append("\t PCAP File Header: ");
      ui->Text->append("Link type: "+QString::number(ps.fHeader.linktype));
      ui->Text->append("Max packet size: "+QString::number(ps.fHeader.snaplen)+" bytes");
      ui->Text->append("Sigfigs: "+QString::number(ps.fHeader.sigfigs));
      ui->Text->append("Local correction to gmt: "+QString::number(ps.fHeader.thiszone));
      ui->Text->append("Minor: "+QString::number(ps.fHeader.version_minor));
      ui->Text->append("Major: "+QString::number(ps.fHeader.version_major));
      ui->Text->append("Magic number: "+QString::number(ps.fHeader.magic));
      ui->Text->append("");
      qDebug() << n;
      ui->Text->append("Packets # "+QString::number(n));
      ui->Text->append("\tt1: "+QString::number(ps.ALLpackets[n].pHeader.t1)+" milisec");
      ui->Text->append("\tt2: "+QString::number(ps.ALLpackets[n].pHeader.t2)+" milisec");
      ui->Text->append("\tPacket: "+QString::number(ps.ALLpackets[n].pHeader.len)+"bytes");
      ui->Text->append("\tPacket: "+QString::number(ps.ALLpackets[n].pHeader.caplen)+" bytes captured");
      ui->Pack->clear();
      ui->Pack->insertPlainText("Data: ");
      for(int i=0; i<ps.ALLpackets[n].pHeader.caplen;i++)
      {
          QString dq;
          dq=QString::number(ps.ALLpackets[n].data[i]);
          int d=dq.toInt();
          //d=QString::number(pops.data[i]);
          QString s=QString::number(d,16).toUpper();
          ui->Pack->insertPlainText(" "+s);
          //qDebug()<<hex<<(pops.data[i]&0xff);
      };


//      file.seek(N[n]);
//      file.read((char *) &pk.m_pHeader, 16);
//      file.read((char*) &pops.data,pk.m_pHeader.caplen);
//      ui->Text->append("Packets # "+QString::number(n));
//      ui->Text->append("\tt1: "+QString::number(pk.m_pHeader.t1)+" milisec");
//      ui->Text->append("\tt1: "+QString::number(pk.m_pHeader.t2)+" milisec");
//      ui->Text->append("\tPacket: "+QString::number(pk.m_pHeader.len)+"bytes");
//      ui->Text->append("\tPacket: "+QString::number(pk.m_pHeader.caplen)+" bytes captured");
//      ui->Pack->clear();
//      ui->Pack->insertPlainText("Data: ");
//      for(int i=0; i<pk.m_pHeader.caplen;i++)
//      {
//          QString dq;
//          dq=QString::number(pops.data[i]);
//          int d=dq.toInt();
//          //d=QString::number(pops.data[i]);
//          QString s=QString::number(d,16).toUpper();
//          ui->Pack->insertPlainText(" "+s);
//          qDebug()<<hex<<(pops.data[i]&0xff);
//      };
  }
  else
  {
      ui->Pack->setText("There is no such packet, please try another number");
  }
}
