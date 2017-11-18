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

    file.read((char *)&ps.fHeader, 24);
    ui->Text->append("\t PCAP File Header: \nLink type: "+QString::number(ps.fHeader.linktype)+"\nMax packet size: "+QString::number(ps.fHeader.snaplen)+" bytes");


    ui->Text->append("Link type: "+QString::number(ps.fHeader.linktype));
    ui->Text->append("Max packet size: "+QString::number(ps.fHeader.snaplen)+" bytes");
    ui->Text->append("Sigfigs: "+QString::number(ps.fHeader.sigfigs));
    ui->Text->append("Local correction to gmt: "+QString::number(ps.fHeader.thiszone));
    ui->Text->append("Minor: "+QString::number(ps.fHeader.version_minor));
    ui->Text->append("Major: "+QString::number(ps.fHeader.version_major));
    ui->Text->append("Magic number: "+QString::number(ps.fHeader.magic));
    ui->Text->append("");
    int minl = 100000000;
    int maxl = 0;
    int avrgl = 0;

    while (file.pos() < file.size())
    {
        qDebug()<<ps.ALLpackets.size()<<"sizzze";
        file.read((char *) &pops.pHeader, 16);
//        qDebug()<<"1";
        pops.data=new unsigned char[pops.pHeader.caplen];
//        qDebug()<<"2";
        for(int i=0; i<pops.pHeader.caplen; i++)
        {
            file.read((char*) &pops.data[i],1);
//            qDebug()<<"3";
        };
//        qDebug()<<"4";
        ps.ALLpackets.append(pops);
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
        ui->Text->append("");


//        for(int i=0; i<pops.pHeader.caplen;i++)
//        {
//            QString dq;
//            dq=QString::number(pops.data[i]);
//            int d=dq.toInt();
//            //d=QString::number(pops.data[i]);
//            QString s=QString::number(d,16).toUpper();  //showing Data of all file
//            ui->Pack->insertPlainText(" "+s);
//            qDebug()<<hex<<(pops.data[i]&0xff);
//        }


        allpackets++;
        delete [] pops.data;
        qDebug()<<allpackets<<" pac";
    }

            ui->Avrg->append(QString::number(avrgl/allpackets));
            ui->Max->append(QString::number(maxl));
            ui->Min->append(QString::number(minl));


    return 1;
}



void Sniffer::on_pushButton_clicked()
{
  QString l;
  l=ui->Num->text();
  int n = l.toInt();
  if(n<allpackets)
  {
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
      //qDebug() << n;
      ui->Text->append("Packets # "+QString::number(n));
      ui->Text->append(" t1: "+QString::number(ps.ALLpackets[n].pHeader.t1)+" milisec");
      ui->Text->append(" t2: "+QString::number(ps.ALLpackets[n].pHeader.t2)+" milisec");
      ui->Text->append(" Packet: "+QString::number(ps.ALLpackets[n].pHeader.len)+"bytes");
      ui->Text->append(" Packet: "+QString::number(ps.ALLpackets[n].pHeader.caplen)+" bytes captured");

      ui->Text->append("");
      ui->Text->insertPlainText(" Destination MAC: ");
      int pos=0;
      for (int i=pos; i<6; i++)
       {
           QString dc;
           dc=QString::number(ps.ALLpackets[n].data[i]);
           int d=dc.toInt();
           QString s=QString::number(d,16).toUpper();

           if(d<16)
               ui->Text->insertPlainText(" 0"+s);
           else
               ui->Text->insertPlainText(" "+s);

       };
      pos=6;
      ui->Text->append("");
      ui->Text->insertPlainText(" Source MAC: ");
      for (int i=pos; i<12; i++)
      {
          QString dc;
          dc=QString::number(ps.ALLpackets[n].data[i]);
          int d=dc.toInt();
          QString s=QString::number(d,16).toUpper();

          if(d<16)
              ui->Text->insertPlainText(" 0"+s);
          else
              ui->Text->insertPlainText(" "+s);
      };
      pos=12;
      ui->Text->append("");
      ui->Text->insertPlainText(" Type: ");
      int b=0;
      for (int i=pos; i<14; i++)
      {
          QString dc;
          dc=QString::number(ps.ALLpackets[n].data[i]);
          int d=dc.toInt();
          QString s=QString::number(d,16).toUpper();

          if(d<16)
              ui->Text->insertPlainText("0"+s);
          else
              ui->Text->insertPlainText(""+s);
          if (d==8) b=1;
      };
      if (b==1) ui->Text->insertPlainText(" - IP");
        else ui->Text->insertPlainText(" - unknown type");
      pos=14;
      QString dc = QString::number(ps.ALLpackets[n].data[pos]);
      int d=dc.toInt();
      QString s = QString::number(d,16).toUpper();
      ui->Text->append("");
      ui->Text->insertPlainText(" Length: "+s[1]);
      int k=s.toInt();
      k=k%10;
      k=4*k;
      k=k-20;
      pos=23;
      dc = QString::number(ps.ALLpackets[n].data[pos]);
      d=dc.toInt();
      s = QString::number(d,16).toUpper();
      ui->Text->append("");
      if(d<16)
      {
          ui->Text->insertPlainText(" Protocol: 0"+s);
          if(d==6) ui->Text->insertPlainText(" - TCP");
          if(d==17) ui->Text->insertPlainText(" - UDP");
          if((d!=6)&&(d!=17)) ui->Text->insertPlainText(" - unknown  protocol");
      }
      else
          ui->Text->insertPlainText(" Protocol: "+s);
      pos=26;
      ui->Text->append("");
      ui->Text->insertPlainText(" Source IP: ");
      for (int i=pos; i<pos+4; i++)
      {
          ui->Text->insertPlainText(QString::number(ps.ALLpackets[n].data[i])+".");
      };
      pos=30;
      ui->Text->append("");
      ui->Text->insertPlainText(" Destination IP: ");
      for (int i=pos; i<pos+4; i++)
      {
          ui->Text->insertPlainText(QString::number(ps.ALLpackets[n].data[i])+".");
      };
      pos=34+k;
      ui->Text->append("");
      s = QString::number(ps.ALLpackets[n].data[pos]);
      d=s.toInt();
      s=QString::number(d,16).toUpper();
      QString s1= QString::number(ps.ALLpackets[n].data[pos+1]);
      d=s1.toInt();
      s1=QString::number(d,16).toUpper();
      s=s+s1;
      ui->Text->insertPlainText(" Source Port: "+QString::number(s.toInt(0,16),10));

      ui->Text->append("");
      pos=36+k;
      s = QString::number(ps.ALLpackets[n].data[pos]);
      d=s.toInt();
      s=QString::number(d,16).toUpper();
      s1= QString::number(ps.ALLpackets[n].data[pos+1]);
      d=s1.toInt();
      s1=QString::number(d,16).toUpper();
      s=s+s1;
      ui->Text->insertPlainText(" Destination Port: "+QString::number(s.toInt(0,16),10));


      ui->Pack->clear();
      ui->Pack->insertPlainText("Data: ");
      for(int i=0; i<ps.ALLpackets[n].pHeader.caplen;i++)
      {
          QString dq;
          dq=QString::number(ps.ALLpackets[n].data[i]);
          int d=dq.toInt();
          QString s=QString::number(d,16).toUpper();
          ui->Pack->insertPlainText(" "+s);
      };




  }
  else
  {
      ui->Pack->setText("There is no such packet, please try another number");
  }
}
