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
QTableWidgetItem *cell;


Sniffer::Sniffer(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Sniffer)
{
    ui->setupUi(this);

    ui->Table->setColumnCount(9);
    ui->Table->setRowCount(0);
    ui->Table->setShowGrid(true);
    ui->Table->setHorizontalHeaderItem(0,new QTableWidgetItem(tr("destination MAC")));
    ui->Table->setHorizontalHeaderItem(1,new QTableWidgetItem(tr("source MAC")));
    ui->Table->setHorizontalHeaderItem(2,new QTableWidgetItem(tr("Type")));
    ui->Table->setHorizontalHeaderItem(3,new QTableWidgetItem(tr("Length of IP")));
    ui->Table->setHorizontalHeaderItem(4,new QTableWidgetItem(tr("source IP")));
    ui->Table->setHorizontalHeaderItem(5,new QTableWidgetItem(tr("destination IP")));
    ui->Table->setHorizontalHeaderItem(6,new QTableWidgetItem(tr("Protocol")));
    ui->Table->setHorizontalHeaderItem(7,new QTableWidgetItem(tr("source Port")));
    ui->Table->setHorizontalHeaderItem(8,new QTableWidgetItem(tr("destination Port")));
    for (int i=1;i<9;i++)
        ui->Table->horizontalHeaderItem(i)->setTextAlignment(4);
}

Sniffer::~Sniffer()
{
    delete ui;
}

bool if_IP(int n)
{
 int s=QString::number(ps.ALLpackets[n].data[12]).toInt(0,16);
 int s1=QString::number(ps.ALLpackets[n].data[13]).toInt(0,16);
 qDebug()<<"s="<<s<<"s1="<<s1;
 if ((s==8) && (s1==0))
     return true;
 else
     return false;
}

void Sniffer::IP_analyzer(int n,int pos)
{
//----------------------------------Length-------------------------------------
    pos=14;
    QString s=QString::number(ps.ALLpackets.at(n).data[pos],16).toUpper();
    cell= new QTableWidgetItem;
    cell->setText(QString(s[1]));
    ui->Table->setItem(n,3,cell);
    cell->setTextAlignment(4);
    int k=s.toInt();
    k=k%10;
    k=4*k;
    k=k-20;
//----------------------------------SourIP-------------------------------------
    pos=26;
    cell= new QTableWidgetItem;
    for (int i=pos; i<pos+4; i++)
    {
       if (i!=pos) cell->setText(cell->text()+".");
       cell->setText(cell->text()+QString::number(ps.ALLpackets[n].data[i]));
    };
    ui->Table->setItem(n,4,cell);
//----------------------------------DestIP-------------------------------------
    pos=30;
    cell= new QTableWidgetItem;
    for (int i=pos; i<pos+4; i++)
    {
        if (i!=pos) cell->setText(cell->text()+".");
        cell->setText(cell->text()+QString::number(ps.ALLpackets[n].data[i]));
    };
    ui->Table->setItem(n,5,cell);
//----------------------------------Protocol-------------------------------------
    pos=23;
    int d=QString::number(ps.ALLpackets.at(allpackets).data[pos],10).toInt();
    if(d<16)
    {
       cell=new QTableWidgetItem;
       cell->setText("0"+QString::number(ps.ALLpackets[n].data[pos]));
       ui->Table->setItem(n,6,cell);
       cell->setTextAlignment(4);
    }
    else
    {
       cell=new QTableWidgetItem;
       cell->setText(QString::number(ps.ALLpackets[n].data[pos]));
       ui->Table->setItem(n,6,cell);
       cell->setTextAlignment(4);
    };
    if_TCP_UDP(n,d,pos,k);
}

void Sniffer::if_TCP_UDP(int n, int d, int pos, int k)
{
    cell=new QTableWidgetItem;
    cell->setText(ui->Table->item(n,6)->text());
    switch (d) {
    case 6: cell->setText(cell->text()+" - TCP"); break;
    case 17: cell->setText(cell->text()+" - UDP"); break;
    default: cell->setText(cell->text()+" - unknown  protocol"); break;
    }
    ui->Table->setItem(n,6,cell);
    cell->setTextAlignment(4);
//----------------------------------SourPort-------------------------------------
    pos=34+k;
    cell=new QTableWidgetItem;
    QString s=QString::number(ps.ALLpackets.at(n).data[pos]);
    int c=s.toInt();
    s=QString::number(c,16).toUpper();
    QString s1=QString::number(ps.ALLpackets.at(n).data[pos+1]);
    c=s1.toInt();
    s1=QString::number(c,16).toUpper();
    s=s+s1;
    cell->setText(QString::number(s.toInt(0,16),10));
    ui->Table->setItem(n,7,cell);
    cell->setTextAlignment(4);
    ui->Table->resizeColumnToContents(7);
//----------------------------------DestPort-------------------------------------
    pos=36+k;
    cell=new QTableWidgetItem;
    s=QString::number(ps.ALLpackets.at(n).data[pos]);
    c=s.toInt();
    s=QString::number(c,16).toUpper();
    s1=QString::number(ps.ALLpackets.at(n).data[pos+1]);
    c=s1.toInt();
    s1=QString::number(c,16).toUpper();
    s=s+s1;
    cell->setText(QString::number(s.toInt(0,16),10));
    ui->Table->setItem(n,8,cell);
    cell->setTextAlignment(4);
    ui->Table->resizeColumnToContents(8);

}


//--------------------------------------------OPEN_OF_FILE----------------------------------
 Sniffer::on_Open_clicked()
{
    ui->Table->setEditTriggers(QAbstractItemView::NoEditTriggers);
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
        ui->Table->setRowCount(ui->Table->rowCount() + 1);
        qDebug()<<ps.ALLpackets.size()<<"sizzze";
        file.read((char *) &pops.pHeader, 16);
//        qDebug()<<"1";
//        qDebug()<<"2";
        pops.data=new unsigned char[pops.pHeader.caplen];
        for (int i=0; i<pops.pHeader.caplen; i++)
        {
            file.read((char*) &pops.data[i],1);
        };
//        qDebug()<<"3";
//        qDebug()<<"4";
        ps.ALLpackets.append(pops);
//        ui->Text->append("Packets # "+QString::number(allpackets));
//        ui->Text->append("\tt1: "+QString::number(pops.pHeader.t1)+" milisec");
//        ui->Text->append("\tt2: "+QString::number(pops.pHeader.t2)+" milisec");
//        ui->Text->append("\tPacket: "+QString::number(pops.pHeader.len)+"bytes");
        if (pops.pHeader.caplen > maxl)
                    maxl = pops.pHeader.caplen;
        if (pops.pHeader.caplen < minl)
                    minl = pops.pHeader.caplen;
        avrgl=avrgl+pops.pHeader.caplen;
//----------------------------------DestMAC-------------------------------------
        cell= new QTableWidgetItem;
        for (int i=0; i<6; i++)
        {
            QString s=QString::number(ps.ALLpackets.at(allpackets).data[i],16).toUpper();
            qDebug()<<"DESTdata"<<s;
            if(QString::number(ps.ALLpackets.at(allpackets).data[i],10).toInt()<16)
            {
                if(i!=0) cell->setText(cell->text()+":");
                cell->setText(cell->text()+"0"+s);
            }
            else
            {
                if(i!=0) cell->setText(cell->text()+":");
                cell->setText(cell->text()+s);
            }
        }
        ui->Table->setItem(allpackets,0,cell);
        ui->Table->resizeColumnToContents(0);
//----------------------------------SourMAC-------------------------------------
        cell= new QTableWidgetItem;
        for (int i=6; i<12; i++)
        {
            QString s=QString::number(ps.ALLpackets.at(allpackets).data[i],16).toUpper();
            if(QString::number(ps.ALLpackets.at(allpackets).data[i],10).toInt()<16)
            {
                if(i!=6) cell->setText(cell->text()+":");
                cell->setText(cell->text()+"0"+s);
            }
            else
            {
                if(i!=6) cell->setText(cell->text()+":");
                cell->setText(cell->text()+s);
            }
        }
        ui->Table->setItem(allpackets,1,cell);
        ui->Table->resizeColumnToContents(1);

//----------------------------------Type-------------------------------------
        cell= new QTableWidgetItem;
        if(QString::number(ps.ALLpackets.at(allpackets).data[12],10).toInt()<16)
           cell->setText("0"+QString::number(pops.data[12])+":0"+QString::number(pops.data[13]));
        else
           cell->setText(QString::number(pops.data[12])+":"+QString::number(pops.data[13]));
        ui->Table->setItem(allpackets,2,cell);
        cell->setTextAlignment(4);

        if(if_IP(allpackets))
        {
            cell->setText(ui->Table->item(allpackets,2)->text()+" - IP");
            ui->Table->setItem(allpackets,2,cell);
            IP_analyzer(allpackets,12);
        }


//        ui->Text->append("\tPacket: "+QString::number(pops.pHeader.caplen)+" bytes captured");
//        ui->Text->append("");


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
//        qDebug()<<allpackets<<" pac";
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
  n=n-1;
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
      ui->Text->append(" t1: "+QString::number(ps.ALLpackets.at(n).pHeader.t1)+" milisec");
      ui->Text->append(" t2: "+QString::number(ps.ALLpackets.at(n).pHeader.t2)+" milisec");
      ui->Text->append(" Packet: "+QString::number(ps.ALLpackets.at(n).pHeader.len)+"bytes");
      ui->Text->append(" Packet: "+QString::number(ps.ALLpackets.at(n).pHeader.caplen)+" bytes captured");
      qDebug()<<if_IP(n);
//----------------------------------DestMAC-------------------------------------
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
//----------------------------------SourMAC-------------------------------------
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
      };\
//----------------------------------Type-------------------------------------
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
//      if (if_IP(n))
//      {
//          ui->Text->insertPlainText(" - IP");
//          IP_analyzer(n,pos);
//      }
//        else
//          ui->Text->insertPlainText(" - unknown type");



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
