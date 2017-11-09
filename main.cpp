#include "mainwindow.h"
#include <QApplication>
#include "start.h"
#include <sniffer.h>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Start w;
    w.show();

//    myPacket::myPacket()
//    {
//        m_data = NULL;
//    };

//    myPacket::~myPacket()
//    {
//        if(m_data!=NULL) delete []m_data;
//    };

//    myPacket::myPacket(const myPacket &p)
//    {
//        m_pHeader=p.m_pHeader;
//        m_data=new unsigned char[m_pHeader.caplen];
//        memcpy(p.m_data,m_data,m_pHeader.caplen);
//    };

//    void myPacket::operator =(const myPacket &p)
//    {
//        m_pHeader=p.m_pHeader;
//        m_data=new unsigned char[m_pHeader.caplen];
//        memcpy(p.m_data,m_data,m_pHeader.caplen);
//    };

    return a.exec();
}
