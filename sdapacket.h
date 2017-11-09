#ifndef SDAPACKET_H
#define SDAPACKET_H

#include <sniffer.h>
#include <start.h>

//struct PcapHeader
//{
//    qint32 t1;
//    qint32 t2;
//    qint32 caplen;
//    qint32 len;
//};

class SDApacket
{
public:
    SDApacket();
    SDApacket(const SDApacket &p);
    ~SDApacket();
    void operator = (const SDApacket &p);
    PcapHeader m_pHeader;
    unsigned char* m_data;

};

#endif // SDAPACKET_H
