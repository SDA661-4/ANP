#ifndef SDAPACKET_H
#define SDAPACKET_H

#include <sniffer.h>
#include <start.h>


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
