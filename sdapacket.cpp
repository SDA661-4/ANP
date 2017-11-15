#include "sdapacket.h"

SDApacket::SDApacket()
{
  m_data = NULL;
}

SDApacket::~SDApacket()
{
    if(m_data!=NULL) delete []m_data;
}

void SDApacket::operator =(const SDApacket &p)
{
 m_pHeader=p.m_pHeader;
 m_data=new unsigned char[m_pHeader.caplen];
 memcpy(p.m_data,m_data,m_pHeader.caplen);
}

SDApacket::SDApacket(const SDApacket &p)
{
 m_pHeader=p.m_pHeader;
 m_data=new unsigned char[m_pHeader.caplen];
 memcpy(p.m_data,m_data,m_pHeader.caplen);
}
