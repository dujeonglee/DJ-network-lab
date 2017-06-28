#ifndef _ARP_SPOOF_
#define _ARP_SPOOF_

#include <cstdint>
#include <utility>
#include <vector>
#include <string>

#include "SingleShotTimer.h"

enum IPVERSION : unsigned char
{
    IPV4 = 0,
    IPV6
};

class ARPSpoof
{
private:/*PRIVATE STATIC VARIABLE*/
    static ARPSpoof* g_Instance;
public:/*PUBLIC STATIC FUNCTION*/
    static ARPSpoof* Instance();
private:/*PRIVATE STATIC FUNCTION*/
    static bool HWAddress(const char* const ifname, unsigned char* const hw_address);
private:/*PRIVATE CLASS VARIABLE*/
    int m_RxSockets[2];
    int m_TxSocket;
    unsigned char HWAddr[6];
    unsigned char m_TxBuffer[1024];
    unsigned char m_RxBuffer[1024];
	SingleShotTimer<1,1> m_Timer;
    std::string m_IfName;
private:/*PRIVATE CLASS FUNCTION*/
    ARPSpoof();
    ~ARPSpoof();
    uint16_t ICMPChecksum(void* IP6Hdr);
	void SendNeighborAdvertisement();
public:
    void DoARPSpoof(const char *ifname, const char* filename);
};
#endif /*_ARP_SPOOF_WIRED_*/
