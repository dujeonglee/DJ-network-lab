#ifndef _ARP_SPOOF_
#define _ARP_SPOOF_

#include <cstdint>
#include <utility>
#include <vector>

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
    unsigned char m_TxBuffer[1024];
    unsigned char m_RxBuffer[1024];
private:/*PRIVATE CLASS FUNCTION*/
    ARPSpoof();
    ~ARPSpoof();
    uint16_t ICMPChecksum(void* IP6Hdr);
public:
    void DoARPSpoof(const char *ifname, const char* filename);
};
#endif /*_ARP_SPOOF_WIRED_*/
