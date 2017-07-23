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

class XSpoof
{
private:/*PRIVATE STATIC VARIABLE*/
    static XSpoof* g_Instance;
public:/*PUBLIC STATIC FUNCTION*/
    static XSpoof* Instance();
private:/*PRIVATE STATIC FUNCTION*/
    static bool HWAddress(const char* const ifname, unsigned char* const hw_address);
private:/*PRIVATE CLASS VARIABLE*/
    bool m_Running;
    int m_RxSockets[2];
    int m_TxSocket;
    unsigned char m_HWAddr[6];
    unsigned char m_TxBuffer[1024];
    unsigned char m_RxBuffer[1024];
    std::string m_IfName;
private:/*PRIVATE CLASS FUNCTION*/
    XSpoof();
    ~XSpoof();
    uint16_t ICMPChecksum(void* IP6Hdr);
	void SendNeighborAdvertisement(const uint8_t* TargetIPAddress, const uint8_t* TargetMACAddress, const std::string interface);
	void SendGratuitousARP(const uint8_t* TargetIPAddress, const uint8_t* TargetMACAddress, const std::string interface);
public:
    bool Start(const std::string interface);
    void Stop();
    void DoXSpoof();
};
#endif /*_ARP_SPOOF_WIRED_*/
