#ifndef _ARP_SPOOF_#define _ARP_SPOOF_
#include <utility>#include <vector>
enum IPVERSION : unsigned char{ IPV4 = 0, IPV6};
class ARPSpoof{private:/*PRIVATE STATIC VARIABLE*/    static ARPSpoof* g_Instance;public:/*PUBLIC STATIC FUNCTION*/    static ARPSpoof* Instance();private:/*PRIVATE STATIC FUNCTION*/
private:/*PRIVATE CLASS VARIABLE*/    std::vector< int > m_RxSockets;    int m_TxSocket;    unsigned char m_TxBuffer[1024];    unsigned char m_RxBuffer[1024];
private:/*PRIVATE CLASS FUNCTION*/    bool HWAddress(const char* const ifname, unsigned char* const hw_address);    ARPSpoof();    ~ARPSpoof();
public:    void DoARPSpoof(const char *ifname, const char* filename);
};
#endif /*_ARP_SPOOF_WIRED_*/
