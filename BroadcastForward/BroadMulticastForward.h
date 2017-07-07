#ifndef _BROADCAST_FORWARD_
#define _BROADCAST_FORWARD_
#include <netinet/ip.h>
#include <netinet/ip6.h>
//#include <netinet/icmp6.h>
#include <netinet/udp.h>

#include <cstdint>
#include <string>

#include "md5.h"
#include "AVLTree.h"
#include "ThreadPool.h"
#include "SingleShotTimer.h"

struct MD5
{
    md5_byte_t stream[16];
};

struct HWAddressType
{
    uint8_t address[6];
};

struct DHCPv4
{
    uint8_t op;									/* 0: Message opcode/type */
    uint8_t htype;								/* 1: Hardware addr type (net/if_types.h) */
    uint8_t hlen;								/* 2: Hardware addr length */
    uint8_t hops;								/* 3: Number of relay agent hops from client */
    uint32_t xid;								/* 4: Transaction ID */
    uint16_t secs;								/* 8: Seconds since client started looking */
    uint16_t flags;								/* 10: Flag bits */
    uint32_t ciaddr;							/* 12: Client IP address (if already in use) */
    uint32_t yiaddr;							/* 16: Client IP address */
    uint32_t siaddr;							/* 18: IP address of next server to talk to */
    uint32_t giaddr;							/* 20: DHCP relay agent IP address */
    uint8_t chaddr[16];						/* 24: Client hardware address */
    char sname[64];			/* 40: Server name */
    char file[128];				/* 104: Boot filename */
    char options[1236];	/* 212: Optional parameters */
}__attribute__((packed));

struct DHCPv6
{
    uint8_t Message;
    uint8_t Data[1];
}__attribute__((packed));

enum NetworkInterfaceType
{
    WIRELESS = 0,
    WIRED,
    MAX_NETWORK_INTERFACES
};

class BroadMulticastForward
{
private:/*PRIVATE STATIC VARIABLE*/
    static BroadMulticastForward* g_Instance;
public:/*PUBLIC STATIC FUNCTION*/
    static BroadMulticastForward* Instance();
private:/*PRIVATE STATIC FUNCTION*/
    static bool HWAddress(const char* const ifname, unsigned char* const hw_address);
    static MD5 MessageDigest(const void* const data, const uint32_t length);
    static std::string MessageDigestStr(const void* const data, const uint32_t length);
private:/*PRIVATE CLASS VARIABLE*/
    std::atomic<bool> m_Running;
    int m_Sockets[MAX_NETWORK_INTERFACES];
    std::string m_InterfaceNames[MAX_NETWORK_INTERFACES];
    HWAddressType m_InterfaceHWAddresses[MAX_NETWORK_INTERFACES];
    unsigned char m_TxBuffer[1024];
    unsigned char m_RxBuffer[1024];

    AVLTree<MD5, uint8_t> m_MD5;
    ThreadPool<2, 1> m_ThreadPool;
    SingleShotTimer<2, 1> m_Timer;

private:/*PRIVATE CLASS FUNCTION*/
    BroadMulticastForward();
    ~BroadMulticastForward();
    void Forward();
    void HandleNormalPackets(void* const pkt, const uint32_t pktlen, const NetworkInterfaceType iftype);
    void HandleDHCPv4Packets(void* const pkt, udphdr* const udp, DHCPv4* const dhcp, const uint32_t pktlen, const NetworkInterfaceType iftype);
    void HandleDHCPv6Packets(void* const pkt, udphdr* const udp, DHCPv6* const dhcp, const uint32_t pktlen, const NetworkInterfaceType iftype);
    int Send(const NetworkInterfaceType iftype, void* const pkt, const uint32_t pktlen);
public:
    void SetNetworkInterface(const NetworkInterfaceType, const std::string);
    bool Start();
    void Stop();
};
#endif /*_ARP_SPOOF_WIRED_*/
