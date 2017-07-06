#ifndef _BROADCAST_FORWARD_
#define _BROADCAST_FORWARD_

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
public:
    void SetNetworkInterface(const NetworkInterfaceType, const std::string);
    bool Start();
    void Stop();
};
#endif /*_ARP_SPOOF_WIRED_*/
