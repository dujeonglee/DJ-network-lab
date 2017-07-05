#ifndef _BROADCAST_FORWARD_
#define _BROADCAST_FORWARD_

#include <cstdint>
#include <utility>
#include <vector>
#include <string>

#include "md5.h"
#include "AVLTree.h"
#include "ThreadPool.h"
#include "SingleShotTimer.h"

struct MD5
{
    md5_byte_t stream[16];
};

class BroadcastForward
{
private:/*PRIVATE STATIC VARIABLE*/
    static BroadcastForward* g_Instance;
public:/*PUBLIC STATIC FUNCTION*/
    static BroadcastForward* Instance();
private:/*PRIVATE STATIC FUNCTION*/
    static bool HWAddress(const char* const ifname, unsigned char* const hw_address);
    static MD5 MessageDigest(const void* const data, const uint32_t length);
    static std::string MessageDigestStr(const void* const data, const uint32_t length);
private:/*PRIVATE CLASS VARIABLE*/
    int m_RxSocket;
    int m_TxSocket;
    unsigned char HWAddr[6];
    unsigned char m_TxBuffer[1024];
    unsigned char m_RxBuffer[1024];
    std::string m_IfName;
    AVLTree<MD5, uint8_t> m_MD5;
    ThreadPool<2, 1> m_ThreadPool;
    SingleShotTimer<2, 1> m_Timer;
private:/*PRIVATE CLASS FUNCTION*/
    BroadcastForward();
    ~BroadcastForward();
public:
    void Forward(const std::string ifname);
};
#endif /*_ARP_SPOOF_WIRED_*/
