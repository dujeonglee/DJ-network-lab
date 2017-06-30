#ifndef _RouteControl_
#define _RouteControl_

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>

#include <asm/types.h>

#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>

struct rtnl_handle
{
    int         fd;
    sockaddr_nl local;
    sockaddr_nl peer;
    uint32_t    seq;
    uint32_t    dump;
    int         proto;
    FILE*       dump_fp;
};

class RouteControl{
private:
	static int rtnl_open(rtnl_handle* const rth, const unsigned subscriptions);
	static void rtnl_close(rtnl_handle* const rth);
	static int rtnl_talk(rtnl_handle* const rtnl, nlmsghdr* const n, const pid_t peer, const unsigned groups, nlmsghdr* const answer);
	static int rtnl_listen(rtnl_handle* const rtnl, char* const buff, const uint32_t size);
	static int addattr_l(nlmsghdr* const n, const int maxlen, const int type, const void* const data, const int alen);
public:
    static int add_or_replace(const uint8_t af, const void* const destination, const uint8_t mask, const void* const gateway, const char* const ifname);
    static int add_or_replace(const uint8_t af, const void* const destination, const uint8_t mask, const void* const gateway, const uint32_t oif);
    static int del(const uint8_t af, const void* const destination, const uint8_t mask, const void* const gateway, const char* const ifname);
    static int del(const uint8_t af, const void* const destination, const uint8_t mask, const void* const gateway, const uint32_t oif);
};

#endif
