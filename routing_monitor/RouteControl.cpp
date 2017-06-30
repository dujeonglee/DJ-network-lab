#include "RouteControl.h"

int RouteControl::rtnl_open(rtnl_handle* const rth, const unsigned subscriptions)
{
	memset(rth, 0, sizeof(rtnl_handle));
	rth->proto = NETLINK_ROUTE;
	if((rth->fd = socket(AF_NETLINK, /*SOCK_RAW | SOCK_CLOEXEC*/SOCK_DGRAM, NETLINK_ROUTE)) < 0)
    {
		return -1;
	}

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;
	if(bind(rth->fd, (sockaddr*)&rth->local, sizeof(rth->local)) < 0)
    {
		return -1;
	}

	rth->seq = time(nullptr);
	return 0;
}

void RouteControl::rtnl_close(rtnl_handle* const rth)
{
	if(rth->fd >= 0)
    {
		close(rth->fd);
		rth->fd = -1;
	}
}

// This function does the actual reading and writing to the netlink socket
int RouteControl::rtnl_talk(rtnl_handle* const rtnl, nlmsghdr* const n, const pid_t peer, const unsigned groups, nlmsghdr* const answer)
{
	// Filling up the details of the netlink socket to be contacted in the
	// kernel. 
	sockaddr_nl nladdr;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = peer;
	nladdr.nl_groups = groups;

    // Forming the iovector with the netlink packet.
	iovec iov = { (void*)n, n->nlmsg_len };
	// Forming the message to be sent.
	const msghdr msg = { (void*)&nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0 };

	n->nlmsg_seq = ++rtnl->seq;
	if(answer == nullptr)
    {
		n->nlmsg_flags |= NLM_F_ACK;
    }
	// Actual sending of the message, status contains success/failure
	const int status = sendmsg(rtnl->fd, &msg, 0);
	if(status < 0)
    {
		return -1;
	}
	return 0;
}

int RouteControl::rtnl_listen(rtnl_handle* const rtnl, char* const buff, const uint32_t size)
{
	nlmsghdr *nlHdr;
	char* bufPtr = buff;
	int readLen = 0;
    int msgLen = 0;

	do{
		/* Recieve response from the kernel */
		if((readLen = recv(rtnl->fd, bufPtr, size - msgLen, 0)) < 0)
        {
			return -1;
		}
        nlHdr = (nlmsghdr *)bufPtr;
		/* Check if the header is valid */
        if((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR))
        {
            return -1;
        }
        if(nlHdr->nlmsg_type == NLMSG_DONE)
        {
		    /* Check if the its the last message */
            break;
        }
        else
        {
		    /* Else move the pointer to buffer appropriately */
            bufPtr += readLen;
            msgLen += readLen;
        }

		/* Check if its a multi part message */
        if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0)
        {
           /* return if its not */
            break;
        }
    }while(nlHdr->nlmsg_seq != rtnl->seq);
    return msgLen;
}

// This is the utility function for adding the parameters to the packet.
int RouteControl::addattr_l(nlmsghdr* const n, const int maxlen, const int type, const void* const data, const int alen)
{
	int len = RTA_LENGTH(alen);
	rtattr *rta;
	if(NLMSG_ALIGN(n->nlmsg_len) + len > (unsigned int)maxlen)
    {
		return -1;
	}
	rta = (rtattr*)(((char*)n) + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
	return 0;
}

int RouteControl::add_or_replace(const uint8_t af, const void* const destination, const uint8_t mask, const void* const gateway, const char* const ifname)
{
	if(ifname != nullptr)
    {
		return add_or_replace(af, destination, mask, gateway, if_nametoindex(ifname));
	}
	return 0;
}

int RouteControl::add_or_replace(const uint8_t af, const void* const destination, const uint8_t mask, const void* const gateway, const uint32_t oif)
{
	rtnl_handle rth;
	struct{
		nlmsghdr    n;
		rtmsg       r;
		char        buf[1024];
	}req;

	int gw_ok = 0;

	if(rtnl_open(&rth, 0) < 0)
    {
		return -1;
	}

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_REPLACE;
	req.n.nlmsg_type = RTM_NEWROUTE;
	req.r.rtm_family = af;
	req.r.rtm_table = RT_TABLE_MAIN;
	req.r.rtm_scope = RT_SCOPE_NOWHERE;
	req.r.rtm_protocol = RTPROT_STATIC;
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	req.r.rtm_type = RTN_UNICAST;

	if(destination != 0)
    {
		req.r.rtm_dst_len = mask;
		addattr_l(&req.n, sizeof(req), RTA_DST, destination, (af == AF_INET?4:16));
	}
	if(gateway != 0)
    {
		gw_ok = 1;
		addattr_l(&req.n, sizeof(req), RTA_GATEWAY, gateway, (af == AF_INET?4:16));
	}
	if(oif != 0)
    {
		addattr_l(&req.n, sizeof(req), RTA_OIF, &oif, sizeof(oif));
	}
	if(!gw_ok)
    {
		req.r.rtm_scope = RT_SCOPE_LINK;
	}
	if(rtnl_talk(&rth, &req.n, 0, 0, NULL) < 0)
    {
		rtnl_close(&rth);
		return -1;
	}
	rtnl_close(&rth);
	return 0;
}

int RouteControl::del(const uint8_t af, const void* const destination, const uint8_t mask, const void* const gateway, const char* const ifname)
{
    if (ifname != nullptr)
    {
		return del(af, destination, mask, gateway, if_nametoindex(ifname));
	}
	return 0;
}

int RouteControl::del(const uint8_t af, const void* const destination, const uint8_t mask, const void* const gateway, const uint32_t oif)
{
	rtnl_handle rth;
	struct{
		struct nlmsghdr     n;
		struct rtmsg		r;
		char                buf[1024];
	} req;

	if(rtnl_open(&rth, 0) < 0)
    {
		return -1;
	}

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELROUTE;
	req.r.rtm_family = af;
	req.r.rtm_table = RT_TABLE_MAIN;
	req.r.rtm_scope = RT_SCOPE_NOWHERE;

	if(destination)
    {
		req.r.rtm_dst_len = mask;
		addattr_l(&req.n, sizeof(req), RTA_DST, destination, (af == AF_INET ? 4 : 16));
	}
	if(gateway != 0)
    {
		addattr_l(&req.n, sizeof(req), RTA_GATEWAY, gateway, (af == AF_INET ? 4 : 16));
	}
	if(oif != 0)
    {
		addattr_l(&req.n, sizeof(req), RTA_OIF, &oif, sizeof(oif));
	}

	if(rtnl_talk(&rth, &req.n, 0, 0, NULL) < 0)
    {
		rtnl_close(&rth);
		return -1;
	}
	rtnl_close(&rth);
	return 0;
}
