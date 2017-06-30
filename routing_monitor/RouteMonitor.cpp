#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <unistd.h>

#include "RouteMonitor.h"

route_monitor* route_monitor::_instance = NULL;

route_monitor* route_monitor::instance(){
    if(_instance){
        return _instance;
    }
    _instance = new route_monitor;
    if(_instance == NULL){
        printf("FATAL - out of memory\n");
    }
    return _instance;
}

void route_monitor::waiting_for_routing_change(){
	int     received_bytes = 0;
    struct  nlmsghdr *nlh;
    struct  rtmsg *route_entry;  /* This struct represent a route entry in the routing table */
    struct  rtattr *route_attribute; /* This struct contain route attributes (route type) */
    int     route_attribute_len = 0;
	u32		destination = 0;
	u32		gateway = 0;
	int		oif = 0;
    
    memset(_instance->_buffer, 0x0, sizeof(_instance->_buffer));

    /* Receiving netlink socket data */
    received_bytes = recv(_instance->_sock, _instance->_buffer, sizeof(_instance->_buffer), 0);
    if (received_bytes < 0){
        return;
	}
	/* cast the received buffer */
	nlh = (struct nlmsghdr *) _instance->_buffer;

    /* Reading netlink socket data */
    /* Loop through all entries */
    /* For more informations on some functions :
     * http://www.kernel.org/doc/man-pages/online/pages/man3/netlink.3.html
     * http://www.kernel.org/doc/man-pages/online/pages/man7/rtnetlink.7.html
     */
    for ( ; NLMSG_OK(nlh, received_bytes); nlh = NLMSG_NEXT(nlh, received_bytes)){
        /* Get the route data */
        route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

        /* We are just intrested in main routing table */
        if (route_entry->rtm_table != RT_TABLE_MAIN)
            continue;

        /* Get attributes of route_entry */
        route_attribute = (struct rtattr *) RTM_RTA(route_entry);

        /* Get the route atttibutes len */
        route_attribute_len = RTM_PAYLOAD(nlh);
        /* Loop through all attributes */
        for ( ; RTA_OK(route_attribute, route_attribute_len); route_attribute = RTA_NEXT(route_attribute, route_attribute_len)){
            /* Get the destination address */
            if (route_attribute->rta_type == RTA_DST){
                destination = *(u32*)RTA_DATA(route_attribute);
            }
            /* Get the gateway (Next hop) */
            if (route_attribute->rta_type == RTA_GATEWAY){
				gateway = *(u32*)RTA_DATA(route_attribute);
            }
			/* Get out interface index */
            if (route_attribute->rta_type == RTA_OIF){
				oif = *(int*)RTA_DATA(route_attribute);
            }
        }

        printf("Route Update: %s %hhu.%hhu.%hhu.%hhu/%hhu via %hhu.%hhu.%hhu.%hhu dev %u [Flags %hu]\n", ((u32)nlh->nlmsg_type==RTM_DELROUTE?"DELETE":"ADD"),
               ((u8*)&destination)[0], ((u8*)&destination)[1], ((u8*)&destination)[2], ((u8*)&destination)[3],
                route_entry->rtm_dst_len,
                ((u8*)&gateway)[0], ((u8*)&gateway)[1], ((u8*)&gateway)[2], ((u8*)&gateway)[3],
                oif,
                nlh->nlmsg_flags);
    }
    return;
}

route_monitor::route_monitor(){
    struct sockaddr_nl addr;

    while((_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0);

    memset(&addr, 0x0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_ROUTE;

    while(bind(_sock,(struct sockaddr *)&addr,sizeof(addr)) < 0);
}

route_monitor::~route_monitor(){
    close(_sock);
}
