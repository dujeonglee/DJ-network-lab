#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <cstdio>
#include <cstring>
#include <cstdint>

#include "RouteMonitor.h"

RouteMonitor* RouteMonitor::m_Instance = NULL;

RouteMonitor* RouteMonitor::Instance(){
    if(m_Instance){
        return m_Instance;
    }
    m_Instance = new RouteMonitor;
    if(m_Instance == NULL){
        printf("FATAL - out of memory\n");
    }
    return m_Instance;
}

void RouteMonitor::MonitorRoutingUpdate(){
	int     received_bytes = 0;
    struct  nlmsghdr *nlh;
    struct  rtmsg *route_entry;  /* This struct represent a route entry in the routing table */
    struct  rtattr *route_attribute; /* This struct contain route attributes (route type) */
    int     route_attribute_len = 0;
	uint8_t*    destination;
	uint8_t*    gateway;
	int		oif = 0;
    
    memset(m_Instance->m_Buffer, 0x0, sizeof(m_Instance->m_Buffer));

    /* Receiving netlink socket data */
    received_bytes = recv(m_Instance->m_Sock, m_Instance->m_Buffer, sizeof(m_Instance->m_Buffer), 0);
    if (received_bytes < 0){
        return;
	}
	/* cast the received buffer */
	nlh = (struct nlmsghdr *) m_Instance->m_Buffer;

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
        destination = nullptr;
        gateway = nullptr;
        oif = 0;
        for ( ; RTA_OK(route_attribute, route_attribute_len); route_attribute = RTA_NEXT(route_attribute, route_attribute_len)){
            /* Get the destination address */
            if (route_attribute->rta_type == RTA_DST){
                destination = (uint8_t*)RTA_DATA(route_attribute);
            }
            /* Get the gateway (Next hop) */
            if (route_attribute->rta_type == RTA_GATEWAY){
				gateway = (uint8_t*)RTA_DATA(route_attribute);
            }
			/* Get out interface index */
            if (route_attribute->rta_type == RTA_OIF){
				oif = *(int*)RTA_DATA(route_attribute);
            }
        }

        if(route_entry->rtm_family == AF_INET)
        {
            printf("IPv4 Route Update : %s ", ((uint32_t)nlh->nlmsg_type==RTM_DELROUTE?"DELETE":"ADD"));
            for(uint8_t i = 0 ; i < 4 ; i++)
            {
                printf("%hhu", destination[i]);
                if(i < 3)
                {
                    printf(".");
                }
            }
            printf("/%hhu", route_entry->rtm_dst_len);
            printf(" via ");
            if(gateway)
            {
                for(uint8_t i = 0 ; i < 4 ; i++)
                {
                    printf("%hhu", gateway[i]);
                    if(i < 3)
                    {
                        printf(".");
                    }
                }
            }
            else
            {
                printf("0.0.0.0");
            }
            printf(" dev %u", oif);
            printf("[Flags %hu]\n", nlh->nlmsg_flags);
        }
        else if(route_entry->rtm_family == AF_INET6)
        {
            printf("IPv6 Route Update : %s ", ((uint32_t)nlh->nlmsg_type==RTM_DELROUTE?"DELETE":"ADD"));
            if(destination)
            {
                for(uint8_t i = 0 ; i < 16 ; i++)
                {
                    printf("%02hhx", destination[i]);
                    if(i % 2 == 1 && i != 15)
                    {
                        printf(":");
                    }
                }
            }
            printf("/%hhu", route_entry->rtm_dst_len);
            printf(" via ");
            if(gateway)
            {
                for(uint8_t i = 0 ; i < 16 ; i++)
                {
                    printf("%02hhx", gateway[i]);
                    if(i % 2 == 1 && i != 15)
                    {
                        printf(":");
                    }
                }
            }
            else
            {
                printf("::");
            }
            printf(" dev %u", oif);
            printf("[Flags %hu]\n", nlh->nlmsg_flags);
        }
    }
    return;
}

RouteMonitor::RouteMonitor(){
    struct sockaddr_nl addr;

    while((m_Sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0);

    memset(&addr, 0x0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;

    while(bind(m_Sock,(struct sockaddr *)&addr,sizeof(addr)) < 0);
}

RouteMonitor::~RouteMonitor(){
    close(m_Sock);
}
