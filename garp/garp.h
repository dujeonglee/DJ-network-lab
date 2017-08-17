#ifndef _GARP_
#define _GARP_

#define ARP_LEN                 (sizeof(struct ether_header) + sizeof(struct ether_arp))
#define GARP_REQ_TYPE           0
#define GARP_REP_TYPE           1
#define MAC_ADDR_BUFFER_SIZE    18
#define FILE_NAME_SIZE          128
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
#ifndef IP_ADDR_LEN
#define IP_ADDR_LEN 4
#endif

class garp{
private:/*PRIVATE STATIC VARIABLE*/
    static garp* _instance;
public:/*PUBLIC STATIC FUNCTION*/
    static garp* instance();
private:/*PRIVATE STATIC FUNCTION*/

private:/*PRIVATE CLASS VARIABLE*/
    int _send_socket;
public:/*PUBLIC CLASS FUNCTION*/
    int send(const unsigned int ip, const char* const ifname, const unsigned char type);
    int send(const unsigned int ip, const char* const ifname, const unsigned char* const mac, const unsigned char type);
private:/*PRIVATE CLASS FUNCTION*/
    bool hw_address(const char* const ifname, unsigned char* const hw_address);
    garp();
    ~garp();
};

#endif

