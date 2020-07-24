#ifndef _ARP_
#define _ARP_

#define ARP_LEN                 (sizeof(struct ether_header) + sizeof(struct ether_arp))
#define MAC_ADDR_BUFFER_SIZE    18
#define FILE_NAME_SIZE          128
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
#ifndef IP_ADDR_LEN
#define IP_ADDR_LEN 4
#endif

class arp{
private:/*PRIVATE STATIC VARIABLE*/
    static arp* _instance;
public:/*PUBLIC STATIC FUNCTION*/
    static arp* instance();
private:/*PRIVATE STATIC FUNCTION*/

private:/*PRIVATE CLASS VARIABLE*/
    int _send_socket;
public:/*PUBLIC CLASS FUNCTION*/
    int garp_send(const unsigned int ip, const char* const ifname);
    int raw_arp_send(const unsigned char* const eth_dst, 
                    const unsigned char* const eth_src,
                    const unsigned short ar_hrd,
                    const unsigned short ar_pro,
                    const unsigned char ar_hln,
                    const unsigned char ar_pln,
                    const unsigned short ar_op,
                    const unsigned char* const arp_sha,
                    const unsigned int arp_spa,
                    const unsigned char* const arp_tha,
                    const unsigned int arp_tpa,
                    const char* const ifname);
private:/*PRIVATE CLASS FUNCTION*/
    bool hw_address(const char* const ifname, unsigned char* const hw_address);
    void print_arp(const char* const buffer);
    arp();
    ~arp();
};

#endif

