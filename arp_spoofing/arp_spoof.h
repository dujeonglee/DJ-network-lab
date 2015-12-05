#ifndef _ARP_SPOOF_
#define _ARP_SPOOF_

class arp_spoof{
private:/*PRIVATE STATIC VARIABLE*/
    static arp_spoof* _instance;
public:/*PUBLIC STATIC FUNCTION*/
    static arp_spoof* instance();
private:/*PRIVATE STATIC FUNCTION*/

private:/*PRIVATE CLASS VARIABLE*/
    int _rx_socket;
    int _tx_socket;
    char* _rx_buffer;
    char* _tx_buffer;

private:/*PRIVATE CLASS FUNCTION*/
    bool hw_address(const char* const ifname, unsigned char* const hw_address);
    arp_spoof();
    ~arp_spoof();

public:
    void do_arp_spoof(const char *ifname, const char* filename);

};

#endif /*_ARP_SPOOF_WIRED_*/
