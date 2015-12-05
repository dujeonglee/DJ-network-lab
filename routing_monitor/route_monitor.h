#ifndef _ROUTE_WATCH_DOG_
#define _ROUTE_WATCH_DOG_

typedef unsigned int u32;											/*!< unsigned integer */
typedef unsigned short u16;											/*!< unsigned short */
typedef unsigned char u8;

class route_monitor{
private:/*PRIVATE STATIC VARIABLE*/
    static route_monitor* _instance;
public:/*PUBLIC STATIC FUNCTION*/
    static route_monitor* instance();
public:/*PRIVATE STATIC FUNCTION*/

private:/*PRIVATE CLASS VARIABLE*/
    int _sock;
    char _buffer[1024];

public:/*PUBLIC CLASS FUNCTION*/
    void waiting_for_routing_change();
private:/*PRIVATE CLASS FUNCTION*/
    route_monitor();
    ~route_monitor();
};
#endif

