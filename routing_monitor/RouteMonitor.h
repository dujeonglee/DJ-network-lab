#ifndef _ROUTE_WATCH_DOG_
#define _ROUTE_WATCH_DOG_

class RouteMonitor{
private:/*PRIVATE STATIC VARIABLE*/
    static RouteMonitor* m_Instance;
public:/*PUBLIC STATIC FUNCTION*/
    static RouteMonitor* Instance();
public:/*PRIVATE STATIC FUNCTION*/

private:/*PRIVATE CLASS VARIABLE*/
    int m_Sock;
    char m_Buffer[1024];

public:/*PUBLIC CLASS FUNCTION*/
    void MonitorRoutingUpdate();
private:/*PRIVATE CLASS FUNCTION*/
    RouteMonitor();
    ~RouteMonitor();
};
#endif

