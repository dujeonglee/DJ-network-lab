#ifndef EVENTQUEUE_H_
#define EVENTQUEUE_H_

#include "SingleShotTimer.h"

class EventQueue
{
private:
    static EventQueue* g_Instance;
    EventQueue();
    ~EventQueue();
public:
    static EventQueue* Instance();
private:
    SingleShotTimer<2,1> m_Queue;
public:
    SingleShotTimer<2,1>& Queue();
};

#endif