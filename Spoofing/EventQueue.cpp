#include "EventQueue.h"

EventQueue* EventQueue::g_Instance = new EventQueue();

EventQueue::EventQueue(){}

EventQueue::~EventQueue(){}

EventQueue* EventQueue::Instance()
{
    return g_Instance;
}

SingleShotTimer<2,1>& EventQueue::Queue()
{
    return m_Queue;
}
