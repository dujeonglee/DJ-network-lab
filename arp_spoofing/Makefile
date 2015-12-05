.PHONY : all debug release backup
.SUFFIXES : .cpp .o

SOURCES  := $(wildcard *.cpp)
INCLUDES := 
OBJECTS  := $(SOURCES:.cpp=.o)
LIBRARY :=
CPP := g++
TARGET = arp_spoof_attck

all : DEBUG

$(TARGET) : $(OBJECTS)
	$(CPP) -o $@  $^

.cc.o : $(SOURCES)
	$(CPP) $(CPPFLAGS) $(INCLUDES) $(SOURCES) $(LIBRARY)

clean :
	rm -rf $(OBJECTS) $(TARGET) *~

DEBUG : CPPFLAGS := -g -c -Wall -Werror
DEBUG : $(TARGET)
	sudo ./$(TARGET) wlan0 attack_ip_list.txt

RELEASE : CPPFLAGS := -O0 -c -Wall -Werror
RELEASE : $(TARGET)
	sudo ./$(TARGET) wlan0 attack_ip_list.txt
