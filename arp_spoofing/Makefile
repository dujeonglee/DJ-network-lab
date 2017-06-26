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

DEBUG : CPPFLAGS := -g -c -Wall -Werror -std=c++11
DEBUG : $(TARGET)


RELEASE : CPPFLAGS := -O3 -c -Wall -Werror -std=c++11
RELEASE : $(TARGET)

