.PHONY : all debug release backup
.SUFFIXES : .cpp .o

SOURCES  := $(wildcard *.cpp)
INCLUDES := 
OBJECTS  := $(SOURCES:.cpp=.o)
LIBRARY :=
CPP := g++
TARGET = arp_spoof_attck

all : debug

$(TARGET) : $(OBJECTS)
	$(CPP) -o $@  $^

.cc.o : $(SOURCES)
	$(CPP) $(CPPFLAGS) $(INCLUDES) $(SOURCES) $(LIBRARY)

clean :
	rm -rf $(OBJECTS) $(TARGET) *~

debug : CPPFLAGS := -g -c -Wall -Werror -std=c++0x
debug : $(TARGET)


release : CPPFLAGS := -O3 -c -Wall -Werror -std=c++0x
release : $(TARGET)

