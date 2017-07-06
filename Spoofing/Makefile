.PHONY : all debug release backup
.SUFFIXES : .cpp .o

SOURCES  := $(wildcard *.cpp)
INCLUDES := -I./basiclibrary/avltree -I./basiclibrary/threadpool -I./basiclibrary/singleshottimer
OBJECTS  := $(SOURCES:.cpp=.o)
LIBRARY := -lpthread
CPP := g++
TARGET = arp_spoof_attck

all : debug

$(TARGET) : $(OBJECTS)
	$(CPP) -o $@  $^  $(LIBRARY)

.cpp.o : $(SOURCES)
	$(CPP) $(CPPFLAGS) $(INCLUDES) $(SOURCES)

./basiclibrary/.git/config : 
	git clone https://github.com/dujeonglee/basiclibrary.git

clean :
	rm -rf $(OBJECTS) $(TARGET) *~

debug : CPPFLAGS := -g -c -Wall -Werror -std=c++0x
debug : ./basiclibrary/.git/config
debug : $(TARGET)


release : CPPFLAGS := -O3 -c -Wall -Werror -std=c++0x
release : ./basiclibrary/.git/config
release : $(TARGET)
