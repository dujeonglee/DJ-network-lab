.PHONY : all debug release backup
.SUFFIXES : .cpp .o

SOURCES  := $(wildcard *.cpp)
INCLUDES := 
OBJECTS  := $(SOURCES:.cpp=.o)
LIBRARY := -lpthread
CPP := g++
TARGET = test

all : DEBUG

$(TARGET) : $(OBJECTS)
	$(CPP) -o $@  $^ $(LIBRARY)

.cc.o : $(SOURCES)
	$(CPP) $(CPPFLAGS) $(INCLUDES) $(SOURCES) $(LIBRARY)

clean :
	rm -rf $(OBJECTS) $(TARGET) *~

DEBUG : CPPFLAGS := -g -c -Wall -Werror -std=c++0x
DEBUG : $(TARGET)
	./test

RELEASE : CPPFLAGS := -O0 -c -Wall -Werror -std=c++0x
RELEASE : $(TARGET)
	./test
