.PHONY : all debug release backup
.SUFFIXES : .cpp .o

SOURCES  := $(wildcard *.cpp)
INCLUDES := 
OBJECTS  := $(SOURCES:.cpp=.o)
LIBRARY :=
CPP := g++
TARGET = route_monitor

all : DEBUG

$(TARGET) : $(OBJECTS)
	$(CPP) -o $@  $^  $(LIBRARY)

.cc.o : $(SOURCES)
	$(CPP) $(CPPFLAGS) $(INCLUDES) $(SOURCES)

clean :
	rm -rf $(OBJECTS) $(TARGET) *~

debug : CPPFLAGS := -g -c -Wall -Werror -std=c++11
debug : $(TARGET)
	./$(TARGET)

release : CPPFLAGS := -O0 -c -Wall -Werror -std=c++11
release : $(TARGET)
	./$(TARGET)
