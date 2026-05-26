CXX = g++
CXXFLAGS = -Wall -O2 -std=c++17
LDLIBS = -lpcap

TARGET = tcp-block
SRCS = main.cpp

all: $(TARGET)

$(TARGET): $(SRCS) ansheader.h
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LDLIBS)

clean:
	rm -f $(TARGET)
