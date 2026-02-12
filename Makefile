# X-VRF Makefile
CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall
LDFLAGS = -lssl -lcrypto

SRCS = main.cpp hash_utils.cpp prg.cpp wots.cpp xmss_core.cpp simple_xmss.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = xvrf

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
