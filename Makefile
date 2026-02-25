# X-VRF Makefile
CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall

# Use pkg-config for OpenSSL (works on Linux, macOS, BSD, etc.)
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

CXXFLAGS += $(OPENSSL_CFLAGS)
LDFLAGS = $(OPENSSL_LIBS)

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
