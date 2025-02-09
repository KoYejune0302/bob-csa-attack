CC = g++
CFLAGS = -Wall -std=c++11
LDFLAGS = -lpcap
TARGET = csa-attack

all: $(TARGET)

$(TARGET): csa_attack.o
	$(CC) $(CFLAGS) -o $(TARGET) csa_attack.o $(LDFLAGS)

csa_attack.o: csa_attack.cpp csa_attack.h
	$(CC) $(CFLAGS) -c csa_attack.cpp

clean:
	rm -f *.o $(TARGET)
