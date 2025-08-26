PREFIX=$(HOME)
CC=g++
AR=ar

CCFLAGS= -Wall -I/opt/homebrew/Cellar/ntl/11.5.1/include/ -I/opt/homebrew/Cellar/gmp/6.3.0/include/ -std=gnu++0x -Ofast 
LDFLAGS= -L/opt/homebrew/Cellar/ntl/11.5.1/lib/ -L/opt/homebrew/Cellar/gmp/6.3.0/lib/ -lntl -lgmp 

SRCS=$(wildcard *.cc)
OBJS=$(SRCS:.cc=.o)

.PHONY: all clean mrproper

all: IBE

IBE: $(OBJS)
	$(CC) $(CCFLAGS) -o IBE $(OBJS) $(LDFLAGS)

%.o: %.cc params.h
	$(CC) $(CCFLAGS) -c $< 

clean:
	rm -f *.o

mrproper:
	rm -f IBE
