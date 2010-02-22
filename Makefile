CC=gcc -ggdb

all: cerom

bysin-linux: cerom.o
	$(CC) -o cerom -linux cerom.c

clean:
	rm -rf cerom
