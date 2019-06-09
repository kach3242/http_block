all: http_block

http_block: http_block.o
	g++ -o http_block http_block.o -lpcap

http_block.o: http_block.c
	g++ -c -o http_block.o http_block.c

clean:
	rm -f *.o http_block

