all: arpmitm

arpmitm: main.o
	g++ -g -o arpmitm main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f *.o
	rm -f arpmitm

reall: clean all