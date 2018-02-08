gzinject: gzinject.o aes.o sha1.o
	gcc gzinject.o aes.o sha1.o -o gzinject

gzinject.o: 
	gcc -O3 gzinject.c -o gzinject.o

aes.o:
	gcc -O3 aes.c -o aes.o

sha1.o: 
	gcc -O3 sha1.c -o sha1.o

clean:
	rm -rf gzinject.o aes.o sha1.o gzinject