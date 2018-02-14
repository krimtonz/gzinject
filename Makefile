gzinject: gzinject.o aes.o sha1.o md5.o
	gcc gzinject.o aes.o sha1.o md5.o -o gzinject

gzinject.o: 
	gcc -c -O3 gzinject.c -o gzinject.o

aes.o:
	gcc -c -O3 aes.c -o aes.o

sha1.o: 
	gcc -c -O3 sha1.c -o sha1.o

md5.o: 
	gcc -c O3 md5.c -o md5.o

install: gzinject
	install gzinject /usr/bin

clean:
	rm -rf gzinject.o aes.o sha1.o gzinject