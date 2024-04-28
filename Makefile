all:
	gcc -c sha512.c -o sha512.o -O3
	gcc -c encrypt.c -o encrypt.o -O3
	gcc -c hexenc.c -o hexenc.o -O3
	gcc -c evlt.c -o evlt.o -O3 -lpthread
	gcc main.c -o evlt -O3 -lpthread sha512.o encrypt.o hexenc.o evlt.o 
clean:
	rm -rf *.o evlt
install:
	mkdir -p ~/bin 2>/dev/null
	cp evlt ~/bin/
uninstall:
	rm ~/bin/evlt
