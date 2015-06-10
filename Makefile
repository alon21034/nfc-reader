main: nfc-utils.o mifare.o crypto1.o 
	gcc -o test nfc-utils.o crypto1.o mifare.o nfc-mfclassic.c -lnfc
	sh compile.sh

nfc-utils.o:
	gcc -o nfc-utils.o -c nfc-utils.c

mifare.o:
	gcc -o mifare.o -c mifare.c

crypto1.o:
	gcc -o crypto1.o -c crypto1.c

clean:
	rm *.o
	rm test
