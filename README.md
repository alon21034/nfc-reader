nfc-reader
==========

for thesis

gcc -o test -lnfc \*.c

sudo apt-get install libusb-dev
sudo apt-get install autoconf
sudo apt-get install libtool
wget https://bintray.com/artifact/download/nfc-tools/sources/libnfc-1.7.1.tar.bz2
tar -xvzf \*.bz2
autoreconf -is
./configure
make
sudo make install
