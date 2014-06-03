num=`sudo launchctl list | grep pcscd | grep '^[0-9]\+' -o -m1`
sudo kill $num
