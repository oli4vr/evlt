#!/bin/bash
#
SEG=32
CNT=64
BS=4M
make
rm -rf ~/.evlt 
echo
echo "####Performance"
echo
dd if=/dev/zero bs=$BS count=$CNT | ./evlt put /myvault/key1/key2/key3 -n $SEG -v
./evlt get /myvault/key1/key2/key3 -n $SEG -v | dd of=/dev/null bs=$BS
dd if=/dev/zero bs=$BS count=$CNT | ./evlt put /myvault/key1/key2/key4 -n $SEG -v
./evlt get /myvault/key1/key2/key4 -n $SEG -v | dd of=/dev/null bs=$BS
rm -rf ~/.evlt 

echo
echo
echo "####Consistency"
echo
cat 8MB.txt | sum | xargs echo "#### CHKSUM1"
./evlt put /test/k1/k2/k3 -n $SEG -v <8MB.txt
./evlt get /test/k1/k2/k3 -n $SEG -v | sum | xargs echo "#### CHKSUM2"
rm -rf ~/.evlt 
