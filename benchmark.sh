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
echo "####First data blob write $CNT * $BS"
time dd if=/dev/zero bs=$BS count=$CNT | ./evlt put /myvault/key1/key2/key3 -n $SEG -v
echo
echo "####First data blob read $CNT * $BS"
time ./evlt get /myvault/key1/key2/key3 -n $SEG -v | dd of=/dev/null bs=$BS
echo
echo "####Second data blob add $CNT * $BS"
time dd if=/dev/zero bs=$BS count=$CNT | ./evlt put /myvault/key1/key2/key4 -n $SEG -v
echo
echo "####Second data blob read $CNT * $BS"
time ./evlt get /myvault/key1/key2/key4 -n $SEG -v | dd of=/dev/null bs=$BS
echo
echo "####Add small blob"
time dd if=/dev/zero bs=4M count=1 | ./evlt put /myvault/key1/key2/key5 -n $SEG -v
echo
echo "####Get small blob"
time ./evlt get /myvault/key1/key2/key5 -n $SEG -v | dd of=/dev/null bs=$BS
echo
ls -ltr ~/.evlt/*.evlt
echo
echo
echo "####Consistency"
echo
cat 8MB.txt | sum | xargs echo "#### CHKSUM1"
time ./evlt put /myvault/k1/k2/k3 -n $SEG -v <8MB.txt
time ./evlt get /myvault/k1/k2/k3 -n $SEG -v | sum | xargs echo "#### CHKSUM2"
echo
ls -ltr ~/.evlt/*.evlt
rm -rf ~/.evlt 
