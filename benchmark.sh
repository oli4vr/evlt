#!/bin/bash
#
SEG=32
CNT=64
BS=4M
VPATH=~/.evlt
if [ "$1" != "" ]
then
 VPATH=$1
fi
make clean && make main
rm -rf $VPATH/*.evlt
echo
echo "####Init"
echo
echo init | ./evlt put init 
echo
echo "####Performance"
echo
echo "####First data blob write $CNT * $BS"
time dd if=/dev/zero bs=$BS count=$CNT | ./evlt put /myvault/key1/key2/key3 -n $SEG -v -d $VPATH -m master
echo
echo "####First data blob read $CNT * $BS"
time ./evlt get /myvault/key1/key2/key3 -n $SEG -v -d $VPATH -m master | dd of=/dev/null bs=$BS
echo
echo "####Second data blob add $CNT * $BS"
time dd if=/dev/zero bs=$BS count=$CNT | ./evlt put /myvault/key1/key2/key4 -n $SEG -v -d $VPATH -m master
echo
echo "####Second data blob read $CNT * $BS"
time ./evlt get /myvault/key1/key2/key4 -n $SEG -v -d $VPATH -m master | dd of=/dev/null bs=$BS
echo
echo "####Add small blob"
time dd if=/dev/zero bs=4M count=1 | ./evlt put /myvault/key1/key2/key5 -n $SEG -v -d $VPATH -m master
echo
echo "####Get small blob"
time ./evlt get /myvault/key1/key2/key5 -n $SEG -v -d $VPATH -m master | dd of=/dev/null bs=$BS
echo
ls -ltr $VPATH/*.evlt
echo
echo
echo "####Consistency"
echo
cat 8MB.txt | sum | xargs echo "#### CHKSUM1"
time ./evlt put /myvault/k1/k2/k3 -n $SEG -v -d $VPATH -m master <8MB.txt
time ./evlt get /myvault/k1/k2/k3 -n $SEG -v -d $VPATH -m master | sum | xargs echo "#### CHKSUM2"
echo
ls -ltr $VPATH/*.evlt
rm -rf $VPATH/*.evlt
