#!/bin/bash
rm -rf ~/.evlt
make clean && make main
echo PUT
cat 128b.txt | ./evlt put /test/test1 -v -m master -b 1 -n 1
echo
ls -ltr ~/.evlt
echo
echo GET
./evlt get /test/test1 -v -m master -b 1 -n 1
rm -rf ~/.evlt
echo
echo PUT
echo voor | ./evlt put /test/test1 -v -m master -b 64 -n 32
echo
echo APPEND 1
echo midden | ./evlt append /test/test1 -v -m master -b 64 -n 32
echo
echo APPEND 2
echo achter | ./evlt append /test/test1 -v -m master -b 64 -n 32
echo
echo GET
./evlt get /test/test1 -v -m master -b 64 -n 32
echo
ls -ltr ~/.evlt
rm -rf ~/.evlt
