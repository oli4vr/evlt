#!/bin/bash
rm -rf ~/.evlt
make clean && make main
echo PUT
cat 128b.txt | ./evlt put /test/test1 -v -m master -b 64 -n 1
echo
ls -ltr ~/.evlt
echo
echo GET
./evlt get /test/test1 -v -m master -b 64 -n 1
