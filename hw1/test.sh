#!/bin/bash

set -eu

./main --help

./main --encrypt key.txt TEST TEST.enc

./main --decrypt key.txt TEST.enc TEST.dec

echo "--------------------------"
cat TEST
echo
echo "--------------------------"
echo
cat TEST.enc
echo
echo "--------------------------"
cat TEST.dec
echo
echo "--------------------------"


echo "RUNING CFG enc"

./main --encrypt key.txt TEST TEST.cfb.enc key.txt

echo "RUNING CFG dec"

./main --decrypt key.txt TEST.cfb.enc TEST.cfb.dec key.txt

echo "--------------------------"
cat TEST
echo
echo "--------------------------"
echo
cat TEST.cfb.enc
echo
echo "--------------------------"
cat TEST.cfb.dec
echo
echo "--------------------------"

./main --generate key2.enc

cat key2.enc

echo "RUNING CFG enc"

./main --encrypt key2.enc TEST TEST.cfb.enc key.txt

echo "SHOULD FAIL SINCE PASSING WRONG SIGNATURE KEY FOR CMAC!!!!!!!!!!!!!!!"

./main --decrypt key2.enc TEST.cfb.enc TEST.cfb.dec key2.enc

echo "NOW SHOULD BE OK!!!!!!!!!!!!!!!"

./main --decrypt key2.enc TEST.cfb.enc TEST.cfb.dec key.txt
