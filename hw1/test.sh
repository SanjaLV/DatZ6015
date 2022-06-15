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
