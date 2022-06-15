#!/bin/bash

set -eu

make

./main --help

./main --create test1.txt private.pem

./main --verify cert.pem

./main --encrypt cert.pem TEST_FILE TEST_FILE.enc

./main --decrypt private.pem TEST_FILE.enc TEST_FILE.dec

echo
echo "----------------------------"
cat TEST_FILE
echo
echo "----------------------------"
cat TEST_FILE.enc
echo
echo "----------------------------"
cat TEST_FILE.dec
echo "----------------------------"
