#!/bin/sh

set -eu

gcc -static -nostdlib -O3 ./main.c -o ./linux-x86-64
./linux-x86-64
