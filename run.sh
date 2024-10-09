#!/bin/sh

set -eu

gcc -static -nostdlib -ffreestanding -O3 ./entry_x86_64.s ./main.c -o ./linux-x86-64
./linux-x86-64 $@
