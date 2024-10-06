#!/bin/sh

set -eu

gcc -ggdb -static -nostdlib -ffreestanding -O0 ./main.c -o ./linux-x86-64
./linux-x86-64
