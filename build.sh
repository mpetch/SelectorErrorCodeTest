nasm -f bin stage2.asm -o stage2.bin
nasm -DWITH_BPB -f bin boot.asm -o disk.img

