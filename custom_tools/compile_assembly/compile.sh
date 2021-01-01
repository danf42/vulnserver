#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

if test -f $1.o; then 

    echo '[+] Linking ...'
    ld -o $1 $1.o

    if test -f $1; then
        
        echo "[+] Creating Shellcode"
        objdump -d $1 |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' > $1.txt

        echo "[+] Disassembling Executable"
        objdump -d -M intel $1 > $1.dis

        echo "[+] Check for null bytes"
        count=`grep -c \\x00 $1.txt`
        
        if test $count -gt 0; then
            echo "[-] null bytes found in shellcode"       
        else
            echo "[+] No null bytes found..."
            echo
            cat $1.txt
            echo
        fi
 
        echo '[+] Done!'
    fi

else
    echo '[-] Error compiling assembly code'

fi



