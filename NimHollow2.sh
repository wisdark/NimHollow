#!/usr/bin/env bash

cd NimlineWhispers2

cat << 'EOT' > functions.txt
NtQueryInformationProcess
NtReadVirtualMemory
NtProtectVirtualMemory
NtWriteVirtualMemory
NtResumeThread
NtClose
EOT

python3 NimlineWhispers2.py --randomise > /dev/null
mv syscalls.nim ../syscalls.nim
