#source: tls.s
#as: -a64
#ld: -melf64ppc tmpdir/libtlslib.so
#objdump: -dr
#target: powerpc64*-*-*

.*: +file format elf64-powerpc

Disassembly of section \.text:

.* <00000010\.plt_call\.__tls_get_addr(|_opt)\+0>:
.*	e9 63 00 00 	ld      r11,0\(r3\)
.*	e9 83 00 08 	ld      r12,8\(r3\)
.*	7c 60 1b 78 	mr      r0,r3
.*	2c 2b 00 00 	cmpdi   r11,0
.*	7c 6c 6a 14 	add     r3,r12,r13
.*	4d 82 00 20 	beqlr   
.*	7c 03 03 78 	mr      r3,r0
.*	7d 68 02 a6 	mflr    r11
.*	f9 61 00 20 	std     r11,32\(r1\)
.*	f8 41 00 28 	std     r2,40\(r1\)
.*	e9 62 80 48 	ld      r11,-32696\(r2\)
.*	7d 69 03 a6 	mtctr   r11
.*	e8 42 80 50 	ld      r2,-32688\(r2\)
.*	4e 80 04 21 	bctrl
.*	e9 61 00 20 	ld      r11,32\(r1\)
.*	e8 41 00 28 	ld      r2,40\(r1\)
.*	7d 68 03 a6 	mtlr    r11
.*	4e 80 00 20 	blr

.* <_start>:
.*	e8 62 80 10 	ld      r3,-32752\(r2\)
.*	60 00 00 00 	nop
.*	7c 63 6a 14 	add     r3,r3,r13
.*	38 62 80 18 	addi    r3,r2,-32744
.*	4b ff ff a9 	bl      .*
.*	60 00 00 00 	nop
.*	3c 6d 00 00 	addis   r3,r13,0
.*	60 00 00 00 	nop
.*	38 63 90 38 	addi    r3,r3,-28616
.*	3c 6d 00 00 	addis   r3,r13,0
.*	60 00 00 00 	nop
.*	38 63 10 00 	addi    r3,r3,4096
.*	39 23 80 40 	addi    r9,r3,-32704
.*	3d 23 00 00 	addis   r9,r3,0
.*	81 49 80 48 	lwz     r10,-32696\(r9\)
.*	e9 22 80 28 	ld      r9,-32728\(r2\)
.*	7d 49 18 2a 	ldx     r10,r9,r3
.*	3d 2d 00 00 	addis   r9,r13,0
.*	a1 49 90 58 	lhz     r10,-28584\(r9\)
.*	89 4d 90 60 	lbz     r10,-28576\(r13\)
.*	3d 2d 00 00 	addis   r9,r13,0
.*	99 49 90 68 	stb     r10,-28568\(r9\)
.*	3c 6d 00 00 	addis   r3,r13,0
.*	60 00 00 00 	nop
.*	38 63 90 00 	addi    r3,r3,-28672
.*	3c 6d 00 00 	addis   r3,r13,0
.*	60 00 00 00 	nop
.*	38 63 10 00 	addi    r3,r3,4096
.*	f9 43 80 08 	std     r10,-32760\(r3\)
.*	3d 23 00 00 	addis   r9,r3,0
.*	91 49 80 10 	stw     r10,-32752\(r9\)
.*	e9 22 80 08 	ld      r9,-32760\(r2\)
.*	7d 49 19 2a 	stdx    r10,r9,r3
.*	3d 2d 00 00 	addis   r9,r13,0
.*	b1 49 90 58 	sth     r10,-28584\(r9\)
.*	e9 4d 90 2a 	lwa     r10,-28632\(r13\)
.*	3d 2d 00 00 	addis   r9,r13,0
.*	a9 49 90 30 	lha     r10,-28624\(r9\)
.*	00 00 00 00 .*
.*	00 01 02 00 .*
.* <__glink_PLTresolve>:
.*	7d 88 02 a6 	mflr    r12
.*	42 9f 00 05 	bcl-    20,4\*cr7\+so,.*
.*	7d 68 02 a6 	mflr    r11
.*	e8 4b ff f0 	ld      r2,-16\(r11\)
.*	7d 88 03 a6 	mtlr    r12
.*	7d 82 5a 14 	add     r12,r2,r11
.*	e9 6c 00 00 	ld      r11,0\(r12\)
.*	e8 4c 00 08 	ld      r2,8\(r12\)
.*	7d 69 03 a6 	mtctr   r11
.*	e9 6c 00 10 	ld      r11,16\(r12\)
.*	4e 80 04 20 	bctr
.*	60 00 00 00 	nop
.*	60 00 00 00 	nop
.*	60 00 00 00 	nop
.*	38 00 00 00 	li      r0,0
.*	4b ff ff c4 	b       .*
