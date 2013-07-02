# Author: Emilia Käsper and Peter Schwabe
# Date: 2009-03-19
# +2010.01.31: minor namespace modifications
# Public domain

.data
.p2align 6

RCON: .int 0x00000000, 0x00000000, 0x00000000, 0xffffffff
ROTB: .int 0x0c000000, 0x00000000, 0x04000000, 0x08000000
EXPB0: .int 0x03030303, 0x07070707, 0x0b0b0b0b, 0x0f0f0f0f
CTRINC1: .int 0x00000001, 0x00000000, 0x00000000, 0x00000000
CTRINC2: .int 0x00000002, 0x00000000, 0x00000000, 0x00000000
CTRINC3: .int 0x00000003, 0x00000000, 0x00000000, 0x00000000
CTRINC4: .int 0x00000004, 0x00000000, 0x00000000, 0x00000000
CTRINC5: .int 0x00000005, 0x00000000, 0x00000000, 0x00000000
CTRINC6: .int 0x00000006, 0x00000000, 0x00000000, 0x00000000
CTRINC7: .int 0x00000007, 0x00000000, 0x00000000, 0x00000000
RCTRINC1: .int 0x00000000, 0x00000000, 0x00000000, 0x00000001
RCTRINC2: .int 0x00000000, 0x00000000, 0x00000000, 0x00000002
RCTRINC3: .int 0x00000000, 0x00000000, 0x00000000, 0x00000003
RCTRINC4: .int 0x00000000, 0x00000000, 0x00000000, 0x00000004
RCTRINC5: .int 0x00000000, 0x00000000, 0x00000000, 0x00000005
RCTRINC6: .int 0x00000000, 0x00000000, 0x00000000, 0x00000006
RCTRINC7: .int 0x00000000, 0x00000000, 0x00000000, 0x00000007

SWAP32: .int 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f
M0SWAP: .quad 0x0105090d0004080c , 0x03070b0f02060a0e

BS0: .quad 0x5555555555555555, 0x5555555555555555
BS1: .quad 0x3333333333333333, 0x3333333333333333
BS2: .quad 0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f
ONE: .quad 0xffffffffffffffff, 0xffffffffffffffff
M0:  .quad 0x02060a0e03070b0f, 0x0004080c0105090d
SRM0:	.quad 0x0304090e00050a0f, 0x01060b0c0207080d
SR: .quad 0x0504070600030201, 0x0f0e0d0c0a09080b

# qhasm: int64 arg1

# qhasm: int64 arg2

# qhasm: input arg1

# qhasm: input arg2

# qhasm: int64 r11_caller

# qhasm: int64 r12_caller

# qhasm: int64 r13_caller

# qhasm: int64 r14_caller

# qhasm: int64 r15_caller

# qhasm: int64 rbx_caller

# qhasm: int64 rbp_caller

# qhasm: caller r11_caller

# qhasm: caller r12_caller

# qhasm: caller r13_caller

# qhasm: caller r14_caller

# qhasm: caller r15_caller

# qhasm: caller rbx_caller

# qhasm: caller rbp_caller

# qhasm: int64 sboxp

# qhasm: int64 c

# qhasm: int64 k

# qhasm: int64 x0

# qhasm: int64 x1

# qhasm: int64 x2

# qhasm: int64 x3

# qhasm: int64 e

# qhasm: int64 q0

# qhasm: int64 q1

# qhasm: int64 q2

# qhasm: int64 q3

# qhasm: int6464 xmm0

# qhasm: int6464 xmm1

# qhasm: int6464 xmm2

# qhasm: int6464 xmm3

# qhasm: int6464 xmm4

# qhasm: int6464 xmm5

# qhasm: int6464 xmm6

# qhasm: int6464 xmm7

# qhasm: int6464 xmm8

# qhasm: int6464 xmm9

# qhasm: int6464 xmm10

# qhasm: int6464 xmm11

# qhasm: int6464 xmm12

# qhasm: int6464 xmm13

# qhasm: int6464 xmm14

# qhasm: int6464 xmm15

# qhasm: int6464 t

# qhasm: enter crypto_stream_aes128ctr_core2_beforenm
.text
.p2align 5
.globl _crypto_stream_aes128ctr_core2_beforenm
.globl crypto_stream_aes128ctr_core2_beforenm
_crypto_stream_aes128ctr_core2_beforenm:
crypto_stream_aes128ctr_core2_beforenm:
mov %rsp,%r11
and $31,%r11
add $0,%r11
sub %r11,%rsp

# qhasm: c = arg1
# asm 1: mov  <arg1=int64#1,>c=int64#1
# asm 2: mov  <arg1=%rdi,>c=%rdi
mov  %rdi,%rdi

# qhasm: k = arg2
# asm 1: mov  <arg2=int64#2,>k=int64#2
# asm 2: mov  <arg2=%rsi,>k=%rsi
mov  %rsi,%rsi

# qhasm:   xmm0 = *(int128 *) (k + 0)
# asm 1: movdqa 0(<k=int64#2),>xmm0=int6464#1
# asm 2: movdqa 0(<k=%rsi),>xmm0=%xmm0
movdqa 0(%rsi),%xmm0

# qhasm:   shuffle bytes of xmm0 by M0
# asm 1: pshufb M0,<xmm0=int6464#1
# asm 2: pshufb M0,<xmm0=%xmm0
pshufb M0,%xmm0

# qhasm:   xmm1 = xmm0
# asm 1: movdqa <xmm0=int6464#1,>xmm1=int6464#2
# asm 2: movdqa <xmm0=%xmm0,>xmm1=%xmm1
movdqa %xmm0,%xmm1

# qhasm:   xmm2 = xmm0
# asm 1: movdqa <xmm0=int6464#1,>xmm2=int6464#3
# asm 2: movdqa <xmm0=%xmm0,>xmm2=%xmm2
movdqa %xmm0,%xmm2

# qhasm:   xmm3 = xmm0
# asm 1: movdqa <xmm0=int6464#1,>xmm3=int6464#4
# asm 2: movdqa <xmm0=%xmm0,>xmm3=%xmm3
movdqa %xmm0,%xmm3

# qhasm:   xmm4 = xmm0
# asm 1: movdqa <xmm0=int6464#1,>xmm4=int6464#5
# asm 2: movdqa <xmm0=%xmm0,>xmm4=%xmm4
movdqa %xmm0,%xmm4

# qhasm:   xmm5 = xmm0
# asm 1: movdqa <xmm0=int6464#1,>xmm5=int6464#6
# asm 2: movdqa <xmm0=%xmm0,>xmm5=%xmm5
movdqa %xmm0,%xmm5

# qhasm:   xmm6 = xmm0
# asm 1: movdqa <xmm0=int6464#1,>xmm6=int6464#7
# asm 2: movdqa <xmm0=%xmm0,>xmm6=%xmm6
movdqa %xmm0,%xmm6

# qhasm:   xmm7 = xmm0
# asm 1: movdqa <xmm0=int6464#1,>xmm7=int6464#8
# asm 2: movdqa <xmm0=%xmm0,>xmm7=%xmm7
movdqa %xmm0,%xmm7

# qhasm:       t = xmm6
# asm 1: movdqa <xmm6=int6464#7,>t=int6464#9
# asm 2: movdqa <xmm6=%xmm6,>t=%xmm8
movdqa %xmm6,%xmm8

# qhasm:       uint6464 t >>= 1
# asm 1: psrlq $1,<t=int6464#9
# asm 2: psrlq $1,<t=%xmm8
psrlq $1,%xmm8

# qhasm:       t ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<t=int6464#9
# asm 2: pxor  <xmm7=%xmm7,<t=%xmm8
pxor  %xmm7,%xmm8

# qhasm:       t &= BS0
# asm 1: pand  BS0,<t=int6464#9
# asm 2: pand  BS0,<t=%xmm8
pand  BS0,%xmm8

# qhasm:       xmm7 ^= t
# asm 1: pxor  <t=int6464#9,<xmm7=int6464#8
# asm 2: pxor  <t=%xmm8,<xmm7=%xmm7
pxor  %xmm8,%xmm7

# qhasm:       uint6464 t <<= 1
# asm 1: psllq $1,<t=int6464#9
# asm 2: psllq $1,<t=%xmm8
psllq $1,%xmm8

# qhasm:       xmm6 ^= t
# asm 1: pxor  <t=int6464#9,<xmm6=int6464#7
# asm 2: pxor  <t=%xmm8,<xmm6=%xmm6
pxor  %xmm8,%xmm6

# qhasm:       t = xmm4
# asm 1: movdqa <xmm4=int6464#5,>t=int6464#9
# asm 2: movdqa <xmm4=%xmm4,>t=%xmm8
movdqa %xmm4,%xmm8

# qhasm:       uint6464 t >>= 1
# asm 1: psrlq $1,<t=int6464#9
# asm 2: psrlq $1,<t=%xmm8
psrlq $1,%xmm8

# qhasm:       t ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<t=int6464#9
# asm 2: pxor  <xmm5=%xmm5,<t=%xmm8
pxor  %xmm5,%xmm8

# qhasm:       t &= BS0
# asm 1: pand  BS0,<t=int6464#9
# asm 2: pand  BS0,<t=%xmm8
pand  BS0,%xmm8

# qhasm:       xmm5 ^= t
# asm 1: pxor  <t=int6464#9,<xmm5=int6464#6
# asm 2: pxor  <t=%xmm8,<xmm5=%xmm5
pxor  %xmm8,%xmm5

# qhasm:       uint6464 t <<= 1
# asm 1: psllq $1,<t=int6464#9
# asm 2: psllq $1,<t=%xmm8
psllq $1,%xmm8

# qhasm:       xmm4 ^= t
# asm 1: pxor  <t=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <t=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:       t = xmm2
# asm 1: movdqa <xmm2=int6464#3,>t=int6464#9
# asm 2: movdqa <xmm2=%xmm2,>t=%xmm8
movdqa %xmm2,%xmm8

# qhasm:       uint6464 t >>= 1
# asm 1: psrlq $1,<t=int6464#9
# asm 2: psrlq $1,<t=%xmm8
psrlq $1,%xmm8

# qhasm:       t ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<t=int6464#9
# asm 2: pxor  <xmm3=%xmm3,<t=%xmm8
pxor  %xmm3,%xmm8

# qhasm:       t &= BS0
# asm 1: pand  BS0,<t=int6464#9
# asm 2: pand  BS0,<t=%xmm8
pand  BS0,%xmm8

# qhasm:       xmm3 ^= t
# asm 1: pxor  <t=int6464#9,<xmm3=int6464#4
# asm 2: pxor  <t=%xmm8,<xmm3=%xmm3
pxor  %xmm8,%xmm3

# qhasm:       uint6464 t <<= 1
# asm 1: psllq $1,<t=int6464#9
# asm 2: psllq $1,<t=%xmm8
psllq $1,%xmm8

# qhasm:       xmm2 ^= t
# asm 1: pxor  <t=int6464#9,<xmm2=int6464#3
# asm 2: pxor  <t=%xmm8,<xmm2=%xmm2
pxor  %xmm8,%xmm2

# qhasm:       t = xmm0
# asm 1: movdqa <xmm0=int6464#1,>t=int6464#9
# asm 2: movdqa <xmm0=%xmm0,>t=%xmm8
movdqa %xmm0,%xmm8

# qhasm:       uint6464 t >>= 1
# asm 1: psrlq $1,<t=int6464#9
# asm 2: psrlq $1,<t=%xmm8
psrlq $1,%xmm8

# qhasm:       t ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<t=int6464#9
# asm 2: pxor  <xmm1=%xmm1,<t=%xmm8
pxor  %xmm1,%xmm8

# qhasm:       t &= BS0
# asm 1: pand  BS0,<t=int6464#9
# asm 2: pand  BS0,<t=%xmm8
pand  BS0,%xmm8

# qhasm:       xmm1 ^= t
# asm 1: pxor  <t=int6464#9,<xmm1=int6464#2
# asm 2: pxor  <t=%xmm8,<xmm1=%xmm1
pxor  %xmm8,%xmm1

# qhasm:       uint6464 t <<= 1
# asm 1: psllq $1,<t=int6464#9
# asm 2: psllq $1,<t=%xmm8
psllq $1,%xmm8

# qhasm:       xmm0 ^= t
# asm 1: pxor  <t=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <t=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:       t = xmm5
# asm 1: movdqa <xmm5=int6464#6,>t=int6464#9
# asm 2: movdqa <xmm5=%xmm5,>t=%xmm8
movdqa %xmm5,%xmm8

# qhasm:       uint6464 t >>= 2
# asm 1: psrlq $2,<t=int6464#9
# asm 2: psrlq $2,<t=%xmm8
psrlq $2,%xmm8

# qhasm:       t ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<t=int6464#9
# asm 2: pxor  <xmm7=%xmm7,<t=%xmm8
pxor  %xmm7,%xmm8

# qhasm:       t &= BS1
# asm 1: pand  BS1,<t=int6464#9
# asm 2: pand  BS1,<t=%xmm8
pand  BS1,%xmm8

# qhasm:       xmm7 ^= t
# asm 1: pxor  <t=int6464#9,<xmm7=int6464#8
# asm 2: pxor  <t=%xmm8,<xmm7=%xmm7
pxor  %xmm8,%xmm7

# qhasm:       uint6464 t <<= 2
# asm 1: psllq $2,<t=int6464#9
# asm 2: psllq $2,<t=%xmm8
psllq $2,%xmm8

# qhasm:       xmm5 ^= t
# asm 1: pxor  <t=int6464#9,<xmm5=int6464#6
# asm 2: pxor  <t=%xmm8,<xmm5=%xmm5
pxor  %xmm8,%xmm5

# qhasm:       t = xmm4
# asm 1: movdqa <xmm4=int6464#5,>t=int6464#9
# asm 2: movdqa <xmm4=%xmm4,>t=%xmm8
movdqa %xmm4,%xmm8

# qhasm:       uint6464 t >>= 2
# asm 1: psrlq $2,<t=int6464#9
# asm 2: psrlq $2,<t=%xmm8
psrlq $2,%xmm8

# qhasm:       t ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<t=int6464#9
# asm 2: pxor  <xmm6=%xmm6,<t=%xmm8
pxor  %xmm6,%xmm8

# qhasm:       t &= BS1
# asm 1: pand  BS1,<t=int6464#9
# asm 2: pand  BS1,<t=%xmm8
pand  BS1,%xmm8

# qhasm:       xmm6 ^= t
# asm 1: pxor  <t=int6464#9,<xmm6=int6464#7
# asm 2: pxor  <t=%xmm8,<xmm6=%xmm6
pxor  %xmm8,%xmm6

# qhasm:       uint6464 t <<= 2
# asm 1: psllq $2,<t=int6464#9
# asm 2: psllq $2,<t=%xmm8
psllq $2,%xmm8

# qhasm:       xmm4 ^= t
# asm 1: pxor  <t=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <t=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:       t = xmm1
# asm 1: movdqa <xmm1=int6464#2,>t=int6464#9
# asm 2: movdqa <xmm1=%xmm1,>t=%xmm8
movdqa %xmm1,%xmm8

# qhasm:       uint6464 t >>= 2
# asm 1: psrlq $2,<t=int6464#9
# asm 2: psrlq $2,<t=%xmm8
psrlq $2,%xmm8

# qhasm:       t ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<t=int6464#9
# asm 2: pxor  <xmm3=%xmm3,<t=%xmm8
pxor  %xmm3,%xmm8

# qhasm:       t &= BS1
# asm 1: pand  BS1,<t=int6464#9
# asm 2: pand  BS1,<t=%xmm8
pand  BS1,%xmm8

# qhasm:       xmm3 ^= t
# asm 1: pxor  <t=int6464#9,<xmm3=int6464#4
# asm 2: pxor  <t=%xmm8,<xmm3=%xmm3
pxor  %xmm8,%xmm3

# qhasm:       uint6464 t <<= 2
# asm 1: psllq $2,<t=int6464#9
# asm 2: psllq $2,<t=%xmm8
psllq $2,%xmm8

# qhasm:       xmm1 ^= t
# asm 1: pxor  <t=int6464#9,<xmm1=int6464#2
# asm 2: pxor  <t=%xmm8,<xmm1=%xmm1
pxor  %xmm8,%xmm1

# qhasm:       t = xmm0
# asm 1: movdqa <xmm0=int6464#1,>t=int6464#9
# asm 2: movdqa <xmm0=%xmm0,>t=%xmm8
movdqa %xmm0,%xmm8

# qhasm:       uint6464 t >>= 2
# asm 1: psrlq $2,<t=int6464#9
# asm 2: psrlq $2,<t=%xmm8
psrlq $2,%xmm8

# qhasm:       t ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<t=int6464#9
# asm 2: pxor  <xmm2=%xmm2,<t=%xmm8
pxor  %xmm2,%xmm8

# qhasm:       t &= BS1
# asm 1: pand  BS1,<t=int6464#9
# asm 2: pand  BS1,<t=%xmm8
pand  BS1,%xmm8

# qhasm:       xmm2 ^= t
# asm 1: pxor  <t=int6464#9,<xmm2=int6464#3
# asm 2: pxor  <t=%xmm8,<xmm2=%xmm2
pxor  %xmm8,%xmm2

# qhasm:       uint6464 t <<= 2
# asm 1: psllq $2,<t=int6464#9
# asm 2: psllq $2,<t=%xmm8
psllq $2,%xmm8

# qhasm:       xmm0 ^= t
# asm 1: pxor  <t=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <t=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:       t = xmm3
# asm 1: movdqa <xmm3=int6464#4,>t=int6464#9
# asm 2: movdqa <xmm3=%xmm3,>t=%xmm8
movdqa %xmm3,%xmm8

# qhasm:       uint6464 t >>= 4
# asm 1: psrlq $4,<t=int6464#9
# asm 2: psrlq $4,<t=%xmm8
psrlq $4,%xmm8

# qhasm:       t ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<t=int6464#9
# asm 2: pxor  <xmm7=%xmm7,<t=%xmm8
pxor  %xmm7,%xmm8

# qhasm:       t &= BS2
# asm 1: pand  BS2,<t=int6464#9
# asm 2: pand  BS2,<t=%xmm8
pand  BS2,%xmm8

# qhasm:       xmm7 ^= t
# asm 1: pxor  <t=int6464#9,<xmm7=int6464#8
# asm 2: pxor  <t=%xmm8,<xmm7=%xmm7
pxor  %xmm8,%xmm7

# qhasm:       uint6464 t <<= 4
# asm 1: psllq $4,<t=int6464#9
# asm 2: psllq $4,<t=%xmm8
psllq $4,%xmm8

# qhasm:       xmm3 ^= t
# asm 1: pxor  <t=int6464#9,<xmm3=int6464#4
# asm 2: pxor  <t=%xmm8,<xmm3=%xmm3
pxor  %xmm8,%xmm3

# qhasm:       t = xmm2
# asm 1: movdqa <xmm2=int6464#3,>t=int6464#9
# asm 2: movdqa <xmm2=%xmm2,>t=%xmm8
movdqa %xmm2,%xmm8

# qhasm:       uint6464 t >>= 4
# asm 1: psrlq $4,<t=int6464#9
# asm 2: psrlq $4,<t=%xmm8
psrlq $4,%xmm8

# qhasm:       t ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<t=int6464#9
# asm 2: pxor  <xmm6=%xmm6,<t=%xmm8
pxor  %xmm6,%xmm8

# qhasm:       t &= BS2
# asm 1: pand  BS2,<t=int6464#9
# asm 2: pand  BS2,<t=%xmm8
pand  BS2,%xmm8

# qhasm:       xmm6 ^= t
# asm 1: pxor  <t=int6464#9,<xmm6=int6464#7
# asm 2: pxor  <t=%xmm8,<xmm6=%xmm6
pxor  %xmm8,%xmm6

# qhasm:       uint6464 t <<= 4
# asm 1: psllq $4,<t=int6464#9
# asm 2: psllq $4,<t=%xmm8
psllq $4,%xmm8

# qhasm:       xmm2 ^= t
# asm 1: pxor  <t=int6464#9,<xmm2=int6464#3
# asm 2: pxor  <t=%xmm8,<xmm2=%xmm2
pxor  %xmm8,%xmm2

# qhasm:       t = xmm1
# asm 1: movdqa <xmm1=int6464#2,>t=int6464#9
# asm 2: movdqa <xmm1=%xmm1,>t=%xmm8
movdqa %xmm1,%xmm8

# qhasm:       uint6464 t >>= 4
# asm 1: psrlq $4,<t=int6464#9
# asm 2: psrlq $4,<t=%xmm8
psrlq $4,%xmm8

# qhasm:       t ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<t=int6464#9
# asm 2: pxor  <xmm5=%xmm5,<t=%xmm8
pxor  %xmm5,%xmm8

# qhasm:       t &= BS2
# asm 1: pand  BS2,<t=int6464#9
# asm 2: pand  BS2,<t=%xmm8
pand  BS2,%xmm8

# qhasm:       xmm5 ^= t
# asm 1: pxor  <t=int6464#9,<xmm5=int6464#6
# asm 2: pxor  <t=%xmm8,<xmm5=%xmm5
pxor  %xmm8,%xmm5

# qhasm:       uint6464 t <<= 4
# asm 1: psllq $4,<t=int6464#9
# asm 2: psllq $4,<t=%xmm8
psllq $4,%xmm8

# qhasm:       xmm1 ^= t
# asm 1: pxor  <t=int6464#9,<xmm1=int6464#2
# asm 2: pxor  <t=%xmm8,<xmm1=%xmm1
pxor  %xmm8,%xmm1

# qhasm:       t = xmm0
# asm 1: movdqa <xmm0=int6464#1,>t=int6464#9
# asm 2: movdqa <xmm0=%xmm0,>t=%xmm8
movdqa %xmm0,%xmm8

# qhasm:       uint6464 t >>= 4
# asm 1: psrlq $4,<t=int6464#9
# asm 2: psrlq $4,<t=%xmm8
psrlq $4,%xmm8

# qhasm:       t ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<t=int6464#9
# asm 2: pxor  <xmm4=%xmm4,<t=%xmm8
pxor  %xmm4,%xmm8

# qhasm:       t &= BS2
# asm 1: pand  BS2,<t=int6464#9
# asm 2: pand  BS2,<t=%xmm8
pand  BS2,%xmm8

# qhasm:       xmm4 ^= t
# asm 1: pxor  <t=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <t=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:       uint6464 t <<= 4
# asm 1: psllq $4,<t=int6464#9
# asm 2: psllq $4,<t=%xmm8
psllq $4,%xmm8

# qhasm:       xmm0 ^= t
# asm 1: pxor  <t=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <t=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   *(int128 *) (c + 0) = xmm0
# asm 1: movdqa <xmm0=int6464#1,0(<c=int64#1)
# asm 2: movdqa <xmm0=%xmm0,0(<c=%rdi)
movdqa %xmm0,0(%rdi)

# qhasm:   *(int128 *) (c + 16) = xmm1
# asm 1: movdqa <xmm1=int6464#2,16(<c=int64#1)
# asm 2: movdqa <xmm1=%xmm1,16(<c=%rdi)
movdqa %xmm1,16(%rdi)

# qhasm:   *(int128 *) (c + 32) = xmm2
# asm 1: movdqa <xmm2=int6464#3,32(<c=int64#1)
# asm 2: movdqa <xmm2=%xmm2,32(<c=%rdi)
movdqa %xmm2,32(%rdi)

# qhasm:   *(int128 *) (c + 48) = xmm3
# asm 1: movdqa <xmm3=int6464#4,48(<c=int64#1)
# asm 2: movdqa <xmm3=%xmm3,48(<c=%rdi)
movdqa %xmm3,48(%rdi)

# qhasm:   *(int128 *) (c + 64) = xmm4
# asm 1: movdqa <xmm4=int6464#5,64(<c=int64#1)
# asm 2: movdqa <xmm4=%xmm4,64(<c=%rdi)
movdqa %xmm4,64(%rdi)

# qhasm:   *(int128 *) (c + 80) = xmm5
# asm 1: movdqa <xmm5=int6464#6,80(<c=int64#1)
# asm 2: movdqa <xmm5=%xmm5,80(<c=%rdi)
movdqa %xmm5,80(%rdi)

# qhasm:   *(int128 *) (c + 96) = xmm6
# asm 1: movdqa <xmm6=int6464#7,96(<c=int64#1)
# asm 2: movdqa <xmm6=%xmm6,96(<c=%rdi)
movdqa %xmm6,96(%rdi)

# qhasm:   *(int128 *) (c + 112) = xmm7
# asm 1: movdqa <xmm7=int6464#8,112(<c=int64#1)
# asm 2: movdqa <xmm7=%xmm7,112(<c=%rdi)
movdqa %xmm7,112(%rdi)

# qhasm:     shuffle bytes of xmm0 by ROTB
# asm 1: pshufb ROTB,<xmm0=int6464#1
# asm 2: pshufb ROTB,<xmm0=%xmm0
pshufb ROTB,%xmm0

# qhasm:     shuffle bytes of xmm1 by ROTB
# asm 1: pshufb ROTB,<xmm1=int6464#2
# asm 2: pshufb ROTB,<xmm1=%xmm1
pshufb ROTB,%xmm1

# qhasm:     shuffle bytes of xmm2 by ROTB
# asm 1: pshufb ROTB,<xmm2=int6464#3
# asm 2: pshufb ROTB,<xmm2=%xmm2
pshufb ROTB,%xmm2

# qhasm:     shuffle bytes of xmm3 by ROTB
# asm 1: pshufb ROTB,<xmm3=int6464#4
# asm 2: pshufb ROTB,<xmm3=%xmm3
pshufb ROTB,%xmm3

# qhasm:     shuffle bytes of xmm4 by ROTB
# asm 1: pshufb ROTB,<xmm4=int6464#5
# asm 2: pshufb ROTB,<xmm4=%xmm4
pshufb ROTB,%xmm4

# qhasm:     shuffle bytes of xmm5 by ROTB
# asm 1: pshufb ROTB,<xmm5=int6464#6
# asm 2: pshufb ROTB,<xmm5=%xmm5
pshufb ROTB,%xmm5

# qhasm:     shuffle bytes of xmm6 by ROTB
# asm 1: pshufb ROTB,<xmm6=int6464#7
# asm 2: pshufb ROTB,<xmm6=%xmm6
pshufb ROTB,%xmm6

# qhasm:     shuffle bytes of xmm7 by ROTB
# asm 1: pshufb ROTB,<xmm7=int6464#8
# asm 2: pshufb ROTB,<xmm7=%xmm7
pshufb ROTB,%xmm7

# qhasm:       xmm5 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm5=int6464#6
# asm 2: pxor  <xmm6=%xmm6,<xmm5=%xmm5
pxor  %xmm6,%xmm5

# qhasm:       xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm1,<xmm2=%xmm2
pxor  %xmm1,%xmm2

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm5=int6464#6
# asm 2: pxor  <xmm0=%xmm0,<xmm5=%xmm5
pxor  %xmm0,%xmm5

# qhasm:       xmm6 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm6=int6464#7
# asm 2: pxor  <xmm2=%xmm2,<xmm6=%xmm6
pxor  %xmm2,%xmm6

# qhasm:       xmm3 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm3=int6464#4
# asm 2: pxor  <xmm0=%xmm0,<xmm3=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm6=int6464#7
# asm 2: pxor  <xmm3=%xmm3,<xmm6=%xmm6
pxor  %xmm3,%xmm6

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:       xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm3=int6464#4
# asm 2: pxor  <xmm4=%xmm4,<xmm3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:       xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm7=int6464#8
# asm 2: pxor  <xmm5=%xmm5,<xmm7=%xmm7
pxor  %xmm5,%xmm7

# qhasm:       xmm3 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm3=int6464#4
# asm 2: pxor  <xmm1=%xmm1,<xmm3=%xmm3
pxor  %xmm1,%xmm3

# qhasm:       xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm1=int6464#2
# asm 2: pxor  <xmm5=%xmm5,<xmm1=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm11 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm11=int6464#9
# asm 2: movdqa <xmm7=%xmm7,>xmm11=%xmm8
movdqa %xmm7,%xmm8

# qhasm:       xmm10 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm10=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm10=%xmm9
movdqa %xmm1,%xmm9

# qhasm:       xmm9 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm9=int6464#11
# asm 2: movdqa <xmm5=%xmm5,>xmm9=%xmm10
movdqa %xmm5,%xmm10

# qhasm:       xmm13 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm13=int6464#12
# asm 2: movdqa <xmm2=%xmm2,>xmm13=%xmm11
movdqa %xmm2,%xmm11

# qhasm:       xmm12 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm12=int6464#13
# asm 2: movdqa <xmm6=%xmm6,>xmm12=%xmm12
movdqa %xmm6,%xmm12

# qhasm:       xmm11 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm11=int6464#9
# asm 2: pxor  <xmm4=%xmm4,<xmm11=%xmm8
pxor  %xmm4,%xmm8

# qhasm:       xmm10 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm10=int6464#10
# asm 2: pxor  <xmm2=%xmm2,<xmm10=%xmm9
pxor  %xmm2,%xmm9

# qhasm:       xmm9 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm9=int6464#11
# asm 2: pxor  <xmm3=%xmm3,<xmm9=%xmm10
pxor  %xmm3,%xmm10

# qhasm:       xmm13 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm13=int6464#12
# asm 2: pxor  <xmm4=%xmm4,<xmm13=%xmm11
pxor  %xmm4,%xmm11

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:       xmm14 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm14=int6464#14
# asm 2: movdqa <xmm11=%xmm8,>xmm14=%xmm13
movdqa %xmm8,%xmm13

# qhasm:       xmm8 = xmm10
# asm 1: movdqa <xmm10=int6464#10,>xmm8=int6464#15
# asm 2: movdqa <xmm10=%xmm9,>xmm8=%xmm14
movdqa %xmm9,%xmm14

# qhasm:       xmm15 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm15=int6464#16
# asm 2: movdqa <xmm11=%xmm8,>xmm15=%xmm15
movdqa %xmm8,%xmm15

# qhasm:       xmm10 |= xmm9
# asm 1: por   <xmm9=int6464#11,<xmm10=int6464#10
# asm 2: por   <xmm9=%xmm10,<xmm10=%xmm9
por   %xmm10,%xmm9

# qhasm:       xmm11 |= xmm12
# asm 1: por   <xmm12=int6464#13,<xmm11=int6464#9
# asm 2: por   <xmm12=%xmm12,<xmm11=%xmm8
por   %xmm12,%xmm8

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm15=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm14 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm14=int6464#14
# asm 2: pand  <xmm12=%xmm12,<xmm14=%xmm13
pand  %xmm12,%xmm13

# qhasm:       xmm8 &= xmm9
# asm 1: pand  <xmm9=int6464#11,<xmm8=int6464#15
# asm 2: pand  <xmm9=%xmm10,<xmm8=%xmm14
pand  %xmm10,%xmm14

# qhasm:       xmm12 ^= xmm9
# asm 1: pxor  <xmm9=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm9=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:       xmm15 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm15=int6464#16
# asm 2: pand  <xmm12=%xmm12,<xmm15=%xmm15
pand  %xmm12,%xmm15

# qhasm:       xmm12 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm12=int6464#11
# asm 2: movdqa <xmm3=%xmm3,>xmm12=%xmm10
movdqa %xmm3,%xmm10

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#11
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm10
pxor  %xmm0,%xmm10

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#11,<xmm13=int6464#12
# asm 2: pand  <xmm12=%xmm10,<xmm13=%xmm11
pand  %xmm10,%xmm11

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm11=int6464#9
# asm 2: pxor  <xmm13=%xmm11,<xmm11=%xmm8
pxor  %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm13 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm13=int6464#11
# asm 2: movdqa <xmm7=%xmm7,>xmm13=%xmm10
movdqa %xmm7,%xmm10

# qhasm:       xmm13 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm13=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm13=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm12 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm12=int6464#12
# asm 2: movdqa <xmm5=%xmm5,>xmm12=%xmm11
movdqa %xmm5,%xmm11

# qhasm:       xmm9 = xmm13
# asm 1: movdqa <xmm13=int6464#11,>xmm9=int6464#13
# asm 2: movdqa <xmm13=%xmm10,>xmm9=%xmm12
movdqa %xmm10,%xmm12

# qhasm:       xmm12 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm12=int6464#12
# asm 2: pxor  <xmm6=%xmm6,<xmm12=%xmm11
pxor  %xmm6,%xmm11

# qhasm:       xmm9 |= xmm12
# asm 1: por   <xmm12=int6464#12,<xmm9=int6464#13
# asm 2: por   <xmm12=%xmm11,<xmm9=%xmm12
por   %xmm11,%xmm12

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#12,<xmm13=int6464#11
# asm 2: pand  <xmm12=%xmm11,<xmm13=%xmm10
pand  %xmm11,%xmm10

# qhasm:       xmm8 ^= xmm13
# asm 1: pxor  <xmm13=int6464#11,<xmm8=int6464#15
# asm 2: pxor  <xmm13=%xmm10,<xmm8=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#9
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm10=int6464#10
# asm 2: pxor  <xmm14=%xmm13,<xmm10=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm9 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm8 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm8=int6464#15
# asm 2: pxor  <xmm14=%xmm13,<xmm8=%xmm14
pxor  %xmm13,%xmm14

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm12 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm12=int6464#11
# asm 2: movdqa <xmm2=%xmm2,>xmm12=%xmm10
movdqa %xmm2,%xmm10

# qhasm:       xmm13 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm13=int6464#12
# asm 2: movdqa <xmm4=%xmm4,>xmm13=%xmm11
movdqa %xmm4,%xmm11

# qhasm:       xmm14 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm14=int6464#14
# asm 2: movdqa <xmm1=%xmm1,>xmm14=%xmm13
movdqa %xmm1,%xmm13

# qhasm:       xmm15 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm15=int6464#16
# asm 2: movdqa <xmm7=%xmm7,>xmm15=%xmm15
movdqa %xmm7,%xmm15

# qhasm:       xmm12 &= xmm3
# asm 1: pand  <xmm3=int6464#4,<xmm12=int6464#11
# asm 2: pand  <xmm3=%xmm3,<xmm12=%xmm10
pand  %xmm3,%xmm10

# qhasm:       xmm13 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm13=int6464#12
# asm 2: pand  <xmm0=%xmm0,<xmm13=%xmm11
pand  %xmm0,%xmm11

# qhasm:       xmm14 &= xmm5
# asm 1: pand  <xmm5=int6464#6,<xmm14=int6464#14
# asm 2: pand  <xmm5=%xmm5,<xmm14=%xmm13
pand  %xmm5,%xmm13

# qhasm:       xmm15 |= xmm6
# asm 1: por   <xmm6=int6464#7,<xmm15=int6464#16
# asm 2: por   <xmm6=%xmm6,<xmm15=%xmm15
por   %xmm6,%xmm15

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm11=int6464#9
# asm 2: pxor  <xmm12=%xmm10,<xmm11=%xmm8
pxor  %xmm10,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm8 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm8=int6464#15
# asm 2: pxor  <xmm15=%xmm15,<xmm8=%xmm14
pxor  %xmm15,%xmm14

# qhasm:       xmm12 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm12=int6464#11
# asm 2: movdqa <xmm11=%xmm8,>xmm12=%xmm10
movdqa %xmm8,%xmm10

# qhasm:       xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm12=int6464#11
# asm 2: pxor  <xmm10=%xmm9,<xmm12=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm11 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm11=int6464#9
# asm 2: pand  <xmm9=%xmm12,<xmm11=%xmm8
pand  %xmm12,%xmm8

# qhasm:       xmm14 = xmm8
# asm 1: movdqa <xmm8=int6464#15,>xmm14=int6464#12
# asm 2: movdqa <xmm8=%xmm14,>xmm14=%xmm11
movdqa %xmm14,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm11=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm15 = xmm12
# asm 1: movdqa <xmm12=int6464#11,>xmm15=int6464#14
# asm 2: movdqa <xmm12=%xmm10,>xmm15=%xmm13
movdqa %xmm10,%xmm13

# qhasm:       xmm15 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm15=int6464#14
# asm 2: pand  <xmm14=%xmm11,<xmm15=%xmm13
pand  %xmm11,%xmm13

# qhasm:       xmm15 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm15=int6464#14
# asm 2: pxor  <xmm10=%xmm9,<xmm15=%xmm13
pxor  %xmm9,%xmm13

# qhasm:       xmm13 = xmm9
# asm 1: movdqa <xmm9=int6464#13,>xmm13=int6464#16
# asm 2: movdqa <xmm9=%xmm12,>xmm13=%xmm15
movdqa %xmm12,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm11 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm11=int6464#9
# asm 2: pxor  <xmm10=%xmm9,<xmm11=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm13 &= xmm11
# asm 1: pand  <xmm11=int6464#9,<xmm13=int6464#16
# asm 2: pand  <xmm11=%xmm8,<xmm13=%xmm15
pand  %xmm8,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm13=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm10 = xmm14
# asm 1: movdqa <xmm14=int6464#12,>xmm10=int6464#9
# asm 2: movdqa <xmm14=%xmm11,>xmm10=%xmm8
movdqa %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm10=int6464#9
# asm 2: pxor  <xmm13=%xmm15,<xmm10=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 &= xmm8
# asm 1: pand  <xmm8=int6464#15,<xmm10=int6464#9
# asm 2: pand  <xmm8=%xmm14,<xmm10=%xmm8
pand  %xmm14,%xmm8

# qhasm:       xmm9 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm9=int6464#13
# asm 2: pxor  <xmm10=%xmm8,<xmm9=%xmm12
pxor  %xmm8,%xmm12

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm10=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm14=int6464#12
# asm 2: pand  <xmm15=%xmm13,<xmm14=%xmm11
pand  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm14=int6464#12
# asm 2: pxor  <xmm12=%xmm10,<xmm14=%xmm11
pxor  %xmm10,%xmm11

# qhasm:         xmm12 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm12=int6464#9
# asm 2: movdqa <xmm6=%xmm6,>xmm12=%xmm8
movdqa %xmm6,%xmm8

# qhasm:         xmm8 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm8=int6464#10
# asm 2: movdqa <xmm5=%xmm5,>xmm8=%xmm9
movdqa %xmm5,%xmm9

# qhasm:           xmm10 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm10=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm10=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm10 &= xmm6
# asm 1: pand  <xmm6=int6464#7,<xmm10=int6464#11
# asm 2: pand  <xmm6=%xmm6,<xmm10=%xmm10
pand  %xmm6,%xmm10

# qhasm:           xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:           xmm6 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm6=int6464#7
# asm 2: pand  <xmm14=%xmm11,<xmm6=%xmm6
pand  %xmm11,%xmm6

# qhasm:           xmm5 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm5=int6464#6
# asm 2: pand  <xmm15=%xmm13,<xmm5=%xmm5
pand  %xmm13,%xmm5

# qhasm:           xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:           xmm5 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm5=int6464#6
# asm 2: pxor  <xmm10=%xmm10,<xmm5=%xmm5
pxor  %xmm10,%xmm5

# qhasm:         xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm8 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm8=int6464#10
# asm 2: pxor  <xmm3=%xmm3,<xmm8=%xmm9
pxor  %xmm3,%xmm9

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm10=int6464#11
# asm 2: pand  <xmm0=%xmm0,<xmm10=%xmm10
pand  %xmm0,%xmm10

# qhasm:           xmm0 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm0=int6464#1
# asm 2: pxor  <xmm3=%xmm3,<xmm0=%xmm0
pxor  %xmm3,%xmm0

# qhasm:           xmm0 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm0=int6464#1
# asm 2: pand  <xmm9=%xmm12,<xmm0=%xmm0
pand  %xmm12,%xmm0

# qhasm:           xmm3 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm3=int6464#4
# asm 2: pand  <xmm13=%xmm15,<xmm3=%xmm3
pand  %xmm15,%xmm3

# qhasm:           xmm0 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm0=int6464#1
# asm 2: pxor  <xmm3=%xmm3,<xmm0=%xmm0
pxor  %xmm3,%xmm0

# qhasm:           xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:         xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm8,<xmm6=%xmm6
pxor  %xmm8,%xmm6

# qhasm:         xmm0 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm12=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm5 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm5=int6464#6
# asm 2: pxor  <xmm8=%xmm9,<xmm5=%xmm5
pxor  %xmm9,%xmm5

# qhasm:         xmm3 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm3=int6464#4
# asm 2: pxor  <xmm8=%xmm9,<xmm3=%xmm3
pxor  %xmm9,%xmm3

# qhasm:         xmm12 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm12=int6464#9
# asm 2: movdqa <xmm7=%xmm7,>xmm12=%xmm8
movdqa %xmm7,%xmm8

# qhasm:         xmm8 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm8=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm8=%xmm9
movdqa %xmm1,%xmm9

# qhasm:         xmm12 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm12=int6464#9
# asm 2: pxor  <xmm4=%xmm4,<xmm12=%xmm8
pxor  %xmm4,%xmm8

# qhasm:         xmm8 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm8=int6464#10
# asm 2: pxor  <xmm2=%xmm2,<xmm8=%xmm9
pxor  %xmm2,%xmm9

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm10=int6464#11
# asm 2: pand  <xmm4=%xmm4,<xmm10=%xmm10
pand  %xmm4,%xmm10

# qhasm:           xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm2=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:           xmm4 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm4=int6464#5
# asm 2: pand  <xmm9=%xmm12,<xmm4=%xmm4
pand  %xmm12,%xmm4

# qhasm:           xmm2 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm2=int6464#3
# asm 2: pand  <xmm13=%xmm15,<xmm2=%xmm2
pand  %xmm15,%xmm2

# qhasm:           xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm2=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:           xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#3
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm2
pxor  %xmm10,%xmm2

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm7
# asm 1: pand  <xmm7=int6464#8,<xmm11=int6464#11
# asm 2: pand  <xmm7=%xmm7,<xmm11=%xmm10
pand  %xmm7,%xmm10

# qhasm:           xmm7 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm7=int6464#8
# asm 2: pxor  <xmm1=%xmm1,<xmm7=%xmm7
pxor  %xmm1,%xmm7

# qhasm:           xmm7 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm7=int6464#8
# asm 2: pand  <xmm14=%xmm11,<xmm7=%xmm7
pand  %xmm11,%xmm7

# qhasm:           xmm1 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm1=int6464#2
# asm 2: pand  <xmm15=%xmm13,<xmm1=%xmm1
pand  %xmm13,%xmm1

# qhasm:           xmm7 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm7=int6464#8
# asm 2: pxor  <xmm1=%xmm1,<xmm7=%xmm7
pxor  %xmm1,%xmm7

# qhasm:           xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm1=int6464#2
# asm 2: pxor  <xmm11=%xmm10,<xmm1=%xmm1
pxor  %xmm10,%xmm1

# qhasm:         xmm7 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm7=int6464#8
# asm 2: pxor  <xmm12=%xmm8,<xmm7=%xmm7
pxor  %xmm8,%xmm7

# qhasm:         xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <xmm12=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:         xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:         xmm2 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm2=int6464#3
# asm 2: pxor  <xmm8=%xmm9,<xmm2=%xmm2
pxor  %xmm9,%xmm2

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm0,<xmm7=%xmm7
pxor  %xmm0,%xmm7

# qhasm:       xmm1 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm1=int6464#2
# asm 2: pxor  <xmm6=%xmm6,<xmm1=%xmm1
pxor  %xmm6,%xmm1

# qhasm:       xmm4 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm4=int6464#5
# asm 2: pxor  <xmm7=%xmm7,<xmm4=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm6 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm6=int6464#7
# asm 2: pxor  <xmm0=%xmm0,<xmm6=%xmm6
pxor  %xmm0,%xmm6

# qhasm:       xmm0 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm0=int6464#1
# asm 2: pxor  <xmm1=%xmm1,<xmm0=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm1=int6464#2
# asm 2: pxor  <xmm5=%xmm5,<xmm1=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm5 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm5=int6464#6
# asm 2: pxor  <xmm2=%xmm2,<xmm5=%xmm5
pxor  %xmm2,%xmm5

# qhasm:       xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm2 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm2=int6464#3
# asm 2: pxor  <xmm3=%xmm3,<xmm2=%xmm2
pxor  %xmm3,%xmm2

# qhasm:       xmm3 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm3=int6464#4
# asm 2: pxor  <xmm5=%xmm5,<xmm3=%xmm3
pxor  %xmm5,%xmm3

# qhasm:       xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm6=int6464#7
# asm 2: pxor  <xmm3=%xmm3,<xmm6=%xmm6
pxor  %xmm3,%xmm6

# qhasm:   xmm0 ^= RCON
# asm 1: pxor  RCON,<xmm0=int6464#1
# asm 2: pxor  RCON,<xmm0=%xmm0
pxor  RCON,%xmm0

# qhasm:   shuffle bytes of xmm0 by EXPB0
# asm 1: pshufb EXPB0,<xmm0=int6464#1
# asm 2: pshufb EXPB0,<xmm0=%xmm0
pshufb EXPB0,%xmm0

# qhasm:   shuffle bytes of xmm1 by EXPB0
# asm 1: pshufb EXPB0,<xmm1=int6464#2
# asm 2: pshufb EXPB0,<xmm1=%xmm1
pshufb EXPB0,%xmm1

# qhasm:   shuffle bytes of xmm4 by EXPB0
# asm 1: pshufb EXPB0,<xmm4=int6464#5
# asm 2: pshufb EXPB0,<xmm4=%xmm4
pshufb EXPB0,%xmm4

# qhasm:   shuffle bytes of xmm6 by EXPB0
# asm 1: pshufb EXPB0,<xmm6=int6464#7
# asm 2: pshufb EXPB0,<xmm6=%xmm6
pshufb EXPB0,%xmm6

# qhasm:   shuffle bytes of xmm3 by EXPB0
# asm 1: pshufb EXPB0,<xmm3=int6464#4
# asm 2: pshufb EXPB0,<xmm3=%xmm3
pshufb EXPB0,%xmm3

# qhasm:   shuffle bytes of xmm7 by EXPB0
# asm 1: pshufb EXPB0,<xmm7=int6464#8
# asm 2: pshufb EXPB0,<xmm7=%xmm7
pshufb EXPB0,%xmm7

# qhasm:   shuffle bytes of xmm2 by EXPB0
# asm 1: pshufb EXPB0,<xmm2=int6464#3
# asm 2: pshufb EXPB0,<xmm2=%xmm2
pshufb EXPB0,%xmm2

# qhasm:   shuffle bytes of xmm5 by EXPB0
# asm 1: pshufb EXPB0,<xmm5=int6464#6
# asm 2: pshufb EXPB0,<xmm5=%xmm5
pshufb EXPB0,%xmm5

# qhasm:   xmm8 = *(int128 *)(c + 0)
# asm 1: movdqa 0(<c=int64#1),>xmm8=int6464#9
# asm 2: movdqa 0(<c=%rdi),>xmm8=%xmm8
movdqa 0(%rdi),%xmm8

# qhasm:   xmm9 = *(int128 *)(c + 16)
# asm 1: movdqa 16(<c=int64#1),>xmm9=int6464#10
# asm 2: movdqa 16(<c=%rdi),>xmm9=%xmm9
movdqa 16(%rdi),%xmm9

# qhasm:   xmm10 = *(int128 *)(c + 32)
# asm 1: movdqa 32(<c=int64#1),>xmm10=int6464#11
# asm 2: movdqa 32(<c=%rdi),>xmm10=%xmm10
movdqa 32(%rdi),%xmm10

# qhasm:   xmm11 = *(int128 *)(c + 48)
# asm 1: movdqa 48(<c=int64#1),>xmm11=int6464#12
# asm 2: movdqa 48(<c=%rdi),>xmm11=%xmm11
movdqa 48(%rdi),%xmm11

# qhasm:   xmm12 = *(int128 *)(c + 64)
# asm 1: movdqa 64(<c=int64#1),>xmm12=int6464#13
# asm 2: movdqa 64(<c=%rdi),>xmm12=%xmm12
movdqa 64(%rdi),%xmm12

# qhasm:   xmm13 = *(int128 *)(c + 80)
# asm 1: movdqa 80(<c=int64#1),>xmm13=int6464#14
# asm 2: movdqa 80(<c=%rdi),>xmm13=%xmm13
movdqa 80(%rdi),%xmm13

# qhasm:   xmm14 = *(int128 *)(c + 96)
# asm 1: movdqa 96(<c=int64#1),>xmm14=int6464#15
# asm 2: movdqa 96(<c=%rdi),>xmm14=%xmm14
movdqa 96(%rdi),%xmm14

# qhasm:   xmm15 = *(int128 *)(c + 112)
# asm 1: movdqa 112(<c=int64#1),>xmm15=int6464#16
# asm 2: movdqa 112(<c=%rdi),>xmm15=%xmm15
movdqa 112(%rdi),%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:   xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:   xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:   xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:   xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:   xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:   xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:   xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:   xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   *(int128 *)(c + 128) = xmm0
# asm 1: movdqa <xmm0=int6464#1,128(<c=int64#1)
# asm 2: movdqa <xmm0=%xmm0,128(<c=%rdi)
movdqa %xmm0,128(%rdi)

# qhasm:   *(int128 *)(c + 144) = xmm1
# asm 1: movdqa <xmm1=int6464#2,144(<c=int64#1)
# asm 2: movdqa <xmm1=%xmm1,144(<c=%rdi)
movdqa %xmm1,144(%rdi)

# qhasm:   *(int128 *)(c + 160) = xmm4
# asm 1: movdqa <xmm4=int6464#5,160(<c=int64#1)
# asm 2: movdqa <xmm4=%xmm4,160(<c=%rdi)
movdqa %xmm4,160(%rdi)

# qhasm:   *(int128 *)(c + 176) = xmm6
# asm 1: movdqa <xmm6=int6464#7,176(<c=int64#1)
# asm 2: movdqa <xmm6=%xmm6,176(<c=%rdi)
movdqa %xmm6,176(%rdi)

# qhasm:   *(int128 *)(c + 192) = xmm3
# asm 1: movdqa <xmm3=int6464#4,192(<c=int64#1)
# asm 2: movdqa <xmm3=%xmm3,192(<c=%rdi)
movdqa %xmm3,192(%rdi)

# qhasm:   *(int128 *)(c + 208) = xmm7
# asm 1: movdqa <xmm7=int6464#8,208(<c=int64#1)
# asm 2: movdqa <xmm7=%xmm7,208(<c=%rdi)
movdqa %xmm7,208(%rdi)

# qhasm:   *(int128 *)(c + 224) = xmm2
# asm 1: movdqa <xmm2=int6464#3,224(<c=int64#1)
# asm 2: movdqa <xmm2=%xmm2,224(<c=%rdi)
movdqa %xmm2,224(%rdi)

# qhasm:   *(int128 *)(c + 240) = xmm5
# asm 1: movdqa <xmm5=int6464#6,240(<c=int64#1)
# asm 2: movdqa <xmm5=%xmm5,240(<c=%rdi)
movdqa %xmm5,240(%rdi)

# qhasm:   xmm0 ^= ONE
# asm 1: pxor  ONE,<xmm0=int6464#1
# asm 2: pxor  ONE,<xmm0=%xmm0
pxor  ONE,%xmm0

# qhasm:   xmm1 ^= ONE
# asm 1: pxor  ONE,<xmm1=int6464#2
# asm 2: pxor  ONE,<xmm1=%xmm1
pxor  ONE,%xmm1

# qhasm:   xmm7 ^= ONE
# asm 1: pxor  ONE,<xmm7=int6464#8
# asm 2: pxor  ONE,<xmm7=%xmm7
pxor  ONE,%xmm7

# qhasm:   xmm2 ^= ONE
# asm 1: pxor  ONE,<xmm2=int6464#3
# asm 2: pxor  ONE,<xmm2=%xmm2
pxor  ONE,%xmm2

# qhasm:     shuffle bytes of xmm0 by ROTB
# asm 1: pshufb ROTB,<xmm0=int6464#1
# asm 2: pshufb ROTB,<xmm0=%xmm0
pshufb ROTB,%xmm0

# qhasm:     shuffle bytes of xmm1 by ROTB
# asm 1: pshufb ROTB,<xmm1=int6464#2
# asm 2: pshufb ROTB,<xmm1=%xmm1
pshufb ROTB,%xmm1

# qhasm:     shuffle bytes of xmm4 by ROTB
# asm 1: pshufb ROTB,<xmm4=int6464#5
# asm 2: pshufb ROTB,<xmm4=%xmm4
pshufb ROTB,%xmm4

# qhasm:     shuffle bytes of xmm6 by ROTB
# asm 1: pshufb ROTB,<xmm6=int6464#7
# asm 2: pshufb ROTB,<xmm6=%xmm6
pshufb ROTB,%xmm6

# qhasm:     shuffle bytes of xmm3 by ROTB
# asm 1: pshufb ROTB,<xmm3=int6464#4
# asm 2: pshufb ROTB,<xmm3=%xmm3
pshufb ROTB,%xmm3

# qhasm:     shuffle bytes of xmm7 by ROTB
# asm 1: pshufb ROTB,<xmm7=int6464#8
# asm 2: pshufb ROTB,<xmm7=%xmm7
pshufb ROTB,%xmm7

# qhasm:     shuffle bytes of xmm2 by ROTB
# asm 1: pshufb ROTB,<xmm2=int6464#3
# asm 2: pshufb ROTB,<xmm2=%xmm2
pshufb ROTB,%xmm2

# qhasm:     shuffle bytes of xmm5 by ROTB
# asm 1: pshufb ROTB,<xmm5=int6464#6
# asm 2: pshufb ROTB,<xmm5=%xmm5
pshufb ROTB,%xmm5

# qhasm:       xmm7 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm7=int6464#8
# asm 2: pxor  <xmm2=%xmm2,<xmm7=%xmm7
pxor  %xmm2,%xmm7

# qhasm:       xmm4 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm4=int6464#5
# asm 2: pxor  <xmm1=%xmm1,<xmm4=%xmm4
pxor  %xmm1,%xmm4

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm0,<xmm7=%xmm7
pxor  %xmm0,%xmm7

# qhasm:       xmm2 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm2=int6464#3
# asm 2: pxor  <xmm4=%xmm4,<xmm2=%xmm2
pxor  %xmm4,%xmm2

# qhasm:       xmm6 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm6=int6464#7
# asm 2: pxor  <xmm0=%xmm0,<xmm6=%xmm6
pxor  %xmm0,%xmm6

# qhasm:       xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm6,<xmm2=%xmm2
pxor  %xmm6,%xmm2

# qhasm:       xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:       xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm6=int6464#7
# asm 2: pxor  <xmm3=%xmm3,<xmm6=%xmm6
pxor  %xmm3,%xmm6

# qhasm:       xmm5 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm5=int6464#6
# asm 2: pxor  <xmm7=%xmm7,<xmm5=%xmm5
pxor  %xmm7,%xmm5

# qhasm:       xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm6=int6464#7
# asm 2: pxor  <xmm1=%xmm1,<xmm6=%xmm6
pxor  %xmm1,%xmm6

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:       xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#2
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm1
pxor  %xmm7,%xmm1

# qhasm:       xmm11 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm11=int6464#9
# asm 2: movdqa <xmm5=%xmm5,>xmm11=%xmm8
movdqa %xmm5,%xmm8

# qhasm:       xmm10 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm10=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm10=%xmm9
movdqa %xmm1,%xmm9

# qhasm:       xmm9 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm9=int6464#11
# asm 2: movdqa <xmm7=%xmm7,>xmm9=%xmm10
movdqa %xmm7,%xmm10

# qhasm:       xmm13 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm13=int6464#12
# asm 2: movdqa <xmm4=%xmm4,>xmm13=%xmm11
movdqa %xmm4,%xmm11

# qhasm:       xmm12 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm12=int6464#13
# asm 2: movdqa <xmm2=%xmm2,>xmm12=%xmm12
movdqa %xmm2,%xmm12

# qhasm:       xmm11 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm11=int6464#9
# asm 2: pxor  <xmm3=%xmm3,<xmm11=%xmm8
pxor  %xmm3,%xmm8

# qhasm:       xmm10 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm10=int6464#10
# asm 2: pxor  <xmm4=%xmm4,<xmm10=%xmm9
pxor  %xmm4,%xmm9

# qhasm:       xmm9 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm9=int6464#11
# asm 2: pxor  <xmm6=%xmm6,<xmm9=%xmm10
pxor  %xmm6,%xmm10

# qhasm:       xmm13 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm13=int6464#12
# asm 2: pxor  <xmm3=%xmm3,<xmm13=%xmm11
pxor  %xmm3,%xmm11

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:       xmm14 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm14=int6464#14
# asm 2: movdqa <xmm11=%xmm8,>xmm14=%xmm13
movdqa %xmm8,%xmm13

# qhasm:       xmm8 = xmm10
# asm 1: movdqa <xmm10=int6464#10,>xmm8=int6464#15
# asm 2: movdqa <xmm10=%xmm9,>xmm8=%xmm14
movdqa %xmm9,%xmm14

# qhasm:       xmm15 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm15=int6464#16
# asm 2: movdqa <xmm11=%xmm8,>xmm15=%xmm15
movdqa %xmm8,%xmm15

# qhasm:       xmm10 |= xmm9
# asm 1: por   <xmm9=int6464#11,<xmm10=int6464#10
# asm 2: por   <xmm9=%xmm10,<xmm10=%xmm9
por   %xmm10,%xmm9

# qhasm:       xmm11 |= xmm12
# asm 1: por   <xmm12=int6464#13,<xmm11=int6464#9
# asm 2: por   <xmm12=%xmm12,<xmm11=%xmm8
por   %xmm12,%xmm8

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm15=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm14 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm14=int6464#14
# asm 2: pand  <xmm12=%xmm12,<xmm14=%xmm13
pand  %xmm12,%xmm13

# qhasm:       xmm8 &= xmm9
# asm 1: pand  <xmm9=int6464#11,<xmm8=int6464#15
# asm 2: pand  <xmm9=%xmm10,<xmm8=%xmm14
pand  %xmm10,%xmm14

# qhasm:       xmm12 ^= xmm9
# asm 1: pxor  <xmm9=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm9=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:       xmm15 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm15=int6464#16
# asm 2: pand  <xmm12=%xmm12,<xmm15=%xmm15
pand  %xmm12,%xmm15

# qhasm:       xmm12 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm12=int6464#11
# asm 2: movdqa <xmm6=%xmm6,>xmm12=%xmm10
movdqa %xmm6,%xmm10

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#11
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm10
pxor  %xmm0,%xmm10

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#11,<xmm13=int6464#12
# asm 2: pand  <xmm12=%xmm10,<xmm13=%xmm11
pand  %xmm10,%xmm11

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm11=int6464#9
# asm 2: pxor  <xmm13=%xmm11,<xmm11=%xmm8
pxor  %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm13 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm13=int6464#11
# asm 2: movdqa <xmm5=%xmm5,>xmm13=%xmm10
movdqa %xmm5,%xmm10

# qhasm:       xmm13 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm13=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm13=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm12 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm12=int6464#12
# asm 2: movdqa <xmm7=%xmm7,>xmm12=%xmm11
movdqa %xmm7,%xmm11

# qhasm:       xmm9 = xmm13
# asm 1: movdqa <xmm13=int6464#11,>xmm9=int6464#13
# asm 2: movdqa <xmm13=%xmm10,>xmm9=%xmm12
movdqa %xmm10,%xmm12

# qhasm:       xmm12 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm12=int6464#12
# asm 2: pxor  <xmm2=%xmm2,<xmm12=%xmm11
pxor  %xmm2,%xmm11

# qhasm:       xmm9 |= xmm12
# asm 1: por   <xmm12=int6464#12,<xmm9=int6464#13
# asm 2: por   <xmm12=%xmm11,<xmm9=%xmm12
por   %xmm11,%xmm12

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#12,<xmm13=int6464#11
# asm 2: pand  <xmm12=%xmm11,<xmm13=%xmm10
pand  %xmm11,%xmm10

# qhasm:       xmm8 ^= xmm13
# asm 1: pxor  <xmm13=int6464#11,<xmm8=int6464#15
# asm 2: pxor  <xmm13=%xmm10,<xmm8=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#9
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm10=int6464#10
# asm 2: pxor  <xmm14=%xmm13,<xmm10=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm9 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm8 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm8=int6464#15
# asm 2: pxor  <xmm14=%xmm13,<xmm8=%xmm14
pxor  %xmm13,%xmm14

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm12 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm12=int6464#11
# asm 2: movdqa <xmm4=%xmm4,>xmm12=%xmm10
movdqa %xmm4,%xmm10

# qhasm:       xmm13 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm13=int6464#12
# asm 2: movdqa <xmm3=%xmm3,>xmm13=%xmm11
movdqa %xmm3,%xmm11

# qhasm:       xmm14 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm14=int6464#14
# asm 2: movdqa <xmm1=%xmm1,>xmm14=%xmm13
movdqa %xmm1,%xmm13

# qhasm:       xmm15 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm15=int6464#16
# asm 2: movdqa <xmm5=%xmm5,>xmm15=%xmm15
movdqa %xmm5,%xmm15

# qhasm:       xmm12 &= xmm6
# asm 1: pand  <xmm6=int6464#7,<xmm12=int6464#11
# asm 2: pand  <xmm6=%xmm6,<xmm12=%xmm10
pand  %xmm6,%xmm10

# qhasm:       xmm13 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm13=int6464#12
# asm 2: pand  <xmm0=%xmm0,<xmm13=%xmm11
pand  %xmm0,%xmm11

# qhasm:       xmm14 &= xmm7
# asm 1: pand  <xmm7=int6464#8,<xmm14=int6464#14
# asm 2: pand  <xmm7=%xmm7,<xmm14=%xmm13
pand  %xmm7,%xmm13

# qhasm:       xmm15 |= xmm2
# asm 1: por   <xmm2=int6464#3,<xmm15=int6464#16
# asm 2: por   <xmm2=%xmm2,<xmm15=%xmm15
por   %xmm2,%xmm15

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm11=int6464#9
# asm 2: pxor  <xmm12=%xmm10,<xmm11=%xmm8
pxor  %xmm10,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm8 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm8=int6464#15
# asm 2: pxor  <xmm15=%xmm15,<xmm8=%xmm14
pxor  %xmm15,%xmm14

# qhasm:       xmm12 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm12=int6464#11
# asm 2: movdqa <xmm11=%xmm8,>xmm12=%xmm10
movdqa %xmm8,%xmm10

# qhasm:       xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm12=int6464#11
# asm 2: pxor  <xmm10=%xmm9,<xmm12=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm11 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm11=int6464#9
# asm 2: pand  <xmm9=%xmm12,<xmm11=%xmm8
pand  %xmm12,%xmm8

# qhasm:       xmm14 = xmm8
# asm 1: movdqa <xmm8=int6464#15,>xmm14=int6464#12
# asm 2: movdqa <xmm8=%xmm14,>xmm14=%xmm11
movdqa %xmm14,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm11=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm15 = xmm12
# asm 1: movdqa <xmm12=int6464#11,>xmm15=int6464#14
# asm 2: movdqa <xmm12=%xmm10,>xmm15=%xmm13
movdqa %xmm10,%xmm13

# qhasm:       xmm15 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm15=int6464#14
# asm 2: pand  <xmm14=%xmm11,<xmm15=%xmm13
pand  %xmm11,%xmm13

# qhasm:       xmm15 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm15=int6464#14
# asm 2: pxor  <xmm10=%xmm9,<xmm15=%xmm13
pxor  %xmm9,%xmm13

# qhasm:       xmm13 = xmm9
# asm 1: movdqa <xmm9=int6464#13,>xmm13=int6464#16
# asm 2: movdqa <xmm9=%xmm12,>xmm13=%xmm15
movdqa %xmm12,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm11 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm11=int6464#9
# asm 2: pxor  <xmm10=%xmm9,<xmm11=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm13 &= xmm11
# asm 1: pand  <xmm11=int6464#9,<xmm13=int6464#16
# asm 2: pand  <xmm11=%xmm8,<xmm13=%xmm15
pand  %xmm8,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm13=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm10 = xmm14
# asm 1: movdqa <xmm14=int6464#12,>xmm10=int6464#9
# asm 2: movdqa <xmm14=%xmm11,>xmm10=%xmm8
movdqa %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm10=int6464#9
# asm 2: pxor  <xmm13=%xmm15,<xmm10=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 &= xmm8
# asm 1: pand  <xmm8=int6464#15,<xmm10=int6464#9
# asm 2: pand  <xmm8=%xmm14,<xmm10=%xmm8
pand  %xmm14,%xmm8

# qhasm:       xmm9 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm9=int6464#13
# asm 2: pxor  <xmm10=%xmm8,<xmm9=%xmm12
pxor  %xmm8,%xmm12

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm10=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm14=int6464#12
# asm 2: pand  <xmm15=%xmm13,<xmm14=%xmm11
pand  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm14=int6464#12
# asm 2: pxor  <xmm12=%xmm10,<xmm14=%xmm11
pxor  %xmm10,%xmm11

# qhasm:         xmm12 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm12=int6464#9
# asm 2: movdqa <xmm2=%xmm2,>xmm12=%xmm8
movdqa %xmm2,%xmm8

# qhasm:         xmm8 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm8=int6464#10
# asm 2: movdqa <xmm7=%xmm7,>xmm8=%xmm9
movdqa %xmm7,%xmm9

# qhasm:           xmm10 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm10=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm10=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm10 &= xmm2
# asm 1: pand  <xmm2=int6464#3,<xmm10=int6464#11
# asm 2: pand  <xmm2=%xmm2,<xmm10=%xmm10
pand  %xmm2,%xmm10

# qhasm:           xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:           xmm2 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm2=int6464#3
# asm 2: pand  <xmm14=%xmm11,<xmm2=%xmm2
pand  %xmm11,%xmm2

# qhasm:           xmm7 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm7=int6464#8
# asm 2: pand  <xmm15=%xmm13,<xmm7=%xmm7
pand  %xmm13,%xmm7

# qhasm:           xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:           xmm7 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm7=int6464#8
# asm 2: pxor  <xmm10=%xmm10,<xmm7=%xmm7
pxor  %xmm10,%xmm7

# qhasm:         xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm8 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm8=int6464#10
# asm 2: pxor  <xmm6=%xmm6,<xmm8=%xmm9
pxor  %xmm6,%xmm9

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm10=int6464#11
# asm 2: pand  <xmm0=%xmm0,<xmm10=%xmm10
pand  %xmm0,%xmm10

# qhasm:           xmm0 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm0=int6464#1
# asm 2: pxor  <xmm6=%xmm6,<xmm0=%xmm0
pxor  %xmm6,%xmm0

# qhasm:           xmm0 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm0=int6464#1
# asm 2: pand  <xmm9=%xmm12,<xmm0=%xmm0
pand  %xmm12,%xmm0

# qhasm:           xmm6 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm6=int6464#7
# asm 2: pand  <xmm13=%xmm15,<xmm6=%xmm6
pand  %xmm15,%xmm6

# qhasm:           xmm0 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm0=int6464#1
# asm 2: pxor  <xmm6=%xmm6,<xmm0=%xmm0
pxor  %xmm6,%xmm0

# qhasm:           xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:         xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm8,<xmm2=%xmm2
pxor  %xmm8,%xmm2

# qhasm:         xmm0 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm12=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm7 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm7=int6464#8
# asm 2: pxor  <xmm8=%xmm9,<xmm7=%xmm7
pxor  %xmm9,%xmm7

# qhasm:         xmm6 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm6=int6464#7
# asm 2: pxor  <xmm8=%xmm9,<xmm6=%xmm6
pxor  %xmm9,%xmm6

# qhasm:         xmm12 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm12=int6464#9
# asm 2: movdqa <xmm5=%xmm5,>xmm12=%xmm8
movdqa %xmm5,%xmm8

# qhasm:         xmm8 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm8=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm8=%xmm9
movdqa %xmm1,%xmm9

# qhasm:         xmm12 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm12=int6464#9
# asm 2: pxor  <xmm3=%xmm3,<xmm12=%xmm8
pxor  %xmm3,%xmm8

# qhasm:         xmm8 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm8=int6464#10
# asm 2: pxor  <xmm4=%xmm4,<xmm8=%xmm9
pxor  %xmm4,%xmm9

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm3
# asm 1: pand  <xmm3=int6464#4,<xmm10=int6464#11
# asm 2: pand  <xmm3=%xmm3,<xmm10=%xmm10
pand  %xmm3,%xmm10

# qhasm:           xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm3=int6464#4
# asm 2: pxor  <xmm4=%xmm4,<xmm3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm3 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm3=int6464#4
# asm 2: pand  <xmm9=%xmm12,<xmm3=%xmm3
pand  %xmm12,%xmm3

# qhasm:           xmm4 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm4=int6464#5
# asm 2: pand  <xmm13=%xmm15,<xmm4=%xmm4
pand  %xmm15,%xmm4

# qhasm:           xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm3=int6464#4
# asm 2: pxor  <xmm4=%xmm4,<xmm3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm5
# asm 1: pand  <xmm5=int6464#6,<xmm11=int6464#11
# asm 2: pand  <xmm5=%xmm5,<xmm11=%xmm10
pand  %xmm5,%xmm10

# qhasm:           xmm5 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm5=int6464#6
# asm 2: pxor  <xmm1=%xmm1,<xmm5=%xmm5
pxor  %xmm1,%xmm5

# qhasm:           xmm5 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm5=int6464#6
# asm 2: pand  <xmm14=%xmm11,<xmm5=%xmm5
pand  %xmm11,%xmm5

# qhasm:           xmm1 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm1=int6464#2
# asm 2: pand  <xmm15=%xmm13,<xmm1=%xmm1
pand  %xmm13,%xmm1

# qhasm:           xmm5 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm5=int6464#6
# asm 2: pxor  <xmm1=%xmm1,<xmm5=%xmm5
pxor  %xmm1,%xmm5

# qhasm:           xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm1=int6464#2
# asm 2: pxor  <xmm11=%xmm10,<xmm1=%xmm1
pxor  %xmm10,%xmm1

# qhasm:         xmm5 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm5=int6464#6
# asm 2: pxor  <xmm12=%xmm8,<xmm5=%xmm5
pxor  %xmm8,%xmm5

# qhasm:         xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm8,<xmm3=%xmm3
pxor  %xmm8,%xmm3

# qhasm:         xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:         xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm4=int6464#5
# asm 2: pxor  <xmm8=%xmm9,<xmm4=%xmm4
pxor  %xmm9,%xmm4

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm5=int6464#6
# asm 2: pxor  <xmm0=%xmm0,<xmm5=%xmm5
pxor  %xmm0,%xmm5

# qhasm:       xmm1 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm1=int6464#2
# asm 2: pxor  <xmm2=%xmm2,<xmm1=%xmm1
pxor  %xmm2,%xmm1

# qhasm:       xmm3 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm3=int6464#4
# asm 2: pxor  <xmm5=%xmm5,<xmm3=%xmm3
pxor  %xmm5,%xmm3

# qhasm:       xmm2 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm2=int6464#3
# asm 2: pxor  <xmm0=%xmm0,<xmm2=%xmm2
pxor  %xmm0,%xmm2

# qhasm:       xmm0 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm0=int6464#1
# asm 2: pxor  <xmm1=%xmm1,<xmm0=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#2
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm1
pxor  %xmm7,%xmm1

# qhasm:       xmm7 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm7=int6464#8
# asm 2: pxor  <xmm4=%xmm4,<xmm7=%xmm7
pxor  %xmm4,%xmm7

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:       xmm4 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm4=int6464#5
# asm 2: pxor  <xmm6=%xmm6,<xmm4=%xmm4
pxor  %xmm6,%xmm4

# qhasm:       xmm6 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm6=int6464#7
# asm 2: pxor  <xmm7=%xmm7,<xmm6=%xmm6
pxor  %xmm7,%xmm6

# qhasm:       xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm6,<xmm2=%xmm2
pxor  %xmm6,%xmm2

# qhasm:   xmm1 ^= RCON
# asm 1: pxor  RCON,<xmm1=int6464#2
# asm 2: pxor  RCON,<xmm1=%xmm1
pxor  RCON,%xmm1

# qhasm:   shuffle bytes of xmm0 by EXPB0
# asm 1: pshufb EXPB0,<xmm0=int6464#1
# asm 2: pshufb EXPB0,<xmm0=%xmm0
pshufb EXPB0,%xmm0

# qhasm:   shuffle bytes of xmm1 by EXPB0
# asm 1: pshufb EXPB0,<xmm1=int6464#2
# asm 2: pshufb EXPB0,<xmm1=%xmm1
pshufb EXPB0,%xmm1

# qhasm:   shuffle bytes of xmm3 by EXPB0
# asm 1: pshufb EXPB0,<xmm3=int6464#4
# asm 2: pshufb EXPB0,<xmm3=%xmm3
pshufb EXPB0,%xmm3

# qhasm:   shuffle bytes of xmm2 by EXPB0
# asm 1: pshufb EXPB0,<xmm2=int6464#3
# asm 2: pshufb EXPB0,<xmm2=%xmm2
pshufb EXPB0,%xmm2

# qhasm:   shuffle bytes of xmm6 by EXPB0
# asm 1: pshufb EXPB0,<xmm6=int6464#7
# asm 2: pshufb EXPB0,<xmm6=%xmm6
pshufb EXPB0,%xmm6

# qhasm:   shuffle bytes of xmm5 by EXPB0
# asm 1: pshufb EXPB0,<xmm5=int6464#6
# asm 2: pshufb EXPB0,<xmm5=%xmm5
pshufb EXPB0,%xmm5

# qhasm:   shuffle bytes of xmm4 by EXPB0
# asm 1: pshufb EXPB0,<xmm4=int6464#5
# asm 2: pshufb EXPB0,<xmm4=%xmm4
pshufb EXPB0,%xmm4

# qhasm:   shuffle bytes of xmm7 by EXPB0
# asm 1: pshufb EXPB0,<xmm7=int6464#8
# asm 2: pshufb EXPB0,<xmm7=%xmm7
pshufb EXPB0,%xmm7

# qhasm:   xmm8 = *(int128 *)(c + 128)
# asm 1: movdqa 128(<c=int64#1),>xmm8=int6464#9
# asm 2: movdqa 128(<c=%rdi),>xmm8=%xmm8
movdqa 128(%rdi),%xmm8

# qhasm:   xmm9 = *(int128 *)(c + 144)
# asm 1: movdqa 144(<c=int64#1),>xmm9=int6464#10
# asm 2: movdqa 144(<c=%rdi),>xmm9=%xmm9
movdqa 144(%rdi),%xmm9

# qhasm:   xmm10 = *(int128 *)(c + 160)
# asm 1: movdqa 160(<c=int64#1),>xmm10=int6464#11
# asm 2: movdqa 160(<c=%rdi),>xmm10=%xmm10
movdqa 160(%rdi),%xmm10

# qhasm:   xmm11 = *(int128 *)(c + 176)
# asm 1: movdqa 176(<c=int64#1),>xmm11=int6464#12
# asm 2: movdqa 176(<c=%rdi),>xmm11=%xmm11
movdqa 176(%rdi),%xmm11

# qhasm:   xmm12 = *(int128 *)(c + 192)
# asm 1: movdqa 192(<c=int64#1),>xmm12=int6464#13
# asm 2: movdqa 192(<c=%rdi),>xmm12=%xmm12
movdqa 192(%rdi),%xmm12

# qhasm:   xmm13 = *(int128 *)(c + 208)
# asm 1: movdqa 208(<c=int64#1),>xmm13=int6464#14
# asm 2: movdqa 208(<c=%rdi),>xmm13=%xmm13
movdqa 208(%rdi),%xmm13

# qhasm:   xmm14 = *(int128 *)(c + 224)
# asm 1: movdqa 224(<c=int64#1),>xmm14=int6464#15
# asm 2: movdqa 224(<c=%rdi),>xmm14=%xmm14
movdqa 224(%rdi),%xmm14

# qhasm:   xmm15 = *(int128 *)(c + 240)
# asm 1: movdqa 240(<c=int64#1),>xmm15=int6464#16
# asm 2: movdqa 240(<c=%rdi),>xmm15=%xmm15
movdqa 240(%rdi),%xmm15

# qhasm:   xmm8 ^= ONE
# asm 1: pxor  ONE,<xmm8=int6464#9
# asm 2: pxor  ONE,<xmm8=%xmm8
pxor  ONE,%xmm8

# qhasm:   xmm9 ^= ONE
# asm 1: pxor  ONE,<xmm9=int6464#10
# asm 2: pxor  ONE,<xmm9=%xmm9
pxor  ONE,%xmm9

# qhasm:   xmm13 ^= ONE
# asm 1: pxor  ONE,<xmm13=int6464#14
# asm 2: pxor  ONE,<xmm13=%xmm13
pxor  ONE,%xmm13

# qhasm:   xmm14 ^= ONE
# asm 1: pxor  ONE,<xmm14=int6464#15
# asm 2: pxor  ONE,<xmm14=%xmm14
pxor  ONE,%xmm14

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:   xmm2 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm2=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm2=%xmm2
pxor  %xmm11,%xmm2

# qhasm:   xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm12,<xmm6=%xmm6
pxor  %xmm12,%xmm6

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:   xmm2 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm2=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm2=%xmm2
pxor  %xmm11,%xmm2

# qhasm:   xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm12,<xmm6=%xmm6
pxor  %xmm12,%xmm6

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:   xmm2 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm2=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm2=%xmm2
pxor  %xmm11,%xmm2

# qhasm:   xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm12,<xmm6=%xmm6
pxor  %xmm12,%xmm6

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:   xmm2 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm2=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm2=%xmm2
pxor  %xmm11,%xmm2

# qhasm:   xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm12,<xmm6=%xmm6
pxor  %xmm12,%xmm6

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   *(int128 *)(c + 256) = xmm0
# asm 1: movdqa <xmm0=int6464#1,256(<c=int64#1)
# asm 2: movdqa <xmm0=%xmm0,256(<c=%rdi)
movdqa %xmm0,256(%rdi)

# qhasm:   *(int128 *)(c + 272) = xmm1
# asm 1: movdqa <xmm1=int6464#2,272(<c=int64#1)
# asm 2: movdqa <xmm1=%xmm1,272(<c=%rdi)
movdqa %xmm1,272(%rdi)

# qhasm:   *(int128 *)(c + 288) = xmm3
# asm 1: movdqa <xmm3=int6464#4,288(<c=int64#1)
# asm 2: movdqa <xmm3=%xmm3,288(<c=%rdi)
movdqa %xmm3,288(%rdi)

# qhasm:   *(int128 *)(c + 304) = xmm2
# asm 1: movdqa <xmm2=int6464#3,304(<c=int64#1)
# asm 2: movdqa <xmm2=%xmm2,304(<c=%rdi)
movdqa %xmm2,304(%rdi)

# qhasm:   *(int128 *)(c + 320) = xmm6
# asm 1: movdqa <xmm6=int6464#7,320(<c=int64#1)
# asm 2: movdqa <xmm6=%xmm6,320(<c=%rdi)
movdqa %xmm6,320(%rdi)

# qhasm:   *(int128 *)(c + 336) = xmm5
# asm 1: movdqa <xmm5=int6464#6,336(<c=int64#1)
# asm 2: movdqa <xmm5=%xmm5,336(<c=%rdi)
movdqa %xmm5,336(%rdi)

# qhasm:   *(int128 *)(c + 352) = xmm4
# asm 1: movdqa <xmm4=int6464#5,352(<c=int64#1)
# asm 2: movdqa <xmm4=%xmm4,352(<c=%rdi)
movdqa %xmm4,352(%rdi)

# qhasm:   *(int128 *)(c + 368) = xmm7
# asm 1: movdqa <xmm7=int6464#8,368(<c=int64#1)
# asm 2: movdqa <xmm7=%xmm7,368(<c=%rdi)
movdqa %xmm7,368(%rdi)

# qhasm:   xmm0 ^= ONE
# asm 1: pxor  ONE,<xmm0=int6464#1
# asm 2: pxor  ONE,<xmm0=%xmm0
pxor  ONE,%xmm0

# qhasm:   xmm1 ^= ONE
# asm 1: pxor  ONE,<xmm1=int6464#2
# asm 2: pxor  ONE,<xmm1=%xmm1
pxor  ONE,%xmm1

# qhasm:   xmm5 ^= ONE
# asm 1: pxor  ONE,<xmm5=int6464#6
# asm 2: pxor  ONE,<xmm5=%xmm5
pxor  ONE,%xmm5

# qhasm:   xmm4 ^= ONE
# asm 1: pxor  ONE,<xmm4=int6464#5
# asm 2: pxor  ONE,<xmm4=%xmm4
pxor  ONE,%xmm4

# qhasm:     shuffle bytes of xmm0 by ROTB
# asm 1: pshufb ROTB,<xmm0=int6464#1
# asm 2: pshufb ROTB,<xmm0=%xmm0
pshufb ROTB,%xmm0

# qhasm:     shuffle bytes of xmm1 by ROTB
# asm 1: pshufb ROTB,<xmm1=int6464#2
# asm 2: pshufb ROTB,<xmm1=%xmm1
pshufb ROTB,%xmm1

# qhasm:     shuffle bytes of xmm3 by ROTB
# asm 1: pshufb ROTB,<xmm3=int6464#4
# asm 2: pshufb ROTB,<xmm3=%xmm3
pshufb ROTB,%xmm3

# qhasm:     shuffle bytes of xmm2 by ROTB
# asm 1: pshufb ROTB,<xmm2=int6464#3
# asm 2: pshufb ROTB,<xmm2=%xmm2
pshufb ROTB,%xmm2

# qhasm:     shuffle bytes of xmm6 by ROTB
# asm 1: pshufb ROTB,<xmm6=int6464#7
# asm 2: pshufb ROTB,<xmm6=%xmm6
pshufb ROTB,%xmm6

# qhasm:     shuffle bytes of xmm5 by ROTB
# asm 1: pshufb ROTB,<xmm5=int6464#6
# asm 2: pshufb ROTB,<xmm5=%xmm5
pshufb ROTB,%xmm5

# qhasm:     shuffle bytes of xmm4 by ROTB
# asm 1: pshufb ROTB,<xmm4=int6464#5
# asm 2: pshufb ROTB,<xmm4=%xmm4
pshufb ROTB,%xmm4

# qhasm:     shuffle bytes of xmm7 by ROTB
# asm 1: pshufb ROTB,<xmm7=int6464#8
# asm 2: pshufb ROTB,<xmm7=%xmm7
pshufb ROTB,%xmm7

# qhasm:       xmm5 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm5=int6464#6
# asm 2: pxor  <xmm4=%xmm4,<xmm5=%xmm5
pxor  %xmm4,%xmm5

# qhasm:       xmm3 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm3=int6464#4
# asm 2: pxor  <xmm1=%xmm1,<xmm3=%xmm3
pxor  %xmm1,%xmm3

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm5=int6464#6
# asm 2: pxor  <xmm0=%xmm0,<xmm5=%xmm5
pxor  %xmm0,%xmm5

# qhasm:       xmm4 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm4=int6464#5
# asm 2: pxor  <xmm3=%xmm3,<xmm4=%xmm4
pxor  %xmm3,%xmm4

# qhasm:       xmm2 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm2=int6464#3
# asm 2: pxor  <xmm0=%xmm0,<xmm2=%xmm2
pxor  %xmm0,%xmm2

# qhasm:       xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm2=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:       xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:       xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm6,<xmm2=%xmm2
pxor  %xmm6,%xmm2

# qhasm:       xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm7=int6464#8
# asm 2: pxor  <xmm5=%xmm5,<xmm7=%xmm7
pxor  %xmm5,%xmm7

# qhasm:       xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm1,<xmm2=%xmm2
pxor  %xmm1,%xmm2

# qhasm:       xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm1=int6464#2
# asm 2: pxor  <xmm5=%xmm5,<xmm1=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm11 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm11=int6464#9
# asm 2: movdqa <xmm7=%xmm7,>xmm11=%xmm8
movdqa %xmm7,%xmm8

# qhasm:       xmm10 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm10=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm10=%xmm9
movdqa %xmm1,%xmm9

# qhasm:       xmm9 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm9=int6464#11
# asm 2: movdqa <xmm5=%xmm5,>xmm9=%xmm10
movdqa %xmm5,%xmm10

# qhasm:       xmm13 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm13=int6464#12
# asm 2: movdqa <xmm3=%xmm3,>xmm13=%xmm11
movdqa %xmm3,%xmm11

# qhasm:       xmm12 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm12=int6464#13
# asm 2: movdqa <xmm4=%xmm4,>xmm12=%xmm12
movdqa %xmm4,%xmm12

# qhasm:       xmm11 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm11=int6464#9
# asm 2: pxor  <xmm6=%xmm6,<xmm11=%xmm8
pxor  %xmm6,%xmm8

# qhasm:       xmm10 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm10=int6464#10
# asm 2: pxor  <xmm3=%xmm3,<xmm10=%xmm9
pxor  %xmm3,%xmm9

# qhasm:       xmm9 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm9=int6464#11
# asm 2: pxor  <xmm2=%xmm2,<xmm9=%xmm10
pxor  %xmm2,%xmm10

# qhasm:       xmm13 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm13=int6464#12
# asm 2: pxor  <xmm6=%xmm6,<xmm13=%xmm11
pxor  %xmm6,%xmm11

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:       xmm14 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm14=int6464#14
# asm 2: movdqa <xmm11=%xmm8,>xmm14=%xmm13
movdqa %xmm8,%xmm13

# qhasm:       xmm8 = xmm10
# asm 1: movdqa <xmm10=int6464#10,>xmm8=int6464#15
# asm 2: movdqa <xmm10=%xmm9,>xmm8=%xmm14
movdqa %xmm9,%xmm14

# qhasm:       xmm15 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm15=int6464#16
# asm 2: movdqa <xmm11=%xmm8,>xmm15=%xmm15
movdqa %xmm8,%xmm15

# qhasm:       xmm10 |= xmm9
# asm 1: por   <xmm9=int6464#11,<xmm10=int6464#10
# asm 2: por   <xmm9=%xmm10,<xmm10=%xmm9
por   %xmm10,%xmm9

# qhasm:       xmm11 |= xmm12
# asm 1: por   <xmm12=int6464#13,<xmm11=int6464#9
# asm 2: por   <xmm12=%xmm12,<xmm11=%xmm8
por   %xmm12,%xmm8

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm15=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm14 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm14=int6464#14
# asm 2: pand  <xmm12=%xmm12,<xmm14=%xmm13
pand  %xmm12,%xmm13

# qhasm:       xmm8 &= xmm9
# asm 1: pand  <xmm9=int6464#11,<xmm8=int6464#15
# asm 2: pand  <xmm9=%xmm10,<xmm8=%xmm14
pand  %xmm10,%xmm14

# qhasm:       xmm12 ^= xmm9
# asm 1: pxor  <xmm9=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm9=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:       xmm15 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm15=int6464#16
# asm 2: pand  <xmm12=%xmm12,<xmm15=%xmm15
pand  %xmm12,%xmm15

# qhasm:       xmm12 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm12=int6464#11
# asm 2: movdqa <xmm2=%xmm2,>xmm12=%xmm10
movdqa %xmm2,%xmm10

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#11
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm10
pxor  %xmm0,%xmm10

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#11,<xmm13=int6464#12
# asm 2: pand  <xmm12=%xmm10,<xmm13=%xmm11
pand  %xmm10,%xmm11

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm11=int6464#9
# asm 2: pxor  <xmm13=%xmm11,<xmm11=%xmm8
pxor  %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm13 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm13=int6464#11
# asm 2: movdqa <xmm7=%xmm7,>xmm13=%xmm10
movdqa %xmm7,%xmm10

# qhasm:       xmm13 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm13=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm13=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm12 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm12=int6464#12
# asm 2: movdqa <xmm5=%xmm5,>xmm12=%xmm11
movdqa %xmm5,%xmm11

# qhasm:       xmm9 = xmm13
# asm 1: movdqa <xmm13=int6464#11,>xmm9=int6464#13
# asm 2: movdqa <xmm13=%xmm10,>xmm9=%xmm12
movdqa %xmm10,%xmm12

# qhasm:       xmm12 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm12=int6464#12
# asm 2: pxor  <xmm4=%xmm4,<xmm12=%xmm11
pxor  %xmm4,%xmm11

# qhasm:       xmm9 |= xmm12
# asm 1: por   <xmm12=int6464#12,<xmm9=int6464#13
# asm 2: por   <xmm12=%xmm11,<xmm9=%xmm12
por   %xmm11,%xmm12

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#12,<xmm13=int6464#11
# asm 2: pand  <xmm12=%xmm11,<xmm13=%xmm10
pand  %xmm11,%xmm10

# qhasm:       xmm8 ^= xmm13
# asm 1: pxor  <xmm13=int6464#11,<xmm8=int6464#15
# asm 2: pxor  <xmm13=%xmm10,<xmm8=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#9
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm10=int6464#10
# asm 2: pxor  <xmm14=%xmm13,<xmm10=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm9 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm8 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm8=int6464#15
# asm 2: pxor  <xmm14=%xmm13,<xmm8=%xmm14
pxor  %xmm13,%xmm14

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm12 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm12=int6464#11
# asm 2: movdqa <xmm3=%xmm3,>xmm12=%xmm10
movdqa %xmm3,%xmm10

# qhasm:       xmm13 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm13=int6464#12
# asm 2: movdqa <xmm6=%xmm6,>xmm13=%xmm11
movdqa %xmm6,%xmm11

# qhasm:       xmm14 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm14=int6464#14
# asm 2: movdqa <xmm1=%xmm1,>xmm14=%xmm13
movdqa %xmm1,%xmm13

# qhasm:       xmm15 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm15=int6464#16
# asm 2: movdqa <xmm7=%xmm7,>xmm15=%xmm15
movdqa %xmm7,%xmm15

# qhasm:       xmm12 &= xmm2
# asm 1: pand  <xmm2=int6464#3,<xmm12=int6464#11
# asm 2: pand  <xmm2=%xmm2,<xmm12=%xmm10
pand  %xmm2,%xmm10

# qhasm:       xmm13 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm13=int6464#12
# asm 2: pand  <xmm0=%xmm0,<xmm13=%xmm11
pand  %xmm0,%xmm11

# qhasm:       xmm14 &= xmm5
# asm 1: pand  <xmm5=int6464#6,<xmm14=int6464#14
# asm 2: pand  <xmm5=%xmm5,<xmm14=%xmm13
pand  %xmm5,%xmm13

# qhasm:       xmm15 |= xmm4
# asm 1: por   <xmm4=int6464#5,<xmm15=int6464#16
# asm 2: por   <xmm4=%xmm4,<xmm15=%xmm15
por   %xmm4,%xmm15

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm11=int6464#9
# asm 2: pxor  <xmm12=%xmm10,<xmm11=%xmm8
pxor  %xmm10,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm8 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm8=int6464#15
# asm 2: pxor  <xmm15=%xmm15,<xmm8=%xmm14
pxor  %xmm15,%xmm14

# qhasm:       xmm12 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm12=int6464#11
# asm 2: movdqa <xmm11=%xmm8,>xmm12=%xmm10
movdqa %xmm8,%xmm10

# qhasm:       xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm12=int6464#11
# asm 2: pxor  <xmm10=%xmm9,<xmm12=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm11 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm11=int6464#9
# asm 2: pand  <xmm9=%xmm12,<xmm11=%xmm8
pand  %xmm12,%xmm8

# qhasm:       xmm14 = xmm8
# asm 1: movdqa <xmm8=int6464#15,>xmm14=int6464#12
# asm 2: movdqa <xmm8=%xmm14,>xmm14=%xmm11
movdqa %xmm14,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm11=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm15 = xmm12
# asm 1: movdqa <xmm12=int6464#11,>xmm15=int6464#14
# asm 2: movdqa <xmm12=%xmm10,>xmm15=%xmm13
movdqa %xmm10,%xmm13

# qhasm:       xmm15 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm15=int6464#14
# asm 2: pand  <xmm14=%xmm11,<xmm15=%xmm13
pand  %xmm11,%xmm13

# qhasm:       xmm15 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm15=int6464#14
# asm 2: pxor  <xmm10=%xmm9,<xmm15=%xmm13
pxor  %xmm9,%xmm13

# qhasm:       xmm13 = xmm9
# asm 1: movdqa <xmm9=int6464#13,>xmm13=int6464#16
# asm 2: movdqa <xmm9=%xmm12,>xmm13=%xmm15
movdqa %xmm12,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm11 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm11=int6464#9
# asm 2: pxor  <xmm10=%xmm9,<xmm11=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm13 &= xmm11
# asm 1: pand  <xmm11=int6464#9,<xmm13=int6464#16
# asm 2: pand  <xmm11=%xmm8,<xmm13=%xmm15
pand  %xmm8,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm13=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm10 = xmm14
# asm 1: movdqa <xmm14=int6464#12,>xmm10=int6464#9
# asm 2: movdqa <xmm14=%xmm11,>xmm10=%xmm8
movdqa %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm10=int6464#9
# asm 2: pxor  <xmm13=%xmm15,<xmm10=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 &= xmm8
# asm 1: pand  <xmm8=int6464#15,<xmm10=int6464#9
# asm 2: pand  <xmm8=%xmm14,<xmm10=%xmm8
pand  %xmm14,%xmm8

# qhasm:       xmm9 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm9=int6464#13
# asm 2: pxor  <xmm10=%xmm8,<xmm9=%xmm12
pxor  %xmm8,%xmm12

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm10=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm14=int6464#12
# asm 2: pand  <xmm15=%xmm13,<xmm14=%xmm11
pand  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm14=int6464#12
# asm 2: pxor  <xmm12=%xmm10,<xmm14=%xmm11
pxor  %xmm10,%xmm11

# qhasm:         xmm12 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm12=int6464#9
# asm 2: movdqa <xmm4=%xmm4,>xmm12=%xmm8
movdqa %xmm4,%xmm8

# qhasm:         xmm8 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm8=int6464#10
# asm 2: movdqa <xmm5=%xmm5,>xmm8=%xmm9
movdqa %xmm5,%xmm9

# qhasm:           xmm10 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm10=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm10=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm10 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm10=int6464#11
# asm 2: pand  <xmm4=%xmm4,<xmm10=%xmm10
pand  %xmm4,%xmm10

# qhasm:           xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:           xmm4 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm4=int6464#5
# asm 2: pand  <xmm14=%xmm11,<xmm4=%xmm4
pand  %xmm11,%xmm4

# qhasm:           xmm5 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm5=int6464#6
# asm 2: pand  <xmm15=%xmm13,<xmm5=%xmm5
pand  %xmm13,%xmm5

# qhasm:           xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:           xmm5 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm5=int6464#6
# asm 2: pxor  <xmm10=%xmm10,<xmm5=%xmm5
pxor  %xmm10,%xmm5

# qhasm:         xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm8 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm8=int6464#10
# asm 2: pxor  <xmm2=%xmm2,<xmm8=%xmm9
pxor  %xmm2,%xmm9

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm10=int6464#11
# asm 2: pand  <xmm0=%xmm0,<xmm10=%xmm10
pand  %xmm0,%xmm10

# qhasm:           xmm0 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm0=int6464#1
# asm 2: pxor  <xmm2=%xmm2,<xmm0=%xmm0
pxor  %xmm2,%xmm0

# qhasm:           xmm0 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm0=int6464#1
# asm 2: pand  <xmm9=%xmm12,<xmm0=%xmm0
pand  %xmm12,%xmm0

# qhasm:           xmm2 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm2=int6464#3
# asm 2: pand  <xmm13=%xmm15,<xmm2=%xmm2
pand  %xmm15,%xmm2

# qhasm:           xmm0 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm0=int6464#1
# asm 2: pxor  <xmm2=%xmm2,<xmm0=%xmm0
pxor  %xmm2,%xmm0

# qhasm:           xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#3
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm2
pxor  %xmm10,%xmm2

# qhasm:         xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <xmm12=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:         xmm0 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm12=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm5 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm5=int6464#6
# asm 2: pxor  <xmm8=%xmm9,<xmm5=%xmm5
pxor  %xmm9,%xmm5

# qhasm:         xmm2 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm2=int6464#3
# asm 2: pxor  <xmm8=%xmm9,<xmm2=%xmm2
pxor  %xmm9,%xmm2

# qhasm:         xmm12 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm12=int6464#9
# asm 2: movdqa <xmm7=%xmm7,>xmm12=%xmm8
movdqa %xmm7,%xmm8

# qhasm:         xmm8 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm8=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm8=%xmm9
movdqa %xmm1,%xmm9

# qhasm:         xmm12 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm12=int6464#9
# asm 2: pxor  <xmm6=%xmm6,<xmm12=%xmm8
pxor  %xmm6,%xmm8

# qhasm:         xmm8 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm8=int6464#10
# asm 2: pxor  <xmm3=%xmm3,<xmm8=%xmm9
pxor  %xmm3,%xmm9

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm6
# asm 1: pand  <xmm6=int6464#7,<xmm10=int6464#11
# asm 2: pand  <xmm6=%xmm6,<xmm10=%xmm10
pand  %xmm6,%xmm10

# qhasm:           xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm6=int6464#7
# asm 2: pxor  <xmm3=%xmm3,<xmm6=%xmm6
pxor  %xmm3,%xmm6

# qhasm:           xmm6 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm6=int6464#7
# asm 2: pand  <xmm9=%xmm12,<xmm6=%xmm6
pand  %xmm12,%xmm6

# qhasm:           xmm3 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm3=int6464#4
# asm 2: pand  <xmm13=%xmm15,<xmm3=%xmm3
pand  %xmm15,%xmm3

# qhasm:           xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm6=int6464#7
# asm 2: pxor  <xmm3=%xmm3,<xmm6=%xmm6
pxor  %xmm3,%xmm6

# qhasm:           xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm7
# asm 1: pand  <xmm7=int6464#8,<xmm11=int6464#11
# asm 2: pand  <xmm7=%xmm7,<xmm11=%xmm10
pand  %xmm7,%xmm10

# qhasm:           xmm7 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm7=int6464#8
# asm 2: pxor  <xmm1=%xmm1,<xmm7=%xmm7
pxor  %xmm1,%xmm7

# qhasm:           xmm7 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm7=int6464#8
# asm 2: pand  <xmm14=%xmm11,<xmm7=%xmm7
pand  %xmm11,%xmm7

# qhasm:           xmm1 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm1=int6464#2
# asm 2: pand  <xmm15=%xmm13,<xmm1=%xmm1
pand  %xmm13,%xmm1

# qhasm:           xmm7 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm7=int6464#8
# asm 2: pxor  <xmm1=%xmm1,<xmm7=%xmm7
pxor  %xmm1,%xmm7

# qhasm:           xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm1=int6464#2
# asm 2: pxor  <xmm11=%xmm10,<xmm1=%xmm1
pxor  %xmm10,%xmm1

# qhasm:         xmm7 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm7=int6464#8
# asm 2: pxor  <xmm12=%xmm8,<xmm7=%xmm7
pxor  %xmm8,%xmm7

# qhasm:         xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm8,<xmm6=%xmm6
pxor  %xmm8,%xmm6

# qhasm:         xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:         xmm3 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm3=int6464#4
# asm 2: pxor  <xmm8=%xmm9,<xmm3=%xmm3
pxor  %xmm9,%xmm3

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm0,<xmm7=%xmm7
pxor  %xmm0,%xmm7

# qhasm:       xmm1 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm1=int6464#2
# asm 2: pxor  <xmm4=%xmm4,<xmm1=%xmm1
pxor  %xmm4,%xmm1

# qhasm:       xmm6 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm6=int6464#7
# asm 2: pxor  <xmm7=%xmm7,<xmm6=%xmm6
pxor  %xmm7,%xmm6

# qhasm:       xmm4 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm4=int6464#5
# asm 2: pxor  <xmm0=%xmm0,<xmm4=%xmm4
pxor  %xmm0,%xmm4

# qhasm:       xmm0 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm0=int6464#1
# asm 2: pxor  <xmm1=%xmm1,<xmm0=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm1=int6464#2
# asm 2: pxor  <xmm5=%xmm5,<xmm1=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm5 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm5=int6464#6
# asm 2: pxor  <xmm3=%xmm3,<xmm5=%xmm5
pxor  %xmm3,%xmm5

# qhasm:       xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:       xmm3 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm3=int6464#4
# asm 2: pxor  <xmm2=%xmm2,<xmm3=%xmm3
pxor  %xmm2,%xmm3

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm2=int6464#3
# asm 2: pxor  <xmm5=%xmm5,<xmm2=%xmm2
pxor  %xmm5,%xmm2

# qhasm:       xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm2=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:   xmm6 ^= RCON
# asm 1: pxor  RCON,<xmm6=int6464#7
# asm 2: pxor  RCON,<xmm6=%xmm6
pxor  RCON,%xmm6

# qhasm:   shuffle bytes of xmm0 by EXPB0
# asm 1: pshufb EXPB0,<xmm0=int6464#1
# asm 2: pshufb EXPB0,<xmm0=%xmm0
pshufb EXPB0,%xmm0

# qhasm:   shuffle bytes of xmm1 by EXPB0
# asm 1: pshufb EXPB0,<xmm1=int6464#2
# asm 2: pshufb EXPB0,<xmm1=%xmm1
pshufb EXPB0,%xmm1

# qhasm:   shuffle bytes of xmm6 by EXPB0
# asm 1: pshufb EXPB0,<xmm6=int6464#7
# asm 2: pshufb EXPB0,<xmm6=%xmm6
pshufb EXPB0,%xmm6

# qhasm:   shuffle bytes of xmm4 by EXPB0
# asm 1: pshufb EXPB0,<xmm4=int6464#5
# asm 2: pshufb EXPB0,<xmm4=%xmm4
pshufb EXPB0,%xmm4

# qhasm:   shuffle bytes of xmm2 by EXPB0
# asm 1: pshufb EXPB0,<xmm2=int6464#3
# asm 2: pshufb EXPB0,<xmm2=%xmm2
pshufb EXPB0,%xmm2

# qhasm:   shuffle bytes of xmm7 by EXPB0
# asm 1: pshufb EXPB0,<xmm7=int6464#8
# asm 2: pshufb EXPB0,<xmm7=%xmm7
pshufb EXPB0,%xmm7

# qhasm:   shuffle bytes of xmm3 by EXPB0
# asm 1: pshufb EXPB0,<xmm3=int6464#4
# asm 2: pshufb EXPB0,<xmm3=%xmm3
pshufb EXPB0,%xmm3

# qhasm:   shuffle bytes of xmm5 by EXPB0
# asm 1: pshufb EXPB0,<xmm5=int6464#6
# asm 2: pshufb EXPB0,<xmm5=%xmm5
pshufb EXPB0,%xmm5

# qhasm:   xmm8 = *(int128 *)(c + 256)
# asm 1: movdqa 256(<c=int64#1),>xmm8=int6464#9
# asm 2: movdqa 256(<c=%rdi),>xmm8=%xmm8
movdqa 256(%rdi),%xmm8

# qhasm:   xmm9 = *(int128 *)(c + 272)
# asm 1: movdqa 272(<c=int64#1),>xmm9=int6464#10
# asm 2: movdqa 272(<c=%rdi),>xmm9=%xmm9
movdqa 272(%rdi),%xmm9

# qhasm:   xmm10 = *(int128 *)(c + 288)
# asm 1: movdqa 288(<c=int64#1),>xmm10=int6464#11
# asm 2: movdqa 288(<c=%rdi),>xmm10=%xmm10
movdqa 288(%rdi),%xmm10

# qhasm:   xmm11 = *(int128 *)(c + 304)
# asm 1: movdqa 304(<c=int64#1),>xmm11=int6464#12
# asm 2: movdqa 304(<c=%rdi),>xmm11=%xmm11
movdqa 304(%rdi),%xmm11

# qhasm:   xmm12 = *(int128 *)(c + 320)
# asm 1: movdqa 320(<c=int64#1),>xmm12=int6464#13
# asm 2: movdqa 320(<c=%rdi),>xmm12=%xmm12
movdqa 320(%rdi),%xmm12

# qhasm:   xmm13 = *(int128 *)(c + 336)
# asm 1: movdqa 336(<c=int64#1),>xmm13=int6464#14
# asm 2: movdqa 336(<c=%rdi),>xmm13=%xmm13
movdqa 336(%rdi),%xmm13

# qhasm:   xmm14 = *(int128 *)(c + 352)
# asm 1: movdqa 352(<c=int64#1),>xmm14=int6464#15
# asm 2: movdqa 352(<c=%rdi),>xmm14=%xmm14
movdqa 352(%rdi),%xmm14

# qhasm:   xmm15 = *(int128 *)(c + 368)
# asm 1: movdqa 368(<c=int64#1),>xmm15=int6464#16
# asm 2: movdqa 368(<c=%rdi),>xmm15=%xmm15
movdqa 368(%rdi),%xmm15

# qhasm:   xmm8 ^= ONE
# asm 1: pxor  ONE,<xmm8=int6464#9
# asm 2: pxor  ONE,<xmm8=%xmm8
pxor  ONE,%xmm8

# qhasm:   xmm9 ^= ONE
# asm 1: pxor  ONE,<xmm9=int6464#10
# asm 2: pxor  ONE,<xmm9=%xmm9
pxor  ONE,%xmm9

# qhasm:   xmm13 ^= ONE
# asm 1: pxor  ONE,<xmm13=int6464#14
# asm 2: pxor  ONE,<xmm13=%xmm13
pxor  ONE,%xmm13

# qhasm:   xmm14 ^= ONE
# asm 1: pxor  ONE,<xmm14=int6464#15
# asm 2: pxor  ONE,<xmm14=%xmm14
pxor  ONE,%xmm14

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:   xmm4 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm4=int6464#5
# asm 2: pxor  <xmm11=%xmm11,<xmm4=%xmm4
pxor  %xmm11,%xmm4

# qhasm:   xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm12,<xmm2=%xmm2
pxor  %xmm12,%xmm2

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm3 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm3=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm3=%xmm3
pxor  %xmm14,%xmm3

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:   xmm4 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm4=int6464#5
# asm 2: pxor  <xmm11=%xmm11,<xmm4=%xmm4
pxor  %xmm11,%xmm4

# qhasm:   xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm12,<xmm2=%xmm2
pxor  %xmm12,%xmm2

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm3 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm3=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm3=%xmm3
pxor  %xmm14,%xmm3

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:   xmm4 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm4=int6464#5
# asm 2: pxor  <xmm11=%xmm11,<xmm4=%xmm4
pxor  %xmm11,%xmm4

# qhasm:   xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm12,<xmm2=%xmm2
pxor  %xmm12,%xmm2

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm3 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm3=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm3=%xmm3
pxor  %xmm14,%xmm3

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:   xmm4 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm4=int6464#5
# asm 2: pxor  <xmm11=%xmm11,<xmm4=%xmm4
pxor  %xmm11,%xmm4

# qhasm:   xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm12,<xmm2=%xmm2
pxor  %xmm12,%xmm2

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm3 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm3=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm3=%xmm3
pxor  %xmm14,%xmm3

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   *(int128 *)(c + 384) = xmm0
# asm 1: movdqa <xmm0=int6464#1,384(<c=int64#1)
# asm 2: movdqa <xmm0=%xmm0,384(<c=%rdi)
movdqa %xmm0,384(%rdi)

# qhasm:   *(int128 *)(c + 400) = xmm1
# asm 1: movdqa <xmm1=int6464#2,400(<c=int64#1)
# asm 2: movdqa <xmm1=%xmm1,400(<c=%rdi)
movdqa %xmm1,400(%rdi)

# qhasm:   *(int128 *)(c + 416) = xmm6
# asm 1: movdqa <xmm6=int6464#7,416(<c=int64#1)
# asm 2: movdqa <xmm6=%xmm6,416(<c=%rdi)
movdqa %xmm6,416(%rdi)

# qhasm:   *(int128 *)(c + 432) = xmm4
# asm 1: movdqa <xmm4=int6464#5,432(<c=int64#1)
# asm 2: movdqa <xmm4=%xmm4,432(<c=%rdi)
movdqa %xmm4,432(%rdi)

# qhasm:   *(int128 *)(c + 448) = xmm2
# asm 1: movdqa <xmm2=int6464#3,448(<c=int64#1)
# asm 2: movdqa <xmm2=%xmm2,448(<c=%rdi)
movdqa %xmm2,448(%rdi)

# qhasm:   *(int128 *)(c + 464) = xmm7
# asm 1: movdqa <xmm7=int6464#8,464(<c=int64#1)
# asm 2: movdqa <xmm7=%xmm7,464(<c=%rdi)
movdqa %xmm7,464(%rdi)

# qhasm:   *(int128 *)(c + 480) = xmm3
# asm 1: movdqa <xmm3=int6464#4,480(<c=int64#1)
# asm 2: movdqa <xmm3=%xmm3,480(<c=%rdi)
movdqa %xmm3,480(%rdi)

# qhasm:   *(int128 *)(c + 496) = xmm5
# asm 1: movdqa <xmm5=int6464#6,496(<c=int64#1)
# asm 2: movdqa <xmm5=%xmm5,496(<c=%rdi)
movdqa %xmm5,496(%rdi)

# qhasm:   xmm0 ^= ONE
# asm 1: pxor  ONE,<xmm0=int6464#1
# asm 2: pxor  ONE,<xmm0=%xmm0
pxor  ONE,%xmm0

# qhasm:   xmm1 ^= ONE
# asm 1: pxor  ONE,<xmm1=int6464#2
# asm 2: pxor  ONE,<xmm1=%xmm1
pxor  ONE,%xmm1

# qhasm:   xmm7 ^= ONE
# asm 1: pxor  ONE,<xmm7=int6464#8
# asm 2: pxor  ONE,<xmm7=%xmm7
pxor  ONE,%xmm7

# qhasm:   xmm3 ^= ONE
# asm 1: pxor  ONE,<xmm3=int6464#4
# asm 2: pxor  ONE,<xmm3=%xmm3
pxor  ONE,%xmm3

# qhasm:     shuffle bytes of xmm0 by ROTB
# asm 1: pshufb ROTB,<xmm0=int6464#1
# asm 2: pshufb ROTB,<xmm0=%xmm0
pshufb ROTB,%xmm0

# qhasm:     shuffle bytes of xmm1 by ROTB
# asm 1: pshufb ROTB,<xmm1=int6464#2
# asm 2: pshufb ROTB,<xmm1=%xmm1
pshufb ROTB,%xmm1

# qhasm:     shuffle bytes of xmm6 by ROTB
# asm 1: pshufb ROTB,<xmm6=int6464#7
# asm 2: pshufb ROTB,<xmm6=%xmm6
pshufb ROTB,%xmm6

# qhasm:     shuffle bytes of xmm4 by ROTB
# asm 1: pshufb ROTB,<xmm4=int6464#5
# asm 2: pshufb ROTB,<xmm4=%xmm4
pshufb ROTB,%xmm4

# qhasm:     shuffle bytes of xmm2 by ROTB
# asm 1: pshufb ROTB,<xmm2=int6464#3
# asm 2: pshufb ROTB,<xmm2=%xmm2
pshufb ROTB,%xmm2

# qhasm:     shuffle bytes of xmm7 by ROTB
# asm 1: pshufb ROTB,<xmm7=int6464#8
# asm 2: pshufb ROTB,<xmm7=%xmm7
pshufb ROTB,%xmm7

# qhasm:     shuffle bytes of xmm3 by ROTB
# asm 1: pshufb ROTB,<xmm3=int6464#4
# asm 2: pshufb ROTB,<xmm3=%xmm3
pshufb ROTB,%xmm3

# qhasm:     shuffle bytes of xmm5 by ROTB
# asm 1: pshufb ROTB,<xmm5=int6464#6
# asm 2: pshufb ROTB,<xmm5=%xmm5
pshufb ROTB,%xmm5

# qhasm:       xmm7 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm7=int6464#8
# asm 2: pxor  <xmm3=%xmm3,<xmm7=%xmm7
pxor  %xmm3,%xmm7

# qhasm:       xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm6=int6464#7
# asm 2: pxor  <xmm1=%xmm1,<xmm6=%xmm6
pxor  %xmm1,%xmm6

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm0,<xmm7=%xmm7
pxor  %xmm0,%xmm7

# qhasm:       xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm3=int6464#4
# asm 2: pxor  <xmm6=%xmm6,<xmm3=%xmm3
pxor  %xmm6,%xmm3

# qhasm:       xmm4 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm4=int6464#5
# asm 2: pxor  <xmm0=%xmm0,<xmm4=%xmm4
pxor  %xmm0,%xmm4

# qhasm:       xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm3=int6464#4
# asm 2: pxor  <xmm4=%xmm4,<xmm3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:       xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm2=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:       xmm5 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm5=int6464#6
# asm 2: pxor  <xmm7=%xmm7,<xmm5=%xmm5
pxor  %xmm7,%xmm5

# qhasm:       xmm4 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm4=int6464#5
# asm 2: pxor  <xmm1=%xmm1,<xmm4=%xmm4
pxor  %xmm1,%xmm4

# qhasm:       xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:       xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#2
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm1
pxor  %xmm7,%xmm1

# qhasm:       xmm11 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm11=int6464#9
# asm 2: movdqa <xmm5=%xmm5,>xmm11=%xmm8
movdqa %xmm5,%xmm8

# qhasm:       xmm10 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm10=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm10=%xmm9
movdqa %xmm1,%xmm9

# qhasm:       xmm9 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm9=int6464#11
# asm 2: movdqa <xmm7=%xmm7,>xmm9=%xmm10
movdqa %xmm7,%xmm10

# qhasm:       xmm13 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm13=int6464#12
# asm 2: movdqa <xmm6=%xmm6,>xmm13=%xmm11
movdqa %xmm6,%xmm11

# qhasm:       xmm12 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm12=int6464#13
# asm 2: movdqa <xmm3=%xmm3,>xmm12=%xmm12
movdqa %xmm3,%xmm12

# qhasm:       xmm11 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm11=int6464#9
# asm 2: pxor  <xmm2=%xmm2,<xmm11=%xmm8
pxor  %xmm2,%xmm8

# qhasm:       xmm10 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm10=int6464#10
# asm 2: pxor  <xmm6=%xmm6,<xmm10=%xmm9
pxor  %xmm6,%xmm9

# qhasm:       xmm9 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm9=int6464#11
# asm 2: pxor  <xmm4=%xmm4,<xmm9=%xmm10
pxor  %xmm4,%xmm10

# qhasm:       xmm13 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm13=int6464#12
# asm 2: pxor  <xmm2=%xmm2,<xmm13=%xmm11
pxor  %xmm2,%xmm11

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:       xmm14 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm14=int6464#14
# asm 2: movdqa <xmm11=%xmm8,>xmm14=%xmm13
movdqa %xmm8,%xmm13

# qhasm:       xmm8 = xmm10
# asm 1: movdqa <xmm10=int6464#10,>xmm8=int6464#15
# asm 2: movdqa <xmm10=%xmm9,>xmm8=%xmm14
movdqa %xmm9,%xmm14

# qhasm:       xmm15 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm15=int6464#16
# asm 2: movdqa <xmm11=%xmm8,>xmm15=%xmm15
movdqa %xmm8,%xmm15

# qhasm:       xmm10 |= xmm9
# asm 1: por   <xmm9=int6464#11,<xmm10=int6464#10
# asm 2: por   <xmm9=%xmm10,<xmm10=%xmm9
por   %xmm10,%xmm9

# qhasm:       xmm11 |= xmm12
# asm 1: por   <xmm12=int6464#13,<xmm11=int6464#9
# asm 2: por   <xmm12=%xmm12,<xmm11=%xmm8
por   %xmm12,%xmm8

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm15=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm14 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm14=int6464#14
# asm 2: pand  <xmm12=%xmm12,<xmm14=%xmm13
pand  %xmm12,%xmm13

# qhasm:       xmm8 &= xmm9
# asm 1: pand  <xmm9=int6464#11,<xmm8=int6464#15
# asm 2: pand  <xmm9=%xmm10,<xmm8=%xmm14
pand  %xmm10,%xmm14

# qhasm:       xmm12 ^= xmm9
# asm 1: pxor  <xmm9=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm9=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:       xmm15 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm15=int6464#16
# asm 2: pand  <xmm12=%xmm12,<xmm15=%xmm15
pand  %xmm12,%xmm15

# qhasm:       xmm12 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm12=int6464#11
# asm 2: movdqa <xmm4=%xmm4,>xmm12=%xmm10
movdqa %xmm4,%xmm10

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#11
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm10
pxor  %xmm0,%xmm10

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#11,<xmm13=int6464#12
# asm 2: pand  <xmm12=%xmm10,<xmm13=%xmm11
pand  %xmm10,%xmm11

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm11=int6464#9
# asm 2: pxor  <xmm13=%xmm11,<xmm11=%xmm8
pxor  %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm13 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm13=int6464#11
# asm 2: movdqa <xmm5=%xmm5,>xmm13=%xmm10
movdqa %xmm5,%xmm10

# qhasm:       xmm13 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm13=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm13=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm12 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm12=int6464#12
# asm 2: movdqa <xmm7=%xmm7,>xmm12=%xmm11
movdqa %xmm7,%xmm11

# qhasm:       xmm9 = xmm13
# asm 1: movdqa <xmm13=int6464#11,>xmm9=int6464#13
# asm 2: movdqa <xmm13=%xmm10,>xmm9=%xmm12
movdqa %xmm10,%xmm12

# qhasm:       xmm12 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm12=int6464#12
# asm 2: pxor  <xmm3=%xmm3,<xmm12=%xmm11
pxor  %xmm3,%xmm11

# qhasm:       xmm9 |= xmm12
# asm 1: por   <xmm12=int6464#12,<xmm9=int6464#13
# asm 2: por   <xmm12=%xmm11,<xmm9=%xmm12
por   %xmm11,%xmm12

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#12,<xmm13=int6464#11
# asm 2: pand  <xmm12=%xmm11,<xmm13=%xmm10
pand  %xmm11,%xmm10

# qhasm:       xmm8 ^= xmm13
# asm 1: pxor  <xmm13=int6464#11,<xmm8=int6464#15
# asm 2: pxor  <xmm13=%xmm10,<xmm8=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#9
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm10=int6464#10
# asm 2: pxor  <xmm14=%xmm13,<xmm10=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm9 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm8 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm8=int6464#15
# asm 2: pxor  <xmm14=%xmm13,<xmm8=%xmm14
pxor  %xmm13,%xmm14

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm12 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm12=int6464#11
# asm 2: movdqa <xmm6=%xmm6,>xmm12=%xmm10
movdqa %xmm6,%xmm10

# qhasm:       xmm13 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm13=int6464#12
# asm 2: movdqa <xmm2=%xmm2,>xmm13=%xmm11
movdqa %xmm2,%xmm11

# qhasm:       xmm14 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm14=int6464#14
# asm 2: movdqa <xmm1=%xmm1,>xmm14=%xmm13
movdqa %xmm1,%xmm13

# qhasm:       xmm15 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm15=int6464#16
# asm 2: movdqa <xmm5=%xmm5,>xmm15=%xmm15
movdqa %xmm5,%xmm15

# qhasm:       xmm12 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm12=int6464#11
# asm 2: pand  <xmm4=%xmm4,<xmm12=%xmm10
pand  %xmm4,%xmm10

# qhasm:       xmm13 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm13=int6464#12
# asm 2: pand  <xmm0=%xmm0,<xmm13=%xmm11
pand  %xmm0,%xmm11

# qhasm:       xmm14 &= xmm7
# asm 1: pand  <xmm7=int6464#8,<xmm14=int6464#14
# asm 2: pand  <xmm7=%xmm7,<xmm14=%xmm13
pand  %xmm7,%xmm13

# qhasm:       xmm15 |= xmm3
# asm 1: por   <xmm3=int6464#4,<xmm15=int6464#16
# asm 2: por   <xmm3=%xmm3,<xmm15=%xmm15
por   %xmm3,%xmm15

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm11=int6464#9
# asm 2: pxor  <xmm12=%xmm10,<xmm11=%xmm8
pxor  %xmm10,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm8 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm8=int6464#15
# asm 2: pxor  <xmm15=%xmm15,<xmm8=%xmm14
pxor  %xmm15,%xmm14

# qhasm:       xmm12 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm12=int6464#11
# asm 2: movdqa <xmm11=%xmm8,>xmm12=%xmm10
movdqa %xmm8,%xmm10

# qhasm:       xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm12=int6464#11
# asm 2: pxor  <xmm10=%xmm9,<xmm12=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm11 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm11=int6464#9
# asm 2: pand  <xmm9=%xmm12,<xmm11=%xmm8
pand  %xmm12,%xmm8

# qhasm:       xmm14 = xmm8
# asm 1: movdqa <xmm8=int6464#15,>xmm14=int6464#12
# asm 2: movdqa <xmm8=%xmm14,>xmm14=%xmm11
movdqa %xmm14,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm11=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm15 = xmm12
# asm 1: movdqa <xmm12=int6464#11,>xmm15=int6464#14
# asm 2: movdqa <xmm12=%xmm10,>xmm15=%xmm13
movdqa %xmm10,%xmm13

# qhasm:       xmm15 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm15=int6464#14
# asm 2: pand  <xmm14=%xmm11,<xmm15=%xmm13
pand  %xmm11,%xmm13

# qhasm:       xmm15 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm15=int6464#14
# asm 2: pxor  <xmm10=%xmm9,<xmm15=%xmm13
pxor  %xmm9,%xmm13

# qhasm:       xmm13 = xmm9
# asm 1: movdqa <xmm9=int6464#13,>xmm13=int6464#16
# asm 2: movdqa <xmm9=%xmm12,>xmm13=%xmm15
movdqa %xmm12,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm11 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm11=int6464#9
# asm 2: pxor  <xmm10=%xmm9,<xmm11=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm13 &= xmm11
# asm 1: pand  <xmm11=int6464#9,<xmm13=int6464#16
# asm 2: pand  <xmm11=%xmm8,<xmm13=%xmm15
pand  %xmm8,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm13=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm10 = xmm14
# asm 1: movdqa <xmm14=int6464#12,>xmm10=int6464#9
# asm 2: movdqa <xmm14=%xmm11,>xmm10=%xmm8
movdqa %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm10=int6464#9
# asm 2: pxor  <xmm13=%xmm15,<xmm10=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 &= xmm8
# asm 1: pand  <xmm8=int6464#15,<xmm10=int6464#9
# asm 2: pand  <xmm8=%xmm14,<xmm10=%xmm8
pand  %xmm14,%xmm8

# qhasm:       xmm9 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm9=int6464#13
# asm 2: pxor  <xmm10=%xmm8,<xmm9=%xmm12
pxor  %xmm8,%xmm12

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm10=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm14=int6464#12
# asm 2: pand  <xmm15=%xmm13,<xmm14=%xmm11
pand  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm14=int6464#12
# asm 2: pxor  <xmm12=%xmm10,<xmm14=%xmm11
pxor  %xmm10,%xmm11

# qhasm:         xmm12 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm12=int6464#9
# asm 2: movdqa <xmm3=%xmm3,>xmm12=%xmm8
movdqa %xmm3,%xmm8

# qhasm:         xmm8 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm8=int6464#10
# asm 2: movdqa <xmm7=%xmm7,>xmm8=%xmm9
movdqa %xmm7,%xmm9

# qhasm:           xmm10 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm10=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm10=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm10 &= xmm3
# asm 1: pand  <xmm3=int6464#4,<xmm10=int6464#11
# asm 2: pand  <xmm3=%xmm3,<xmm10=%xmm10
pand  %xmm3,%xmm10

# qhasm:           xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:           xmm3 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm3=int6464#4
# asm 2: pand  <xmm14=%xmm11,<xmm3=%xmm3
pand  %xmm11,%xmm3

# qhasm:           xmm7 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm7=int6464#8
# asm 2: pand  <xmm15=%xmm13,<xmm7=%xmm7
pand  %xmm13,%xmm7

# qhasm:           xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:           xmm7 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm7=int6464#8
# asm 2: pxor  <xmm10=%xmm10,<xmm7=%xmm7
pxor  %xmm10,%xmm7

# qhasm:         xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm8 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm8=int6464#10
# asm 2: pxor  <xmm4=%xmm4,<xmm8=%xmm9
pxor  %xmm4,%xmm9

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm10=int6464#11
# asm 2: pand  <xmm0=%xmm0,<xmm10=%xmm10
pand  %xmm0,%xmm10

# qhasm:           xmm0 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm0=int6464#1
# asm 2: pxor  <xmm4=%xmm4,<xmm0=%xmm0
pxor  %xmm4,%xmm0

# qhasm:           xmm0 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm0=int6464#1
# asm 2: pand  <xmm9=%xmm12,<xmm0=%xmm0
pand  %xmm12,%xmm0

# qhasm:           xmm4 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm4=int6464#5
# asm 2: pand  <xmm13=%xmm15,<xmm4=%xmm4
pand  %xmm15,%xmm4

# qhasm:           xmm0 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm0=int6464#1
# asm 2: pxor  <xmm4=%xmm4,<xmm0=%xmm0
pxor  %xmm4,%xmm0

# qhasm:           xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:         xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm8,<xmm3=%xmm3
pxor  %xmm8,%xmm3

# qhasm:         xmm0 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm12=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm7 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm7=int6464#8
# asm 2: pxor  <xmm8=%xmm9,<xmm7=%xmm7
pxor  %xmm9,%xmm7

# qhasm:         xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm4=int6464#5
# asm 2: pxor  <xmm8=%xmm9,<xmm4=%xmm4
pxor  %xmm9,%xmm4

# qhasm:         xmm12 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm12=int6464#9
# asm 2: movdqa <xmm5=%xmm5,>xmm12=%xmm8
movdqa %xmm5,%xmm8

# qhasm:         xmm8 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm8=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm8=%xmm9
movdqa %xmm1,%xmm9

# qhasm:         xmm12 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm12=int6464#9
# asm 2: pxor  <xmm2=%xmm2,<xmm12=%xmm8
pxor  %xmm2,%xmm8

# qhasm:         xmm8 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm8=int6464#10
# asm 2: pxor  <xmm6=%xmm6,<xmm8=%xmm9
pxor  %xmm6,%xmm9

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm2
# asm 1: pand  <xmm2=int6464#3,<xmm10=int6464#11
# asm 2: pand  <xmm2=%xmm2,<xmm10=%xmm10
pand  %xmm2,%xmm10

# qhasm:           xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm6,<xmm2=%xmm2
pxor  %xmm6,%xmm2

# qhasm:           xmm2 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm2=int6464#3
# asm 2: pand  <xmm9=%xmm12,<xmm2=%xmm2
pand  %xmm12,%xmm2

# qhasm:           xmm6 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm6=int6464#7
# asm 2: pand  <xmm13=%xmm15,<xmm6=%xmm6
pand  %xmm15,%xmm6

# qhasm:           xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm6,<xmm2=%xmm2
pxor  %xmm6,%xmm2

# qhasm:           xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm5
# asm 1: pand  <xmm5=int6464#6,<xmm11=int6464#11
# asm 2: pand  <xmm5=%xmm5,<xmm11=%xmm10
pand  %xmm5,%xmm10

# qhasm:           xmm5 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm5=int6464#6
# asm 2: pxor  <xmm1=%xmm1,<xmm5=%xmm5
pxor  %xmm1,%xmm5

# qhasm:           xmm5 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm5=int6464#6
# asm 2: pand  <xmm14=%xmm11,<xmm5=%xmm5
pand  %xmm11,%xmm5

# qhasm:           xmm1 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm1=int6464#2
# asm 2: pand  <xmm15=%xmm13,<xmm1=%xmm1
pand  %xmm13,%xmm1

# qhasm:           xmm5 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm5=int6464#6
# asm 2: pxor  <xmm1=%xmm1,<xmm5=%xmm5
pxor  %xmm1,%xmm5

# qhasm:           xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm1=int6464#2
# asm 2: pxor  <xmm11=%xmm10,<xmm1=%xmm1
pxor  %xmm10,%xmm1

# qhasm:         xmm5 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm5=int6464#6
# asm 2: pxor  <xmm12=%xmm8,<xmm5=%xmm5
pxor  %xmm8,%xmm5

# qhasm:         xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm8,<xmm2=%xmm2
pxor  %xmm8,%xmm2

# qhasm:         xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:         xmm6 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm6=int6464#7
# asm 2: pxor  <xmm8=%xmm9,<xmm6=%xmm6
pxor  %xmm9,%xmm6

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm5=int6464#6
# asm 2: pxor  <xmm0=%xmm0,<xmm5=%xmm5
pxor  %xmm0,%xmm5

# qhasm:       xmm1 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm1=int6464#2
# asm 2: pxor  <xmm3=%xmm3,<xmm1=%xmm1
pxor  %xmm3,%xmm1

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm2=int6464#3
# asm 2: pxor  <xmm5=%xmm5,<xmm2=%xmm2
pxor  %xmm5,%xmm2

# qhasm:       xmm3 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm3=int6464#4
# asm 2: pxor  <xmm0=%xmm0,<xmm3=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm0 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm0=int6464#1
# asm 2: pxor  <xmm1=%xmm1,<xmm0=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#2
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm1
pxor  %xmm7,%xmm1

# qhasm:       xmm7 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm7=int6464#8
# asm 2: pxor  <xmm6=%xmm6,<xmm7=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:       xmm6 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm6=int6464#7
# asm 2: pxor  <xmm4=%xmm4,<xmm6=%xmm6
pxor  %xmm4,%xmm6

# qhasm:       xmm4 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm4=int6464#5
# asm 2: pxor  <xmm7=%xmm7,<xmm4=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm3=int6464#4
# asm 2: pxor  <xmm4=%xmm4,<xmm3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:   xmm3 ^= RCON
# asm 1: pxor  RCON,<xmm3=int6464#4
# asm 2: pxor  RCON,<xmm3=%xmm3
pxor  RCON,%xmm3

# qhasm:   shuffle bytes of xmm0 by EXPB0
# asm 1: pshufb EXPB0,<xmm0=int6464#1
# asm 2: pshufb EXPB0,<xmm0=%xmm0
pshufb EXPB0,%xmm0

# qhasm:   shuffle bytes of xmm1 by EXPB0
# asm 1: pshufb EXPB0,<xmm1=int6464#2
# asm 2: pshufb EXPB0,<xmm1=%xmm1
pshufb EXPB0,%xmm1

# qhasm:   shuffle bytes of xmm2 by EXPB0
# asm 1: pshufb EXPB0,<xmm2=int6464#3
# asm 2: pshufb EXPB0,<xmm2=%xmm2
pshufb EXPB0,%xmm2

# qhasm:   shuffle bytes of xmm3 by EXPB0
# asm 1: pshufb EXPB0,<xmm3=int6464#4
# asm 2: pshufb EXPB0,<xmm3=%xmm3
pshufb EXPB0,%xmm3

# qhasm:   shuffle bytes of xmm4 by EXPB0
# asm 1: pshufb EXPB0,<xmm4=int6464#5
# asm 2: pshufb EXPB0,<xmm4=%xmm4
pshufb EXPB0,%xmm4

# qhasm:   shuffle bytes of xmm5 by EXPB0
# asm 1: pshufb EXPB0,<xmm5=int6464#6
# asm 2: pshufb EXPB0,<xmm5=%xmm5
pshufb EXPB0,%xmm5

# qhasm:   shuffle bytes of xmm6 by EXPB0
# asm 1: pshufb EXPB0,<xmm6=int6464#7
# asm 2: pshufb EXPB0,<xmm6=%xmm6
pshufb EXPB0,%xmm6

# qhasm:   shuffle bytes of xmm7 by EXPB0
# asm 1: pshufb EXPB0,<xmm7=int6464#8
# asm 2: pshufb EXPB0,<xmm7=%xmm7
pshufb EXPB0,%xmm7

# qhasm:   xmm8 = *(int128 *)(c + 384)
# asm 1: movdqa 384(<c=int64#1),>xmm8=int6464#9
# asm 2: movdqa 384(<c=%rdi),>xmm8=%xmm8
movdqa 384(%rdi),%xmm8

# qhasm:   xmm9 = *(int128 *)(c + 400)
# asm 1: movdqa 400(<c=int64#1),>xmm9=int6464#10
# asm 2: movdqa 400(<c=%rdi),>xmm9=%xmm9
movdqa 400(%rdi),%xmm9

# qhasm:   xmm10 = *(int128 *)(c + 416)
# asm 1: movdqa 416(<c=int64#1),>xmm10=int6464#11
# asm 2: movdqa 416(<c=%rdi),>xmm10=%xmm10
movdqa 416(%rdi),%xmm10

# qhasm:   xmm11 = *(int128 *)(c + 432)
# asm 1: movdqa 432(<c=int64#1),>xmm11=int6464#12
# asm 2: movdqa 432(<c=%rdi),>xmm11=%xmm11
movdqa 432(%rdi),%xmm11

# qhasm:   xmm12 = *(int128 *)(c + 448)
# asm 1: movdqa 448(<c=int64#1),>xmm12=int6464#13
# asm 2: movdqa 448(<c=%rdi),>xmm12=%xmm12
movdqa 448(%rdi),%xmm12

# qhasm:   xmm13 = *(int128 *)(c + 464)
# asm 1: movdqa 464(<c=int64#1),>xmm13=int6464#14
# asm 2: movdqa 464(<c=%rdi),>xmm13=%xmm13
movdqa 464(%rdi),%xmm13

# qhasm:   xmm14 = *(int128 *)(c + 480)
# asm 1: movdqa 480(<c=int64#1),>xmm14=int6464#15
# asm 2: movdqa 480(<c=%rdi),>xmm14=%xmm14
movdqa 480(%rdi),%xmm14

# qhasm:   xmm15 = *(int128 *)(c + 496)
# asm 1: movdqa 496(<c=int64#1),>xmm15=int6464#16
# asm 2: movdqa 496(<c=%rdi),>xmm15=%xmm15
movdqa 496(%rdi),%xmm15

# qhasm:   xmm8 ^= ONE
# asm 1: pxor  ONE,<xmm8=int6464#9
# asm 2: pxor  ONE,<xmm8=%xmm8
pxor  ONE,%xmm8

# qhasm:   xmm9 ^= ONE
# asm 1: pxor  ONE,<xmm9=int6464#10
# asm 2: pxor  ONE,<xmm9=%xmm9
pxor  ONE,%xmm9

# qhasm:   xmm13 ^= ONE
# asm 1: pxor  ONE,<xmm13=int6464#14
# asm 2: pxor  ONE,<xmm13=%xmm13
pxor  ONE,%xmm13

# qhasm:   xmm14 ^= ONE
# asm 1: pxor  ONE,<xmm14=int6464#15
# asm 2: pxor  ONE,<xmm14=%xmm14
pxor  ONE,%xmm14

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#3
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm2
pxor  %xmm10,%xmm2

# qhasm:   xmm3 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm3=int6464#4
# asm 2: pxor  <xmm11=%xmm11,<xmm3=%xmm3
pxor  %xmm11,%xmm3

# qhasm:   xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm4=int6464#5
# asm 2: pxor  <xmm12=%xmm12,<xmm4=%xmm4
pxor  %xmm12,%xmm4

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm6 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm6=int6464#7
# asm 2: pxor  <xmm14=%xmm14,<xmm6=%xmm6
pxor  %xmm14,%xmm6

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#3
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm2
pxor  %xmm10,%xmm2

# qhasm:   xmm3 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm3=int6464#4
# asm 2: pxor  <xmm11=%xmm11,<xmm3=%xmm3
pxor  %xmm11,%xmm3

# qhasm:   xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm4=int6464#5
# asm 2: pxor  <xmm12=%xmm12,<xmm4=%xmm4
pxor  %xmm12,%xmm4

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm6 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm6=int6464#7
# asm 2: pxor  <xmm14=%xmm14,<xmm6=%xmm6
pxor  %xmm14,%xmm6

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#3
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm2
pxor  %xmm10,%xmm2

# qhasm:   xmm3 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm3=int6464#4
# asm 2: pxor  <xmm11=%xmm11,<xmm3=%xmm3
pxor  %xmm11,%xmm3

# qhasm:   xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm4=int6464#5
# asm 2: pxor  <xmm12=%xmm12,<xmm4=%xmm4
pxor  %xmm12,%xmm4

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm6 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm6=int6464#7
# asm 2: pxor  <xmm14=%xmm14,<xmm6=%xmm6
pxor  %xmm14,%xmm6

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#3
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm2
pxor  %xmm10,%xmm2

# qhasm:   xmm3 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm3=int6464#4
# asm 2: pxor  <xmm11=%xmm11,<xmm3=%xmm3
pxor  %xmm11,%xmm3

# qhasm:   xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm4=int6464#5
# asm 2: pxor  <xmm12=%xmm12,<xmm4=%xmm4
pxor  %xmm12,%xmm4

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm6 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm6=int6464#7
# asm 2: pxor  <xmm14=%xmm14,<xmm6=%xmm6
pxor  %xmm14,%xmm6

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   *(int128 *)(c + 512) = xmm0
# asm 1: movdqa <xmm0=int6464#1,512(<c=int64#1)
# asm 2: movdqa <xmm0=%xmm0,512(<c=%rdi)
movdqa %xmm0,512(%rdi)

# qhasm:   *(int128 *)(c + 528) = xmm1
# asm 1: movdqa <xmm1=int6464#2,528(<c=int64#1)
# asm 2: movdqa <xmm1=%xmm1,528(<c=%rdi)
movdqa %xmm1,528(%rdi)

# qhasm:   *(int128 *)(c + 544) = xmm2
# asm 1: movdqa <xmm2=int6464#3,544(<c=int64#1)
# asm 2: movdqa <xmm2=%xmm2,544(<c=%rdi)
movdqa %xmm2,544(%rdi)

# qhasm:   *(int128 *)(c + 560) = xmm3
# asm 1: movdqa <xmm3=int6464#4,560(<c=int64#1)
# asm 2: movdqa <xmm3=%xmm3,560(<c=%rdi)
movdqa %xmm3,560(%rdi)

# qhasm:   *(int128 *)(c + 576) = xmm4
# asm 1: movdqa <xmm4=int6464#5,576(<c=int64#1)
# asm 2: movdqa <xmm4=%xmm4,576(<c=%rdi)
movdqa %xmm4,576(%rdi)

# qhasm:   *(int128 *)(c + 592) = xmm5
# asm 1: movdqa <xmm5=int6464#6,592(<c=int64#1)
# asm 2: movdqa <xmm5=%xmm5,592(<c=%rdi)
movdqa %xmm5,592(%rdi)

# qhasm:   *(int128 *)(c + 608) = xmm6
# asm 1: movdqa <xmm6=int6464#7,608(<c=int64#1)
# asm 2: movdqa <xmm6=%xmm6,608(<c=%rdi)
movdqa %xmm6,608(%rdi)

# qhasm:   *(int128 *)(c + 624) = xmm7
# asm 1: movdqa <xmm7=int6464#8,624(<c=int64#1)
# asm 2: movdqa <xmm7=%xmm7,624(<c=%rdi)
movdqa %xmm7,624(%rdi)

# qhasm:   xmm0 ^= ONE
# asm 1: pxor  ONE,<xmm0=int6464#1
# asm 2: pxor  ONE,<xmm0=%xmm0
pxor  ONE,%xmm0

# qhasm:   xmm1 ^= ONE
# asm 1: pxor  ONE,<xmm1=int6464#2
# asm 2: pxor  ONE,<xmm1=%xmm1
pxor  ONE,%xmm1

# qhasm:   xmm5 ^= ONE
# asm 1: pxor  ONE,<xmm5=int6464#6
# asm 2: pxor  ONE,<xmm5=%xmm5
pxor  ONE,%xmm5

# qhasm:   xmm6 ^= ONE
# asm 1: pxor  ONE,<xmm6=int6464#7
# asm 2: pxor  ONE,<xmm6=%xmm6
pxor  ONE,%xmm6

# qhasm:     shuffle bytes of xmm0 by ROTB
# asm 1: pshufb ROTB,<xmm0=int6464#1
# asm 2: pshufb ROTB,<xmm0=%xmm0
pshufb ROTB,%xmm0

# qhasm:     shuffle bytes of xmm1 by ROTB
# asm 1: pshufb ROTB,<xmm1=int6464#2
# asm 2: pshufb ROTB,<xmm1=%xmm1
pshufb ROTB,%xmm1

# qhasm:     shuffle bytes of xmm2 by ROTB
# asm 1: pshufb ROTB,<xmm2=int6464#3
# asm 2: pshufb ROTB,<xmm2=%xmm2
pshufb ROTB,%xmm2

# qhasm:     shuffle bytes of xmm3 by ROTB
# asm 1: pshufb ROTB,<xmm3=int6464#4
# asm 2: pshufb ROTB,<xmm3=%xmm3
pshufb ROTB,%xmm3

# qhasm:     shuffle bytes of xmm4 by ROTB
# asm 1: pshufb ROTB,<xmm4=int6464#5
# asm 2: pshufb ROTB,<xmm4=%xmm4
pshufb ROTB,%xmm4

# qhasm:     shuffle bytes of xmm5 by ROTB
# asm 1: pshufb ROTB,<xmm5=int6464#6
# asm 2: pshufb ROTB,<xmm5=%xmm5
pshufb ROTB,%xmm5

# qhasm:     shuffle bytes of xmm6 by ROTB
# asm 1: pshufb ROTB,<xmm6=int6464#7
# asm 2: pshufb ROTB,<xmm6=%xmm6
pshufb ROTB,%xmm6

# qhasm:     shuffle bytes of xmm7 by ROTB
# asm 1: pshufb ROTB,<xmm7=int6464#8
# asm 2: pshufb ROTB,<xmm7=%xmm7
pshufb ROTB,%xmm7

# qhasm:       xmm5 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm5=int6464#6
# asm 2: pxor  <xmm6=%xmm6,<xmm5=%xmm5
pxor  %xmm6,%xmm5

# qhasm:       xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm1,<xmm2=%xmm2
pxor  %xmm1,%xmm2

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm5=int6464#6
# asm 2: pxor  <xmm0=%xmm0,<xmm5=%xmm5
pxor  %xmm0,%xmm5

# qhasm:       xmm6 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm6=int6464#7
# asm 2: pxor  <xmm2=%xmm2,<xmm6=%xmm6
pxor  %xmm2,%xmm6

# qhasm:       xmm3 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm3=int6464#4
# asm 2: pxor  <xmm0=%xmm0,<xmm3=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm6=int6464#7
# asm 2: pxor  <xmm3=%xmm3,<xmm6=%xmm6
pxor  %xmm3,%xmm6

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:       xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm3=int6464#4
# asm 2: pxor  <xmm4=%xmm4,<xmm3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:       xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm7=int6464#8
# asm 2: pxor  <xmm5=%xmm5,<xmm7=%xmm7
pxor  %xmm5,%xmm7

# qhasm:       xmm3 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm3=int6464#4
# asm 2: pxor  <xmm1=%xmm1,<xmm3=%xmm3
pxor  %xmm1,%xmm3

# qhasm:       xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm1=int6464#2
# asm 2: pxor  <xmm5=%xmm5,<xmm1=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm11 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm11=int6464#9
# asm 2: movdqa <xmm7=%xmm7,>xmm11=%xmm8
movdqa %xmm7,%xmm8

# qhasm:       xmm10 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm10=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm10=%xmm9
movdqa %xmm1,%xmm9

# qhasm:       xmm9 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm9=int6464#11
# asm 2: movdqa <xmm5=%xmm5,>xmm9=%xmm10
movdqa %xmm5,%xmm10

# qhasm:       xmm13 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm13=int6464#12
# asm 2: movdqa <xmm2=%xmm2,>xmm13=%xmm11
movdqa %xmm2,%xmm11

# qhasm:       xmm12 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm12=int6464#13
# asm 2: movdqa <xmm6=%xmm6,>xmm12=%xmm12
movdqa %xmm6,%xmm12

# qhasm:       xmm11 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm11=int6464#9
# asm 2: pxor  <xmm4=%xmm4,<xmm11=%xmm8
pxor  %xmm4,%xmm8

# qhasm:       xmm10 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm10=int6464#10
# asm 2: pxor  <xmm2=%xmm2,<xmm10=%xmm9
pxor  %xmm2,%xmm9

# qhasm:       xmm9 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm9=int6464#11
# asm 2: pxor  <xmm3=%xmm3,<xmm9=%xmm10
pxor  %xmm3,%xmm10

# qhasm:       xmm13 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm13=int6464#12
# asm 2: pxor  <xmm4=%xmm4,<xmm13=%xmm11
pxor  %xmm4,%xmm11

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:       xmm14 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm14=int6464#14
# asm 2: movdqa <xmm11=%xmm8,>xmm14=%xmm13
movdqa %xmm8,%xmm13

# qhasm:       xmm8 = xmm10
# asm 1: movdqa <xmm10=int6464#10,>xmm8=int6464#15
# asm 2: movdqa <xmm10=%xmm9,>xmm8=%xmm14
movdqa %xmm9,%xmm14

# qhasm:       xmm15 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm15=int6464#16
# asm 2: movdqa <xmm11=%xmm8,>xmm15=%xmm15
movdqa %xmm8,%xmm15

# qhasm:       xmm10 |= xmm9
# asm 1: por   <xmm9=int6464#11,<xmm10=int6464#10
# asm 2: por   <xmm9=%xmm10,<xmm10=%xmm9
por   %xmm10,%xmm9

# qhasm:       xmm11 |= xmm12
# asm 1: por   <xmm12=int6464#13,<xmm11=int6464#9
# asm 2: por   <xmm12=%xmm12,<xmm11=%xmm8
por   %xmm12,%xmm8

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm15=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm14 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm14=int6464#14
# asm 2: pand  <xmm12=%xmm12,<xmm14=%xmm13
pand  %xmm12,%xmm13

# qhasm:       xmm8 &= xmm9
# asm 1: pand  <xmm9=int6464#11,<xmm8=int6464#15
# asm 2: pand  <xmm9=%xmm10,<xmm8=%xmm14
pand  %xmm10,%xmm14

# qhasm:       xmm12 ^= xmm9
# asm 1: pxor  <xmm9=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm9=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:       xmm15 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm15=int6464#16
# asm 2: pand  <xmm12=%xmm12,<xmm15=%xmm15
pand  %xmm12,%xmm15

# qhasm:       xmm12 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm12=int6464#11
# asm 2: movdqa <xmm3=%xmm3,>xmm12=%xmm10
movdqa %xmm3,%xmm10

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#11
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm10
pxor  %xmm0,%xmm10

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#11,<xmm13=int6464#12
# asm 2: pand  <xmm12=%xmm10,<xmm13=%xmm11
pand  %xmm10,%xmm11

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm11=int6464#9
# asm 2: pxor  <xmm13=%xmm11,<xmm11=%xmm8
pxor  %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm13 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm13=int6464#11
# asm 2: movdqa <xmm7=%xmm7,>xmm13=%xmm10
movdqa %xmm7,%xmm10

# qhasm:       xmm13 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm13=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm13=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm12 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm12=int6464#12
# asm 2: movdqa <xmm5=%xmm5,>xmm12=%xmm11
movdqa %xmm5,%xmm11

# qhasm:       xmm9 = xmm13
# asm 1: movdqa <xmm13=int6464#11,>xmm9=int6464#13
# asm 2: movdqa <xmm13=%xmm10,>xmm9=%xmm12
movdqa %xmm10,%xmm12

# qhasm:       xmm12 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm12=int6464#12
# asm 2: pxor  <xmm6=%xmm6,<xmm12=%xmm11
pxor  %xmm6,%xmm11

# qhasm:       xmm9 |= xmm12
# asm 1: por   <xmm12=int6464#12,<xmm9=int6464#13
# asm 2: por   <xmm12=%xmm11,<xmm9=%xmm12
por   %xmm11,%xmm12

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#12,<xmm13=int6464#11
# asm 2: pand  <xmm12=%xmm11,<xmm13=%xmm10
pand  %xmm11,%xmm10

# qhasm:       xmm8 ^= xmm13
# asm 1: pxor  <xmm13=int6464#11,<xmm8=int6464#15
# asm 2: pxor  <xmm13=%xmm10,<xmm8=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#9
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm10=int6464#10
# asm 2: pxor  <xmm14=%xmm13,<xmm10=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm9 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm8 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm8=int6464#15
# asm 2: pxor  <xmm14=%xmm13,<xmm8=%xmm14
pxor  %xmm13,%xmm14

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm12 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm12=int6464#11
# asm 2: movdqa <xmm2=%xmm2,>xmm12=%xmm10
movdqa %xmm2,%xmm10

# qhasm:       xmm13 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm13=int6464#12
# asm 2: movdqa <xmm4=%xmm4,>xmm13=%xmm11
movdqa %xmm4,%xmm11

# qhasm:       xmm14 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm14=int6464#14
# asm 2: movdqa <xmm1=%xmm1,>xmm14=%xmm13
movdqa %xmm1,%xmm13

# qhasm:       xmm15 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm15=int6464#16
# asm 2: movdqa <xmm7=%xmm7,>xmm15=%xmm15
movdqa %xmm7,%xmm15

# qhasm:       xmm12 &= xmm3
# asm 1: pand  <xmm3=int6464#4,<xmm12=int6464#11
# asm 2: pand  <xmm3=%xmm3,<xmm12=%xmm10
pand  %xmm3,%xmm10

# qhasm:       xmm13 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm13=int6464#12
# asm 2: pand  <xmm0=%xmm0,<xmm13=%xmm11
pand  %xmm0,%xmm11

# qhasm:       xmm14 &= xmm5
# asm 1: pand  <xmm5=int6464#6,<xmm14=int6464#14
# asm 2: pand  <xmm5=%xmm5,<xmm14=%xmm13
pand  %xmm5,%xmm13

# qhasm:       xmm15 |= xmm6
# asm 1: por   <xmm6=int6464#7,<xmm15=int6464#16
# asm 2: por   <xmm6=%xmm6,<xmm15=%xmm15
por   %xmm6,%xmm15

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm11=int6464#9
# asm 2: pxor  <xmm12=%xmm10,<xmm11=%xmm8
pxor  %xmm10,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm8 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm8=int6464#15
# asm 2: pxor  <xmm15=%xmm15,<xmm8=%xmm14
pxor  %xmm15,%xmm14

# qhasm:       xmm12 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm12=int6464#11
# asm 2: movdqa <xmm11=%xmm8,>xmm12=%xmm10
movdqa %xmm8,%xmm10

# qhasm:       xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm12=int6464#11
# asm 2: pxor  <xmm10=%xmm9,<xmm12=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm11 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm11=int6464#9
# asm 2: pand  <xmm9=%xmm12,<xmm11=%xmm8
pand  %xmm12,%xmm8

# qhasm:       xmm14 = xmm8
# asm 1: movdqa <xmm8=int6464#15,>xmm14=int6464#12
# asm 2: movdqa <xmm8=%xmm14,>xmm14=%xmm11
movdqa %xmm14,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm11=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm15 = xmm12
# asm 1: movdqa <xmm12=int6464#11,>xmm15=int6464#14
# asm 2: movdqa <xmm12=%xmm10,>xmm15=%xmm13
movdqa %xmm10,%xmm13

# qhasm:       xmm15 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm15=int6464#14
# asm 2: pand  <xmm14=%xmm11,<xmm15=%xmm13
pand  %xmm11,%xmm13

# qhasm:       xmm15 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm15=int6464#14
# asm 2: pxor  <xmm10=%xmm9,<xmm15=%xmm13
pxor  %xmm9,%xmm13

# qhasm:       xmm13 = xmm9
# asm 1: movdqa <xmm9=int6464#13,>xmm13=int6464#16
# asm 2: movdqa <xmm9=%xmm12,>xmm13=%xmm15
movdqa %xmm12,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm11 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm11=int6464#9
# asm 2: pxor  <xmm10=%xmm9,<xmm11=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm13 &= xmm11
# asm 1: pand  <xmm11=int6464#9,<xmm13=int6464#16
# asm 2: pand  <xmm11=%xmm8,<xmm13=%xmm15
pand  %xmm8,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm13=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm10 = xmm14
# asm 1: movdqa <xmm14=int6464#12,>xmm10=int6464#9
# asm 2: movdqa <xmm14=%xmm11,>xmm10=%xmm8
movdqa %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm10=int6464#9
# asm 2: pxor  <xmm13=%xmm15,<xmm10=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 &= xmm8
# asm 1: pand  <xmm8=int6464#15,<xmm10=int6464#9
# asm 2: pand  <xmm8=%xmm14,<xmm10=%xmm8
pand  %xmm14,%xmm8

# qhasm:       xmm9 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm9=int6464#13
# asm 2: pxor  <xmm10=%xmm8,<xmm9=%xmm12
pxor  %xmm8,%xmm12

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm10=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm14=int6464#12
# asm 2: pand  <xmm15=%xmm13,<xmm14=%xmm11
pand  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm14=int6464#12
# asm 2: pxor  <xmm12=%xmm10,<xmm14=%xmm11
pxor  %xmm10,%xmm11

# qhasm:         xmm12 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm12=int6464#9
# asm 2: movdqa <xmm6=%xmm6,>xmm12=%xmm8
movdqa %xmm6,%xmm8

# qhasm:         xmm8 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm8=int6464#10
# asm 2: movdqa <xmm5=%xmm5,>xmm8=%xmm9
movdqa %xmm5,%xmm9

# qhasm:           xmm10 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm10=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm10=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm10 &= xmm6
# asm 1: pand  <xmm6=int6464#7,<xmm10=int6464#11
# asm 2: pand  <xmm6=%xmm6,<xmm10=%xmm10
pand  %xmm6,%xmm10

# qhasm:           xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:           xmm6 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm6=int6464#7
# asm 2: pand  <xmm14=%xmm11,<xmm6=%xmm6
pand  %xmm11,%xmm6

# qhasm:           xmm5 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm5=int6464#6
# asm 2: pand  <xmm15=%xmm13,<xmm5=%xmm5
pand  %xmm13,%xmm5

# qhasm:           xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:           xmm5 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm5=int6464#6
# asm 2: pxor  <xmm10=%xmm10,<xmm5=%xmm5
pxor  %xmm10,%xmm5

# qhasm:         xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm8 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm8=int6464#10
# asm 2: pxor  <xmm3=%xmm3,<xmm8=%xmm9
pxor  %xmm3,%xmm9

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm10=int6464#11
# asm 2: pand  <xmm0=%xmm0,<xmm10=%xmm10
pand  %xmm0,%xmm10

# qhasm:           xmm0 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm0=int6464#1
# asm 2: pxor  <xmm3=%xmm3,<xmm0=%xmm0
pxor  %xmm3,%xmm0

# qhasm:           xmm0 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm0=int6464#1
# asm 2: pand  <xmm9=%xmm12,<xmm0=%xmm0
pand  %xmm12,%xmm0

# qhasm:           xmm3 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm3=int6464#4
# asm 2: pand  <xmm13=%xmm15,<xmm3=%xmm3
pand  %xmm15,%xmm3

# qhasm:           xmm0 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm0=int6464#1
# asm 2: pxor  <xmm3=%xmm3,<xmm0=%xmm0
pxor  %xmm3,%xmm0

# qhasm:           xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:         xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm8,<xmm6=%xmm6
pxor  %xmm8,%xmm6

# qhasm:         xmm0 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm12=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm5 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm5=int6464#6
# asm 2: pxor  <xmm8=%xmm9,<xmm5=%xmm5
pxor  %xmm9,%xmm5

# qhasm:         xmm3 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm3=int6464#4
# asm 2: pxor  <xmm8=%xmm9,<xmm3=%xmm3
pxor  %xmm9,%xmm3

# qhasm:         xmm12 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm12=int6464#9
# asm 2: movdqa <xmm7=%xmm7,>xmm12=%xmm8
movdqa %xmm7,%xmm8

# qhasm:         xmm8 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm8=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm8=%xmm9
movdqa %xmm1,%xmm9

# qhasm:         xmm12 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm12=int6464#9
# asm 2: pxor  <xmm4=%xmm4,<xmm12=%xmm8
pxor  %xmm4,%xmm8

# qhasm:         xmm8 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm8=int6464#10
# asm 2: pxor  <xmm2=%xmm2,<xmm8=%xmm9
pxor  %xmm2,%xmm9

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm10=int6464#11
# asm 2: pand  <xmm4=%xmm4,<xmm10=%xmm10
pand  %xmm4,%xmm10

# qhasm:           xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm2=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:           xmm4 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm4=int6464#5
# asm 2: pand  <xmm9=%xmm12,<xmm4=%xmm4
pand  %xmm12,%xmm4

# qhasm:           xmm2 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm2=int6464#3
# asm 2: pand  <xmm13=%xmm15,<xmm2=%xmm2
pand  %xmm15,%xmm2

# qhasm:           xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm2=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:           xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#3
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm2
pxor  %xmm10,%xmm2

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm7
# asm 1: pand  <xmm7=int6464#8,<xmm11=int6464#11
# asm 2: pand  <xmm7=%xmm7,<xmm11=%xmm10
pand  %xmm7,%xmm10

# qhasm:           xmm7 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm7=int6464#8
# asm 2: pxor  <xmm1=%xmm1,<xmm7=%xmm7
pxor  %xmm1,%xmm7

# qhasm:           xmm7 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm7=int6464#8
# asm 2: pand  <xmm14=%xmm11,<xmm7=%xmm7
pand  %xmm11,%xmm7

# qhasm:           xmm1 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm1=int6464#2
# asm 2: pand  <xmm15=%xmm13,<xmm1=%xmm1
pand  %xmm13,%xmm1

# qhasm:           xmm7 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm7=int6464#8
# asm 2: pxor  <xmm1=%xmm1,<xmm7=%xmm7
pxor  %xmm1,%xmm7

# qhasm:           xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm1=int6464#2
# asm 2: pxor  <xmm11=%xmm10,<xmm1=%xmm1
pxor  %xmm10,%xmm1

# qhasm:         xmm7 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm7=int6464#8
# asm 2: pxor  <xmm12=%xmm8,<xmm7=%xmm7
pxor  %xmm8,%xmm7

# qhasm:         xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <xmm12=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:         xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:         xmm2 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm2=int6464#3
# asm 2: pxor  <xmm8=%xmm9,<xmm2=%xmm2
pxor  %xmm9,%xmm2

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm0,<xmm7=%xmm7
pxor  %xmm0,%xmm7

# qhasm:       xmm1 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm1=int6464#2
# asm 2: pxor  <xmm6=%xmm6,<xmm1=%xmm1
pxor  %xmm6,%xmm1

# qhasm:       xmm4 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm4=int6464#5
# asm 2: pxor  <xmm7=%xmm7,<xmm4=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm6 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm6=int6464#7
# asm 2: pxor  <xmm0=%xmm0,<xmm6=%xmm6
pxor  %xmm0,%xmm6

# qhasm:       xmm0 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm0=int6464#1
# asm 2: pxor  <xmm1=%xmm1,<xmm0=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm1=int6464#2
# asm 2: pxor  <xmm5=%xmm5,<xmm1=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm5 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm5=int6464#6
# asm 2: pxor  <xmm2=%xmm2,<xmm5=%xmm5
pxor  %xmm2,%xmm5

# qhasm:       xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm2 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm2=int6464#3
# asm 2: pxor  <xmm3=%xmm3,<xmm2=%xmm2
pxor  %xmm3,%xmm2

# qhasm:       xmm3 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm3=int6464#4
# asm 2: pxor  <xmm5=%xmm5,<xmm3=%xmm3
pxor  %xmm5,%xmm3

# qhasm:       xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm6=int6464#7
# asm 2: pxor  <xmm3=%xmm3,<xmm6=%xmm6
pxor  %xmm3,%xmm6

# qhasm:   xmm3 ^= RCON
# asm 1: pxor  RCON,<xmm3=int6464#4
# asm 2: pxor  RCON,<xmm3=%xmm3
pxor  RCON,%xmm3

# qhasm:   shuffle bytes of xmm0 by EXPB0
# asm 1: pshufb EXPB0,<xmm0=int6464#1
# asm 2: pshufb EXPB0,<xmm0=%xmm0
pshufb EXPB0,%xmm0

# qhasm:   shuffle bytes of xmm1 by EXPB0
# asm 1: pshufb EXPB0,<xmm1=int6464#2
# asm 2: pshufb EXPB0,<xmm1=%xmm1
pshufb EXPB0,%xmm1

# qhasm:   shuffle bytes of xmm4 by EXPB0
# asm 1: pshufb EXPB0,<xmm4=int6464#5
# asm 2: pshufb EXPB0,<xmm4=%xmm4
pshufb EXPB0,%xmm4

# qhasm:   shuffle bytes of xmm6 by EXPB0
# asm 1: pshufb EXPB0,<xmm6=int6464#7
# asm 2: pshufb EXPB0,<xmm6=%xmm6
pshufb EXPB0,%xmm6

# qhasm:   shuffle bytes of xmm3 by EXPB0
# asm 1: pshufb EXPB0,<xmm3=int6464#4
# asm 2: pshufb EXPB0,<xmm3=%xmm3
pshufb EXPB0,%xmm3

# qhasm:   shuffle bytes of xmm7 by EXPB0
# asm 1: pshufb EXPB0,<xmm7=int6464#8
# asm 2: pshufb EXPB0,<xmm7=%xmm7
pshufb EXPB0,%xmm7

# qhasm:   shuffle bytes of xmm2 by EXPB0
# asm 1: pshufb EXPB0,<xmm2=int6464#3
# asm 2: pshufb EXPB0,<xmm2=%xmm2
pshufb EXPB0,%xmm2

# qhasm:   shuffle bytes of xmm5 by EXPB0
# asm 1: pshufb EXPB0,<xmm5=int6464#6
# asm 2: pshufb EXPB0,<xmm5=%xmm5
pshufb EXPB0,%xmm5

# qhasm:   xmm8 = *(int128 *)(c + 512)
# asm 1: movdqa 512(<c=int64#1),>xmm8=int6464#9
# asm 2: movdqa 512(<c=%rdi),>xmm8=%xmm8
movdqa 512(%rdi),%xmm8

# qhasm:   xmm9 = *(int128 *)(c + 528)
# asm 1: movdqa 528(<c=int64#1),>xmm9=int6464#10
# asm 2: movdqa 528(<c=%rdi),>xmm9=%xmm9
movdqa 528(%rdi),%xmm9

# qhasm:   xmm10 = *(int128 *)(c + 544)
# asm 1: movdqa 544(<c=int64#1),>xmm10=int6464#11
# asm 2: movdqa 544(<c=%rdi),>xmm10=%xmm10
movdqa 544(%rdi),%xmm10

# qhasm:   xmm11 = *(int128 *)(c + 560)
# asm 1: movdqa 560(<c=int64#1),>xmm11=int6464#12
# asm 2: movdqa 560(<c=%rdi),>xmm11=%xmm11
movdqa 560(%rdi),%xmm11

# qhasm:   xmm12 = *(int128 *)(c + 576)
# asm 1: movdqa 576(<c=int64#1),>xmm12=int6464#13
# asm 2: movdqa 576(<c=%rdi),>xmm12=%xmm12
movdqa 576(%rdi),%xmm12

# qhasm:   xmm13 = *(int128 *)(c + 592)
# asm 1: movdqa 592(<c=int64#1),>xmm13=int6464#14
# asm 2: movdqa 592(<c=%rdi),>xmm13=%xmm13
movdqa 592(%rdi),%xmm13

# qhasm:   xmm14 = *(int128 *)(c + 608)
# asm 1: movdqa 608(<c=int64#1),>xmm14=int6464#15
# asm 2: movdqa 608(<c=%rdi),>xmm14=%xmm14
movdqa 608(%rdi),%xmm14

# qhasm:   xmm15 = *(int128 *)(c + 624)
# asm 1: movdqa 624(<c=int64#1),>xmm15=int6464#16
# asm 2: movdqa 624(<c=%rdi),>xmm15=%xmm15
movdqa 624(%rdi),%xmm15

# qhasm:   xmm8 ^= ONE
# asm 1: pxor  ONE,<xmm8=int6464#9
# asm 2: pxor  ONE,<xmm8=%xmm8
pxor  ONE,%xmm8

# qhasm:   xmm9 ^= ONE
# asm 1: pxor  ONE,<xmm9=int6464#10
# asm 2: pxor  ONE,<xmm9=%xmm9
pxor  ONE,%xmm9

# qhasm:   xmm13 ^= ONE
# asm 1: pxor  ONE,<xmm13=int6464#14
# asm 2: pxor  ONE,<xmm13=%xmm13
pxor  ONE,%xmm13

# qhasm:   xmm14 ^= ONE
# asm 1: pxor  ONE,<xmm14=int6464#15
# asm 2: pxor  ONE,<xmm14=%xmm14
pxor  ONE,%xmm14

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:   xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:   xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:   xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:   xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:   xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:   xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:   xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:   xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   *(int128 *)(c + 640) = xmm0
# asm 1: movdqa <xmm0=int6464#1,640(<c=int64#1)
# asm 2: movdqa <xmm0=%xmm0,640(<c=%rdi)
movdqa %xmm0,640(%rdi)

# qhasm:   *(int128 *)(c + 656) = xmm1
# asm 1: movdqa <xmm1=int6464#2,656(<c=int64#1)
# asm 2: movdqa <xmm1=%xmm1,656(<c=%rdi)
movdqa %xmm1,656(%rdi)

# qhasm:   *(int128 *)(c + 672) = xmm4
# asm 1: movdqa <xmm4=int6464#5,672(<c=int64#1)
# asm 2: movdqa <xmm4=%xmm4,672(<c=%rdi)
movdqa %xmm4,672(%rdi)

# qhasm:   *(int128 *)(c + 688) = xmm6
# asm 1: movdqa <xmm6=int6464#7,688(<c=int64#1)
# asm 2: movdqa <xmm6=%xmm6,688(<c=%rdi)
movdqa %xmm6,688(%rdi)

# qhasm:   *(int128 *)(c + 704) = xmm3
# asm 1: movdqa <xmm3=int6464#4,704(<c=int64#1)
# asm 2: movdqa <xmm3=%xmm3,704(<c=%rdi)
movdqa %xmm3,704(%rdi)

# qhasm:   *(int128 *)(c + 720) = xmm7
# asm 1: movdqa <xmm7=int6464#8,720(<c=int64#1)
# asm 2: movdqa <xmm7=%xmm7,720(<c=%rdi)
movdqa %xmm7,720(%rdi)

# qhasm:   *(int128 *)(c + 736) = xmm2
# asm 1: movdqa <xmm2=int6464#3,736(<c=int64#1)
# asm 2: movdqa <xmm2=%xmm2,736(<c=%rdi)
movdqa %xmm2,736(%rdi)

# qhasm:   *(int128 *)(c + 752) = xmm5
# asm 1: movdqa <xmm5=int6464#6,752(<c=int64#1)
# asm 2: movdqa <xmm5=%xmm5,752(<c=%rdi)
movdqa %xmm5,752(%rdi)

# qhasm:   xmm0 ^= ONE
# asm 1: pxor  ONE,<xmm0=int6464#1
# asm 2: pxor  ONE,<xmm0=%xmm0
pxor  ONE,%xmm0

# qhasm:   xmm1 ^= ONE
# asm 1: pxor  ONE,<xmm1=int6464#2
# asm 2: pxor  ONE,<xmm1=%xmm1
pxor  ONE,%xmm1

# qhasm:   xmm7 ^= ONE
# asm 1: pxor  ONE,<xmm7=int6464#8
# asm 2: pxor  ONE,<xmm7=%xmm7
pxor  ONE,%xmm7

# qhasm:   xmm2 ^= ONE
# asm 1: pxor  ONE,<xmm2=int6464#3
# asm 2: pxor  ONE,<xmm2=%xmm2
pxor  ONE,%xmm2

# qhasm:     shuffle bytes of xmm0 by ROTB
# asm 1: pshufb ROTB,<xmm0=int6464#1
# asm 2: pshufb ROTB,<xmm0=%xmm0
pshufb ROTB,%xmm0

# qhasm:     shuffle bytes of xmm1 by ROTB
# asm 1: pshufb ROTB,<xmm1=int6464#2
# asm 2: pshufb ROTB,<xmm1=%xmm1
pshufb ROTB,%xmm1

# qhasm:     shuffle bytes of xmm4 by ROTB
# asm 1: pshufb ROTB,<xmm4=int6464#5
# asm 2: pshufb ROTB,<xmm4=%xmm4
pshufb ROTB,%xmm4

# qhasm:     shuffle bytes of xmm6 by ROTB
# asm 1: pshufb ROTB,<xmm6=int6464#7
# asm 2: pshufb ROTB,<xmm6=%xmm6
pshufb ROTB,%xmm6

# qhasm:     shuffle bytes of xmm3 by ROTB
# asm 1: pshufb ROTB,<xmm3=int6464#4
# asm 2: pshufb ROTB,<xmm3=%xmm3
pshufb ROTB,%xmm3

# qhasm:     shuffle bytes of xmm7 by ROTB
# asm 1: pshufb ROTB,<xmm7=int6464#8
# asm 2: pshufb ROTB,<xmm7=%xmm7
pshufb ROTB,%xmm7

# qhasm:     shuffle bytes of xmm2 by ROTB
# asm 1: pshufb ROTB,<xmm2=int6464#3
# asm 2: pshufb ROTB,<xmm2=%xmm2
pshufb ROTB,%xmm2

# qhasm:     shuffle bytes of xmm5 by ROTB
# asm 1: pshufb ROTB,<xmm5=int6464#6
# asm 2: pshufb ROTB,<xmm5=%xmm5
pshufb ROTB,%xmm5

# qhasm:       xmm7 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm7=int6464#8
# asm 2: pxor  <xmm2=%xmm2,<xmm7=%xmm7
pxor  %xmm2,%xmm7

# qhasm:       xmm4 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm4=int6464#5
# asm 2: pxor  <xmm1=%xmm1,<xmm4=%xmm4
pxor  %xmm1,%xmm4

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm0,<xmm7=%xmm7
pxor  %xmm0,%xmm7

# qhasm:       xmm2 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm2=int6464#3
# asm 2: pxor  <xmm4=%xmm4,<xmm2=%xmm2
pxor  %xmm4,%xmm2

# qhasm:       xmm6 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm6=int6464#7
# asm 2: pxor  <xmm0=%xmm0,<xmm6=%xmm6
pxor  %xmm0,%xmm6

# qhasm:       xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm6,<xmm2=%xmm2
pxor  %xmm6,%xmm2

# qhasm:       xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:       xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm6=int6464#7
# asm 2: pxor  <xmm3=%xmm3,<xmm6=%xmm6
pxor  %xmm3,%xmm6

# qhasm:       xmm5 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm5=int6464#6
# asm 2: pxor  <xmm7=%xmm7,<xmm5=%xmm5
pxor  %xmm7,%xmm5

# qhasm:       xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm6=int6464#7
# asm 2: pxor  <xmm1=%xmm1,<xmm6=%xmm6
pxor  %xmm1,%xmm6

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:       xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#2
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm1
pxor  %xmm7,%xmm1

# qhasm:       xmm11 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm11=int6464#9
# asm 2: movdqa <xmm5=%xmm5,>xmm11=%xmm8
movdqa %xmm5,%xmm8

# qhasm:       xmm10 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm10=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm10=%xmm9
movdqa %xmm1,%xmm9

# qhasm:       xmm9 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm9=int6464#11
# asm 2: movdqa <xmm7=%xmm7,>xmm9=%xmm10
movdqa %xmm7,%xmm10

# qhasm:       xmm13 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm13=int6464#12
# asm 2: movdqa <xmm4=%xmm4,>xmm13=%xmm11
movdqa %xmm4,%xmm11

# qhasm:       xmm12 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm12=int6464#13
# asm 2: movdqa <xmm2=%xmm2,>xmm12=%xmm12
movdqa %xmm2,%xmm12

# qhasm:       xmm11 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm11=int6464#9
# asm 2: pxor  <xmm3=%xmm3,<xmm11=%xmm8
pxor  %xmm3,%xmm8

# qhasm:       xmm10 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm10=int6464#10
# asm 2: pxor  <xmm4=%xmm4,<xmm10=%xmm9
pxor  %xmm4,%xmm9

# qhasm:       xmm9 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm9=int6464#11
# asm 2: pxor  <xmm6=%xmm6,<xmm9=%xmm10
pxor  %xmm6,%xmm10

# qhasm:       xmm13 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm13=int6464#12
# asm 2: pxor  <xmm3=%xmm3,<xmm13=%xmm11
pxor  %xmm3,%xmm11

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:       xmm14 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm14=int6464#14
# asm 2: movdqa <xmm11=%xmm8,>xmm14=%xmm13
movdqa %xmm8,%xmm13

# qhasm:       xmm8 = xmm10
# asm 1: movdqa <xmm10=int6464#10,>xmm8=int6464#15
# asm 2: movdqa <xmm10=%xmm9,>xmm8=%xmm14
movdqa %xmm9,%xmm14

# qhasm:       xmm15 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm15=int6464#16
# asm 2: movdqa <xmm11=%xmm8,>xmm15=%xmm15
movdqa %xmm8,%xmm15

# qhasm:       xmm10 |= xmm9
# asm 1: por   <xmm9=int6464#11,<xmm10=int6464#10
# asm 2: por   <xmm9=%xmm10,<xmm10=%xmm9
por   %xmm10,%xmm9

# qhasm:       xmm11 |= xmm12
# asm 1: por   <xmm12=int6464#13,<xmm11=int6464#9
# asm 2: por   <xmm12=%xmm12,<xmm11=%xmm8
por   %xmm12,%xmm8

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm15=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm14 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm14=int6464#14
# asm 2: pand  <xmm12=%xmm12,<xmm14=%xmm13
pand  %xmm12,%xmm13

# qhasm:       xmm8 &= xmm9
# asm 1: pand  <xmm9=int6464#11,<xmm8=int6464#15
# asm 2: pand  <xmm9=%xmm10,<xmm8=%xmm14
pand  %xmm10,%xmm14

# qhasm:       xmm12 ^= xmm9
# asm 1: pxor  <xmm9=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm9=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:       xmm15 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm15=int6464#16
# asm 2: pand  <xmm12=%xmm12,<xmm15=%xmm15
pand  %xmm12,%xmm15

# qhasm:       xmm12 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm12=int6464#11
# asm 2: movdqa <xmm6=%xmm6,>xmm12=%xmm10
movdqa %xmm6,%xmm10

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#11
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm10
pxor  %xmm0,%xmm10

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#11,<xmm13=int6464#12
# asm 2: pand  <xmm12=%xmm10,<xmm13=%xmm11
pand  %xmm10,%xmm11

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm11=int6464#9
# asm 2: pxor  <xmm13=%xmm11,<xmm11=%xmm8
pxor  %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm13 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm13=int6464#11
# asm 2: movdqa <xmm5=%xmm5,>xmm13=%xmm10
movdqa %xmm5,%xmm10

# qhasm:       xmm13 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm13=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm13=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm12 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm12=int6464#12
# asm 2: movdqa <xmm7=%xmm7,>xmm12=%xmm11
movdqa %xmm7,%xmm11

# qhasm:       xmm9 = xmm13
# asm 1: movdqa <xmm13=int6464#11,>xmm9=int6464#13
# asm 2: movdqa <xmm13=%xmm10,>xmm9=%xmm12
movdqa %xmm10,%xmm12

# qhasm:       xmm12 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm12=int6464#12
# asm 2: pxor  <xmm2=%xmm2,<xmm12=%xmm11
pxor  %xmm2,%xmm11

# qhasm:       xmm9 |= xmm12
# asm 1: por   <xmm12=int6464#12,<xmm9=int6464#13
# asm 2: por   <xmm12=%xmm11,<xmm9=%xmm12
por   %xmm11,%xmm12

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#12,<xmm13=int6464#11
# asm 2: pand  <xmm12=%xmm11,<xmm13=%xmm10
pand  %xmm11,%xmm10

# qhasm:       xmm8 ^= xmm13
# asm 1: pxor  <xmm13=int6464#11,<xmm8=int6464#15
# asm 2: pxor  <xmm13=%xmm10,<xmm8=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#9
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm10=int6464#10
# asm 2: pxor  <xmm14=%xmm13,<xmm10=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm9 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm8 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm8=int6464#15
# asm 2: pxor  <xmm14=%xmm13,<xmm8=%xmm14
pxor  %xmm13,%xmm14

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm12 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm12=int6464#11
# asm 2: movdqa <xmm4=%xmm4,>xmm12=%xmm10
movdqa %xmm4,%xmm10

# qhasm:       xmm13 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm13=int6464#12
# asm 2: movdqa <xmm3=%xmm3,>xmm13=%xmm11
movdqa %xmm3,%xmm11

# qhasm:       xmm14 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm14=int6464#14
# asm 2: movdqa <xmm1=%xmm1,>xmm14=%xmm13
movdqa %xmm1,%xmm13

# qhasm:       xmm15 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm15=int6464#16
# asm 2: movdqa <xmm5=%xmm5,>xmm15=%xmm15
movdqa %xmm5,%xmm15

# qhasm:       xmm12 &= xmm6
# asm 1: pand  <xmm6=int6464#7,<xmm12=int6464#11
# asm 2: pand  <xmm6=%xmm6,<xmm12=%xmm10
pand  %xmm6,%xmm10

# qhasm:       xmm13 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm13=int6464#12
# asm 2: pand  <xmm0=%xmm0,<xmm13=%xmm11
pand  %xmm0,%xmm11

# qhasm:       xmm14 &= xmm7
# asm 1: pand  <xmm7=int6464#8,<xmm14=int6464#14
# asm 2: pand  <xmm7=%xmm7,<xmm14=%xmm13
pand  %xmm7,%xmm13

# qhasm:       xmm15 |= xmm2
# asm 1: por   <xmm2=int6464#3,<xmm15=int6464#16
# asm 2: por   <xmm2=%xmm2,<xmm15=%xmm15
por   %xmm2,%xmm15

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm11=int6464#9
# asm 2: pxor  <xmm12=%xmm10,<xmm11=%xmm8
pxor  %xmm10,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm8 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm8=int6464#15
# asm 2: pxor  <xmm15=%xmm15,<xmm8=%xmm14
pxor  %xmm15,%xmm14

# qhasm:       xmm12 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm12=int6464#11
# asm 2: movdqa <xmm11=%xmm8,>xmm12=%xmm10
movdqa %xmm8,%xmm10

# qhasm:       xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm12=int6464#11
# asm 2: pxor  <xmm10=%xmm9,<xmm12=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm11 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm11=int6464#9
# asm 2: pand  <xmm9=%xmm12,<xmm11=%xmm8
pand  %xmm12,%xmm8

# qhasm:       xmm14 = xmm8
# asm 1: movdqa <xmm8=int6464#15,>xmm14=int6464#12
# asm 2: movdqa <xmm8=%xmm14,>xmm14=%xmm11
movdqa %xmm14,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm11=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm15 = xmm12
# asm 1: movdqa <xmm12=int6464#11,>xmm15=int6464#14
# asm 2: movdqa <xmm12=%xmm10,>xmm15=%xmm13
movdqa %xmm10,%xmm13

# qhasm:       xmm15 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm15=int6464#14
# asm 2: pand  <xmm14=%xmm11,<xmm15=%xmm13
pand  %xmm11,%xmm13

# qhasm:       xmm15 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm15=int6464#14
# asm 2: pxor  <xmm10=%xmm9,<xmm15=%xmm13
pxor  %xmm9,%xmm13

# qhasm:       xmm13 = xmm9
# asm 1: movdqa <xmm9=int6464#13,>xmm13=int6464#16
# asm 2: movdqa <xmm9=%xmm12,>xmm13=%xmm15
movdqa %xmm12,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm11 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm11=int6464#9
# asm 2: pxor  <xmm10=%xmm9,<xmm11=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm13 &= xmm11
# asm 1: pand  <xmm11=int6464#9,<xmm13=int6464#16
# asm 2: pand  <xmm11=%xmm8,<xmm13=%xmm15
pand  %xmm8,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm13=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm10 = xmm14
# asm 1: movdqa <xmm14=int6464#12,>xmm10=int6464#9
# asm 2: movdqa <xmm14=%xmm11,>xmm10=%xmm8
movdqa %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm10=int6464#9
# asm 2: pxor  <xmm13=%xmm15,<xmm10=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 &= xmm8
# asm 1: pand  <xmm8=int6464#15,<xmm10=int6464#9
# asm 2: pand  <xmm8=%xmm14,<xmm10=%xmm8
pand  %xmm14,%xmm8

# qhasm:       xmm9 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm9=int6464#13
# asm 2: pxor  <xmm10=%xmm8,<xmm9=%xmm12
pxor  %xmm8,%xmm12

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm10=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm14=int6464#12
# asm 2: pand  <xmm15=%xmm13,<xmm14=%xmm11
pand  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm14=int6464#12
# asm 2: pxor  <xmm12=%xmm10,<xmm14=%xmm11
pxor  %xmm10,%xmm11

# qhasm:         xmm12 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm12=int6464#9
# asm 2: movdqa <xmm2=%xmm2,>xmm12=%xmm8
movdqa %xmm2,%xmm8

# qhasm:         xmm8 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm8=int6464#10
# asm 2: movdqa <xmm7=%xmm7,>xmm8=%xmm9
movdqa %xmm7,%xmm9

# qhasm:           xmm10 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm10=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm10=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm10 &= xmm2
# asm 1: pand  <xmm2=int6464#3,<xmm10=int6464#11
# asm 2: pand  <xmm2=%xmm2,<xmm10=%xmm10
pand  %xmm2,%xmm10

# qhasm:           xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:           xmm2 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm2=int6464#3
# asm 2: pand  <xmm14=%xmm11,<xmm2=%xmm2
pand  %xmm11,%xmm2

# qhasm:           xmm7 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm7=int6464#8
# asm 2: pand  <xmm15=%xmm13,<xmm7=%xmm7
pand  %xmm13,%xmm7

# qhasm:           xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:           xmm7 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm7=int6464#8
# asm 2: pxor  <xmm10=%xmm10,<xmm7=%xmm7
pxor  %xmm10,%xmm7

# qhasm:         xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm8 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm8=int6464#10
# asm 2: pxor  <xmm6=%xmm6,<xmm8=%xmm9
pxor  %xmm6,%xmm9

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm10=int6464#11
# asm 2: pand  <xmm0=%xmm0,<xmm10=%xmm10
pand  %xmm0,%xmm10

# qhasm:           xmm0 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm0=int6464#1
# asm 2: pxor  <xmm6=%xmm6,<xmm0=%xmm0
pxor  %xmm6,%xmm0

# qhasm:           xmm0 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm0=int6464#1
# asm 2: pand  <xmm9=%xmm12,<xmm0=%xmm0
pand  %xmm12,%xmm0

# qhasm:           xmm6 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm6=int6464#7
# asm 2: pand  <xmm13=%xmm15,<xmm6=%xmm6
pand  %xmm15,%xmm6

# qhasm:           xmm0 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm0=int6464#1
# asm 2: pxor  <xmm6=%xmm6,<xmm0=%xmm0
pxor  %xmm6,%xmm0

# qhasm:           xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:         xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm8,<xmm2=%xmm2
pxor  %xmm8,%xmm2

# qhasm:         xmm0 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm12=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm7 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm7=int6464#8
# asm 2: pxor  <xmm8=%xmm9,<xmm7=%xmm7
pxor  %xmm9,%xmm7

# qhasm:         xmm6 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm6=int6464#7
# asm 2: pxor  <xmm8=%xmm9,<xmm6=%xmm6
pxor  %xmm9,%xmm6

# qhasm:         xmm12 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm12=int6464#9
# asm 2: movdqa <xmm5=%xmm5,>xmm12=%xmm8
movdqa %xmm5,%xmm8

# qhasm:         xmm8 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm8=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm8=%xmm9
movdqa %xmm1,%xmm9

# qhasm:         xmm12 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm12=int6464#9
# asm 2: pxor  <xmm3=%xmm3,<xmm12=%xmm8
pxor  %xmm3,%xmm8

# qhasm:         xmm8 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm8=int6464#10
# asm 2: pxor  <xmm4=%xmm4,<xmm8=%xmm9
pxor  %xmm4,%xmm9

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm3
# asm 1: pand  <xmm3=int6464#4,<xmm10=int6464#11
# asm 2: pand  <xmm3=%xmm3,<xmm10=%xmm10
pand  %xmm3,%xmm10

# qhasm:           xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm3=int6464#4
# asm 2: pxor  <xmm4=%xmm4,<xmm3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm3 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm3=int6464#4
# asm 2: pand  <xmm9=%xmm12,<xmm3=%xmm3
pand  %xmm12,%xmm3

# qhasm:           xmm4 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm4=int6464#5
# asm 2: pand  <xmm13=%xmm15,<xmm4=%xmm4
pand  %xmm15,%xmm4

# qhasm:           xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm3=int6464#4
# asm 2: pxor  <xmm4=%xmm4,<xmm3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm5
# asm 1: pand  <xmm5=int6464#6,<xmm11=int6464#11
# asm 2: pand  <xmm5=%xmm5,<xmm11=%xmm10
pand  %xmm5,%xmm10

# qhasm:           xmm5 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm5=int6464#6
# asm 2: pxor  <xmm1=%xmm1,<xmm5=%xmm5
pxor  %xmm1,%xmm5

# qhasm:           xmm5 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm5=int6464#6
# asm 2: pand  <xmm14=%xmm11,<xmm5=%xmm5
pand  %xmm11,%xmm5

# qhasm:           xmm1 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm1=int6464#2
# asm 2: pand  <xmm15=%xmm13,<xmm1=%xmm1
pand  %xmm13,%xmm1

# qhasm:           xmm5 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm5=int6464#6
# asm 2: pxor  <xmm1=%xmm1,<xmm5=%xmm5
pxor  %xmm1,%xmm5

# qhasm:           xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm1=int6464#2
# asm 2: pxor  <xmm11=%xmm10,<xmm1=%xmm1
pxor  %xmm10,%xmm1

# qhasm:         xmm5 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm5=int6464#6
# asm 2: pxor  <xmm12=%xmm8,<xmm5=%xmm5
pxor  %xmm8,%xmm5

# qhasm:         xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm8,<xmm3=%xmm3
pxor  %xmm8,%xmm3

# qhasm:         xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:         xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm4=int6464#5
# asm 2: pxor  <xmm8=%xmm9,<xmm4=%xmm4
pxor  %xmm9,%xmm4

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm5=int6464#6
# asm 2: pxor  <xmm0=%xmm0,<xmm5=%xmm5
pxor  %xmm0,%xmm5

# qhasm:       xmm1 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm1=int6464#2
# asm 2: pxor  <xmm2=%xmm2,<xmm1=%xmm1
pxor  %xmm2,%xmm1

# qhasm:       xmm3 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm3=int6464#4
# asm 2: pxor  <xmm5=%xmm5,<xmm3=%xmm3
pxor  %xmm5,%xmm3

# qhasm:       xmm2 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm2=int6464#3
# asm 2: pxor  <xmm0=%xmm0,<xmm2=%xmm2
pxor  %xmm0,%xmm2

# qhasm:       xmm0 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm0=int6464#1
# asm 2: pxor  <xmm1=%xmm1,<xmm0=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#2
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm1
pxor  %xmm7,%xmm1

# qhasm:       xmm7 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm7=int6464#8
# asm 2: pxor  <xmm4=%xmm4,<xmm7=%xmm7
pxor  %xmm4,%xmm7

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:       xmm4 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm4=int6464#5
# asm 2: pxor  <xmm6=%xmm6,<xmm4=%xmm4
pxor  %xmm6,%xmm4

# qhasm:       xmm6 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm6=int6464#7
# asm 2: pxor  <xmm7=%xmm7,<xmm6=%xmm6
pxor  %xmm7,%xmm6

# qhasm:       xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm6,<xmm2=%xmm2
pxor  %xmm6,%xmm2

# qhasm:   xmm5 ^= RCON
# asm 1: pxor  RCON,<xmm5=int6464#6
# asm 2: pxor  RCON,<xmm5=%xmm5
pxor  RCON,%xmm5

# qhasm:   shuffle bytes of xmm0 by EXPB0
# asm 1: pshufb EXPB0,<xmm0=int6464#1
# asm 2: pshufb EXPB0,<xmm0=%xmm0
pshufb EXPB0,%xmm0

# qhasm:   shuffle bytes of xmm1 by EXPB0
# asm 1: pshufb EXPB0,<xmm1=int6464#2
# asm 2: pshufb EXPB0,<xmm1=%xmm1
pshufb EXPB0,%xmm1

# qhasm:   shuffle bytes of xmm3 by EXPB0
# asm 1: pshufb EXPB0,<xmm3=int6464#4
# asm 2: pshufb EXPB0,<xmm3=%xmm3
pshufb EXPB0,%xmm3

# qhasm:   shuffle bytes of xmm2 by EXPB0
# asm 1: pshufb EXPB0,<xmm2=int6464#3
# asm 2: pshufb EXPB0,<xmm2=%xmm2
pshufb EXPB0,%xmm2

# qhasm:   shuffle bytes of xmm6 by EXPB0
# asm 1: pshufb EXPB0,<xmm6=int6464#7
# asm 2: pshufb EXPB0,<xmm6=%xmm6
pshufb EXPB0,%xmm6

# qhasm:   shuffle bytes of xmm5 by EXPB0
# asm 1: pshufb EXPB0,<xmm5=int6464#6
# asm 2: pshufb EXPB0,<xmm5=%xmm5
pshufb EXPB0,%xmm5

# qhasm:   shuffle bytes of xmm4 by EXPB0
# asm 1: pshufb EXPB0,<xmm4=int6464#5
# asm 2: pshufb EXPB0,<xmm4=%xmm4
pshufb EXPB0,%xmm4

# qhasm:   shuffle bytes of xmm7 by EXPB0
# asm 1: pshufb EXPB0,<xmm7=int6464#8
# asm 2: pshufb EXPB0,<xmm7=%xmm7
pshufb EXPB0,%xmm7

# qhasm:   xmm8 = *(int128 *)(c + 640)
# asm 1: movdqa 640(<c=int64#1),>xmm8=int6464#9
# asm 2: movdqa 640(<c=%rdi),>xmm8=%xmm8
movdqa 640(%rdi),%xmm8

# qhasm:   xmm9 = *(int128 *)(c + 656)
# asm 1: movdqa 656(<c=int64#1),>xmm9=int6464#10
# asm 2: movdqa 656(<c=%rdi),>xmm9=%xmm9
movdqa 656(%rdi),%xmm9

# qhasm:   xmm10 = *(int128 *)(c + 672)
# asm 1: movdqa 672(<c=int64#1),>xmm10=int6464#11
# asm 2: movdqa 672(<c=%rdi),>xmm10=%xmm10
movdqa 672(%rdi),%xmm10

# qhasm:   xmm11 = *(int128 *)(c + 688)
# asm 1: movdqa 688(<c=int64#1),>xmm11=int6464#12
# asm 2: movdqa 688(<c=%rdi),>xmm11=%xmm11
movdqa 688(%rdi),%xmm11

# qhasm:   xmm12 = *(int128 *)(c + 704)
# asm 1: movdqa 704(<c=int64#1),>xmm12=int6464#13
# asm 2: movdqa 704(<c=%rdi),>xmm12=%xmm12
movdqa 704(%rdi),%xmm12

# qhasm:   xmm13 = *(int128 *)(c + 720)
# asm 1: movdqa 720(<c=int64#1),>xmm13=int6464#14
# asm 2: movdqa 720(<c=%rdi),>xmm13=%xmm13
movdqa 720(%rdi),%xmm13

# qhasm:   xmm14 = *(int128 *)(c + 736)
# asm 1: movdqa 736(<c=int64#1),>xmm14=int6464#15
# asm 2: movdqa 736(<c=%rdi),>xmm14=%xmm14
movdqa 736(%rdi),%xmm14

# qhasm:   xmm15 = *(int128 *)(c + 752)
# asm 1: movdqa 752(<c=int64#1),>xmm15=int6464#16
# asm 2: movdqa 752(<c=%rdi),>xmm15=%xmm15
movdqa 752(%rdi),%xmm15

# qhasm:   xmm8 ^= ONE
# asm 1: pxor  ONE,<xmm8=int6464#9
# asm 2: pxor  ONE,<xmm8=%xmm8
pxor  ONE,%xmm8

# qhasm:   xmm9 ^= ONE
# asm 1: pxor  ONE,<xmm9=int6464#10
# asm 2: pxor  ONE,<xmm9=%xmm9
pxor  ONE,%xmm9

# qhasm:   xmm13 ^= ONE
# asm 1: pxor  ONE,<xmm13=int6464#14
# asm 2: pxor  ONE,<xmm13=%xmm13
pxor  ONE,%xmm13

# qhasm:   xmm14 ^= ONE
# asm 1: pxor  ONE,<xmm14=int6464#15
# asm 2: pxor  ONE,<xmm14=%xmm14
pxor  ONE,%xmm14

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:   xmm2 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm2=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm2=%xmm2
pxor  %xmm11,%xmm2

# qhasm:   xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm12,<xmm6=%xmm6
pxor  %xmm12,%xmm6

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:   xmm2 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm2=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm2=%xmm2
pxor  %xmm11,%xmm2

# qhasm:   xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm12,<xmm6=%xmm6
pxor  %xmm12,%xmm6

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:   xmm2 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm2=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm2=%xmm2
pxor  %xmm11,%xmm2

# qhasm:   xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm12,<xmm6=%xmm6
pxor  %xmm12,%xmm6

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:   xmm2 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm2=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm2=%xmm2
pxor  %xmm11,%xmm2

# qhasm:   xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm12,<xmm6=%xmm6
pxor  %xmm12,%xmm6

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   *(int128 *)(c + 768) = xmm0
# asm 1: movdqa <xmm0=int6464#1,768(<c=int64#1)
# asm 2: movdqa <xmm0=%xmm0,768(<c=%rdi)
movdqa %xmm0,768(%rdi)

# qhasm:   *(int128 *)(c + 784) = xmm1
# asm 1: movdqa <xmm1=int6464#2,784(<c=int64#1)
# asm 2: movdqa <xmm1=%xmm1,784(<c=%rdi)
movdqa %xmm1,784(%rdi)

# qhasm:   *(int128 *)(c + 800) = xmm3
# asm 1: movdqa <xmm3=int6464#4,800(<c=int64#1)
# asm 2: movdqa <xmm3=%xmm3,800(<c=%rdi)
movdqa %xmm3,800(%rdi)

# qhasm:   *(int128 *)(c + 816) = xmm2
# asm 1: movdqa <xmm2=int6464#3,816(<c=int64#1)
# asm 2: movdqa <xmm2=%xmm2,816(<c=%rdi)
movdqa %xmm2,816(%rdi)

# qhasm:   *(int128 *)(c + 832) = xmm6
# asm 1: movdqa <xmm6=int6464#7,832(<c=int64#1)
# asm 2: movdqa <xmm6=%xmm6,832(<c=%rdi)
movdqa %xmm6,832(%rdi)

# qhasm:   *(int128 *)(c + 848) = xmm5
# asm 1: movdqa <xmm5=int6464#6,848(<c=int64#1)
# asm 2: movdqa <xmm5=%xmm5,848(<c=%rdi)
movdqa %xmm5,848(%rdi)

# qhasm:   *(int128 *)(c + 864) = xmm4
# asm 1: movdqa <xmm4=int6464#5,864(<c=int64#1)
# asm 2: movdqa <xmm4=%xmm4,864(<c=%rdi)
movdqa %xmm4,864(%rdi)

# qhasm:   *(int128 *)(c + 880) = xmm7
# asm 1: movdqa <xmm7=int6464#8,880(<c=int64#1)
# asm 2: movdqa <xmm7=%xmm7,880(<c=%rdi)
movdqa %xmm7,880(%rdi)

# qhasm:   xmm0 ^= ONE
# asm 1: pxor  ONE,<xmm0=int6464#1
# asm 2: pxor  ONE,<xmm0=%xmm0
pxor  ONE,%xmm0

# qhasm:   xmm1 ^= ONE
# asm 1: pxor  ONE,<xmm1=int6464#2
# asm 2: pxor  ONE,<xmm1=%xmm1
pxor  ONE,%xmm1

# qhasm:   xmm5 ^= ONE
# asm 1: pxor  ONE,<xmm5=int6464#6
# asm 2: pxor  ONE,<xmm5=%xmm5
pxor  ONE,%xmm5

# qhasm:   xmm4 ^= ONE
# asm 1: pxor  ONE,<xmm4=int6464#5
# asm 2: pxor  ONE,<xmm4=%xmm4
pxor  ONE,%xmm4

# qhasm:     shuffle bytes of xmm0 by ROTB
# asm 1: pshufb ROTB,<xmm0=int6464#1
# asm 2: pshufb ROTB,<xmm0=%xmm0
pshufb ROTB,%xmm0

# qhasm:     shuffle bytes of xmm1 by ROTB
# asm 1: pshufb ROTB,<xmm1=int6464#2
# asm 2: pshufb ROTB,<xmm1=%xmm1
pshufb ROTB,%xmm1

# qhasm:     shuffle bytes of xmm3 by ROTB
# asm 1: pshufb ROTB,<xmm3=int6464#4
# asm 2: pshufb ROTB,<xmm3=%xmm3
pshufb ROTB,%xmm3

# qhasm:     shuffle bytes of xmm2 by ROTB
# asm 1: pshufb ROTB,<xmm2=int6464#3
# asm 2: pshufb ROTB,<xmm2=%xmm2
pshufb ROTB,%xmm2

# qhasm:     shuffle bytes of xmm6 by ROTB
# asm 1: pshufb ROTB,<xmm6=int6464#7
# asm 2: pshufb ROTB,<xmm6=%xmm6
pshufb ROTB,%xmm6

# qhasm:     shuffle bytes of xmm5 by ROTB
# asm 1: pshufb ROTB,<xmm5=int6464#6
# asm 2: pshufb ROTB,<xmm5=%xmm5
pshufb ROTB,%xmm5

# qhasm:     shuffle bytes of xmm4 by ROTB
# asm 1: pshufb ROTB,<xmm4=int6464#5
# asm 2: pshufb ROTB,<xmm4=%xmm4
pshufb ROTB,%xmm4

# qhasm:     shuffle bytes of xmm7 by ROTB
# asm 1: pshufb ROTB,<xmm7=int6464#8
# asm 2: pshufb ROTB,<xmm7=%xmm7
pshufb ROTB,%xmm7

# qhasm:       xmm5 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm5=int6464#6
# asm 2: pxor  <xmm4=%xmm4,<xmm5=%xmm5
pxor  %xmm4,%xmm5

# qhasm:       xmm3 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm3=int6464#4
# asm 2: pxor  <xmm1=%xmm1,<xmm3=%xmm3
pxor  %xmm1,%xmm3

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm5=int6464#6
# asm 2: pxor  <xmm0=%xmm0,<xmm5=%xmm5
pxor  %xmm0,%xmm5

# qhasm:       xmm4 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm4=int6464#5
# asm 2: pxor  <xmm3=%xmm3,<xmm4=%xmm4
pxor  %xmm3,%xmm4

# qhasm:       xmm2 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm2=int6464#3
# asm 2: pxor  <xmm0=%xmm0,<xmm2=%xmm2
pxor  %xmm0,%xmm2

# qhasm:       xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm2=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:       xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:       xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm6,<xmm2=%xmm2
pxor  %xmm6,%xmm2

# qhasm:       xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm7=int6464#8
# asm 2: pxor  <xmm5=%xmm5,<xmm7=%xmm7
pxor  %xmm5,%xmm7

# qhasm:       xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm1,<xmm2=%xmm2
pxor  %xmm1,%xmm2

# qhasm:       xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm1=int6464#2
# asm 2: pxor  <xmm5=%xmm5,<xmm1=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm11 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm11=int6464#9
# asm 2: movdqa <xmm7=%xmm7,>xmm11=%xmm8
movdqa %xmm7,%xmm8

# qhasm:       xmm10 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm10=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm10=%xmm9
movdqa %xmm1,%xmm9

# qhasm:       xmm9 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm9=int6464#11
# asm 2: movdqa <xmm5=%xmm5,>xmm9=%xmm10
movdqa %xmm5,%xmm10

# qhasm:       xmm13 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm13=int6464#12
# asm 2: movdqa <xmm3=%xmm3,>xmm13=%xmm11
movdqa %xmm3,%xmm11

# qhasm:       xmm12 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm12=int6464#13
# asm 2: movdqa <xmm4=%xmm4,>xmm12=%xmm12
movdqa %xmm4,%xmm12

# qhasm:       xmm11 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm11=int6464#9
# asm 2: pxor  <xmm6=%xmm6,<xmm11=%xmm8
pxor  %xmm6,%xmm8

# qhasm:       xmm10 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm10=int6464#10
# asm 2: pxor  <xmm3=%xmm3,<xmm10=%xmm9
pxor  %xmm3,%xmm9

# qhasm:       xmm9 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm9=int6464#11
# asm 2: pxor  <xmm2=%xmm2,<xmm9=%xmm10
pxor  %xmm2,%xmm10

# qhasm:       xmm13 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm13=int6464#12
# asm 2: pxor  <xmm6=%xmm6,<xmm13=%xmm11
pxor  %xmm6,%xmm11

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:       xmm14 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm14=int6464#14
# asm 2: movdqa <xmm11=%xmm8,>xmm14=%xmm13
movdqa %xmm8,%xmm13

# qhasm:       xmm8 = xmm10
# asm 1: movdqa <xmm10=int6464#10,>xmm8=int6464#15
# asm 2: movdqa <xmm10=%xmm9,>xmm8=%xmm14
movdqa %xmm9,%xmm14

# qhasm:       xmm15 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm15=int6464#16
# asm 2: movdqa <xmm11=%xmm8,>xmm15=%xmm15
movdqa %xmm8,%xmm15

# qhasm:       xmm10 |= xmm9
# asm 1: por   <xmm9=int6464#11,<xmm10=int6464#10
# asm 2: por   <xmm9=%xmm10,<xmm10=%xmm9
por   %xmm10,%xmm9

# qhasm:       xmm11 |= xmm12
# asm 1: por   <xmm12=int6464#13,<xmm11=int6464#9
# asm 2: por   <xmm12=%xmm12,<xmm11=%xmm8
por   %xmm12,%xmm8

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm15=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm14 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm14=int6464#14
# asm 2: pand  <xmm12=%xmm12,<xmm14=%xmm13
pand  %xmm12,%xmm13

# qhasm:       xmm8 &= xmm9
# asm 1: pand  <xmm9=int6464#11,<xmm8=int6464#15
# asm 2: pand  <xmm9=%xmm10,<xmm8=%xmm14
pand  %xmm10,%xmm14

# qhasm:       xmm12 ^= xmm9
# asm 1: pxor  <xmm9=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm9=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:       xmm15 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm15=int6464#16
# asm 2: pand  <xmm12=%xmm12,<xmm15=%xmm15
pand  %xmm12,%xmm15

# qhasm:       xmm12 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm12=int6464#11
# asm 2: movdqa <xmm2=%xmm2,>xmm12=%xmm10
movdqa %xmm2,%xmm10

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#11
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm10
pxor  %xmm0,%xmm10

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#11,<xmm13=int6464#12
# asm 2: pand  <xmm12=%xmm10,<xmm13=%xmm11
pand  %xmm10,%xmm11

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm11=int6464#9
# asm 2: pxor  <xmm13=%xmm11,<xmm11=%xmm8
pxor  %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm13 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm13=int6464#11
# asm 2: movdqa <xmm7=%xmm7,>xmm13=%xmm10
movdqa %xmm7,%xmm10

# qhasm:       xmm13 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm13=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm13=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm12 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm12=int6464#12
# asm 2: movdqa <xmm5=%xmm5,>xmm12=%xmm11
movdqa %xmm5,%xmm11

# qhasm:       xmm9 = xmm13
# asm 1: movdqa <xmm13=int6464#11,>xmm9=int6464#13
# asm 2: movdqa <xmm13=%xmm10,>xmm9=%xmm12
movdqa %xmm10,%xmm12

# qhasm:       xmm12 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm12=int6464#12
# asm 2: pxor  <xmm4=%xmm4,<xmm12=%xmm11
pxor  %xmm4,%xmm11

# qhasm:       xmm9 |= xmm12
# asm 1: por   <xmm12=int6464#12,<xmm9=int6464#13
# asm 2: por   <xmm12=%xmm11,<xmm9=%xmm12
por   %xmm11,%xmm12

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#12,<xmm13=int6464#11
# asm 2: pand  <xmm12=%xmm11,<xmm13=%xmm10
pand  %xmm11,%xmm10

# qhasm:       xmm8 ^= xmm13
# asm 1: pxor  <xmm13=int6464#11,<xmm8=int6464#15
# asm 2: pxor  <xmm13=%xmm10,<xmm8=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#9
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm10=int6464#10
# asm 2: pxor  <xmm14=%xmm13,<xmm10=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm9 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm8 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm8=int6464#15
# asm 2: pxor  <xmm14=%xmm13,<xmm8=%xmm14
pxor  %xmm13,%xmm14

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm12 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm12=int6464#11
# asm 2: movdqa <xmm3=%xmm3,>xmm12=%xmm10
movdqa %xmm3,%xmm10

# qhasm:       xmm13 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm13=int6464#12
# asm 2: movdqa <xmm6=%xmm6,>xmm13=%xmm11
movdqa %xmm6,%xmm11

# qhasm:       xmm14 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm14=int6464#14
# asm 2: movdqa <xmm1=%xmm1,>xmm14=%xmm13
movdqa %xmm1,%xmm13

# qhasm:       xmm15 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm15=int6464#16
# asm 2: movdqa <xmm7=%xmm7,>xmm15=%xmm15
movdqa %xmm7,%xmm15

# qhasm:       xmm12 &= xmm2
# asm 1: pand  <xmm2=int6464#3,<xmm12=int6464#11
# asm 2: pand  <xmm2=%xmm2,<xmm12=%xmm10
pand  %xmm2,%xmm10

# qhasm:       xmm13 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm13=int6464#12
# asm 2: pand  <xmm0=%xmm0,<xmm13=%xmm11
pand  %xmm0,%xmm11

# qhasm:       xmm14 &= xmm5
# asm 1: pand  <xmm5=int6464#6,<xmm14=int6464#14
# asm 2: pand  <xmm5=%xmm5,<xmm14=%xmm13
pand  %xmm5,%xmm13

# qhasm:       xmm15 |= xmm4
# asm 1: por   <xmm4=int6464#5,<xmm15=int6464#16
# asm 2: por   <xmm4=%xmm4,<xmm15=%xmm15
por   %xmm4,%xmm15

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm11=int6464#9
# asm 2: pxor  <xmm12=%xmm10,<xmm11=%xmm8
pxor  %xmm10,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm8 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm8=int6464#15
# asm 2: pxor  <xmm15=%xmm15,<xmm8=%xmm14
pxor  %xmm15,%xmm14

# qhasm:       xmm12 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm12=int6464#11
# asm 2: movdqa <xmm11=%xmm8,>xmm12=%xmm10
movdqa %xmm8,%xmm10

# qhasm:       xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm12=int6464#11
# asm 2: pxor  <xmm10=%xmm9,<xmm12=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm11 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm11=int6464#9
# asm 2: pand  <xmm9=%xmm12,<xmm11=%xmm8
pand  %xmm12,%xmm8

# qhasm:       xmm14 = xmm8
# asm 1: movdqa <xmm8=int6464#15,>xmm14=int6464#12
# asm 2: movdqa <xmm8=%xmm14,>xmm14=%xmm11
movdqa %xmm14,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm11=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm15 = xmm12
# asm 1: movdqa <xmm12=int6464#11,>xmm15=int6464#14
# asm 2: movdqa <xmm12=%xmm10,>xmm15=%xmm13
movdqa %xmm10,%xmm13

# qhasm:       xmm15 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm15=int6464#14
# asm 2: pand  <xmm14=%xmm11,<xmm15=%xmm13
pand  %xmm11,%xmm13

# qhasm:       xmm15 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm15=int6464#14
# asm 2: pxor  <xmm10=%xmm9,<xmm15=%xmm13
pxor  %xmm9,%xmm13

# qhasm:       xmm13 = xmm9
# asm 1: movdqa <xmm9=int6464#13,>xmm13=int6464#16
# asm 2: movdqa <xmm9=%xmm12,>xmm13=%xmm15
movdqa %xmm12,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm11 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm11=int6464#9
# asm 2: pxor  <xmm10=%xmm9,<xmm11=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm13 &= xmm11
# asm 1: pand  <xmm11=int6464#9,<xmm13=int6464#16
# asm 2: pand  <xmm11=%xmm8,<xmm13=%xmm15
pand  %xmm8,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm13=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm10 = xmm14
# asm 1: movdqa <xmm14=int6464#12,>xmm10=int6464#9
# asm 2: movdqa <xmm14=%xmm11,>xmm10=%xmm8
movdqa %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm10=int6464#9
# asm 2: pxor  <xmm13=%xmm15,<xmm10=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 &= xmm8
# asm 1: pand  <xmm8=int6464#15,<xmm10=int6464#9
# asm 2: pand  <xmm8=%xmm14,<xmm10=%xmm8
pand  %xmm14,%xmm8

# qhasm:       xmm9 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm9=int6464#13
# asm 2: pxor  <xmm10=%xmm8,<xmm9=%xmm12
pxor  %xmm8,%xmm12

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm10=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm14=int6464#12
# asm 2: pand  <xmm15=%xmm13,<xmm14=%xmm11
pand  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm14=int6464#12
# asm 2: pxor  <xmm12=%xmm10,<xmm14=%xmm11
pxor  %xmm10,%xmm11

# qhasm:         xmm12 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm12=int6464#9
# asm 2: movdqa <xmm4=%xmm4,>xmm12=%xmm8
movdqa %xmm4,%xmm8

# qhasm:         xmm8 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm8=int6464#10
# asm 2: movdqa <xmm5=%xmm5,>xmm8=%xmm9
movdqa %xmm5,%xmm9

# qhasm:           xmm10 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm10=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm10=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm10 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm10=int6464#11
# asm 2: pand  <xmm4=%xmm4,<xmm10=%xmm10
pand  %xmm4,%xmm10

# qhasm:           xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:           xmm4 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm4=int6464#5
# asm 2: pand  <xmm14=%xmm11,<xmm4=%xmm4
pand  %xmm11,%xmm4

# qhasm:           xmm5 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm5=int6464#6
# asm 2: pand  <xmm15=%xmm13,<xmm5=%xmm5
pand  %xmm13,%xmm5

# qhasm:           xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:           xmm5 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm5=int6464#6
# asm 2: pxor  <xmm10=%xmm10,<xmm5=%xmm5
pxor  %xmm10,%xmm5

# qhasm:         xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm8 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm8=int6464#10
# asm 2: pxor  <xmm2=%xmm2,<xmm8=%xmm9
pxor  %xmm2,%xmm9

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm10=int6464#11
# asm 2: pand  <xmm0=%xmm0,<xmm10=%xmm10
pand  %xmm0,%xmm10

# qhasm:           xmm0 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm0=int6464#1
# asm 2: pxor  <xmm2=%xmm2,<xmm0=%xmm0
pxor  %xmm2,%xmm0

# qhasm:           xmm0 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm0=int6464#1
# asm 2: pand  <xmm9=%xmm12,<xmm0=%xmm0
pand  %xmm12,%xmm0

# qhasm:           xmm2 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm2=int6464#3
# asm 2: pand  <xmm13=%xmm15,<xmm2=%xmm2
pand  %xmm15,%xmm2

# qhasm:           xmm0 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm0=int6464#1
# asm 2: pxor  <xmm2=%xmm2,<xmm0=%xmm0
pxor  %xmm2,%xmm0

# qhasm:           xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#3
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm2
pxor  %xmm10,%xmm2

# qhasm:         xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <xmm12=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:         xmm0 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm12=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm5 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm5=int6464#6
# asm 2: pxor  <xmm8=%xmm9,<xmm5=%xmm5
pxor  %xmm9,%xmm5

# qhasm:         xmm2 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm2=int6464#3
# asm 2: pxor  <xmm8=%xmm9,<xmm2=%xmm2
pxor  %xmm9,%xmm2

# qhasm:         xmm12 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm12=int6464#9
# asm 2: movdqa <xmm7=%xmm7,>xmm12=%xmm8
movdqa %xmm7,%xmm8

# qhasm:         xmm8 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm8=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm8=%xmm9
movdqa %xmm1,%xmm9

# qhasm:         xmm12 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm12=int6464#9
# asm 2: pxor  <xmm6=%xmm6,<xmm12=%xmm8
pxor  %xmm6,%xmm8

# qhasm:         xmm8 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm8=int6464#10
# asm 2: pxor  <xmm3=%xmm3,<xmm8=%xmm9
pxor  %xmm3,%xmm9

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm6
# asm 1: pand  <xmm6=int6464#7,<xmm10=int6464#11
# asm 2: pand  <xmm6=%xmm6,<xmm10=%xmm10
pand  %xmm6,%xmm10

# qhasm:           xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm6=int6464#7
# asm 2: pxor  <xmm3=%xmm3,<xmm6=%xmm6
pxor  %xmm3,%xmm6

# qhasm:           xmm6 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm6=int6464#7
# asm 2: pand  <xmm9=%xmm12,<xmm6=%xmm6
pand  %xmm12,%xmm6

# qhasm:           xmm3 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm3=int6464#4
# asm 2: pand  <xmm13=%xmm15,<xmm3=%xmm3
pand  %xmm15,%xmm3

# qhasm:           xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm6=int6464#7
# asm 2: pxor  <xmm3=%xmm3,<xmm6=%xmm6
pxor  %xmm3,%xmm6

# qhasm:           xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm7
# asm 1: pand  <xmm7=int6464#8,<xmm11=int6464#11
# asm 2: pand  <xmm7=%xmm7,<xmm11=%xmm10
pand  %xmm7,%xmm10

# qhasm:           xmm7 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm7=int6464#8
# asm 2: pxor  <xmm1=%xmm1,<xmm7=%xmm7
pxor  %xmm1,%xmm7

# qhasm:           xmm7 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm7=int6464#8
# asm 2: pand  <xmm14=%xmm11,<xmm7=%xmm7
pand  %xmm11,%xmm7

# qhasm:           xmm1 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm1=int6464#2
# asm 2: pand  <xmm15=%xmm13,<xmm1=%xmm1
pand  %xmm13,%xmm1

# qhasm:           xmm7 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm7=int6464#8
# asm 2: pxor  <xmm1=%xmm1,<xmm7=%xmm7
pxor  %xmm1,%xmm7

# qhasm:           xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm1=int6464#2
# asm 2: pxor  <xmm11=%xmm10,<xmm1=%xmm1
pxor  %xmm10,%xmm1

# qhasm:         xmm7 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm7=int6464#8
# asm 2: pxor  <xmm12=%xmm8,<xmm7=%xmm7
pxor  %xmm8,%xmm7

# qhasm:         xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm8,<xmm6=%xmm6
pxor  %xmm8,%xmm6

# qhasm:         xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:         xmm3 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm3=int6464#4
# asm 2: pxor  <xmm8=%xmm9,<xmm3=%xmm3
pxor  %xmm9,%xmm3

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm0,<xmm7=%xmm7
pxor  %xmm0,%xmm7

# qhasm:       xmm1 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm1=int6464#2
# asm 2: pxor  <xmm4=%xmm4,<xmm1=%xmm1
pxor  %xmm4,%xmm1

# qhasm:       xmm6 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm6=int6464#7
# asm 2: pxor  <xmm7=%xmm7,<xmm6=%xmm6
pxor  %xmm7,%xmm6

# qhasm:       xmm4 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm4=int6464#5
# asm 2: pxor  <xmm0=%xmm0,<xmm4=%xmm4
pxor  %xmm0,%xmm4

# qhasm:       xmm0 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm0=int6464#1
# asm 2: pxor  <xmm1=%xmm1,<xmm0=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm1=int6464#2
# asm 2: pxor  <xmm5=%xmm5,<xmm1=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm5 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm5=int6464#6
# asm 2: pxor  <xmm3=%xmm3,<xmm5=%xmm5
pxor  %xmm3,%xmm5

# qhasm:       xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:       xmm3 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm3=int6464#4
# asm 2: pxor  <xmm2=%xmm2,<xmm3=%xmm3
pxor  %xmm2,%xmm3

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm2=int6464#3
# asm 2: pxor  <xmm5=%xmm5,<xmm2=%xmm2
pxor  %xmm5,%xmm2

# qhasm:       xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm2=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:   xmm3 ^= RCON
# asm 1: pxor  RCON,<xmm3=int6464#4
# asm 2: pxor  RCON,<xmm3=%xmm3
pxor  RCON,%xmm3

# qhasm:   shuffle bytes of xmm0 by EXPB0
# asm 1: pshufb EXPB0,<xmm0=int6464#1
# asm 2: pshufb EXPB0,<xmm0=%xmm0
pshufb EXPB0,%xmm0

# qhasm:   shuffle bytes of xmm1 by EXPB0
# asm 1: pshufb EXPB0,<xmm1=int6464#2
# asm 2: pshufb EXPB0,<xmm1=%xmm1
pshufb EXPB0,%xmm1

# qhasm:   shuffle bytes of xmm6 by EXPB0
# asm 1: pshufb EXPB0,<xmm6=int6464#7
# asm 2: pshufb EXPB0,<xmm6=%xmm6
pshufb EXPB0,%xmm6

# qhasm:   shuffle bytes of xmm4 by EXPB0
# asm 1: pshufb EXPB0,<xmm4=int6464#5
# asm 2: pshufb EXPB0,<xmm4=%xmm4
pshufb EXPB0,%xmm4

# qhasm:   shuffle bytes of xmm2 by EXPB0
# asm 1: pshufb EXPB0,<xmm2=int6464#3
# asm 2: pshufb EXPB0,<xmm2=%xmm2
pshufb EXPB0,%xmm2

# qhasm:   shuffle bytes of xmm7 by EXPB0
# asm 1: pshufb EXPB0,<xmm7=int6464#8
# asm 2: pshufb EXPB0,<xmm7=%xmm7
pshufb EXPB0,%xmm7

# qhasm:   shuffle bytes of xmm3 by EXPB0
# asm 1: pshufb EXPB0,<xmm3=int6464#4
# asm 2: pshufb EXPB0,<xmm3=%xmm3
pshufb EXPB0,%xmm3

# qhasm:   shuffle bytes of xmm5 by EXPB0
# asm 1: pshufb EXPB0,<xmm5=int6464#6
# asm 2: pshufb EXPB0,<xmm5=%xmm5
pshufb EXPB0,%xmm5

# qhasm:   xmm8 = *(int128 *)(c + 768)
# asm 1: movdqa 768(<c=int64#1),>xmm8=int6464#9
# asm 2: movdqa 768(<c=%rdi),>xmm8=%xmm8
movdqa 768(%rdi),%xmm8

# qhasm:   xmm9 = *(int128 *)(c + 784)
# asm 1: movdqa 784(<c=int64#1),>xmm9=int6464#10
# asm 2: movdqa 784(<c=%rdi),>xmm9=%xmm9
movdqa 784(%rdi),%xmm9

# qhasm:   xmm10 = *(int128 *)(c + 800)
# asm 1: movdqa 800(<c=int64#1),>xmm10=int6464#11
# asm 2: movdqa 800(<c=%rdi),>xmm10=%xmm10
movdqa 800(%rdi),%xmm10

# qhasm:   xmm11 = *(int128 *)(c + 816)
# asm 1: movdqa 816(<c=int64#1),>xmm11=int6464#12
# asm 2: movdqa 816(<c=%rdi),>xmm11=%xmm11
movdqa 816(%rdi),%xmm11

# qhasm:   xmm12 = *(int128 *)(c + 832)
# asm 1: movdqa 832(<c=int64#1),>xmm12=int6464#13
# asm 2: movdqa 832(<c=%rdi),>xmm12=%xmm12
movdqa 832(%rdi),%xmm12

# qhasm:   xmm13 = *(int128 *)(c + 848)
# asm 1: movdqa 848(<c=int64#1),>xmm13=int6464#14
# asm 2: movdqa 848(<c=%rdi),>xmm13=%xmm13
movdqa 848(%rdi),%xmm13

# qhasm:   xmm14 = *(int128 *)(c + 864)
# asm 1: movdqa 864(<c=int64#1),>xmm14=int6464#15
# asm 2: movdqa 864(<c=%rdi),>xmm14=%xmm14
movdqa 864(%rdi),%xmm14

# qhasm:   xmm15 = *(int128 *)(c + 880)
# asm 1: movdqa 880(<c=int64#1),>xmm15=int6464#16
# asm 2: movdqa 880(<c=%rdi),>xmm15=%xmm15
movdqa 880(%rdi),%xmm15

# qhasm:   xmm8 ^= ONE
# asm 1: pxor  ONE,<xmm8=int6464#9
# asm 2: pxor  ONE,<xmm8=%xmm8
pxor  ONE,%xmm8

# qhasm:   xmm9 ^= ONE
# asm 1: pxor  ONE,<xmm9=int6464#10
# asm 2: pxor  ONE,<xmm9=%xmm9
pxor  ONE,%xmm9

# qhasm:   xmm13 ^= ONE
# asm 1: pxor  ONE,<xmm13=int6464#14
# asm 2: pxor  ONE,<xmm13=%xmm13
pxor  ONE,%xmm13

# qhasm:   xmm14 ^= ONE
# asm 1: pxor  ONE,<xmm14=int6464#15
# asm 2: pxor  ONE,<xmm14=%xmm14
pxor  ONE,%xmm14

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:   xmm4 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm4=int6464#5
# asm 2: pxor  <xmm11=%xmm11,<xmm4=%xmm4
pxor  %xmm11,%xmm4

# qhasm:   xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm12,<xmm2=%xmm2
pxor  %xmm12,%xmm2

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm3 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm3=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm3=%xmm3
pxor  %xmm14,%xmm3

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:   xmm4 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm4=int6464#5
# asm 2: pxor  <xmm11=%xmm11,<xmm4=%xmm4
pxor  %xmm11,%xmm4

# qhasm:   xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm12,<xmm2=%xmm2
pxor  %xmm12,%xmm2

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm3 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm3=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm3=%xmm3
pxor  %xmm14,%xmm3

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:   xmm4 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm4=int6464#5
# asm 2: pxor  <xmm11=%xmm11,<xmm4=%xmm4
pxor  %xmm11,%xmm4

# qhasm:   xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm12,<xmm2=%xmm2
pxor  %xmm12,%xmm2

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm3 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm3=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm3=%xmm3
pxor  %xmm14,%xmm3

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:   xmm4 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm4=int6464#5
# asm 2: pxor  <xmm11=%xmm11,<xmm4=%xmm4
pxor  %xmm11,%xmm4

# qhasm:   xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm12,<xmm2=%xmm2
pxor  %xmm12,%xmm2

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm3 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm3=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm3=%xmm3
pxor  %xmm14,%xmm3

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   *(int128 *)(c + 896) = xmm0
# asm 1: movdqa <xmm0=int6464#1,896(<c=int64#1)
# asm 2: movdqa <xmm0=%xmm0,896(<c=%rdi)
movdqa %xmm0,896(%rdi)

# qhasm:   *(int128 *)(c + 912) = xmm1
# asm 1: movdqa <xmm1=int6464#2,912(<c=int64#1)
# asm 2: movdqa <xmm1=%xmm1,912(<c=%rdi)
movdqa %xmm1,912(%rdi)

# qhasm:   *(int128 *)(c + 928) = xmm6
# asm 1: movdqa <xmm6=int6464#7,928(<c=int64#1)
# asm 2: movdqa <xmm6=%xmm6,928(<c=%rdi)
movdqa %xmm6,928(%rdi)

# qhasm:   *(int128 *)(c + 944) = xmm4
# asm 1: movdqa <xmm4=int6464#5,944(<c=int64#1)
# asm 2: movdqa <xmm4=%xmm4,944(<c=%rdi)
movdqa %xmm4,944(%rdi)

# qhasm:   *(int128 *)(c + 960) = xmm2
# asm 1: movdqa <xmm2=int6464#3,960(<c=int64#1)
# asm 2: movdqa <xmm2=%xmm2,960(<c=%rdi)
movdqa %xmm2,960(%rdi)

# qhasm:   *(int128 *)(c + 976) = xmm7
# asm 1: movdqa <xmm7=int6464#8,976(<c=int64#1)
# asm 2: movdqa <xmm7=%xmm7,976(<c=%rdi)
movdqa %xmm7,976(%rdi)

# qhasm:   *(int128 *)(c + 992) = xmm3
# asm 1: movdqa <xmm3=int6464#4,992(<c=int64#1)
# asm 2: movdqa <xmm3=%xmm3,992(<c=%rdi)
movdqa %xmm3,992(%rdi)

# qhasm:   *(int128 *)(c + 1008) = xmm5
# asm 1: movdqa <xmm5=int6464#6,1008(<c=int64#1)
# asm 2: movdqa <xmm5=%xmm5,1008(<c=%rdi)
movdqa %xmm5,1008(%rdi)

# qhasm:   xmm0 ^= ONE
# asm 1: pxor  ONE,<xmm0=int6464#1
# asm 2: pxor  ONE,<xmm0=%xmm0
pxor  ONE,%xmm0

# qhasm:   xmm1 ^= ONE
# asm 1: pxor  ONE,<xmm1=int6464#2
# asm 2: pxor  ONE,<xmm1=%xmm1
pxor  ONE,%xmm1

# qhasm:   xmm7 ^= ONE
# asm 1: pxor  ONE,<xmm7=int6464#8
# asm 2: pxor  ONE,<xmm7=%xmm7
pxor  ONE,%xmm7

# qhasm:   xmm3 ^= ONE
# asm 1: pxor  ONE,<xmm3=int6464#4
# asm 2: pxor  ONE,<xmm3=%xmm3
pxor  ONE,%xmm3

# qhasm:     shuffle bytes of xmm0 by ROTB
# asm 1: pshufb ROTB,<xmm0=int6464#1
# asm 2: pshufb ROTB,<xmm0=%xmm0
pshufb ROTB,%xmm0

# qhasm:     shuffle bytes of xmm1 by ROTB
# asm 1: pshufb ROTB,<xmm1=int6464#2
# asm 2: pshufb ROTB,<xmm1=%xmm1
pshufb ROTB,%xmm1

# qhasm:     shuffle bytes of xmm6 by ROTB
# asm 1: pshufb ROTB,<xmm6=int6464#7
# asm 2: pshufb ROTB,<xmm6=%xmm6
pshufb ROTB,%xmm6

# qhasm:     shuffle bytes of xmm4 by ROTB
# asm 1: pshufb ROTB,<xmm4=int6464#5
# asm 2: pshufb ROTB,<xmm4=%xmm4
pshufb ROTB,%xmm4

# qhasm:     shuffle bytes of xmm2 by ROTB
# asm 1: pshufb ROTB,<xmm2=int6464#3
# asm 2: pshufb ROTB,<xmm2=%xmm2
pshufb ROTB,%xmm2

# qhasm:     shuffle bytes of xmm7 by ROTB
# asm 1: pshufb ROTB,<xmm7=int6464#8
# asm 2: pshufb ROTB,<xmm7=%xmm7
pshufb ROTB,%xmm7

# qhasm:     shuffle bytes of xmm3 by ROTB
# asm 1: pshufb ROTB,<xmm3=int6464#4
# asm 2: pshufb ROTB,<xmm3=%xmm3
pshufb ROTB,%xmm3

# qhasm:     shuffle bytes of xmm5 by ROTB
# asm 1: pshufb ROTB,<xmm5=int6464#6
# asm 2: pshufb ROTB,<xmm5=%xmm5
pshufb ROTB,%xmm5

# qhasm:       xmm7 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm7=int6464#8
# asm 2: pxor  <xmm3=%xmm3,<xmm7=%xmm7
pxor  %xmm3,%xmm7

# qhasm:       xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm6=int6464#7
# asm 2: pxor  <xmm1=%xmm1,<xmm6=%xmm6
pxor  %xmm1,%xmm6

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm0,<xmm7=%xmm7
pxor  %xmm0,%xmm7

# qhasm:       xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm3=int6464#4
# asm 2: pxor  <xmm6=%xmm6,<xmm3=%xmm3
pxor  %xmm6,%xmm3

# qhasm:       xmm4 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm4=int6464#5
# asm 2: pxor  <xmm0=%xmm0,<xmm4=%xmm4
pxor  %xmm0,%xmm4

# qhasm:       xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm3=int6464#4
# asm 2: pxor  <xmm4=%xmm4,<xmm3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:       xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm2=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:       xmm5 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm5=int6464#6
# asm 2: pxor  <xmm7=%xmm7,<xmm5=%xmm5
pxor  %xmm7,%xmm5

# qhasm:       xmm4 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm4=int6464#5
# asm 2: pxor  <xmm1=%xmm1,<xmm4=%xmm4
pxor  %xmm1,%xmm4

# qhasm:       xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:       xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#2
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm1
pxor  %xmm7,%xmm1

# qhasm:       xmm11 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm11=int6464#9
# asm 2: movdqa <xmm5=%xmm5,>xmm11=%xmm8
movdqa %xmm5,%xmm8

# qhasm:       xmm10 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm10=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm10=%xmm9
movdqa %xmm1,%xmm9

# qhasm:       xmm9 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm9=int6464#11
# asm 2: movdqa <xmm7=%xmm7,>xmm9=%xmm10
movdqa %xmm7,%xmm10

# qhasm:       xmm13 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm13=int6464#12
# asm 2: movdqa <xmm6=%xmm6,>xmm13=%xmm11
movdqa %xmm6,%xmm11

# qhasm:       xmm12 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm12=int6464#13
# asm 2: movdqa <xmm3=%xmm3,>xmm12=%xmm12
movdqa %xmm3,%xmm12

# qhasm:       xmm11 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm11=int6464#9
# asm 2: pxor  <xmm2=%xmm2,<xmm11=%xmm8
pxor  %xmm2,%xmm8

# qhasm:       xmm10 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm10=int6464#10
# asm 2: pxor  <xmm6=%xmm6,<xmm10=%xmm9
pxor  %xmm6,%xmm9

# qhasm:       xmm9 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm9=int6464#11
# asm 2: pxor  <xmm4=%xmm4,<xmm9=%xmm10
pxor  %xmm4,%xmm10

# qhasm:       xmm13 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm13=int6464#12
# asm 2: pxor  <xmm2=%xmm2,<xmm13=%xmm11
pxor  %xmm2,%xmm11

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:       xmm14 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm14=int6464#14
# asm 2: movdqa <xmm11=%xmm8,>xmm14=%xmm13
movdqa %xmm8,%xmm13

# qhasm:       xmm8 = xmm10
# asm 1: movdqa <xmm10=int6464#10,>xmm8=int6464#15
# asm 2: movdqa <xmm10=%xmm9,>xmm8=%xmm14
movdqa %xmm9,%xmm14

# qhasm:       xmm15 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm15=int6464#16
# asm 2: movdqa <xmm11=%xmm8,>xmm15=%xmm15
movdqa %xmm8,%xmm15

# qhasm:       xmm10 |= xmm9
# asm 1: por   <xmm9=int6464#11,<xmm10=int6464#10
# asm 2: por   <xmm9=%xmm10,<xmm10=%xmm9
por   %xmm10,%xmm9

# qhasm:       xmm11 |= xmm12
# asm 1: por   <xmm12=int6464#13,<xmm11=int6464#9
# asm 2: por   <xmm12=%xmm12,<xmm11=%xmm8
por   %xmm12,%xmm8

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm15=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm14 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm14=int6464#14
# asm 2: pand  <xmm12=%xmm12,<xmm14=%xmm13
pand  %xmm12,%xmm13

# qhasm:       xmm8 &= xmm9
# asm 1: pand  <xmm9=int6464#11,<xmm8=int6464#15
# asm 2: pand  <xmm9=%xmm10,<xmm8=%xmm14
pand  %xmm10,%xmm14

# qhasm:       xmm12 ^= xmm9
# asm 1: pxor  <xmm9=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm9=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:       xmm15 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm15=int6464#16
# asm 2: pand  <xmm12=%xmm12,<xmm15=%xmm15
pand  %xmm12,%xmm15

# qhasm:       xmm12 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm12=int6464#11
# asm 2: movdqa <xmm4=%xmm4,>xmm12=%xmm10
movdqa %xmm4,%xmm10

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#11
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm10
pxor  %xmm0,%xmm10

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#11,<xmm13=int6464#12
# asm 2: pand  <xmm12=%xmm10,<xmm13=%xmm11
pand  %xmm10,%xmm11

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm11=int6464#9
# asm 2: pxor  <xmm13=%xmm11,<xmm11=%xmm8
pxor  %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm13 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm13=int6464#11
# asm 2: movdqa <xmm5=%xmm5,>xmm13=%xmm10
movdqa %xmm5,%xmm10

# qhasm:       xmm13 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm13=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm13=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm12 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm12=int6464#12
# asm 2: movdqa <xmm7=%xmm7,>xmm12=%xmm11
movdqa %xmm7,%xmm11

# qhasm:       xmm9 = xmm13
# asm 1: movdqa <xmm13=int6464#11,>xmm9=int6464#13
# asm 2: movdqa <xmm13=%xmm10,>xmm9=%xmm12
movdqa %xmm10,%xmm12

# qhasm:       xmm12 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm12=int6464#12
# asm 2: pxor  <xmm3=%xmm3,<xmm12=%xmm11
pxor  %xmm3,%xmm11

# qhasm:       xmm9 |= xmm12
# asm 1: por   <xmm12=int6464#12,<xmm9=int6464#13
# asm 2: por   <xmm12=%xmm11,<xmm9=%xmm12
por   %xmm11,%xmm12

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#12,<xmm13=int6464#11
# asm 2: pand  <xmm12=%xmm11,<xmm13=%xmm10
pand  %xmm11,%xmm10

# qhasm:       xmm8 ^= xmm13
# asm 1: pxor  <xmm13=int6464#11,<xmm8=int6464#15
# asm 2: pxor  <xmm13=%xmm10,<xmm8=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#9
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm10=int6464#10
# asm 2: pxor  <xmm14=%xmm13,<xmm10=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm9 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm8 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm8=int6464#15
# asm 2: pxor  <xmm14=%xmm13,<xmm8=%xmm14
pxor  %xmm13,%xmm14

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm12 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm12=int6464#11
# asm 2: movdqa <xmm6=%xmm6,>xmm12=%xmm10
movdqa %xmm6,%xmm10

# qhasm:       xmm13 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm13=int6464#12
# asm 2: movdqa <xmm2=%xmm2,>xmm13=%xmm11
movdqa %xmm2,%xmm11

# qhasm:       xmm14 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm14=int6464#14
# asm 2: movdqa <xmm1=%xmm1,>xmm14=%xmm13
movdqa %xmm1,%xmm13

# qhasm:       xmm15 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm15=int6464#16
# asm 2: movdqa <xmm5=%xmm5,>xmm15=%xmm15
movdqa %xmm5,%xmm15

# qhasm:       xmm12 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm12=int6464#11
# asm 2: pand  <xmm4=%xmm4,<xmm12=%xmm10
pand  %xmm4,%xmm10

# qhasm:       xmm13 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm13=int6464#12
# asm 2: pand  <xmm0=%xmm0,<xmm13=%xmm11
pand  %xmm0,%xmm11

# qhasm:       xmm14 &= xmm7
# asm 1: pand  <xmm7=int6464#8,<xmm14=int6464#14
# asm 2: pand  <xmm7=%xmm7,<xmm14=%xmm13
pand  %xmm7,%xmm13

# qhasm:       xmm15 |= xmm3
# asm 1: por   <xmm3=int6464#4,<xmm15=int6464#16
# asm 2: por   <xmm3=%xmm3,<xmm15=%xmm15
por   %xmm3,%xmm15

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm11=int6464#9
# asm 2: pxor  <xmm12=%xmm10,<xmm11=%xmm8
pxor  %xmm10,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm8 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm8=int6464#15
# asm 2: pxor  <xmm15=%xmm15,<xmm8=%xmm14
pxor  %xmm15,%xmm14

# qhasm:       xmm12 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm12=int6464#11
# asm 2: movdqa <xmm11=%xmm8,>xmm12=%xmm10
movdqa %xmm8,%xmm10

# qhasm:       xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm12=int6464#11
# asm 2: pxor  <xmm10=%xmm9,<xmm12=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm11 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm11=int6464#9
# asm 2: pand  <xmm9=%xmm12,<xmm11=%xmm8
pand  %xmm12,%xmm8

# qhasm:       xmm14 = xmm8
# asm 1: movdqa <xmm8=int6464#15,>xmm14=int6464#12
# asm 2: movdqa <xmm8=%xmm14,>xmm14=%xmm11
movdqa %xmm14,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm11=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm15 = xmm12
# asm 1: movdqa <xmm12=int6464#11,>xmm15=int6464#14
# asm 2: movdqa <xmm12=%xmm10,>xmm15=%xmm13
movdqa %xmm10,%xmm13

# qhasm:       xmm15 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm15=int6464#14
# asm 2: pand  <xmm14=%xmm11,<xmm15=%xmm13
pand  %xmm11,%xmm13

# qhasm:       xmm15 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm15=int6464#14
# asm 2: pxor  <xmm10=%xmm9,<xmm15=%xmm13
pxor  %xmm9,%xmm13

# qhasm:       xmm13 = xmm9
# asm 1: movdqa <xmm9=int6464#13,>xmm13=int6464#16
# asm 2: movdqa <xmm9=%xmm12,>xmm13=%xmm15
movdqa %xmm12,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm11 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm11=int6464#9
# asm 2: pxor  <xmm10=%xmm9,<xmm11=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm13 &= xmm11
# asm 1: pand  <xmm11=int6464#9,<xmm13=int6464#16
# asm 2: pand  <xmm11=%xmm8,<xmm13=%xmm15
pand  %xmm8,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm13=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm10 = xmm14
# asm 1: movdqa <xmm14=int6464#12,>xmm10=int6464#9
# asm 2: movdqa <xmm14=%xmm11,>xmm10=%xmm8
movdqa %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm10=int6464#9
# asm 2: pxor  <xmm13=%xmm15,<xmm10=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 &= xmm8
# asm 1: pand  <xmm8=int6464#15,<xmm10=int6464#9
# asm 2: pand  <xmm8=%xmm14,<xmm10=%xmm8
pand  %xmm14,%xmm8

# qhasm:       xmm9 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm9=int6464#13
# asm 2: pxor  <xmm10=%xmm8,<xmm9=%xmm12
pxor  %xmm8,%xmm12

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm10=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm14=int6464#12
# asm 2: pand  <xmm15=%xmm13,<xmm14=%xmm11
pand  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm14=int6464#12
# asm 2: pxor  <xmm12=%xmm10,<xmm14=%xmm11
pxor  %xmm10,%xmm11

# qhasm:         xmm12 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm12=int6464#9
# asm 2: movdqa <xmm3=%xmm3,>xmm12=%xmm8
movdqa %xmm3,%xmm8

# qhasm:         xmm8 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm8=int6464#10
# asm 2: movdqa <xmm7=%xmm7,>xmm8=%xmm9
movdqa %xmm7,%xmm9

# qhasm:           xmm10 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm10=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm10=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm10 &= xmm3
# asm 1: pand  <xmm3=int6464#4,<xmm10=int6464#11
# asm 2: pand  <xmm3=%xmm3,<xmm10=%xmm10
pand  %xmm3,%xmm10

# qhasm:           xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:           xmm3 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm3=int6464#4
# asm 2: pand  <xmm14=%xmm11,<xmm3=%xmm3
pand  %xmm11,%xmm3

# qhasm:           xmm7 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm7=int6464#8
# asm 2: pand  <xmm15=%xmm13,<xmm7=%xmm7
pand  %xmm13,%xmm7

# qhasm:           xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:           xmm7 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm7=int6464#8
# asm 2: pxor  <xmm10=%xmm10,<xmm7=%xmm7
pxor  %xmm10,%xmm7

# qhasm:         xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm8 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm8=int6464#10
# asm 2: pxor  <xmm4=%xmm4,<xmm8=%xmm9
pxor  %xmm4,%xmm9

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm10=int6464#11
# asm 2: pand  <xmm0=%xmm0,<xmm10=%xmm10
pand  %xmm0,%xmm10

# qhasm:           xmm0 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm0=int6464#1
# asm 2: pxor  <xmm4=%xmm4,<xmm0=%xmm0
pxor  %xmm4,%xmm0

# qhasm:           xmm0 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm0=int6464#1
# asm 2: pand  <xmm9=%xmm12,<xmm0=%xmm0
pand  %xmm12,%xmm0

# qhasm:           xmm4 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm4=int6464#5
# asm 2: pand  <xmm13=%xmm15,<xmm4=%xmm4
pand  %xmm15,%xmm4

# qhasm:           xmm0 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm0=int6464#1
# asm 2: pxor  <xmm4=%xmm4,<xmm0=%xmm0
pxor  %xmm4,%xmm0

# qhasm:           xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:         xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm8,<xmm3=%xmm3
pxor  %xmm8,%xmm3

# qhasm:         xmm0 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm12=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm7 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm7=int6464#8
# asm 2: pxor  <xmm8=%xmm9,<xmm7=%xmm7
pxor  %xmm9,%xmm7

# qhasm:         xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm4=int6464#5
# asm 2: pxor  <xmm8=%xmm9,<xmm4=%xmm4
pxor  %xmm9,%xmm4

# qhasm:         xmm12 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm12=int6464#9
# asm 2: movdqa <xmm5=%xmm5,>xmm12=%xmm8
movdqa %xmm5,%xmm8

# qhasm:         xmm8 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm8=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm8=%xmm9
movdqa %xmm1,%xmm9

# qhasm:         xmm12 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm12=int6464#9
# asm 2: pxor  <xmm2=%xmm2,<xmm12=%xmm8
pxor  %xmm2,%xmm8

# qhasm:         xmm8 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm8=int6464#10
# asm 2: pxor  <xmm6=%xmm6,<xmm8=%xmm9
pxor  %xmm6,%xmm9

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm2
# asm 1: pand  <xmm2=int6464#3,<xmm10=int6464#11
# asm 2: pand  <xmm2=%xmm2,<xmm10=%xmm10
pand  %xmm2,%xmm10

# qhasm:           xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm6,<xmm2=%xmm2
pxor  %xmm6,%xmm2

# qhasm:           xmm2 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm2=int6464#3
# asm 2: pand  <xmm9=%xmm12,<xmm2=%xmm2
pand  %xmm12,%xmm2

# qhasm:           xmm6 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm6=int6464#7
# asm 2: pand  <xmm13=%xmm15,<xmm6=%xmm6
pand  %xmm15,%xmm6

# qhasm:           xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm6,<xmm2=%xmm2
pxor  %xmm6,%xmm2

# qhasm:           xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm5
# asm 1: pand  <xmm5=int6464#6,<xmm11=int6464#11
# asm 2: pand  <xmm5=%xmm5,<xmm11=%xmm10
pand  %xmm5,%xmm10

# qhasm:           xmm5 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm5=int6464#6
# asm 2: pxor  <xmm1=%xmm1,<xmm5=%xmm5
pxor  %xmm1,%xmm5

# qhasm:           xmm5 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm5=int6464#6
# asm 2: pand  <xmm14=%xmm11,<xmm5=%xmm5
pand  %xmm11,%xmm5

# qhasm:           xmm1 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm1=int6464#2
# asm 2: pand  <xmm15=%xmm13,<xmm1=%xmm1
pand  %xmm13,%xmm1

# qhasm:           xmm5 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm5=int6464#6
# asm 2: pxor  <xmm1=%xmm1,<xmm5=%xmm5
pxor  %xmm1,%xmm5

# qhasm:           xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm1=int6464#2
# asm 2: pxor  <xmm11=%xmm10,<xmm1=%xmm1
pxor  %xmm10,%xmm1

# qhasm:         xmm5 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm5=int6464#6
# asm 2: pxor  <xmm12=%xmm8,<xmm5=%xmm5
pxor  %xmm8,%xmm5

# qhasm:         xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm8,<xmm2=%xmm2
pxor  %xmm8,%xmm2

# qhasm:         xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:         xmm6 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm6=int6464#7
# asm 2: pxor  <xmm8=%xmm9,<xmm6=%xmm6
pxor  %xmm9,%xmm6

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm5=int6464#6
# asm 2: pxor  <xmm0=%xmm0,<xmm5=%xmm5
pxor  %xmm0,%xmm5

# qhasm:       xmm1 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm1=int6464#2
# asm 2: pxor  <xmm3=%xmm3,<xmm1=%xmm1
pxor  %xmm3,%xmm1

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm2=int6464#3
# asm 2: pxor  <xmm5=%xmm5,<xmm2=%xmm2
pxor  %xmm5,%xmm2

# qhasm:       xmm3 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm3=int6464#4
# asm 2: pxor  <xmm0=%xmm0,<xmm3=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm0 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm0=int6464#1
# asm 2: pxor  <xmm1=%xmm1,<xmm0=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#2
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm1
pxor  %xmm7,%xmm1

# qhasm:       xmm7 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm7=int6464#8
# asm 2: pxor  <xmm6=%xmm6,<xmm7=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:       xmm6 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm6=int6464#7
# asm 2: pxor  <xmm4=%xmm4,<xmm6=%xmm6
pxor  %xmm4,%xmm6

# qhasm:       xmm4 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm4=int6464#5
# asm 2: pxor  <xmm7=%xmm7,<xmm4=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm3=int6464#4
# asm 2: pxor  <xmm4=%xmm4,<xmm3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:   xmm7 ^= RCON
# asm 1: pxor  RCON,<xmm7=int6464#8
# asm 2: pxor  RCON,<xmm7=%xmm7
pxor  RCON,%xmm7

# qhasm:   shuffle bytes of xmm0 by EXPB0
# asm 1: pshufb EXPB0,<xmm0=int6464#1
# asm 2: pshufb EXPB0,<xmm0=%xmm0
pshufb EXPB0,%xmm0

# qhasm:   shuffle bytes of xmm1 by EXPB0
# asm 1: pshufb EXPB0,<xmm1=int6464#2
# asm 2: pshufb EXPB0,<xmm1=%xmm1
pshufb EXPB0,%xmm1

# qhasm:   shuffle bytes of xmm2 by EXPB0
# asm 1: pshufb EXPB0,<xmm2=int6464#3
# asm 2: pshufb EXPB0,<xmm2=%xmm2
pshufb EXPB0,%xmm2

# qhasm:   shuffle bytes of xmm3 by EXPB0
# asm 1: pshufb EXPB0,<xmm3=int6464#4
# asm 2: pshufb EXPB0,<xmm3=%xmm3
pshufb EXPB0,%xmm3

# qhasm:   shuffle bytes of xmm4 by EXPB0
# asm 1: pshufb EXPB0,<xmm4=int6464#5
# asm 2: pshufb EXPB0,<xmm4=%xmm4
pshufb EXPB0,%xmm4

# qhasm:   shuffle bytes of xmm5 by EXPB0
# asm 1: pshufb EXPB0,<xmm5=int6464#6
# asm 2: pshufb EXPB0,<xmm5=%xmm5
pshufb EXPB0,%xmm5

# qhasm:   shuffle bytes of xmm6 by EXPB0
# asm 1: pshufb EXPB0,<xmm6=int6464#7
# asm 2: pshufb EXPB0,<xmm6=%xmm6
pshufb EXPB0,%xmm6

# qhasm:   shuffle bytes of xmm7 by EXPB0
# asm 1: pshufb EXPB0,<xmm7=int6464#8
# asm 2: pshufb EXPB0,<xmm7=%xmm7
pshufb EXPB0,%xmm7

# qhasm:   xmm8 = *(int128 *)(c + 896)
# asm 1: movdqa 896(<c=int64#1),>xmm8=int6464#9
# asm 2: movdqa 896(<c=%rdi),>xmm8=%xmm8
movdqa 896(%rdi),%xmm8

# qhasm:   xmm9 = *(int128 *)(c + 912)
# asm 1: movdqa 912(<c=int64#1),>xmm9=int6464#10
# asm 2: movdqa 912(<c=%rdi),>xmm9=%xmm9
movdqa 912(%rdi),%xmm9

# qhasm:   xmm10 = *(int128 *)(c + 928)
# asm 1: movdqa 928(<c=int64#1),>xmm10=int6464#11
# asm 2: movdqa 928(<c=%rdi),>xmm10=%xmm10
movdqa 928(%rdi),%xmm10

# qhasm:   xmm11 = *(int128 *)(c + 944)
# asm 1: movdqa 944(<c=int64#1),>xmm11=int6464#12
# asm 2: movdqa 944(<c=%rdi),>xmm11=%xmm11
movdqa 944(%rdi),%xmm11

# qhasm:   xmm12 = *(int128 *)(c + 960)
# asm 1: movdqa 960(<c=int64#1),>xmm12=int6464#13
# asm 2: movdqa 960(<c=%rdi),>xmm12=%xmm12
movdqa 960(%rdi),%xmm12

# qhasm:   xmm13 = *(int128 *)(c + 976)
# asm 1: movdqa 976(<c=int64#1),>xmm13=int6464#14
# asm 2: movdqa 976(<c=%rdi),>xmm13=%xmm13
movdqa 976(%rdi),%xmm13

# qhasm:   xmm14 = *(int128 *)(c + 992)
# asm 1: movdqa 992(<c=int64#1),>xmm14=int6464#15
# asm 2: movdqa 992(<c=%rdi),>xmm14=%xmm14
movdqa 992(%rdi),%xmm14

# qhasm:   xmm15 = *(int128 *)(c + 1008)
# asm 1: movdqa 1008(<c=int64#1),>xmm15=int6464#16
# asm 2: movdqa 1008(<c=%rdi),>xmm15=%xmm15
movdqa 1008(%rdi),%xmm15

# qhasm:   xmm8 ^= ONE
# asm 1: pxor  ONE,<xmm8=int6464#9
# asm 2: pxor  ONE,<xmm8=%xmm8
pxor  ONE,%xmm8

# qhasm:   xmm9 ^= ONE
# asm 1: pxor  ONE,<xmm9=int6464#10
# asm 2: pxor  ONE,<xmm9=%xmm9
pxor  ONE,%xmm9

# qhasm:   xmm13 ^= ONE
# asm 1: pxor  ONE,<xmm13=int6464#14
# asm 2: pxor  ONE,<xmm13=%xmm13
pxor  ONE,%xmm13

# qhasm:   xmm14 ^= ONE
# asm 1: pxor  ONE,<xmm14=int6464#15
# asm 2: pxor  ONE,<xmm14=%xmm14
pxor  ONE,%xmm14

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#3
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm2
pxor  %xmm10,%xmm2

# qhasm:   xmm3 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm3=int6464#4
# asm 2: pxor  <xmm11=%xmm11,<xmm3=%xmm3
pxor  %xmm11,%xmm3

# qhasm:   xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm4=int6464#5
# asm 2: pxor  <xmm12=%xmm12,<xmm4=%xmm4
pxor  %xmm12,%xmm4

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm6 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm6=int6464#7
# asm 2: pxor  <xmm14=%xmm14,<xmm6=%xmm6
pxor  %xmm14,%xmm6

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#3
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm2
pxor  %xmm10,%xmm2

# qhasm:   xmm3 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm3=int6464#4
# asm 2: pxor  <xmm11=%xmm11,<xmm3=%xmm3
pxor  %xmm11,%xmm3

# qhasm:   xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm4=int6464#5
# asm 2: pxor  <xmm12=%xmm12,<xmm4=%xmm4
pxor  %xmm12,%xmm4

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm6 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm6=int6464#7
# asm 2: pxor  <xmm14=%xmm14,<xmm6=%xmm6
pxor  %xmm14,%xmm6

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#3
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm2
pxor  %xmm10,%xmm2

# qhasm:   xmm3 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm3=int6464#4
# asm 2: pxor  <xmm11=%xmm11,<xmm3=%xmm3
pxor  %xmm11,%xmm3

# qhasm:   xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm4=int6464#5
# asm 2: pxor  <xmm12=%xmm12,<xmm4=%xmm4
pxor  %xmm12,%xmm4

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm6 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm6=int6464#7
# asm 2: pxor  <xmm14=%xmm14,<xmm6=%xmm6
pxor  %xmm14,%xmm6

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#3
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm2
pxor  %xmm10,%xmm2

# qhasm:   xmm3 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm3=int6464#4
# asm 2: pxor  <xmm11=%xmm11,<xmm3=%xmm3
pxor  %xmm11,%xmm3

# qhasm:   xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm4=int6464#5
# asm 2: pxor  <xmm12=%xmm12,<xmm4=%xmm4
pxor  %xmm12,%xmm4

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm6 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm6=int6464#7
# asm 2: pxor  <xmm14=%xmm14,<xmm6=%xmm6
pxor  %xmm14,%xmm6

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   *(int128 *)(c + 1024) = xmm0
# asm 1: movdqa <xmm0=int6464#1,1024(<c=int64#1)
# asm 2: movdqa <xmm0=%xmm0,1024(<c=%rdi)
movdqa %xmm0,1024(%rdi)

# qhasm:   *(int128 *)(c + 1040) = xmm1
# asm 1: movdqa <xmm1=int6464#2,1040(<c=int64#1)
# asm 2: movdqa <xmm1=%xmm1,1040(<c=%rdi)
movdqa %xmm1,1040(%rdi)

# qhasm:   *(int128 *)(c + 1056) = xmm2
# asm 1: movdqa <xmm2=int6464#3,1056(<c=int64#1)
# asm 2: movdqa <xmm2=%xmm2,1056(<c=%rdi)
movdqa %xmm2,1056(%rdi)

# qhasm:   *(int128 *)(c + 1072) = xmm3
# asm 1: movdqa <xmm3=int6464#4,1072(<c=int64#1)
# asm 2: movdqa <xmm3=%xmm3,1072(<c=%rdi)
movdqa %xmm3,1072(%rdi)

# qhasm:   *(int128 *)(c + 1088) = xmm4
# asm 1: movdqa <xmm4=int6464#5,1088(<c=int64#1)
# asm 2: movdqa <xmm4=%xmm4,1088(<c=%rdi)
movdqa %xmm4,1088(%rdi)

# qhasm:   *(int128 *)(c + 1104) = xmm5
# asm 1: movdqa <xmm5=int6464#6,1104(<c=int64#1)
# asm 2: movdqa <xmm5=%xmm5,1104(<c=%rdi)
movdqa %xmm5,1104(%rdi)

# qhasm:   *(int128 *)(c + 1120) = xmm6
# asm 1: movdqa <xmm6=int6464#7,1120(<c=int64#1)
# asm 2: movdqa <xmm6=%xmm6,1120(<c=%rdi)
movdqa %xmm6,1120(%rdi)

# qhasm:   *(int128 *)(c + 1136) = xmm7
# asm 1: movdqa <xmm7=int6464#8,1136(<c=int64#1)
# asm 2: movdqa <xmm7=%xmm7,1136(<c=%rdi)
movdqa %xmm7,1136(%rdi)

# qhasm:   xmm0 ^= ONE
# asm 1: pxor  ONE,<xmm0=int6464#1
# asm 2: pxor  ONE,<xmm0=%xmm0
pxor  ONE,%xmm0

# qhasm:   xmm1 ^= ONE
# asm 1: pxor  ONE,<xmm1=int6464#2
# asm 2: pxor  ONE,<xmm1=%xmm1
pxor  ONE,%xmm1

# qhasm:   xmm5 ^= ONE
# asm 1: pxor  ONE,<xmm5=int6464#6
# asm 2: pxor  ONE,<xmm5=%xmm5
pxor  ONE,%xmm5

# qhasm:   xmm6 ^= ONE
# asm 1: pxor  ONE,<xmm6=int6464#7
# asm 2: pxor  ONE,<xmm6=%xmm6
pxor  ONE,%xmm6

# qhasm:     shuffle bytes of xmm0 by ROTB
# asm 1: pshufb ROTB,<xmm0=int6464#1
# asm 2: pshufb ROTB,<xmm0=%xmm0
pshufb ROTB,%xmm0

# qhasm:     shuffle bytes of xmm1 by ROTB
# asm 1: pshufb ROTB,<xmm1=int6464#2
# asm 2: pshufb ROTB,<xmm1=%xmm1
pshufb ROTB,%xmm1

# qhasm:     shuffle bytes of xmm2 by ROTB
# asm 1: pshufb ROTB,<xmm2=int6464#3
# asm 2: pshufb ROTB,<xmm2=%xmm2
pshufb ROTB,%xmm2

# qhasm:     shuffle bytes of xmm3 by ROTB
# asm 1: pshufb ROTB,<xmm3=int6464#4
# asm 2: pshufb ROTB,<xmm3=%xmm3
pshufb ROTB,%xmm3

# qhasm:     shuffle bytes of xmm4 by ROTB
# asm 1: pshufb ROTB,<xmm4=int6464#5
# asm 2: pshufb ROTB,<xmm4=%xmm4
pshufb ROTB,%xmm4

# qhasm:     shuffle bytes of xmm5 by ROTB
# asm 1: pshufb ROTB,<xmm5=int6464#6
# asm 2: pshufb ROTB,<xmm5=%xmm5
pshufb ROTB,%xmm5

# qhasm:     shuffle bytes of xmm6 by ROTB
# asm 1: pshufb ROTB,<xmm6=int6464#7
# asm 2: pshufb ROTB,<xmm6=%xmm6
pshufb ROTB,%xmm6

# qhasm:     shuffle bytes of xmm7 by ROTB
# asm 1: pshufb ROTB,<xmm7=int6464#8
# asm 2: pshufb ROTB,<xmm7=%xmm7
pshufb ROTB,%xmm7

# qhasm:       xmm5 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm5=int6464#6
# asm 2: pxor  <xmm6=%xmm6,<xmm5=%xmm5
pxor  %xmm6,%xmm5

# qhasm:       xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm1,<xmm2=%xmm2
pxor  %xmm1,%xmm2

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm5=int6464#6
# asm 2: pxor  <xmm0=%xmm0,<xmm5=%xmm5
pxor  %xmm0,%xmm5

# qhasm:       xmm6 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm6=int6464#7
# asm 2: pxor  <xmm2=%xmm2,<xmm6=%xmm6
pxor  %xmm2,%xmm6

# qhasm:       xmm3 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm3=int6464#4
# asm 2: pxor  <xmm0=%xmm0,<xmm3=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm6=int6464#7
# asm 2: pxor  <xmm3=%xmm3,<xmm6=%xmm6
pxor  %xmm3,%xmm6

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:       xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm3=int6464#4
# asm 2: pxor  <xmm4=%xmm4,<xmm3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:       xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm7=int6464#8
# asm 2: pxor  <xmm5=%xmm5,<xmm7=%xmm7
pxor  %xmm5,%xmm7

# qhasm:       xmm3 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm3=int6464#4
# asm 2: pxor  <xmm1=%xmm1,<xmm3=%xmm3
pxor  %xmm1,%xmm3

# qhasm:       xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm1=int6464#2
# asm 2: pxor  <xmm5=%xmm5,<xmm1=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm11 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm11=int6464#9
# asm 2: movdqa <xmm7=%xmm7,>xmm11=%xmm8
movdqa %xmm7,%xmm8

# qhasm:       xmm10 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm10=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm10=%xmm9
movdqa %xmm1,%xmm9

# qhasm:       xmm9 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm9=int6464#11
# asm 2: movdqa <xmm5=%xmm5,>xmm9=%xmm10
movdqa %xmm5,%xmm10

# qhasm:       xmm13 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm13=int6464#12
# asm 2: movdqa <xmm2=%xmm2,>xmm13=%xmm11
movdqa %xmm2,%xmm11

# qhasm:       xmm12 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm12=int6464#13
# asm 2: movdqa <xmm6=%xmm6,>xmm12=%xmm12
movdqa %xmm6,%xmm12

# qhasm:       xmm11 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm11=int6464#9
# asm 2: pxor  <xmm4=%xmm4,<xmm11=%xmm8
pxor  %xmm4,%xmm8

# qhasm:       xmm10 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm10=int6464#10
# asm 2: pxor  <xmm2=%xmm2,<xmm10=%xmm9
pxor  %xmm2,%xmm9

# qhasm:       xmm9 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm9=int6464#11
# asm 2: pxor  <xmm3=%xmm3,<xmm9=%xmm10
pxor  %xmm3,%xmm10

# qhasm:       xmm13 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm13=int6464#12
# asm 2: pxor  <xmm4=%xmm4,<xmm13=%xmm11
pxor  %xmm4,%xmm11

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:       xmm14 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm14=int6464#14
# asm 2: movdqa <xmm11=%xmm8,>xmm14=%xmm13
movdqa %xmm8,%xmm13

# qhasm:       xmm8 = xmm10
# asm 1: movdqa <xmm10=int6464#10,>xmm8=int6464#15
# asm 2: movdqa <xmm10=%xmm9,>xmm8=%xmm14
movdqa %xmm9,%xmm14

# qhasm:       xmm15 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm15=int6464#16
# asm 2: movdqa <xmm11=%xmm8,>xmm15=%xmm15
movdqa %xmm8,%xmm15

# qhasm:       xmm10 |= xmm9
# asm 1: por   <xmm9=int6464#11,<xmm10=int6464#10
# asm 2: por   <xmm9=%xmm10,<xmm10=%xmm9
por   %xmm10,%xmm9

# qhasm:       xmm11 |= xmm12
# asm 1: por   <xmm12=int6464#13,<xmm11=int6464#9
# asm 2: por   <xmm12=%xmm12,<xmm11=%xmm8
por   %xmm12,%xmm8

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm15=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm14 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm14=int6464#14
# asm 2: pand  <xmm12=%xmm12,<xmm14=%xmm13
pand  %xmm12,%xmm13

# qhasm:       xmm8 &= xmm9
# asm 1: pand  <xmm9=int6464#11,<xmm8=int6464#15
# asm 2: pand  <xmm9=%xmm10,<xmm8=%xmm14
pand  %xmm10,%xmm14

# qhasm:       xmm12 ^= xmm9
# asm 1: pxor  <xmm9=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm9=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:       xmm15 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm15=int6464#16
# asm 2: pand  <xmm12=%xmm12,<xmm15=%xmm15
pand  %xmm12,%xmm15

# qhasm:       xmm12 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm12=int6464#11
# asm 2: movdqa <xmm3=%xmm3,>xmm12=%xmm10
movdqa %xmm3,%xmm10

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#11
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm10
pxor  %xmm0,%xmm10

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#11,<xmm13=int6464#12
# asm 2: pand  <xmm12=%xmm10,<xmm13=%xmm11
pand  %xmm10,%xmm11

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm11=int6464#9
# asm 2: pxor  <xmm13=%xmm11,<xmm11=%xmm8
pxor  %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm13 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm13=int6464#11
# asm 2: movdqa <xmm7=%xmm7,>xmm13=%xmm10
movdqa %xmm7,%xmm10

# qhasm:       xmm13 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm13=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm13=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm12 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm12=int6464#12
# asm 2: movdqa <xmm5=%xmm5,>xmm12=%xmm11
movdqa %xmm5,%xmm11

# qhasm:       xmm9 = xmm13
# asm 1: movdqa <xmm13=int6464#11,>xmm9=int6464#13
# asm 2: movdqa <xmm13=%xmm10,>xmm9=%xmm12
movdqa %xmm10,%xmm12

# qhasm:       xmm12 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm12=int6464#12
# asm 2: pxor  <xmm6=%xmm6,<xmm12=%xmm11
pxor  %xmm6,%xmm11

# qhasm:       xmm9 |= xmm12
# asm 1: por   <xmm12=int6464#12,<xmm9=int6464#13
# asm 2: por   <xmm12=%xmm11,<xmm9=%xmm12
por   %xmm11,%xmm12

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#12,<xmm13=int6464#11
# asm 2: pand  <xmm12=%xmm11,<xmm13=%xmm10
pand  %xmm11,%xmm10

# qhasm:       xmm8 ^= xmm13
# asm 1: pxor  <xmm13=int6464#11,<xmm8=int6464#15
# asm 2: pxor  <xmm13=%xmm10,<xmm8=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#9
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm10=int6464#10
# asm 2: pxor  <xmm14=%xmm13,<xmm10=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm9 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm8 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm8=int6464#15
# asm 2: pxor  <xmm14=%xmm13,<xmm8=%xmm14
pxor  %xmm13,%xmm14

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm12 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm12=int6464#11
# asm 2: movdqa <xmm2=%xmm2,>xmm12=%xmm10
movdqa %xmm2,%xmm10

# qhasm:       xmm13 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm13=int6464#12
# asm 2: movdqa <xmm4=%xmm4,>xmm13=%xmm11
movdqa %xmm4,%xmm11

# qhasm:       xmm14 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm14=int6464#14
# asm 2: movdqa <xmm1=%xmm1,>xmm14=%xmm13
movdqa %xmm1,%xmm13

# qhasm:       xmm15 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm15=int6464#16
# asm 2: movdqa <xmm7=%xmm7,>xmm15=%xmm15
movdqa %xmm7,%xmm15

# qhasm:       xmm12 &= xmm3
# asm 1: pand  <xmm3=int6464#4,<xmm12=int6464#11
# asm 2: pand  <xmm3=%xmm3,<xmm12=%xmm10
pand  %xmm3,%xmm10

# qhasm:       xmm13 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm13=int6464#12
# asm 2: pand  <xmm0=%xmm0,<xmm13=%xmm11
pand  %xmm0,%xmm11

# qhasm:       xmm14 &= xmm5
# asm 1: pand  <xmm5=int6464#6,<xmm14=int6464#14
# asm 2: pand  <xmm5=%xmm5,<xmm14=%xmm13
pand  %xmm5,%xmm13

# qhasm:       xmm15 |= xmm6
# asm 1: por   <xmm6=int6464#7,<xmm15=int6464#16
# asm 2: por   <xmm6=%xmm6,<xmm15=%xmm15
por   %xmm6,%xmm15

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm11=int6464#9
# asm 2: pxor  <xmm12=%xmm10,<xmm11=%xmm8
pxor  %xmm10,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm8 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm8=int6464#15
# asm 2: pxor  <xmm15=%xmm15,<xmm8=%xmm14
pxor  %xmm15,%xmm14

# qhasm:       xmm12 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm12=int6464#11
# asm 2: movdqa <xmm11=%xmm8,>xmm12=%xmm10
movdqa %xmm8,%xmm10

# qhasm:       xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm12=int6464#11
# asm 2: pxor  <xmm10=%xmm9,<xmm12=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm11 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm11=int6464#9
# asm 2: pand  <xmm9=%xmm12,<xmm11=%xmm8
pand  %xmm12,%xmm8

# qhasm:       xmm14 = xmm8
# asm 1: movdqa <xmm8=int6464#15,>xmm14=int6464#12
# asm 2: movdqa <xmm8=%xmm14,>xmm14=%xmm11
movdqa %xmm14,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm11=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm15 = xmm12
# asm 1: movdqa <xmm12=int6464#11,>xmm15=int6464#14
# asm 2: movdqa <xmm12=%xmm10,>xmm15=%xmm13
movdqa %xmm10,%xmm13

# qhasm:       xmm15 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm15=int6464#14
# asm 2: pand  <xmm14=%xmm11,<xmm15=%xmm13
pand  %xmm11,%xmm13

# qhasm:       xmm15 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm15=int6464#14
# asm 2: pxor  <xmm10=%xmm9,<xmm15=%xmm13
pxor  %xmm9,%xmm13

# qhasm:       xmm13 = xmm9
# asm 1: movdqa <xmm9=int6464#13,>xmm13=int6464#16
# asm 2: movdqa <xmm9=%xmm12,>xmm13=%xmm15
movdqa %xmm12,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm11 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm11=int6464#9
# asm 2: pxor  <xmm10=%xmm9,<xmm11=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm13 &= xmm11
# asm 1: pand  <xmm11=int6464#9,<xmm13=int6464#16
# asm 2: pand  <xmm11=%xmm8,<xmm13=%xmm15
pand  %xmm8,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm13=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm10 = xmm14
# asm 1: movdqa <xmm14=int6464#12,>xmm10=int6464#9
# asm 2: movdqa <xmm14=%xmm11,>xmm10=%xmm8
movdqa %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm10=int6464#9
# asm 2: pxor  <xmm13=%xmm15,<xmm10=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 &= xmm8
# asm 1: pand  <xmm8=int6464#15,<xmm10=int6464#9
# asm 2: pand  <xmm8=%xmm14,<xmm10=%xmm8
pand  %xmm14,%xmm8

# qhasm:       xmm9 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm9=int6464#13
# asm 2: pxor  <xmm10=%xmm8,<xmm9=%xmm12
pxor  %xmm8,%xmm12

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm10=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm14=int6464#12
# asm 2: pand  <xmm15=%xmm13,<xmm14=%xmm11
pand  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm14=int6464#12
# asm 2: pxor  <xmm12=%xmm10,<xmm14=%xmm11
pxor  %xmm10,%xmm11

# qhasm:         xmm12 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm12=int6464#9
# asm 2: movdqa <xmm6=%xmm6,>xmm12=%xmm8
movdqa %xmm6,%xmm8

# qhasm:         xmm8 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm8=int6464#10
# asm 2: movdqa <xmm5=%xmm5,>xmm8=%xmm9
movdqa %xmm5,%xmm9

# qhasm:           xmm10 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm10=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm10=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm10 &= xmm6
# asm 1: pand  <xmm6=int6464#7,<xmm10=int6464#11
# asm 2: pand  <xmm6=%xmm6,<xmm10=%xmm10
pand  %xmm6,%xmm10

# qhasm:           xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:           xmm6 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm6=int6464#7
# asm 2: pand  <xmm14=%xmm11,<xmm6=%xmm6
pand  %xmm11,%xmm6

# qhasm:           xmm5 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm5=int6464#6
# asm 2: pand  <xmm15=%xmm13,<xmm5=%xmm5
pand  %xmm13,%xmm5

# qhasm:           xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:           xmm5 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm5=int6464#6
# asm 2: pxor  <xmm10=%xmm10,<xmm5=%xmm5
pxor  %xmm10,%xmm5

# qhasm:         xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm8 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm8=int6464#10
# asm 2: pxor  <xmm3=%xmm3,<xmm8=%xmm9
pxor  %xmm3,%xmm9

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm10=int6464#11
# asm 2: pand  <xmm0=%xmm0,<xmm10=%xmm10
pand  %xmm0,%xmm10

# qhasm:           xmm0 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm0=int6464#1
# asm 2: pxor  <xmm3=%xmm3,<xmm0=%xmm0
pxor  %xmm3,%xmm0

# qhasm:           xmm0 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm0=int6464#1
# asm 2: pand  <xmm9=%xmm12,<xmm0=%xmm0
pand  %xmm12,%xmm0

# qhasm:           xmm3 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm3=int6464#4
# asm 2: pand  <xmm13=%xmm15,<xmm3=%xmm3
pand  %xmm15,%xmm3

# qhasm:           xmm0 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm0=int6464#1
# asm 2: pxor  <xmm3=%xmm3,<xmm0=%xmm0
pxor  %xmm3,%xmm0

# qhasm:           xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:         xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm8,<xmm6=%xmm6
pxor  %xmm8,%xmm6

# qhasm:         xmm0 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm12=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm5 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm5=int6464#6
# asm 2: pxor  <xmm8=%xmm9,<xmm5=%xmm5
pxor  %xmm9,%xmm5

# qhasm:         xmm3 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm3=int6464#4
# asm 2: pxor  <xmm8=%xmm9,<xmm3=%xmm3
pxor  %xmm9,%xmm3

# qhasm:         xmm12 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm12=int6464#9
# asm 2: movdqa <xmm7=%xmm7,>xmm12=%xmm8
movdqa %xmm7,%xmm8

# qhasm:         xmm8 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm8=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm8=%xmm9
movdqa %xmm1,%xmm9

# qhasm:         xmm12 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm12=int6464#9
# asm 2: pxor  <xmm4=%xmm4,<xmm12=%xmm8
pxor  %xmm4,%xmm8

# qhasm:         xmm8 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm8=int6464#10
# asm 2: pxor  <xmm2=%xmm2,<xmm8=%xmm9
pxor  %xmm2,%xmm9

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm10=int6464#11
# asm 2: pand  <xmm4=%xmm4,<xmm10=%xmm10
pand  %xmm4,%xmm10

# qhasm:           xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm2=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:           xmm4 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm4=int6464#5
# asm 2: pand  <xmm9=%xmm12,<xmm4=%xmm4
pand  %xmm12,%xmm4

# qhasm:           xmm2 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm2=int6464#3
# asm 2: pand  <xmm13=%xmm15,<xmm2=%xmm2
pand  %xmm15,%xmm2

# qhasm:           xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm2=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:           xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#3
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm2
pxor  %xmm10,%xmm2

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm7
# asm 1: pand  <xmm7=int6464#8,<xmm11=int6464#11
# asm 2: pand  <xmm7=%xmm7,<xmm11=%xmm10
pand  %xmm7,%xmm10

# qhasm:           xmm7 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm7=int6464#8
# asm 2: pxor  <xmm1=%xmm1,<xmm7=%xmm7
pxor  %xmm1,%xmm7

# qhasm:           xmm7 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm7=int6464#8
# asm 2: pand  <xmm14=%xmm11,<xmm7=%xmm7
pand  %xmm11,%xmm7

# qhasm:           xmm1 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm1=int6464#2
# asm 2: pand  <xmm15=%xmm13,<xmm1=%xmm1
pand  %xmm13,%xmm1

# qhasm:           xmm7 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm7=int6464#8
# asm 2: pxor  <xmm1=%xmm1,<xmm7=%xmm7
pxor  %xmm1,%xmm7

# qhasm:           xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm1=int6464#2
# asm 2: pxor  <xmm11=%xmm10,<xmm1=%xmm1
pxor  %xmm10,%xmm1

# qhasm:         xmm7 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm7=int6464#8
# asm 2: pxor  <xmm12=%xmm8,<xmm7=%xmm7
pxor  %xmm8,%xmm7

# qhasm:         xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <xmm12=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:         xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:         xmm2 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm2=int6464#3
# asm 2: pxor  <xmm8=%xmm9,<xmm2=%xmm2
pxor  %xmm9,%xmm2

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm0,<xmm7=%xmm7
pxor  %xmm0,%xmm7

# qhasm:       xmm1 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm1=int6464#2
# asm 2: pxor  <xmm6=%xmm6,<xmm1=%xmm1
pxor  %xmm6,%xmm1

# qhasm:       xmm4 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm4=int6464#5
# asm 2: pxor  <xmm7=%xmm7,<xmm4=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm6 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm6=int6464#7
# asm 2: pxor  <xmm0=%xmm0,<xmm6=%xmm6
pxor  %xmm0,%xmm6

# qhasm:       xmm0 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm0=int6464#1
# asm 2: pxor  <xmm1=%xmm1,<xmm0=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm1=int6464#2
# asm 2: pxor  <xmm5=%xmm5,<xmm1=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm5 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm5=int6464#6
# asm 2: pxor  <xmm2=%xmm2,<xmm5=%xmm5
pxor  %xmm2,%xmm5

# qhasm:       xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm2 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm2=int6464#3
# asm 2: pxor  <xmm3=%xmm3,<xmm2=%xmm2
pxor  %xmm3,%xmm2

# qhasm:       xmm3 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm3=int6464#4
# asm 2: pxor  <xmm5=%xmm5,<xmm3=%xmm3
pxor  %xmm5,%xmm3

# qhasm:       xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm6=int6464#7
# asm 2: pxor  <xmm3=%xmm3,<xmm6=%xmm6
pxor  %xmm3,%xmm6

# qhasm:   xmm0 ^= RCON
# asm 1: pxor  RCON,<xmm0=int6464#1
# asm 2: pxor  RCON,<xmm0=%xmm0
pxor  RCON,%xmm0

# qhasm:   xmm1 ^= RCON
# asm 1: pxor  RCON,<xmm1=int6464#2
# asm 2: pxor  RCON,<xmm1=%xmm1
pxor  RCON,%xmm1

# qhasm:   xmm6 ^= RCON
# asm 1: pxor  RCON,<xmm6=int6464#7
# asm 2: pxor  RCON,<xmm6=%xmm6
pxor  RCON,%xmm6

# qhasm:   xmm3 ^= RCON
# asm 1: pxor  RCON,<xmm3=int6464#4
# asm 2: pxor  RCON,<xmm3=%xmm3
pxor  RCON,%xmm3

# qhasm:   shuffle bytes of xmm0 by EXPB0
# asm 1: pshufb EXPB0,<xmm0=int6464#1
# asm 2: pshufb EXPB0,<xmm0=%xmm0
pshufb EXPB0,%xmm0

# qhasm:   shuffle bytes of xmm1 by EXPB0
# asm 1: pshufb EXPB0,<xmm1=int6464#2
# asm 2: pshufb EXPB0,<xmm1=%xmm1
pshufb EXPB0,%xmm1

# qhasm:   shuffle bytes of xmm4 by EXPB0
# asm 1: pshufb EXPB0,<xmm4=int6464#5
# asm 2: pshufb EXPB0,<xmm4=%xmm4
pshufb EXPB0,%xmm4

# qhasm:   shuffle bytes of xmm6 by EXPB0
# asm 1: pshufb EXPB0,<xmm6=int6464#7
# asm 2: pshufb EXPB0,<xmm6=%xmm6
pshufb EXPB0,%xmm6

# qhasm:   shuffle bytes of xmm3 by EXPB0
# asm 1: pshufb EXPB0,<xmm3=int6464#4
# asm 2: pshufb EXPB0,<xmm3=%xmm3
pshufb EXPB0,%xmm3

# qhasm:   shuffle bytes of xmm7 by EXPB0
# asm 1: pshufb EXPB0,<xmm7=int6464#8
# asm 2: pshufb EXPB0,<xmm7=%xmm7
pshufb EXPB0,%xmm7

# qhasm:   shuffle bytes of xmm2 by EXPB0
# asm 1: pshufb EXPB0,<xmm2=int6464#3
# asm 2: pshufb EXPB0,<xmm2=%xmm2
pshufb EXPB0,%xmm2

# qhasm:   shuffle bytes of xmm5 by EXPB0
# asm 1: pshufb EXPB0,<xmm5=int6464#6
# asm 2: pshufb EXPB0,<xmm5=%xmm5
pshufb EXPB0,%xmm5

# qhasm:   xmm8 = *(int128 *)(c + 1024)
# asm 1: movdqa 1024(<c=int64#1),>xmm8=int6464#9
# asm 2: movdqa 1024(<c=%rdi),>xmm8=%xmm8
movdqa 1024(%rdi),%xmm8

# qhasm:   xmm9 = *(int128 *)(c + 1040)
# asm 1: movdqa 1040(<c=int64#1),>xmm9=int6464#10
# asm 2: movdqa 1040(<c=%rdi),>xmm9=%xmm9
movdqa 1040(%rdi),%xmm9

# qhasm:   xmm10 = *(int128 *)(c + 1056)
# asm 1: movdqa 1056(<c=int64#1),>xmm10=int6464#11
# asm 2: movdqa 1056(<c=%rdi),>xmm10=%xmm10
movdqa 1056(%rdi),%xmm10

# qhasm:   xmm11 = *(int128 *)(c + 1072)
# asm 1: movdqa 1072(<c=int64#1),>xmm11=int6464#12
# asm 2: movdqa 1072(<c=%rdi),>xmm11=%xmm11
movdqa 1072(%rdi),%xmm11

# qhasm:   xmm12 = *(int128 *)(c + 1088)
# asm 1: movdqa 1088(<c=int64#1),>xmm12=int6464#13
# asm 2: movdqa 1088(<c=%rdi),>xmm12=%xmm12
movdqa 1088(%rdi),%xmm12

# qhasm:   xmm13 = *(int128 *)(c + 1104)
# asm 1: movdqa 1104(<c=int64#1),>xmm13=int6464#14
# asm 2: movdqa 1104(<c=%rdi),>xmm13=%xmm13
movdqa 1104(%rdi),%xmm13

# qhasm:   xmm14 = *(int128 *)(c + 1120)
# asm 1: movdqa 1120(<c=int64#1),>xmm14=int6464#15
# asm 2: movdqa 1120(<c=%rdi),>xmm14=%xmm14
movdqa 1120(%rdi),%xmm14

# qhasm:   xmm15 = *(int128 *)(c + 1136)
# asm 1: movdqa 1136(<c=int64#1),>xmm15=int6464#16
# asm 2: movdqa 1136(<c=%rdi),>xmm15=%xmm15
movdqa 1136(%rdi),%xmm15

# qhasm:   xmm8 ^= ONE
# asm 1: pxor  ONE,<xmm8=int6464#9
# asm 2: pxor  ONE,<xmm8=%xmm8
pxor  ONE,%xmm8

# qhasm:   xmm9 ^= ONE
# asm 1: pxor  ONE,<xmm9=int6464#10
# asm 2: pxor  ONE,<xmm9=%xmm9
pxor  ONE,%xmm9

# qhasm:   xmm13 ^= ONE
# asm 1: pxor  ONE,<xmm13=int6464#14
# asm 2: pxor  ONE,<xmm13=%xmm13
pxor  ONE,%xmm13

# qhasm:   xmm14 ^= ONE
# asm 1: pxor  ONE,<xmm14=int6464#15
# asm 2: pxor  ONE,<xmm14=%xmm14
pxor  ONE,%xmm14

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:   xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:   xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:   xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:   xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:   xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:   xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:   xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:   xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:   xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:   xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:   xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:   *(int128 *)(c + 1152) = xmm0
# asm 1: movdqa <xmm0=int6464#1,1152(<c=int64#1)
# asm 2: movdqa <xmm0=%xmm0,1152(<c=%rdi)
movdqa %xmm0,1152(%rdi)

# qhasm:   *(int128 *)(c + 1168) = xmm1
# asm 1: movdqa <xmm1=int6464#2,1168(<c=int64#1)
# asm 2: movdqa <xmm1=%xmm1,1168(<c=%rdi)
movdqa %xmm1,1168(%rdi)

# qhasm:   *(int128 *)(c + 1184) = xmm4
# asm 1: movdqa <xmm4=int6464#5,1184(<c=int64#1)
# asm 2: movdqa <xmm4=%xmm4,1184(<c=%rdi)
movdqa %xmm4,1184(%rdi)

# qhasm:   *(int128 *)(c + 1200) = xmm6
# asm 1: movdqa <xmm6=int6464#7,1200(<c=int64#1)
# asm 2: movdqa <xmm6=%xmm6,1200(<c=%rdi)
movdqa %xmm6,1200(%rdi)

# qhasm:   *(int128 *)(c + 1216) = xmm3
# asm 1: movdqa <xmm3=int6464#4,1216(<c=int64#1)
# asm 2: movdqa <xmm3=%xmm3,1216(<c=%rdi)
movdqa %xmm3,1216(%rdi)

# qhasm:   *(int128 *)(c + 1232) = xmm7
# asm 1: movdqa <xmm7=int6464#8,1232(<c=int64#1)
# asm 2: movdqa <xmm7=%xmm7,1232(<c=%rdi)
movdqa %xmm7,1232(%rdi)

# qhasm:   *(int128 *)(c + 1248) = xmm2
# asm 1: movdqa <xmm2=int6464#3,1248(<c=int64#1)
# asm 2: movdqa <xmm2=%xmm2,1248(<c=%rdi)
movdqa %xmm2,1248(%rdi)

# qhasm:   *(int128 *)(c + 1264) = xmm5
# asm 1: movdqa <xmm5=int6464#6,1264(<c=int64#1)
# asm 2: movdqa <xmm5=%xmm5,1264(<c=%rdi)
movdqa %xmm5,1264(%rdi)

# qhasm:   xmm0 ^= ONE
# asm 1: pxor  ONE,<xmm0=int6464#1
# asm 2: pxor  ONE,<xmm0=%xmm0
pxor  ONE,%xmm0

# qhasm:   xmm1 ^= ONE
# asm 1: pxor  ONE,<xmm1=int6464#2
# asm 2: pxor  ONE,<xmm1=%xmm1
pxor  ONE,%xmm1

# qhasm:   xmm7 ^= ONE
# asm 1: pxor  ONE,<xmm7=int6464#8
# asm 2: pxor  ONE,<xmm7=%xmm7
pxor  ONE,%xmm7

# qhasm:   xmm2 ^= ONE
# asm 1: pxor  ONE,<xmm2=int6464#3
# asm 2: pxor  ONE,<xmm2=%xmm2
pxor  ONE,%xmm2

# qhasm:     shuffle bytes of xmm0 by ROTB
# asm 1: pshufb ROTB,<xmm0=int6464#1
# asm 2: pshufb ROTB,<xmm0=%xmm0
pshufb ROTB,%xmm0

# qhasm:     shuffle bytes of xmm1 by ROTB
# asm 1: pshufb ROTB,<xmm1=int6464#2
# asm 2: pshufb ROTB,<xmm1=%xmm1
pshufb ROTB,%xmm1

# qhasm:     shuffle bytes of xmm4 by ROTB
# asm 1: pshufb ROTB,<xmm4=int6464#5
# asm 2: pshufb ROTB,<xmm4=%xmm4
pshufb ROTB,%xmm4

# qhasm:     shuffle bytes of xmm6 by ROTB
# asm 1: pshufb ROTB,<xmm6=int6464#7
# asm 2: pshufb ROTB,<xmm6=%xmm6
pshufb ROTB,%xmm6

# qhasm:     shuffle bytes of xmm3 by ROTB
# asm 1: pshufb ROTB,<xmm3=int6464#4
# asm 2: pshufb ROTB,<xmm3=%xmm3
pshufb ROTB,%xmm3

# qhasm:     shuffle bytes of xmm7 by ROTB
# asm 1: pshufb ROTB,<xmm7=int6464#8
# asm 2: pshufb ROTB,<xmm7=%xmm7
pshufb ROTB,%xmm7

# qhasm:     shuffle bytes of xmm2 by ROTB
# asm 1: pshufb ROTB,<xmm2=int6464#3
# asm 2: pshufb ROTB,<xmm2=%xmm2
pshufb ROTB,%xmm2

# qhasm:     shuffle bytes of xmm5 by ROTB
# asm 1: pshufb ROTB,<xmm5=int6464#6
# asm 2: pshufb ROTB,<xmm5=%xmm5
pshufb ROTB,%xmm5

# qhasm:       xmm7 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm7=int6464#8
# asm 2: pxor  <xmm2=%xmm2,<xmm7=%xmm7
pxor  %xmm2,%xmm7

# qhasm:       xmm4 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm4=int6464#5
# asm 2: pxor  <xmm1=%xmm1,<xmm4=%xmm4
pxor  %xmm1,%xmm4

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm0,<xmm7=%xmm7
pxor  %xmm0,%xmm7

# qhasm:       xmm2 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm2=int6464#3
# asm 2: pxor  <xmm4=%xmm4,<xmm2=%xmm2
pxor  %xmm4,%xmm2

# qhasm:       xmm6 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm6=int6464#7
# asm 2: pxor  <xmm0=%xmm0,<xmm6=%xmm6
pxor  %xmm0,%xmm6

# qhasm:       xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm6,<xmm2=%xmm2
pxor  %xmm6,%xmm2

# qhasm:       xmm6 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm6=int6464#7
# asm 2: pxor  <xmm5=%xmm5,<xmm6=%xmm6
pxor  %xmm5,%xmm6

# qhasm:       xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm6=int6464#7
# asm 2: pxor  <xmm3=%xmm3,<xmm6=%xmm6
pxor  %xmm3,%xmm6

# qhasm:       xmm5 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm5=int6464#6
# asm 2: pxor  <xmm7=%xmm7,<xmm5=%xmm5
pxor  %xmm7,%xmm5

# qhasm:       xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm6=int6464#7
# asm 2: pxor  <xmm1=%xmm1,<xmm6=%xmm6
pxor  %xmm1,%xmm6

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:       xmm4 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm4=int6464#5
# asm 2: pxor  <xmm5=%xmm5,<xmm4=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#2
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm1
pxor  %xmm7,%xmm1

# qhasm:       xmm11 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm11=int6464#9
# asm 2: movdqa <xmm5=%xmm5,>xmm11=%xmm8
movdqa %xmm5,%xmm8

# qhasm:       xmm10 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm10=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm10=%xmm9
movdqa %xmm1,%xmm9

# qhasm:       xmm9 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm9=int6464#11
# asm 2: movdqa <xmm7=%xmm7,>xmm9=%xmm10
movdqa %xmm7,%xmm10

# qhasm:       xmm13 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm13=int6464#12
# asm 2: movdqa <xmm4=%xmm4,>xmm13=%xmm11
movdqa %xmm4,%xmm11

# qhasm:       xmm12 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm12=int6464#13
# asm 2: movdqa <xmm2=%xmm2,>xmm12=%xmm12
movdqa %xmm2,%xmm12

# qhasm:       xmm11 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm11=int6464#9
# asm 2: pxor  <xmm3=%xmm3,<xmm11=%xmm8
pxor  %xmm3,%xmm8

# qhasm:       xmm10 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm10=int6464#10
# asm 2: pxor  <xmm4=%xmm4,<xmm10=%xmm9
pxor  %xmm4,%xmm9

# qhasm:       xmm9 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm9=int6464#11
# asm 2: pxor  <xmm6=%xmm6,<xmm9=%xmm10
pxor  %xmm6,%xmm10

# qhasm:       xmm13 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm13=int6464#12
# asm 2: pxor  <xmm3=%xmm3,<xmm13=%xmm11
pxor  %xmm3,%xmm11

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:       xmm14 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm14=int6464#14
# asm 2: movdqa <xmm11=%xmm8,>xmm14=%xmm13
movdqa %xmm8,%xmm13

# qhasm:       xmm8 = xmm10
# asm 1: movdqa <xmm10=int6464#10,>xmm8=int6464#15
# asm 2: movdqa <xmm10=%xmm9,>xmm8=%xmm14
movdqa %xmm9,%xmm14

# qhasm:       xmm15 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm15=int6464#16
# asm 2: movdqa <xmm11=%xmm8,>xmm15=%xmm15
movdqa %xmm8,%xmm15

# qhasm:       xmm10 |= xmm9
# asm 1: por   <xmm9=int6464#11,<xmm10=int6464#10
# asm 2: por   <xmm9=%xmm10,<xmm10=%xmm9
por   %xmm10,%xmm9

# qhasm:       xmm11 |= xmm12
# asm 1: por   <xmm12=int6464#13,<xmm11=int6464#9
# asm 2: por   <xmm12=%xmm12,<xmm11=%xmm8
por   %xmm12,%xmm8

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm15=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm14 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm14=int6464#14
# asm 2: pand  <xmm12=%xmm12,<xmm14=%xmm13
pand  %xmm12,%xmm13

# qhasm:       xmm8 &= xmm9
# asm 1: pand  <xmm9=int6464#11,<xmm8=int6464#15
# asm 2: pand  <xmm9=%xmm10,<xmm8=%xmm14
pand  %xmm10,%xmm14

# qhasm:       xmm12 ^= xmm9
# asm 1: pxor  <xmm9=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm9=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:       xmm15 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm15=int6464#16
# asm 2: pand  <xmm12=%xmm12,<xmm15=%xmm15
pand  %xmm12,%xmm15

# qhasm:       xmm12 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm12=int6464#11
# asm 2: movdqa <xmm6=%xmm6,>xmm12=%xmm10
movdqa %xmm6,%xmm10

# qhasm:       xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#11
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm10
pxor  %xmm0,%xmm10

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#11,<xmm13=int6464#12
# asm 2: pand  <xmm12=%xmm10,<xmm13=%xmm11
pand  %xmm10,%xmm11

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm11=int6464#9
# asm 2: pxor  <xmm13=%xmm11,<xmm11=%xmm8
pxor  %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm13 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm13=int6464#11
# asm 2: movdqa <xmm5=%xmm5,>xmm13=%xmm10
movdqa %xmm5,%xmm10

# qhasm:       xmm13 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm13=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm13=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm12 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm12=int6464#12
# asm 2: movdqa <xmm7=%xmm7,>xmm12=%xmm11
movdqa %xmm7,%xmm11

# qhasm:       xmm9 = xmm13
# asm 1: movdqa <xmm13=int6464#11,>xmm9=int6464#13
# asm 2: movdqa <xmm13=%xmm10,>xmm9=%xmm12
movdqa %xmm10,%xmm12

# qhasm:       xmm12 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm12=int6464#12
# asm 2: pxor  <xmm2=%xmm2,<xmm12=%xmm11
pxor  %xmm2,%xmm11

# qhasm:       xmm9 |= xmm12
# asm 1: por   <xmm12=int6464#12,<xmm9=int6464#13
# asm 2: por   <xmm12=%xmm11,<xmm9=%xmm12
por   %xmm11,%xmm12

# qhasm:       xmm13 &= xmm12
# asm 1: pand  <xmm12=int6464#12,<xmm13=int6464#11
# asm 2: pand  <xmm12=%xmm11,<xmm13=%xmm10
pand  %xmm11,%xmm10

# qhasm:       xmm8 ^= xmm13
# asm 1: pxor  <xmm13=int6464#11,<xmm8=int6464#15
# asm 2: pxor  <xmm13=%xmm10,<xmm8=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#9
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm10=int6464#10
# asm 2: pxor  <xmm14=%xmm13,<xmm10=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm9 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm8 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm8=int6464#15
# asm 2: pxor  <xmm14=%xmm13,<xmm8=%xmm14
pxor  %xmm13,%xmm14

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm12 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm12=int6464#11
# asm 2: movdqa <xmm4=%xmm4,>xmm12=%xmm10
movdqa %xmm4,%xmm10

# qhasm:       xmm13 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm13=int6464#12
# asm 2: movdqa <xmm3=%xmm3,>xmm13=%xmm11
movdqa %xmm3,%xmm11

# qhasm:       xmm14 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm14=int6464#14
# asm 2: movdqa <xmm1=%xmm1,>xmm14=%xmm13
movdqa %xmm1,%xmm13

# qhasm:       xmm15 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm15=int6464#16
# asm 2: movdqa <xmm5=%xmm5,>xmm15=%xmm15
movdqa %xmm5,%xmm15

# qhasm:       xmm12 &= xmm6
# asm 1: pand  <xmm6=int6464#7,<xmm12=int6464#11
# asm 2: pand  <xmm6=%xmm6,<xmm12=%xmm10
pand  %xmm6,%xmm10

# qhasm:       xmm13 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm13=int6464#12
# asm 2: pand  <xmm0=%xmm0,<xmm13=%xmm11
pand  %xmm0,%xmm11

# qhasm:       xmm14 &= xmm7
# asm 1: pand  <xmm7=int6464#8,<xmm14=int6464#14
# asm 2: pand  <xmm7=%xmm7,<xmm14=%xmm13
pand  %xmm7,%xmm13

# qhasm:       xmm15 |= xmm2
# asm 1: por   <xmm2=int6464#3,<xmm15=int6464#16
# asm 2: por   <xmm2=%xmm2,<xmm15=%xmm15
por   %xmm2,%xmm15

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm11=int6464#9
# asm 2: pxor  <xmm12=%xmm10,<xmm11=%xmm8
pxor  %xmm10,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#12,<xmm10=int6464#10
# asm 2: pxor  <xmm13=%xmm11,<xmm10=%xmm9
pxor  %xmm11,%xmm9

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#14,<xmm9=int6464#13
# asm 2: pxor  <xmm14=%xmm13,<xmm9=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm8 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm8=int6464#15
# asm 2: pxor  <xmm15=%xmm15,<xmm8=%xmm14
pxor  %xmm15,%xmm14

# qhasm:       xmm12 = xmm11
# asm 1: movdqa <xmm11=int6464#9,>xmm12=int6464#11
# asm 2: movdqa <xmm11=%xmm8,>xmm12=%xmm10
movdqa %xmm8,%xmm10

# qhasm:       xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm12=int6464#11
# asm 2: pxor  <xmm10=%xmm9,<xmm12=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm11 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm11=int6464#9
# asm 2: pand  <xmm9=%xmm12,<xmm11=%xmm8
pand  %xmm12,%xmm8

# qhasm:       xmm14 = xmm8
# asm 1: movdqa <xmm8=int6464#15,>xmm14=int6464#12
# asm 2: movdqa <xmm8=%xmm14,>xmm14=%xmm11
movdqa %xmm14,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm11=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm15 = xmm12
# asm 1: movdqa <xmm12=int6464#11,>xmm15=int6464#14
# asm 2: movdqa <xmm12=%xmm10,>xmm15=%xmm13
movdqa %xmm10,%xmm13

# qhasm:       xmm15 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm15=int6464#14
# asm 2: pand  <xmm14=%xmm11,<xmm15=%xmm13
pand  %xmm11,%xmm13

# qhasm:       xmm15 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm15=int6464#14
# asm 2: pxor  <xmm10=%xmm9,<xmm15=%xmm13
pxor  %xmm9,%xmm13

# qhasm:       xmm13 = xmm9
# asm 1: movdqa <xmm9=int6464#13,>xmm13=int6464#16
# asm 2: movdqa <xmm9=%xmm12,>xmm13=%xmm15
movdqa %xmm12,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm11 ^= xmm10
# asm 1: pxor  <xmm10=int6464#10,<xmm11=int6464#9
# asm 2: pxor  <xmm10=%xmm9,<xmm11=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm13 &= xmm11
# asm 1: pand  <xmm11=int6464#9,<xmm13=int6464#16
# asm 2: pand  <xmm11=%xmm8,<xmm13=%xmm15
pand  %xmm8,%xmm15

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#15,<xmm13=int6464#16
# asm 2: pxor  <xmm8=%xmm14,<xmm13=%xmm15
pxor  %xmm14,%xmm15

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm9=int6464#13
# asm 2: pxor  <xmm13=%xmm15,<xmm9=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm10 = xmm14
# asm 1: movdqa <xmm14=int6464#12,>xmm10=int6464#9
# asm 2: movdqa <xmm14=%xmm11,>xmm10=%xmm8
movdqa %xmm11,%xmm8

# qhasm:       xmm10 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm10=int6464#9
# asm 2: pxor  <xmm13=%xmm15,<xmm10=%xmm8
pxor  %xmm15,%xmm8

# qhasm:       xmm10 &= xmm8
# asm 1: pand  <xmm8=int6464#15,<xmm10=int6464#9
# asm 2: pand  <xmm8=%xmm14,<xmm10=%xmm8
pand  %xmm14,%xmm8

# qhasm:       xmm9 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm9=int6464#13
# asm 2: pxor  <xmm10=%xmm8,<xmm9=%xmm12
pxor  %xmm8,%xmm12

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#9,<xmm14=int6464#12
# asm 2: pxor  <xmm10=%xmm8,<xmm14=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm14=int6464#12
# asm 2: pand  <xmm15=%xmm13,<xmm14=%xmm11
pand  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm12
# asm 1: pxor  <xmm12=int6464#11,<xmm14=int6464#12
# asm 2: pxor  <xmm12=%xmm10,<xmm14=%xmm11
pxor  %xmm10,%xmm11

# qhasm:         xmm12 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm12=int6464#9
# asm 2: movdqa <xmm2=%xmm2,>xmm12=%xmm8
movdqa %xmm2,%xmm8

# qhasm:         xmm8 = xmm7
# asm 1: movdqa <xmm7=int6464#8,>xmm8=int6464#10
# asm 2: movdqa <xmm7=%xmm7,>xmm8=%xmm9
movdqa %xmm7,%xmm9

# qhasm:           xmm10 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm10=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm10=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm10 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm10 &= xmm2
# asm 1: pand  <xmm2=int6464#3,<xmm10=int6464#11
# asm 2: pand  <xmm2=%xmm2,<xmm10=%xmm10
pand  %xmm2,%xmm10

# qhasm:           xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:           xmm2 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm2=int6464#3
# asm 2: pand  <xmm14=%xmm11,<xmm2=%xmm2
pand  %xmm11,%xmm2

# qhasm:           xmm7 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm7=int6464#8
# asm 2: pand  <xmm15=%xmm13,<xmm7=%xmm7
pand  %xmm13,%xmm7

# qhasm:           xmm2 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm2=int6464#3
# asm 2: pxor  <xmm7=%xmm7,<xmm2=%xmm2
pxor  %xmm7,%xmm2

# qhasm:           xmm7 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm7=int6464#8
# asm 2: pxor  <xmm10=%xmm10,<xmm7=%xmm7
pxor  %xmm10,%xmm7

# qhasm:         xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm8 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm8=int6464#10
# asm 2: pxor  <xmm6=%xmm6,<xmm8=%xmm9
pxor  %xmm6,%xmm9

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm0
# asm 1: pand  <xmm0=int6464#1,<xmm10=int6464#11
# asm 2: pand  <xmm0=%xmm0,<xmm10=%xmm10
pand  %xmm0,%xmm10

# qhasm:           xmm0 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm0=int6464#1
# asm 2: pxor  <xmm6=%xmm6,<xmm0=%xmm0
pxor  %xmm6,%xmm0

# qhasm:           xmm0 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm0=int6464#1
# asm 2: pand  <xmm9=%xmm12,<xmm0=%xmm0
pand  %xmm12,%xmm0

# qhasm:           xmm6 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm6=int6464#7
# asm 2: pand  <xmm13=%xmm15,<xmm6=%xmm6
pand  %xmm15,%xmm6

# qhasm:           xmm0 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm0=int6464#1
# asm 2: pxor  <xmm6=%xmm6,<xmm0=%xmm0
pxor  %xmm6,%xmm0

# qhasm:           xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:         xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm8,<xmm2=%xmm2
pxor  %xmm8,%xmm2

# qhasm:         xmm0 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm12=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm7 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm7=int6464#8
# asm 2: pxor  <xmm8=%xmm9,<xmm7=%xmm7
pxor  %xmm9,%xmm7

# qhasm:         xmm6 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm6=int6464#7
# asm 2: pxor  <xmm8=%xmm9,<xmm6=%xmm6
pxor  %xmm9,%xmm6

# qhasm:         xmm12 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm12=int6464#9
# asm 2: movdqa <xmm5=%xmm5,>xmm12=%xmm8
movdqa %xmm5,%xmm8

# qhasm:         xmm8 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm8=int6464#10
# asm 2: movdqa <xmm1=%xmm1,>xmm8=%xmm9
movdqa %xmm1,%xmm9

# qhasm:         xmm12 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm12=int6464#9
# asm 2: pxor  <xmm3=%xmm3,<xmm12=%xmm8
pxor  %xmm3,%xmm8

# qhasm:         xmm8 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm8=int6464#10
# asm 2: pxor  <xmm4=%xmm4,<xmm8=%xmm9
pxor  %xmm4,%xmm9

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm12
# asm 1: pand  <xmm12=int6464#9,<xmm11=int6464#11
# asm 2: pand  <xmm12=%xmm8,<xmm11=%xmm10
pand  %xmm8,%xmm10

# qhasm:           xmm12 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm12=int6464#9
# asm 2: pxor  <xmm8=%xmm9,<xmm12=%xmm8
pxor  %xmm9,%xmm8

# qhasm:           xmm12 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm12=int6464#9
# asm 2: pand  <xmm14=%xmm11,<xmm12=%xmm8
pand  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm8=int6464#10
# asm 2: pand  <xmm15=%xmm13,<xmm8=%xmm9
pand  %xmm13,%xmm9

# qhasm:           xmm8 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm8=int6464#10
# asm 2: pxor  <xmm12=%xmm8,<xmm8=%xmm9
pxor  %xmm8,%xmm9

# qhasm:           xmm12 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm12=int6464#9
# asm 2: pxor  <xmm11=%xmm10,<xmm12=%xmm8
pxor  %xmm10,%xmm8

# qhasm:           xmm10 = xmm13
# asm 1: movdqa <xmm13=int6464#16,>xmm10=int6464#11
# asm 2: movdqa <xmm13=%xmm15,>xmm10=%xmm10
movdqa %xmm15,%xmm10

# qhasm:           xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm12,<xmm10=%xmm10
pxor  %xmm12,%xmm10

# qhasm:           xmm10 &= xmm3
# asm 1: pand  <xmm3=int6464#4,<xmm10=int6464#11
# asm 2: pand  <xmm3=%xmm3,<xmm10=%xmm10
pand  %xmm3,%xmm10

# qhasm:           xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm3=int6464#4
# asm 2: pxor  <xmm4=%xmm4,<xmm3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm3 &= xmm9
# asm 1: pand  <xmm9=int6464#13,<xmm3=int6464#4
# asm 2: pand  <xmm9=%xmm12,<xmm3=%xmm3
pand  %xmm12,%xmm3

# qhasm:           xmm4 &= xmm13
# asm 1: pand  <xmm13=int6464#16,<xmm4=int6464#5
# asm 2: pand  <xmm13=%xmm15,<xmm4=%xmm4
pand  %xmm15,%xmm4

# qhasm:           xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm3=int6464#4
# asm 2: pxor  <xmm4=%xmm4,<xmm3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:         xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#16,<xmm15=int6464#14
# asm 2: pxor  <xmm13=%xmm15,<xmm15=%xmm13
pxor  %xmm15,%xmm13

# qhasm:         xmm14 ^= xmm9
# asm 1: pxor  <xmm9=int6464#13,<xmm14=int6464#12
# asm 2: pxor  <xmm9=%xmm12,<xmm14=%xmm11
pxor  %xmm12,%xmm11

# qhasm:           xmm11 = xmm15
# asm 1: movdqa <xmm15=int6464#14,>xmm11=int6464#11
# asm 2: movdqa <xmm15=%xmm13,>xmm11=%xmm10
movdqa %xmm13,%xmm10

# qhasm:           xmm11 ^= xmm14
# asm 1: pxor  <xmm14=int6464#12,<xmm11=int6464#11
# asm 2: pxor  <xmm14=%xmm11,<xmm11=%xmm10
pxor  %xmm11,%xmm10

# qhasm:           xmm11 &= xmm5
# asm 1: pand  <xmm5=int6464#6,<xmm11=int6464#11
# asm 2: pand  <xmm5=%xmm5,<xmm11=%xmm10
pand  %xmm5,%xmm10

# qhasm:           xmm5 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm5=int6464#6
# asm 2: pxor  <xmm1=%xmm1,<xmm5=%xmm5
pxor  %xmm1,%xmm5

# qhasm:           xmm5 &= xmm14
# asm 1: pand  <xmm14=int6464#12,<xmm5=int6464#6
# asm 2: pand  <xmm14=%xmm11,<xmm5=%xmm5
pand  %xmm11,%xmm5

# qhasm:           xmm1 &= xmm15
# asm 1: pand  <xmm15=int6464#14,<xmm1=int6464#2
# asm 2: pand  <xmm15=%xmm13,<xmm1=%xmm1
pand  %xmm13,%xmm1

# qhasm:           xmm5 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm5=int6464#6
# asm 2: pxor  <xmm1=%xmm1,<xmm5=%xmm5
pxor  %xmm1,%xmm5

# qhasm:           xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#11,<xmm1=int6464#2
# asm 2: pxor  <xmm11=%xmm10,<xmm1=%xmm1
pxor  %xmm10,%xmm1

# qhasm:         xmm5 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm5=int6464#6
# asm 2: pxor  <xmm12=%xmm8,<xmm5=%xmm5
pxor  %xmm8,%xmm5

# qhasm:         xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#9,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm8,<xmm3=%xmm3
pxor  %xmm8,%xmm3

# qhasm:         xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:         xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#10,<xmm4=int6464#5
# asm 2: pxor  <xmm8=%xmm9,<xmm4=%xmm4
pxor  %xmm9,%xmm4

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm5=int6464#6
# asm 2: pxor  <xmm0=%xmm0,<xmm5=%xmm5
pxor  %xmm0,%xmm5

# qhasm:       xmm1 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm1=int6464#2
# asm 2: pxor  <xmm2=%xmm2,<xmm1=%xmm1
pxor  %xmm2,%xmm1

# qhasm:       xmm3 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm3=int6464#4
# asm 2: pxor  <xmm5=%xmm5,<xmm3=%xmm3
pxor  %xmm5,%xmm3

# qhasm:       xmm2 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm2=int6464#3
# asm 2: pxor  <xmm0=%xmm0,<xmm2=%xmm2
pxor  %xmm0,%xmm2

# qhasm:       xmm0 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm0=int6464#1
# asm 2: pxor  <xmm1=%xmm1,<xmm0=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#2
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm1
pxor  %xmm7,%xmm1

# qhasm:       xmm7 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm7=int6464#8
# asm 2: pxor  <xmm4=%xmm4,<xmm7=%xmm7
pxor  %xmm4,%xmm7

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#4
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm3
pxor  %xmm7,%xmm3

# qhasm:       xmm4 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm4=int6464#5
# asm 2: pxor  <xmm6=%xmm6,<xmm4=%xmm4
pxor  %xmm6,%xmm4

# qhasm:       xmm6 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm6=int6464#7
# asm 2: pxor  <xmm7=%xmm7,<xmm6=%xmm6
pxor  %xmm7,%xmm6

# qhasm:       xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm6,<xmm2=%xmm2
pxor  %xmm6,%xmm2

# qhasm:   xmm1 ^= RCON
# asm 1: pxor  RCON,<xmm1=int6464#2
# asm 2: pxor  RCON,<xmm1=%xmm1
pxor  RCON,%xmm1

# qhasm:   xmm3 ^= RCON
# asm 1: pxor  RCON,<xmm3=int6464#4
# asm 2: pxor  RCON,<xmm3=%xmm3
pxor  RCON,%xmm3

# qhasm:   xmm6 ^= RCON
# asm 1: pxor  RCON,<xmm6=int6464#7
# asm 2: pxor  RCON,<xmm6=%xmm6
pxor  RCON,%xmm6

# qhasm:   xmm5 ^= RCON
# asm 1: pxor  RCON,<xmm5=int6464#6
# asm 2: pxor  RCON,<xmm5=%xmm5
pxor  RCON,%xmm5

# qhasm:   shuffle bytes of xmm0 by EXPB0
# asm 1: pshufb EXPB0,<xmm0=int6464#1
# asm 2: pshufb EXPB0,<xmm0=%xmm0
pshufb EXPB0,%xmm0

# qhasm:   shuffle bytes of xmm1 by EXPB0
# asm 1: pshufb EXPB0,<xmm1=int6464#2
# asm 2: pshufb EXPB0,<xmm1=%xmm1
pshufb EXPB0,%xmm1

# qhasm:   shuffle bytes of xmm3 by EXPB0
# asm 1: pshufb EXPB0,<xmm3=int6464#4
# asm 2: pshufb EXPB0,<xmm3=%xmm3
pshufb EXPB0,%xmm3

# qhasm:   shuffle bytes of xmm2 by EXPB0
# asm 1: pshufb EXPB0,<xmm2=int6464#3
# asm 2: pshufb EXPB0,<xmm2=%xmm2
pshufb EXPB0,%xmm2

# qhasm:   shuffle bytes of xmm6 by EXPB0
# asm 1: pshufb EXPB0,<xmm6=int6464#7
# asm 2: pshufb EXPB0,<xmm6=%xmm6
pshufb EXPB0,%xmm6

# qhasm:   shuffle bytes of xmm5 by EXPB0
# asm 1: pshufb EXPB0,<xmm5=int6464#6
# asm 2: pshufb EXPB0,<xmm5=%xmm5
pshufb EXPB0,%xmm5

# qhasm:   shuffle bytes of xmm4 by EXPB0
# asm 1: pshufb EXPB0,<xmm4=int6464#5
# asm 2: pshufb EXPB0,<xmm4=%xmm4
pshufb EXPB0,%xmm4

# qhasm:   shuffle bytes of xmm7 by EXPB0
# asm 1: pshufb EXPB0,<xmm7=int6464#8
# asm 2: pshufb EXPB0,<xmm7=%xmm7
pshufb EXPB0,%xmm7

# qhasm:   xmm8 = *(int128 *)(c + 1152)
# asm 1: movdqa 1152(<c=int64#1),>xmm8=int6464#9
# asm 2: movdqa 1152(<c=%rdi),>xmm8=%xmm8
movdqa 1152(%rdi),%xmm8

# qhasm:   xmm9 = *(int128 *)(c + 1168)
# asm 1: movdqa 1168(<c=int64#1),>xmm9=int6464#10
# asm 2: movdqa 1168(<c=%rdi),>xmm9=%xmm9
movdqa 1168(%rdi),%xmm9

# qhasm:   xmm10 = *(int128 *)(c + 1184)
# asm 1: movdqa 1184(<c=int64#1),>xmm10=int6464#11
# asm 2: movdqa 1184(<c=%rdi),>xmm10=%xmm10
movdqa 1184(%rdi),%xmm10

# qhasm:   xmm11 = *(int128 *)(c + 1200)
# asm 1: movdqa 1200(<c=int64#1),>xmm11=int6464#12
# asm 2: movdqa 1200(<c=%rdi),>xmm11=%xmm11
movdqa 1200(%rdi),%xmm11

# qhasm:   xmm12 = *(int128 *)(c + 1216)
# asm 1: movdqa 1216(<c=int64#1),>xmm12=int6464#13
# asm 2: movdqa 1216(<c=%rdi),>xmm12=%xmm12
movdqa 1216(%rdi),%xmm12

# qhasm:   xmm13 = *(int128 *)(c + 1232)
# asm 1: movdqa 1232(<c=int64#1),>xmm13=int6464#14
# asm 2: movdqa 1232(<c=%rdi),>xmm13=%xmm13
movdqa 1232(%rdi),%xmm13

# qhasm:   xmm14 = *(int128 *)(c + 1248)
# asm 1: movdqa 1248(<c=int64#1),>xmm14=int6464#15
# asm 2: movdqa 1248(<c=%rdi),>xmm14=%xmm14
movdqa 1248(%rdi),%xmm14

# qhasm:   xmm15 = *(int128 *)(c + 1264)
# asm 1: movdqa 1264(<c=int64#1),>xmm15=int6464#16
# asm 2: movdqa 1264(<c=%rdi),>xmm15=%xmm15
movdqa 1264(%rdi),%xmm15

# qhasm:   xmm8 ^= ONE
# asm 1: pxor  ONE,<xmm8=int6464#9
# asm 2: pxor  ONE,<xmm8=%xmm8
pxor  ONE,%xmm8

# qhasm:   xmm9 ^= ONE
# asm 1: pxor  ONE,<xmm9=int6464#10
# asm 2: pxor  ONE,<xmm9=%xmm9
pxor  ONE,%xmm9

# qhasm:   xmm13 ^= ONE
# asm 1: pxor  ONE,<xmm13=int6464#14
# asm 2: pxor  ONE,<xmm13=%xmm13
pxor  ONE,%xmm13

# qhasm:   xmm14 ^= ONE
# asm 1: pxor  ONE,<xmm14=int6464#15
# asm 2: pxor  ONE,<xmm14=%xmm14
pxor  ONE,%xmm14

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:   xmm2 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm2=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm2=%xmm2
pxor  %xmm11,%xmm2

# qhasm:   xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm12,<xmm6=%xmm6
pxor  %xmm12,%xmm6

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:   xmm2 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm2=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm2=%xmm2
pxor  %xmm11,%xmm2

# qhasm:   xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm12,<xmm6=%xmm6
pxor  %xmm12,%xmm6

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:   xmm2 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm2=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm2=%xmm2
pxor  %xmm11,%xmm2

# qhasm:   xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm12,<xmm6=%xmm6
pxor  %xmm12,%xmm6

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   uint32323232 xmm8 >>= 8
# asm 1: psrld $8,<xmm8=int6464#9
# asm 2: psrld $8,<xmm8=%xmm8
psrld $8,%xmm8

# qhasm:   uint32323232 xmm9 >>= 8
# asm 1: psrld $8,<xmm9=int6464#10
# asm 2: psrld $8,<xmm9=%xmm9
psrld $8,%xmm9

# qhasm:   uint32323232 xmm10 >>= 8
# asm 1: psrld $8,<xmm10=int6464#11
# asm 2: psrld $8,<xmm10=%xmm10
psrld $8,%xmm10

# qhasm:   uint32323232 xmm11 >>= 8
# asm 1: psrld $8,<xmm11=int6464#12
# asm 2: psrld $8,<xmm11=%xmm11
psrld $8,%xmm11

# qhasm:   uint32323232 xmm12 >>= 8
# asm 1: psrld $8,<xmm12=int6464#13
# asm 2: psrld $8,<xmm12=%xmm12
psrld $8,%xmm12

# qhasm:   uint32323232 xmm13 >>= 8
# asm 1: psrld $8,<xmm13=int6464#14
# asm 2: psrld $8,<xmm13=%xmm13
psrld $8,%xmm13

# qhasm:   uint32323232 xmm14 >>= 8
# asm 1: psrld $8,<xmm14=int6464#15
# asm 2: psrld $8,<xmm14=%xmm14
psrld $8,%xmm14

# qhasm:   uint32323232 xmm15 >>= 8
# asm 1: psrld $8,<xmm15=int6464#16
# asm 2: psrld $8,<xmm15=%xmm15
psrld $8,%xmm15

# qhasm:   xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:   xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:   xmm3 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm3=int6464#4
# asm 2: pxor  <xmm10=%xmm10,<xmm3=%xmm3
pxor  %xmm10,%xmm3

# qhasm:   xmm2 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm2=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm2=%xmm2
pxor  %xmm11,%xmm2

# qhasm:   xmm6 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm6=int6464#7
# asm 2: pxor  <xmm12=%xmm12,<xmm6=%xmm6
pxor  %xmm12,%xmm6

# qhasm:   xmm5 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm5=int6464#6
# asm 2: pxor  <xmm13=%xmm13,<xmm5=%xmm5
pxor  %xmm13,%xmm5

# qhasm:   xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:   xmm7 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm7=int6464#8
# asm 2: pxor  <xmm15=%xmm15,<xmm7=%xmm7
pxor  %xmm15,%xmm7

# qhasm:   shuffle bytes of xmm0 by M0
# asm 1: pshufb M0,<xmm0=int6464#1
# asm 2: pshufb M0,<xmm0=%xmm0
pshufb M0,%xmm0

# qhasm:   shuffle bytes of xmm1 by M0
# asm 1: pshufb M0,<xmm1=int6464#2
# asm 2: pshufb M0,<xmm1=%xmm1
pshufb M0,%xmm1

# qhasm:   shuffle bytes of xmm4 by M0
# asm 1: pshufb M0,<xmm4=int6464#5
# asm 2: pshufb M0,<xmm4=%xmm4
pshufb M0,%xmm4

# qhasm:   shuffle bytes of xmm6 by M0
# asm 1: pshufb M0,<xmm6=int6464#7
# asm 2: pshufb M0,<xmm6=%xmm6
pshufb M0,%xmm6

# qhasm:   shuffle bytes of xmm3 by M0
# asm 1: pshufb M0,<xmm3=int6464#4
# asm 2: pshufb M0,<xmm3=%xmm3
pshufb M0,%xmm3

# qhasm:   shuffle bytes of xmm7 by M0
# asm 1: pshufb M0,<xmm7=int6464#8
# asm 2: pshufb M0,<xmm7=%xmm7
pshufb M0,%xmm7

# qhasm:   shuffle bytes of xmm2 by M0
# asm 1: pshufb M0,<xmm2=int6464#3
# asm 2: pshufb M0,<xmm2=%xmm2
pshufb M0,%xmm2

# qhasm:   shuffle bytes of xmm5 by M0
# asm 1: pshufb M0,<xmm5=int6464#6
# asm 2: pshufb M0,<xmm5=%xmm5
pshufb M0,%xmm5

# qhasm:   *(int128 *)(c + 1280) = xmm0
# asm 1: movdqa <xmm0=int6464#1,1280(<c=int64#1)
# asm 2: movdqa <xmm0=%xmm0,1280(<c=%rdi)
movdqa %xmm0,1280(%rdi)

# qhasm:   *(int128 *)(c + 1296) = xmm1
# asm 1: movdqa <xmm1=int6464#2,1296(<c=int64#1)
# asm 2: movdqa <xmm1=%xmm1,1296(<c=%rdi)
movdqa %xmm1,1296(%rdi)

# qhasm:   *(int128 *)(c + 1312) = xmm3
# asm 1: movdqa <xmm3=int6464#4,1312(<c=int64#1)
# asm 2: movdqa <xmm3=%xmm3,1312(<c=%rdi)
movdqa %xmm3,1312(%rdi)

# qhasm:   *(int128 *)(c + 1328) = xmm2
# asm 1: movdqa <xmm2=int6464#3,1328(<c=int64#1)
# asm 2: movdqa <xmm2=%xmm2,1328(<c=%rdi)
movdqa %xmm2,1328(%rdi)

# qhasm:   *(int128 *)(c + 1344) = xmm6
# asm 1: movdqa <xmm6=int6464#7,1344(<c=int64#1)
# asm 2: movdqa <xmm6=%xmm6,1344(<c=%rdi)
movdqa %xmm6,1344(%rdi)

# qhasm:   *(int128 *)(c + 1360) = xmm5
# asm 1: movdqa <xmm5=int6464#6,1360(<c=int64#1)
# asm 2: movdqa <xmm5=%xmm5,1360(<c=%rdi)
movdqa %xmm5,1360(%rdi)

# qhasm:   *(int128 *)(c + 1376) = xmm4
# asm 1: movdqa <xmm4=int6464#5,1376(<c=int64#1)
# asm 2: movdqa <xmm4=%xmm4,1376(<c=%rdi)
movdqa %xmm4,1376(%rdi)

# qhasm:   *(int128 *)(c + 1392) = xmm7
# asm 1: movdqa <xmm7=int6464#8,1392(<c=int64#1)
# asm 2: movdqa <xmm7=%xmm7,1392(<c=%rdi)
movdqa %xmm7,1392(%rdi)

# qhasm: leave
add %r11,%rsp
mov %rdi,%rax
mov %rsi,%rdx
xor %rax,%rax
ret
