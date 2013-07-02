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

# qhasm: int64 outp

# qhasm: int64 len

# qhasm: int64 np

# qhasm: int64 c

# qhasm: input outp

# qhasm: input len

# qhasm: input np

# qhasm: input c

# qhasm: int64 lensav

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

# qhasm: stack1024 bl

# qhasm: stack128 nonce_stack

# qhasm: int64 blp

# qhasm: int64 b

# qhasm: int64 tmp

# qhasm: enter crypto_stream_aes128ctr_core2_afternm
.text
.p2align 5
.globl _crypto_stream_aes128ctr_core2_afternm
.globl crypto_stream_aes128ctr_core2_afternm
_crypto_stream_aes128ctr_core2_afternm:
crypto_stream_aes128ctr_core2_afternm:
mov %rsp,%r11
and $31,%r11
add $160,%r11
sub %r11,%rsp

# qhasm: xmm0 = *(int128 *) (np + 0)
# asm 1: movdqa 0(<np=int64#3),>xmm0=int6464#1
# asm 2: movdqa 0(<np=%rdx),>xmm0=%xmm0
movdqa 0(%rdx),%xmm0

# qhasm: nonce_stack = xmm0
# asm 1: movdqa <xmm0=int6464#1,>nonce_stack=stack128#1
# asm 2: movdqa <xmm0=%xmm0,>nonce_stack=0(%rsp)
movdqa %xmm0,0(%rsp)

# qhasm: np = &nonce_stack
# asm 1: leaq <nonce_stack=stack128#1,>np=int64#3
# asm 2: leaq <nonce_stack=0(%rsp),>np=%rdx
leaq 0(%rsp),%rdx

# qhasm: enc_block:
._enc_block:

# qhasm: xmm0 = *(int128 *) (np + 0)
# asm 1: movdqa 0(<np=int64#3),>xmm0=int6464#1
# asm 2: movdqa 0(<np=%rdx),>xmm0=%xmm0
movdqa 0(%rdx),%xmm0

# qhasm: xmm1 = xmm0
# asm 1: movdqa <xmm0=int6464#1,>xmm1=int6464#2
# asm 2: movdqa <xmm0=%xmm0,>xmm1=%xmm1
movdqa %xmm0,%xmm1

# qhasm: shuffle bytes of xmm1 by SWAP32
# asm 1: pshufb SWAP32,<xmm1=int6464#2
# asm 2: pshufb SWAP32,<xmm1=%xmm1
pshufb SWAP32,%xmm1

# qhasm: xmm2 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm2=int6464#3
# asm 2: movdqa <xmm1=%xmm1,>xmm2=%xmm2
movdqa %xmm1,%xmm2

# qhasm: xmm3 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm3=int6464#4
# asm 2: movdqa <xmm1=%xmm1,>xmm3=%xmm3
movdqa %xmm1,%xmm3

# qhasm: xmm4 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm4=int6464#5
# asm 2: movdqa <xmm1=%xmm1,>xmm4=%xmm4
movdqa %xmm1,%xmm4

# qhasm: xmm5 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm5=int6464#6
# asm 2: movdqa <xmm1=%xmm1,>xmm5=%xmm5
movdqa %xmm1,%xmm5

# qhasm: xmm6 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm6=int6464#7
# asm 2: movdqa <xmm1=%xmm1,>xmm6=%xmm6
movdqa %xmm1,%xmm6

# qhasm: xmm7 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm7=int6464#8
# asm 2: movdqa <xmm1=%xmm1,>xmm7=%xmm7
movdqa %xmm1,%xmm7

# qhasm: int32323232 xmm1 += RCTRINC1
# asm 1: paddd  RCTRINC1,<xmm1=int6464#2
# asm 2: paddd  RCTRINC1,<xmm1=%xmm1
paddd  RCTRINC1,%xmm1

# qhasm: int32323232 xmm2 += RCTRINC2
# asm 1: paddd  RCTRINC2,<xmm2=int6464#3
# asm 2: paddd  RCTRINC2,<xmm2=%xmm2
paddd  RCTRINC2,%xmm2

# qhasm: int32323232 xmm3 += RCTRINC3
# asm 1: paddd  RCTRINC3,<xmm3=int6464#4
# asm 2: paddd  RCTRINC3,<xmm3=%xmm3
paddd  RCTRINC3,%xmm3

# qhasm: int32323232 xmm4 += RCTRINC4
# asm 1: paddd  RCTRINC4,<xmm4=int6464#5
# asm 2: paddd  RCTRINC4,<xmm4=%xmm4
paddd  RCTRINC4,%xmm4

# qhasm: int32323232 xmm5 += RCTRINC5
# asm 1: paddd  RCTRINC5,<xmm5=int6464#6
# asm 2: paddd  RCTRINC5,<xmm5=%xmm5
paddd  RCTRINC5,%xmm5

# qhasm: int32323232 xmm6 += RCTRINC6
# asm 1: paddd  RCTRINC6,<xmm6=int6464#7
# asm 2: paddd  RCTRINC6,<xmm6=%xmm6
paddd  RCTRINC6,%xmm6

# qhasm: int32323232 xmm7 += RCTRINC7
# asm 1: paddd  RCTRINC7,<xmm7=int6464#8
# asm 2: paddd  RCTRINC7,<xmm7=%xmm7
paddd  RCTRINC7,%xmm7

# qhasm: shuffle bytes of xmm0 by M0
# asm 1: pshufb M0,<xmm0=int6464#1
# asm 2: pshufb M0,<xmm0=%xmm0
pshufb M0,%xmm0

# qhasm: shuffle bytes of xmm1 by M0SWAP
# asm 1: pshufb M0SWAP,<xmm1=int6464#2
# asm 2: pshufb M0SWAP,<xmm1=%xmm1
pshufb M0SWAP,%xmm1

# qhasm: shuffle bytes of xmm2 by M0SWAP
# asm 1: pshufb M0SWAP,<xmm2=int6464#3
# asm 2: pshufb M0SWAP,<xmm2=%xmm2
pshufb M0SWAP,%xmm2

# qhasm: shuffle bytes of xmm3 by M0SWAP
# asm 1: pshufb M0SWAP,<xmm3=int6464#4
# asm 2: pshufb M0SWAP,<xmm3=%xmm3
pshufb M0SWAP,%xmm3

# qhasm: shuffle bytes of xmm4 by M0SWAP
# asm 1: pshufb M0SWAP,<xmm4=int6464#5
# asm 2: pshufb M0SWAP,<xmm4=%xmm4
pshufb M0SWAP,%xmm4

# qhasm: shuffle bytes of xmm5 by M0SWAP
# asm 1: pshufb M0SWAP,<xmm5=int6464#6
# asm 2: pshufb M0SWAP,<xmm5=%xmm5
pshufb M0SWAP,%xmm5

# qhasm: shuffle bytes of xmm6 by M0SWAP
# asm 1: pshufb M0SWAP,<xmm6=int6464#7
# asm 2: pshufb M0SWAP,<xmm6=%xmm6
pshufb M0SWAP,%xmm6

# qhasm: shuffle bytes of xmm7 by M0SWAP
# asm 1: pshufb M0SWAP,<xmm7=int6464#8
# asm 2: pshufb M0SWAP,<xmm7=%xmm7
pshufb M0SWAP,%xmm7

# qhasm:     xmm8 = xmm6
# asm 1: movdqa <xmm6=int6464#7,>xmm8=int6464#9
# asm 2: movdqa <xmm6=%xmm6,>xmm8=%xmm8
movdqa %xmm6,%xmm8

# qhasm:     uint6464 xmm8 >>= 1
# asm 1: psrlq $1,<xmm8=int6464#9
# asm 2: psrlq $1,<xmm8=%xmm8
psrlq $1,%xmm8

# qhasm:     xmm8 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm8=int6464#9
# asm 2: pxor  <xmm7=%xmm7,<xmm8=%xmm8
pxor  %xmm7,%xmm8

# qhasm:     xmm8 &= BS0
# asm 1: pand  BS0,<xmm8=int6464#9
# asm 2: pand  BS0,<xmm8=%xmm8
pand  BS0,%xmm8

# qhasm:     xmm7 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm7=int6464#8
# asm 2: pxor  <xmm8=%xmm8,<xmm7=%xmm7
pxor  %xmm8,%xmm7

# qhasm:     uint6464 xmm8 <<= 1
# asm 1: psllq $1,<xmm8=int6464#9
# asm 2: psllq $1,<xmm8=%xmm8
psllq $1,%xmm8

# qhasm:     xmm6 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm6=int6464#7
# asm 2: pxor  <xmm8=%xmm8,<xmm6=%xmm6
pxor  %xmm8,%xmm6

# qhasm:     xmm8 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm8=int6464#9
# asm 2: movdqa <xmm4=%xmm4,>xmm8=%xmm8
movdqa %xmm4,%xmm8

# qhasm:     uint6464 xmm8 >>= 1
# asm 1: psrlq $1,<xmm8=int6464#9
# asm 2: psrlq $1,<xmm8=%xmm8
psrlq $1,%xmm8

# qhasm:     xmm8 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm8=int6464#9
# asm 2: pxor  <xmm5=%xmm5,<xmm8=%xmm8
pxor  %xmm5,%xmm8

# qhasm:     xmm8 &= BS0
# asm 1: pand  BS0,<xmm8=int6464#9
# asm 2: pand  BS0,<xmm8=%xmm8
pand  BS0,%xmm8

# qhasm:     xmm5 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm5=int6464#6
# asm 2: pxor  <xmm8=%xmm8,<xmm5=%xmm5
pxor  %xmm8,%xmm5

# qhasm:     uint6464 xmm8 <<= 1
# asm 1: psllq $1,<xmm8=int6464#9
# asm 2: psllq $1,<xmm8=%xmm8
psllq $1,%xmm8

# qhasm:     xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:     xmm8 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm8=int6464#9
# asm 2: movdqa <xmm2=%xmm2,>xmm8=%xmm8
movdqa %xmm2,%xmm8

# qhasm:     uint6464 xmm8 >>= 1
# asm 1: psrlq $1,<xmm8=int6464#9
# asm 2: psrlq $1,<xmm8=%xmm8
psrlq $1,%xmm8

# qhasm:     xmm8 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm8=int6464#9
# asm 2: pxor  <xmm3=%xmm3,<xmm8=%xmm8
pxor  %xmm3,%xmm8

# qhasm:     xmm8 &= BS0
# asm 1: pand  BS0,<xmm8=int6464#9
# asm 2: pand  BS0,<xmm8=%xmm8
pand  BS0,%xmm8

# qhasm:     xmm3 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm3=int6464#4
# asm 2: pxor  <xmm8=%xmm8,<xmm3=%xmm3
pxor  %xmm8,%xmm3

# qhasm:     uint6464 xmm8 <<= 1
# asm 1: psllq $1,<xmm8=int6464#9
# asm 2: psllq $1,<xmm8=%xmm8
psllq $1,%xmm8

# qhasm:     xmm2 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm2=int6464#3
# asm 2: pxor  <xmm8=%xmm8,<xmm2=%xmm2
pxor  %xmm8,%xmm2

# qhasm:     xmm8 = xmm0
# asm 1: movdqa <xmm0=int6464#1,>xmm8=int6464#9
# asm 2: movdqa <xmm0=%xmm0,>xmm8=%xmm8
movdqa %xmm0,%xmm8

# qhasm:     uint6464 xmm8 >>= 1
# asm 1: psrlq $1,<xmm8=int6464#9
# asm 2: psrlq $1,<xmm8=%xmm8
psrlq $1,%xmm8

# qhasm:     xmm8 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm8=int6464#9
# asm 2: pxor  <xmm1=%xmm1,<xmm8=%xmm8
pxor  %xmm1,%xmm8

# qhasm:     xmm8 &= BS0
# asm 1: pand  BS0,<xmm8=int6464#9
# asm 2: pand  BS0,<xmm8=%xmm8
pand  BS0,%xmm8

# qhasm:     xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm8,<xmm1=%xmm1
pxor  %xmm8,%xmm1

# qhasm:     uint6464 xmm8 <<= 1
# asm 1: psllq $1,<xmm8=int6464#9
# asm 2: psllq $1,<xmm8=%xmm8
psllq $1,%xmm8

# qhasm:     xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:     xmm8 = xmm5
# asm 1: movdqa <xmm5=int6464#6,>xmm8=int6464#9
# asm 2: movdqa <xmm5=%xmm5,>xmm8=%xmm8
movdqa %xmm5,%xmm8

# qhasm:     uint6464 xmm8 >>= 2
# asm 1: psrlq $2,<xmm8=int6464#9
# asm 2: psrlq $2,<xmm8=%xmm8
psrlq $2,%xmm8

# qhasm:     xmm8 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm8=int6464#9
# asm 2: pxor  <xmm7=%xmm7,<xmm8=%xmm8
pxor  %xmm7,%xmm8

# qhasm:     xmm8 &= BS1
# asm 1: pand  BS1,<xmm8=int6464#9
# asm 2: pand  BS1,<xmm8=%xmm8
pand  BS1,%xmm8

# qhasm:     xmm7 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm7=int6464#8
# asm 2: pxor  <xmm8=%xmm8,<xmm7=%xmm7
pxor  %xmm8,%xmm7

# qhasm:     uint6464 xmm8 <<= 2
# asm 1: psllq $2,<xmm8=int6464#9
# asm 2: psllq $2,<xmm8=%xmm8
psllq $2,%xmm8

# qhasm:     xmm5 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm5=int6464#6
# asm 2: pxor  <xmm8=%xmm8,<xmm5=%xmm5
pxor  %xmm8,%xmm5

# qhasm:     xmm8 = xmm4
# asm 1: movdqa <xmm4=int6464#5,>xmm8=int6464#9
# asm 2: movdqa <xmm4=%xmm4,>xmm8=%xmm8
movdqa %xmm4,%xmm8

# qhasm:     uint6464 xmm8 >>= 2
# asm 1: psrlq $2,<xmm8=int6464#9
# asm 2: psrlq $2,<xmm8=%xmm8
psrlq $2,%xmm8

# qhasm:     xmm8 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm8=int6464#9
# asm 2: pxor  <xmm6=%xmm6,<xmm8=%xmm8
pxor  %xmm6,%xmm8

# qhasm:     xmm8 &= BS1
# asm 1: pand  BS1,<xmm8=int6464#9
# asm 2: pand  BS1,<xmm8=%xmm8
pand  BS1,%xmm8

# qhasm:     xmm6 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm6=int6464#7
# asm 2: pxor  <xmm8=%xmm8,<xmm6=%xmm6
pxor  %xmm8,%xmm6

# qhasm:     uint6464 xmm8 <<= 2
# asm 1: psllq $2,<xmm8=int6464#9
# asm 2: psllq $2,<xmm8=%xmm8
psllq $2,%xmm8

# qhasm:     xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:     xmm8 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm8=int6464#9
# asm 2: movdqa <xmm1=%xmm1,>xmm8=%xmm8
movdqa %xmm1,%xmm8

# qhasm:     uint6464 xmm8 >>= 2
# asm 1: psrlq $2,<xmm8=int6464#9
# asm 2: psrlq $2,<xmm8=%xmm8
psrlq $2,%xmm8

# qhasm:     xmm8 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm8=int6464#9
# asm 2: pxor  <xmm3=%xmm3,<xmm8=%xmm8
pxor  %xmm3,%xmm8

# qhasm:     xmm8 &= BS1
# asm 1: pand  BS1,<xmm8=int6464#9
# asm 2: pand  BS1,<xmm8=%xmm8
pand  BS1,%xmm8

# qhasm:     xmm3 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm3=int6464#4
# asm 2: pxor  <xmm8=%xmm8,<xmm3=%xmm3
pxor  %xmm8,%xmm3

# qhasm:     uint6464 xmm8 <<= 2
# asm 1: psllq $2,<xmm8=int6464#9
# asm 2: psllq $2,<xmm8=%xmm8
psllq $2,%xmm8

# qhasm:     xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm8,<xmm1=%xmm1
pxor  %xmm8,%xmm1

# qhasm:     xmm8 = xmm0
# asm 1: movdqa <xmm0=int6464#1,>xmm8=int6464#9
# asm 2: movdqa <xmm0=%xmm0,>xmm8=%xmm8
movdqa %xmm0,%xmm8

# qhasm:     uint6464 xmm8 >>= 2
# asm 1: psrlq $2,<xmm8=int6464#9
# asm 2: psrlq $2,<xmm8=%xmm8
psrlq $2,%xmm8

# qhasm:     xmm8 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm8=int6464#9
# asm 2: pxor  <xmm2=%xmm2,<xmm8=%xmm8
pxor  %xmm2,%xmm8

# qhasm:     xmm8 &= BS1
# asm 1: pand  BS1,<xmm8=int6464#9
# asm 2: pand  BS1,<xmm8=%xmm8
pand  BS1,%xmm8

# qhasm:     xmm2 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm2=int6464#3
# asm 2: pxor  <xmm8=%xmm8,<xmm2=%xmm2
pxor  %xmm8,%xmm2

# qhasm:     uint6464 xmm8 <<= 2
# asm 1: psllq $2,<xmm8=int6464#9
# asm 2: psllq $2,<xmm8=%xmm8
psllq $2,%xmm8

# qhasm:     xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:     xmm8 = xmm3
# asm 1: movdqa <xmm3=int6464#4,>xmm8=int6464#9
# asm 2: movdqa <xmm3=%xmm3,>xmm8=%xmm8
movdqa %xmm3,%xmm8

# qhasm:     uint6464 xmm8 >>= 4
# asm 1: psrlq $4,<xmm8=int6464#9
# asm 2: psrlq $4,<xmm8=%xmm8
psrlq $4,%xmm8

# qhasm:     xmm8 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm8=int6464#9
# asm 2: pxor  <xmm7=%xmm7,<xmm8=%xmm8
pxor  %xmm7,%xmm8

# qhasm:     xmm8 &= BS2
# asm 1: pand  BS2,<xmm8=int6464#9
# asm 2: pand  BS2,<xmm8=%xmm8
pand  BS2,%xmm8

# qhasm:     xmm7 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm7=int6464#8
# asm 2: pxor  <xmm8=%xmm8,<xmm7=%xmm7
pxor  %xmm8,%xmm7

# qhasm:     uint6464 xmm8 <<= 4
# asm 1: psllq $4,<xmm8=int6464#9
# asm 2: psllq $4,<xmm8=%xmm8
psllq $4,%xmm8

# qhasm:     xmm3 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm3=int6464#4
# asm 2: pxor  <xmm8=%xmm8,<xmm3=%xmm3
pxor  %xmm8,%xmm3

# qhasm:     xmm8 = xmm2
# asm 1: movdqa <xmm2=int6464#3,>xmm8=int6464#9
# asm 2: movdqa <xmm2=%xmm2,>xmm8=%xmm8
movdqa %xmm2,%xmm8

# qhasm:     uint6464 xmm8 >>= 4
# asm 1: psrlq $4,<xmm8=int6464#9
# asm 2: psrlq $4,<xmm8=%xmm8
psrlq $4,%xmm8

# qhasm:     xmm8 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm8=int6464#9
# asm 2: pxor  <xmm6=%xmm6,<xmm8=%xmm8
pxor  %xmm6,%xmm8

# qhasm:     xmm8 &= BS2
# asm 1: pand  BS2,<xmm8=int6464#9
# asm 2: pand  BS2,<xmm8=%xmm8
pand  BS2,%xmm8

# qhasm:     xmm6 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm6=int6464#7
# asm 2: pxor  <xmm8=%xmm8,<xmm6=%xmm6
pxor  %xmm8,%xmm6

# qhasm:     uint6464 xmm8 <<= 4
# asm 1: psllq $4,<xmm8=int6464#9
# asm 2: psllq $4,<xmm8=%xmm8
psllq $4,%xmm8

# qhasm:     xmm2 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm2=int6464#3
# asm 2: pxor  <xmm8=%xmm8,<xmm2=%xmm2
pxor  %xmm8,%xmm2

# qhasm:     xmm8 = xmm1
# asm 1: movdqa <xmm1=int6464#2,>xmm8=int6464#9
# asm 2: movdqa <xmm1=%xmm1,>xmm8=%xmm8
movdqa %xmm1,%xmm8

# qhasm:     uint6464 xmm8 >>= 4
# asm 1: psrlq $4,<xmm8=int6464#9
# asm 2: psrlq $4,<xmm8=%xmm8
psrlq $4,%xmm8

# qhasm:     xmm8 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm8=int6464#9
# asm 2: pxor  <xmm5=%xmm5,<xmm8=%xmm8
pxor  %xmm5,%xmm8

# qhasm:     xmm8 &= BS2
# asm 1: pand  BS2,<xmm8=int6464#9
# asm 2: pand  BS2,<xmm8=%xmm8
pand  BS2,%xmm8

# qhasm:     xmm5 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm5=int6464#6
# asm 2: pxor  <xmm8=%xmm8,<xmm5=%xmm5
pxor  %xmm8,%xmm5

# qhasm:     uint6464 xmm8 <<= 4
# asm 1: psllq $4,<xmm8=int6464#9
# asm 2: psllq $4,<xmm8=%xmm8
psllq $4,%xmm8

# qhasm:     xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm8,<xmm1=%xmm1
pxor  %xmm8,%xmm1

# qhasm:     xmm8 = xmm0
# asm 1: movdqa <xmm0=int6464#1,>xmm8=int6464#9
# asm 2: movdqa <xmm0=%xmm0,>xmm8=%xmm8
movdqa %xmm0,%xmm8

# qhasm:     uint6464 xmm8 >>= 4
# asm 1: psrlq $4,<xmm8=int6464#9
# asm 2: psrlq $4,<xmm8=%xmm8
psrlq $4,%xmm8

# qhasm:     xmm8 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm8=int6464#9
# asm 2: pxor  <xmm4=%xmm4,<xmm8=%xmm8
pxor  %xmm4,%xmm8

# qhasm:     xmm8 &= BS2
# asm 1: pand  BS2,<xmm8=int6464#9
# asm 2: pand  BS2,<xmm8=%xmm8
pand  BS2,%xmm8

# qhasm:     xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:     uint6464 xmm8 <<= 4
# asm 1: psllq $4,<xmm8=int6464#9
# asm 2: psllq $4,<xmm8=%xmm8
psllq $4,%xmm8

# qhasm:     xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:     xmm0 ^= *(int128 *)(c + 0)
# asm 1: pxor 0(<c=int64#4),<xmm0=int6464#1
# asm 2: pxor 0(<c=%rcx),<xmm0=%xmm0
pxor 0(%rcx),%xmm0

# qhasm:     shuffle bytes of xmm0 by SR
# asm 1: pshufb SR,<xmm0=int6464#1
# asm 2: pshufb SR,<xmm0=%xmm0
pshufb SR,%xmm0

# qhasm:     xmm1 ^= *(int128 *)(c + 16)
# asm 1: pxor 16(<c=int64#4),<xmm1=int6464#2
# asm 2: pxor 16(<c=%rcx),<xmm1=%xmm1
pxor 16(%rcx),%xmm1

# qhasm:     shuffle bytes of xmm1 by SR
# asm 1: pshufb SR,<xmm1=int6464#2
# asm 2: pshufb SR,<xmm1=%xmm1
pshufb SR,%xmm1

# qhasm:     xmm2 ^= *(int128 *)(c + 32)
# asm 1: pxor 32(<c=int64#4),<xmm2=int6464#3
# asm 2: pxor 32(<c=%rcx),<xmm2=%xmm2
pxor 32(%rcx),%xmm2

# qhasm:     shuffle bytes of xmm2 by SR
# asm 1: pshufb SR,<xmm2=int6464#3
# asm 2: pshufb SR,<xmm2=%xmm2
pshufb SR,%xmm2

# qhasm:     xmm3 ^= *(int128 *)(c + 48)
# asm 1: pxor 48(<c=int64#4),<xmm3=int6464#4
# asm 2: pxor 48(<c=%rcx),<xmm3=%xmm3
pxor 48(%rcx),%xmm3

# qhasm:     shuffle bytes of xmm3 by SR
# asm 1: pshufb SR,<xmm3=int6464#4
# asm 2: pshufb SR,<xmm3=%xmm3
pshufb SR,%xmm3

# qhasm:     xmm4 ^= *(int128 *)(c + 64)
# asm 1: pxor 64(<c=int64#4),<xmm4=int6464#5
# asm 2: pxor 64(<c=%rcx),<xmm4=%xmm4
pxor 64(%rcx),%xmm4

# qhasm:     shuffle bytes of xmm4 by SR
# asm 1: pshufb SR,<xmm4=int6464#5
# asm 2: pshufb SR,<xmm4=%xmm4
pshufb SR,%xmm4

# qhasm:     xmm5 ^= *(int128 *)(c + 80)
# asm 1: pxor 80(<c=int64#4),<xmm5=int6464#6
# asm 2: pxor 80(<c=%rcx),<xmm5=%xmm5
pxor 80(%rcx),%xmm5

# qhasm:     shuffle bytes of xmm5 by SR
# asm 1: pshufb SR,<xmm5=int6464#6
# asm 2: pshufb SR,<xmm5=%xmm5
pshufb SR,%xmm5

# qhasm:     xmm6 ^= *(int128 *)(c + 96)
# asm 1: pxor 96(<c=int64#4),<xmm6=int6464#7
# asm 2: pxor 96(<c=%rcx),<xmm6=%xmm6
pxor 96(%rcx),%xmm6

# qhasm:     shuffle bytes of xmm6 by SR
# asm 1: pshufb SR,<xmm6=int6464#7
# asm 2: pshufb SR,<xmm6=%xmm6
pshufb SR,%xmm6

# qhasm:     xmm7 ^= *(int128 *)(c + 112)
# asm 1: pxor 112(<c=int64#4),<xmm7=int6464#8
# asm 2: pxor 112(<c=%rcx),<xmm7=%xmm7
pxor 112(%rcx),%xmm7

# qhasm:     shuffle bytes of xmm7 by SR
# asm 1: pshufb SR,<xmm7=int6464#8
# asm 2: pshufb SR,<xmm7=%xmm7
pshufb SR,%xmm7

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

# qhasm:     xmm8 = shuffle dwords of xmm0 by 0x93
# asm 1: pshufd $0x93,<xmm0=int6464#1,>xmm8=int6464#9
# asm 2: pshufd $0x93,<xmm0=%xmm0,>xmm8=%xmm8
pshufd $0x93,%xmm0,%xmm8

# qhasm:     xmm9 = shuffle dwords of xmm1 by 0x93
# asm 1: pshufd $0x93,<xmm1=int6464#2,>xmm9=int6464#10
# asm 2: pshufd $0x93,<xmm1=%xmm1,>xmm9=%xmm9
pshufd $0x93,%xmm1,%xmm9

# qhasm:     xmm10 = shuffle dwords of xmm4 by 0x93
# asm 1: pshufd $0x93,<xmm4=int6464#5,>xmm10=int6464#11
# asm 2: pshufd $0x93,<xmm4=%xmm4,>xmm10=%xmm10
pshufd $0x93,%xmm4,%xmm10

# qhasm:     xmm11 = shuffle dwords of xmm6 by 0x93
# asm 1: pshufd $0x93,<xmm6=int6464#7,>xmm11=int6464#12
# asm 2: pshufd $0x93,<xmm6=%xmm6,>xmm11=%xmm11
pshufd $0x93,%xmm6,%xmm11

# qhasm:     xmm12 = shuffle dwords of xmm3 by 0x93
# asm 1: pshufd $0x93,<xmm3=int6464#4,>xmm12=int6464#13
# asm 2: pshufd $0x93,<xmm3=%xmm3,>xmm12=%xmm12
pshufd $0x93,%xmm3,%xmm12

# qhasm:     xmm13 = shuffle dwords of xmm7 by 0x93
# asm 1: pshufd $0x93,<xmm7=int6464#8,>xmm13=int6464#14
# asm 2: pshufd $0x93,<xmm7=%xmm7,>xmm13=%xmm13
pshufd $0x93,%xmm7,%xmm13

# qhasm:     xmm14 = shuffle dwords of xmm2 by 0x93
# asm 1: pshufd $0x93,<xmm2=int6464#3,>xmm14=int6464#15
# asm 2: pshufd $0x93,<xmm2=%xmm2,>xmm14=%xmm14
pshufd $0x93,%xmm2,%xmm14

# qhasm:     xmm15 = shuffle dwords of xmm5 by 0x93
# asm 1: pshufd $0x93,<xmm5=int6464#6,>xmm15=int6464#16
# asm 2: pshufd $0x93,<xmm5=%xmm5,>xmm15=%xmm15
pshufd $0x93,%xmm5,%xmm15

# qhasm:     xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:     xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:     xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:     xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:     xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:     xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:     xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:     xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:     xmm8 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm8=int6464#9
# asm 2: pxor  <xmm5=%xmm5,<xmm8=%xmm8
pxor  %xmm5,%xmm8

# qhasm:     xmm9 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm9=int6464#10
# asm 2: pxor  <xmm0=%xmm0,<xmm9=%xmm9
pxor  %xmm0,%xmm9

# qhasm:     xmm10 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm10=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm10=%xmm10
pxor  %xmm1,%xmm10

# qhasm:     xmm9 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm9=int6464#10
# asm 2: pxor  <xmm5=%xmm5,<xmm9=%xmm9
pxor  %xmm5,%xmm9

# qhasm:     xmm11 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm11=int6464#12
# asm 2: pxor  <xmm4=%xmm4,<xmm11=%xmm11
pxor  %xmm4,%xmm11

# qhasm:     xmm12 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm12=int6464#13
# asm 2: pxor  <xmm6=%xmm6,<xmm12=%xmm12
pxor  %xmm6,%xmm12

# qhasm:     xmm13 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm13=int6464#14
# asm 2: pxor  <xmm3=%xmm3,<xmm13=%xmm13
pxor  %xmm3,%xmm13

# qhasm:     xmm11 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm11=int6464#12
# asm 2: pxor  <xmm5=%xmm5,<xmm11=%xmm11
pxor  %xmm5,%xmm11

# qhasm:     xmm14 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm14=int6464#15
# asm 2: pxor  <xmm7=%xmm7,<xmm14=%xmm14
pxor  %xmm7,%xmm14

# qhasm:     xmm15 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm15=int6464#16
# asm 2: pxor  <xmm2=%xmm2,<xmm15=%xmm15
pxor  %xmm2,%xmm15

# qhasm:     xmm12 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm12=int6464#13
# asm 2: pxor  <xmm5=%xmm5,<xmm12=%xmm12
pxor  %xmm5,%xmm12

# qhasm:     xmm0 = shuffle dwords of xmm0 by 0x4E
# asm 1: pshufd $0x4E,<xmm0=int6464#1,>xmm0=int6464#1
# asm 2: pshufd $0x4E,<xmm0=%xmm0,>xmm0=%xmm0
pshufd $0x4E,%xmm0,%xmm0

# qhasm:     xmm1 = shuffle dwords of xmm1 by 0x4E
# asm 1: pshufd $0x4E,<xmm1=int6464#2,>xmm1=int6464#2
# asm 2: pshufd $0x4E,<xmm1=%xmm1,>xmm1=%xmm1
pshufd $0x4E,%xmm1,%xmm1

# qhasm:     xmm4 = shuffle dwords of xmm4 by 0x4E
# asm 1: pshufd $0x4E,<xmm4=int6464#5,>xmm4=int6464#5
# asm 2: pshufd $0x4E,<xmm4=%xmm4,>xmm4=%xmm4
pshufd $0x4E,%xmm4,%xmm4

# qhasm:     xmm6 = shuffle dwords of xmm6 by 0x4E
# asm 1: pshufd $0x4E,<xmm6=int6464#7,>xmm6=int6464#7
# asm 2: pshufd $0x4E,<xmm6=%xmm6,>xmm6=%xmm6
pshufd $0x4E,%xmm6,%xmm6

# qhasm:     xmm3 = shuffle dwords of xmm3 by 0x4E
# asm 1: pshufd $0x4E,<xmm3=int6464#4,>xmm3=int6464#4
# asm 2: pshufd $0x4E,<xmm3=%xmm3,>xmm3=%xmm3
pshufd $0x4E,%xmm3,%xmm3

# qhasm:     xmm7 = shuffle dwords of xmm7 by 0x4E
# asm 1: pshufd $0x4E,<xmm7=int6464#8,>xmm7=int6464#8
# asm 2: pshufd $0x4E,<xmm7=%xmm7,>xmm7=%xmm7
pshufd $0x4E,%xmm7,%xmm7

# qhasm:     xmm2 = shuffle dwords of xmm2 by 0x4E
# asm 1: pshufd $0x4E,<xmm2=int6464#3,>xmm2=int6464#3
# asm 2: pshufd $0x4E,<xmm2=%xmm2,>xmm2=%xmm2
pshufd $0x4E,%xmm2,%xmm2

# qhasm:     xmm5 = shuffle dwords of xmm5 by 0x4E
# asm 1: pshufd $0x4E,<xmm5=int6464#6,>xmm5=int6464#6
# asm 2: pshufd $0x4E,<xmm5=%xmm5,>xmm5=%xmm5
pshufd $0x4E,%xmm5,%xmm5

# qhasm:     xmm8 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:     xmm9 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm9=int6464#10
# asm 2: pxor  <xmm1=%xmm1,<xmm9=%xmm9
pxor  %xmm1,%xmm9

# qhasm:     xmm10 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm10=int6464#11
# asm 2: pxor  <xmm4=%xmm4,<xmm10=%xmm10
pxor  %xmm4,%xmm10

# qhasm:     xmm11 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm11=int6464#12
# asm 2: pxor  <xmm6=%xmm6,<xmm11=%xmm11
pxor  %xmm6,%xmm11

# qhasm:     xmm12 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm12=int6464#13
# asm 2: pxor  <xmm3=%xmm3,<xmm12=%xmm12
pxor  %xmm3,%xmm12

# qhasm:     xmm13 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm13=int6464#14
# asm 2: pxor  <xmm7=%xmm7,<xmm13=%xmm13
pxor  %xmm7,%xmm13

# qhasm:     xmm14 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm14=int6464#15
# asm 2: pxor  <xmm2=%xmm2,<xmm14=%xmm14
pxor  %xmm2,%xmm14

# qhasm:     xmm15 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm15=int6464#16
# asm 2: pxor  <xmm5=%xmm5,<xmm15=%xmm15
pxor  %xmm5,%xmm15

# qhasm:     xmm8 ^= *(int128 *)(c + 128)
# asm 1: pxor 128(<c=int64#4),<xmm8=int6464#9
# asm 2: pxor 128(<c=%rcx),<xmm8=%xmm8
pxor 128(%rcx),%xmm8

# qhasm:     shuffle bytes of xmm8 by SR
# asm 1: pshufb SR,<xmm8=int6464#9
# asm 2: pshufb SR,<xmm8=%xmm8
pshufb SR,%xmm8

# qhasm:     xmm9 ^= *(int128 *)(c + 144)
# asm 1: pxor 144(<c=int64#4),<xmm9=int6464#10
# asm 2: pxor 144(<c=%rcx),<xmm9=%xmm9
pxor 144(%rcx),%xmm9

# qhasm:     shuffle bytes of xmm9 by SR
# asm 1: pshufb SR,<xmm9=int6464#10
# asm 2: pshufb SR,<xmm9=%xmm9
pshufb SR,%xmm9

# qhasm:     xmm10 ^= *(int128 *)(c + 160)
# asm 1: pxor 160(<c=int64#4),<xmm10=int6464#11
# asm 2: pxor 160(<c=%rcx),<xmm10=%xmm10
pxor 160(%rcx),%xmm10

# qhasm:     shuffle bytes of xmm10 by SR
# asm 1: pshufb SR,<xmm10=int6464#11
# asm 2: pshufb SR,<xmm10=%xmm10
pshufb SR,%xmm10

# qhasm:     xmm11 ^= *(int128 *)(c + 176)
# asm 1: pxor 176(<c=int64#4),<xmm11=int6464#12
# asm 2: pxor 176(<c=%rcx),<xmm11=%xmm11
pxor 176(%rcx),%xmm11

# qhasm:     shuffle bytes of xmm11 by SR
# asm 1: pshufb SR,<xmm11=int6464#12
# asm 2: pshufb SR,<xmm11=%xmm11
pshufb SR,%xmm11

# qhasm:     xmm12 ^= *(int128 *)(c + 192)
# asm 1: pxor 192(<c=int64#4),<xmm12=int6464#13
# asm 2: pxor 192(<c=%rcx),<xmm12=%xmm12
pxor 192(%rcx),%xmm12

# qhasm:     shuffle bytes of xmm12 by SR
# asm 1: pshufb SR,<xmm12=int6464#13
# asm 2: pshufb SR,<xmm12=%xmm12
pshufb SR,%xmm12

# qhasm:     xmm13 ^= *(int128 *)(c + 208)
# asm 1: pxor 208(<c=int64#4),<xmm13=int6464#14
# asm 2: pxor 208(<c=%rcx),<xmm13=%xmm13
pxor 208(%rcx),%xmm13

# qhasm:     shuffle bytes of xmm13 by SR
# asm 1: pshufb SR,<xmm13=int6464#14
# asm 2: pshufb SR,<xmm13=%xmm13
pshufb SR,%xmm13

# qhasm:     xmm14 ^= *(int128 *)(c + 224)
# asm 1: pxor 224(<c=int64#4),<xmm14=int6464#15
# asm 2: pxor 224(<c=%rcx),<xmm14=%xmm14
pxor 224(%rcx),%xmm14

# qhasm:     shuffle bytes of xmm14 by SR
# asm 1: pshufb SR,<xmm14=int6464#15
# asm 2: pshufb SR,<xmm14=%xmm14
pshufb SR,%xmm14

# qhasm:     xmm15 ^= *(int128 *)(c + 240)
# asm 1: pxor 240(<c=int64#4),<xmm15=int6464#16
# asm 2: pxor 240(<c=%rcx),<xmm15=%xmm15
pxor 240(%rcx),%xmm15

# qhasm:     shuffle bytes of xmm15 by SR
# asm 1: pshufb SR,<xmm15=int6464#16
# asm 2: pshufb SR,<xmm15=%xmm15
pshufb SR,%xmm15

# qhasm:       xmm13 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm13=int6464#14
# asm 2: pxor  <xmm14=%xmm14,<xmm13=%xmm13
pxor  %xmm14,%xmm13

# qhasm:       xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm9,<xmm10=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm13=int6464#14
# asm 2: pxor  <xmm8=%xmm8,<xmm13=%xmm13
pxor  %xmm8,%xmm13

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm14=int6464#15
# asm 2: pxor  <xmm10=%xmm10,<xmm14=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm11=int6464#12
# asm 2: pxor  <xmm8=%xmm8,<xmm11=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm14=int6464#15
# asm 2: pxor  <xmm11=%xmm11,<xmm14=%xmm14
pxor  %xmm11,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#12
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm11
pxor  %xmm15,%xmm11

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm11=int6464#12
# asm 2: pxor  <xmm12=%xmm12,<xmm11=%xmm11
pxor  %xmm12,%xmm11

# qhasm:       xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm15=int6464#16
# asm 2: pxor  <xmm13=%xmm13,<xmm15=%xmm15
pxor  %xmm13,%xmm15

# qhasm:       xmm11 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm11=int6464#12
# asm 2: pxor  <xmm9=%xmm9,<xmm11=%xmm11
pxor  %xmm9,%xmm11

# qhasm:       xmm12 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm12=int6464#13
# asm 2: pxor  <xmm13=%xmm13,<xmm12=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm10 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm10=int6464#11
# asm 2: pxor  <xmm15=%xmm15,<xmm10=%xmm10
pxor  %xmm15,%xmm10

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm9=int6464#10
# asm 2: pxor  <xmm13=%xmm13,<xmm9=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm3 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm3=int6464#1
# asm 2: movdqa <xmm15=%xmm15,>xmm3=%xmm0
movdqa %xmm15,%xmm0

# qhasm:       xmm2 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm2=int6464#2
# asm 2: movdqa <xmm9=%xmm9,>xmm2=%xmm1
movdqa %xmm9,%xmm1

# qhasm:       xmm1 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm1=int6464#3
# asm 2: movdqa <xmm13=%xmm13,>xmm1=%xmm2
movdqa %xmm13,%xmm2

# qhasm:       xmm5 = xmm10
# asm 1: movdqa <xmm10=int6464#11,>xmm5=int6464#4
# asm 2: movdqa <xmm10=%xmm10,>xmm5=%xmm3
movdqa %xmm10,%xmm3

# qhasm:       xmm4 = xmm14
# asm 1: movdqa <xmm14=int6464#15,>xmm4=int6464#5
# asm 2: movdqa <xmm14=%xmm14,>xmm4=%xmm4
movdqa %xmm14,%xmm4

# qhasm:       xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#1
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm0
pxor  %xmm12,%xmm0

# qhasm:       xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#2
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm1
pxor  %xmm10,%xmm1

# qhasm:       xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm1=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm1=%xmm2
pxor  %xmm11,%xmm2

# qhasm:       xmm5 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm5=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm5=%xmm3
pxor  %xmm12,%xmm3

# qhasm:       xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:       xmm6 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm6=int6464#6
# asm 2: movdqa <xmm3=%xmm0,>xmm6=%xmm5
movdqa %xmm0,%xmm5

# qhasm:       xmm0 = xmm2
# asm 1: movdqa <xmm2=int6464#2,>xmm0=int6464#7
# asm 2: movdqa <xmm2=%xmm1,>xmm0=%xmm6
movdqa %xmm1,%xmm6

# qhasm:       xmm7 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm7=int6464#8
# asm 2: movdqa <xmm3=%xmm0,>xmm7=%xmm7
movdqa %xmm0,%xmm7

# qhasm:       xmm2 |= xmm1
# asm 1: por   <xmm1=int6464#3,<xmm2=int6464#2
# asm 2: por   <xmm1=%xmm2,<xmm2=%xmm1
por   %xmm2,%xmm1

# qhasm:       xmm3 |= xmm4
# asm 1: por   <xmm4=int6464#5,<xmm3=int6464#1
# asm 2: por   <xmm4=%xmm4,<xmm3=%xmm0
por   %xmm4,%xmm0

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm7=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm6 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm6=int6464#6
# asm 2: pand  <xmm4=%xmm4,<xmm6=%xmm5
pand  %xmm4,%xmm5

# qhasm:       xmm0 &= xmm1
# asm 1: pand  <xmm1=int6464#3,<xmm0=int6464#7
# asm 2: pand  <xmm1=%xmm2,<xmm0=%xmm6
pand  %xmm2,%xmm6

# qhasm:       xmm4 ^= xmm1
# asm 1: pxor  <xmm1=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm1=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:       xmm7 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm7=int6464#8
# asm 2: pand  <xmm4=%xmm4,<xmm7=%xmm7
pand  %xmm4,%xmm7

# qhasm:       xmm4 = xmm11
# asm 1: movdqa <xmm11=int6464#12,>xmm4=int6464#3
# asm 2: movdqa <xmm11=%xmm11,>xmm4=%xmm2
movdqa %xmm11,%xmm2

# qhasm:       xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#3
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm2
pxor  %xmm8,%xmm2

# qhasm:       xmm5 &= xmm4
# asm 1: pand  <xmm4=int6464#3,<xmm5=int6464#4
# asm 2: pand  <xmm4=%xmm2,<xmm5=%xmm3
pand  %xmm2,%xmm3

# qhasm:       xmm3 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm3=int6464#1
# asm 2: pxor  <xmm5=%xmm3,<xmm3=%xmm0
pxor  %xmm3,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm2=int6464#2
# asm 2: pxor  <xmm5=%xmm3,<xmm2=%xmm1
pxor  %xmm3,%xmm1

# qhasm:       xmm5 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm5=int6464#3
# asm 2: movdqa <xmm15=%xmm15,>xmm5=%xmm2
movdqa %xmm15,%xmm2

# qhasm:       xmm5 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm5=int6464#3
# asm 2: pxor  <xmm9=%xmm9,<xmm5=%xmm2
pxor  %xmm9,%xmm2

# qhasm:       xmm4 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm4=int6464#4
# asm 2: movdqa <xmm13=%xmm13,>xmm4=%xmm3
movdqa %xmm13,%xmm3

# qhasm:       xmm1 = xmm5
# asm 1: movdqa <xmm5=int6464#3,>xmm1=int6464#5
# asm 2: movdqa <xmm5=%xmm2,>xmm1=%xmm4
movdqa %xmm2,%xmm4

# qhasm:       xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm3
pxor  %xmm14,%xmm3

# qhasm:       xmm1 |= xmm4
# asm 1: por   <xmm4=int6464#4,<xmm1=int6464#5
# asm 2: por   <xmm4=%xmm3,<xmm1=%xmm4
por   %xmm3,%xmm4

# qhasm:       xmm5 &= xmm4
# asm 1: pand  <xmm4=int6464#4,<xmm5=int6464#3
# asm 2: pand  <xmm4=%xmm3,<xmm5=%xmm2
pand  %xmm3,%xmm2

# qhasm:       xmm0 ^= xmm5
# asm 1: pxor  <xmm5=int6464#3,<xmm0=int6464#7
# asm 2: pxor  <xmm5=%xmm2,<xmm0=%xmm6
pxor  %xmm2,%xmm6

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#1
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm0
pxor  %xmm7,%xmm0

# qhasm:       xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm2=int6464#2
# asm 2: pxor  <xmm6=%xmm5,<xmm2=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#5
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm0 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm0=int6464#7
# asm 2: pxor  <xmm6=%xmm5,<xmm0=%xmm6
pxor  %xmm5,%xmm6

# qhasm:       xmm1 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm1=int6464#5
# asm 2: pxor  <xmm6=%xmm5,<xmm1=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm4 = xmm10
# asm 1: movdqa <xmm10=int6464#11,>xmm4=int6464#3
# asm 2: movdqa <xmm10=%xmm10,>xmm4=%xmm2
movdqa %xmm10,%xmm2

# qhasm:       xmm5 = xmm12
# asm 1: movdqa <xmm12=int6464#13,>xmm5=int6464#4
# asm 2: movdqa <xmm12=%xmm12,>xmm5=%xmm3
movdqa %xmm12,%xmm3

# qhasm:       xmm6 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm6=int6464#6
# asm 2: movdqa <xmm9=%xmm9,>xmm6=%xmm5
movdqa %xmm9,%xmm5

# qhasm:       xmm7 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm7=int6464#8
# asm 2: movdqa <xmm15=%xmm15,>xmm7=%xmm7
movdqa %xmm15,%xmm7

# qhasm:       xmm4 &= xmm11
# asm 1: pand  <xmm11=int6464#12,<xmm4=int6464#3
# asm 2: pand  <xmm11=%xmm11,<xmm4=%xmm2
pand  %xmm11,%xmm2

# qhasm:       xmm5 &= xmm8
# asm 1: pand  <xmm8=int6464#9,<xmm5=int6464#4
# asm 2: pand  <xmm8=%xmm8,<xmm5=%xmm3
pand  %xmm8,%xmm3

# qhasm:       xmm6 &= xmm13
# asm 1: pand  <xmm13=int6464#14,<xmm6=int6464#6
# asm 2: pand  <xmm13=%xmm13,<xmm6=%xmm5
pand  %xmm13,%xmm5

# qhasm:       xmm7 |= xmm14
# asm 1: por   <xmm14=int6464#15,<xmm7=int6464#8
# asm 2: por   <xmm14=%xmm14,<xmm7=%xmm7
por   %xmm14,%xmm7

# qhasm:       xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#3,<xmm3=int6464#1
# asm 2: pxor  <xmm4=%xmm2,<xmm3=%xmm0
pxor  %xmm2,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm2=int6464#2
# asm 2: pxor  <xmm5=%xmm3,<xmm2=%xmm1
pxor  %xmm3,%xmm1

# qhasm:       xmm1 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm1=int6464#5
# asm 2: pxor  <xmm6=%xmm5,<xmm1=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm0 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm0=int6464#7
# asm 2: pxor  <xmm7=%xmm7,<xmm0=%xmm6
pxor  %xmm7,%xmm6

# qhasm:       xmm4 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm4=int6464#3
# asm 2: movdqa <xmm3=%xmm0,>xmm4=%xmm2
movdqa %xmm0,%xmm2

# qhasm:       xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm4=int6464#3
# asm 2: pxor  <xmm2=%xmm1,<xmm4=%xmm2
pxor  %xmm1,%xmm2

# qhasm:       xmm3 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm3=int6464#1
# asm 2: pand  <xmm1=%xmm4,<xmm3=%xmm0
pand  %xmm4,%xmm0

# qhasm:       xmm6 = xmm0
# asm 1: movdqa <xmm0=int6464#7,>xmm6=int6464#4
# asm 2: movdqa <xmm0=%xmm6,>xmm6=%xmm3
movdqa %xmm6,%xmm3

# qhasm:       xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#1,<xmm6=int6464#4
# asm 2: pxor  <xmm3=%xmm0,<xmm6=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm7 = xmm4
# asm 1: movdqa <xmm4=int6464#3,>xmm7=int6464#6
# asm 2: movdqa <xmm4=%xmm2,>xmm7=%xmm5
movdqa %xmm2,%xmm5

# qhasm:       xmm7 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm7=int6464#6
# asm 2: pand  <xmm6=%xmm3,<xmm7=%xmm5
pand  %xmm3,%xmm5

# qhasm:       xmm7 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm7=int6464#6
# asm 2: pxor  <xmm2=%xmm1,<xmm7=%xmm5
pxor  %xmm1,%xmm5

# qhasm:       xmm5 = xmm1
# asm 1: movdqa <xmm1=int6464#5,>xmm5=int6464#8
# asm 2: movdqa <xmm1=%xmm4,>xmm5=%xmm7
movdqa %xmm4,%xmm7

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm5=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm5=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm3 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm3=int6464#1
# asm 2: pxor  <xmm2=%xmm1,<xmm3=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm5 &= xmm3
# asm 1: pand  <xmm3=int6464#1,<xmm5=int6464#8
# asm 2: pand  <xmm3=%xmm0,<xmm5=%xmm7
pand  %xmm0,%xmm7

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm5=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm5=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm1=int6464#5
# asm 2: pxor  <xmm5=%xmm7,<xmm1=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm2 = xmm6
# asm 1: movdqa <xmm6=int6464#4,>xmm2=int6464#1
# asm 2: movdqa <xmm6=%xmm3,>xmm2=%xmm0
movdqa %xmm3,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm2=int6464#1
# asm 2: pxor  <xmm5=%xmm7,<xmm2=%xmm0
pxor  %xmm7,%xmm0

# qhasm:       xmm2 &= xmm0
# asm 1: pand  <xmm0=int6464#7,<xmm2=int6464#1
# asm 2: pand  <xmm0=%xmm6,<xmm2=%xmm0
pand  %xmm6,%xmm0

# qhasm:       xmm1 ^= xmm2
# asm 1: pxor  <xmm2=int6464#1,<xmm1=int6464#5
# asm 2: pxor  <xmm2=%xmm0,<xmm1=%xmm4
pxor  %xmm0,%xmm4

# qhasm:       xmm6 ^= xmm2
# asm 1: pxor  <xmm2=int6464#1,<xmm6=int6464#4
# asm 2: pxor  <xmm2=%xmm0,<xmm6=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm6 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm6=int6464#4
# asm 2: pand  <xmm7=%xmm5,<xmm6=%xmm3
pand  %xmm5,%xmm3

# qhasm:       xmm6 ^= xmm4
# asm 1: pxor  <xmm4=int6464#3,<xmm6=int6464#4
# asm 2: pxor  <xmm4=%xmm2,<xmm6=%xmm3
pxor  %xmm2,%xmm3

# qhasm:         xmm4 = xmm14
# asm 1: movdqa <xmm14=int6464#15,>xmm4=int6464#1
# asm 2: movdqa <xmm14=%xmm14,>xmm4=%xmm0
movdqa %xmm14,%xmm0

# qhasm:         xmm0 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm0=int6464#2
# asm 2: movdqa <xmm13=%xmm13,>xmm0=%xmm1
movdqa %xmm13,%xmm1

# qhasm:           xmm2 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm2=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm2=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm2=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm2 &= xmm14
# asm 1: pand  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pand  <xmm14=%xmm14,<xmm2=%xmm2
pand  %xmm14,%xmm2

# qhasm:           xmm14 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm14=int6464#15
# asm 2: pxor  <xmm13=%xmm13,<xmm14=%xmm14
pxor  %xmm13,%xmm14

# qhasm:           xmm14 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm14=int6464#15
# asm 2: pand  <xmm6=%xmm3,<xmm14=%xmm14
pand  %xmm3,%xmm14

# qhasm:           xmm13 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm13=int6464#14
# asm 2: pand  <xmm7=%xmm5,<xmm13=%xmm13
pand  %xmm5,%xmm13

# qhasm:           xmm14 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm14=int6464#15
# asm 2: pxor  <xmm13=%xmm13,<xmm14=%xmm14
pxor  %xmm13,%xmm14

# qhasm:           xmm13 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm13=int6464#14
# asm 2: pxor  <xmm2=%xmm2,<xmm13=%xmm13
pxor  %xmm2,%xmm13

# qhasm:         xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm0 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm0=int6464#2
# asm 2: pxor  <xmm11=%xmm11,<xmm0=%xmm1
pxor  %xmm11,%xmm1

# qhasm:         xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm7=int6464#6
# asm 2: pxor  <xmm5=%xmm7,<xmm7=%xmm5
pxor  %xmm7,%xmm5

# qhasm:         xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm6=int6464#4
# asm 2: pxor  <xmm1=%xmm4,<xmm6=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm4
# asm 1: pand  <xmm4=int6464#1,<xmm3=int6464#3
# asm 2: pand  <xmm4=%xmm0,<xmm3=%xmm2
pand  %xmm0,%xmm2

# qhasm:           xmm4 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm4=int6464#1
# asm 2: pxor  <xmm0=%xmm1,<xmm4=%xmm0
pxor  %xmm1,%xmm0

# qhasm:           xmm4 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm4=int6464#1
# asm 2: pand  <xmm6=%xmm3,<xmm4=%xmm0
pand  %xmm3,%xmm0

# qhasm:           xmm0 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm0=int6464#2
# asm 2: pand  <xmm7=%xmm5,<xmm0=%xmm1
pand  %xmm5,%xmm1

# qhasm:           xmm0 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm0=int6464#2
# asm 2: pxor  <xmm4=%xmm0,<xmm0=%xmm1
pxor  %xmm0,%xmm1

# qhasm:           xmm4 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm4=int6464#1
# asm 2: pxor  <xmm3=%xmm2,<xmm4=%xmm0
pxor  %xmm2,%xmm0

# qhasm:           xmm2 = xmm5
# asm 1: movdqa <xmm5=int6464#8,>xmm2=int6464#3
# asm 2: movdqa <xmm5=%xmm7,>xmm2=%xmm2
movdqa %xmm7,%xmm2

# qhasm:           xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm4,<xmm2=%xmm2
pxor  %xmm4,%xmm2

# qhasm:           xmm2 &= xmm8
# asm 1: pand  <xmm8=int6464#9,<xmm2=int6464#3
# asm 2: pand  <xmm8=%xmm8,<xmm2=%xmm2
pand  %xmm8,%xmm2

# qhasm:           xmm8 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm8=int6464#9
# asm 2: pxor  <xmm11=%xmm11,<xmm8=%xmm8
pxor  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm8=int6464#9
# asm 2: pand  <xmm1=%xmm4,<xmm8=%xmm8
pand  %xmm4,%xmm8

# qhasm:           xmm11 &= xmm5
# asm 1: pand  <xmm5=int6464#8,<xmm11=int6464#12
# asm 2: pand  <xmm5=%xmm7,<xmm11=%xmm11
pand  %xmm7,%xmm11

# qhasm:           xmm8 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm8=int6464#9
# asm 2: pxor  <xmm11=%xmm11,<xmm8=%xmm8
pxor  %xmm11,%xmm8

# qhasm:           xmm11 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm11=int6464#12
# asm 2: pxor  <xmm2=%xmm2,<xmm11=%xmm11
pxor  %xmm2,%xmm11

# qhasm:         xmm14 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm14=int6464#15
# asm 2: pxor  <xmm4=%xmm0,<xmm14=%xmm14
pxor  %xmm0,%xmm14

# qhasm:         xmm8 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm4=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm13 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm13=int6464#14
# asm 2: pxor  <xmm0=%xmm1,<xmm13=%xmm13
pxor  %xmm1,%xmm13

# qhasm:         xmm11 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm11=int6464#12
# asm 2: pxor  <xmm0=%xmm1,<xmm11=%xmm11
pxor  %xmm1,%xmm11

# qhasm:         xmm4 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm4=int6464#1
# asm 2: movdqa <xmm15=%xmm15,>xmm4=%xmm0
movdqa %xmm15,%xmm0

# qhasm:         xmm0 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm0=int6464#2
# asm 2: movdqa <xmm9=%xmm9,>xmm0=%xmm1
movdqa %xmm9,%xmm1

# qhasm:         xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm4=int6464#1
# asm 2: pxor  <xmm12=%xmm12,<xmm4=%xmm0
pxor  %xmm12,%xmm0

# qhasm:         xmm0 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm0=int6464#2
# asm 2: pxor  <xmm10=%xmm10,<xmm0=%xmm1
pxor  %xmm10,%xmm1

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm4
# asm 1: pand  <xmm4=int6464#1,<xmm3=int6464#3
# asm 2: pand  <xmm4=%xmm0,<xmm3=%xmm2
pand  %xmm0,%xmm2

# qhasm:           xmm4 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm4=int6464#1
# asm 2: pxor  <xmm0=%xmm1,<xmm4=%xmm0
pxor  %xmm1,%xmm0

# qhasm:           xmm4 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm4=int6464#1
# asm 2: pand  <xmm6=%xmm3,<xmm4=%xmm0
pand  %xmm3,%xmm0

# qhasm:           xmm0 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm0=int6464#2
# asm 2: pand  <xmm7=%xmm5,<xmm0=%xmm1
pand  %xmm5,%xmm1

# qhasm:           xmm0 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm0=int6464#2
# asm 2: pxor  <xmm4=%xmm0,<xmm0=%xmm1
pxor  %xmm0,%xmm1

# qhasm:           xmm4 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm4=int6464#1
# asm 2: pxor  <xmm3=%xmm2,<xmm4=%xmm0
pxor  %xmm2,%xmm0

# qhasm:           xmm2 = xmm5
# asm 1: movdqa <xmm5=int6464#8,>xmm2=int6464#3
# asm 2: movdqa <xmm5=%xmm7,>xmm2=%xmm2
movdqa %xmm7,%xmm2

# qhasm:           xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm4,<xmm2=%xmm2
pxor  %xmm4,%xmm2

# qhasm:           xmm2 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pand  <xmm12=%xmm12,<xmm2=%xmm2
pand  %xmm12,%xmm2

# qhasm:           xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm10=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:           xmm12 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm12=int6464#13
# asm 2: pand  <xmm1=%xmm4,<xmm12=%xmm12
pand  %xmm4,%xmm12

# qhasm:           xmm10 &= xmm5
# asm 1: pand  <xmm5=int6464#8,<xmm10=int6464#11
# asm 2: pand  <xmm5=%xmm7,<xmm10=%xmm10
pand  %xmm7,%xmm10

# qhasm:           xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm10=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:           xmm10 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm10=int6464#11
# asm 2: pxor  <xmm2=%xmm2,<xmm10=%xmm10
pxor  %xmm2,%xmm10

# qhasm:         xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm7=int6464#6
# asm 2: pxor  <xmm5=%xmm7,<xmm7=%xmm5
pxor  %xmm7,%xmm5

# qhasm:         xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm6=int6464#4
# asm 2: pxor  <xmm1=%xmm4,<xmm6=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm15
# asm 1: pand  <xmm15=int6464#16,<xmm3=int6464#3
# asm 2: pand  <xmm15=%xmm15,<xmm3=%xmm2
pand  %xmm15,%xmm2

# qhasm:           xmm15 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm15=int6464#16
# asm 2: pxor  <xmm9=%xmm9,<xmm15=%xmm15
pxor  %xmm9,%xmm15

# qhasm:           xmm15 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm15=int6464#16
# asm 2: pand  <xmm6=%xmm3,<xmm15=%xmm15
pand  %xmm3,%xmm15

# qhasm:           xmm9 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm9=int6464#10
# asm 2: pand  <xmm7=%xmm5,<xmm9=%xmm9
pand  %xmm5,%xmm9

# qhasm:           xmm15 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm15=int6464#16
# asm 2: pxor  <xmm9=%xmm9,<xmm15=%xmm15
pxor  %xmm9,%xmm15

# qhasm:           xmm9 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm9=int6464#10
# asm 2: pxor  <xmm3=%xmm2,<xmm9=%xmm9
pxor  %xmm2,%xmm9

# qhasm:         xmm15 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm15=int6464#16
# asm 2: pxor  <xmm4=%xmm0,<xmm15=%xmm15
pxor  %xmm0,%xmm15

# qhasm:         xmm12 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm4=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:         xmm9 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm9=int6464#10
# asm 2: pxor  <xmm0=%xmm1,<xmm9=%xmm9
pxor  %xmm1,%xmm9

# qhasm:         xmm10 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm10=int6464#11
# asm 2: pxor  <xmm0=%xmm1,<xmm10=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm8,<xmm15=%xmm15
pxor  %xmm8,%xmm15

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm9=int6464#10
# asm 2: pxor  <xmm14=%xmm14,<xmm9=%xmm9
pxor  %xmm14,%xmm9

# qhasm:       xmm12 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm12=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm12=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm14 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm14=int6464#15
# asm 2: pxor  <xmm8=%xmm8,<xmm14=%xmm14
pxor  %xmm8,%xmm14

# qhasm:       xmm8 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm8=int6464#9
# asm 2: pxor  <xmm9=%xmm9,<xmm8=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm9=int6464#10
# asm 2: pxor  <xmm13=%xmm13,<xmm9=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm13 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm13=int6464#14
# asm 2: pxor  <xmm10=%xmm10,<xmm13=%xmm13
pxor  %xmm10,%xmm13

# qhasm:       xmm12 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm12=int6464#13
# asm 2: pxor  <xmm13=%xmm13,<xmm12=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm10 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm11=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm11=int6464#12
# asm 2: pxor  <xmm13=%xmm13,<xmm11=%xmm11
pxor  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm14=int6464#15
# asm 2: pxor  <xmm11=%xmm11,<xmm14=%xmm14
pxor  %xmm11,%xmm14

# qhasm:     xmm0 = shuffle dwords of xmm8 by 0x93
# asm 1: pshufd $0x93,<xmm8=int6464#9,>xmm0=int6464#1
# asm 2: pshufd $0x93,<xmm8=%xmm8,>xmm0=%xmm0
pshufd $0x93,%xmm8,%xmm0

# qhasm:     xmm1 = shuffle dwords of xmm9 by 0x93
# asm 1: pshufd $0x93,<xmm9=int6464#10,>xmm1=int6464#2
# asm 2: pshufd $0x93,<xmm9=%xmm9,>xmm1=%xmm1
pshufd $0x93,%xmm9,%xmm1

# qhasm:     xmm2 = shuffle dwords of xmm12 by 0x93
# asm 1: pshufd $0x93,<xmm12=int6464#13,>xmm2=int6464#3
# asm 2: pshufd $0x93,<xmm12=%xmm12,>xmm2=%xmm2
pshufd $0x93,%xmm12,%xmm2

# qhasm:     xmm3 = shuffle dwords of xmm14 by 0x93
# asm 1: pshufd $0x93,<xmm14=int6464#15,>xmm3=int6464#4
# asm 2: pshufd $0x93,<xmm14=%xmm14,>xmm3=%xmm3
pshufd $0x93,%xmm14,%xmm3

# qhasm:     xmm4 = shuffle dwords of xmm11 by 0x93
# asm 1: pshufd $0x93,<xmm11=int6464#12,>xmm4=int6464#5
# asm 2: pshufd $0x93,<xmm11=%xmm11,>xmm4=%xmm4
pshufd $0x93,%xmm11,%xmm4

# qhasm:     xmm5 = shuffle dwords of xmm15 by 0x93
# asm 1: pshufd $0x93,<xmm15=int6464#16,>xmm5=int6464#6
# asm 2: pshufd $0x93,<xmm15=%xmm15,>xmm5=%xmm5
pshufd $0x93,%xmm15,%xmm5

# qhasm:     xmm6 = shuffle dwords of xmm10 by 0x93
# asm 1: pshufd $0x93,<xmm10=int6464#11,>xmm6=int6464#7
# asm 2: pshufd $0x93,<xmm10=%xmm10,>xmm6=%xmm6
pshufd $0x93,%xmm10,%xmm6

# qhasm:     xmm7 = shuffle dwords of xmm13 by 0x93
# asm 1: pshufd $0x93,<xmm13=int6464#14,>xmm7=int6464#8
# asm 2: pshufd $0x93,<xmm13=%xmm13,>xmm7=%xmm7
pshufd $0x93,%xmm13,%xmm7

# qhasm:     xmm8 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:     xmm9 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm9=int6464#10
# asm 2: pxor  <xmm1=%xmm1,<xmm9=%xmm9
pxor  %xmm1,%xmm9

# qhasm:     xmm12 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm12=int6464#13
# asm 2: pxor  <xmm2=%xmm2,<xmm12=%xmm12
pxor  %xmm2,%xmm12

# qhasm:     xmm14 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm14=int6464#15
# asm 2: pxor  <xmm3=%xmm3,<xmm14=%xmm14
pxor  %xmm3,%xmm14

# qhasm:     xmm11 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm11=int6464#12
# asm 2: pxor  <xmm4=%xmm4,<xmm11=%xmm11
pxor  %xmm4,%xmm11

# qhasm:     xmm15 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm15=int6464#16
# asm 2: pxor  <xmm5=%xmm5,<xmm15=%xmm15
pxor  %xmm5,%xmm15

# qhasm:     xmm10 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm10=int6464#11
# asm 2: pxor  <xmm6=%xmm6,<xmm10=%xmm10
pxor  %xmm6,%xmm10

# qhasm:     xmm13 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm13=int6464#14
# asm 2: pxor  <xmm7=%xmm7,<xmm13=%xmm13
pxor  %xmm7,%xmm13

# qhasm:     xmm0 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm0=int6464#1
# asm 2: pxor  <xmm13=%xmm13,<xmm0=%xmm0
pxor  %xmm13,%xmm0

# qhasm:     xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm8,<xmm1=%xmm1
pxor  %xmm8,%xmm1

# qhasm:     xmm2 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm2=int6464#3
# asm 2: pxor  <xmm9=%xmm9,<xmm2=%xmm2
pxor  %xmm9,%xmm2

# qhasm:     xmm1 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm1=int6464#2
# asm 2: pxor  <xmm13=%xmm13,<xmm1=%xmm1
pxor  %xmm13,%xmm1

# qhasm:     xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:     xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:     xmm5 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm5=int6464#6
# asm 2: pxor  <xmm11=%xmm11,<xmm5=%xmm5
pxor  %xmm11,%xmm5

# qhasm:     xmm3 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm3=int6464#4
# asm 2: pxor  <xmm13=%xmm13,<xmm3=%xmm3
pxor  %xmm13,%xmm3

# qhasm:     xmm6 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm6=int6464#7
# asm 2: pxor  <xmm15=%xmm15,<xmm6=%xmm6
pxor  %xmm15,%xmm6

# qhasm:     xmm7 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm7=int6464#8
# asm 2: pxor  <xmm10=%xmm10,<xmm7=%xmm7
pxor  %xmm10,%xmm7

# qhasm:     xmm4 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm4=int6464#5
# asm 2: pxor  <xmm13=%xmm13,<xmm4=%xmm4
pxor  %xmm13,%xmm4

# qhasm:     xmm8 = shuffle dwords of xmm8 by 0x4E
# asm 1: pshufd $0x4E,<xmm8=int6464#9,>xmm8=int6464#9
# asm 2: pshufd $0x4E,<xmm8=%xmm8,>xmm8=%xmm8
pshufd $0x4E,%xmm8,%xmm8

# qhasm:     xmm9 = shuffle dwords of xmm9 by 0x4E
# asm 1: pshufd $0x4E,<xmm9=int6464#10,>xmm9=int6464#10
# asm 2: pshufd $0x4E,<xmm9=%xmm9,>xmm9=%xmm9
pshufd $0x4E,%xmm9,%xmm9

# qhasm:     xmm12 = shuffle dwords of xmm12 by 0x4E
# asm 1: pshufd $0x4E,<xmm12=int6464#13,>xmm12=int6464#13
# asm 2: pshufd $0x4E,<xmm12=%xmm12,>xmm12=%xmm12
pshufd $0x4E,%xmm12,%xmm12

# qhasm:     xmm14 = shuffle dwords of xmm14 by 0x4E
# asm 1: pshufd $0x4E,<xmm14=int6464#15,>xmm14=int6464#15
# asm 2: pshufd $0x4E,<xmm14=%xmm14,>xmm14=%xmm14
pshufd $0x4E,%xmm14,%xmm14

# qhasm:     xmm11 = shuffle dwords of xmm11 by 0x4E
# asm 1: pshufd $0x4E,<xmm11=int6464#12,>xmm11=int6464#12
# asm 2: pshufd $0x4E,<xmm11=%xmm11,>xmm11=%xmm11
pshufd $0x4E,%xmm11,%xmm11

# qhasm:     xmm15 = shuffle dwords of xmm15 by 0x4E
# asm 1: pshufd $0x4E,<xmm15=int6464#16,>xmm15=int6464#16
# asm 2: pshufd $0x4E,<xmm15=%xmm15,>xmm15=%xmm15
pshufd $0x4E,%xmm15,%xmm15

# qhasm:     xmm10 = shuffle dwords of xmm10 by 0x4E
# asm 1: pshufd $0x4E,<xmm10=int6464#11,>xmm10=int6464#11
# asm 2: pshufd $0x4E,<xmm10=%xmm10,>xmm10=%xmm10
pshufd $0x4E,%xmm10,%xmm10

# qhasm:     xmm13 = shuffle dwords of xmm13 by 0x4E
# asm 1: pshufd $0x4E,<xmm13=int6464#14,>xmm13=int6464#14
# asm 2: pshufd $0x4E,<xmm13=%xmm13,>xmm13=%xmm13
pshufd $0x4E,%xmm13,%xmm13

# qhasm:     xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:     xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:     xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm12,<xmm2=%xmm2
pxor  %xmm12,%xmm2

# qhasm:     xmm3 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm3=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm3=%xmm3
pxor  %xmm14,%xmm3

# qhasm:     xmm4 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm4=int6464#5
# asm 2: pxor  <xmm11=%xmm11,<xmm4=%xmm4
pxor  %xmm11,%xmm4

# qhasm:     xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:     xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:     xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:     xmm0 ^= *(int128 *)(c + 256)
# asm 1: pxor 256(<c=int64#4),<xmm0=int6464#1
# asm 2: pxor 256(<c=%rcx),<xmm0=%xmm0
pxor 256(%rcx),%xmm0

# qhasm:     shuffle bytes of xmm0 by SR
# asm 1: pshufb SR,<xmm0=int6464#1
# asm 2: pshufb SR,<xmm0=%xmm0
pshufb SR,%xmm0

# qhasm:     xmm1 ^= *(int128 *)(c + 272)
# asm 1: pxor 272(<c=int64#4),<xmm1=int6464#2
# asm 2: pxor 272(<c=%rcx),<xmm1=%xmm1
pxor 272(%rcx),%xmm1

# qhasm:     shuffle bytes of xmm1 by SR
# asm 1: pshufb SR,<xmm1=int6464#2
# asm 2: pshufb SR,<xmm1=%xmm1
pshufb SR,%xmm1

# qhasm:     xmm2 ^= *(int128 *)(c + 288)
# asm 1: pxor 288(<c=int64#4),<xmm2=int6464#3
# asm 2: pxor 288(<c=%rcx),<xmm2=%xmm2
pxor 288(%rcx),%xmm2

# qhasm:     shuffle bytes of xmm2 by SR
# asm 1: pshufb SR,<xmm2=int6464#3
# asm 2: pshufb SR,<xmm2=%xmm2
pshufb SR,%xmm2

# qhasm:     xmm3 ^= *(int128 *)(c + 304)
# asm 1: pxor 304(<c=int64#4),<xmm3=int6464#4
# asm 2: pxor 304(<c=%rcx),<xmm3=%xmm3
pxor 304(%rcx),%xmm3

# qhasm:     shuffle bytes of xmm3 by SR
# asm 1: pshufb SR,<xmm3=int6464#4
# asm 2: pshufb SR,<xmm3=%xmm3
pshufb SR,%xmm3

# qhasm:     xmm4 ^= *(int128 *)(c + 320)
# asm 1: pxor 320(<c=int64#4),<xmm4=int6464#5
# asm 2: pxor 320(<c=%rcx),<xmm4=%xmm4
pxor 320(%rcx),%xmm4

# qhasm:     shuffle bytes of xmm4 by SR
# asm 1: pshufb SR,<xmm4=int6464#5
# asm 2: pshufb SR,<xmm4=%xmm4
pshufb SR,%xmm4

# qhasm:     xmm5 ^= *(int128 *)(c + 336)
# asm 1: pxor 336(<c=int64#4),<xmm5=int6464#6
# asm 2: pxor 336(<c=%rcx),<xmm5=%xmm5
pxor 336(%rcx),%xmm5

# qhasm:     shuffle bytes of xmm5 by SR
# asm 1: pshufb SR,<xmm5=int6464#6
# asm 2: pshufb SR,<xmm5=%xmm5
pshufb SR,%xmm5

# qhasm:     xmm6 ^= *(int128 *)(c + 352)
# asm 1: pxor 352(<c=int64#4),<xmm6=int6464#7
# asm 2: pxor 352(<c=%rcx),<xmm6=%xmm6
pxor 352(%rcx),%xmm6

# qhasm:     shuffle bytes of xmm6 by SR
# asm 1: pshufb SR,<xmm6=int6464#7
# asm 2: pshufb SR,<xmm6=%xmm6
pshufb SR,%xmm6

# qhasm:     xmm7 ^= *(int128 *)(c + 368)
# asm 1: pxor 368(<c=int64#4),<xmm7=int6464#8
# asm 2: pxor 368(<c=%rcx),<xmm7=%xmm7
pxor 368(%rcx),%xmm7

# qhasm:     shuffle bytes of xmm7 by SR
# asm 1: pshufb SR,<xmm7=int6464#8
# asm 2: pshufb SR,<xmm7=%xmm7
pshufb SR,%xmm7

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

# qhasm:     xmm8 = shuffle dwords of xmm0 by 0x93
# asm 1: pshufd $0x93,<xmm0=int6464#1,>xmm8=int6464#9
# asm 2: pshufd $0x93,<xmm0=%xmm0,>xmm8=%xmm8
pshufd $0x93,%xmm0,%xmm8

# qhasm:     xmm9 = shuffle dwords of xmm1 by 0x93
# asm 1: pshufd $0x93,<xmm1=int6464#2,>xmm9=int6464#10
# asm 2: pshufd $0x93,<xmm1=%xmm1,>xmm9=%xmm9
pshufd $0x93,%xmm1,%xmm9

# qhasm:     xmm10 = shuffle dwords of xmm4 by 0x93
# asm 1: pshufd $0x93,<xmm4=int6464#5,>xmm10=int6464#11
# asm 2: pshufd $0x93,<xmm4=%xmm4,>xmm10=%xmm10
pshufd $0x93,%xmm4,%xmm10

# qhasm:     xmm11 = shuffle dwords of xmm6 by 0x93
# asm 1: pshufd $0x93,<xmm6=int6464#7,>xmm11=int6464#12
# asm 2: pshufd $0x93,<xmm6=%xmm6,>xmm11=%xmm11
pshufd $0x93,%xmm6,%xmm11

# qhasm:     xmm12 = shuffle dwords of xmm3 by 0x93
# asm 1: pshufd $0x93,<xmm3=int6464#4,>xmm12=int6464#13
# asm 2: pshufd $0x93,<xmm3=%xmm3,>xmm12=%xmm12
pshufd $0x93,%xmm3,%xmm12

# qhasm:     xmm13 = shuffle dwords of xmm7 by 0x93
# asm 1: pshufd $0x93,<xmm7=int6464#8,>xmm13=int6464#14
# asm 2: pshufd $0x93,<xmm7=%xmm7,>xmm13=%xmm13
pshufd $0x93,%xmm7,%xmm13

# qhasm:     xmm14 = shuffle dwords of xmm2 by 0x93
# asm 1: pshufd $0x93,<xmm2=int6464#3,>xmm14=int6464#15
# asm 2: pshufd $0x93,<xmm2=%xmm2,>xmm14=%xmm14
pshufd $0x93,%xmm2,%xmm14

# qhasm:     xmm15 = shuffle dwords of xmm5 by 0x93
# asm 1: pshufd $0x93,<xmm5=int6464#6,>xmm15=int6464#16
# asm 2: pshufd $0x93,<xmm5=%xmm5,>xmm15=%xmm15
pshufd $0x93,%xmm5,%xmm15

# qhasm:     xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:     xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:     xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:     xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:     xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:     xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:     xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:     xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:     xmm8 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm8=int6464#9
# asm 2: pxor  <xmm5=%xmm5,<xmm8=%xmm8
pxor  %xmm5,%xmm8

# qhasm:     xmm9 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm9=int6464#10
# asm 2: pxor  <xmm0=%xmm0,<xmm9=%xmm9
pxor  %xmm0,%xmm9

# qhasm:     xmm10 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm10=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm10=%xmm10
pxor  %xmm1,%xmm10

# qhasm:     xmm9 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm9=int6464#10
# asm 2: pxor  <xmm5=%xmm5,<xmm9=%xmm9
pxor  %xmm5,%xmm9

# qhasm:     xmm11 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm11=int6464#12
# asm 2: pxor  <xmm4=%xmm4,<xmm11=%xmm11
pxor  %xmm4,%xmm11

# qhasm:     xmm12 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm12=int6464#13
# asm 2: pxor  <xmm6=%xmm6,<xmm12=%xmm12
pxor  %xmm6,%xmm12

# qhasm:     xmm13 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm13=int6464#14
# asm 2: pxor  <xmm3=%xmm3,<xmm13=%xmm13
pxor  %xmm3,%xmm13

# qhasm:     xmm11 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm11=int6464#12
# asm 2: pxor  <xmm5=%xmm5,<xmm11=%xmm11
pxor  %xmm5,%xmm11

# qhasm:     xmm14 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm14=int6464#15
# asm 2: pxor  <xmm7=%xmm7,<xmm14=%xmm14
pxor  %xmm7,%xmm14

# qhasm:     xmm15 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm15=int6464#16
# asm 2: pxor  <xmm2=%xmm2,<xmm15=%xmm15
pxor  %xmm2,%xmm15

# qhasm:     xmm12 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm12=int6464#13
# asm 2: pxor  <xmm5=%xmm5,<xmm12=%xmm12
pxor  %xmm5,%xmm12

# qhasm:     xmm0 = shuffle dwords of xmm0 by 0x4E
# asm 1: pshufd $0x4E,<xmm0=int6464#1,>xmm0=int6464#1
# asm 2: pshufd $0x4E,<xmm0=%xmm0,>xmm0=%xmm0
pshufd $0x4E,%xmm0,%xmm0

# qhasm:     xmm1 = shuffle dwords of xmm1 by 0x4E
# asm 1: pshufd $0x4E,<xmm1=int6464#2,>xmm1=int6464#2
# asm 2: pshufd $0x4E,<xmm1=%xmm1,>xmm1=%xmm1
pshufd $0x4E,%xmm1,%xmm1

# qhasm:     xmm4 = shuffle dwords of xmm4 by 0x4E
# asm 1: pshufd $0x4E,<xmm4=int6464#5,>xmm4=int6464#5
# asm 2: pshufd $0x4E,<xmm4=%xmm4,>xmm4=%xmm4
pshufd $0x4E,%xmm4,%xmm4

# qhasm:     xmm6 = shuffle dwords of xmm6 by 0x4E
# asm 1: pshufd $0x4E,<xmm6=int6464#7,>xmm6=int6464#7
# asm 2: pshufd $0x4E,<xmm6=%xmm6,>xmm6=%xmm6
pshufd $0x4E,%xmm6,%xmm6

# qhasm:     xmm3 = shuffle dwords of xmm3 by 0x4E
# asm 1: pshufd $0x4E,<xmm3=int6464#4,>xmm3=int6464#4
# asm 2: pshufd $0x4E,<xmm3=%xmm3,>xmm3=%xmm3
pshufd $0x4E,%xmm3,%xmm3

# qhasm:     xmm7 = shuffle dwords of xmm7 by 0x4E
# asm 1: pshufd $0x4E,<xmm7=int6464#8,>xmm7=int6464#8
# asm 2: pshufd $0x4E,<xmm7=%xmm7,>xmm7=%xmm7
pshufd $0x4E,%xmm7,%xmm7

# qhasm:     xmm2 = shuffle dwords of xmm2 by 0x4E
# asm 1: pshufd $0x4E,<xmm2=int6464#3,>xmm2=int6464#3
# asm 2: pshufd $0x4E,<xmm2=%xmm2,>xmm2=%xmm2
pshufd $0x4E,%xmm2,%xmm2

# qhasm:     xmm5 = shuffle dwords of xmm5 by 0x4E
# asm 1: pshufd $0x4E,<xmm5=int6464#6,>xmm5=int6464#6
# asm 2: pshufd $0x4E,<xmm5=%xmm5,>xmm5=%xmm5
pshufd $0x4E,%xmm5,%xmm5

# qhasm:     xmm8 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:     xmm9 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm9=int6464#10
# asm 2: pxor  <xmm1=%xmm1,<xmm9=%xmm9
pxor  %xmm1,%xmm9

# qhasm:     xmm10 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm10=int6464#11
# asm 2: pxor  <xmm4=%xmm4,<xmm10=%xmm10
pxor  %xmm4,%xmm10

# qhasm:     xmm11 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm11=int6464#12
# asm 2: pxor  <xmm6=%xmm6,<xmm11=%xmm11
pxor  %xmm6,%xmm11

# qhasm:     xmm12 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm12=int6464#13
# asm 2: pxor  <xmm3=%xmm3,<xmm12=%xmm12
pxor  %xmm3,%xmm12

# qhasm:     xmm13 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm13=int6464#14
# asm 2: pxor  <xmm7=%xmm7,<xmm13=%xmm13
pxor  %xmm7,%xmm13

# qhasm:     xmm14 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm14=int6464#15
# asm 2: pxor  <xmm2=%xmm2,<xmm14=%xmm14
pxor  %xmm2,%xmm14

# qhasm:     xmm15 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm15=int6464#16
# asm 2: pxor  <xmm5=%xmm5,<xmm15=%xmm15
pxor  %xmm5,%xmm15

# qhasm:     xmm8 ^= *(int128 *)(c + 384)
# asm 1: pxor 384(<c=int64#4),<xmm8=int6464#9
# asm 2: pxor 384(<c=%rcx),<xmm8=%xmm8
pxor 384(%rcx),%xmm8

# qhasm:     shuffle bytes of xmm8 by SR
# asm 1: pshufb SR,<xmm8=int6464#9
# asm 2: pshufb SR,<xmm8=%xmm8
pshufb SR,%xmm8

# qhasm:     xmm9 ^= *(int128 *)(c + 400)
# asm 1: pxor 400(<c=int64#4),<xmm9=int6464#10
# asm 2: pxor 400(<c=%rcx),<xmm9=%xmm9
pxor 400(%rcx),%xmm9

# qhasm:     shuffle bytes of xmm9 by SR
# asm 1: pshufb SR,<xmm9=int6464#10
# asm 2: pshufb SR,<xmm9=%xmm9
pshufb SR,%xmm9

# qhasm:     xmm10 ^= *(int128 *)(c + 416)
# asm 1: pxor 416(<c=int64#4),<xmm10=int6464#11
# asm 2: pxor 416(<c=%rcx),<xmm10=%xmm10
pxor 416(%rcx),%xmm10

# qhasm:     shuffle bytes of xmm10 by SR
# asm 1: pshufb SR,<xmm10=int6464#11
# asm 2: pshufb SR,<xmm10=%xmm10
pshufb SR,%xmm10

# qhasm:     xmm11 ^= *(int128 *)(c + 432)
# asm 1: pxor 432(<c=int64#4),<xmm11=int6464#12
# asm 2: pxor 432(<c=%rcx),<xmm11=%xmm11
pxor 432(%rcx),%xmm11

# qhasm:     shuffle bytes of xmm11 by SR
# asm 1: pshufb SR,<xmm11=int6464#12
# asm 2: pshufb SR,<xmm11=%xmm11
pshufb SR,%xmm11

# qhasm:     xmm12 ^= *(int128 *)(c + 448)
# asm 1: pxor 448(<c=int64#4),<xmm12=int6464#13
# asm 2: pxor 448(<c=%rcx),<xmm12=%xmm12
pxor 448(%rcx),%xmm12

# qhasm:     shuffle bytes of xmm12 by SR
# asm 1: pshufb SR,<xmm12=int6464#13
# asm 2: pshufb SR,<xmm12=%xmm12
pshufb SR,%xmm12

# qhasm:     xmm13 ^= *(int128 *)(c + 464)
# asm 1: pxor 464(<c=int64#4),<xmm13=int6464#14
# asm 2: pxor 464(<c=%rcx),<xmm13=%xmm13
pxor 464(%rcx),%xmm13

# qhasm:     shuffle bytes of xmm13 by SR
# asm 1: pshufb SR,<xmm13=int6464#14
# asm 2: pshufb SR,<xmm13=%xmm13
pshufb SR,%xmm13

# qhasm:     xmm14 ^= *(int128 *)(c + 480)
# asm 1: pxor 480(<c=int64#4),<xmm14=int6464#15
# asm 2: pxor 480(<c=%rcx),<xmm14=%xmm14
pxor 480(%rcx),%xmm14

# qhasm:     shuffle bytes of xmm14 by SR
# asm 1: pshufb SR,<xmm14=int6464#15
# asm 2: pshufb SR,<xmm14=%xmm14
pshufb SR,%xmm14

# qhasm:     xmm15 ^= *(int128 *)(c + 496)
# asm 1: pxor 496(<c=int64#4),<xmm15=int6464#16
# asm 2: pxor 496(<c=%rcx),<xmm15=%xmm15
pxor 496(%rcx),%xmm15

# qhasm:     shuffle bytes of xmm15 by SR
# asm 1: pshufb SR,<xmm15=int6464#16
# asm 2: pshufb SR,<xmm15=%xmm15
pshufb SR,%xmm15

# qhasm:       xmm13 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm13=int6464#14
# asm 2: pxor  <xmm14=%xmm14,<xmm13=%xmm13
pxor  %xmm14,%xmm13

# qhasm:       xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm9,<xmm10=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm13=int6464#14
# asm 2: pxor  <xmm8=%xmm8,<xmm13=%xmm13
pxor  %xmm8,%xmm13

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm14=int6464#15
# asm 2: pxor  <xmm10=%xmm10,<xmm14=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm11=int6464#12
# asm 2: pxor  <xmm8=%xmm8,<xmm11=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm14=int6464#15
# asm 2: pxor  <xmm11=%xmm11,<xmm14=%xmm14
pxor  %xmm11,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#12
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm11
pxor  %xmm15,%xmm11

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm11=int6464#12
# asm 2: pxor  <xmm12=%xmm12,<xmm11=%xmm11
pxor  %xmm12,%xmm11

# qhasm:       xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm15=int6464#16
# asm 2: pxor  <xmm13=%xmm13,<xmm15=%xmm15
pxor  %xmm13,%xmm15

# qhasm:       xmm11 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm11=int6464#12
# asm 2: pxor  <xmm9=%xmm9,<xmm11=%xmm11
pxor  %xmm9,%xmm11

# qhasm:       xmm12 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm12=int6464#13
# asm 2: pxor  <xmm13=%xmm13,<xmm12=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm10 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm10=int6464#11
# asm 2: pxor  <xmm15=%xmm15,<xmm10=%xmm10
pxor  %xmm15,%xmm10

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm9=int6464#10
# asm 2: pxor  <xmm13=%xmm13,<xmm9=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm3 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm3=int6464#1
# asm 2: movdqa <xmm15=%xmm15,>xmm3=%xmm0
movdqa %xmm15,%xmm0

# qhasm:       xmm2 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm2=int6464#2
# asm 2: movdqa <xmm9=%xmm9,>xmm2=%xmm1
movdqa %xmm9,%xmm1

# qhasm:       xmm1 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm1=int6464#3
# asm 2: movdqa <xmm13=%xmm13,>xmm1=%xmm2
movdqa %xmm13,%xmm2

# qhasm:       xmm5 = xmm10
# asm 1: movdqa <xmm10=int6464#11,>xmm5=int6464#4
# asm 2: movdqa <xmm10=%xmm10,>xmm5=%xmm3
movdqa %xmm10,%xmm3

# qhasm:       xmm4 = xmm14
# asm 1: movdqa <xmm14=int6464#15,>xmm4=int6464#5
# asm 2: movdqa <xmm14=%xmm14,>xmm4=%xmm4
movdqa %xmm14,%xmm4

# qhasm:       xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#1
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm0
pxor  %xmm12,%xmm0

# qhasm:       xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#2
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm1
pxor  %xmm10,%xmm1

# qhasm:       xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm1=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm1=%xmm2
pxor  %xmm11,%xmm2

# qhasm:       xmm5 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm5=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm5=%xmm3
pxor  %xmm12,%xmm3

# qhasm:       xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:       xmm6 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm6=int6464#6
# asm 2: movdqa <xmm3=%xmm0,>xmm6=%xmm5
movdqa %xmm0,%xmm5

# qhasm:       xmm0 = xmm2
# asm 1: movdqa <xmm2=int6464#2,>xmm0=int6464#7
# asm 2: movdqa <xmm2=%xmm1,>xmm0=%xmm6
movdqa %xmm1,%xmm6

# qhasm:       xmm7 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm7=int6464#8
# asm 2: movdqa <xmm3=%xmm0,>xmm7=%xmm7
movdqa %xmm0,%xmm7

# qhasm:       xmm2 |= xmm1
# asm 1: por   <xmm1=int6464#3,<xmm2=int6464#2
# asm 2: por   <xmm1=%xmm2,<xmm2=%xmm1
por   %xmm2,%xmm1

# qhasm:       xmm3 |= xmm4
# asm 1: por   <xmm4=int6464#5,<xmm3=int6464#1
# asm 2: por   <xmm4=%xmm4,<xmm3=%xmm0
por   %xmm4,%xmm0

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm7=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm6 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm6=int6464#6
# asm 2: pand  <xmm4=%xmm4,<xmm6=%xmm5
pand  %xmm4,%xmm5

# qhasm:       xmm0 &= xmm1
# asm 1: pand  <xmm1=int6464#3,<xmm0=int6464#7
# asm 2: pand  <xmm1=%xmm2,<xmm0=%xmm6
pand  %xmm2,%xmm6

# qhasm:       xmm4 ^= xmm1
# asm 1: pxor  <xmm1=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm1=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:       xmm7 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm7=int6464#8
# asm 2: pand  <xmm4=%xmm4,<xmm7=%xmm7
pand  %xmm4,%xmm7

# qhasm:       xmm4 = xmm11
# asm 1: movdqa <xmm11=int6464#12,>xmm4=int6464#3
# asm 2: movdqa <xmm11=%xmm11,>xmm4=%xmm2
movdqa %xmm11,%xmm2

# qhasm:       xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#3
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm2
pxor  %xmm8,%xmm2

# qhasm:       xmm5 &= xmm4
# asm 1: pand  <xmm4=int6464#3,<xmm5=int6464#4
# asm 2: pand  <xmm4=%xmm2,<xmm5=%xmm3
pand  %xmm2,%xmm3

# qhasm:       xmm3 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm3=int6464#1
# asm 2: pxor  <xmm5=%xmm3,<xmm3=%xmm0
pxor  %xmm3,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm2=int6464#2
# asm 2: pxor  <xmm5=%xmm3,<xmm2=%xmm1
pxor  %xmm3,%xmm1

# qhasm:       xmm5 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm5=int6464#3
# asm 2: movdqa <xmm15=%xmm15,>xmm5=%xmm2
movdqa %xmm15,%xmm2

# qhasm:       xmm5 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm5=int6464#3
# asm 2: pxor  <xmm9=%xmm9,<xmm5=%xmm2
pxor  %xmm9,%xmm2

# qhasm:       xmm4 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm4=int6464#4
# asm 2: movdqa <xmm13=%xmm13,>xmm4=%xmm3
movdqa %xmm13,%xmm3

# qhasm:       xmm1 = xmm5
# asm 1: movdqa <xmm5=int6464#3,>xmm1=int6464#5
# asm 2: movdqa <xmm5=%xmm2,>xmm1=%xmm4
movdqa %xmm2,%xmm4

# qhasm:       xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm3
pxor  %xmm14,%xmm3

# qhasm:       xmm1 |= xmm4
# asm 1: por   <xmm4=int6464#4,<xmm1=int6464#5
# asm 2: por   <xmm4=%xmm3,<xmm1=%xmm4
por   %xmm3,%xmm4

# qhasm:       xmm5 &= xmm4
# asm 1: pand  <xmm4=int6464#4,<xmm5=int6464#3
# asm 2: pand  <xmm4=%xmm3,<xmm5=%xmm2
pand  %xmm3,%xmm2

# qhasm:       xmm0 ^= xmm5
# asm 1: pxor  <xmm5=int6464#3,<xmm0=int6464#7
# asm 2: pxor  <xmm5=%xmm2,<xmm0=%xmm6
pxor  %xmm2,%xmm6

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#1
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm0
pxor  %xmm7,%xmm0

# qhasm:       xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm2=int6464#2
# asm 2: pxor  <xmm6=%xmm5,<xmm2=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#5
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm0 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm0=int6464#7
# asm 2: pxor  <xmm6=%xmm5,<xmm0=%xmm6
pxor  %xmm5,%xmm6

# qhasm:       xmm1 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm1=int6464#5
# asm 2: pxor  <xmm6=%xmm5,<xmm1=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm4 = xmm10
# asm 1: movdqa <xmm10=int6464#11,>xmm4=int6464#3
# asm 2: movdqa <xmm10=%xmm10,>xmm4=%xmm2
movdqa %xmm10,%xmm2

# qhasm:       xmm5 = xmm12
# asm 1: movdqa <xmm12=int6464#13,>xmm5=int6464#4
# asm 2: movdqa <xmm12=%xmm12,>xmm5=%xmm3
movdqa %xmm12,%xmm3

# qhasm:       xmm6 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm6=int6464#6
# asm 2: movdqa <xmm9=%xmm9,>xmm6=%xmm5
movdqa %xmm9,%xmm5

# qhasm:       xmm7 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm7=int6464#8
# asm 2: movdqa <xmm15=%xmm15,>xmm7=%xmm7
movdqa %xmm15,%xmm7

# qhasm:       xmm4 &= xmm11
# asm 1: pand  <xmm11=int6464#12,<xmm4=int6464#3
# asm 2: pand  <xmm11=%xmm11,<xmm4=%xmm2
pand  %xmm11,%xmm2

# qhasm:       xmm5 &= xmm8
# asm 1: pand  <xmm8=int6464#9,<xmm5=int6464#4
# asm 2: pand  <xmm8=%xmm8,<xmm5=%xmm3
pand  %xmm8,%xmm3

# qhasm:       xmm6 &= xmm13
# asm 1: pand  <xmm13=int6464#14,<xmm6=int6464#6
# asm 2: pand  <xmm13=%xmm13,<xmm6=%xmm5
pand  %xmm13,%xmm5

# qhasm:       xmm7 |= xmm14
# asm 1: por   <xmm14=int6464#15,<xmm7=int6464#8
# asm 2: por   <xmm14=%xmm14,<xmm7=%xmm7
por   %xmm14,%xmm7

# qhasm:       xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#3,<xmm3=int6464#1
# asm 2: pxor  <xmm4=%xmm2,<xmm3=%xmm0
pxor  %xmm2,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm2=int6464#2
# asm 2: pxor  <xmm5=%xmm3,<xmm2=%xmm1
pxor  %xmm3,%xmm1

# qhasm:       xmm1 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm1=int6464#5
# asm 2: pxor  <xmm6=%xmm5,<xmm1=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm0 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm0=int6464#7
# asm 2: pxor  <xmm7=%xmm7,<xmm0=%xmm6
pxor  %xmm7,%xmm6

# qhasm:       xmm4 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm4=int6464#3
# asm 2: movdqa <xmm3=%xmm0,>xmm4=%xmm2
movdqa %xmm0,%xmm2

# qhasm:       xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm4=int6464#3
# asm 2: pxor  <xmm2=%xmm1,<xmm4=%xmm2
pxor  %xmm1,%xmm2

# qhasm:       xmm3 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm3=int6464#1
# asm 2: pand  <xmm1=%xmm4,<xmm3=%xmm0
pand  %xmm4,%xmm0

# qhasm:       xmm6 = xmm0
# asm 1: movdqa <xmm0=int6464#7,>xmm6=int6464#4
# asm 2: movdqa <xmm0=%xmm6,>xmm6=%xmm3
movdqa %xmm6,%xmm3

# qhasm:       xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#1,<xmm6=int6464#4
# asm 2: pxor  <xmm3=%xmm0,<xmm6=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm7 = xmm4
# asm 1: movdqa <xmm4=int6464#3,>xmm7=int6464#6
# asm 2: movdqa <xmm4=%xmm2,>xmm7=%xmm5
movdqa %xmm2,%xmm5

# qhasm:       xmm7 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm7=int6464#6
# asm 2: pand  <xmm6=%xmm3,<xmm7=%xmm5
pand  %xmm3,%xmm5

# qhasm:       xmm7 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm7=int6464#6
# asm 2: pxor  <xmm2=%xmm1,<xmm7=%xmm5
pxor  %xmm1,%xmm5

# qhasm:       xmm5 = xmm1
# asm 1: movdqa <xmm1=int6464#5,>xmm5=int6464#8
# asm 2: movdqa <xmm1=%xmm4,>xmm5=%xmm7
movdqa %xmm4,%xmm7

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm5=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm5=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm3 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm3=int6464#1
# asm 2: pxor  <xmm2=%xmm1,<xmm3=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm5 &= xmm3
# asm 1: pand  <xmm3=int6464#1,<xmm5=int6464#8
# asm 2: pand  <xmm3=%xmm0,<xmm5=%xmm7
pand  %xmm0,%xmm7

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm5=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm5=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm1=int6464#5
# asm 2: pxor  <xmm5=%xmm7,<xmm1=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm2 = xmm6
# asm 1: movdqa <xmm6=int6464#4,>xmm2=int6464#1
# asm 2: movdqa <xmm6=%xmm3,>xmm2=%xmm0
movdqa %xmm3,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm2=int6464#1
# asm 2: pxor  <xmm5=%xmm7,<xmm2=%xmm0
pxor  %xmm7,%xmm0

# qhasm:       xmm2 &= xmm0
# asm 1: pand  <xmm0=int6464#7,<xmm2=int6464#1
# asm 2: pand  <xmm0=%xmm6,<xmm2=%xmm0
pand  %xmm6,%xmm0

# qhasm:       xmm1 ^= xmm2
# asm 1: pxor  <xmm2=int6464#1,<xmm1=int6464#5
# asm 2: pxor  <xmm2=%xmm0,<xmm1=%xmm4
pxor  %xmm0,%xmm4

# qhasm:       xmm6 ^= xmm2
# asm 1: pxor  <xmm2=int6464#1,<xmm6=int6464#4
# asm 2: pxor  <xmm2=%xmm0,<xmm6=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm6 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm6=int6464#4
# asm 2: pand  <xmm7=%xmm5,<xmm6=%xmm3
pand  %xmm5,%xmm3

# qhasm:       xmm6 ^= xmm4
# asm 1: pxor  <xmm4=int6464#3,<xmm6=int6464#4
# asm 2: pxor  <xmm4=%xmm2,<xmm6=%xmm3
pxor  %xmm2,%xmm3

# qhasm:         xmm4 = xmm14
# asm 1: movdqa <xmm14=int6464#15,>xmm4=int6464#1
# asm 2: movdqa <xmm14=%xmm14,>xmm4=%xmm0
movdqa %xmm14,%xmm0

# qhasm:         xmm0 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm0=int6464#2
# asm 2: movdqa <xmm13=%xmm13,>xmm0=%xmm1
movdqa %xmm13,%xmm1

# qhasm:           xmm2 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm2=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm2=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm2=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm2 &= xmm14
# asm 1: pand  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pand  <xmm14=%xmm14,<xmm2=%xmm2
pand  %xmm14,%xmm2

# qhasm:           xmm14 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm14=int6464#15
# asm 2: pxor  <xmm13=%xmm13,<xmm14=%xmm14
pxor  %xmm13,%xmm14

# qhasm:           xmm14 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm14=int6464#15
# asm 2: pand  <xmm6=%xmm3,<xmm14=%xmm14
pand  %xmm3,%xmm14

# qhasm:           xmm13 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm13=int6464#14
# asm 2: pand  <xmm7=%xmm5,<xmm13=%xmm13
pand  %xmm5,%xmm13

# qhasm:           xmm14 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm14=int6464#15
# asm 2: pxor  <xmm13=%xmm13,<xmm14=%xmm14
pxor  %xmm13,%xmm14

# qhasm:           xmm13 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm13=int6464#14
# asm 2: pxor  <xmm2=%xmm2,<xmm13=%xmm13
pxor  %xmm2,%xmm13

# qhasm:         xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm0 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm0=int6464#2
# asm 2: pxor  <xmm11=%xmm11,<xmm0=%xmm1
pxor  %xmm11,%xmm1

# qhasm:         xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm7=int6464#6
# asm 2: pxor  <xmm5=%xmm7,<xmm7=%xmm5
pxor  %xmm7,%xmm5

# qhasm:         xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm6=int6464#4
# asm 2: pxor  <xmm1=%xmm4,<xmm6=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm4
# asm 1: pand  <xmm4=int6464#1,<xmm3=int6464#3
# asm 2: pand  <xmm4=%xmm0,<xmm3=%xmm2
pand  %xmm0,%xmm2

# qhasm:           xmm4 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm4=int6464#1
# asm 2: pxor  <xmm0=%xmm1,<xmm4=%xmm0
pxor  %xmm1,%xmm0

# qhasm:           xmm4 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm4=int6464#1
# asm 2: pand  <xmm6=%xmm3,<xmm4=%xmm0
pand  %xmm3,%xmm0

# qhasm:           xmm0 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm0=int6464#2
# asm 2: pand  <xmm7=%xmm5,<xmm0=%xmm1
pand  %xmm5,%xmm1

# qhasm:           xmm0 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm0=int6464#2
# asm 2: pxor  <xmm4=%xmm0,<xmm0=%xmm1
pxor  %xmm0,%xmm1

# qhasm:           xmm4 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm4=int6464#1
# asm 2: pxor  <xmm3=%xmm2,<xmm4=%xmm0
pxor  %xmm2,%xmm0

# qhasm:           xmm2 = xmm5
# asm 1: movdqa <xmm5=int6464#8,>xmm2=int6464#3
# asm 2: movdqa <xmm5=%xmm7,>xmm2=%xmm2
movdqa %xmm7,%xmm2

# qhasm:           xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm4,<xmm2=%xmm2
pxor  %xmm4,%xmm2

# qhasm:           xmm2 &= xmm8
# asm 1: pand  <xmm8=int6464#9,<xmm2=int6464#3
# asm 2: pand  <xmm8=%xmm8,<xmm2=%xmm2
pand  %xmm8,%xmm2

# qhasm:           xmm8 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm8=int6464#9
# asm 2: pxor  <xmm11=%xmm11,<xmm8=%xmm8
pxor  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm8=int6464#9
# asm 2: pand  <xmm1=%xmm4,<xmm8=%xmm8
pand  %xmm4,%xmm8

# qhasm:           xmm11 &= xmm5
# asm 1: pand  <xmm5=int6464#8,<xmm11=int6464#12
# asm 2: pand  <xmm5=%xmm7,<xmm11=%xmm11
pand  %xmm7,%xmm11

# qhasm:           xmm8 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm8=int6464#9
# asm 2: pxor  <xmm11=%xmm11,<xmm8=%xmm8
pxor  %xmm11,%xmm8

# qhasm:           xmm11 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm11=int6464#12
# asm 2: pxor  <xmm2=%xmm2,<xmm11=%xmm11
pxor  %xmm2,%xmm11

# qhasm:         xmm14 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm14=int6464#15
# asm 2: pxor  <xmm4=%xmm0,<xmm14=%xmm14
pxor  %xmm0,%xmm14

# qhasm:         xmm8 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm4=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm13 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm13=int6464#14
# asm 2: pxor  <xmm0=%xmm1,<xmm13=%xmm13
pxor  %xmm1,%xmm13

# qhasm:         xmm11 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm11=int6464#12
# asm 2: pxor  <xmm0=%xmm1,<xmm11=%xmm11
pxor  %xmm1,%xmm11

# qhasm:         xmm4 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm4=int6464#1
# asm 2: movdqa <xmm15=%xmm15,>xmm4=%xmm0
movdqa %xmm15,%xmm0

# qhasm:         xmm0 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm0=int6464#2
# asm 2: movdqa <xmm9=%xmm9,>xmm0=%xmm1
movdqa %xmm9,%xmm1

# qhasm:         xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm4=int6464#1
# asm 2: pxor  <xmm12=%xmm12,<xmm4=%xmm0
pxor  %xmm12,%xmm0

# qhasm:         xmm0 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm0=int6464#2
# asm 2: pxor  <xmm10=%xmm10,<xmm0=%xmm1
pxor  %xmm10,%xmm1

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm4
# asm 1: pand  <xmm4=int6464#1,<xmm3=int6464#3
# asm 2: pand  <xmm4=%xmm0,<xmm3=%xmm2
pand  %xmm0,%xmm2

# qhasm:           xmm4 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm4=int6464#1
# asm 2: pxor  <xmm0=%xmm1,<xmm4=%xmm0
pxor  %xmm1,%xmm0

# qhasm:           xmm4 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm4=int6464#1
# asm 2: pand  <xmm6=%xmm3,<xmm4=%xmm0
pand  %xmm3,%xmm0

# qhasm:           xmm0 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm0=int6464#2
# asm 2: pand  <xmm7=%xmm5,<xmm0=%xmm1
pand  %xmm5,%xmm1

# qhasm:           xmm0 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm0=int6464#2
# asm 2: pxor  <xmm4=%xmm0,<xmm0=%xmm1
pxor  %xmm0,%xmm1

# qhasm:           xmm4 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm4=int6464#1
# asm 2: pxor  <xmm3=%xmm2,<xmm4=%xmm0
pxor  %xmm2,%xmm0

# qhasm:           xmm2 = xmm5
# asm 1: movdqa <xmm5=int6464#8,>xmm2=int6464#3
# asm 2: movdqa <xmm5=%xmm7,>xmm2=%xmm2
movdqa %xmm7,%xmm2

# qhasm:           xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm4,<xmm2=%xmm2
pxor  %xmm4,%xmm2

# qhasm:           xmm2 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pand  <xmm12=%xmm12,<xmm2=%xmm2
pand  %xmm12,%xmm2

# qhasm:           xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm10=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:           xmm12 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm12=int6464#13
# asm 2: pand  <xmm1=%xmm4,<xmm12=%xmm12
pand  %xmm4,%xmm12

# qhasm:           xmm10 &= xmm5
# asm 1: pand  <xmm5=int6464#8,<xmm10=int6464#11
# asm 2: pand  <xmm5=%xmm7,<xmm10=%xmm10
pand  %xmm7,%xmm10

# qhasm:           xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm10=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:           xmm10 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm10=int6464#11
# asm 2: pxor  <xmm2=%xmm2,<xmm10=%xmm10
pxor  %xmm2,%xmm10

# qhasm:         xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm7=int6464#6
# asm 2: pxor  <xmm5=%xmm7,<xmm7=%xmm5
pxor  %xmm7,%xmm5

# qhasm:         xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm6=int6464#4
# asm 2: pxor  <xmm1=%xmm4,<xmm6=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm15
# asm 1: pand  <xmm15=int6464#16,<xmm3=int6464#3
# asm 2: pand  <xmm15=%xmm15,<xmm3=%xmm2
pand  %xmm15,%xmm2

# qhasm:           xmm15 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm15=int6464#16
# asm 2: pxor  <xmm9=%xmm9,<xmm15=%xmm15
pxor  %xmm9,%xmm15

# qhasm:           xmm15 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm15=int6464#16
# asm 2: pand  <xmm6=%xmm3,<xmm15=%xmm15
pand  %xmm3,%xmm15

# qhasm:           xmm9 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm9=int6464#10
# asm 2: pand  <xmm7=%xmm5,<xmm9=%xmm9
pand  %xmm5,%xmm9

# qhasm:           xmm15 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm15=int6464#16
# asm 2: pxor  <xmm9=%xmm9,<xmm15=%xmm15
pxor  %xmm9,%xmm15

# qhasm:           xmm9 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm9=int6464#10
# asm 2: pxor  <xmm3=%xmm2,<xmm9=%xmm9
pxor  %xmm2,%xmm9

# qhasm:         xmm15 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm15=int6464#16
# asm 2: pxor  <xmm4=%xmm0,<xmm15=%xmm15
pxor  %xmm0,%xmm15

# qhasm:         xmm12 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm4=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:         xmm9 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm9=int6464#10
# asm 2: pxor  <xmm0=%xmm1,<xmm9=%xmm9
pxor  %xmm1,%xmm9

# qhasm:         xmm10 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm10=int6464#11
# asm 2: pxor  <xmm0=%xmm1,<xmm10=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm8,<xmm15=%xmm15
pxor  %xmm8,%xmm15

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm9=int6464#10
# asm 2: pxor  <xmm14=%xmm14,<xmm9=%xmm9
pxor  %xmm14,%xmm9

# qhasm:       xmm12 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm12=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm12=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm14 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm14=int6464#15
# asm 2: pxor  <xmm8=%xmm8,<xmm14=%xmm14
pxor  %xmm8,%xmm14

# qhasm:       xmm8 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm8=int6464#9
# asm 2: pxor  <xmm9=%xmm9,<xmm8=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm9=int6464#10
# asm 2: pxor  <xmm13=%xmm13,<xmm9=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm13 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm13=int6464#14
# asm 2: pxor  <xmm10=%xmm10,<xmm13=%xmm13
pxor  %xmm10,%xmm13

# qhasm:       xmm12 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm12=int6464#13
# asm 2: pxor  <xmm13=%xmm13,<xmm12=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm10 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm11=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm11=int6464#12
# asm 2: pxor  <xmm13=%xmm13,<xmm11=%xmm11
pxor  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm14=int6464#15
# asm 2: pxor  <xmm11=%xmm11,<xmm14=%xmm14
pxor  %xmm11,%xmm14

# qhasm:     xmm0 = shuffle dwords of xmm8 by 0x93
# asm 1: pshufd $0x93,<xmm8=int6464#9,>xmm0=int6464#1
# asm 2: pshufd $0x93,<xmm8=%xmm8,>xmm0=%xmm0
pshufd $0x93,%xmm8,%xmm0

# qhasm:     xmm1 = shuffle dwords of xmm9 by 0x93
# asm 1: pshufd $0x93,<xmm9=int6464#10,>xmm1=int6464#2
# asm 2: pshufd $0x93,<xmm9=%xmm9,>xmm1=%xmm1
pshufd $0x93,%xmm9,%xmm1

# qhasm:     xmm2 = shuffle dwords of xmm12 by 0x93
# asm 1: pshufd $0x93,<xmm12=int6464#13,>xmm2=int6464#3
# asm 2: pshufd $0x93,<xmm12=%xmm12,>xmm2=%xmm2
pshufd $0x93,%xmm12,%xmm2

# qhasm:     xmm3 = shuffle dwords of xmm14 by 0x93
# asm 1: pshufd $0x93,<xmm14=int6464#15,>xmm3=int6464#4
# asm 2: pshufd $0x93,<xmm14=%xmm14,>xmm3=%xmm3
pshufd $0x93,%xmm14,%xmm3

# qhasm:     xmm4 = shuffle dwords of xmm11 by 0x93
# asm 1: pshufd $0x93,<xmm11=int6464#12,>xmm4=int6464#5
# asm 2: pshufd $0x93,<xmm11=%xmm11,>xmm4=%xmm4
pshufd $0x93,%xmm11,%xmm4

# qhasm:     xmm5 = shuffle dwords of xmm15 by 0x93
# asm 1: pshufd $0x93,<xmm15=int6464#16,>xmm5=int6464#6
# asm 2: pshufd $0x93,<xmm15=%xmm15,>xmm5=%xmm5
pshufd $0x93,%xmm15,%xmm5

# qhasm:     xmm6 = shuffle dwords of xmm10 by 0x93
# asm 1: pshufd $0x93,<xmm10=int6464#11,>xmm6=int6464#7
# asm 2: pshufd $0x93,<xmm10=%xmm10,>xmm6=%xmm6
pshufd $0x93,%xmm10,%xmm6

# qhasm:     xmm7 = shuffle dwords of xmm13 by 0x93
# asm 1: pshufd $0x93,<xmm13=int6464#14,>xmm7=int6464#8
# asm 2: pshufd $0x93,<xmm13=%xmm13,>xmm7=%xmm7
pshufd $0x93,%xmm13,%xmm7

# qhasm:     xmm8 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:     xmm9 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm9=int6464#10
# asm 2: pxor  <xmm1=%xmm1,<xmm9=%xmm9
pxor  %xmm1,%xmm9

# qhasm:     xmm12 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm12=int6464#13
# asm 2: pxor  <xmm2=%xmm2,<xmm12=%xmm12
pxor  %xmm2,%xmm12

# qhasm:     xmm14 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm14=int6464#15
# asm 2: pxor  <xmm3=%xmm3,<xmm14=%xmm14
pxor  %xmm3,%xmm14

# qhasm:     xmm11 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm11=int6464#12
# asm 2: pxor  <xmm4=%xmm4,<xmm11=%xmm11
pxor  %xmm4,%xmm11

# qhasm:     xmm15 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm15=int6464#16
# asm 2: pxor  <xmm5=%xmm5,<xmm15=%xmm15
pxor  %xmm5,%xmm15

# qhasm:     xmm10 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm10=int6464#11
# asm 2: pxor  <xmm6=%xmm6,<xmm10=%xmm10
pxor  %xmm6,%xmm10

# qhasm:     xmm13 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm13=int6464#14
# asm 2: pxor  <xmm7=%xmm7,<xmm13=%xmm13
pxor  %xmm7,%xmm13

# qhasm:     xmm0 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm0=int6464#1
# asm 2: pxor  <xmm13=%xmm13,<xmm0=%xmm0
pxor  %xmm13,%xmm0

# qhasm:     xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm8,<xmm1=%xmm1
pxor  %xmm8,%xmm1

# qhasm:     xmm2 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm2=int6464#3
# asm 2: pxor  <xmm9=%xmm9,<xmm2=%xmm2
pxor  %xmm9,%xmm2

# qhasm:     xmm1 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm1=int6464#2
# asm 2: pxor  <xmm13=%xmm13,<xmm1=%xmm1
pxor  %xmm13,%xmm1

# qhasm:     xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:     xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:     xmm5 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm5=int6464#6
# asm 2: pxor  <xmm11=%xmm11,<xmm5=%xmm5
pxor  %xmm11,%xmm5

# qhasm:     xmm3 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm3=int6464#4
# asm 2: pxor  <xmm13=%xmm13,<xmm3=%xmm3
pxor  %xmm13,%xmm3

# qhasm:     xmm6 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm6=int6464#7
# asm 2: pxor  <xmm15=%xmm15,<xmm6=%xmm6
pxor  %xmm15,%xmm6

# qhasm:     xmm7 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm7=int6464#8
# asm 2: pxor  <xmm10=%xmm10,<xmm7=%xmm7
pxor  %xmm10,%xmm7

# qhasm:     xmm4 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm4=int6464#5
# asm 2: pxor  <xmm13=%xmm13,<xmm4=%xmm4
pxor  %xmm13,%xmm4

# qhasm:     xmm8 = shuffle dwords of xmm8 by 0x4E
# asm 1: pshufd $0x4E,<xmm8=int6464#9,>xmm8=int6464#9
# asm 2: pshufd $0x4E,<xmm8=%xmm8,>xmm8=%xmm8
pshufd $0x4E,%xmm8,%xmm8

# qhasm:     xmm9 = shuffle dwords of xmm9 by 0x4E
# asm 1: pshufd $0x4E,<xmm9=int6464#10,>xmm9=int6464#10
# asm 2: pshufd $0x4E,<xmm9=%xmm9,>xmm9=%xmm9
pshufd $0x4E,%xmm9,%xmm9

# qhasm:     xmm12 = shuffle dwords of xmm12 by 0x4E
# asm 1: pshufd $0x4E,<xmm12=int6464#13,>xmm12=int6464#13
# asm 2: pshufd $0x4E,<xmm12=%xmm12,>xmm12=%xmm12
pshufd $0x4E,%xmm12,%xmm12

# qhasm:     xmm14 = shuffle dwords of xmm14 by 0x4E
# asm 1: pshufd $0x4E,<xmm14=int6464#15,>xmm14=int6464#15
# asm 2: pshufd $0x4E,<xmm14=%xmm14,>xmm14=%xmm14
pshufd $0x4E,%xmm14,%xmm14

# qhasm:     xmm11 = shuffle dwords of xmm11 by 0x4E
# asm 1: pshufd $0x4E,<xmm11=int6464#12,>xmm11=int6464#12
# asm 2: pshufd $0x4E,<xmm11=%xmm11,>xmm11=%xmm11
pshufd $0x4E,%xmm11,%xmm11

# qhasm:     xmm15 = shuffle dwords of xmm15 by 0x4E
# asm 1: pshufd $0x4E,<xmm15=int6464#16,>xmm15=int6464#16
# asm 2: pshufd $0x4E,<xmm15=%xmm15,>xmm15=%xmm15
pshufd $0x4E,%xmm15,%xmm15

# qhasm:     xmm10 = shuffle dwords of xmm10 by 0x4E
# asm 1: pshufd $0x4E,<xmm10=int6464#11,>xmm10=int6464#11
# asm 2: pshufd $0x4E,<xmm10=%xmm10,>xmm10=%xmm10
pshufd $0x4E,%xmm10,%xmm10

# qhasm:     xmm13 = shuffle dwords of xmm13 by 0x4E
# asm 1: pshufd $0x4E,<xmm13=int6464#14,>xmm13=int6464#14
# asm 2: pshufd $0x4E,<xmm13=%xmm13,>xmm13=%xmm13
pshufd $0x4E,%xmm13,%xmm13

# qhasm:     xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:     xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:     xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm12,<xmm2=%xmm2
pxor  %xmm12,%xmm2

# qhasm:     xmm3 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm3=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm3=%xmm3
pxor  %xmm14,%xmm3

# qhasm:     xmm4 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm4=int6464#5
# asm 2: pxor  <xmm11=%xmm11,<xmm4=%xmm4
pxor  %xmm11,%xmm4

# qhasm:     xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:     xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:     xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:     xmm0 ^= *(int128 *)(c + 512)
# asm 1: pxor 512(<c=int64#4),<xmm0=int6464#1
# asm 2: pxor 512(<c=%rcx),<xmm0=%xmm0
pxor 512(%rcx),%xmm0

# qhasm:     shuffle bytes of xmm0 by SR
# asm 1: pshufb SR,<xmm0=int6464#1
# asm 2: pshufb SR,<xmm0=%xmm0
pshufb SR,%xmm0

# qhasm:     xmm1 ^= *(int128 *)(c + 528)
# asm 1: pxor 528(<c=int64#4),<xmm1=int6464#2
# asm 2: pxor 528(<c=%rcx),<xmm1=%xmm1
pxor 528(%rcx),%xmm1

# qhasm:     shuffle bytes of xmm1 by SR
# asm 1: pshufb SR,<xmm1=int6464#2
# asm 2: pshufb SR,<xmm1=%xmm1
pshufb SR,%xmm1

# qhasm:     xmm2 ^= *(int128 *)(c + 544)
# asm 1: pxor 544(<c=int64#4),<xmm2=int6464#3
# asm 2: pxor 544(<c=%rcx),<xmm2=%xmm2
pxor 544(%rcx),%xmm2

# qhasm:     shuffle bytes of xmm2 by SR
# asm 1: pshufb SR,<xmm2=int6464#3
# asm 2: pshufb SR,<xmm2=%xmm2
pshufb SR,%xmm2

# qhasm:     xmm3 ^= *(int128 *)(c + 560)
# asm 1: pxor 560(<c=int64#4),<xmm3=int6464#4
# asm 2: pxor 560(<c=%rcx),<xmm3=%xmm3
pxor 560(%rcx),%xmm3

# qhasm:     shuffle bytes of xmm3 by SR
# asm 1: pshufb SR,<xmm3=int6464#4
# asm 2: pshufb SR,<xmm3=%xmm3
pshufb SR,%xmm3

# qhasm:     xmm4 ^= *(int128 *)(c + 576)
# asm 1: pxor 576(<c=int64#4),<xmm4=int6464#5
# asm 2: pxor 576(<c=%rcx),<xmm4=%xmm4
pxor 576(%rcx),%xmm4

# qhasm:     shuffle bytes of xmm4 by SR
# asm 1: pshufb SR,<xmm4=int6464#5
# asm 2: pshufb SR,<xmm4=%xmm4
pshufb SR,%xmm4

# qhasm:     xmm5 ^= *(int128 *)(c + 592)
# asm 1: pxor 592(<c=int64#4),<xmm5=int6464#6
# asm 2: pxor 592(<c=%rcx),<xmm5=%xmm5
pxor 592(%rcx),%xmm5

# qhasm:     shuffle bytes of xmm5 by SR
# asm 1: pshufb SR,<xmm5=int6464#6
# asm 2: pshufb SR,<xmm5=%xmm5
pshufb SR,%xmm5

# qhasm:     xmm6 ^= *(int128 *)(c + 608)
# asm 1: pxor 608(<c=int64#4),<xmm6=int6464#7
# asm 2: pxor 608(<c=%rcx),<xmm6=%xmm6
pxor 608(%rcx),%xmm6

# qhasm:     shuffle bytes of xmm6 by SR
# asm 1: pshufb SR,<xmm6=int6464#7
# asm 2: pshufb SR,<xmm6=%xmm6
pshufb SR,%xmm6

# qhasm:     xmm7 ^= *(int128 *)(c + 624)
# asm 1: pxor 624(<c=int64#4),<xmm7=int6464#8
# asm 2: pxor 624(<c=%rcx),<xmm7=%xmm7
pxor 624(%rcx),%xmm7

# qhasm:     shuffle bytes of xmm7 by SR
# asm 1: pshufb SR,<xmm7=int6464#8
# asm 2: pshufb SR,<xmm7=%xmm7
pshufb SR,%xmm7

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

# qhasm:     xmm8 = shuffle dwords of xmm0 by 0x93
# asm 1: pshufd $0x93,<xmm0=int6464#1,>xmm8=int6464#9
# asm 2: pshufd $0x93,<xmm0=%xmm0,>xmm8=%xmm8
pshufd $0x93,%xmm0,%xmm8

# qhasm:     xmm9 = shuffle dwords of xmm1 by 0x93
# asm 1: pshufd $0x93,<xmm1=int6464#2,>xmm9=int6464#10
# asm 2: pshufd $0x93,<xmm1=%xmm1,>xmm9=%xmm9
pshufd $0x93,%xmm1,%xmm9

# qhasm:     xmm10 = shuffle dwords of xmm4 by 0x93
# asm 1: pshufd $0x93,<xmm4=int6464#5,>xmm10=int6464#11
# asm 2: pshufd $0x93,<xmm4=%xmm4,>xmm10=%xmm10
pshufd $0x93,%xmm4,%xmm10

# qhasm:     xmm11 = shuffle dwords of xmm6 by 0x93
# asm 1: pshufd $0x93,<xmm6=int6464#7,>xmm11=int6464#12
# asm 2: pshufd $0x93,<xmm6=%xmm6,>xmm11=%xmm11
pshufd $0x93,%xmm6,%xmm11

# qhasm:     xmm12 = shuffle dwords of xmm3 by 0x93
# asm 1: pshufd $0x93,<xmm3=int6464#4,>xmm12=int6464#13
# asm 2: pshufd $0x93,<xmm3=%xmm3,>xmm12=%xmm12
pshufd $0x93,%xmm3,%xmm12

# qhasm:     xmm13 = shuffle dwords of xmm7 by 0x93
# asm 1: pshufd $0x93,<xmm7=int6464#8,>xmm13=int6464#14
# asm 2: pshufd $0x93,<xmm7=%xmm7,>xmm13=%xmm13
pshufd $0x93,%xmm7,%xmm13

# qhasm:     xmm14 = shuffle dwords of xmm2 by 0x93
# asm 1: pshufd $0x93,<xmm2=int6464#3,>xmm14=int6464#15
# asm 2: pshufd $0x93,<xmm2=%xmm2,>xmm14=%xmm14
pshufd $0x93,%xmm2,%xmm14

# qhasm:     xmm15 = shuffle dwords of xmm5 by 0x93
# asm 1: pshufd $0x93,<xmm5=int6464#6,>xmm15=int6464#16
# asm 2: pshufd $0x93,<xmm5=%xmm5,>xmm15=%xmm15
pshufd $0x93,%xmm5,%xmm15

# qhasm:     xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:     xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:     xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:     xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:     xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:     xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:     xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:     xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:     xmm8 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm8=int6464#9
# asm 2: pxor  <xmm5=%xmm5,<xmm8=%xmm8
pxor  %xmm5,%xmm8

# qhasm:     xmm9 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm9=int6464#10
# asm 2: pxor  <xmm0=%xmm0,<xmm9=%xmm9
pxor  %xmm0,%xmm9

# qhasm:     xmm10 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm10=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm10=%xmm10
pxor  %xmm1,%xmm10

# qhasm:     xmm9 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm9=int6464#10
# asm 2: pxor  <xmm5=%xmm5,<xmm9=%xmm9
pxor  %xmm5,%xmm9

# qhasm:     xmm11 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm11=int6464#12
# asm 2: pxor  <xmm4=%xmm4,<xmm11=%xmm11
pxor  %xmm4,%xmm11

# qhasm:     xmm12 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm12=int6464#13
# asm 2: pxor  <xmm6=%xmm6,<xmm12=%xmm12
pxor  %xmm6,%xmm12

# qhasm:     xmm13 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm13=int6464#14
# asm 2: pxor  <xmm3=%xmm3,<xmm13=%xmm13
pxor  %xmm3,%xmm13

# qhasm:     xmm11 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm11=int6464#12
# asm 2: pxor  <xmm5=%xmm5,<xmm11=%xmm11
pxor  %xmm5,%xmm11

# qhasm:     xmm14 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm14=int6464#15
# asm 2: pxor  <xmm7=%xmm7,<xmm14=%xmm14
pxor  %xmm7,%xmm14

# qhasm:     xmm15 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm15=int6464#16
# asm 2: pxor  <xmm2=%xmm2,<xmm15=%xmm15
pxor  %xmm2,%xmm15

# qhasm:     xmm12 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm12=int6464#13
# asm 2: pxor  <xmm5=%xmm5,<xmm12=%xmm12
pxor  %xmm5,%xmm12

# qhasm:     xmm0 = shuffle dwords of xmm0 by 0x4E
# asm 1: pshufd $0x4E,<xmm0=int6464#1,>xmm0=int6464#1
# asm 2: pshufd $0x4E,<xmm0=%xmm0,>xmm0=%xmm0
pshufd $0x4E,%xmm0,%xmm0

# qhasm:     xmm1 = shuffle dwords of xmm1 by 0x4E
# asm 1: pshufd $0x4E,<xmm1=int6464#2,>xmm1=int6464#2
# asm 2: pshufd $0x4E,<xmm1=%xmm1,>xmm1=%xmm1
pshufd $0x4E,%xmm1,%xmm1

# qhasm:     xmm4 = shuffle dwords of xmm4 by 0x4E
# asm 1: pshufd $0x4E,<xmm4=int6464#5,>xmm4=int6464#5
# asm 2: pshufd $0x4E,<xmm4=%xmm4,>xmm4=%xmm4
pshufd $0x4E,%xmm4,%xmm4

# qhasm:     xmm6 = shuffle dwords of xmm6 by 0x4E
# asm 1: pshufd $0x4E,<xmm6=int6464#7,>xmm6=int6464#7
# asm 2: pshufd $0x4E,<xmm6=%xmm6,>xmm6=%xmm6
pshufd $0x4E,%xmm6,%xmm6

# qhasm:     xmm3 = shuffle dwords of xmm3 by 0x4E
# asm 1: pshufd $0x4E,<xmm3=int6464#4,>xmm3=int6464#4
# asm 2: pshufd $0x4E,<xmm3=%xmm3,>xmm3=%xmm3
pshufd $0x4E,%xmm3,%xmm3

# qhasm:     xmm7 = shuffle dwords of xmm7 by 0x4E
# asm 1: pshufd $0x4E,<xmm7=int6464#8,>xmm7=int6464#8
# asm 2: pshufd $0x4E,<xmm7=%xmm7,>xmm7=%xmm7
pshufd $0x4E,%xmm7,%xmm7

# qhasm:     xmm2 = shuffle dwords of xmm2 by 0x4E
# asm 1: pshufd $0x4E,<xmm2=int6464#3,>xmm2=int6464#3
# asm 2: pshufd $0x4E,<xmm2=%xmm2,>xmm2=%xmm2
pshufd $0x4E,%xmm2,%xmm2

# qhasm:     xmm5 = shuffle dwords of xmm5 by 0x4E
# asm 1: pshufd $0x4E,<xmm5=int6464#6,>xmm5=int6464#6
# asm 2: pshufd $0x4E,<xmm5=%xmm5,>xmm5=%xmm5
pshufd $0x4E,%xmm5,%xmm5

# qhasm:     xmm8 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:     xmm9 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm9=int6464#10
# asm 2: pxor  <xmm1=%xmm1,<xmm9=%xmm9
pxor  %xmm1,%xmm9

# qhasm:     xmm10 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm10=int6464#11
# asm 2: pxor  <xmm4=%xmm4,<xmm10=%xmm10
pxor  %xmm4,%xmm10

# qhasm:     xmm11 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm11=int6464#12
# asm 2: pxor  <xmm6=%xmm6,<xmm11=%xmm11
pxor  %xmm6,%xmm11

# qhasm:     xmm12 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm12=int6464#13
# asm 2: pxor  <xmm3=%xmm3,<xmm12=%xmm12
pxor  %xmm3,%xmm12

# qhasm:     xmm13 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm13=int6464#14
# asm 2: pxor  <xmm7=%xmm7,<xmm13=%xmm13
pxor  %xmm7,%xmm13

# qhasm:     xmm14 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm14=int6464#15
# asm 2: pxor  <xmm2=%xmm2,<xmm14=%xmm14
pxor  %xmm2,%xmm14

# qhasm:     xmm15 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm15=int6464#16
# asm 2: pxor  <xmm5=%xmm5,<xmm15=%xmm15
pxor  %xmm5,%xmm15

# qhasm:     xmm8 ^= *(int128 *)(c + 640)
# asm 1: pxor 640(<c=int64#4),<xmm8=int6464#9
# asm 2: pxor 640(<c=%rcx),<xmm8=%xmm8
pxor 640(%rcx),%xmm8

# qhasm:     shuffle bytes of xmm8 by SR
# asm 1: pshufb SR,<xmm8=int6464#9
# asm 2: pshufb SR,<xmm8=%xmm8
pshufb SR,%xmm8

# qhasm:     xmm9 ^= *(int128 *)(c + 656)
# asm 1: pxor 656(<c=int64#4),<xmm9=int6464#10
# asm 2: pxor 656(<c=%rcx),<xmm9=%xmm9
pxor 656(%rcx),%xmm9

# qhasm:     shuffle bytes of xmm9 by SR
# asm 1: pshufb SR,<xmm9=int6464#10
# asm 2: pshufb SR,<xmm9=%xmm9
pshufb SR,%xmm9

# qhasm:     xmm10 ^= *(int128 *)(c + 672)
# asm 1: pxor 672(<c=int64#4),<xmm10=int6464#11
# asm 2: pxor 672(<c=%rcx),<xmm10=%xmm10
pxor 672(%rcx),%xmm10

# qhasm:     shuffle bytes of xmm10 by SR
# asm 1: pshufb SR,<xmm10=int6464#11
# asm 2: pshufb SR,<xmm10=%xmm10
pshufb SR,%xmm10

# qhasm:     xmm11 ^= *(int128 *)(c + 688)
# asm 1: pxor 688(<c=int64#4),<xmm11=int6464#12
# asm 2: pxor 688(<c=%rcx),<xmm11=%xmm11
pxor 688(%rcx),%xmm11

# qhasm:     shuffle bytes of xmm11 by SR
# asm 1: pshufb SR,<xmm11=int6464#12
# asm 2: pshufb SR,<xmm11=%xmm11
pshufb SR,%xmm11

# qhasm:     xmm12 ^= *(int128 *)(c + 704)
# asm 1: pxor 704(<c=int64#4),<xmm12=int6464#13
# asm 2: pxor 704(<c=%rcx),<xmm12=%xmm12
pxor 704(%rcx),%xmm12

# qhasm:     shuffle bytes of xmm12 by SR
# asm 1: pshufb SR,<xmm12=int6464#13
# asm 2: pshufb SR,<xmm12=%xmm12
pshufb SR,%xmm12

# qhasm:     xmm13 ^= *(int128 *)(c + 720)
# asm 1: pxor 720(<c=int64#4),<xmm13=int6464#14
# asm 2: pxor 720(<c=%rcx),<xmm13=%xmm13
pxor 720(%rcx),%xmm13

# qhasm:     shuffle bytes of xmm13 by SR
# asm 1: pshufb SR,<xmm13=int6464#14
# asm 2: pshufb SR,<xmm13=%xmm13
pshufb SR,%xmm13

# qhasm:     xmm14 ^= *(int128 *)(c + 736)
# asm 1: pxor 736(<c=int64#4),<xmm14=int6464#15
# asm 2: pxor 736(<c=%rcx),<xmm14=%xmm14
pxor 736(%rcx),%xmm14

# qhasm:     shuffle bytes of xmm14 by SR
# asm 1: pshufb SR,<xmm14=int6464#15
# asm 2: pshufb SR,<xmm14=%xmm14
pshufb SR,%xmm14

# qhasm:     xmm15 ^= *(int128 *)(c + 752)
# asm 1: pxor 752(<c=int64#4),<xmm15=int6464#16
# asm 2: pxor 752(<c=%rcx),<xmm15=%xmm15
pxor 752(%rcx),%xmm15

# qhasm:     shuffle bytes of xmm15 by SR
# asm 1: pshufb SR,<xmm15=int6464#16
# asm 2: pshufb SR,<xmm15=%xmm15
pshufb SR,%xmm15

# qhasm:       xmm13 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm13=int6464#14
# asm 2: pxor  <xmm14=%xmm14,<xmm13=%xmm13
pxor  %xmm14,%xmm13

# qhasm:       xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm9,<xmm10=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm13=int6464#14
# asm 2: pxor  <xmm8=%xmm8,<xmm13=%xmm13
pxor  %xmm8,%xmm13

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm14=int6464#15
# asm 2: pxor  <xmm10=%xmm10,<xmm14=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm11=int6464#12
# asm 2: pxor  <xmm8=%xmm8,<xmm11=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm14=int6464#15
# asm 2: pxor  <xmm11=%xmm11,<xmm14=%xmm14
pxor  %xmm11,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#12
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm11
pxor  %xmm15,%xmm11

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm11=int6464#12
# asm 2: pxor  <xmm12=%xmm12,<xmm11=%xmm11
pxor  %xmm12,%xmm11

# qhasm:       xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm15=int6464#16
# asm 2: pxor  <xmm13=%xmm13,<xmm15=%xmm15
pxor  %xmm13,%xmm15

# qhasm:       xmm11 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm11=int6464#12
# asm 2: pxor  <xmm9=%xmm9,<xmm11=%xmm11
pxor  %xmm9,%xmm11

# qhasm:       xmm12 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm12=int6464#13
# asm 2: pxor  <xmm13=%xmm13,<xmm12=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm10 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm10=int6464#11
# asm 2: pxor  <xmm15=%xmm15,<xmm10=%xmm10
pxor  %xmm15,%xmm10

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm9=int6464#10
# asm 2: pxor  <xmm13=%xmm13,<xmm9=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm3 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm3=int6464#1
# asm 2: movdqa <xmm15=%xmm15,>xmm3=%xmm0
movdqa %xmm15,%xmm0

# qhasm:       xmm2 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm2=int6464#2
# asm 2: movdqa <xmm9=%xmm9,>xmm2=%xmm1
movdqa %xmm9,%xmm1

# qhasm:       xmm1 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm1=int6464#3
# asm 2: movdqa <xmm13=%xmm13,>xmm1=%xmm2
movdqa %xmm13,%xmm2

# qhasm:       xmm5 = xmm10
# asm 1: movdqa <xmm10=int6464#11,>xmm5=int6464#4
# asm 2: movdqa <xmm10=%xmm10,>xmm5=%xmm3
movdqa %xmm10,%xmm3

# qhasm:       xmm4 = xmm14
# asm 1: movdqa <xmm14=int6464#15,>xmm4=int6464#5
# asm 2: movdqa <xmm14=%xmm14,>xmm4=%xmm4
movdqa %xmm14,%xmm4

# qhasm:       xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#1
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm0
pxor  %xmm12,%xmm0

# qhasm:       xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#2
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm1
pxor  %xmm10,%xmm1

# qhasm:       xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm1=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm1=%xmm2
pxor  %xmm11,%xmm2

# qhasm:       xmm5 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm5=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm5=%xmm3
pxor  %xmm12,%xmm3

# qhasm:       xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:       xmm6 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm6=int6464#6
# asm 2: movdqa <xmm3=%xmm0,>xmm6=%xmm5
movdqa %xmm0,%xmm5

# qhasm:       xmm0 = xmm2
# asm 1: movdqa <xmm2=int6464#2,>xmm0=int6464#7
# asm 2: movdqa <xmm2=%xmm1,>xmm0=%xmm6
movdqa %xmm1,%xmm6

# qhasm:       xmm7 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm7=int6464#8
# asm 2: movdqa <xmm3=%xmm0,>xmm7=%xmm7
movdqa %xmm0,%xmm7

# qhasm:       xmm2 |= xmm1
# asm 1: por   <xmm1=int6464#3,<xmm2=int6464#2
# asm 2: por   <xmm1=%xmm2,<xmm2=%xmm1
por   %xmm2,%xmm1

# qhasm:       xmm3 |= xmm4
# asm 1: por   <xmm4=int6464#5,<xmm3=int6464#1
# asm 2: por   <xmm4=%xmm4,<xmm3=%xmm0
por   %xmm4,%xmm0

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm7=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm6 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm6=int6464#6
# asm 2: pand  <xmm4=%xmm4,<xmm6=%xmm5
pand  %xmm4,%xmm5

# qhasm:       xmm0 &= xmm1
# asm 1: pand  <xmm1=int6464#3,<xmm0=int6464#7
# asm 2: pand  <xmm1=%xmm2,<xmm0=%xmm6
pand  %xmm2,%xmm6

# qhasm:       xmm4 ^= xmm1
# asm 1: pxor  <xmm1=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm1=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:       xmm7 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm7=int6464#8
# asm 2: pand  <xmm4=%xmm4,<xmm7=%xmm7
pand  %xmm4,%xmm7

# qhasm:       xmm4 = xmm11
# asm 1: movdqa <xmm11=int6464#12,>xmm4=int6464#3
# asm 2: movdqa <xmm11=%xmm11,>xmm4=%xmm2
movdqa %xmm11,%xmm2

# qhasm:       xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#3
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm2
pxor  %xmm8,%xmm2

# qhasm:       xmm5 &= xmm4
# asm 1: pand  <xmm4=int6464#3,<xmm5=int6464#4
# asm 2: pand  <xmm4=%xmm2,<xmm5=%xmm3
pand  %xmm2,%xmm3

# qhasm:       xmm3 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm3=int6464#1
# asm 2: pxor  <xmm5=%xmm3,<xmm3=%xmm0
pxor  %xmm3,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm2=int6464#2
# asm 2: pxor  <xmm5=%xmm3,<xmm2=%xmm1
pxor  %xmm3,%xmm1

# qhasm:       xmm5 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm5=int6464#3
# asm 2: movdqa <xmm15=%xmm15,>xmm5=%xmm2
movdqa %xmm15,%xmm2

# qhasm:       xmm5 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm5=int6464#3
# asm 2: pxor  <xmm9=%xmm9,<xmm5=%xmm2
pxor  %xmm9,%xmm2

# qhasm:       xmm4 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm4=int6464#4
# asm 2: movdqa <xmm13=%xmm13,>xmm4=%xmm3
movdqa %xmm13,%xmm3

# qhasm:       xmm1 = xmm5
# asm 1: movdqa <xmm5=int6464#3,>xmm1=int6464#5
# asm 2: movdqa <xmm5=%xmm2,>xmm1=%xmm4
movdqa %xmm2,%xmm4

# qhasm:       xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm3
pxor  %xmm14,%xmm3

# qhasm:       xmm1 |= xmm4
# asm 1: por   <xmm4=int6464#4,<xmm1=int6464#5
# asm 2: por   <xmm4=%xmm3,<xmm1=%xmm4
por   %xmm3,%xmm4

# qhasm:       xmm5 &= xmm4
# asm 1: pand  <xmm4=int6464#4,<xmm5=int6464#3
# asm 2: pand  <xmm4=%xmm3,<xmm5=%xmm2
pand  %xmm3,%xmm2

# qhasm:       xmm0 ^= xmm5
# asm 1: pxor  <xmm5=int6464#3,<xmm0=int6464#7
# asm 2: pxor  <xmm5=%xmm2,<xmm0=%xmm6
pxor  %xmm2,%xmm6

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#1
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm0
pxor  %xmm7,%xmm0

# qhasm:       xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm2=int6464#2
# asm 2: pxor  <xmm6=%xmm5,<xmm2=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#5
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm0 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm0=int6464#7
# asm 2: pxor  <xmm6=%xmm5,<xmm0=%xmm6
pxor  %xmm5,%xmm6

# qhasm:       xmm1 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm1=int6464#5
# asm 2: pxor  <xmm6=%xmm5,<xmm1=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm4 = xmm10
# asm 1: movdqa <xmm10=int6464#11,>xmm4=int6464#3
# asm 2: movdqa <xmm10=%xmm10,>xmm4=%xmm2
movdqa %xmm10,%xmm2

# qhasm:       xmm5 = xmm12
# asm 1: movdqa <xmm12=int6464#13,>xmm5=int6464#4
# asm 2: movdqa <xmm12=%xmm12,>xmm5=%xmm3
movdqa %xmm12,%xmm3

# qhasm:       xmm6 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm6=int6464#6
# asm 2: movdqa <xmm9=%xmm9,>xmm6=%xmm5
movdqa %xmm9,%xmm5

# qhasm:       xmm7 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm7=int6464#8
# asm 2: movdqa <xmm15=%xmm15,>xmm7=%xmm7
movdqa %xmm15,%xmm7

# qhasm:       xmm4 &= xmm11
# asm 1: pand  <xmm11=int6464#12,<xmm4=int6464#3
# asm 2: pand  <xmm11=%xmm11,<xmm4=%xmm2
pand  %xmm11,%xmm2

# qhasm:       xmm5 &= xmm8
# asm 1: pand  <xmm8=int6464#9,<xmm5=int6464#4
# asm 2: pand  <xmm8=%xmm8,<xmm5=%xmm3
pand  %xmm8,%xmm3

# qhasm:       xmm6 &= xmm13
# asm 1: pand  <xmm13=int6464#14,<xmm6=int6464#6
# asm 2: pand  <xmm13=%xmm13,<xmm6=%xmm5
pand  %xmm13,%xmm5

# qhasm:       xmm7 |= xmm14
# asm 1: por   <xmm14=int6464#15,<xmm7=int6464#8
# asm 2: por   <xmm14=%xmm14,<xmm7=%xmm7
por   %xmm14,%xmm7

# qhasm:       xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#3,<xmm3=int6464#1
# asm 2: pxor  <xmm4=%xmm2,<xmm3=%xmm0
pxor  %xmm2,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm2=int6464#2
# asm 2: pxor  <xmm5=%xmm3,<xmm2=%xmm1
pxor  %xmm3,%xmm1

# qhasm:       xmm1 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm1=int6464#5
# asm 2: pxor  <xmm6=%xmm5,<xmm1=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm0 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm0=int6464#7
# asm 2: pxor  <xmm7=%xmm7,<xmm0=%xmm6
pxor  %xmm7,%xmm6

# qhasm:       xmm4 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm4=int6464#3
# asm 2: movdqa <xmm3=%xmm0,>xmm4=%xmm2
movdqa %xmm0,%xmm2

# qhasm:       xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm4=int6464#3
# asm 2: pxor  <xmm2=%xmm1,<xmm4=%xmm2
pxor  %xmm1,%xmm2

# qhasm:       xmm3 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm3=int6464#1
# asm 2: pand  <xmm1=%xmm4,<xmm3=%xmm0
pand  %xmm4,%xmm0

# qhasm:       xmm6 = xmm0
# asm 1: movdqa <xmm0=int6464#7,>xmm6=int6464#4
# asm 2: movdqa <xmm0=%xmm6,>xmm6=%xmm3
movdqa %xmm6,%xmm3

# qhasm:       xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#1,<xmm6=int6464#4
# asm 2: pxor  <xmm3=%xmm0,<xmm6=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm7 = xmm4
# asm 1: movdqa <xmm4=int6464#3,>xmm7=int6464#6
# asm 2: movdqa <xmm4=%xmm2,>xmm7=%xmm5
movdqa %xmm2,%xmm5

# qhasm:       xmm7 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm7=int6464#6
# asm 2: pand  <xmm6=%xmm3,<xmm7=%xmm5
pand  %xmm3,%xmm5

# qhasm:       xmm7 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm7=int6464#6
# asm 2: pxor  <xmm2=%xmm1,<xmm7=%xmm5
pxor  %xmm1,%xmm5

# qhasm:       xmm5 = xmm1
# asm 1: movdqa <xmm1=int6464#5,>xmm5=int6464#8
# asm 2: movdqa <xmm1=%xmm4,>xmm5=%xmm7
movdqa %xmm4,%xmm7

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm5=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm5=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm3 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm3=int6464#1
# asm 2: pxor  <xmm2=%xmm1,<xmm3=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm5 &= xmm3
# asm 1: pand  <xmm3=int6464#1,<xmm5=int6464#8
# asm 2: pand  <xmm3=%xmm0,<xmm5=%xmm7
pand  %xmm0,%xmm7

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm5=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm5=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm1=int6464#5
# asm 2: pxor  <xmm5=%xmm7,<xmm1=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm2 = xmm6
# asm 1: movdqa <xmm6=int6464#4,>xmm2=int6464#1
# asm 2: movdqa <xmm6=%xmm3,>xmm2=%xmm0
movdqa %xmm3,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm2=int6464#1
# asm 2: pxor  <xmm5=%xmm7,<xmm2=%xmm0
pxor  %xmm7,%xmm0

# qhasm:       xmm2 &= xmm0
# asm 1: pand  <xmm0=int6464#7,<xmm2=int6464#1
# asm 2: pand  <xmm0=%xmm6,<xmm2=%xmm0
pand  %xmm6,%xmm0

# qhasm:       xmm1 ^= xmm2
# asm 1: pxor  <xmm2=int6464#1,<xmm1=int6464#5
# asm 2: pxor  <xmm2=%xmm0,<xmm1=%xmm4
pxor  %xmm0,%xmm4

# qhasm:       xmm6 ^= xmm2
# asm 1: pxor  <xmm2=int6464#1,<xmm6=int6464#4
# asm 2: pxor  <xmm2=%xmm0,<xmm6=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm6 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm6=int6464#4
# asm 2: pand  <xmm7=%xmm5,<xmm6=%xmm3
pand  %xmm5,%xmm3

# qhasm:       xmm6 ^= xmm4
# asm 1: pxor  <xmm4=int6464#3,<xmm6=int6464#4
# asm 2: pxor  <xmm4=%xmm2,<xmm6=%xmm3
pxor  %xmm2,%xmm3

# qhasm:         xmm4 = xmm14
# asm 1: movdqa <xmm14=int6464#15,>xmm4=int6464#1
# asm 2: movdqa <xmm14=%xmm14,>xmm4=%xmm0
movdqa %xmm14,%xmm0

# qhasm:         xmm0 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm0=int6464#2
# asm 2: movdqa <xmm13=%xmm13,>xmm0=%xmm1
movdqa %xmm13,%xmm1

# qhasm:           xmm2 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm2=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm2=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm2=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm2 &= xmm14
# asm 1: pand  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pand  <xmm14=%xmm14,<xmm2=%xmm2
pand  %xmm14,%xmm2

# qhasm:           xmm14 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm14=int6464#15
# asm 2: pxor  <xmm13=%xmm13,<xmm14=%xmm14
pxor  %xmm13,%xmm14

# qhasm:           xmm14 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm14=int6464#15
# asm 2: pand  <xmm6=%xmm3,<xmm14=%xmm14
pand  %xmm3,%xmm14

# qhasm:           xmm13 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm13=int6464#14
# asm 2: pand  <xmm7=%xmm5,<xmm13=%xmm13
pand  %xmm5,%xmm13

# qhasm:           xmm14 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm14=int6464#15
# asm 2: pxor  <xmm13=%xmm13,<xmm14=%xmm14
pxor  %xmm13,%xmm14

# qhasm:           xmm13 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm13=int6464#14
# asm 2: pxor  <xmm2=%xmm2,<xmm13=%xmm13
pxor  %xmm2,%xmm13

# qhasm:         xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm0 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm0=int6464#2
# asm 2: pxor  <xmm11=%xmm11,<xmm0=%xmm1
pxor  %xmm11,%xmm1

# qhasm:         xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm7=int6464#6
# asm 2: pxor  <xmm5=%xmm7,<xmm7=%xmm5
pxor  %xmm7,%xmm5

# qhasm:         xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm6=int6464#4
# asm 2: pxor  <xmm1=%xmm4,<xmm6=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm4
# asm 1: pand  <xmm4=int6464#1,<xmm3=int6464#3
# asm 2: pand  <xmm4=%xmm0,<xmm3=%xmm2
pand  %xmm0,%xmm2

# qhasm:           xmm4 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm4=int6464#1
# asm 2: pxor  <xmm0=%xmm1,<xmm4=%xmm0
pxor  %xmm1,%xmm0

# qhasm:           xmm4 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm4=int6464#1
# asm 2: pand  <xmm6=%xmm3,<xmm4=%xmm0
pand  %xmm3,%xmm0

# qhasm:           xmm0 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm0=int6464#2
# asm 2: pand  <xmm7=%xmm5,<xmm0=%xmm1
pand  %xmm5,%xmm1

# qhasm:           xmm0 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm0=int6464#2
# asm 2: pxor  <xmm4=%xmm0,<xmm0=%xmm1
pxor  %xmm0,%xmm1

# qhasm:           xmm4 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm4=int6464#1
# asm 2: pxor  <xmm3=%xmm2,<xmm4=%xmm0
pxor  %xmm2,%xmm0

# qhasm:           xmm2 = xmm5
# asm 1: movdqa <xmm5=int6464#8,>xmm2=int6464#3
# asm 2: movdqa <xmm5=%xmm7,>xmm2=%xmm2
movdqa %xmm7,%xmm2

# qhasm:           xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm4,<xmm2=%xmm2
pxor  %xmm4,%xmm2

# qhasm:           xmm2 &= xmm8
# asm 1: pand  <xmm8=int6464#9,<xmm2=int6464#3
# asm 2: pand  <xmm8=%xmm8,<xmm2=%xmm2
pand  %xmm8,%xmm2

# qhasm:           xmm8 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm8=int6464#9
# asm 2: pxor  <xmm11=%xmm11,<xmm8=%xmm8
pxor  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm8=int6464#9
# asm 2: pand  <xmm1=%xmm4,<xmm8=%xmm8
pand  %xmm4,%xmm8

# qhasm:           xmm11 &= xmm5
# asm 1: pand  <xmm5=int6464#8,<xmm11=int6464#12
# asm 2: pand  <xmm5=%xmm7,<xmm11=%xmm11
pand  %xmm7,%xmm11

# qhasm:           xmm8 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm8=int6464#9
# asm 2: pxor  <xmm11=%xmm11,<xmm8=%xmm8
pxor  %xmm11,%xmm8

# qhasm:           xmm11 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm11=int6464#12
# asm 2: pxor  <xmm2=%xmm2,<xmm11=%xmm11
pxor  %xmm2,%xmm11

# qhasm:         xmm14 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm14=int6464#15
# asm 2: pxor  <xmm4=%xmm0,<xmm14=%xmm14
pxor  %xmm0,%xmm14

# qhasm:         xmm8 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm4=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm13 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm13=int6464#14
# asm 2: pxor  <xmm0=%xmm1,<xmm13=%xmm13
pxor  %xmm1,%xmm13

# qhasm:         xmm11 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm11=int6464#12
# asm 2: pxor  <xmm0=%xmm1,<xmm11=%xmm11
pxor  %xmm1,%xmm11

# qhasm:         xmm4 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm4=int6464#1
# asm 2: movdqa <xmm15=%xmm15,>xmm4=%xmm0
movdqa %xmm15,%xmm0

# qhasm:         xmm0 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm0=int6464#2
# asm 2: movdqa <xmm9=%xmm9,>xmm0=%xmm1
movdqa %xmm9,%xmm1

# qhasm:         xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm4=int6464#1
# asm 2: pxor  <xmm12=%xmm12,<xmm4=%xmm0
pxor  %xmm12,%xmm0

# qhasm:         xmm0 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm0=int6464#2
# asm 2: pxor  <xmm10=%xmm10,<xmm0=%xmm1
pxor  %xmm10,%xmm1

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm4
# asm 1: pand  <xmm4=int6464#1,<xmm3=int6464#3
# asm 2: pand  <xmm4=%xmm0,<xmm3=%xmm2
pand  %xmm0,%xmm2

# qhasm:           xmm4 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm4=int6464#1
# asm 2: pxor  <xmm0=%xmm1,<xmm4=%xmm0
pxor  %xmm1,%xmm0

# qhasm:           xmm4 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm4=int6464#1
# asm 2: pand  <xmm6=%xmm3,<xmm4=%xmm0
pand  %xmm3,%xmm0

# qhasm:           xmm0 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm0=int6464#2
# asm 2: pand  <xmm7=%xmm5,<xmm0=%xmm1
pand  %xmm5,%xmm1

# qhasm:           xmm0 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm0=int6464#2
# asm 2: pxor  <xmm4=%xmm0,<xmm0=%xmm1
pxor  %xmm0,%xmm1

# qhasm:           xmm4 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm4=int6464#1
# asm 2: pxor  <xmm3=%xmm2,<xmm4=%xmm0
pxor  %xmm2,%xmm0

# qhasm:           xmm2 = xmm5
# asm 1: movdqa <xmm5=int6464#8,>xmm2=int6464#3
# asm 2: movdqa <xmm5=%xmm7,>xmm2=%xmm2
movdqa %xmm7,%xmm2

# qhasm:           xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm4,<xmm2=%xmm2
pxor  %xmm4,%xmm2

# qhasm:           xmm2 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pand  <xmm12=%xmm12,<xmm2=%xmm2
pand  %xmm12,%xmm2

# qhasm:           xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm10=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:           xmm12 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm12=int6464#13
# asm 2: pand  <xmm1=%xmm4,<xmm12=%xmm12
pand  %xmm4,%xmm12

# qhasm:           xmm10 &= xmm5
# asm 1: pand  <xmm5=int6464#8,<xmm10=int6464#11
# asm 2: pand  <xmm5=%xmm7,<xmm10=%xmm10
pand  %xmm7,%xmm10

# qhasm:           xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm10=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:           xmm10 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm10=int6464#11
# asm 2: pxor  <xmm2=%xmm2,<xmm10=%xmm10
pxor  %xmm2,%xmm10

# qhasm:         xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm7=int6464#6
# asm 2: pxor  <xmm5=%xmm7,<xmm7=%xmm5
pxor  %xmm7,%xmm5

# qhasm:         xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm6=int6464#4
# asm 2: pxor  <xmm1=%xmm4,<xmm6=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm15
# asm 1: pand  <xmm15=int6464#16,<xmm3=int6464#3
# asm 2: pand  <xmm15=%xmm15,<xmm3=%xmm2
pand  %xmm15,%xmm2

# qhasm:           xmm15 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm15=int6464#16
# asm 2: pxor  <xmm9=%xmm9,<xmm15=%xmm15
pxor  %xmm9,%xmm15

# qhasm:           xmm15 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm15=int6464#16
# asm 2: pand  <xmm6=%xmm3,<xmm15=%xmm15
pand  %xmm3,%xmm15

# qhasm:           xmm9 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm9=int6464#10
# asm 2: pand  <xmm7=%xmm5,<xmm9=%xmm9
pand  %xmm5,%xmm9

# qhasm:           xmm15 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm15=int6464#16
# asm 2: pxor  <xmm9=%xmm9,<xmm15=%xmm15
pxor  %xmm9,%xmm15

# qhasm:           xmm9 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm9=int6464#10
# asm 2: pxor  <xmm3=%xmm2,<xmm9=%xmm9
pxor  %xmm2,%xmm9

# qhasm:         xmm15 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm15=int6464#16
# asm 2: pxor  <xmm4=%xmm0,<xmm15=%xmm15
pxor  %xmm0,%xmm15

# qhasm:         xmm12 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm4=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:         xmm9 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm9=int6464#10
# asm 2: pxor  <xmm0=%xmm1,<xmm9=%xmm9
pxor  %xmm1,%xmm9

# qhasm:         xmm10 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm10=int6464#11
# asm 2: pxor  <xmm0=%xmm1,<xmm10=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm8,<xmm15=%xmm15
pxor  %xmm8,%xmm15

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm9=int6464#10
# asm 2: pxor  <xmm14=%xmm14,<xmm9=%xmm9
pxor  %xmm14,%xmm9

# qhasm:       xmm12 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm12=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm12=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm14 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm14=int6464#15
# asm 2: pxor  <xmm8=%xmm8,<xmm14=%xmm14
pxor  %xmm8,%xmm14

# qhasm:       xmm8 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm8=int6464#9
# asm 2: pxor  <xmm9=%xmm9,<xmm8=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm9=int6464#10
# asm 2: pxor  <xmm13=%xmm13,<xmm9=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm13 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm13=int6464#14
# asm 2: pxor  <xmm10=%xmm10,<xmm13=%xmm13
pxor  %xmm10,%xmm13

# qhasm:       xmm12 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm12=int6464#13
# asm 2: pxor  <xmm13=%xmm13,<xmm12=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm10 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm11=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm11=int6464#12
# asm 2: pxor  <xmm13=%xmm13,<xmm11=%xmm11
pxor  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm14=int6464#15
# asm 2: pxor  <xmm11=%xmm11,<xmm14=%xmm14
pxor  %xmm11,%xmm14

# qhasm:     xmm0 = shuffle dwords of xmm8 by 0x93
# asm 1: pshufd $0x93,<xmm8=int6464#9,>xmm0=int6464#1
# asm 2: pshufd $0x93,<xmm8=%xmm8,>xmm0=%xmm0
pshufd $0x93,%xmm8,%xmm0

# qhasm:     xmm1 = shuffle dwords of xmm9 by 0x93
# asm 1: pshufd $0x93,<xmm9=int6464#10,>xmm1=int6464#2
# asm 2: pshufd $0x93,<xmm9=%xmm9,>xmm1=%xmm1
pshufd $0x93,%xmm9,%xmm1

# qhasm:     xmm2 = shuffle dwords of xmm12 by 0x93
# asm 1: pshufd $0x93,<xmm12=int6464#13,>xmm2=int6464#3
# asm 2: pshufd $0x93,<xmm12=%xmm12,>xmm2=%xmm2
pshufd $0x93,%xmm12,%xmm2

# qhasm:     xmm3 = shuffle dwords of xmm14 by 0x93
# asm 1: pshufd $0x93,<xmm14=int6464#15,>xmm3=int6464#4
# asm 2: pshufd $0x93,<xmm14=%xmm14,>xmm3=%xmm3
pshufd $0x93,%xmm14,%xmm3

# qhasm:     xmm4 = shuffle dwords of xmm11 by 0x93
# asm 1: pshufd $0x93,<xmm11=int6464#12,>xmm4=int6464#5
# asm 2: pshufd $0x93,<xmm11=%xmm11,>xmm4=%xmm4
pshufd $0x93,%xmm11,%xmm4

# qhasm:     xmm5 = shuffle dwords of xmm15 by 0x93
# asm 1: pshufd $0x93,<xmm15=int6464#16,>xmm5=int6464#6
# asm 2: pshufd $0x93,<xmm15=%xmm15,>xmm5=%xmm5
pshufd $0x93,%xmm15,%xmm5

# qhasm:     xmm6 = shuffle dwords of xmm10 by 0x93
# asm 1: pshufd $0x93,<xmm10=int6464#11,>xmm6=int6464#7
# asm 2: pshufd $0x93,<xmm10=%xmm10,>xmm6=%xmm6
pshufd $0x93,%xmm10,%xmm6

# qhasm:     xmm7 = shuffle dwords of xmm13 by 0x93
# asm 1: pshufd $0x93,<xmm13=int6464#14,>xmm7=int6464#8
# asm 2: pshufd $0x93,<xmm13=%xmm13,>xmm7=%xmm7
pshufd $0x93,%xmm13,%xmm7

# qhasm:     xmm8 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:     xmm9 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm9=int6464#10
# asm 2: pxor  <xmm1=%xmm1,<xmm9=%xmm9
pxor  %xmm1,%xmm9

# qhasm:     xmm12 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm12=int6464#13
# asm 2: pxor  <xmm2=%xmm2,<xmm12=%xmm12
pxor  %xmm2,%xmm12

# qhasm:     xmm14 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm14=int6464#15
# asm 2: pxor  <xmm3=%xmm3,<xmm14=%xmm14
pxor  %xmm3,%xmm14

# qhasm:     xmm11 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm11=int6464#12
# asm 2: pxor  <xmm4=%xmm4,<xmm11=%xmm11
pxor  %xmm4,%xmm11

# qhasm:     xmm15 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm15=int6464#16
# asm 2: pxor  <xmm5=%xmm5,<xmm15=%xmm15
pxor  %xmm5,%xmm15

# qhasm:     xmm10 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm10=int6464#11
# asm 2: pxor  <xmm6=%xmm6,<xmm10=%xmm10
pxor  %xmm6,%xmm10

# qhasm:     xmm13 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm13=int6464#14
# asm 2: pxor  <xmm7=%xmm7,<xmm13=%xmm13
pxor  %xmm7,%xmm13

# qhasm:     xmm0 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm0=int6464#1
# asm 2: pxor  <xmm13=%xmm13,<xmm0=%xmm0
pxor  %xmm13,%xmm0

# qhasm:     xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm8,<xmm1=%xmm1
pxor  %xmm8,%xmm1

# qhasm:     xmm2 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm2=int6464#3
# asm 2: pxor  <xmm9=%xmm9,<xmm2=%xmm2
pxor  %xmm9,%xmm2

# qhasm:     xmm1 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm1=int6464#2
# asm 2: pxor  <xmm13=%xmm13,<xmm1=%xmm1
pxor  %xmm13,%xmm1

# qhasm:     xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:     xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:     xmm5 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm5=int6464#6
# asm 2: pxor  <xmm11=%xmm11,<xmm5=%xmm5
pxor  %xmm11,%xmm5

# qhasm:     xmm3 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm3=int6464#4
# asm 2: pxor  <xmm13=%xmm13,<xmm3=%xmm3
pxor  %xmm13,%xmm3

# qhasm:     xmm6 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm6=int6464#7
# asm 2: pxor  <xmm15=%xmm15,<xmm6=%xmm6
pxor  %xmm15,%xmm6

# qhasm:     xmm7 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm7=int6464#8
# asm 2: pxor  <xmm10=%xmm10,<xmm7=%xmm7
pxor  %xmm10,%xmm7

# qhasm:     xmm4 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm4=int6464#5
# asm 2: pxor  <xmm13=%xmm13,<xmm4=%xmm4
pxor  %xmm13,%xmm4

# qhasm:     xmm8 = shuffle dwords of xmm8 by 0x4E
# asm 1: pshufd $0x4E,<xmm8=int6464#9,>xmm8=int6464#9
# asm 2: pshufd $0x4E,<xmm8=%xmm8,>xmm8=%xmm8
pshufd $0x4E,%xmm8,%xmm8

# qhasm:     xmm9 = shuffle dwords of xmm9 by 0x4E
# asm 1: pshufd $0x4E,<xmm9=int6464#10,>xmm9=int6464#10
# asm 2: pshufd $0x4E,<xmm9=%xmm9,>xmm9=%xmm9
pshufd $0x4E,%xmm9,%xmm9

# qhasm:     xmm12 = shuffle dwords of xmm12 by 0x4E
# asm 1: pshufd $0x4E,<xmm12=int6464#13,>xmm12=int6464#13
# asm 2: pshufd $0x4E,<xmm12=%xmm12,>xmm12=%xmm12
pshufd $0x4E,%xmm12,%xmm12

# qhasm:     xmm14 = shuffle dwords of xmm14 by 0x4E
# asm 1: pshufd $0x4E,<xmm14=int6464#15,>xmm14=int6464#15
# asm 2: pshufd $0x4E,<xmm14=%xmm14,>xmm14=%xmm14
pshufd $0x4E,%xmm14,%xmm14

# qhasm:     xmm11 = shuffle dwords of xmm11 by 0x4E
# asm 1: pshufd $0x4E,<xmm11=int6464#12,>xmm11=int6464#12
# asm 2: pshufd $0x4E,<xmm11=%xmm11,>xmm11=%xmm11
pshufd $0x4E,%xmm11,%xmm11

# qhasm:     xmm15 = shuffle dwords of xmm15 by 0x4E
# asm 1: pshufd $0x4E,<xmm15=int6464#16,>xmm15=int6464#16
# asm 2: pshufd $0x4E,<xmm15=%xmm15,>xmm15=%xmm15
pshufd $0x4E,%xmm15,%xmm15

# qhasm:     xmm10 = shuffle dwords of xmm10 by 0x4E
# asm 1: pshufd $0x4E,<xmm10=int6464#11,>xmm10=int6464#11
# asm 2: pshufd $0x4E,<xmm10=%xmm10,>xmm10=%xmm10
pshufd $0x4E,%xmm10,%xmm10

# qhasm:     xmm13 = shuffle dwords of xmm13 by 0x4E
# asm 1: pshufd $0x4E,<xmm13=int6464#14,>xmm13=int6464#14
# asm 2: pshufd $0x4E,<xmm13=%xmm13,>xmm13=%xmm13
pshufd $0x4E,%xmm13,%xmm13

# qhasm:     xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:     xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:     xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm12,<xmm2=%xmm2
pxor  %xmm12,%xmm2

# qhasm:     xmm3 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm3=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm3=%xmm3
pxor  %xmm14,%xmm3

# qhasm:     xmm4 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm4=int6464#5
# asm 2: pxor  <xmm11=%xmm11,<xmm4=%xmm4
pxor  %xmm11,%xmm4

# qhasm:     xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:     xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:     xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:     xmm0 ^= *(int128 *)(c + 768)
# asm 1: pxor 768(<c=int64#4),<xmm0=int6464#1
# asm 2: pxor 768(<c=%rcx),<xmm0=%xmm0
pxor 768(%rcx),%xmm0

# qhasm:     shuffle bytes of xmm0 by SR
# asm 1: pshufb SR,<xmm0=int6464#1
# asm 2: pshufb SR,<xmm0=%xmm0
pshufb SR,%xmm0

# qhasm:     xmm1 ^= *(int128 *)(c + 784)
# asm 1: pxor 784(<c=int64#4),<xmm1=int6464#2
# asm 2: pxor 784(<c=%rcx),<xmm1=%xmm1
pxor 784(%rcx),%xmm1

# qhasm:     shuffle bytes of xmm1 by SR
# asm 1: pshufb SR,<xmm1=int6464#2
# asm 2: pshufb SR,<xmm1=%xmm1
pshufb SR,%xmm1

# qhasm:     xmm2 ^= *(int128 *)(c + 800)
# asm 1: pxor 800(<c=int64#4),<xmm2=int6464#3
# asm 2: pxor 800(<c=%rcx),<xmm2=%xmm2
pxor 800(%rcx),%xmm2

# qhasm:     shuffle bytes of xmm2 by SR
# asm 1: pshufb SR,<xmm2=int6464#3
# asm 2: pshufb SR,<xmm2=%xmm2
pshufb SR,%xmm2

# qhasm:     xmm3 ^= *(int128 *)(c + 816)
# asm 1: pxor 816(<c=int64#4),<xmm3=int6464#4
# asm 2: pxor 816(<c=%rcx),<xmm3=%xmm3
pxor 816(%rcx),%xmm3

# qhasm:     shuffle bytes of xmm3 by SR
# asm 1: pshufb SR,<xmm3=int6464#4
# asm 2: pshufb SR,<xmm3=%xmm3
pshufb SR,%xmm3

# qhasm:     xmm4 ^= *(int128 *)(c + 832)
# asm 1: pxor 832(<c=int64#4),<xmm4=int6464#5
# asm 2: pxor 832(<c=%rcx),<xmm4=%xmm4
pxor 832(%rcx),%xmm4

# qhasm:     shuffle bytes of xmm4 by SR
# asm 1: pshufb SR,<xmm4=int6464#5
# asm 2: pshufb SR,<xmm4=%xmm4
pshufb SR,%xmm4

# qhasm:     xmm5 ^= *(int128 *)(c + 848)
# asm 1: pxor 848(<c=int64#4),<xmm5=int6464#6
# asm 2: pxor 848(<c=%rcx),<xmm5=%xmm5
pxor 848(%rcx),%xmm5

# qhasm:     shuffle bytes of xmm5 by SR
# asm 1: pshufb SR,<xmm5=int6464#6
# asm 2: pshufb SR,<xmm5=%xmm5
pshufb SR,%xmm5

# qhasm:     xmm6 ^= *(int128 *)(c + 864)
# asm 1: pxor 864(<c=int64#4),<xmm6=int6464#7
# asm 2: pxor 864(<c=%rcx),<xmm6=%xmm6
pxor 864(%rcx),%xmm6

# qhasm:     shuffle bytes of xmm6 by SR
# asm 1: pshufb SR,<xmm6=int6464#7
# asm 2: pshufb SR,<xmm6=%xmm6
pshufb SR,%xmm6

# qhasm:     xmm7 ^= *(int128 *)(c + 880)
# asm 1: pxor 880(<c=int64#4),<xmm7=int6464#8
# asm 2: pxor 880(<c=%rcx),<xmm7=%xmm7
pxor 880(%rcx),%xmm7

# qhasm:     shuffle bytes of xmm7 by SR
# asm 1: pshufb SR,<xmm7=int6464#8
# asm 2: pshufb SR,<xmm7=%xmm7
pshufb SR,%xmm7

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

# qhasm:     xmm8 = shuffle dwords of xmm0 by 0x93
# asm 1: pshufd $0x93,<xmm0=int6464#1,>xmm8=int6464#9
# asm 2: pshufd $0x93,<xmm0=%xmm0,>xmm8=%xmm8
pshufd $0x93,%xmm0,%xmm8

# qhasm:     xmm9 = shuffle dwords of xmm1 by 0x93
# asm 1: pshufd $0x93,<xmm1=int6464#2,>xmm9=int6464#10
# asm 2: pshufd $0x93,<xmm1=%xmm1,>xmm9=%xmm9
pshufd $0x93,%xmm1,%xmm9

# qhasm:     xmm10 = shuffle dwords of xmm4 by 0x93
# asm 1: pshufd $0x93,<xmm4=int6464#5,>xmm10=int6464#11
# asm 2: pshufd $0x93,<xmm4=%xmm4,>xmm10=%xmm10
pshufd $0x93,%xmm4,%xmm10

# qhasm:     xmm11 = shuffle dwords of xmm6 by 0x93
# asm 1: pshufd $0x93,<xmm6=int6464#7,>xmm11=int6464#12
# asm 2: pshufd $0x93,<xmm6=%xmm6,>xmm11=%xmm11
pshufd $0x93,%xmm6,%xmm11

# qhasm:     xmm12 = shuffle dwords of xmm3 by 0x93
# asm 1: pshufd $0x93,<xmm3=int6464#4,>xmm12=int6464#13
# asm 2: pshufd $0x93,<xmm3=%xmm3,>xmm12=%xmm12
pshufd $0x93,%xmm3,%xmm12

# qhasm:     xmm13 = shuffle dwords of xmm7 by 0x93
# asm 1: pshufd $0x93,<xmm7=int6464#8,>xmm13=int6464#14
# asm 2: pshufd $0x93,<xmm7=%xmm7,>xmm13=%xmm13
pshufd $0x93,%xmm7,%xmm13

# qhasm:     xmm14 = shuffle dwords of xmm2 by 0x93
# asm 1: pshufd $0x93,<xmm2=int6464#3,>xmm14=int6464#15
# asm 2: pshufd $0x93,<xmm2=%xmm2,>xmm14=%xmm14
pshufd $0x93,%xmm2,%xmm14

# qhasm:     xmm15 = shuffle dwords of xmm5 by 0x93
# asm 1: pshufd $0x93,<xmm5=int6464#6,>xmm15=int6464#16
# asm 2: pshufd $0x93,<xmm5=%xmm5,>xmm15=%xmm15
pshufd $0x93,%xmm5,%xmm15

# qhasm:     xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:     xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:     xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:     xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:     xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:     xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:     xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:     xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:     xmm8 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm8=int6464#9
# asm 2: pxor  <xmm5=%xmm5,<xmm8=%xmm8
pxor  %xmm5,%xmm8

# qhasm:     xmm9 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm9=int6464#10
# asm 2: pxor  <xmm0=%xmm0,<xmm9=%xmm9
pxor  %xmm0,%xmm9

# qhasm:     xmm10 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm10=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm10=%xmm10
pxor  %xmm1,%xmm10

# qhasm:     xmm9 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm9=int6464#10
# asm 2: pxor  <xmm5=%xmm5,<xmm9=%xmm9
pxor  %xmm5,%xmm9

# qhasm:     xmm11 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm11=int6464#12
# asm 2: pxor  <xmm4=%xmm4,<xmm11=%xmm11
pxor  %xmm4,%xmm11

# qhasm:     xmm12 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm12=int6464#13
# asm 2: pxor  <xmm6=%xmm6,<xmm12=%xmm12
pxor  %xmm6,%xmm12

# qhasm:     xmm13 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm13=int6464#14
# asm 2: pxor  <xmm3=%xmm3,<xmm13=%xmm13
pxor  %xmm3,%xmm13

# qhasm:     xmm11 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm11=int6464#12
# asm 2: pxor  <xmm5=%xmm5,<xmm11=%xmm11
pxor  %xmm5,%xmm11

# qhasm:     xmm14 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm14=int6464#15
# asm 2: pxor  <xmm7=%xmm7,<xmm14=%xmm14
pxor  %xmm7,%xmm14

# qhasm:     xmm15 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm15=int6464#16
# asm 2: pxor  <xmm2=%xmm2,<xmm15=%xmm15
pxor  %xmm2,%xmm15

# qhasm:     xmm12 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm12=int6464#13
# asm 2: pxor  <xmm5=%xmm5,<xmm12=%xmm12
pxor  %xmm5,%xmm12

# qhasm:     xmm0 = shuffle dwords of xmm0 by 0x4E
# asm 1: pshufd $0x4E,<xmm0=int6464#1,>xmm0=int6464#1
# asm 2: pshufd $0x4E,<xmm0=%xmm0,>xmm0=%xmm0
pshufd $0x4E,%xmm0,%xmm0

# qhasm:     xmm1 = shuffle dwords of xmm1 by 0x4E
# asm 1: pshufd $0x4E,<xmm1=int6464#2,>xmm1=int6464#2
# asm 2: pshufd $0x4E,<xmm1=%xmm1,>xmm1=%xmm1
pshufd $0x4E,%xmm1,%xmm1

# qhasm:     xmm4 = shuffle dwords of xmm4 by 0x4E
# asm 1: pshufd $0x4E,<xmm4=int6464#5,>xmm4=int6464#5
# asm 2: pshufd $0x4E,<xmm4=%xmm4,>xmm4=%xmm4
pshufd $0x4E,%xmm4,%xmm4

# qhasm:     xmm6 = shuffle dwords of xmm6 by 0x4E
# asm 1: pshufd $0x4E,<xmm6=int6464#7,>xmm6=int6464#7
# asm 2: pshufd $0x4E,<xmm6=%xmm6,>xmm6=%xmm6
pshufd $0x4E,%xmm6,%xmm6

# qhasm:     xmm3 = shuffle dwords of xmm3 by 0x4E
# asm 1: pshufd $0x4E,<xmm3=int6464#4,>xmm3=int6464#4
# asm 2: pshufd $0x4E,<xmm3=%xmm3,>xmm3=%xmm3
pshufd $0x4E,%xmm3,%xmm3

# qhasm:     xmm7 = shuffle dwords of xmm7 by 0x4E
# asm 1: pshufd $0x4E,<xmm7=int6464#8,>xmm7=int6464#8
# asm 2: pshufd $0x4E,<xmm7=%xmm7,>xmm7=%xmm7
pshufd $0x4E,%xmm7,%xmm7

# qhasm:     xmm2 = shuffle dwords of xmm2 by 0x4E
# asm 1: pshufd $0x4E,<xmm2=int6464#3,>xmm2=int6464#3
# asm 2: pshufd $0x4E,<xmm2=%xmm2,>xmm2=%xmm2
pshufd $0x4E,%xmm2,%xmm2

# qhasm:     xmm5 = shuffle dwords of xmm5 by 0x4E
# asm 1: pshufd $0x4E,<xmm5=int6464#6,>xmm5=int6464#6
# asm 2: pshufd $0x4E,<xmm5=%xmm5,>xmm5=%xmm5
pshufd $0x4E,%xmm5,%xmm5

# qhasm:     xmm8 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:     xmm9 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm9=int6464#10
# asm 2: pxor  <xmm1=%xmm1,<xmm9=%xmm9
pxor  %xmm1,%xmm9

# qhasm:     xmm10 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm10=int6464#11
# asm 2: pxor  <xmm4=%xmm4,<xmm10=%xmm10
pxor  %xmm4,%xmm10

# qhasm:     xmm11 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm11=int6464#12
# asm 2: pxor  <xmm6=%xmm6,<xmm11=%xmm11
pxor  %xmm6,%xmm11

# qhasm:     xmm12 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm12=int6464#13
# asm 2: pxor  <xmm3=%xmm3,<xmm12=%xmm12
pxor  %xmm3,%xmm12

# qhasm:     xmm13 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm13=int6464#14
# asm 2: pxor  <xmm7=%xmm7,<xmm13=%xmm13
pxor  %xmm7,%xmm13

# qhasm:     xmm14 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm14=int6464#15
# asm 2: pxor  <xmm2=%xmm2,<xmm14=%xmm14
pxor  %xmm2,%xmm14

# qhasm:     xmm15 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm15=int6464#16
# asm 2: pxor  <xmm5=%xmm5,<xmm15=%xmm15
pxor  %xmm5,%xmm15

# qhasm:     xmm8 ^= *(int128 *)(c + 896)
# asm 1: pxor 896(<c=int64#4),<xmm8=int6464#9
# asm 2: pxor 896(<c=%rcx),<xmm8=%xmm8
pxor 896(%rcx),%xmm8

# qhasm:     shuffle bytes of xmm8 by SR
# asm 1: pshufb SR,<xmm8=int6464#9
# asm 2: pshufb SR,<xmm8=%xmm8
pshufb SR,%xmm8

# qhasm:     xmm9 ^= *(int128 *)(c + 912)
# asm 1: pxor 912(<c=int64#4),<xmm9=int6464#10
# asm 2: pxor 912(<c=%rcx),<xmm9=%xmm9
pxor 912(%rcx),%xmm9

# qhasm:     shuffle bytes of xmm9 by SR
# asm 1: pshufb SR,<xmm9=int6464#10
# asm 2: pshufb SR,<xmm9=%xmm9
pshufb SR,%xmm9

# qhasm:     xmm10 ^= *(int128 *)(c + 928)
# asm 1: pxor 928(<c=int64#4),<xmm10=int6464#11
# asm 2: pxor 928(<c=%rcx),<xmm10=%xmm10
pxor 928(%rcx),%xmm10

# qhasm:     shuffle bytes of xmm10 by SR
# asm 1: pshufb SR,<xmm10=int6464#11
# asm 2: pshufb SR,<xmm10=%xmm10
pshufb SR,%xmm10

# qhasm:     xmm11 ^= *(int128 *)(c + 944)
# asm 1: pxor 944(<c=int64#4),<xmm11=int6464#12
# asm 2: pxor 944(<c=%rcx),<xmm11=%xmm11
pxor 944(%rcx),%xmm11

# qhasm:     shuffle bytes of xmm11 by SR
# asm 1: pshufb SR,<xmm11=int6464#12
# asm 2: pshufb SR,<xmm11=%xmm11
pshufb SR,%xmm11

# qhasm:     xmm12 ^= *(int128 *)(c + 960)
# asm 1: pxor 960(<c=int64#4),<xmm12=int6464#13
# asm 2: pxor 960(<c=%rcx),<xmm12=%xmm12
pxor 960(%rcx),%xmm12

# qhasm:     shuffle bytes of xmm12 by SR
# asm 1: pshufb SR,<xmm12=int6464#13
# asm 2: pshufb SR,<xmm12=%xmm12
pshufb SR,%xmm12

# qhasm:     xmm13 ^= *(int128 *)(c + 976)
# asm 1: pxor 976(<c=int64#4),<xmm13=int6464#14
# asm 2: pxor 976(<c=%rcx),<xmm13=%xmm13
pxor 976(%rcx),%xmm13

# qhasm:     shuffle bytes of xmm13 by SR
# asm 1: pshufb SR,<xmm13=int6464#14
# asm 2: pshufb SR,<xmm13=%xmm13
pshufb SR,%xmm13

# qhasm:     xmm14 ^= *(int128 *)(c + 992)
# asm 1: pxor 992(<c=int64#4),<xmm14=int6464#15
# asm 2: pxor 992(<c=%rcx),<xmm14=%xmm14
pxor 992(%rcx),%xmm14

# qhasm:     shuffle bytes of xmm14 by SR
# asm 1: pshufb SR,<xmm14=int6464#15
# asm 2: pshufb SR,<xmm14=%xmm14
pshufb SR,%xmm14

# qhasm:     xmm15 ^= *(int128 *)(c + 1008)
# asm 1: pxor 1008(<c=int64#4),<xmm15=int6464#16
# asm 2: pxor 1008(<c=%rcx),<xmm15=%xmm15
pxor 1008(%rcx),%xmm15

# qhasm:     shuffle bytes of xmm15 by SR
# asm 1: pshufb SR,<xmm15=int6464#16
# asm 2: pshufb SR,<xmm15=%xmm15
pshufb SR,%xmm15

# qhasm:       xmm13 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm13=int6464#14
# asm 2: pxor  <xmm14=%xmm14,<xmm13=%xmm13
pxor  %xmm14,%xmm13

# qhasm:       xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm9,<xmm10=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm13=int6464#14
# asm 2: pxor  <xmm8=%xmm8,<xmm13=%xmm13
pxor  %xmm8,%xmm13

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm14=int6464#15
# asm 2: pxor  <xmm10=%xmm10,<xmm14=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm11=int6464#12
# asm 2: pxor  <xmm8=%xmm8,<xmm11=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm14=int6464#15
# asm 2: pxor  <xmm11=%xmm11,<xmm14=%xmm14
pxor  %xmm11,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#12
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm11
pxor  %xmm15,%xmm11

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm11=int6464#12
# asm 2: pxor  <xmm12=%xmm12,<xmm11=%xmm11
pxor  %xmm12,%xmm11

# qhasm:       xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm15=int6464#16
# asm 2: pxor  <xmm13=%xmm13,<xmm15=%xmm15
pxor  %xmm13,%xmm15

# qhasm:       xmm11 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm11=int6464#12
# asm 2: pxor  <xmm9=%xmm9,<xmm11=%xmm11
pxor  %xmm9,%xmm11

# qhasm:       xmm12 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm12=int6464#13
# asm 2: pxor  <xmm13=%xmm13,<xmm12=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm10 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm10=int6464#11
# asm 2: pxor  <xmm15=%xmm15,<xmm10=%xmm10
pxor  %xmm15,%xmm10

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm9=int6464#10
# asm 2: pxor  <xmm13=%xmm13,<xmm9=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm3 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm3=int6464#1
# asm 2: movdqa <xmm15=%xmm15,>xmm3=%xmm0
movdqa %xmm15,%xmm0

# qhasm:       xmm2 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm2=int6464#2
# asm 2: movdqa <xmm9=%xmm9,>xmm2=%xmm1
movdqa %xmm9,%xmm1

# qhasm:       xmm1 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm1=int6464#3
# asm 2: movdqa <xmm13=%xmm13,>xmm1=%xmm2
movdqa %xmm13,%xmm2

# qhasm:       xmm5 = xmm10
# asm 1: movdqa <xmm10=int6464#11,>xmm5=int6464#4
# asm 2: movdqa <xmm10=%xmm10,>xmm5=%xmm3
movdqa %xmm10,%xmm3

# qhasm:       xmm4 = xmm14
# asm 1: movdqa <xmm14=int6464#15,>xmm4=int6464#5
# asm 2: movdqa <xmm14=%xmm14,>xmm4=%xmm4
movdqa %xmm14,%xmm4

# qhasm:       xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#1
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm0
pxor  %xmm12,%xmm0

# qhasm:       xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#2
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm1
pxor  %xmm10,%xmm1

# qhasm:       xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm1=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm1=%xmm2
pxor  %xmm11,%xmm2

# qhasm:       xmm5 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm5=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm5=%xmm3
pxor  %xmm12,%xmm3

# qhasm:       xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:       xmm6 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm6=int6464#6
# asm 2: movdqa <xmm3=%xmm0,>xmm6=%xmm5
movdqa %xmm0,%xmm5

# qhasm:       xmm0 = xmm2
# asm 1: movdqa <xmm2=int6464#2,>xmm0=int6464#7
# asm 2: movdqa <xmm2=%xmm1,>xmm0=%xmm6
movdqa %xmm1,%xmm6

# qhasm:       xmm7 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm7=int6464#8
# asm 2: movdqa <xmm3=%xmm0,>xmm7=%xmm7
movdqa %xmm0,%xmm7

# qhasm:       xmm2 |= xmm1
# asm 1: por   <xmm1=int6464#3,<xmm2=int6464#2
# asm 2: por   <xmm1=%xmm2,<xmm2=%xmm1
por   %xmm2,%xmm1

# qhasm:       xmm3 |= xmm4
# asm 1: por   <xmm4=int6464#5,<xmm3=int6464#1
# asm 2: por   <xmm4=%xmm4,<xmm3=%xmm0
por   %xmm4,%xmm0

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm7=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm6 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm6=int6464#6
# asm 2: pand  <xmm4=%xmm4,<xmm6=%xmm5
pand  %xmm4,%xmm5

# qhasm:       xmm0 &= xmm1
# asm 1: pand  <xmm1=int6464#3,<xmm0=int6464#7
# asm 2: pand  <xmm1=%xmm2,<xmm0=%xmm6
pand  %xmm2,%xmm6

# qhasm:       xmm4 ^= xmm1
# asm 1: pxor  <xmm1=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm1=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:       xmm7 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm7=int6464#8
# asm 2: pand  <xmm4=%xmm4,<xmm7=%xmm7
pand  %xmm4,%xmm7

# qhasm:       xmm4 = xmm11
# asm 1: movdqa <xmm11=int6464#12,>xmm4=int6464#3
# asm 2: movdqa <xmm11=%xmm11,>xmm4=%xmm2
movdqa %xmm11,%xmm2

# qhasm:       xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#3
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm2
pxor  %xmm8,%xmm2

# qhasm:       xmm5 &= xmm4
# asm 1: pand  <xmm4=int6464#3,<xmm5=int6464#4
# asm 2: pand  <xmm4=%xmm2,<xmm5=%xmm3
pand  %xmm2,%xmm3

# qhasm:       xmm3 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm3=int6464#1
# asm 2: pxor  <xmm5=%xmm3,<xmm3=%xmm0
pxor  %xmm3,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm2=int6464#2
# asm 2: pxor  <xmm5=%xmm3,<xmm2=%xmm1
pxor  %xmm3,%xmm1

# qhasm:       xmm5 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm5=int6464#3
# asm 2: movdqa <xmm15=%xmm15,>xmm5=%xmm2
movdqa %xmm15,%xmm2

# qhasm:       xmm5 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm5=int6464#3
# asm 2: pxor  <xmm9=%xmm9,<xmm5=%xmm2
pxor  %xmm9,%xmm2

# qhasm:       xmm4 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm4=int6464#4
# asm 2: movdqa <xmm13=%xmm13,>xmm4=%xmm3
movdqa %xmm13,%xmm3

# qhasm:       xmm1 = xmm5
# asm 1: movdqa <xmm5=int6464#3,>xmm1=int6464#5
# asm 2: movdqa <xmm5=%xmm2,>xmm1=%xmm4
movdqa %xmm2,%xmm4

# qhasm:       xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm3
pxor  %xmm14,%xmm3

# qhasm:       xmm1 |= xmm4
# asm 1: por   <xmm4=int6464#4,<xmm1=int6464#5
# asm 2: por   <xmm4=%xmm3,<xmm1=%xmm4
por   %xmm3,%xmm4

# qhasm:       xmm5 &= xmm4
# asm 1: pand  <xmm4=int6464#4,<xmm5=int6464#3
# asm 2: pand  <xmm4=%xmm3,<xmm5=%xmm2
pand  %xmm3,%xmm2

# qhasm:       xmm0 ^= xmm5
# asm 1: pxor  <xmm5=int6464#3,<xmm0=int6464#7
# asm 2: pxor  <xmm5=%xmm2,<xmm0=%xmm6
pxor  %xmm2,%xmm6

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#1
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm0
pxor  %xmm7,%xmm0

# qhasm:       xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm2=int6464#2
# asm 2: pxor  <xmm6=%xmm5,<xmm2=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#5
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm0 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm0=int6464#7
# asm 2: pxor  <xmm6=%xmm5,<xmm0=%xmm6
pxor  %xmm5,%xmm6

# qhasm:       xmm1 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm1=int6464#5
# asm 2: pxor  <xmm6=%xmm5,<xmm1=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm4 = xmm10
# asm 1: movdqa <xmm10=int6464#11,>xmm4=int6464#3
# asm 2: movdqa <xmm10=%xmm10,>xmm4=%xmm2
movdqa %xmm10,%xmm2

# qhasm:       xmm5 = xmm12
# asm 1: movdqa <xmm12=int6464#13,>xmm5=int6464#4
# asm 2: movdqa <xmm12=%xmm12,>xmm5=%xmm3
movdqa %xmm12,%xmm3

# qhasm:       xmm6 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm6=int6464#6
# asm 2: movdqa <xmm9=%xmm9,>xmm6=%xmm5
movdqa %xmm9,%xmm5

# qhasm:       xmm7 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm7=int6464#8
# asm 2: movdqa <xmm15=%xmm15,>xmm7=%xmm7
movdqa %xmm15,%xmm7

# qhasm:       xmm4 &= xmm11
# asm 1: pand  <xmm11=int6464#12,<xmm4=int6464#3
# asm 2: pand  <xmm11=%xmm11,<xmm4=%xmm2
pand  %xmm11,%xmm2

# qhasm:       xmm5 &= xmm8
# asm 1: pand  <xmm8=int6464#9,<xmm5=int6464#4
# asm 2: pand  <xmm8=%xmm8,<xmm5=%xmm3
pand  %xmm8,%xmm3

# qhasm:       xmm6 &= xmm13
# asm 1: pand  <xmm13=int6464#14,<xmm6=int6464#6
# asm 2: pand  <xmm13=%xmm13,<xmm6=%xmm5
pand  %xmm13,%xmm5

# qhasm:       xmm7 |= xmm14
# asm 1: por   <xmm14=int6464#15,<xmm7=int6464#8
# asm 2: por   <xmm14=%xmm14,<xmm7=%xmm7
por   %xmm14,%xmm7

# qhasm:       xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#3,<xmm3=int6464#1
# asm 2: pxor  <xmm4=%xmm2,<xmm3=%xmm0
pxor  %xmm2,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm2=int6464#2
# asm 2: pxor  <xmm5=%xmm3,<xmm2=%xmm1
pxor  %xmm3,%xmm1

# qhasm:       xmm1 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm1=int6464#5
# asm 2: pxor  <xmm6=%xmm5,<xmm1=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm0 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm0=int6464#7
# asm 2: pxor  <xmm7=%xmm7,<xmm0=%xmm6
pxor  %xmm7,%xmm6

# qhasm:       xmm4 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm4=int6464#3
# asm 2: movdqa <xmm3=%xmm0,>xmm4=%xmm2
movdqa %xmm0,%xmm2

# qhasm:       xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm4=int6464#3
# asm 2: pxor  <xmm2=%xmm1,<xmm4=%xmm2
pxor  %xmm1,%xmm2

# qhasm:       xmm3 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm3=int6464#1
# asm 2: pand  <xmm1=%xmm4,<xmm3=%xmm0
pand  %xmm4,%xmm0

# qhasm:       xmm6 = xmm0
# asm 1: movdqa <xmm0=int6464#7,>xmm6=int6464#4
# asm 2: movdqa <xmm0=%xmm6,>xmm6=%xmm3
movdqa %xmm6,%xmm3

# qhasm:       xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#1,<xmm6=int6464#4
# asm 2: pxor  <xmm3=%xmm0,<xmm6=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm7 = xmm4
# asm 1: movdqa <xmm4=int6464#3,>xmm7=int6464#6
# asm 2: movdqa <xmm4=%xmm2,>xmm7=%xmm5
movdqa %xmm2,%xmm5

# qhasm:       xmm7 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm7=int6464#6
# asm 2: pand  <xmm6=%xmm3,<xmm7=%xmm5
pand  %xmm3,%xmm5

# qhasm:       xmm7 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm7=int6464#6
# asm 2: pxor  <xmm2=%xmm1,<xmm7=%xmm5
pxor  %xmm1,%xmm5

# qhasm:       xmm5 = xmm1
# asm 1: movdqa <xmm1=int6464#5,>xmm5=int6464#8
# asm 2: movdqa <xmm1=%xmm4,>xmm5=%xmm7
movdqa %xmm4,%xmm7

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm5=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm5=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm3 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm3=int6464#1
# asm 2: pxor  <xmm2=%xmm1,<xmm3=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm5 &= xmm3
# asm 1: pand  <xmm3=int6464#1,<xmm5=int6464#8
# asm 2: pand  <xmm3=%xmm0,<xmm5=%xmm7
pand  %xmm0,%xmm7

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm5=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm5=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm1=int6464#5
# asm 2: pxor  <xmm5=%xmm7,<xmm1=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm2 = xmm6
# asm 1: movdqa <xmm6=int6464#4,>xmm2=int6464#1
# asm 2: movdqa <xmm6=%xmm3,>xmm2=%xmm0
movdqa %xmm3,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm2=int6464#1
# asm 2: pxor  <xmm5=%xmm7,<xmm2=%xmm0
pxor  %xmm7,%xmm0

# qhasm:       xmm2 &= xmm0
# asm 1: pand  <xmm0=int6464#7,<xmm2=int6464#1
# asm 2: pand  <xmm0=%xmm6,<xmm2=%xmm0
pand  %xmm6,%xmm0

# qhasm:       xmm1 ^= xmm2
# asm 1: pxor  <xmm2=int6464#1,<xmm1=int6464#5
# asm 2: pxor  <xmm2=%xmm0,<xmm1=%xmm4
pxor  %xmm0,%xmm4

# qhasm:       xmm6 ^= xmm2
# asm 1: pxor  <xmm2=int6464#1,<xmm6=int6464#4
# asm 2: pxor  <xmm2=%xmm0,<xmm6=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm6 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm6=int6464#4
# asm 2: pand  <xmm7=%xmm5,<xmm6=%xmm3
pand  %xmm5,%xmm3

# qhasm:       xmm6 ^= xmm4
# asm 1: pxor  <xmm4=int6464#3,<xmm6=int6464#4
# asm 2: pxor  <xmm4=%xmm2,<xmm6=%xmm3
pxor  %xmm2,%xmm3

# qhasm:         xmm4 = xmm14
# asm 1: movdqa <xmm14=int6464#15,>xmm4=int6464#1
# asm 2: movdqa <xmm14=%xmm14,>xmm4=%xmm0
movdqa %xmm14,%xmm0

# qhasm:         xmm0 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm0=int6464#2
# asm 2: movdqa <xmm13=%xmm13,>xmm0=%xmm1
movdqa %xmm13,%xmm1

# qhasm:           xmm2 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm2=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm2=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm2=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm2 &= xmm14
# asm 1: pand  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pand  <xmm14=%xmm14,<xmm2=%xmm2
pand  %xmm14,%xmm2

# qhasm:           xmm14 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm14=int6464#15
# asm 2: pxor  <xmm13=%xmm13,<xmm14=%xmm14
pxor  %xmm13,%xmm14

# qhasm:           xmm14 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm14=int6464#15
# asm 2: pand  <xmm6=%xmm3,<xmm14=%xmm14
pand  %xmm3,%xmm14

# qhasm:           xmm13 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm13=int6464#14
# asm 2: pand  <xmm7=%xmm5,<xmm13=%xmm13
pand  %xmm5,%xmm13

# qhasm:           xmm14 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm14=int6464#15
# asm 2: pxor  <xmm13=%xmm13,<xmm14=%xmm14
pxor  %xmm13,%xmm14

# qhasm:           xmm13 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm13=int6464#14
# asm 2: pxor  <xmm2=%xmm2,<xmm13=%xmm13
pxor  %xmm2,%xmm13

# qhasm:         xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm0 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm0=int6464#2
# asm 2: pxor  <xmm11=%xmm11,<xmm0=%xmm1
pxor  %xmm11,%xmm1

# qhasm:         xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm7=int6464#6
# asm 2: pxor  <xmm5=%xmm7,<xmm7=%xmm5
pxor  %xmm7,%xmm5

# qhasm:         xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm6=int6464#4
# asm 2: pxor  <xmm1=%xmm4,<xmm6=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm4
# asm 1: pand  <xmm4=int6464#1,<xmm3=int6464#3
# asm 2: pand  <xmm4=%xmm0,<xmm3=%xmm2
pand  %xmm0,%xmm2

# qhasm:           xmm4 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm4=int6464#1
# asm 2: pxor  <xmm0=%xmm1,<xmm4=%xmm0
pxor  %xmm1,%xmm0

# qhasm:           xmm4 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm4=int6464#1
# asm 2: pand  <xmm6=%xmm3,<xmm4=%xmm0
pand  %xmm3,%xmm0

# qhasm:           xmm0 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm0=int6464#2
# asm 2: pand  <xmm7=%xmm5,<xmm0=%xmm1
pand  %xmm5,%xmm1

# qhasm:           xmm0 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm0=int6464#2
# asm 2: pxor  <xmm4=%xmm0,<xmm0=%xmm1
pxor  %xmm0,%xmm1

# qhasm:           xmm4 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm4=int6464#1
# asm 2: pxor  <xmm3=%xmm2,<xmm4=%xmm0
pxor  %xmm2,%xmm0

# qhasm:           xmm2 = xmm5
# asm 1: movdqa <xmm5=int6464#8,>xmm2=int6464#3
# asm 2: movdqa <xmm5=%xmm7,>xmm2=%xmm2
movdqa %xmm7,%xmm2

# qhasm:           xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm4,<xmm2=%xmm2
pxor  %xmm4,%xmm2

# qhasm:           xmm2 &= xmm8
# asm 1: pand  <xmm8=int6464#9,<xmm2=int6464#3
# asm 2: pand  <xmm8=%xmm8,<xmm2=%xmm2
pand  %xmm8,%xmm2

# qhasm:           xmm8 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm8=int6464#9
# asm 2: pxor  <xmm11=%xmm11,<xmm8=%xmm8
pxor  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm8=int6464#9
# asm 2: pand  <xmm1=%xmm4,<xmm8=%xmm8
pand  %xmm4,%xmm8

# qhasm:           xmm11 &= xmm5
# asm 1: pand  <xmm5=int6464#8,<xmm11=int6464#12
# asm 2: pand  <xmm5=%xmm7,<xmm11=%xmm11
pand  %xmm7,%xmm11

# qhasm:           xmm8 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm8=int6464#9
# asm 2: pxor  <xmm11=%xmm11,<xmm8=%xmm8
pxor  %xmm11,%xmm8

# qhasm:           xmm11 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm11=int6464#12
# asm 2: pxor  <xmm2=%xmm2,<xmm11=%xmm11
pxor  %xmm2,%xmm11

# qhasm:         xmm14 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm14=int6464#15
# asm 2: pxor  <xmm4=%xmm0,<xmm14=%xmm14
pxor  %xmm0,%xmm14

# qhasm:         xmm8 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm4=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm13 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm13=int6464#14
# asm 2: pxor  <xmm0=%xmm1,<xmm13=%xmm13
pxor  %xmm1,%xmm13

# qhasm:         xmm11 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm11=int6464#12
# asm 2: pxor  <xmm0=%xmm1,<xmm11=%xmm11
pxor  %xmm1,%xmm11

# qhasm:         xmm4 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm4=int6464#1
# asm 2: movdqa <xmm15=%xmm15,>xmm4=%xmm0
movdqa %xmm15,%xmm0

# qhasm:         xmm0 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm0=int6464#2
# asm 2: movdqa <xmm9=%xmm9,>xmm0=%xmm1
movdqa %xmm9,%xmm1

# qhasm:         xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm4=int6464#1
# asm 2: pxor  <xmm12=%xmm12,<xmm4=%xmm0
pxor  %xmm12,%xmm0

# qhasm:         xmm0 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm0=int6464#2
# asm 2: pxor  <xmm10=%xmm10,<xmm0=%xmm1
pxor  %xmm10,%xmm1

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm4
# asm 1: pand  <xmm4=int6464#1,<xmm3=int6464#3
# asm 2: pand  <xmm4=%xmm0,<xmm3=%xmm2
pand  %xmm0,%xmm2

# qhasm:           xmm4 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm4=int6464#1
# asm 2: pxor  <xmm0=%xmm1,<xmm4=%xmm0
pxor  %xmm1,%xmm0

# qhasm:           xmm4 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm4=int6464#1
# asm 2: pand  <xmm6=%xmm3,<xmm4=%xmm0
pand  %xmm3,%xmm0

# qhasm:           xmm0 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm0=int6464#2
# asm 2: pand  <xmm7=%xmm5,<xmm0=%xmm1
pand  %xmm5,%xmm1

# qhasm:           xmm0 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm0=int6464#2
# asm 2: pxor  <xmm4=%xmm0,<xmm0=%xmm1
pxor  %xmm0,%xmm1

# qhasm:           xmm4 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm4=int6464#1
# asm 2: pxor  <xmm3=%xmm2,<xmm4=%xmm0
pxor  %xmm2,%xmm0

# qhasm:           xmm2 = xmm5
# asm 1: movdqa <xmm5=int6464#8,>xmm2=int6464#3
# asm 2: movdqa <xmm5=%xmm7,>xmm2=%xmm2
movdqa %xmm7,%xmm2

# qhasm:           xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm4,<xmm2=%xmm2
pxor  %xmm4,%xmm2

# qhasm:           xmm2 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pand  <xmm12=%xmm12,<xmm2=%xmm2
pand  %xmm12,%xmm2

# qhasm:           xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm10=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:           xmm12 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm12=int6464#13
# asm 2: pand  <xmm1=%xmm4,<xmm12=%xmm12
pand  %xmm4,%xmm12

# qhasm:           xmm10 &= xmm5
# asm 1: pand  <xmm5=int6464#8,<xmm10=int6464#11
# asm 2: pand  <xmm5=%xmm7,<xmm10=%xmm10
pand  %xmm7,%xmm10

# qhasm:           xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm10=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:           xmm10 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm10=int6464#11
# asm 2: pxor  <xmm2=%xmm2,<xmm10=%xmm10
pxor  %xmm2,%xmm10

# qhasm:         xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm7=int6464#6
# asm 2: pxor  <xmm5=%xmm7,<xmm7=%xmm5
pxor  %xmm7,%xmm5

# qhasm:         xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm6=int6464#4
# asm 2: pxor  <xmm1=%xmm4,<xmm6=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm15
# asm 1: pand  <xmm15=int6464#16,<xmm3=int6464#3
# asm 2: pand  <xmm15=%xmm15,<xmm3=%xmm2
pand  %xmm15,%xmm2

# qhasm:           xmm15 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm15=int6464#16
# asm 2: pxor  <xmm9=%xmm9,<xmm15=%xmm15
pxor  %xmm9,%xmm15

# qhasm:           xmm15 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm15=int6464#16
# asm 2: pand  <xmm6=%xmm3,<xmm15=%xmm15
pand  %xmm3,%xmm15

# qhasm:           xmm9 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm9=int6464#10
# asm 2: pand  <xmm7=%xmm5,<xmm9=%xmm9
pand  %xmm5,%xmm9

# qhasm:           xmm15 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm15=int6464#16
# asm 2: pxor  <xmm9=%xmm9,<xmm15=%xmm15
pxor  %xmm9,%xmm15

# qhasm:           xmm9 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm9=int6464#10
# asm 2: pxor  <xmm3=%xmm2,<xmm9=%xmm9
pxor  %xmm2,%xmm9

# qhasm:         xmm15 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm15=int6464#16
# asm 2: pxor  <xmm4=%xmm0,<xmm15=%xmm15
pxor  %xmm0,%xmm15

# qhasm:         xmm12 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm4=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:         xmm9 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm9=int6464#10
# asm 2: pxor  <xmm0=%xmm1,<xmm9=%xmm9
pxor  %xmm1,%xmm9

# qhasm:         xmm10 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm10=int6464#11
# asm 2: pxor  <xmm0=%xmm1,<xmm10=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm8,<xmm15=%xmm15
pxor  %xmm8,%xmm15

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm9=int6464#10
# asm 2: pxor  <xmm14=%xmm14,<xmm9=%xmm9
pxor  %xmm14,%xmm9

# qhasm:       xmm12 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm12=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm12=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm14 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm14=int6464#15
# asm 2: pxor  <xmm8=%xmm8,<xmm14=%xmm14
pxor  %xmm8,%xmm14

# qhasm:       xmm8 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm8=int6464#9
# asm 2: pxor  <xmm9=%xmm9,<xmm8=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm9=int6464#10
# asm 2: pxor  <xmm13=%xmm13,<xmm9=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm13 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm13=int6464#14
# asm 2: pxor  <xmm10=%xmm10,<xmm13=%xmm13
pxor  %xmm10,%xmm13

# qhasm:       xmm12 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm12=int6464#13
# asm 2: pxor  <xmm13=%xmm13,<xmm12=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm10 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm11=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm11=int6464#12
# asm 2: pxor  <xmm13=%xmm13,<xmm11=%xmm11
pxor  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm14=int6464#15
# asm 2: pxor  <xmm11=%xmm11,<xmm14=%xmm14
pxor  %xmm11,%xmm14

# qhasm:     xmm0 = shuffle dwords of xmm8 by 0x93
# asm 1: pshufd $0x93,<xmm8=int6464#9,>xmm0=int6464#1
# asm 2: pshufd $0x93,<xmm8=%xmm8,>xmm0=%xmm0
pshufd $0x93,%xmm8,%xmm0

# qhasm:     xmm1 = shuffle dwords of xmm9 by 0x93
# asm 1: pshufd $0x93,<xmm9=int6464#10,>xmm1=int6464#2
# asm 2: pshufd $0x93,<xmm9=%xmm9,>xmm1=%xmm1
pshufd $0x93,%xmm9,%xmm1

# qhasm:     xmm2 = shuffle dwords of xmm12 by 0x93
# asm 1: pshufd $0x93,<xmm12=int6464#13,>xmm2=int6464#3
# asm 2: pshufd $0x93,<xmm12=%xmm12,>xmm2=%xmm2
pshufd $0x93,%xmm12,%xmm2

# qhasm:     xmm3 = shuffle dwords of xmm14 by 0x93
# asm 1: pshufd $0x93,<xmm14=int6464#15,>xmm3=int6464#4
# asm 2: pshufd $0x93,<xmm14=%xmm14,>xmm3=%xmm3
pshufd $0x93,%xmm14,%xmm3

# qhasm:     xmm4 = shuffle dwords of xmm11 by 0x93
# asm 1: pshufd $0x93,<xmm11=int6464#12,>xmm4=int6464#5
# asm 2: pshufd $0x93,<xmm11=%xmm11,>xmm4=%xmm4
pshufd $0x93,%xmm11,%xmm4

# qhasm:     xmm5 = shuffle dwords of xmm15 by 0x93
# asm 1: pshufd $0x93,<xmm15=int6464#16,>xmm5=int6464#6
# asm 2: pshufd $0x93,<xmm15=%xmm15,>xmm5=%xmm5
pshufd $0x93,%xmm15,%xmm5

# qhasm:     xmm6 = shuffle dwords of xmm10 by 0x93
# asm 1: pshufd $0x93,<xmm10=int6464#11,>xmm6=int6464#7
# asm 2: pshufd $0x93,<xmm10=%xmm10,>xmm6=%xmm6
pshufd $0x93,%xmm10,%xmm6

# qhasm:     xmm7 = shuffle dwords of xmm13 by 0x93
# asm 1: pshufd $0x93,<xmm13=int6464#14,>xmm7=int6464#8
# asm 2: pshufd $0x93,<xmm13=%xmm13,>xmm7=%xmm7
pshufd $0x93,%xmm13,%xmm7

# qhasm:     xmm8 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:     xmm9 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm9=int6464#10
# asm 2: pxor  <xmm1=%xmm1,<xmm9=%xmm9
pxor  %xmm1,%xmm9

# qhasm:     xmm12 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm12=int6464#13
# asm 2: pxor  <xmm2=%xmm2,<xmm12=%xmm12
pxor  %xmm2,%xmm12

# qhasm:     xmm14 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm14=int6464#15
# asm 2: pxor  <xmm3=%xmm3,<xmm14=%xmm14
pxor  %xmm3,%xmm14

# qhasm:     xmm11 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm11=int6464#12
# asm 2: pxor  <xmm4=%xmm4,<xmm11=%xmm11
pxor  %xmm4,%xmm11

# qhasm:     xmm15 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm15=int6464#16
# asm 2: pxor  <xmm5=%xmm5,<xmm15=%xmm15
pxor  %xmm5,%xmm15

# qhasm:     xmm10 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm10=int6464#11
# asm 2: pxor  <xmm6=%xmm6,<xmm10=%xmm10
pxor  %xmm6,%xmm10

# qhasm:     xmm13 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm13=int6464#14
# asm 2: pxor  <xmm7=%xmm7,<xmm13=%xmm13
pxor  %xmm7,%xmm13

# qhasm:     xmm0 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm0=int6464#1
# asm 2: pxor  <xmm13=%xmm13,<xmm0=%xmm0
pxor  %xmm13,%xmm0

# qhasm:     xmm1 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm1=int6464#2
# asm 2: pxor  <xmm8=%xmm8,<xmm1=%xmm1
pxor  %xmm8,%xmm1

# qhasm:     xmm2 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm2=int6464#3
# asm 2: pxor  <xmm9=%xmm9,<xmm2=%xmm2
pxor  %xmm9,%xmm2

# qhasm:     xmm1 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm1=int6464#2
# asm 2: pxor  <xmm13=%xmm13,<xmm1=%xmm1
pxor  %xmm13,%xmm1

# qhasm:     xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:     xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#5
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm4
pxor  %xmm14,%xmm4

# qhasm:     xmm5 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm5=int6464#6
# asm 2: pxor  <xmm11=%xmm11,<xmm5=%xmm5
pxor  %xmm11,%xmm5

# qhasm:     xmm3 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm3=int6464#4
# asm 2: pxor  <xmm13=%xmm13,<xmm3=%xmm3
pxor  %xmm13,%xmm3

# qhasm:     xmm6 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm6=int6464#7
# asm 2: pxor  <xmm15=%xmm15,<xmm6=%xmm6
pxor  %xmm15,%xmm6

# qhasm:     xmm7 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm7=int6464#8
# asm 2: pxor  <xmm10=%xmm10,<xmm7=%xmm7
pxor  %xmm10,%xmm7

# qhasm:     xmm4 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm4=int6464#5
# asm 2: pxor  <xmm13=%xmm13,<xmm4=%xmm4
pxor  %xmm13,%xmm4

# qhasm:     xmm8 = shuffle dwords of xmm8 by 0x4E
# asm 1: pshufd $0x4E,<xmm8=int6464#9,>xmm8=int6464#9
# asm 2: pshufd $0x4E,<xmm8=%xmm8,>xmm8=%xmm8
pshufd $0x4E,%xmm8,%xmm8

# qhasm:     xmm9 = shuffle dwords of xmm9 by 0x4E
# asm 1: pshufd $0x4E,<xmm9=int6464#10,>xmm9=int6464#10
# asm 2: pshufd $0x4E,<xmm9=%xmm9,>xmm9=%xmm9
pshufd $0x4E,%xmm9,%xmm9

# qhasm:     xmm12 = shuffle dwords of xmm12 by 0x4E
# asm 1: pshufd $0x4E,<xmm12=int6464#13,>xmm12=int6464#13
# asm 2: pshufd $0x4E,<xmm12=%xmm12,>xmm12=%xmm12
pshufd $0x4E,%xmm12,%xmm12

# qhasm:     xmm14 = shuffle dwords of xmm14 by 0x4E
# asm 1: pshufd $0x4E,<xmm14=int6464#15,>xmm14=int6464#15
# asm 2: pshufd $0x4E,<xmm14=%xmm14,>xmm14=%xmm14
pshufd $0x4E,%xmm14,%xmm14

# qhasm:     xmm11 = shuffle dwords of xmm11 by 0x4E
# asm 1: pshufd $0x4E,<xmm11=int6464#12,>xmm11=int6464#12
# asm 2: pshufd $0x4E,<xmm11=%xmm11,>xmm11=%xmm11
pshufd $0x4E,%xmm11,%xmm11

# qhasm:     xmm15 = shuffle dwords of xmm15 by 0x4E
# asm 1: pshufd $0x4E,<xmm15=int6464#16,>xmm15=int6464#16
# asm 2: pshufd $0x4E,<xmm15=%xmm15,>xmm15=%xmm15
pshufd $0x4E,%xmm15,%xmm15

# qhasm:     xmm10 = shuffle dwords of xmm10 by 0x4E
# asm 1: pshufd $0x4E,<xmm10=int6464#11,>xmm10=int6464#11
# asm 2: pshufd $0x4E,<xmm10=%xmm10,>xmm10=%xmm10
pshufd $0x4E,%xmm10,%xmm10

# qhasm:     xmm13 = shuffle dwords of xmm13 by 0x4E
# asm 1: pshufd $0x4E,<xmm13=int6464#14,>xmm13=int6464#14
# asm 2: pshufd $0x4E,<xmm13=%xmm13,>xmm13=%xmm13
pshufd $0x4E,%xmm13,%xmm13

# qhasm:     xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:     xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:     xmm2 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pxor  <xmm12=%xmm12,<xmm2=%xmm2
pxor  %xmm12,%xmm2

# qhasm:     xmm3 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm3=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm3=%xmm3
pxor  %xmm14,%xmm3

# qhasm:     xmm4 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm4=int6464#5
# asm 2: pxor  <xmm11=%xmm11,<xmm4=%xmm4
pxor  %xmm11,%xmm4

# qhasm:     xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:     xmm6 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm6=int6464#7
# asm 2: pxor  <xmm10=%xmm10,<xmm6=%xmm6
pxor  %xmm10,%xmm6

# qhasm:     xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:     xmm0 ^= *(int128 *)(c + 1024)
# asm 1: pxor 1024(<c=int64#4),<xmm0=int6464#1
# asm 2: pxor 1024(<c=%rcx),<xmm0=%xmm0
pxor 1024(%rcx),%xmm0

# qhasm:     shuffle bytes of xmm0 by SR
# asm 1: pshufb SR,<xmm0=int6464#1
# asm 2: pshufb SR,<xmm0=%xmm0
pshufb SR,%xmm0

# qhasm:     xmm1 ^= *(int128 *)(c + 1040)
# asm 1: pxor 1040(<c=int64#4),<xmm1=int6464#2
# asm 2: pxor 1040(<c=%rcx),<xmm1=%xmm1
pxor 1040(%rcx),%xmm1

# qhasm:     shuffle bytes of xmm1 by SR
# asm 1: pshufb SR,<xmm1=int6464#2
# asm 2: pshufb SR,<xmm1=%xmm1
pshufb SR,%xmm1

# qhasm:     xmm2 ^= *(int128 *)(c + 1056)
# asm 1: pxor 1056(<c=int64#4),<xmm2=int6464#3
# asm 2: pxor 1056(<c=%rcx),<xmm2=%xmm2
pxor 1056(%rcx),%xmm2

# qhasm:     shuffle bytes of xmm2 by SR
# asm 1: pshufb SR,<xmm2=int6464#3
# asm 2: pshufb SR,<xmm2=%xmm2
pshufb SR,%xmm2

# qhasm:     xmm3 ^= *(int128 *)(c + 1072)
# asm 1: pxor 1072(<c=int64#4),<xmm3=int6464#4
# asm 2: pxor 1072(<c=%rcx),<xmm3=%xmm3
pxor 1072(%rcx),%xmm3

# qhasm:     shuffle bytes of xmm3 by SR
# asm 1: pshufb SR,<xmm3=int6464#4
# asm 2: pshufb SR,<xmm3=%xmm3
pshufb SR,%xmm3

# qhasm:     xmm4 ^= *(int128 *)(c + 1088)
# asm 1: pxor 1088(<c=int64#4),<xmm4=int6464#5
# asm 2: pxor 1088(<c=%rcx),<xmm4=%xmm4
pxor 1088(%rcx),%xmm4

# qhasm:     shuffle bytes of xmm4 by SR
# asm 1: pshufb SR,<xmm4=int6464#5
# asm 2: pshufb SR,<xmm4=%xmm4
pshufb SR,%xmm4

# qhasm:     xmm5 ^= *(int128 *)(c + 1104)
# asm 1: pxor 1104(<c=int64#4),<xmm5=int6464#6
# asm 2: pxor 1104(<c=%rcx),<xmm5=%xmm5
pxor 1104(%rcx),%xmm5

# qhasm:     shuffle bytes of xmm5 by SR
# asm 1: pshufb SR,<xmm5=int6464#6
# asm 2: pshufb SR,<xmm5=%xmm5
pshufb SR,%xmm5

# qhasm:     xmm6 ^= *(int128 *)(c + 1120)
# asm 1: pxor 1120(<c=int64#4),<xmm6=int6464#7
# asm 2: pxor 1120(<c=%rcx),<xmm6=%xmm6
pxor 1120(%rcx),%xmm6

# qhasm:     shuffle bytes of xmm6 by SR
# asm 1: pshufb SR,<xmm6=int6464#7
# asm 2: pshufb SR,<xmm6=%xmm6
pshufb SR,%xmm6

# qhasm:     xmm7 ^= *(int128 *)(c + 1136)
# asm 1: pxor 1136(<c=int64#4),<xmm7=int6464#8
# asm 2: pxor 1136(<c=%rcx),<xmm7=%xmm7
pxor 1136(%rcx),%xmm7

# qhasm:     shuffle bytes of xmm7 by SR
# asm 1: pshufb SR,<xmm7=int6464#8
# asm 2: pshufb SR,<xmm7=%xmm7
pshufb SR,%xmm7

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

# qhasm:     xmm8 = shuffle dwords of xmm0 by 0x93
# asm 1: pshufd $0x93,<xmm0=int6464#1,>xmm8=int6464#9
# asm 2: pshufd $0x93,<xmm0=%xmm0,>xmm8=%xmm8
pshufd $0x93,%xmm0,%xmm8

# qhasm:     xmm9 = shuffle dwords of xmm1 by 0x93
# asm 1: pshufd $0x93,<xmm1=int6464#2,>xmm9=int6464#10
# asm 2: pshufd $0x93,<xmm1=%xmm1,>xmm9=%xmm9
pshufd $0x93,%xmm1,%xmm9

# qhasm:     xmm10 = shuffle dwords of xmm4 by 0x93
# asm 1: pshufd $0x93,<xmm4=int6464#5,>xmm10=int6464#11
# asm 2: pshufd $0x93,<xmm4=%xmm4,>xmm10=%xmm10
pshufd $0x93,%xmm4,%xmm10

# qhasm:     xmm11 = shuffle dwords of xmm6 by 0x93
# asm 1: pshufd $0x93,<xmm6=int6464#7,>xmm11=int6464#12
# asm 2: pshufd $0x93,<xmm6=%xmm6,>xmm11=%xmm11
pshufd $0x93,%xmm6,%xmm11

# qhasm:     xmm12 = shuffle dwords of xmm3 by 0x93
# asm 1: pshufd $0x93,<xmm3=int6464#4,>xmm12=int6464#13
# asm 2: pshufd $0x93,<xmm3=%xmm3,>xmm12=%xmm12
pshufd $0x93,%xmm3,%xmm12

# qhasm:     xmm13 = shuffle dwords of xmm7 by 0x93
# asm 1: pshufd $0x93,<xmm7=int6464#8,>xmm13=int6464#14
# asm 2: pshufd $0x93,<xmm7=%xmm7,>xmm13=%xmm13
pshufd $0x93,%xmm7,%xmm13

# qhasm:     xmm14 = shuffle dwords of xmm2 by 0x93
# asm 1: pshufd $0x93,<xmm2=int6464#3,>xmm14=int6464#15
# asm 2: pshufd $0x93,<xmm2=%xmm2,>xmm14=%xmm14
pshufd $0x93,%xmm2,%xmm14

# qhasm:     xmm15 = shuffle dwords of xmm5 by 0x93
# asm 1: pshufd $0x93,<xmm5=int6464#6,>xmm15=int6464#16
# asm 2: pshufd $0x93,<xmm5=%xmm5,>xmm15=%xmm15
pshufd $0x93,%xmm5,%xmm15

# qhasm:     xmm0 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm0=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm0=%xmm0
pxor  %xmm8,%xmm0

# qhasm:     xmm1 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm1=int6464#2
# asm 2: pxor  <xmm9=%xmm9,<xmm1=%xmm1
pxor  %xmm9,%xmm1

# qhasm:     xmm4 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm4=int6464#5
# asm 2: pxor  <xmm10=%xmm10,<xmm4=%xmm4
pxor  %xmm10,%xmm4

# qhasm:     xmm6 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm6=int6464#7
# asm 2: pxor  <xmm11=%xmm11,<xmm6=%xmm6
pxor  %xmm11,%xmm6

# qhasm:     xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm3
pxor  %xmm12,%xmm3

# qhasm:     xmm7 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm7=int6464#8
# asm 2: pxor  <xmm13=%xmm13,<xmm7=%xmm7
pxor  %xmm13,%xmm7

# qhasm:     xmm2 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pxor  <xmm14=%xmm14,<xmm2=%xmm2
pxor  %xmm14,%xmm2

# qhasm:     xmm5 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm5=int6464#6
# asm 2: pxor  <xmm15=%xmm15,<xmm5=%xmm5
pxor  %xmm15,%xmm5

# qhasm:     xmm8 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm8=int6464#9
# asm 2: pxor  <xmm5=%xmm5,<xmm8=%xmm8
pxor  %xmm5,%xmm8

# qhasm:     xmm9 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm9=int6464#10
# asm 2: pxor  <xmm0=%xmm0,<xmm9=%xmm9
pxor  %xmm0,%xmm9

# qhasm:     xmm10 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm10=int6464#11
# asm 2: pxor  <xmm1=%xmm1,<xmm10=%xmm10
pxor  %xmm1,%xmm10

# qhasm:     xmm9 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm9=int6464#10
# asm 2: pxor  <xmm5=%xmm5,<xmm9=%xmm9
pxor  %xmm5,%xmm9

# qhasm:     xmm11 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm11=int6464#12
# asm 2: pxor  <xmm4=%xmm4,<xmm11=%xmm11
pxor  %xmm4,%xmm11

# qhasm:     xmm12 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm12=int6464#13
# asm 2: pxor  <xmm6=%xmm6,<xmm12=%xmm12
pxor  %xmm6,%xmm12

# qhasm:     xmm13 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm13=int6464#14
# asm 2: pxor  <xmm3=%xmm3,<xmm13=%xmm13
pxor  %xmm3,%xmm13

# qhasm:     xmm11 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm11=int6464#12
# asm 2: pxor  <xmm5=%xmm5,<xmm11=%xmm11
pxor  %xmm5,%xmm11

# qhasm:     xmm14 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm14=int6464#15
# asm 2: pxor  <xmm7=%xmm7,<xmm14=%xmm14
pxor  %xmm7,%xmm14

# qhasm:     xmm15 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm15=int6464#16
# asm 2: pxor  <xmm2=%xmm2,<xmm15=%xmm15
pxor  %xmm2,%xmm15

# qhasm:     xmm12 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm12=int6464#13
# asm 2: pxor  <xmm5=%xmm5,<xmm12=%xmm12
pxor  %xmm5,%xmm12

# qhasm:     xmm0 = shuffle dwords of xmm0 by 0x4E
# asm 1: pshufd $0x4E,<xmm0=int6464#1,>xmm0=int6464#1
# asm 2: pshufd $0x4E,<xmm0=%xmm0,>xmm0=%xmm0
pshufd $0x4E,%xmm0,%xmm0

# qhasm:     xmm1 = shuffle dwords of xmm1 by 0x4E
# asm 1: pshufd $0x4E,<xmm1=int6464#2,>xmm1=int6464#2
# asm 2: pshufd $0x4E,<xmm1=%xmm1,>xmm1=%xmm1
pshufd $0x4E,%xmm1,%xmm1

# qhasm:     xmm4 = shuffle dwords of xmm4 by 0x4E
# asm 1: pshufd $0x4E,<xmm4=int6464#5,>xmm4=int6464#5
# asm 2: pshufd $0x4E,<xmm4=%xmm4,>xmm4=%xmm4
pshufd $0x4E,%xmm4,%xmm4

# qhasm:     xmm6 = shuffle dwords of xmm6 by 0x4E
# asm 1: pshufd $0x4E,<xmm6=int6464#7,>xmm6=int6464#7
# asm 2: pshufd $0x4E,<xmm6=%xmm6,>xmm6=%xmm6
pshufd $0x4E,%xmm6,%xmm6

# qhasm:     xmm3 = shuffle dwords of xmm3 by 0x4E
# asm 1: pshufd $0x4E,<xmm3=int6464#4,>xmm3=int6464#4
# asm 2: pshufd $0x4E,<xmm3=%xmm3,>xmm3=%xmm3
pshufd $0x4E,%xmm3,%xmm3

# qhasm:     xmm7 = shuffle dwords of xmm7 by 0x4E
# asm 1: pshufd $0x4E,<xmm7=int6464#8,>xmm7=int6464#8
# asm 2: pshufd $0x4E,<xmm7=%xmm7,>xmm7=%xmm7
pshufd $0x4E,%xmm7,%xmm7

# qhasm:     xmm2 = shuffle dwords of xmm2 by 0x4E
# asm 1: pshufd $0x4E,<xmm2=int6464#3,>xmm2=int6464#3
# asm 2: pshufd $0x4E,<xmm2=%xmm2,>xmm2=%xmm2
pshufd $0x4E,%xmm2,%xmm2

# qhasm:     xmm5 = shuffle dwords of xmm5 by 0x4E
# asm 1: pshufd $0x4E,<xmm5=int6464#6,>xmm5=int6464#6
# asm 2: pshufd $0x4E,<xmm5=%xmm5,>xmm5=%xmm5
pshufd $0x4E,%xmm5,%xmm5

# qhasm:     xmm8 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:     xmm9 ^= xmm1
# asm 1: pxor  <xmm1=int6464#2,<xmm9=int6464#10
# asm 2: pxor  <xmm1=%xmm1,<xmm9=%xmm9
pxor  %xmm1,%xmm9

# qhasm:     xmm10 ^= xmm4
# asm 1: pxor  <xmm4=int6464#5,<xmm10=int6464#11
# asm 2: pxor  <xmm4=%xmm4,<xmm10=%xmm10
pxor  %xmm4,%xmm10

# qhasm:     xmm11 ^= xmm6
# asm 1: pxor  <xmm6=int6464#7,<xmm11=int6464#12
# asm 2: pxor  <xmm6=%xmm6,<xmm11=%xmm11
pxor  %xmm6,%xmm11

# qhasm:     xmm12 ^= xmm3
# asm 1: pxor  <xmm3=int6464#4,<xmm12=int6464#13
# asm 2: pxor  <xmm3=%xmm3,<xmm12=%xmm12
pxor  %xmm3,%xmm12

# qhasm:     xmm13 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm13=int6464#14
# asm 2: pxor  <xmm7=%xmm7,<xmm13=%xmm13
pxor  %xmm7,%xmm13

# qhasm:     xmm14 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm14=int6464#15
# asm 2: pxor  <xmm2=%xmm2,<xmm14=%xmm14
pxor  %xmm2,%xmm14

# qhasm:     xmm15 ^= xmm5
# asm 1: pxor  <xmm5=int6464#6,<xmm15=int6464#16
# asm 2: pxor  <xmm5=%xmm5,<xmm15=%xmm15
pxor  %xmm5,%xmm15

# qhasm:     xmm8 ^= *(int128 *)(c + 1152)
# asm 1: pxor 1152(<c=int64#4),<xmm8=int6464#9
# asm 2: pxor 1152(<c=%rcx),<xmm8=%xmm8
pxor 1152(%rcx),%xmm8

# qhasm:     shuffle bytes of xmm8 by SRM0
# asm 1: pshufb SRM0,<xmm8=int6464#9
# asm 2: pshufb SRM0,<xmm8=%xmm8
pshufb SRM0,%xmm8

# qhasm:     xmm9 ^= *(int128 *)(c + 1168)
# asm 1: pxor 1168(<c=int64#4),<xmm9=int6464#10
# asm 2: pxor 1168(<c=%rcx),<xmm9=%xmm9
pxor 1168(%rcx),%xmm9

# qhasm:     shuffle bytes of xmm9 by SRM0
# asm 1: pshufb SRM0,<xmm9=int6464#10
# asm 2: pshufb SRM0,<xmm9=%xmm9
pshufb SRM0,%xmm9

# qhasm:     xmm10 ^= *(int128 *)(c + 1184)
# asm 1: pxor 1184(<c=int64#4),<xmm10=int6464#11
# asm 2: pxor 1184(<c=%rcx),<xmm10=%xmm10
pxor 1184(%rcx),%xmm10

# qhasm:     shuffle bytes of xmm10 by SRM0
# asm 1: pshufb SRM0,<xmm10=int6464#11
# asm 2: pshufb SRM0,<xmm10=%xmm10
pshufb SRM0,%xmm10

# qhasm:     xmm11 ^= *(int128 *)(c + 1200)
# asm 1: pxor 1200(<c=int64#4),<xmm11=int6464#12
# asm 2: pxor 1200(<c=%rcx),<xmm11=%xmm11
pxor 1200(%rcx),%xmm11

# qhasm:     shuffle bytes of xmm11 by SRM0
# asm 1: pshufb SRM0,<xmm11=int6464#12
# asm 2: pshufb SRM0,<xmm11=%xmm11
pshufb SRM0,%xmm11

# qhasm:     xmm12 ^= *(int128 *)(c + 1216)
# asm 1: pxor 1216(<c=int64#4),<xmm12=int6464#13
# asm 2: pxor 1216(<c=%rcx),<xmm12=%xmm12
pxor 1216(%rcx),%xmm12

# qhasm:     shuffle bytes of xmm12 by SRM0
# asm 1: pshufb SRM0,<xmm12=int6464#13
# asm 2: pshufb SRM0,<xmm12=%xmm12
pshufb SRM0,%xmm12

# qhasm:     xmm13 ^= *(int128 *)(c + 1232)
# asm 1: pxor 1232(<c=int64#4),<xmm13=int6464#14
# asm 2: pxor 1232(<c=%rcx),<xmm13=%xmm13
pxor 1232(%rcx),%xmm13

# qhasm:     shuffle bytes of xmm13 by SRM0
# asm 1: pshufb SRM0,<xmm13=int6464#14
# asm 2: pshufb SRM0,<xmm13=%xmm13
pshufb SRM0,%xmm13

# qhasm:     xmm14 ^= *(int128 *)(c + 1248)
# asm 1: pxor 1248(<c=int64#4),<xmm14=int6464#15
# asm 2: pxor 1248(<c=%rcx),<xmm14=%xmm14
pxor 1248(%rcx),%xmm14

# qhasm:     shuffle bytes of xmm14 by SRM0
# asm 1: pshufb SRM0,<xmm14=int6464#15
# asm 2: pshufb SRM0,<xmm14=%xmm14
pshufb SRM0,%xmm14

# qhasm:     xmm15 ^= *(int128 *)(c + 1264)
# asm 1: pxor 1264(<c=int64#4),<xmm15=int6464#16
# asm 2: pxor 1264(<c=%rcx),<xmm15=%xmm15
pxor 1264(%rcx),%xmm15

# qhasm:     shuffle bytes of xmm15 by SRM0
# asm 1: pshufb SRM0,<xmm15=int6464#16
# asm 2: pshufb SRM0,<xmm15=%xmm15
pshufb SRM0,%xmm15

# qhasm:       xmm13 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm13=int6464#14
# asm 2: pxor  <xmm14=%xmm14,<xmm13=%xmm13
pxor  %xmm14,%xmm13

# qhasm:       xmm10 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm10=int6464#11
# asm 2: pxor  <xmm9=%xmm9,<xmm10=%xmm10
pxor  %xmm9,%xmm10

# qhasm:       xmm13 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm13=int6464#14
# asm 2: pxor  <xmm8=%xmm8,<xmm13=%xmm13
pxor  %xmm8,%xmm13

# qhasm:       xmm14 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm14=int6464#15
# asm 2: pxor  <xmm10=%xmm10,<xmm14=%xmm14
pxor  %xmm10,%xmm14

# qhasm:       xmm11 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm11=int6464#12
# asm 2: pxor  <xmm8=%xmm8,<xmm11=%xmm11
pxor  %xmm8,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm14=int6464#15
# asm 2: pxor  <xmm11=%xmm11,<xmm14=%xmm14
pxor  %xmm11,%xmm14

# qhasm:       xmm11 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm11=int6464#12
# asm 2: pxor  <xmm15=%xmm15,<xmm11=%xmm11
pxor  %xmm15,%xmm11

# qhasm:       xmm11 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm11=int6464#12
# asm 2: pxor  <xmm12=%xmm12,<xmm11=%xmm11
pxor  %xmm12,%xmm11

# qhasm:       xmm15 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm15=int6464#16
# asm 2: pxor  <xmm13=%xmm13,<xmm15=%xmm15
pxor  %xmm13,%xmm15

# qhasm:       xmm11 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm11=int6464#12
# asm 2: pxor  <xmm9=%xmm9,<xmm11=%xmm11
pxor  %xmm9,%xmm11

# qhasm:       xmm12 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm12=int6464#13
# asm 2: pxor  <xmm13=%xmm13,<xmm12=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm10 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm10=int6464#11
# asm 2: pxor  <xmm15=%xmm15,<xmm10=%xmm10
pxor  %xmm15,%xmm10

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm9=int6464#10
# asm 2: pxor  <xmm13=%xmm13,<xmm9=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm3 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm3=int6464#1
# asm 2: movdqa <xmm15=%xmm15,>xmm3=%xmm0
movdqa %xmm15,%xmm0

# qhasm:       xmm2 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm2=int6464#2
# asm 2: movdqa <xmm9=%xmm9,>xmm2=%xmm1
movdqa %xmm9,%xmm1

# qhasm:       xmm1 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm1=int6464#3
# asm 2: movdqa <xmm13=%xmm13,>xmm1=%xmm2
movdqa %xmm13,%xmm2

# qhasm:       xmm5 = xmm10
# asm 1: movdqa <xmm10=int6464#11,>xmm5=int6464#4
# asm 2: movdqa <xmm10=%xmm10,>xmm5=%xmm3
movdqa %xmm10,%xmm3

# qhasm:       xmm4 = xmm14
# asm 1: movdqa <xmm14=int6464#15,>xmm4=int6464#5
# asm 2: movdqa <xmm14=%xmm14,>xmm4=%xmm4
movdqa %xmm14,%xmm4

# qhasm:       xmm3 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm3=int6464#1
# asm 2: pxor  <xmm12=%xmm12,<xmm3=%xmm0
pxor  %xmm12,%xmm0

# qhasm:       xmm2 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm2=int6464#2
# asm 2: pxor  <xmm10=%xmm10,<xmm2=%xmm1
pxor  %xmm10,%xmm1

# qhasm:       xmm1 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm1=int6464#3
# asm 2: pxor  <xmm11=%xmm11,<xmm1=%xmm2
pxor  %xmm11,%xmm2

# qhasm:       xmm5 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm5=int6464#4
# asm 2: pxor  <xmm12=%xmm12,<xmm5=%xmm3
pxor  %xmm12,%xmm3

# qhasm:       xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#5
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm4
pxor  %xmm8,%xmm4

# qhasm:       xmm6 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm6=int6464#6
# asm 2: movdqa <xmm3=%xmm0,>xmm6=%xmm5
movdqa %xmm0,%xmm5

# qhasm:       xmm0 = xmm2
# asm 1: movdqa <xmm2=int6464#2,>xmm0=int6464#7
# asm 2: movdqa <xmm2=%xmm1,>xmm0=%xmm6
movdqa %xmm1,%xmm6

# qhasm:       xmm7 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm7=int6464#8
# asm 2: movdqa <xmm3=%xmm0,>xmm7=%xmm7
movdqa %xmm0,%xmm7

# qhasm:       xmm2 |= xmm1
# asm 1: por   <xmm1=int6464#3,<xmm2=int6464#2
# asm 2: por   <xmm1=%xmm2,<xmm2=%xmm1
por   %xmm2,%xmm1

# qhasm:       xmm3 |= xmm4
# asm 1: por   <xmm4=int6464#5,<xmm3=int6464#1
# asm 2: por   <xmm4=%xmm4,<xmm3=%xmm0
por   %xmm4,%xmm0

# qhasm:       xmm7 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm7=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm7=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm6 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm6=int6464#6
# asm 2: pand  <xmm4=%xmm4,<xmm6=%xmm5
pand  %xmm4,%xmm5

# qhasm:       xmm0 &= xmm1
# asm 1: pand  <xmm1=int6464#3,<xmm0=int6464#7
# asm 2: pand  <xmm1=%xmm2,<xmm0=%xmm6
pand  %xmm2,%xmm6

# qhasm:       xmm4 ^= xmm1
# asm 1: pxor  <xmm1=int6464#3,<xmm4=int6464#5
# asm 2: pxor  <xmm1=%xmm2,<xmm4=%xmm4
pxor  %xmm2,%xmm4

# qhasm:       xmm7 &= xmm4
# asm 1: pand  <xmm4=int6464#5,<xmm7=int6464#8
# asm 2: pand  <xmm4=%xmm4,<xmm7=%xmm7
pand  %xmm4,%xmm7

# qhasm:       xmm4 = xmm11
# asm 1: movdqa <xmm11=int6464#12,>xmm4=int6464#3
# asm 2: movdqa <xmm11=%xmm11,>xmm4=%xmm2
movdqa %xmm11,%xmm2

# qhasm:       xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#3
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm2
pxor  %xmm8,%xmm2

# qhasm:       xmm5 &= xmm4
# asm 1: pand  <xmm4=int6464#3,<xmm5=int6464#4
# asm 2: pand  <xmm4=%xmm2,<xmm5=%xmm3
pand  %xmm2,%xmm3

# qhasm:       xmm3 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm3=int6464#1
# asm 2: pxor  <xmm5=%xmm3,<xmm3=%xmm0
pxor  %xmm3,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm2=int6464#2
# asm 2: pxor  <xmm5=%xmm3,<xmm2=%xmm1
pxor  %xmm3,%xmm1

# qhasm:       xmm5 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm5=int6464#3
# asm 2: movdqa <xmm15=%xmm15,>xmm5=%xmm2
movdqa %xmm15,%xmm2

# qhasm:       xmm5 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm5=int6464#3
# asm 2: pxor  <xmm9=%xmm9,<xmm5=%xmm2
pxor  %xmm9,%xmm2

# qhasm:       xmm4 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm4=int6464#4
# asm 2: movdqa <xmm13=%xmm13,>xmm4=%xmm3
movdqa %xmm13,%xmm3

# qhasm:       xmm1 = xmm5
# asm 1: movdqa <xmm5=int6464#3,>xmm1=int6464#5
# asm 2: movdqa <xmm5=%xmm2,>xmm1=%xmm4
movdqa %xmm2,%xmm4

# qhasm:       xmm4 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm4=int6464#4
# asm 2: pxor  <xmm14=%xmm14,<xmm4=%xmm3
pxor  %xmm14,%xmm3

# qhasm:       xmm1 |= xmm4
# asm 1: por   <xmm4=int6464#4,<xmm1=int6464#5
# asm 2: por   <xmm4=%xmm3,<xmm1=%xmm4
por   %xmm3,%xmm4

# qhasm:       xmm5 &= xmm4
# asm 1: pand  <xmm4=int6464#4,<xmm5=int6464#3
# asm 2: pand  <xmm4=%xmm3,<xmm5=%xmm2
pand  %xmm3,%xmm2

# qhasm:       xmm0 ^= xmm5
# asm 1: pxor  <xmm5=int6464#3,<xmm0=int6464#7
# asm 2: pxor  <xmm5=%xmm2,<xmm0=%xmm6
pxor  %xmm2,%xmm6

# qhasm:       xmm3 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm3=int6464#1
# asm 2: pxor  <xmm7=%xmm7,<xmm3=%xmm0
pxor  %xmm7,%xmm0

# qhasm:       xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm2=int6464#2
# asm 2: pxor  <xmm6=%xmm5,<xmm2=%xmm1
pxor  %xmm5,%xmm1

# qhasm:       xmm1 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm1=int6464#5
# asm 2: pxor  <xmm7=%xmm7,<xmm1=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm0 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm0=int6464#7
# asm 2: pxor  <xmm6=%xmm5,<xmm0=%xmm6
pxor  %xmm5,%xmm6

# qhasm:       xmm1 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm1=int6464#5
# asm 2: pxor  <xmm6=%xmm5,<xmm1=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm4 = xmm10
# asm 1: movdqa <xmm10=int6464#11,>xmm4=int6464#3
# asm 2: movdqa <xmm10=%xmm10,>xmm4=%xmm2
movdqa %xmm10,%xmm2

# qhasm:       xmm5 = xmm12
# asm 1: movdqa <xmm12=int6464#13,>xmm5=int6464#4
# asm 2: movdqa <xmm12=%xmm12,>xmm5=%xmm3
movdqa %xmm12,%xmm3

# qhasm:       xmm6 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm6=int6464#6
# asm 2: movdqa <xmm9=%xmm9,>xmm6=%xmm5
movdqa %xmm9,%xmm5

# qhasm:       xmm7 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm7=int6464#8
# asm 2: movdqa <xmm15=%xmm15,>xmm7=%xmm7
movdqa %xmm15,%xmm7

# qhasm:       xmm4 &= xmm11
# asm 1: pand  <xmm11=int6464#12,<xmm4=int6464#3
# asm 2: pand  <xmm11=%xmm11,<xmm4=%xmm2
pand  %xmm11,%xmm2

# qhasm:       xmm5 &= xmm8
# asm 1: pand  <xmm8=int6464#9,<xmm5=int6464#4
# asm 2: pand  <xmm8=%xmm8,<xmm5=%xmm3
pand  %xmm8,%xmm3

# qhasm:       xmm6 &= xmm13
# asm 1: pand  <xmm13=int6464#14,<xmm6=int6464#6
# asm 2: pand  <xmm13=%xmm13,<xmm6=%xmm5
pand  %xmm13,%xmm5

# qhasm:       xmm7 |= xmm14
# asm 1: por   <xmm14=int6464#15,<xmm7=int6464#8
# asm 2: por   <xmm14=%xmm14,<xmm7=%xmm7
por   %xmm14,%xmm7

# qhasm:       xmm3 ^= xmm4
# asm 1: pxor  <xmm4=int6464#3,<xmm3=int6464#1
# asm 2: pxor  <xmm4=%xmm2,<xmm3=%xmm0
pxor  %xmm2,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#4,<xmm2=int6464#2
# asm 2: pxor  <xmm5=%xmm3,<xmm2=%xmm1
pxor  %xmm3,%xmm1

# qhasm:       xmm1 ^= xmm6
# asm 1: pxor  <xmm6=int6464#6,<xmm1=int6464#5
# asm 2: pxor  <xmm6=%xmm5,<xmm1=%xmm4
pxor  %xmm5,%xmm4

# qhasm:       xmm0 ^= xmm7
# asm 1: pxor  <xmm7=int6464#8,<xmm0=int6464#7
# asm 2: pxor  <xmm7=%xmm7,<xmm0=%xmm6
pxor  %xmm7,%xmm6

# qhasm:       xmm4 = xmm3
# asm 1: movdqa <xmm3=int6464#1,>xmm4=int6464#3
# asm 2: movdqa <xmm3=%xmm0,>xmm4=%xmm2
movdqa %xmm0,%xmm2

# qhasm:       xmm4 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm4=int6464#3
# asm 2: pxor  <xmm2=%xmm1,<xmm4=%xmm2
pxor  %xmm1,%xmm2

# qhasm:       xmm3 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm3=int6464#1
# asm 2: pand  <xmm1=%xmm4,<xmm3=%xmm0
pand  %xmm4,%xmm0

# qhasm:       xmm6 = xmm0
# asm 1: movdqa <xmm0=int6464#7,>xmm6=int6464#4
# asm 2: movdqa <xmm0=%xmm6,>xmm6=%xmm3
movdqa %xmm6,%xmm3

# qhasm:       xmm6 ^= xmm3
# asm 1: pxor  <xmm3=int6464#1,<xmm6=int6464#4
# asm 2: pxor  <xmm3=%xmm0,<xmm6=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm7 = xmm4
# asm 1: movdqa <xmm4=int6464#3,>xmm7=int6464#6
# asm 2: movdqa <xmm4=%xmm2,>xmm7=%xmm5
movdqa %xmm2,%xmm5

# qhasm:       xmm7 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm7=int6464#6
# asm 2: pand  <xmm6=%xmm3,<xmm7=%xmm5
pand  %xmm3,%xmm5

# qhasm:       xmm7 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm7=int6464#6
# asm 2: pxor  <xmm2=%xmm1,<xmm7=%xmm5
pxor  %xmm1,%xmm5

# qhasm:       xmm5 = xmm1
# asm 1: movdqa <xmm1=int6464#5,>xmm5=int6464#8
# asm 2: movdqa <xmm1=%xmm4,>xmm5=%xmm7
movdqa %xmm4,%xmm7

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm5=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm5=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm3 ^= xmm2
# asm 1: pxor  <xmm2=int6464#2,<xmm3=int6464#1
# asm 2: pxor  <xmm2=%xmm1,<xmm3=%xmm0
pxor  %xmm1,%xmm0

# qhasm:       xmm5 &= xmm3
# asm 1: pand  <xmm3=int6464#1,<xmm5=int6464#8
# asm 2: pand  <xmm3=%xmm0,<xmm5=%xmm7
pand  %xmm0,%xmm7

# qhasm:       xmm5 ^= xmm0
# asm 1: pxor  <xmm0=int6464#7,<xmm5=int6464#8
# asm 2: pxor  <xmm0=%xmm6,<xmm5=%xmm7
pxor  %xmm6,%xmm7

# qhasm:       xmm1 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm1=int6464#5
# asm 2: pxor  <xmm5=%xmm7,<xmm1=%xmm4
pxor  %xmm7,%xmm4

# qhasm:       xmm2 = xmm6
# asm 1: movdqa <xmm6=int6464#4,>xmm2=int6464#1
# asm 2: movdqa <xmm6=%xmm3,>xmm2=%xmm0
movdqa %xmm3,%xmm0

# qhasm:       xmm2 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm2=int6464#1
# asm 2: pxor  <xmm5=%xmm7,<xmm2=%xmm0
pxor  %xmm7,%xmm0

# qhasm:       xmm2 &= xmm0
# asm 1: pand  <xmm0=int6464#7,<xmm2=int6464#1
# asm 2: pand  <xmm0=%xmm6,<xmm2=%xmm0
pand  %xmm6,%xmm0

# qhasm:       xmm1 ^= xmm2
# asm 1: pxor  <xmm2=int6464#1,<xmm1=int6464#5
# asm 2: pxor  <xmm2=%xmm0,<xmm1=%xmm4
pxor  %xmm0,%xmm4

# qhasm:       xmm6 ^= xmm2
# asm 1: pxor  <xmm2=int6464#1,<xmm6=int6464#4
# asm 2: pxor  <xmm2=%xmm0,<xmm6=%xmm3
pxor  %xmm0,%xmm3

# qhasm:       xmm6 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm6=int6464#4
# asm 2: pand  <xmm7=%xmm5,<xmm6=%xmm3
pand  %xmm5,%xmm3

# qhasm:       xmm6 ^= xmm4
# asm 1: pxor  <xmm4=int6464#3,<xmm6=int6464#4
# asm 2: pxor  <xmm4=%xmm2,<xmm6=%xmm3
pxor  %xmm2,%xmm3

# qhasm:         xmm4 = xmm14
# asm 1: movdqa <xmm14=int6464#15,>xmm4=int6464#1
# asm 2: movdqa <xmm14=%xmm14,>xmm4=%xmm0
movdqa %xmm14,%xmm0

# qhasm:         xmm0 = xmm13
# asm 1: movdqa <xmm13=int6464#14,>xmm0=int6464#2
# asm 2: movdqa <xmm13=%xmm13,>xmm0=%xmm1
movdqa %xmm13,%xmm1

# qhasm:           xmm2 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm2=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm2=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm2 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm2=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm2=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm2 &= xmm14
# asm 1: pand  <xmm14=int6464#15,<xmm2=int6464#3
# asm 2: pand  <xmm14=%xmm14,<xmm2=%xmm2
pand  %xmm14,%xmm2

# qhasm:           xmm14 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm14=int6464#15
# asm 2: pxor  <xmm13=%xmm13,<xmm14=%xmm14
pxor  %xmm13,%xmm14

# qhasm:           xmm14 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm14=int6464#15
# asm 2: pand  <xmm6=%xmm3,<xmm14=%xmm14
pand  %xmm3,%xmm14

# qhasm:           xmm13 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm13=int6464#14
# asm 2: pand  <xmm7=%xmm5,<xmm13=%xmm13
pand  %xmm5,%xmm13

# qhasm:           xmm14 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm14=int6464#15
# asm 2: pxor  <xmm13=%xmm13,<xmm14=%xmm14
pxor  %xmm13,%xmm14

# qhasm:           xmm13 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm13=int6464#14
# asm 2: pxor  <xmm2=%xmm2,<xmm13=%xmm13
pxor  %xmm2,%xmm13

# qhasm:         xmm4 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm4=int6464#1
# asm 2: pxor  <xmm8=%xmm8,<xmm4=%xmm0
pxor  %xmm8,%xmm0

# qhasm:         xmm0 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm0=int6464#2
# asm 2: pxor  <xmm11=%xmm11,<xmm0=%xmm1
pxor  %xmm11,%xmm1

# qhasm:         xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm7=int6464#6
# asm 2: pxor  <xmm5=%xmm7,<xmm7=%xmm5
pxor  %xmm7,%xmm5

# qhasm:         xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm6=int6464#4
# asm 2: pxor  <xmm1=%xmm4,<xmm6=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm4
# asm 1: pand  <xmm4=int6464#1,<xmm3=int6464#3
# asm 2: pand  <xmm4=%xmm0,<xmm3=%xmm2
pand  %xmm0,%xmm2

# qhasm:           xmm4 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm4=int6464#1
# asm 2: pxor  <xmm0=%xmm1,<xmm4=%xmm0
pxor  %xmm1,%xmm0

# qhasm:           xmm4 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm4=int6464#1
# asm 2: pand  <xmm6=%xmm3,<xmm4=%xmm0
pand  %xmm3,%xmm0

# qhasm:           xmm0 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm0=int6464#2
# asm 2: pand  <xmm7=%xmm5,<xmm0=%xmm1
pand  %xmm5,%xmm1

# qhasm:           xmm0 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm0=int6464#2
# asm 2: pxor  <xmm4=%xmm0,<xmm0=%xmm1
pxor  %xmm0,%xmm1

# qhasm:           xmm4 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm4=int6464#1
# asm 2: pxor  <xmm3=%xmm2,<xmm4=%xmm0
pxor  %xmm2,%xmm0

# qhasm:           xmm2 = xmm5
# asm 1: movdqa <xmm5=int6464#8,>xmm2=int6464#3
# asm 2: movdqa <xmm5=%xmm7,>xmm2=%xmm2
movdqa %xmm7,%xmm2

# qhasm:           xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm4,<xmm2=%xmm2
pxor  %xmm4,%xmm2

# qhasm:           xmm2 &= xmm8
# asm 1: pand  <xmm8=int6464#9,<xmm2=int6464#3
# asm 2: pand  <xmm8=%xmm8,<xmm2=%xmm2
pand  %xmm8,%xmm2

# qhasm:           xmm8 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm8=int6464#9
# asm 2: pxor  <xmm11=%xmm11,<xmm8=%xmm8
pxor  %xmm11,%xmm8

# qhasm:           xmm8 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm8=int6464#9
# asm 2: pand  <xmm1=%xmm4,<xmm8=%xmm8
pand  %xmm4,%xmm8

# qhasm:           xmm11 &= xmm5
# asm 1: pand  <xmm5=int6464#8,<xmm11=int6464#12
# asm 2: pand  <xmm5=%xmm7,<xmm11=%xmm11
pand  %xmm7,%xmm11

# qhasm:           xmm8 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm8=int6464#9
# asm 2: pxor  <xmm11=%xmm11,<xmm8=%xmm8
pxor  %xmm11,%xmm8

# qhasm:           xmm11 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm11=int6464#12
# asm 2: pxor  <xmm2=%xmm2,<xmm11=%xmm11
pxor  %xmm2,%xmm11

# qhasm:         xmm14 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm14=int6464#15
# asm 2: pxor  <xmm4=%xmm0,<xmm14=%xmm14
pxor  %xmm0,%xmm14

# qhasm:         xmm8 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm4=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:         xmm13 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm13=int6464#14
# asm 2: pxor  <xmm0=%xmm1,<xmm13=%xmm13
pxor  %xmm1,%xmm13

# qhasm:         xmm11 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm11=int6464#12
# asm 2: pxor  <xmm0=%xmm1,<xmm11=%xmm11
pxor  %xmm1,%xmm11

# qhasm:         xmm4 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm4=int6464#1
# asm 2: movdqa <xmm15=%xmm15,>xmm4=%xmm0
movdqa %xmm15,%xmm0

# qhasm:         xmm0 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm0=int6464#2
# asm 2: movdqa <xmm9=%xmm9,>xmm0=%xmm1
movdqa %xmm9,%xmm1

# qhasm:         xmm4 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm4=int6464#1
# asm 2: pxor  <xmm12=%xmm12,<xmm4=%xmm0
pxor  %xmm12,%xmm0

# qhasm:         xmm0 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm0=int6464#2
# asm 2: pxor  <xmm10=%xmm10,<xmm0=%xmm1
pxor  %xmm10,%xmm1

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm4
# asm 1: pand  <xmm4=int6464#1,<xmm3=int6464#3
# asm 2: pand  <xmm4=%xmm0,<xmm3=%xmm2
pand  %xmm0,%xmm2

# qhasm:           xmm4 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm4=int6464#1
# asm 2: pxor  <xmm0=%xmm1,<xmm4=%xmm0
pxor  %xmm1,%xmm0

# qhasm:           xmm4 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm4=int6464#1
# asm 2: pand  <xmm6=%xmm3,<xmm4=%xmm0
pand  %xmm3,%xmm0

# qhasm:           xmm0 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm0=int6464#2
# asm 2: pand  <xmm7=%xmm5,<xmm0=%xmm1
pand  %xmm5,%xmm1

# qhasm:           xmm0 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm0=int6464#2
# asm 2: pxor  <xmm4=%xmm0,<xmm0=%xmm1
pxor  %xmm0,%xmm1

# qhasm:           xmm4 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm4=int6464#1
# asm 2: pxor  <xmm3=%xmm2,<xmm4=%xmm0
pxor  %xmm2,%xmm0

# qhasm:           xmm2 = xmm5
# asm 1: movdqa <xmm5=int6464#8,>xmm2=int6464#3
# asm 2: movdqa <xmm5=%xmm7,>xmm2=%xmm2
movdqa %xmm7,%xmm2

# qhasm:           xmm2 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm2=int6464#3
# asm 2: pxor  <xmm1=%xmm4,<xmm2=%xmm2
pxor  %xmm4,%xmm2

# qhasm:           xmm2 &= xmm12
# asm 1: pand  <xmm12=int6464#13,<xmm2=int6464#3
# asm 2: pand  <xmm12=%xmm12,<xmm2=%xmm2
pand  %xmm12,%xmm2

# qhasm:           xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm10=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:           xmm12 &= xmm1
# asm 1: pand  <xmm1=int6464#5,<xmm12=int6464#13
# asm 2: pand  <xmm1=%xmm4,<xmm12=%xmm12
pand  %xmm4,%xmm12

# qhasm:           xmm10 &= xmm5
# asm 1: pand  <xmm5=int6464#8,<xmm10=int6464#11
# asm 2: pand  <xmm5=%xmm7,<xmm10=%xmm10
pand  %xmm7,%xmm10

# qhasm:           xmm12 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm12=int6464#13
# asm 2: pxor  <xmm10=%xmm10,<xmm12=%xmm12
pxor  %xmm10,%xmm12

# qhasm:           xmm10 ^= xmm2
# asm 1: pxor  <xmm2=int6464#3,<xmm10=int6464#11
# asm 2: pxor  <xmm2=%xmm2,<xmm10=%xmm10
pxor  %xmm2,%xmm10

# qhasm:         xmm7 ^= xmm5
# asm 1: pxor  <xmm5=int6464#8,<xmm7=int6464#6
# asm 2: pxor  <xmm5=%xmm7,<xmm7=%xmm5
pxor  %xmm7,%xmm5

# qhasm:         xmm6 ^= xmm1
# asm 1: pxor  <xmm1=int6464#5,<xmm6=int6464#4
# asm 2: pxor  <xmm1=%xmm4,<xmm6=%xmm3
pxor  %xmm4,%xmm3

# qhasm:           xmm3 = xmm7
# asm 1: movdqa <xmm7=int6464#6,>xmm3=int6464#3
# asm 2: movdqa <xmm7=%xmm5,>xmm3=%xmm2
movdqa %xmm5,%xmm2

# qhasm:           xmm3 ^= xmm6
# asm 1: pxor  <xmm6=int6464#4,<xmm3=int6464#3
# asm 2: pxor  <xmm6=%xmm3,<xmm3=%xmm2
pxor  %xmm3,%xmm2

# qhasm:           xmm3 &= xmm15
# asm 1: pand  <xmm15=int6464#16,<xmm3=int6464#3
# asm 2: pand  <xmm15=%xmm15,<xmm3=%xmm2
pand  %xmm15,%xmm2

# qhasm:           xmm15 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm15=int6464#16
# asm 2: pxor  <xmm9=%xmm9,<xmm15=%xmm15
pxor  %xmm9,%xmm15

# qhasm:           xmm15 &= xmm6
# asm 1: pand  <xmm6=int6464#4,<xmm15=int6464#16
# asm 2: pand  <xmm6=%xmm3,<xmm15=%xmm15
pand  %xmm3,%xmm15

# qhasm:           xmm9 &= xmm7
# asm 1: pand  <xmm7=int6464#6,<xmm9=int6464#10
# asm 2: pand  <xmm7=%xmm5,<xmm9=%xmm9
pand  %xmm5,%xmm9

# qhasm:           xmm15 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm15=int6464#16
# asm 2: pxor  <xmm9=%xmm9,<xmm15=%xmm15
pxor  %xmm9,%xmm15

# qhasm:           xmm9 ^= xmm3
# asm 1: pxor  <xmm3=int6464#3,<xmm9=int6464#10
# asm 2: pxor  <xmm3=%xmm2,<xmm9=%xmm9
pxor  %xmm2,%xmm9

# qhasm:         xmm15 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm15=int6464#16
# asm 2: pxor  <xmm4=%xmm0,<xmm15=%xmm15
pxor  %xmm0,%xmm15

# qhasm:         xmm12 ^= xmm4
# asm 1: pxor  <xmm4=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm4=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:         xmm9 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm9=int6464#10
# asm 2: pxor  <xmm0=%xmm1,<xmm9=%xmm9
pxor  %xmm1,%xmm9

# qhasm:         xmm10 ^= xmm0
# asm 1: pxor  <xmm0=int6464#2,<xmm10=int6464#11
# asm 2: pxor  <xmm0=%xmm1,<xmm10=%xmm10
pxor  %xmm1,%xmm10

# qhasm:       xmm15 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm15=int6464#16
# asm 2: pxor  <xmm8=%xmm8,<xmm15=%xmm15
pxor  %xmm8,%xmm15

# qhasm:       xmm9 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm9=int6464#10
# asm 2: pxor  <xmm14=%xmm14,<xmm9=%xmm9
pxor  %xmm14,%xmm9

# qhasm:       xmm12 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm12=int6464#13
# asm 2: pxor  <xmm15=%xmm15,<xmm12=%xmm12
pxor  %xmm15,%xmm12

# qhasm:       xmm14 ^= xmm8
# asm 1: pxor  <xmm8=int6464#9,<xmm14=int6464#15
# asm 2: pxor  <xmm8=%xmm8,<xmm14=%xmm14
pxor  %xmm8,%xmm14

# qhasm:       xmm8 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm8=int6464#9
# asm 2: pxor  <xmm9=%xmm9,<xmm8=%xmm8
pxor  %xmm9,%xmm8

# qhasm:       xmm9 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm9=int6464#10
# asm 2: pxor  <xmm13=%xmm13,<xmm9=%xmm9
pxor  %xmm13,%xmm9

# qhasm:       xmm13 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm13=int6464#14
# asm 2: pxor  <xmm10=%xmm10,<xmm13=%xmm13
pxor  %xmm10,%xmm13

# qhasm:       xmm12 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm12=int6464#13
# asm 2: pxor  <xmm13=%xmm13,<xmm12=%xmm12
pxor  %xmm13,%xmm12

# qhasm:       xmm10 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm10=int6464#11
# asm 2: pxor  <xmm11=%xmm11,<xmm10=%xmm10
pxor  %xmm11,%xmm10

# qhasm:       xmm11 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm11=int6464#12
# asm 2: pxor  <xmm13=%xmm13,<xmm11=%xmm11
pxor  %xmm13,%xmm11

# qhasm:       xmm14 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm14=int6464#15
# asm 2: pxor  <xmm11=%xmm11,<xmm14=%xmm14
pxor  %xmm11,%xmm14

# qhasm:   xmm8 ^= *(int128 *)(c + 1280)
# asm 1: pxor 1280(<c=int64#4),<xmm8=int6464#9
# asm 2: pxor 1280(<c=%rcx),<xmm8=%xmm8
pxor 1280(%rcx),%xmm8

# qhasm:   xmm9 ^= *(int128 *)(c + 1296)
# asm 1: pxor 1296(<c=int64#4),<xmm9=int6464#10
# asm 2: pxor 1296(<c=%rcx),<xmm9=%xmm9
pxor 1296(%rcx),%xmm9

# qhasm:   xmm12 ^= *(int128 *)(c + 1312)
# asm 1: pxor 1312(<c=int64#4),<xmm12=int6464#13
# asm 2: pxor 1312(<c=%rcx),<xmm12=%xmm12
pxor 1312(%rcx),%xmm12

# qhasm:   xmm14 ^= *(int128 *)(c + 1328)
# asm 1: pxor 1328(<c=int64#4),<xmm14=int6464#15
# asm 2: pxor 1328(<c=%rcx),<xmm14=%xmm14
pxor 1328(%rcx),%xmm14

# qhasm:   xmm11 ^= *(int128 *)(c + 1344)
# asm 1: pxor 1344(<c=int64#4),<xmm11=int6464#12
# asm 2: pxor 1344(<c=%rcx),<xmm11=%xmm11
pxor 1344(%rcx),%xmm11

# qhasm:   xmm15 ^= *(int128 *)(c + 1360)
# asm 1: pxor 1360(<c=int64#4),<xmm15=int6464#16
# asm 2: pxor 1360(<c=%rcx),<xmm15=%xmm15
pxor 1360(%rcx),%xmm15

# qhasm:   xmm10 ^= *(int128 *)(c + 1376)
# asm 1: pxor 1376(<c=int64#4),<xmm10=int6464#11
# asm 2: pxor 1376(<c=%rcx),<xmm10=%xmm10
pxor 1376(%rcx),%xmm10

# qhasm:   xmm13 ^= *(int128 *)(c + 1392)
# asm 1: pxor 1392(<c=int64#4),<xmm13=int6464#14
# asm 2: pxor 1392(<c=%rcx),<xmm13=%xmm13
pxor 1392(%rcx),%xmm13

# qhasm:     xmm0 = xmm10
# asm 1: movdqa <xmm10=int6464#11,>xmm0=int6464#1
# asm 2: movdqa <xmm10=%xmm10,>xmm0=%xmm0
movdqa %xmm10,%xmm0

# qhasm:     uint6464 xmm0 >>= 1
# asm 1: psrlq $1,<xmm0=int6464#1
# asm 2: psrlq $1,<xmm0=%xmm0
psrlq $1,%xmm0

# qhasm:     xmm0 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm0=int6464#1
# asm 2: pxor  <xmm13=%xmm13,<xmm0=%xmm0
pxor  %xmm13,%xmm0

# qhasm:     xmm0 &= BS0
# asm 1: pand  BS0,<xmm0=int6464#1
# asm 2: pand  BS0,<xmm0=%xmm0
pand  BS0,%xmm0

# qhasm:     xmm13 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm13=int6464#14
# asm 2: pxor  <xmm0=%xmm0,<xmm13=%xmm13
pxor  %xmm0,%xmm13

# qhasm:     uint6464 xmm0 <<= 1
# asm 1: psllq $1,<xmm0=int6464#1
# asm 2: psllq $1,<xmm0=%xmm0
psllq $1,%xmm0

# qhasm:     xmm10 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm10=int6464#11
# asm 2: pxor  <xmm0=%xmm0,<xmm10=%xmm10
pxor  %xmm0,%xmm10

# qhasm:     xmm0 = xmm11
# asm 1: movdqa <xmm11=int6464#12,>xmm0=int6464#1
# asm 2: movdqa <xmm11=%xmm11,>xmm0=%xmm0
movdqa %xmm11,%xmm0

# qhasm:     uint6464 xmm0 >>= 1
# asm 1: psrlq $1,<xmm0=int6464#1
# asm 2: psrlq $1,<xmm0=%xmm0
psrlq $1,%xmm0

# qhasm:     xmm0 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm0=int6464#1
# asm 2: pxor  <xmm15=%xmm15,<xmm0=%xmm0
pxor  %xmm15,%xmm0

# qhasm:     xmm0 &= BS0
# asm 1: pand  BS0,<xmm0=int6464#1
# asm 2: pand  BS0,<xmm0=%xmm0
pand  BS0,%xmm0

# qhasm:     xmm15 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm15=int6464#16
# asm 2: pxor  <xmm0=%xmm0,<xmm15=%xmm15
pxor  %xmm0,%xmm15

# qhasm:     uint6464 xmm0 <<= 1
# asm 1: psllq $1,<xmm0=int6464#1
# asm 2: psllq $1,<xmm0=%xmm0
psllq $1,%xmm0

# qhasm:     xmm11 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm11=int6464#12
# asm 2: pxor  <xmm0=%xmm0,<xmm11=%xmm11
pxor  %xmm0,%xmm11

# qhasm:     xmm0 = xmm12
# asm 1: movdqa <xmm12=int6464#13,>xmm0=int6464#1
# asm 2: movdqa <xmm12=%xmm12,>xmm0=%xmm0
movdqa %xmm12,%xmm0

# qhasm:     uint6464 xmm0 >>= 1
# asm 1: psrlq $1,<xmm0=int6464#1
# asm 2: psrlq $1,<xmm0=%xmm0
psrlq $1,%xmm0

# qhasm:     xmm0 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm0=int6464#1
# asm 2: pxor  <xmm14=%xmm14,<xmm0=%xmm0
pxor  %xmm14,%xmm0

# qhasm:     xmm0 &= BS0
# asm 1: pand  BS0,<xmm0=int6464#1
# asm 2: pand  BS0,<xmm0=%xmm0
pand  BS0,%xmm0

# qhasm:     xmm14 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm14=int6464#15
# asm 2: pxor  <xmm0=%xmm0,<xmm14=%xmm14
pxor  %xmm0,%xmm14

# qhasm:     uint6464 xmm0 <<= 1
# asm 1: psllq $1,<xmm0=int6464#1
# asm 2: psllq $1,<xmm0=%xmm0
psllq $1,%xmm0

# qhasm:     xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:     xmm0 = xmm8
# asm 1: movdqa <xmm8=int6464#9,>xmm0=int6464#1
# asm 2: movdqa <xmm8=%xmm8,>xmm0=%xmm0
movdqa %xmm8,%xmm0

# qhasm:     uint6464 xmm0 >>= 1
# asm 1: psrlq $1,<xmm0=int6464#1
# asm 2: psrlq $1,<xmm0=%xmm0
psrlq $1,%xmm0

# qhasm:     xmm0 ^= xmm9
# asm 1: pxor  <xmm9=int6464#10,<xmm0=int6464#1
# asm 2: pxor  <xmm9=%xmm9,<xmm0=%xmm0
pxor  %xmm9,%xmm0

# qhasm:     xmm0 &= BS0
# asm 1: pand  BS0,<xmm0=int6464#1
# asm 2: pand  BS0,<xmm0=%xmm0
pand  BS0,%xmm0

# qhasm:     xmm9 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm9=int6464#10
# asm 2: pxor  <xmm0=%xmm0,<xmm9=%xmm9
pxor  %xmm0,%xmm9

# qhasm:     uint6464 xmm0 <<= 1
# asm 1: psllq $1,<xmm0=int6464#1
# asm 2: psllq $1,<xmm0=%xmm0
psllq $1,%xmm0

# qhasm:     xmm8 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:     xmm0 = xmm15
# asm 1: movdqa <xmm15=int6464#16,>xmm0=int6464#1
# asm 2: movdqa <xmm15=%xmm15,>xmm0=%xmm0
movdqa %xmm15,%xmm0

# qhasm:     uint6464 xmm0 >>= 2
# asm 1: psrlq $2,<xmm0=int6464#1
# asm 2: psrlq $2,<xmm0=%xmm0
psrlq $2,%xmm0

# qhasm:     xmm0 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm0=int6464#1
# asm 2: pxor  <xmm13=%xmm13,<xmm0=%xmm0
pxor  %xmm13,%xmm0

# qhasm:     xmm0 &= BS1
# asm 1: pand  BS1,<xmm0=int6464#1
# asm 2: pand  BS1,<xmm0=%xmm0
pand  BS1,%xmm0

# qhasm:     xmm13 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm13=int6464#14
# asm 2: pxor  <xmm0=%xmm0,<xmm13=%xmm13
pxor  %xmm0,%xmm13

# qhasm:     uint6464 xmm0 <<= 2
# asm 1: psllq $2,<xmm0=int6464#1
# asm 2: psllq $2,<xmm0=%xmm0
psllq $2,%xmm0

# qhasm:     xmm15 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm15=int6464#16
# asm 2: pxor  <xmm0=%xmm0,<xmm15=%xmm15
pxor  %xmm0,%xmm15

# qhasm:     xmm0 = xmm11
# asm 1: movdqa <xmm11=int6464#12,>xmm0=int6464#1
# asm 2: movdqa <xmm11=%xmm11,>xmm0=%xmm0
movdqa %xmm11,%xmm0

# qhasm:     uint6464 xmm0 >>= 2
# asm 1: psrlq $2,<xmm0=int6464#1
# asm 2: psrlq $2,<xmm0=%xmm0
psrlq $2,%xmm0

# qhasm:     xmm0 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm0=int6464#1
# asm 2: pxor  <xmm10=%xmm10,<xmm0=%xmm0
pxor  %xmm10,%xmm0

# qhasm:     xmm0 &= BS1
# asm 1: pand  BS1,<xmm0=int6464#1
# asm 2: pand  BS1,<xmm0=%xmm0
pand  BS1,%xmm0

# qhasm:     xmm10 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm10=int6464#11
# asm 2: pxor  <xmm0=%xmm0,<xmm10=%xmm10
pxor  %xmm0,%xmm10

# qhasm:     uint6464 xmm0 <<= 2
# asm 1: psllq $2,<xmm0=int6464#1
# asm 2: psllq $2,<xmm0=%xmm0
psllq $2,%xmm0

# qhasm:     xmm11 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm11=int6464#12
# asm 2: pxor  <xmm0=%xmm0,<xmm11=%xmm11
pxor  %xmm0,%xmm11

# qhasm:     xmm0 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm0=int6464#1
# asm 2: movdqa <xmm9=%xmm9,>xmm0=%xmm0
movdqa %xmm9,%xmm0

# qhasm:     uint6464 xmm0 >>= 2
# asm 1: psrlq $2,<xmm0=int6464#1
# asm 2: psrlq $2,<xmm0=%xmm0
psrlq $2,%xmm0

# qhasm:     xmm0 ^= xmm14
# asm 1: pxor  <xmm14=int6464#15,<xmm0=int6464#1
# asm 2: pxor  <xmm14=%xmm14,<xmm0=%xmm0
pxor  %xmm14,%xmm0

# qhasm:     xmm0 &= BS1
# asm 1: pand  BS1,<xmm0=int6464#1
# asm 2: pand  BS1,<xmm0=%xmm0
pand  BS1,%xmm0

# qhasm:     xmm14 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm14=int6464#15
# asm 2: pxor  <xmm0=%xmm0,<xmm14=%xmm14
pxor  %xmm0,%xmm14

# qhasm:     uint6464 xmm0 <<= 2
# asm 1: psllq $2,<xmm0=int6464#1
# asm 2: psllq $2,<xmm0=%xmm0
psllq $2,%xmm0

# qhasm:     xmm9 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm9=int6464#10
# asm 2: pxor  <xmm0=%xmm0,<xmm9=%xmm9
pxor  %xmm0,%xmm9

# qhasm:     xmm0 = xmm8
# asm 1: movdqa <xmm8=int6464#9,>xmm0=int6464#1
# asm 2: movdqa <xmm8=%xmm8,>xmm0=%xmm0
movdqa %xmm8,%xmm0

# qhasm:     uint6464 xmm0 >>= 2
# asm 1: psrlq $2,<xmm0=int6464#1
# asm 2: psrlq $2,<xmm0=%xmm0
psrlq $2,%xmm0

# qhasm:     xmm0 ^= xmm12
# asm 1: pxor  <xmm12=int6464#13,<xmm0=int6464#1
# asm 2: pxor  <xmm12=%xmm12,<xmm0=%xmm0
pxor  %xmm12,%xmm0

# qhasm:     xmm0 &= BS1
# asm 1: pand  BS1,<xmm0=int6464#1
# asm 2: pand  BS1,<xmm0=%xmm0
pand  BS1,%xmm0

# qhasm:     xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:     uint6464 xmm0 <<= 2
# asm 1: psllq $2,<xmm0=int6464#1
# asm 2: psllq $2,<xmm0=%xmm0
psllq $2,%xmm0

# qhasm:     xmm8 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm:     xmm0 = xmm14
# asm 1: movdqa <xmm14=int6464#15,>xmm0=int6464#1
# asm 2: movdqa <xmm14=%xmm14,>xmm0=%xmm0
movdqa %xmm14,%xmm0

# qhasm:     uint6464 xmm0 >>= 4
# asm 1: psrlq $4,<xmm0=int6464#1
# asm 2: psrlq $4,<xmm0=%xmm0
psrlq $4,%xmm0

# qhasm:     xmm0 ^= xmm13
# asm 1: pxor  <xmm13=int6464#14,<xmm0=int6464#1
# asm 2: pxor  <xmm13=%xmm13,<xmm0=%xmm0
pxor  %xmm13,%xmm0

# qhasm:     xmm0 &= BS2
# asm 1: pand  BS2,<xmm0=int6464#1
# asm 2: pand  BS2,<xmm0=%xmm0
pand  BS2,%xmm0

# qhasm:     xmm13 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm13=int6464#14
# asm 2: pxor  <xmm0=%xmm0,<xmm13=%xmm13
pxor  %xmm0,%xmm13

# qhasm:     uint6464 xmm0 <<= 4
# asm 1: psllq $4,<xmm0=int6464#1
# asm 2: psllq $4,<xmm0=%xmm0
psllq $4,%xmm0

# qhasm:     xmm14 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm14=int6464#15
# asm 2: pxor  <xmm0=%xmm0,<xmm14=%xmm14
pxor  %xmm0,%xmm14

# qhasm:     xmm0 = xmm12
# asm 1: movdqa <xmm12=int6464#13,>xmm0=int6464#1
# asm 2: movdqa <xmm12=%xmm12,>xmm0=%xmm0
movdqa %xmm12,%xmm0

# qhasm:     uint6464 xmm0 >>= 4
# asm 1: psrlq $4,<xmm0=int6464#1
# asm 2: psrlq $4,<xmm0=%xmm0
psrlq $4,%xmm0

# qhasm:     xmm0 ^= xmm10
# asm 1: pxor  <xmm10=int6464#11,<xmm0=int6464#1
# asm 2: pxor  <xmm10=%xmm10,<xmm0=%xmm0
pxor  %xmm10,%xmm0

# qhasm:     xmm0 &= BS2
# asm 1: pand  BS2,<xmm0=int6464#1
# asm 2: pand  BS2,<xmm0=%xmm0
pand  BS2,%xmm0

# qhasm:     xmm10 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm10=int6464#11
# asm 2: pxor  <xmm0=%xmm0,<xmm10=%xmm10
pxor  %xmm0,%xmm10

# qhasm:     uint6464 xmm0 <<= 4
# asm 1: psllq $4,<xmm0=int6464#1
# asm 2: psllq $4,<xmm0=%xmm0
psllq $4,%xmm0

# qhasm:     xmm12 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm12=int6464#13
# asm 2: pxor  <xmm0=%xmm0,<xmm12=%xmm12
pxor  %xmm0,%xmm12

# qhasm:     xmm0 = xmm9
# asm 1: movdqa <xmm9=int6464#10,>xmm0=int6464#1
# asm 2: movdqa <xmm9=%xmm9,>xmm0=%xmm0
movdqa %xmm9,%xmm0

# qhasm:     uint6464 xmm0 >>= 4
# asm 1: psrlq $4,<xmm0=int6464#1
# asm 2: psrlq $4,<xmm0=%xmm0
psrlq $4,%xmm0

# qhasm:     xmm0 ^= xmm15
# asm 1: pxor  <xmm15=int6464#16,<xmm0=int6464#1
# asm 2: pxor  <xmm15=%xmm15,<xmm0=%xmm0
pxor  %xmm15,%xmm0

# qhasm:     xmm0 &= BS2
# asm 1: pand  BS2,<xmm0=int6464#1
# asm 2: pand  BS2,<xmm0=%xmm0
pand  BS2,%xmm0

# qhasm:     xmm15 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm15=int6464#16
# asm 2: pxor  <xmm0=%xmm0,<xmm15=%xmm15
pxor  %xmm0,%xmm15

# qhasm:     uint6464 xmm0 <<= 4
# asm 1: psllq $4,<xmm0=int6464#1
# asm 2: psllq $4,<xmm0=%xmm0
psllq $4,%xmm0

# qhasm:     xmm9 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm9=int6464#10
# asm 2: pxor  <xmm0=%xmm0,<xmm9=%xmm9
pxor  %xmm0,%xmm9

# qhasm:     xmm0 = xmm8
# asm 1: movdqa <xmm8=int6464#9,>xmm0=int6464#1
# asm 2: movdqa <xmm8=%xmm8,>xmm0=%xmm0
movdqa %xmm8,%xmm0

# qhasm:     uint6464 xmm0 >>= 4
# asm 1: psrlq $4,<xmm0=int6464#1
# asm 2: psrlq $4,<xmm0=%xmm0
psrlq $4,%xmm0

# qhasm:     xmm0 ^= xmm11
# asm 1: pxor  <xmm11=int6464#12,<xmm0=int6464#1
# asm 2: pxor  <xmm11=%xmm11,<xmm0=%xmm0
pxor  %xmm11,%xmm0

# qhasm:     xmm0 &= BS2
# asm 1: pand  BS2,<xmm0=int6464#1
# asm 2: pand  BS2,<xmm0=%xmm0
pand  BS2,%xmm0

# qhasm:     xmm11 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm11=int6464#12
# asm 2: pxor  <xmm0=%xmm0,<xmm11=%xmm11
pxor  %xmm0,%xmm11

# qhasm:     uint6464 xmm0 <<= 4
# asm 1: psllq $4,<xmm0=int6464#1
# asm 2: psllq $4,<xmm0=%xmm0
psllq $4,%xmm0

# qhasm:     xmm8 ^= xmm0
# asm 1: pxor  <xmm0=int6464#1,<xmm8=int6464#9
# asm 2: pxor  <xmm0=%xmm0,<xmm8=%xmm8
pxor  %xmm0,%xmm8

# qhasm: unsigned<? =? len-128
# asm 1: cmp  $128,<len=int64#2
# asm 2: cmp  $128,<len=%rsi
cmp  $128,%rsi
# comment:fp stack unchanged by jump

# qhasm: goto partial if unsigned<
jb ._partial
# comment:fp stack unchanged by jump

# qhasm: goto full if =
je ._full

# qhasm: tmp = *(uint32 *)(np + 12)
# asm 1: movl   12(<np=int64#3),>tmp=int64#5d
# asm 2: movl   12(<np=%rdx),>tmp=%r8d
movl   12(%rdx),%r8d

# qhasm: (uint32) bswap tmp
# asm 1: bswap <tmp=int64#5d
# asm 2: bswap <tmp=%r8d
bswap %r8d

# qhasm: tmp += 8
# asm 1: add  $8,<tmp=int64#5
# asm 2: add  $8,<tmp=%r8
add  $8,%r8

# qhasm: (uint32) bswap tmp
# asm 1: bswap <tmp=int64#5d
# asm 2: bswap <tmp=%r8d
bswap %r8d

# qhasm: *(uint32 *)(np + 12) = tmp
# asm 1: movl   <tmp=int64#5d,12(<np=int64#3)
# asm 2: movl   <tmp=%r8d,12(<np=%rdx)
movl   %r8d,12(%rdx)

# qhasm: *(int128 *) (outp + 0) = xmm8
# asm 1: movdqa <xmm8=int6464#9,0(<outp=int64#1)
# asm 2: movdqa <xmm8=%xmm8,0(<outp=%rdi)
movdqa %xmm8,0(%rdi)

# qhasm: *(int128 *) (outp + 16) = xmm9
# asm 1: movdqa <xmm9=int6464#10,16(<outp=int64#1)
# asm 2: movdqa <xmm9=%xmm9,16(<outp=%rdi)
movdqa %xmm9,16(%rdi)

# qhasm: *(int128 *) (outp + 32) = xmm12
# asm 1: movdqa <xmm12=int6464#13,32(<outp=int64#1)
# asm 2: movdqa <xmm12=%xmm12,32(<outp=%rdi)
movdqa %xmm12,32(%rdi)

# qhasm: *(int128 *) (outp + 48) = xmm14
# asm 1: movdqa <xmm14=int6464#15,48(<outp=int64#1)
# asm 2: movdqa <xmm14=%xmm14,48(<outp=%rdi)
movdqa %xmm14,48(%rdi)

# qhasm: *(int128 *) (outp + 64) = xmm11
# asm 1: movdqa <xmm11=int6464#12,64(<outp=int64#1)
# asm 2: movdqa <xmm11=%xmm11,64(<outp=%rdi)
movdqa %xmm11,64(%rdi)

# qhasm: *(int128 *) (outp + 80) = xmm15
# asm 1: movdqa <xmm15=int6464#16,80(<outp=int64#1)
# asm 2: movdqa <xmm15=%xmm15,80(<outp=%rdi)
movdqa %xmm15,80(%rdi)

# qhasm: *(int128 *) (outp + 96) = xmm10
# asm 1: movdqa <xmm10=int6464#11,96(<outp=int64#1)
# asm 2: movdqa <xmm10=%xmm10,96(<outp=%rdi)
movdqa %xmm10,96(%rdi)

# qhasm: *(int128 *) (outp + 112) = xmm13
# asm 1: movdqa <xmm13=int6464#14,112(<outp=int64#1)
# asm 2: movdqa <xmm13=%xmm13,112(<outp=%rdi)
movdqa %xmm13,112(%rdi)

# qhasm: len -= 128
# asm 1: sub  $128,<len=int64#2
# asm 2: sub  $128,<len=%rsi
sub  $128,%rsi

# qhasm: outp += 128
# asm 1: add  $128,<outp=int64#1
# asm 2: add  $128,<outp=%rdi
add  $128,%rdi
# comment:fp stack unchanged by jump

# qhasm: goto enc_block
jmp ._enc_block

# qhasm: partial:
._partial:

# qhasm: lensav = len
# asm 1: mov  <len=int64#2,>lensav=int64#4
# asm 2: mov  <len=%rsi,>lensav=%rcx
mov  %rsi,%rcx

# qhasm: (uint32) len >>= 4
# asm 1: shr  $4,<len=int64#2d
# asm 2: shr  $4,<len=%esi
shr  $4,%esi

# qhasm: tmp = *(uint32 *)(np + 12)
# asm 1: movl   12(<np=int64#3),>tmp=int64#5d
# asm 2: movl   12(<np=%rdx),>tmp=%r8d
movl   12(%rdx),%r8d

# qhasm: (uint32) bswap tmp
# asm 1: bswap <tmp=int64#5d
# asm 2: bswap <tmp=%r8d
bswap %r8d

# qhasm: tmp += len
# asm 1: add  <len=int64#2,<tmp=int64#5
# asm 2: add  <len=%rsi,<tmp=%r8
add  %rsi,%r8

# qhasm: (uint32) bswap tmp
# asm 1: bswap <tmp=int64#5d
# asm 2: bswap <tmp=%r8d
bswap %r8d

# qhasm: *(uint32 *)(np + 12) = tmp
# asm 1: movl   <tmp=int64#5d,12(<np=int64#3)
# asm 2: movl   <tmp=%r8d,12(<np=%rdx)
movl   %r8d,12(%rdx)

# qhasm: blp = &bl
# asm 1: leaq <bl=stack1024#1,>blp=int64#2
# asm 2: leaq <bl=32(%rsp),>blp=%rsi
leaq 32(%rsp),%rsi

# qhasm: *(int128 *)(blp + 0) = xmm8
# asm 1: movdqa <xmm8=int6464#9,0(<blp=int64#2)
# asm 2: movdqa <xmm8=%xmm8,0(<blp=%rsi)
movdqa %xmm8,0(%rsi)

# qhasm: *(int128 *)(blp + 16) = xmm9
# asm 1: movdqa <xmm9=int6464#10,16(<blp=int64#2)
# asm 2: movdqa <xmm9=%xmm9,16(<blp=%rsi)
movdqa %xmm9,16(%rsi)

# qhasm: *(int128 *)(blp + 32) = xmm12
# asm 1: movdqa <xmm12=int6464#13,32(<blp=int64#2)
# asm 2: movdqa <xmm12=%xmm12,32(<blp=%rsi)
movdqa %xmm12,32(%rsi)

# qhasm: *(int128 *)(blp + 48) = xmm14
# asm 1: movdqa <xmm14=int6464#15,48(<blp=int64#2)
# asm 2: movdqa <xmm14=%xmm14,48(<blp=%rsi)
movdqa %xmm14,48(%rsi)

# qhasm: *(int128 *)(blp + 64) = xmm11
# asm 1: movdqa <xmm11=int6464#12,64(<blp=int64#2)
# asm 2: movdqa <xmm11=%xmm11,64(<blp=%rsi)
movdqa %xmm11,64(%rsi)

# qhasm: *(int128 *)(blp + 80) = xmm15
# asm 1: movdqa <xmm15=int6464#16,80(<blp=int64#2)
# asm 2: movdqa <xmm15=%xmm15,80(<blp=%rsi)
movdqa %xmm15,80(%rsi)

# qhasm: *(int128 *)(blp + 96) = xmm10
# asm 1: movdqa <xmm10=int6464#11,96(<blp=int64#2)
# asm 2: movdqa <xmm10=%xmm10,96(<blp=%rsi)
movdqa %xmm10,96(%rsi)

# qhasm: *(int128 *)(blp + 112) = xmm13
# asm 1: movdqa <xmm13=int6464#14,112(<blp=int64#2)
# asm 2: movdqa <xmm13=%xmm13,112(<blp=%rsi)
movdqa %xmm13,112(%rsi)

# qhasm: bytes:
._bytes:

# qhasm: =? lensav-0
# asm 1: cmp  $0,<lensav=int64#4
# asm 2: cmp  $0,<lensav=%rcx
cmp  $0,%rcx
# comment:fp stack unchanged by jump

# qhasm: goto end if =
je ._end

# qhasm: b = *(uint8 *)(blp + 0)
# asm 1: movzbq 0(<blp=int64#2),>b=int64#3
# asm 2: movzbq 0(<blp=%rsi),>b=%rdx
movzbq 0(%rsi),%rdx

# qhasm: *(uint8 *)(outp + 0) = b
# asm 1: movb   <b=int64#3b,0(<outp=int64#1)
# asm 2: movb   <b=%dl,0(<outp=%rdi)
movb   %dl,0(%rdi)

# qhasm: blp += 1
# asm 1: add  $1,<blp=int64#2
# asm 2: add  $1,<blp=%rsi
add  $1,%rsi

# qhasm: outp +=1
# asm 1: add  $1,<outp=int64#1
# asm 2: add  $1,<outp=%rdi
add  $1,%rdi

# qhasm: lensav -= 1
# asm 1: sub  $1,<lensav=int64#4
# asm 2: sub  $1,<lensav=%rcx
sub  $1,%rcx
# comment:fp stack unchanged by jump

# qhasm: goto bytes
jmp ._bytes

# qhasm: full:
._full:

# qhasm: tmp = *(uint32 *)(np + 12)
# asm 1: movl   12(<np=int64#3),>tmp=int64#4d
# asm 2: movl   12(<np=%rdx),>tmp=%ecx
movl   12(%rdx),%ecx

# qhasm: (uint32) bswap tmp
# asm 1: bswap <tmp=int64#4d
# asm 2: bswap <tmp=%ecx
bswap %ecx

# qhasm: tmp += len
# asm 1: add  <len=int64#2,<tmp=int64#4
# asm 2: add  <len=%rsi,<tmp=%rcx
add  %rsi,%rcx

# qhasm: (uint32) bswap tmp
# asm 1: bswap <tmp=int64#4d
# asm 2: bswap <tmp=%ecx
bswap %ecx

# qhasm: *(uint32 *)(np + 12) = tmp
# asm 1: movl   <tmp=int64#4d,12(<np=int64#3)
# asm 2: movl   <tmp=%ecx,12(<np=%rdx)
movl   %ecx,12(%rdx)

# qhasm: *(int128 *) (outp + 0) = xmm8
# asm 1: movdqa <xmm8=int6464#9,0(<outp=int64#1)
# asm 2: movdqa <xmm8=%xmm8,0(<outp=%rdi)
movdqa %xmm8,0(%rdi)

# qhasm: *(int128 *) (outp + 16) = xmm9
# asm 1: movdqa <xmm9=int6464#10,16(<outp=int64#1)
# asm 2: movdqa <xmm9=%xmm9,16(<outp=%rdi)
movdqa %xmm9,16(%rdi)

# qhasm: *(int128 *) (outp + 32) = xmm12
# asm 1: movdqa <xmm12=int6464#13,32(<outp=int64#1)
# asm 2: movdqa <xmm12=%xmm12,32(<outp=%rdi)
movdqa %xmm12,32(%rdi)

# qhasm: *(int128 *) (outp + 48) = xmm14
# asm 1: movdqa <xmm14=int6464#15,48(<outp=int64#1)
# asm 2: movdqa <xmm14=%xmm14,48(<outp=%rdi)
movdqa %xmm14,48(%rdi)

# qhasm: *(int128 *) (outp + 64) = xmm11
# asm 1: movdqa <xmm11=int6464#12,64(<outp=int64#1)
# asm 2: movdqa <xmm11=%xmm11,64(<outp=%rdi)
movdqa %xmm11,64(%rdi)

# qhasm: *(int128 *) (outp + 80) = xmm15
# asm 1: movdqa <xmm15=int6464#16,80(<outp=int64#1)
# asm 2: movdqa <xmm15=%xmm15,80(<outp=%rdi)
movdqa %xmm15,80(%rdi)

# qhasm: *(int128 *) (outp + 96) = xmm10
# asm 1: movdqa <xmm10=int6464#11,96(<outp=int64#1)
# asm 2: movdqa <xmm10=%xmm10,96(<outp=%rdi)
movdqa %xmm10,96(%rdi)

# qhasm: *(int128 *) (outp + 112) = xmm13
# asm 1: movdqa <xmm13=int6464#14,112(<outp=int64#1)
# asm 2: movdqa <xmm13=%xmm13,112(<outp=%rdi)
movdqa %xmm13,112(%rdi)
# comment:fp stack unchanged by fallthrough

# qhasm: end:
._end:

# qhasm: leave
add %r11,%rsp
mov %rdi,%rax
mov %rsi,%rdx
xor %rax,%rax
ret
