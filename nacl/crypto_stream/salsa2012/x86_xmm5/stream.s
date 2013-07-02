
# qhasm: int32 a

# qhasm: stack32 arg1

# qhasm: stack32 arg2

# qhasm: stack32 arg3

# qhasm: stack32 arg4

# qhasm: stack32 arg5

# qhasm: stack32 arg6

# qhasm: input arg1

# qhasm: input arg2

# qhasm: input arg3

# qhasm: input arg4

# qhasm: input arg5

# qhasm: input arg6

# qhasm: int32 eax

# qhasm: int32 ebx

# qhasm: int32 esi

# qhasm: int32 edi

# qhasm: int32 ebp

# qhasm: caller eax

# qhasm: caller ebx

# qhasm: caller esi

# qhasm: caller edi

# qhasm: caller ebp

# qhasm: int32 k

# qhasm: int32 kbits

# qhasm: int32 iv

# qhasm: int32 i

# qhasm: stack128 x0

# qhasm: stack128 x1

# qhasm: stack128 x2

# qhasm: stack128 x3

# qhasm: int32 m

# qhasm: stack32 out_stack

# qhasm: int32 out

# qhasm: stack32 bytes_stack

# qhasm: int32 bytes

# qhasm: stack32 eax_stack

# qhasm: stack32 ebx_stack

# qhasm: stack32 esi_stack

# qhasm: stack32 edi_stack

# qhasm: stack32 ebp_stack

# qhasm: int6464 diag0

# qhasm: int6464 diag1

# qhasm: int6464 diag2

# qhasm: int6464 diag3

# qhasm: int6464 a0

# qhasm: int6464 a1

# qhasm: int6464 a2

# qhasm: int6464 a3

# qhasm: int6464 a4

# qhasm: int6464 a5

# qhasm: int6464 a6

# qhasm: int6464 a7

# qhasm: int6464 b0

# qhasm: int6464 b1

# qhasm: int6464 b2

# qhasm: int6464 b3

# qhasm: int6464 b4

# qhasm: int6464 b5

# qhasm: int6464 b6

# qhasm: int6464 b7

# qhasm: int6464 z0

# qhasm: int6464 z1

# qhasm: int6464 z2

# qhasm: int6464 z3

# qhasm: int6464 z4

# qhasm: int6464 z5

# qhasm: int6464 z6

# qhasm: int6464 z7

# qhasm: int6464 z8

# qhasm: int6464 z9

# qhasm: int6464 z10

# qhasm: int6464 z11

# qhasm: int6464 z12

# qhasm: int6464 z13

# qhasm: int6464 z14

# qhasm: int6464 z15

# qhasm: stack128 z0_stack

# qhasm: stack128 z1_stack

# qhasm: stack128 z2_stack

# qhasm: stack128 z3_stack

# qhasm: stack128 z4_stack

# qhasm: stack128 z5_stack

# qhasm: stack128 z6_stack

# qhasm: stack128 z7_stack

# qhasm: stack128 z8_stack

# qhasm: stack128 z9_stack

# qhasm: stack128 z10_stack

# qhasm: stack128 z11_stack

# qhasm: stack128 z12_stack

# qhasm: stack128 z13_stack

# qhasm: stack128 z14_stack

# qhasm: stack128 z15_stack

# qhasm: stack128 orig0

# qhasm: stack128 orig1

# qhasm: stack128 orig2

# qhasm: stack128 orig3

# qhasm: stack128 orig4

# qhasm: stack128 orig5

# qhasm: stack128 orig6

# qhasm: stack128 orig7

# qhasm: stack128 orig8

# qhasm: stack128 orig9

# qhasm: stack128 orig10

# qhasm: stack128 orig11

# qhasm: stack128 orig12

# qhasm: stack128 orig13

# qhasm: stack128 orig14

# qhasm: stack128 orig15

# qhasm: int6464 p

# qhasm: int6464 q

# qhasm: int6464 r

# qhasm: int6464 s

# qhasm: int6464 t

# qhasm: int6464 u

# qhasm: int6464 v

# qhasm: int6464 w

# qhasm: int6464 mp

# qhasm: int6464 mq

# qhasm: int6464 mr

# qhasm: int6464 ms

# qhasm: int6464 mt

# qhasm: int6464 mu

# qhasm: int6464 mv

# qhasm: int6464 mw

# qhasm: int32 in0

# qhasm: int32 in1

# qhasm: int32 in2

# qhasm: int32 in3

# qhasm: int32 in4

# qhasm: int32 in5

# qhasm: int32 in6

# qhasm: int32 in7

# qhasm: int32 in8

# qhasm: int32 in9

# qhasm: int32 in10

# qhasm: int32 in11

# qhasm: int32 in12

# qhasm: int32 in13

# qhasm: int32 in14

# qhasm: int32 in15

# qhasm: stack512 tmp

# qhasm: stack32 ctarget

# qhasm: enter crypto_stream_salsa2012_x86_xmm5
.text
.p2align 5
.globl _crypto_stream_salsa2012_x86_xmm5
.globl crypto_stream_salsa2012_x86_xmm5
_crypto_stream_salsa2012_x86_xmm5:
crypto_stream_salsa2012_x86_xmm5:
mov %esp,%eax
and $31,%eax
add $704,%eax
sub %eax,%esp

# qhasm: eax_stack = eax
# asm 1: movl <eax=int32#1,>eax_stack=stack32#1
# asm 2: movl <eax=%eax,>eax_stack=0(%esp)
movl %eax,0(%esp)

# qhasm: ebx_stack = ebx
# asm 1: movl <ebx=int32#4,>ebx_stack=stack32#2
# asm 2: movl <ebx=%ebx,>ebx_stack=4(%esp)
movl %ebx,4(%esp)

# qhasm: esi_stack = esi
# asm 1: movl <esi=int32#5,>esi_stack=stack32#3
# asm 2: movl <esi=%esi,>esi_stack=8(%esp)
movl %esi,8(%esp)

# qhasm: edi_stack = edi
# asm 1: movl <edi=int32#6,>edi_stack=stack32#4
# asm 2: movl <edi=%edi,>edi_stack=12(%esp)
movl %edi,12(%esp)

# qhasm: ebp_stack = ebp
# asm 1: movl <ebp=int32#7,>ebp_stack=stack32#5
# asm 2: movl <ebp=%ebp,>ebp_stack=16(%esp)
movl %ebp,16(%esp)

# qhasm: bytes = arg2
# asm 1: movl <arg2=stack32#-2,>bytes=int32#3
# asm 2: movl <arg2=8(%esp,%eax),>bytes=%edx
movl 8(%esp,%eax),%edx

# qhasm: out = arg1
# asm 1: movl <arg1=stack32#-1,>out=int32#6
# asm 2: movl <arg1=4(%esp,%eax),>out=%edi
movl 4(%esp,%eax),%edi

# qhasm: m = out
# asm 1: mov  <out=int32#6,>m=int32#5
# asm 2: mov  <out=%edi,>m=%esi
mov  %edi,%esi

# qhasm: iv = arg4
# asm 1: movl <arg4=stack32#-4,>iv=int32#4
# asm 2: movl <arg4=16(%esp,%eax),>iv=%ebx
movl 16(%esp,%eax),%ebx

# qhasm: k = arg5
# asm 1: movl <arg5=stack32#-5,>k=int32#7
# asm 2: movl <arg5=20(%esp,%eax),>k=%ebp
movl 20(%esp,%eax),%ebp

# qhasm:               unsigned>? bytes - 0
# asm 1: cmp  $0,<bytes=int32#3
# asm 2: cmp  $0,<bytes=%edx
cmp  $0,%edx
# comment:fp stack unchanged by jump

# qhasm: goto done if !unsigned>
jbe ._done

# qhasm: a = 0
# asm 1: mov  $0,>a=int32#1
# asm 2: mov  $0,>a=%eax
mov  $0,%eax

# qhasm: i = bytes
# asm 1: mov  <bytes=int32#3,>i=int32#2
# asm 2: mov  <bytes=%edx,>i=%ecx
mov  %edx,%ecx

# qhasm: while (i) { *out++ = a; --i }
rep stosb

# qhasm: out -= bytes
# asm 1: subl <bytes=int32#3,<out=int32#6
# asm 2: subl <bytes=%edx,<out=%edi
subl %edx,%edi
# comment:fp stack unchanged by jump

# qhasm: goto start
jmp ._start

# qhasm: enter crypto_stream_salsa2012_x86_xmm5_xor
.text
.p2align 5
.globl _crypto_stream_salsa2012_x86_xmm5_xor
.globl crypto_stream_salsa2012_x86_xmm5_xor
_crypto_stream_salsa2012_x86_xmm5_xor:
crypto_stream_salsa2012_x86_xmm5_xor:
mov %esp,%eax
and $31,%eax
add $704,%eax
sub %eax,%esp

# qhasm: eax_stack = eax
# asm 1: movl <eax=int32#1,>eax_stack=stack32#1
# asm 2: movl <eax=%eax,>eax_stack=0(%esp)
movl %eax,0(%esp)

# qhasm: ebx_stack = ebx
# asm 1: movl <ebx=int32#4,>ebx_stack=stack32#2
# asm 2: movl <ebx=%ebx,>ebx_stack=4(%esp)
movl %ebx,4(%esp)

# qhasm: esi_stack = esi
# asm 1: movl <esi=int32#5,>esi_stack=stack32#3
# asm 2: movl <esi=%esi,>esi_stack=8(%esp)
movl %esi,8(%esp)

# qhasm: edi_stack = edi
# asm 1: movl <edi=int32#6,>edi_stack=stack32#4
# asm 2: movl <edi=%edi,>edi_stack=12(%esp)
movl %edi,12(%esp)

# qhasm: ebp_stack = ebp
# asm 1: movl <ebp=int32#7,>ebp_stack=stack32#5
# asm 2: movl <ebp=%ebp,>ebp_stack=16(%esp)
movl %ebp,16(%esp)

# qhasm: out = arg1
# asm 1: movl <arg1=stack32#-1,>out=int32#6
# asm 2: movl <arg1=4(%esp,%eax),>out=%edi
movl 4(%esp,%eax),%edi

# qhasm: m = arg2
# asm 1: movl <arg2=stack32#-2,>m=int32#5
# asm 2: movl <arg2=8(%esp,%eax),>m=%esi
movl 8(%esp,%eax),%esi

# qhasm: bytes = arg3
# asm 1: movl <arg3=stack32#-3,>bytes=int32#3
# asm 2: movl <arg3=12(%esp,%eax),>bytes=%edx
movl 12(%esp,%eax),%edx

# qhasm: iv = arg5
# asm 1: movl <arg5=stack32#-5,>iv=int32#4
# asm 2: movl <arg5=20(%esp,%eax),>iv=%ebx
movl 20(%esp,%eax),%ebx

# qhasm: k = arg6
# asm 1: movl <arg6=stack32#-6,>k=int32#7
# asm 2: movl <arg6=24(%esp,%eax),>k=%ebp
movl 24(%esp,%eax),%ebp

# qhasm:               unsigned>? bytes - 0
# asm 1: cmp  $0,<bytes=int32#3
# asm 2: cmp  $0,<bytes=%edx
cmp  $0,%edx
# comment:fp stack unchanged by jump

# qhasm: goto done if !unsigned>
jbe ._done
# comment:fp stack unchanged by fallthrough

# qhasm: start:
._start:

# qhasm:   out_stack = out
# asm 1: movl <out=int32#6,>out_stack=stack32#6
# asm 2: movl <out=%edi,>out_stack=20(%esp)
movl %edi,20(%esp)

# qhasm:   bytes_stack = bytes
# asm 1: movl <bytes=int32#3,>bytes_stack=stack32#7
# asm 2: movl <bytes=%edx,>bytes_stack=24(%esp)
movl %edx,24(%esp)

# qhasm:   in4 = *(uint32 *) (k + 12)
# asm 1: movl 12(<k=int32#7),>in4=int32#1
# asm 2: movl 12(<k=%ebp),>in4=%eax
movl 12(%ebp),%eax

# qhasm:   in12 = *(uint32 *) (k + 20)
# asm 1: movl 20(<k=int32#7),>in12=int32#2
# asm 2: movl 20(<k=%ebp),>in12=%ecx
movl 20(%ebp),%ecx

# qhasm:   ((uint32 *)&x3)[0] = in4
# asm 1: movl <in4=int32#1,>x3=stack128#1
# asm 2: movl <in4=%eax,>x3=32(%esp)
movl %eax,32(%esp)

# qhasm:   ((uint32 *)&x1)[0] = in12
# asm 1: movl <in12=int32#2,>x1=stack128#2
# asm 2: movl <in12=%ecx,>x1=48(%esp)
movl %ecx,48(%esp)

# qhasm:   in0 = 1634760805
# asm 1: mov  $1634760805,>in0=int32#1
# asm 2: mov  $1634760805,>in0=%eax
mov  $1634760805,%eax

# qhasm:   in8 = 0
# asm 1: mov  $0,>in8=int32#2
# asm 2: mov  $0,>in8=%ecx
mov  $0,%ecx

# qhasm:   ((uint32 *)&x0)[0] = in0
# asm 1: movl <in0=int32#1,>x0=stack128#3
# asm 2: movl <in0=%eax,>x0=64(%esp)
movl %eax,64(%esp)

# qhasm:   ((uint32 *)&x2)[0] = in8
# asm 1: movl <in8=int32#2,>x2=stack128#4
# asm 2: movl <in8=%ecx,>x2=80(%esp)
movl %ecx,80(%esp)

# qhasm:   in6 = *(uint32 *) (iv + 0)
# asm 1: movl 0(<iv=int32#4),>in6=int32#1
# asm 2: movl 0(<iv=%ebx),>in6=%eax
movl 0(%ebx),%eax

# qhasm:   in7 = *(uint32 *) (iv + 4)
# asm 1: movl 4(<iv=int32#4),>in7=int32#2
# asm 2: movl 4(<iv=%ebx),>in7=%ecx
movl 4(%ebx),%ecx

# qhasm:   ((uint32 *)&x1)[2] = in6
# asm 1: movl <in6=int32#1,8+<x1=stack128#2
# asm 2: movl <in6=%eax,8+<x1=48(%esp)
movl %eax,8+48(%esp)

# qhasm:   ((uint32 *)&x2)[3] = in7
# asm 1: movl <in7=int32#2,12+<x2=stack128#4
# asm 2: movl <in7=%ecx,12+<x2=80(%esp)
movl %ecx,12+80(%esp)

# qhasm:   in9 = 0
# asm 1: mov  $0,>in9=int32#1
# asm 2: mov  $0,>in9=%eax
mov  $0,%eax

# qhasm:   in10 = 2036477234
# asm 1: mov  $2036477234,>in10=int32#2
# asm 2: mov  $2036477234,>in10=%ecx
mov  $2036477234,%ecx

# qhasm:   ((uint32 *)&x3)[1] = in9
# asm 1: movl <in9=int32#1,4+<x3=stack128#1
# asm 2: movl <in9=%eax,4+<x3=32(%esp)
movl %eax,4+32(%esp)

# qhasm:   ((uint32 *)&x0)[2] = in10
# asm 1: movl <in10=int32#2,8+<x0=stack128#3
# asm 2: movl <in10=%ecx,8+<x0=64(%esp)
movl %ecx,8+64(%esp)

# qhasm:   in1 = *(uint32 *) (k + 0)
# asm 1: movl 0(<k=int32#7),>in1=int32#1
# asm 2: movl 0(<k=%ebp),>in1=%eax
movl 0(%ebp),%eax

# qhasm:   in2 = *(uint32 *) (k + 4)
# asm 1: movl 4(<k=int32#7),>in2=int32#2
# asm 2: movl 4(<k=%ebp),>in2=%ecx
movl 4(%ebp),%ecx

# qhasm:   in3 = *(uint32 *) (k + 8)
# asm 1: movl 8(<k=int32#7),>in3=int32#3
# asm 2: movl 8(<k=%ebp),>in3=%edx
movl 8(%ebp),%edx

# qhasm:   in5 = 857760878
# asm 1: mov  $857760878,>in5=int32#4
# asm 2: mov  $857760878,>in5=%ebx
mov  $857760878,%ebx

# qhasm:   ((uint32 *)&x1)[1] = in1
# asm 1: movl <in1=int32#1,4+<x1=stack128#2
# asm 2: movl <in1=%eax,4+<x1=48(%esp)
movl %eax,4+48(%esp)

# qhasm:   ((uint32 *)&x2)[2] = in2
# asm 1: movl <in2=int32#2,8+<x2=stack128#4
# asm 2: movl <in2=%ecx,8+<x2=80(%esp)
movl %ecx,8+80(%esp)

# qhasm:   ((uint32 *)&x3)[3] = in3
# asm 1: movl <in3=int32#3,12+<x3=stack128#1
# asm 2: movl <in3=%edx,12+<x3=32(%esp)
movl %edx,12+32(%esp)

# qhasm:   ((uint32 *)&x0)[1] = in5
# asm 1: movl <in5=int32#4,4+<x0=stack128#3
# asm 2: movl <in5=%ebx,4+<x0=64(%esp)
movl %ebx,4+64(%esp)

# qhasm:   in11 = *(uint32 *) (k + 16)
# asm 1: movl 16(<k=int32#7),>in11=int32#1
# asm 2: movl 16(<k=%ebp),>in11=%eax
movl 16(%ebp),%eax

# qhasm:   in13 = *(uint32 *) (k + 24)
# asm 1: movl 24(<k=int32#7),>in13=int32#2
# asm 2: movl 24(<k=%ebp),>in13=%ecx
movl 24(%ebp),%ecx

# qhasm:   in14 = *(uint32 *) (k + 28)
# asm 1: movl 28(<k=int32#7),>in14=int32#3
# asm 2: movl 28(<k=%ebp),>in14=%edx
movl 28(%ebp),%edx

# qhasm:   in15 = 1797285236
# asm 1: mov  $1797285236,>in15=int32#4
# asm 2: mov  $1797285236,>in15=%ebx
mov  $1797285236,%ebx

# qhasm:   ((uint32 *)&x1)[3] = in11
# asm 1: movl <in11=int32#1,12+<x1=stack128#2
# asm 2: movl <in11=%eax,12+<x1=48(%esp)
movl %eax,12+48(%esp)

# qhasm:   ((uint32 *)&x2)[1] = in13
# asm 1: movl <in13=int32#2,4+<x2=stack128#4
# asm 2: movl <in13=%ecx,4+<x2=80(%esp)
movl %ecx,4+80(%esp)

# qhasm:   ((uint32 *)&x3)[2] = in14
# asm 1: movl <in14=int32#3,8+<x3=stack128#1
# asm 2: movl <in14=%edx,8+<x3=32(%esp)
movl %edx,8+32(%esp)

# qhasm:   ((uint32 *)&x0)[3] = in15
# asm 1: movl <in15=int32#4,12+<x0=stack128#3
# asm 2: movl <in15=%ebx,12+<x0=64(%esp)
movl %ebx,12+64(%esp)

# qhasm:   bytes = bytes_stack
# asm 1: movl <bytes_stack=stack32#7,>bytes=int32#1
# asm 2: movl <bytes_stack=24(%esp),>bytes=%eax
movl 24(%esp),%eax

# qhasm:                               unsigned<? bytes - 256
# asm 1: cmp  $256,<bytes=int32#1
# asm 2: cmp  $256,<bytes=%eax
cmp  $256,%eax
# comment:fp stack unchanged by jump

# qhasm:   goto bytesbetween1and255 if unsigned<
jb ._bytesbetween1and255

# qhasm:   z0 = x0
# asm 1: movdqa <x0=stack128#3,>z0=int6464#1
# asm 2: movdqa <x0=64(%esp),>z0=%xmm0
movdqa 64(%esp),%xmm0

# qhasm:   z5 = z0[1,1,1,1]
# asm 1: pshufd $0x55,<z0=int6464#1,>z5=int6464#2
# asm 2: pshufd $0x55,<z0=%xmm0,>z5=%xmm1
pshufd $0x55,%xmm0,%xmm1

# qhasm:   z10 = z0[2,2,2,2]
# asm 1: pshufd $0xaa,<z0=int6464#1,>z10=int6464#3
# asm 2: pshufd $0xaa,<z0=%xmm0,>z10=%xmm2
pshufd $0xaa,%xmm0,%xmm2

# qhasm:   z15 = z0[3,3,3,3]
# asm 1: pshufd $0xff,<z0=int6464#1,>z15=int6464#4
# asm 2: pshufd $0xff,<z0=%xmm0,>z15=%xmm3
pshufd $0xff,%xmm0,%xmm3

# qhasm:   z0 = z0[0,0,0,0]
# asm 1: pshufd $0x00,<z0=int6464#1,>z0=int6464#1
# asm 2: pshufd $0x00,<z0=%xmm0,>z0=%xmm0
pshufd $0x00,%xmm0,%xmm0

# qhasm:   orig5 = z5
# asm 1: movdqa <z5=int6464#2,>orig5=stack128#5
# asm 2: movdqa <z5=%xmm1,>orig5=96(%esp)
movdqa %xmm1,96(%esp)

# qhasm:   orig10 = z10
# asm 1: movdqa <z10=int6464#3,>orig10=stack128#6
# asm 2: movdqa <z10=%xmm2,>orig10=112(%esp)
movdqa %xmm2,112(%esp)

# qhasm:   orig15 = z15
# asm 1: movdqa <z15=int6464#4,>orig15=stack128#7
# asm 2: movdqa <z15=%xmm3,>orig15=128(%esp)
movdqa %xmm3,128(%esp)

# qhasm:   orig0 = z0
# asm 1: movdqa <z0=int6464#1,>orig0=stack128#8
# asm 2: movdqa <z0=%xmm0,>orig0=144(%esp)
movdqa %xmm0,144(%esp)

# qhasm:   z1 = x1
# asm 1: movdqa <x1=stack128#2,>z1=int6464#1
# asm 2: movdqa <x1=48(%esp),>z1=%xmm0
movdqa 48(%esp),%xmm0

# qhasm:   z6 = z1[2,2,2,2]
# asm 1: pshufd $0xaa,<z1=int6464#1,>z6=int6464#2
# asm 2: pshufd $0xaa,<z1=%xmm0,>z6=%xmm1
pshufd $0xaa,%xmm0,%xmm1

# qhasm:   z11 = z1[3,3,3,3]
# asm 1: pshufd $0xff,<z1=int6464#1,>z11=int6464#3
# asm 2: pshufd $0xff,<z1=%xmm0,>z11=%xmm2
pshufd $0xff,%xmm0,%xmm2

# qhasm:   z12 = z1[0,0,0,0]
# asm 1: pshufd $0x00,<z1=int6464#1,>z12=int6464#4
# asm 2: pshufd $0x00,<z1=%xmm0,>z12=%xmm3
pshufd $0x00,%xmm0,%xmm3

# qhasm:   z1 = z1[1,1,1,1]
# asm 1: pshufd $0x55,<z1=int6464#1,>z1=int6464#1
# asm 2: pshufd $0x55,<z1=%xmm0,>z1=%xmm0
pshufd $0x55,%xmm0,%xmm0

# qhasm:   orig6 = z6
# asm 1: movdqa <z6=int6464#2,>orig6=stack128#9
# asm 2: movdqa <z6=%xmm1,>orig6=160(%esp)
movdqa %xmm1,160(%esp)

# qhasm:   orig11 = z11
# asm 1: movdqa <z11=int6464#3,>orig11=stack128#10
# asm 2: movdqa <z11=%xmm2,>orig11=176(%esp)
movdqa %xmm2,176(%esp)

# qhasm:   orig12 = z12
# asm 1: movdqa <z12=int6464#4,>orig12=stack128#11
# asm 2: movdqa <z12=%xmm3,>orig12=192(%esp)
movdqa %xmm3,192(%esp)

# qhasm:   orig1 = z1
# asm 1: movdqa <z1=int6464#1,>orig1=stack128#12
# asm 2: movdqa <z1=%xmm0,>orig1=208(%esp)
movdqa %xmm0,208(%esp)

# qhasm:   z2 = x2
# asm 1: movdqa <x2=stack128#4,>z2=int6464#1
# asm 2: movdqa <x2=80(%esp),>z2=%xmm0
movdqa 80(%esp),%xmm0

# qhasm:   z7 = z2[3,3,3,3]
# asm 1: pshufd $0xff,<z2=int6464#1,>z7=int6464#2
# asm 2: pshufd $0xff,<z2=%xmm0,>z7=%xmm1
pshufd $0xff,%xmm0,%xmm1

# qhasm:   z13 = z2[1,1,1,1]
# asm 1: pshufd $0x55,<z2=int6464#1,>z13=int6464#3
# asm 2: pshufd $0x55,<z2=%xmm0,>z13=%xmm2
pshufd $0x55,%xmm0,%xmm2

# qhasm:   z2 = z2[2,2,2,2]
# asm 1: pshufd $0xaa,<z2=int6464#1,>z2=int6464#1
# asm 2: pshufd $0xaa,<z2=%xmm0,>z2=%xmm0
pshufd $0xaa,%xmm0,%xmm0

# qhasm:   orig7 = z7
# asm 1: movdqa <z7=int6464#2,>orig7=stack128#13
# asm 2: movdqa <z7=%xmm1,>orig7=224(%esp)
movdqa %xmm1,224(%esp)

# qhasm:   orig13 = z13
# asm 1: movdqa <z13=int6464#3,>orig13=stack128#14
# asm 2: movdqa <z13=%xmm2,>orig13=240(%esp)
movdqa %xmm2,240(%esp)

# qhasm:   orig2 = z2
# asm 1: movdqa <z2=int6464#1,>orig2=stack128#15
# asm 2: movdqa <z2=%xmm0,>orig2=256(%esp)
movdqa %xmm0,256(%esp)

# qhasm:   z3 = x3
# asm 1: movdqa <x3=stack128#1,>z3=int6464#1
# asm 2: movdqa <x3=32(%esp),>z3=%xmm0
movdqa 32(%esp),%xmm0

# qhasm:   z4 = z3[0,0,0,0]
# asm 1: pshufd $0x00,<z3=int6464#1,>z4=int6464#2
# asm 2: pshufd $0x00,<z3=%xmm0,>z4=%xmm1
pshufd $0x00,%xmm0,%xmm1

# qhasm:   z14 = z3[2,2,2,2]
# asm 1: pshufd $0xaa,<z3=int6464#1,>z14=int6464#3
# asm 2: pshufd $0xaa,<z3=%xmm0,>z14=%xmm2
pshufd $0xaa,%xmm0,%xmm2

# qhasm:   z3 = z3[3,3,3,3]
# asm 1: pshufd $0xff,<z3=int6464#1,>z3=int6464#1
# asm 2: pshufd $0xff,<z3=%xmm0,>z3=%xmm0
pshufd $0xff,%xmm0,%xmm0

# qhasm:   orig4 = z4
# asm 1: movdqa <z4=int6464#2,>orig4=stack128#16
# asm 2: movdqa <z4=%xmm1,>orig4=272(%esp)
movdqa %xmm1,272(%esp)

# qhasm:   orig14 = z14
# asm 1: movdqa <z14=int6464#3,>orig14=stack128#17
# asm 2: movdqa <z14=%xmm2,>orig14=288(%esp)
movdqa %xmm2,288(%esp)

# qhasm:   orig3 = z3
# asm 1: movdqa <z3=int6464#1,>orig3=stack128#18
# asm 2: movdqa <z3=%xmm0,>orig3=304(%esp)
movdqa %xmm0,304(%esp)

# qhasm: bytesatleast256:
._bytesatleast256:

# qhasm:   in8 = ((uint32 *)&x2)[0]
# asm 1: movl <x2=stack128#4,>in8=int32#2
# asm 2: movl <x2=80(%esp),>in8=%ecx
movl 80(%esp),%ecx

# qhasm:   in9 = ((uint32 *)&x3)[1]
# asm 1: movl 4+<x3=stack128#1,>in9=int32#3
# asm 2: movl 4+<x3=32(%esp),>in9=%edx
movl 4+32(%esp),%edx

# qhasm:   ((uint32 *) &orig8)[0] = in8
# asm 1: movl <in8=int32#2,>orig8=stack128#19
# asm 2: movl <in8=%ecx,>orig8=320(%esp)
movl %ecx,320(%esp)

# qhasm:   ((uint32 *) &orig9)[0] = in9
# asm 1: movl <in9=int32#3,>orig9=stack128#20
# asm 2: movl <in9=%edx,>orig9=336(%esp)
movl %edx,336(%esp)

# qhasm:   carry? in8 += 1
# asm 1: add  $1,<in8=int32#2
# asm 2: add  $1,<in8=%ecx
add  $1,%ecx

# qhasm:   in9 += 0 + carry
# asm 1: adc $0,<in9=int32#3
# asm 2: adc $0,<in9=%edx
adc $0,%edx

# qhasm:   ((uint32 *) &orig8)[1] = in8
# asm 1: movl <in8=int32#2,4+<orig8=stack128#19
# asm 2: movl <in8=%ecx,4+<orig8=320(%esp)
movl %ecx,4+320(%esp)

# qhasm:   ((uint32 *) &orig9)[1] = in9
# asm 1: movl <in9=int32#3,4+<orig9=stack128#20
# asm 2: movl <in9=%edx,4+<orig9=336(%esp)
movl %edx,4+336(%esp)

# qhasm:   carry? in8 += 1
# asm 1: add  $1,<in8=int32#2
# asm 2: add  $1,<in8=%ecx
add  $1,%ecx

# qhasm:   in9 += 0 + carry
# asm 1: adc $0,<in9=int32#3
# asm 2: adc $0,<in9=%edx
adc $0,%edx

# qhasm:   ((uint32 *) &orig8)[2] = in8
# asm 1: movl <in8=int32#2,8+<orig8=stack128#19
# asm 2: movl <in8=%ecx,8+<orig8=320(%esp)
movl %ecx,8+320(%esp)

# qhasm:   ((uint32 *) &orig9)[2] = in9
# asm 1: movl <in9=int32#3,8+<orig9=stack128#20
# asm 2: movl <in9=%edx,8+<orig9=336(%esp)
movl %edx,8+336(%esp)

# qhasm:   carry? in8 += 1
# asm 1: add  $1,<in8=int32#2
# asm 2: add  $1,<in8=%ecx
add  $1,%ecx

# qhasm:   in9 += 0 + carry
# asm 1: adc $0,<in9=int32#3
# asm 2: adc $0,<in9=%edx
adc $0,%edx

# qhasm:   ((uint32 *) &orig8)[3] = in8
# asm 1: movl <in8=int32#2,12+<orig8=stack128#19
# asm 2: movl <in8=%ecx,12+<orig8=320(%esp)
movl %ecx,12+320(%esp)

# qhasm:   ((uint32 *) &orig9)[3] = in9
# asm 1: movl <in9=int32#3,12+<orig9=stack128#20
# asm 2: movl <in9=%edx,12+<orig9=336(%esp)
movl %edx,12+336(%esp)

# qhasm:   carry? in8 += 1
# asm 1: add  $1,<in8=int32#2
# asm 2: add  $1,<in8=%ecx
add  $1,%ecx

# qhasm:   in9 += 0 + carry
# asm 1: adc $0,<in9=int32#3
# asm 2: adc $0,<in9=%edx
adc $0,%edx

# qhasm:   ((uint32 *)&x2)[0] = in8
# asm 1: movl <in8=int32#2,>x2=stack128#4
# asm 2: movl <in8=%ecx,>x2=80(%esp)
movl %ecx,80(%esp)

# qhasm:   ((uint32 *)&x3)[1] = in9
# asm 1: movl <in9=int32#3,4+<x3=stack128#1
# asm 2: movl <in9=%edx,4+<x3=32(%esp)
movl %edx,4+32(%esp)

# qhasm:   bytes_stack = bytes
# asm 1: movl <bytes=int32#1,>bytes_stack=stack32#7
# asm 2: movl <bytes=%eax,>bytes_stack=24(%esp)
movl %eax,24(%esp)

# qhasm: i = 12
# asm 1: mov  $12,>i=int32#1
# asm 2: mov  $12,>i=%eax
mov  $12,%eax

# qhasm:   z5 = orig5
# asm 1: movdqa <orig5=stack128#5,>z5=int6464#1
# asm 2: movdqa <orig5=96(%esp),>z5=%xmm0
movdqa 96(%esp),%xmm0

# qhasm:   z10 = orig10
# asm 1: movdqa <orig10=stack128#6,>z10=int6464#2
# asm 2: movdqa <orig10=112(%esp),>z10=%xmm1
movdqa 112(%esp),%xmm1

# qhasm:   z15 = orig15
# asm 1: movdqa <orig15=stack128#7,>z15=int6464#3
# asm 2: movdqa <orig15=128(%esp),>z15=%xmm2
movdqa 128(%esp),%xmm2

# qhasm:   z14 = orig14
# asm 1: movdqa <orig14=stack128#17,>z14=int6464#4
# asm 2: movdqa <orig14=288(%esp),>z14=%xmm3
movdqa 288(%esp),%xmm3

# qhasm:   z3 = orig3
# asm 1: movdqa <orig3=stack128#18,>z3=int6464#5
# asm 2: movdqa <orig3=304(%esp),>z3=%xmm4
movdqa 304(%esp),%xmm4

# qhasm:   z6 = orig6
# asm 1: movdqa <orig6=stack128#9,>z6=int6464#6
# asm 2: movdqa <orig6=160(%esp),>z6=%xmm5
movdqa 160(%esp),%xmm5

# qhasm:   z11 = orig11
# asm 1: movdqa <orig11=stack128#10,>z11=int6464#7
# asm 2: movdqa <orig11=176(%esp),>z11=%xmm6
movdqa 176(%esp),%xmm6

# qhasm:   z1 = orig1
# asm 1: movdqa <orig1=stack128#12,>z1=int6464#8
# asm 2: movdqa <orig1=208(%esp),>z1=%xmm7
movdqa 208(%esp),%xmm7

# qhasm:   z5_stack = z5
# asm 1: movdqa <z5=int6464#1,>z5_stack=stack128#21
# asm 2: movdqa <z5=%xmm0,>z5_stack=352(%esp)
movdqa %xmm0,352(%esp)

# qhasm:   z10_stack = z10
# asm 1: movdqa <z10=int6464#2,>z10_stack=stack128#22
# asm 2: movdqa <z10=%xmm1,>z10_stack=368(%esp)
movdqa %xmm1,368(%esp)

# qhasm:   z15_stack = z15
# asm 1: movdqa <z15=int6464#3,>z15_stack=stack128#23
# asm 2: movdqa <z15=%xmm2,>z15_stack=384(%esp)
movdqa %xmm2,384(%esp)

# qhasm:   z14_stack = z14
# asm 1: movdqa <z14=int6464#4,>z14_stack=stack128#24
# asm 2: movdqa <z14=%xmm3,>z14_stack=400(%esp)
movdqa %xmm3,400(%esp)

# qhasm:   z3_stack = z3
# asm 1: movdqa <z3=int6464#5,>z3_stack=stack128#25
# asm 2: movdqa <z3=%xmm4,>z3_stack=416(%esp)
movdqa %xmm4,416(%esp)

# qhasm:   z6_stack = z6
# asm 1: movdqa <z6=int6464#6,>z6_stack=stack128#26
# asm 2: movdqa <z6=%xmm5,>z6_stack=432(%esp)
movdqa %xmm5,432(%esp)

# qhasm:   z11_stack = z11
# asm 1: movdqa <z11=int6464#7,>z11_stack=stack128#27
# asm 2: movdqa <z11=%xmm6,>z11_stack=448(%esp)
movdqa %xmm6,448(%esp)

# qhasm:   z1_stack = z1
# asm 1: movdqa <z1=int6464#8,>z1_stack=stack128#28
# asm 2: movdqa <z1=%xmm7,>z1_stack=464(%esp)
movdqa %xmm7,464(%esp)

# qhasm:   z7 = orig7
# asm 1: movdqa <orig7=stack128#13,>z7=int6464#5
# asm 2: movdqa <orig7=224(%esp),>z7=%xmm4
movdqa 224(%esp),%xmm4

# qhasm:   z13 = orig13
# asm 1: movdqa <orig13=stack128#14,>z13=int6464#6
# asm 2: movdqa <orig13=240(%esp),>z13=%xmm5
movdqa 240(%esp),%xmm5

# qhasm:   z2 = orig2
# asm 1: movdqa <orig2=stack128#15,>z2=int6464#7
# asm 2: movdqa <orig2=256(%esp),>z2=%xmm6
movdqa 256(%esp),%xmm6

# qhasm:   z9 = orig9
# asm 1: movdqa <orig9=stack128#20,>z9=int6464#8
# asm 2: movdqa <orig9=336(%esp),>z9=%xmm7
movdqa 336(%esp),%xmm7

# qhasm:                   p = orig0
# asm 1: movdqa <orig0=stack128#8,>p=int6464#1
# asm 2: movdqa <orig0=144(%esp),>p=%xmm0
movdqa 144(%esp),%xmm0

# qhasm:                   t = orig12
# asm 1: movdqa <orig12=stack128#11,>t=int6464#3
# asm 2: movdqa <orig12=192(%esp),>t=%xmm2
movdqa 192(%esp),%xmm2

# qhasm:                   q = orig4
# asm 1: movdqa <orig4=stack128#16,>q=int6464#4
# asm 2: movdqa <orig4=272(%esp),>q=%xmm3
movdqa 272(%esp),%xmm3

# qhasm:                   r = orig8
# asm 1: movdqa <orig8=stack128#19,>r=int6464#2
# asm 2: movdqa <orig8=320(%esp),>r=%xmm1
movdqa 320(%esp),%xmm1

# qhasm:   z7_stack = z7
# asm 1: movdqa <z7=int6464#5,>z7_stack=stack128#29
# asm 2: movdqa <z7=%xmm4,>z7_stack=480(%esp)
movdqa %xmm4,480(%esp)

# qhasm:   z13_stack = z13
# asm 1: movdqa <z13=int6464#6,>z13_stack=stack128#30
# asm 2: movdqa <z13=%xmm5,>z13_stack=496(%esp)
movdqa %xmm5,496(%esp)

# qhasm:   z2_stack = z2
# asm 1: movdqa <z2=int6464#7,>z2_stack=stack128#31
# asm 2: movdqa <z2=%xmm6,>z2_stack=512(%esp)
movdqa %xmm6,512(%esp)

# qhasm:   z9_stack = z9
# asm 1: movdqa <z9=int6464#8,>z9_stack=stack128#32
# asm 2: movdqa <z9=%xmm7,>z9_stack=528(%esp)
movdqa %xmm7,528(%esp)

# qhasm:   z0_stack = p
# asm 1: movdqa <p=int6464#1,>z0_stack=stack128#33
# asm 2: movdqa <p=%xmm0,>z0_stack=544(%esp)
movdqa %xmm0,544(%esp)

# qhasm:   z12_stack = t
# asm 1: movdqa <t=int6464#3,>z12_stack=stack128#34
# asm 2: movdqa <t=%xmm2,>z12_stack=560(%esp)
movdqa %xmm2,560(%esp)

# qhasm:   z4_stack = q
# asm 1: movdqa <q=int6464#4,>z4_stack=stack128#35
# asm 2: movdqa <q=%xmm3,>z4_stack=576(%esp)
movdqa %xmm3,576(%esp)

# qhasm:   z8_stack = r
# asm 1: movdqa <r=int6464#2,>z8_stack=stack128#36
# asm 2: movdqa <r=%xmm1,>z8_stack=592(%esp)
movdqa %xmm1,592(%esp)

# qhasm: mainloop1:
._mainloop1:

# qhasm:                   assign xmm0 to p

# qhasm:                   assign xmm1 to r

# qhasm:                   assign xmm2 to t

# qhasm:                   assign xmm3 to q

# qhasm:                   s = t
# asm 1: movdqa <t=int6464#3,>s=int6464#7
# asm 2: movdqa <t=%xmm2,>s=%xmm6
movdqa %xmm2,%xmm6

# qhasm: uint32323232      t += p
# asm 1: paddd <p=int6464#1,<t=int6464#3
# asm 2: paddd <p=%xmm0,<t=%xmm2
paddd %xmm0,%xmm2

# qhasm:                   u = t
# asm 1: movdqa <t=int6464#3,>u=int6464#5
# asm 2: movdqa <t=%xmm2,>u=%xmm4
movdqa %xmm2,%xmm4

# qhasm: uint32323232      t >>= 25
# asm 1: psrld $25,<t=int6464#3
# asm 2: psrld $25,<t=%xmm2
psrld $25,%xmm2

# qhasm:                   q ^= t
# asm 1: pxor  <t=int6464#3,<q=int6464#4
# asm 2: pxor  <t=%xmm2,<q=%xmm3
pxor  %xmm2,%xmm3

# qhasm: uint32323232      u <<= 7
# asm 1: pslld $7,<u=int6464#5
# asm 2: pslld $7,<u=%xmm4
pslld $7,%xmm4

# qhasm:                   q ^= u
# asm 1: pxor  <u=int6464#5,<q=int6464#4
# asm 2: pxor  <u=%xmm4,<q=%xmm3
pxor  %xmm4,%xmm3

# qhasm:                   z4_stack = q
# asm 1: movdqa <q=int6464#4,>z4_stack=stack128#33
# asm 2: movdqa <q=%xmm3,>z4_stack=544(%esp)
movdqa %xmm3,544(%esp)

# qhasm:                   t = p
# asm 1: movdqa <p=int6464#1,>t=int6464#3
# asm 2: movdqa <p=%xmm0,>t=%xmm2
movdqa %xmm0,%xmm2

# qhasm: uint32323232      t += q
# asm 1: paddd <q=int6464#4,<t=int6464#3
# asm 2: paddd <q=%xmm3,<t=%xmm2
paddd %xmm3,%xmm2

# qhasm:                   u = t
# asm 1: movdqa <t=int6464#3,>u=int6464#5
# asm 2: movdqa <t=%xmm2,>u=%xmm4
movdqa %xmm2,%xmm4

# qhasm: uint32323232      t >>= 23
# asm 1: psrld $23,<t=int6464#3
# asm 2: psrld $23,<t=%xmm2
psrld $23,%xmm2

# qhasm:                   r ^= t
# asm 1: pxor  <t=int6464#3,<r=int6464#2
# asm 2: pxor  <t=%xmm2,<r=%xmm1
pxor  %xmm2,%xmm1

# qhasm: uint32323232      u <<= 9
# asm 1: pslld $9,<u=int6464#5
# asm 2: pslld $9,<u=%xmm4
pslld $9,%xmm4

# qhasm:                   r ^= u
# asm 1: pxor  <u=int6464#5,<r=int6464#2
# asm 2: pxor  <u=%xmm4,<r=%xmm1
pxor  %xmm4,%xmm1

# qhasm:                   z8_stack = r
# asm 1: movdqa <r=int6464#2,>z8_stack=stack128#34
# asm 2: movdqa <r=%xmm1,>z8_stack=560(%esp)
movdqa %xmm1,560(%esp)

# qhasm: uint32323232      q += r
# asm 1: paddd <r=int6464#2,<q=int6464#4
# asm 2: paddd <r=%xmm1,<q=%xmm3
paddd %xmm1,%xmm3

# qhasm:                   u = q
# asm 1: movdqa <q=int6464#4,>u=int6464#3
# asm 2: movdqa <q=%xmm3,>u=%xmm2
movdqa %xmm3,%xmm2

# qhasm: uint32323232      q >>= 19
# asm 1: psrld $19,<q=int6464#4
# asm 2: psrld $19,<q=%xmm3
psrld $19,%xmm3

# qhasm:                   s ^= q
# asm 1: pxor  <q=int6464#4,<s=int6464#7
# asm 2: pxor  <q=%xmm3,<s=%xmm6
pxor  %xmm3,%xmm6

# qhasm: uint32323232      u <<= 13
# asm 1: pslld $13,<u=int6464#3
# asm 2: pslld $13,<u=%xmm2
pslld $13,%xmm2

# qhasm:                   s ^= u
# asm 1: pxor  <u=int6464#3,<s=int6464#7
# asm 2: pxor  <u=%xmm2,<s=%xmm6
pxor  %xmm2,%xmm6

# qhasm:                                   mt = z1_stack
# asm 1: movdqa <z1_stack=stack128#28,>mt=int6464#3
# asm 2: movdqa <z1_stack=464(%esp),>mt=%xmm2
movdqa 464(%esp),%xmm2

# qhasm:                                   mp = z5_stack
# asm 1: movdqa <z5_stack=stack128#21,>mp=int6464#5
# asm 2: movdqa <z5_stack=352(%esp),>mp=%xmm4
movdqa 352(%esp),%xmm4

# qhasm:                                   mq = z9_stack
# asm 1: movdqa <z9_stack=stack128#32,>mq=int6464#4
# asm 2: movdqa <z9_stack=528(%esp),>mq=%xmm3
movdqa 528(%esp),%xmm3

# qhasm:                                   mr = z13_stack
# asm 1: movdqa <z13_stack=stack128#30,>mr=int6464#6
# asm 2: movdqa <z13_stack=496(%esp),>mr=%xmm5
movdqa 496(%esp),%xmm5

# qhasm:                   z12_stack = s
# asm 1: movdqa <s=int6464#7,>z12_stack=stack128#30
# asm 2: movdqa <s=%xmm6,>z12_stack=496(%esp)
movdqa %xmm6,496(%esp)

# qhasm: uint32323232      r += s
# asm 1: paddd <s=int6464#7,<r=int6464#2
# asm 2: paddd <s=%xmm6,<r=%xmm1
paddd %xmm6,%xmm1

# qhasm:                   u = r
# asm 1: movdqa <r=int6464#2,>u=int6464#7
# asm 2: movdqa <r=%xmm1,>u=%xmm6
movdqa %xmm1,%xmm6

# qhasm: uint32323232      r >>= 14
# asm 1: psrld $14,<r=int6464#2
# asm 2: psrld $14,<r=%xmm1
psrld $14,%xmm1

# qhasm:                   p ^= r
# asm 1: pxor  <r=int6464#2,<p=int6464#1
# asm 2: pxor  <r=%xmm1,<p=%xmm0
pxor  %xmm1,%xmm0

# qhasm: uint32323232      u <<= 18
# asm 1: pslld $18,<u=int6464#7
# asm 2: pslld $18,<u=%xmm6
pslld $18,%xmm6

# qhasm:                   p ^= u
# asm 1: pxor  <u=int6464#7,<p=int6464#1
# asm 2: pxor  <u=%xmm6,<p=%xmm0
pxor  %xmm6,%xmm0

# qhasm:                   z0_stack = p
# asm 1: movdqa <p=int6464#1,>z0_stack=stack128#21
# asm 2: movdqa <p=%xmm0,>z0_stack=352(%esp)
movdqa %xmm0,352(%esp)

# qhasm:                                   assign xmm2 to mt

# qhasm:                                   assign xmm3 to mq

# qhasm:                                   assign xmm4 to mp

# qhasm:                                   assign xmm5 to mr

# qhasm:                                   ms = mt
# asm 1: movdqa <mt=int6464#3,>ms=int6464#7
# asm 2: movdqa <mt=%xmm2,>ms=%xmm6
movdqa %xmm2,%xmm6

# qhasm: uint32323232                      mt += mp
# asm 1: paddd <mp=int6464#5,<mt=int6464#3
# asm 2: paddd <mp=%xmm4,<mt=%xmm2
paddd %xmm4,%xmm2

# qhasm:                                   mu = mt
# asm 1: movdqa <mt=int6464#3,>mu=int6464#1
# asm 2: movdqa <mt=%xmm2,>mu=%xmm0
movdqa %xmm2,%xmm0

# qhasm: uint32323232                      mt >>= 25
# asm 1: psrld $25,<mt=int6464#3
# asm 2: psrld $25,<mt=%xmm2
psrld $25,%xmm2

# qhasm:                                   mq ^= mt
# asm 1: pxor  <mt=int6464#3,<mq=int6464#4
# asm 2: pxor  <mt=%xmm2,<mq=%xmm3
pxor  %xmm2,%xmm3

# qhasm: uint32323232                      mu <<= 7
# asm 1: pslld $7,<mu=int6464#1
# asm 2: pslld $7,<mu=%xmm0
pslld $7,%xmm0

# qhasm:                                   mq ^= mu
# asm 1: pxor  <mu=int6464#1,<mq=int6464#4
# asm 2: pxor  <mu=%xmm0,<mq=%xmm3
pxor  %xmm0,%xmm3

# qhasm:                                   z9_stack = mq
# asm 1: movdqa <mq=int6464#4,>z9_stack=stack128#32
# asm 2: movdqa <mq=%xmm3,>z9_stack=528(%esp)
movdqa %xmm3,528(%esp)

# qhasm:                                   mt = mp
# asm 1: movdqa <mp=int6464#5,>mt=int6464#1
# asm 2: movdqa <mp=%xmm4,>mt=%xmm0
movdqa %xmm4,%xmm0

# qhasm: uint32323232                      mt += mq
# asm 1: paddd <mq=int6464#4,<mt=int6464#1
# asm 2: paddd <mq=%xmm3,<mt=%xmm0
paddd %xmm3,%xmm0

# qhasm:                                   mu = mt
# asm 1: movdqa <mt=int6464#1,>mu=int6464#2
# asm 2: movdqa <mt=%xmm0,>mu=%xmm1
movdqa %xmm0,%xmm1

# qhasm: uint32323232                      mt >>= 23
# asm 1: psrld $23,<mt=int6464#1
# asm 2: psrld $23,<mt=%xmm0
psrld $23,%xmm0

# qhasm:                                   mr ^= mt
# asm 1: pxor  <mt=int6464#1,<mr=int6464#6
# asm 2: pxor  <mt=%xmm0,<mr=%xmm5
pxor  %xmm0,%xmm5

# qhasm: uint32323232                      mu <<= 9
# asm 1: pslld $9,<mu=int6464#2
# asm 2: pslld $9,<mu=%xmm1
pslld $9,%xmm1

# qhasm:                                   mr ^= mu
# asm 1: pxor  <mu=int6464#2,<mr=int6464#6
# asm 2: pxor  <mu=%xmm1,<mr=%xmm5
pxor  %xmm1,%xmm5

# qhasm:                                   z13_stack = mr
# asm 1: movdqa <mr=int6464#6,>z13_stack=stack128#35
# asm 2: movdqa <mr=%xmm5,>z13_stack=576(%esp)
movdqa %xmm5,576(%esp)

# qhasm: uint32323232                      mq += mr
# asm 1: paddd <mr=int6464#6,<mq=int6464#4
# asm 2: paddd <mr=%xmm5,<mq=%xmm3
paddd %xmm5,%xmm3

# qhasm:                                   mu = mq
# asm 1: movdqa <mq=int6464#4,>mu=int6464#1
# asm 2: movdqa <mq=%xmm3,>mu=%xmm0
movdqa %xmm3,%xmm0

# qhasm: uint32323232                      mq >>= 19
# asm 1: psrld $19,<mq=int6464#4
# asm 2: psrld $19,<mq=%xmm3
psrld $19,%xmm3

# qhasm:                                   ms ^= mq
# asm 1: pxor  <mq=int6464#4,<ms=int6464#7
# asm 2: pxor  <mq=%xmm3,<ms=%xmm6
pxor  %xmm3,%xmm6

# qhasm: uint32323232                      mu <<= 13
# asm 1: pslld $13,<mu=int6464#1
# asm 2: pslld $13,<mu=%xmm0
pslld $13,%xmm0

# qhasm:                                   ms ^= mu
# asm 1: pxor  <mu=int6464#1,<ms=int6464#7
# asm 2: pxor  <mu=%xmm0,<ms=%xmm6
pxor  %xmm0,%xmm6

# qhasm:                                                   t = z6_stack
# asm 1: movdqa <z6_stack=stack128#26,>t=int6464#3
# asm 2: movdqa <z6_stack=432(%esp),>t=%xmm2
movdqa 432(%esp),%xmm2

# qhasm:                                                   p = z10_stack
# asm 1: movdqa <z10_stack=stack128#22,>p=int6464#1
# asm 2: movdqa <z10_stack=368(%esp),>p=%xmm0
movdqa 368(%esp),%xmm0

# qhasm:                                                   q = z14_stack
# asm 1: movdqa <z14_stack=stack128#24,>q=int6464#4
# asm 2: movdqa <z14_stack=400(%esp),>q=%xmm3
movdqa 400(%esp),%xmm3

# qhasm:                                                   r = z2_stack
# asm 1: movdqa <z2_stack=stack128#31,>r=int6464#2
# asm 2: movdqa <z2_stack=512(%esp),>r=%xmm1
movdqa 512(%esp),%xmm1

# qhasm:                                   z1_stack = ms
# asm 1: movdqa <ms=int6464#7,>z1_stack=stack128#22
# asm 2: movdqa <ms=%xmm6,>z1_stack=368(%esp)
movdqa %xmm6,368(%esp)

# qhasm: uint32323232                      mr += ms
# asm 1: paddd <ms=int6464#7,<mr=int6464#6
# asm 2: paddd <ms=%xmm6,<mr=%xmm5
paddd %xmm6,%xmm5

# qhasm:                                   mu = mr
# asm 1: movdqa <mr=int6464#6,>mu=int6464#7
# asm 2: movdqa <mr=%xmm5,>mu=%xmm6
movdqa %xmm5,%xmm6

# qhasm: uint32323232                      mr >>= 14
# asm 1: psrld $14,<mr=int6464#6
# asm 2: psrld $14,<mr=%xmm5
psrld $14,%xmm5

# qhasm:                                   mp ^= mr
# asm 1: pxor  <mr=int6464#6,<mp=int6464#5
# asm 2: pxor  <mr=%xmm5,<mp=%xmm4
pxor  %xmm5,%xmm4

# qhasm: uint32323232                      mu <<= 18
# asm 1: pslld $18,<mu=int6464#7
# asm 2: pslld $18,<mu=%xmm6
pslld $18,%xmm6

# qhasm:                                   mp ^= mu
# asm 1: pxor  <mu=int6464#7,<mp=int6464#5
# asm 2: pxor  <mu=%xmm6,<mp=%xmm4
pxor  %xmm6,%xmm4

# qhasm:                                   z5_stack = mp
# asm 1: movdqa <mp=int6464#5,>z5_stack=stack128#24
# asm 2: movdqa <mp=%xmm4,>z5_stack=400(%esp)
movdqa %xmm4,400(%esp)

# qhasm:                                                   assign xmm0 to p

# qhasm:                                                   assign xmm1 to r

# qhasm:                                                   assign xmm2 to t

# qhasm:                                                   assign xmm3 to q

# qhasm:                                                   s = t
# asm 1: movdqa <t=int6464#3,>s=int6464#7
# asm 2: movdqa <t=%xmm2,>s=%xmm6
movdqa %xmm2,%xmm6

# qhasm: uint32323232                                      t += p
# asm 1: paddd <p=int6464#1,<t=int6464#3
# asm 2: paddd <p=%xmm0,<t=%xmm2
paddd %xmm0,%xmm2

# qhasm:                                                   u = t
# asm 1: movdqa <t=int6464#3,>u=int6464#5
# asm 2: movdqa <t=%xmm2,>u=%xmm4
movdqa %xmm2,%xmm4

# qhasm: uint32323232                                      t >>= 25
# asm 1: psrld $25,<t=int6464#3
# asm 2: psrld $25,<t=%xmm2
psrld $25,%xmm2

# qhasm:                                                   q ^= t
# asm 1: pxor  <t=int6464#3,<q=int6464#4
# asm 2: pxor  <t=%xmm2,<q=%xmm3
pxor  %xmm2,%xmm3

# qhasm: uint32323232                                      u <<= 7
# asm 1: pslld $7,<u=int6464#5
# asm 2: pslld $7,<u=%xmm4
pslld $7,%xmm4

# qhasm:                                                   q ^= u
# asm 1: pxor  <u=int6464#5,<q=int6464#4
# asm 2: pxor  <u=%xmm4,<q=%xmm3
pxor  %xmm4,%xmm3

# qhasm:                                                   z14_stack = q
# asm 1: movdqa <q=int6464#4,>z14_stack=stack128#36
# asm 2: movdqa <q=%xmm3,>z14_stack=592(%esp)
movdqa %xmm3,592(%esp)

# qhasm:                                                   t = p
# asm 1: movdqa <p=int6464#1,>t=int6464#3
# asm 2: movdqa <p=%xmm0,>t=%xmm2
movdqa %xmm0,%xmm2

# qhasm: uint32323232                                      t += q
# asm 1: paddd <q=int6464#4,<t=int6464#3
# asm 2: paddd <q=%xmm3,<t=%xmm2
paddd %xmm3,%xmm2

# qhasm:                                                   u = t
# asm 1: movdqa <t=int6464#3,>u=int6464#5
# asm 2: movdqa <t=%xmm2,>u=%xmm4
movdqa %xmm2,%xmm4

# qhasm: uint32323232                                      t >>= 23
# asm 1: psrld $23,<t=int6464#3
# asm 2: psrld $23,<t=%xmm2
psrld $23,%xmm2

# qhasm:                                                   r ^= t
# asm 1: pxor  <t=int6464#3,<r=int6464#2
# asm 2: pxor  <t=%xmm2,<r=%xmm1
pxor  %xmm2,%xmm1

# qhasm: uint32323232                                      u <<= 9
# asm 1: pslld $9,<u=int6464#5
# asm 2: pslld $9,<u=%xmm4
pslld $9,%xmm4

# qhasm:                                                   r ^= u
# asm 1: pxor  <u=int6464#5,<r=int6464#2
# asm 2: pxor  <u=%xmm4,<r=%xmm1
pxor  %xmm4,%xmm1

# qhasm:                                                   z2_stack = r
# asm 1: movdqa <r=int6464#2,>z2_stack=stack128#26
# asm 2: movdqa <r=%xmm1,>z2_stack=432(%esp)
movdqa %xmm1,432(%esp)

# qhasm: uint32323232                                      q += r
# asm 1: paddd <r=int6464#2,<q=int6464#4
# asm 2: paddd <r=%xmm1,<q=%xmm3
paddd %xmm1,%xmm3

# qhasm:                                                   u = q
# asm 1: movdqa <q=int6464#4,>u=int6464#3
# asm 2: movdqa <q=%xmm3,>u=%xmm2
movdqa %xmm3,%xmm2

# qhasm: uint32323232                                      q >>= 19
# asm 1: psrld $19,<q=int6464#4
# asm 2: psrld $19,<q=%xmm3
psrld $19,%xmm3

# qhasm:                                                   s ^= q
# asm 1: pxor  <q=int6464#4,<s=int6464#7
# asm 2: pxor  <q=%xmm3,<s=%xmm6
pxor  %xmm3,%xmm6

# qhasm: uint32323232                                      u <<= 13
# asm 1: pslld $13,<u=int6464#3
# asm 2: pslld $13,<u=%xmm2
pslld $13,%xmm2

# qhasm:                                                   s ^= u
# asm 1: pxor  <u=int6464#3,<s=int6464#7
# asm 2: pxor  <u=%xmm2,<s=%xmm6
pxor  %xmm2,%xmm6

# qhasm:                                                                   mt = z11_stack
# asm 1: movdqa <z11_stack=stack128#27,>mt=int6464#3
# asm 2: movdqa <z11_stack=448(%esp),>mt=%xmm2
movdqa 448(%esp),%xmm2

# qhasm:                                                                   mp = z15_stack
# asm 1: movdqa <z15_stack=stack128#23,>mp=int6464#5
# asm 2: movdqa <z15_stack=384(%esp),>mp=%xmm4
movdqa 384(%esp),%xmm4

# qhasm:                                                                   mq = z3_stack
# asm 1: movdqa <z3_stack=stack128#25,>mq=int6464#4
# asm 2: movdqa <z3_stack=416(%esp),>mq=%xmm3
movdqa 416(%esp),%xmm3

# qhasm:                                                                   mr = z7_stack
# asm 1: movdqa <z7_stack=stack128#29,>mr=int6464#6
# asm 2: movdqa <z7_stack=480(%esp),>mr=%xmm5
movdqa 480(%esp),%xmm5

# qhasm:                                                   z6_stack = s
# asm 1: movdqa <s=int6464#7,>z6_stack=stack128#23
# asm 2: movdqa <s=%xmm6,>z6_stack=384(%esp)
movdqa %xmm6,384(%esp)

# qhasm: uint32323232                                      r += s
# asm 1: paddd <s=int6464#7,<r=int6464#2
# asm 2: paddd <s=%xmm6,<r=%xmm1
paddd %xmm6,%xmm1

# qhasm:                                                   u = r
# asm 1: movdqa <r=int6464#2,>u=int6464#7
# asm 2: movdqa <r=%xmm1,>u=%xmm6
movdqa %xmm1,%xmm6

# qhasm: uint32323232                                      r >>= 14
# asm 1: psrld $14,<r=int6464#2
# asm 2: psrld $14,<r=%xmm1
psrld $14,%xmm1

# qhasm:                                                   p ^= r
# asm 1: pxor  <r=int6464#2,<p=int6464#1
# asm 2: pxor  <r=%xmm1,<p=%xmm0
pxor  %xmm1,%xmm0

# qhasm: uint32323232                                      u <<= 18
# asm 1: pslld $18,<u=int6464#7
# asm 2: pslld $18,<u=%xmm6
pslld $18,%xmm6

# qhasm:                                                   p ^= u
# asm 1: pxor  <u=int6464#7,<p=int6464#1
# asm 2: pxor  <u=%xmm6,<p=%xmm0
pxor  %xmm6,%xmm0

# qhasm:                                                   z10_stack = p
# asm 1: movdqa <p=int6464#1,>z10_stack=stack128#27
# asm 2: movdqa <p=%xmm0,>z10_stack=448(%esp)
movdqa %xmm0,448(%esp)

# qhasm:                                                                   assign xmm2 to mt

# qhasm:                                                                   assign xmm3 to mq

# qhasm:                                                                   assign xmm4 to mp

# qhasm:                                                                   assign xmm5 to mr

# qhasm:                                                                   ms = mt
# asm 1: movdqa <mt=int6464#3,>ms=int6464#7
# asm 2: movdqa <mt=%xmm2,>ms=%xmm6
movdqa %xmm2,%xmm6

# qhasm: uint32323232                                                      mt += mp
# asm 1: paddd <mp=int6464#5,<mt=int6464#3
# asm 2: paddd <mp=%xmm4,<mt=%xmm2
paddd %xmm4,%xmm2

# qhasm:                                                                   mu = mt
# asm 1: movdqa <mt=int6464#3,>mu=int6464#1
# asm 2: movdqa <mt=%xmm2,>mu=%xmm0
movdqa %xmm2,%xmm0

# qhasm: uint32323232                                                      mt >>= 25
# asm 1: psrld $25,<mt=int6464#3
# asm 2: psrld $25,<mt=%xmm2
psrld $25,%xmm2

# qhasm:                                                                   mq ^= mt
# asm 1: pxor  <mt=int6464#3,<mq=int6464#4
# asm 2: pxor  <mt=%xmm2,<mq=%xmm3
pxor  %xmm2,%xmm3

# qhasm: uint32323232                                                      mu <<= 7
# asm 1: pslld $7,<mu=int6464#1
# asm 2: pslld $7,<mu=%xmm0
pslld $7,%xmm0

# qhasm:                                                                   mq ^= mu
# asm 1: pxor  <mu=int6464#1,<mq=int6464#4
# asm 2: pxor  <mu=%xmm0,<mq=%xmm3
pxor  %xmm0,%xmm3

# qhasm:                                                                   z3_stack = mq
# asm 1: movdqa <mq=int6464#4,>z3_stack=stack128#25
# asm 2: movdqa <mq=%xmm3,>z3_stack=416(%esp)
movdqa %xmm3,416(%esp)

# qhasm:                                                                   mt = mp
# asm 1: movdqa <mp=int6464#5,>mt=int6464#1
# asm 2: movdqa <mp=%xmm4,>mt=%xmm0
movdqa %xmm4,%xmm0

# qhasm: uint32323232                                                      mt += mq
# asm 1: paddd <mq=int6464#4,<mt=int6464#1
# asm 2: paddd <mq=%xmm3,<mt=%xmm0
paddd %xmm3,%xmm0

# qhasm:                                                                   mu = mt
# asm 1: movdqa <mt=int6464#1,>mu=int6464#2
# asm 2: movdqa <mt=%xmm0,>mu=%xmm1
movdqa %xmm0,%xmm1

# qhasm: uint32323232                                                      mt >>= 23
# asm 1: psrld $23,<mt=int6464#1
# asm 2: psrld $23,<mt=%xmm0
psrld $23,%xmm0

# qhasm:                                                                   mr ^= mt
# asm 1: pxor  <mt=int6464#1,<mr=int6464#6
# asm 2: pxor  <mt=%xmm0,<mr=%xmm5
pxor  %xmm0,%xmm5

# qhasm: uint32323232                                                      mu <<= 9
# asm 1: pslld $9,<mu=int6464#2
# asm 2: pslld $9,<mu=%xmm1
pslld $9,%xmm1

# qhasm:                                                                   mr ^= mu
# asm 1: pxor  <mu=int6464#2,<mr=int6464#6
# asm 2: pxor  <mu=%xmm1,<mr=%xmm5
pxor  %xmm1,%xmm5

# qhasm:                                                                   z7_stack = mr
# asm 1: movdqa <mr=int6464#6,>z7_stack=stack128#29
# asm 2: movdqa <mr=%xmm5,>z7_stack=480(%esp)
movdqa %xmm5,480(%esp)

# qhasm: uint32323232                                                      mq += mr
# asm 1: paddd <mr=int6464#6,<mq=int6464#4
# asm 2: paddd <mr=%xmm5,<mq=%xmm3
paddd %xmm5,%xmm3

# qhasm:                                                                   mu = mq
# asm 1: movdqa <mq=int6464#4,>mu=int6464#1
# asm 2: movdqa <mq=%xmm3,>mu=%xmm0
movdqa %xmm3,%xmm0

# qhasm: uint32323232                                                      mq >>= 19
# asm 1: psrld $19,<mq=int6464#4
# asm 2: psrld $19,<mq=%xmm3
psrld $19,%xmm3

# qhasm:                                                                   ms ^= mq
# asm 1: pxor  <mq=int6464#4,<ms=int6464#7
# asm 2: pxor  <mq=%xmm3,<ms=%xmm6
pxor  %xmm3,%xmm6

# qhasm: uint32323232                                                      mu <<= 13
# asm 1: pslld $13,<mu=int6464#1
# asm 2: pslld $13,<mu=%xmm0
pslld $13,%xmm0

# qhasm:                                                                   ms ^= mu
# asm 1: pxor  <mu=int6464#1,<ms=int6464#7
# asm 2: pxor  <mu=%xmm0,<ms=%xmm6
pxor  %xmm0,%xmm6

# qhasm:                   t = z3_stack
# asm 1: movdqa <z3_stack=stack128#25,>t=int6464#3
# asm 2: movdqa <z3_stack=416(%esp),>t=%xmm2
movdqa 416(%esp),%xmm2

# qhasm:                   p = z0_stack
# asm 1: movdqa <z0_stack=stack128#21,>p=int6464#1
# asm 2: movdqa <z0_stack=352(%esp),>p=%xmm0
movdqa 352(%esp),%xmm0

# qhasm:                   q = z1_stack
# asm 1: movdqa <z1_stack=stack128#22,>q=int6464#4
# asm 2: movdqa <z1_stack=368(%esp),>q=%xmm3
movdqa 368(%esp),%xmm3

# qhasm:                   r = z2_stack
# asm 1: movdqa <z2_stack=stack128#26,>r=int6464#2
# asm 2: movdqa <z2_stack=432(%esp),>r=%xmm1
movdqa 432(%esp),%xmm1

# qhasm:                                                                   z11_stack = ms
# asm 1: movdqa <ms=int6464#7,>z11_stack=stack128#21
# asm 2: movdqa <ms=%xmm6,>z11_stack=352(%esp)
movdqa %xmm6,352(%esp)

# qhasm: uint32323232                                                      mr += ms
# asm 1: paddd <ms=int6464#7,<mr=int6464#6
# asm 2: paddd <ms=%xmm6,<mr=%xmm5
paddd %xmm6,%xmm5

# qhasm:                                                                   mu = mr
# asm 1: movdqa <mr=int6464#6,>mu=int6464#7
# asm 2: movdqa <mr=%xmm5,>mu=%xmm6
movdqa %xmm5,%xmm6

# qhasm: uint32323232                                                      mr >>= 14
# asm 1: psrld $14,<mr=int6464#6
# asm 2: psrld $14,<mr=%xmm5
psrld $14,%xmm5

# qhasm:                                                                   mp ^= mr
# asm 1: pxor  <mr=int6464#6,<mp=int6464#5
# asm 2: pxor  <mr=%xmm5,<mp=%xmm4
pxor  %xmm5,%xmm4

# qhasm: uint32323232                                                      mu <<= 18
# asm 1: pslld $18,<mu=int6464#7
# asm 2: pslld $18,<mu=%xmm6
pslld $18,%xmm6

# qhasm:                                                                   mp ^= mu
# asm 1: pxor  <mu=int6464#7,<mp=int6464#5
# asm 2: pxor  <mu=%xmm6,<mp=%xmm4
pxor  %xmm6,%xmm4

# qhasm:                                                                   z15_stack = mp
# asm 1: movdqa <mp=int6464#5,>z15_stack=stack128#22
# asm 2: movdqa <mp=%xmm4,>z15_stack=368(%esp)
movdqa %xmm4,368(%esp)

# qhasm:                   assign xmm0 to p

# qhasm:                   assign xmm1 to r

# qhasm:                   assign xmm2 to t

# qhasm:                   assign xmm3 to q

# qhasm:                   s = t
# asm 1: movdqa <t=int6464#3,>s=int6464#7
# asm 2: movdqa <t=%xmm2,>s=%xmm6
movdqa %xmm2,%xmm6

# qhasm: uint32323232      t += p
# asm 1: paddd <p=int6464#1,<t=int6464#3
# asm 2: paddd <p=%xmm0,<t=%xmm2
paddd %xmm0,%xmm2

# qhasm:                   u = t
# asm 1: movdqa <t=int6464#3,>u=int6464#5
# asm 2: movdqa <t=%xmm2,>u=%xmm4
movdqa %xmm2,%xmm4

# qhasm: uint32323232      t >>= 25
# asm 1: psrld $25,<t=int6464#3
# asm 2: psrld $25,<t=%xmm2
psrld $25,%xmm2

# qhasm:                   q ^= t
# asm 1: pxor  <t=int6464#3,<q=int6464#4
# asm 2: pxor  <t=%xmm2,<q=%xmm3
pxor  %xmm2,%xmm3

# qhasm: uint32323232      u <<= 7
# asm 1: pslld $7,<u=int6464#5
# asm 2: pslld $7,<u=%xmm4
pslld $7,%xmm4

# qhasm:                   q ^= u
# asm 1: pxor  <u=int6464#5,<q=int6464#4
# asm 2: pxor  <u=%xmm4,<q=%xmm3
pxor  %xmm4,%xmm3

# qhasm:                   z1_stack = q
# asm 1: movdqa <q=int6464#4,>z1_stack=stack128#28
# asm 2: movdqa <q=%xmm3,>z1_stack=464(%esp)
movdqa %xmm3,464(%esp)

# qhasm:                   t = p
# asm 1: movdqa <p=int6464#1,>t=int6464#3
# asm 2: movdqa <p=%xmm0,>t=%xmm2
movdqa %xmm0,%xmm2

# qhasm: uint32323232      t += q
# asm 1: paddd <q=int6464#4,<t=int6464#3
# asm 2: paddd <q=%xmm3,<t=%xmm2
paddd %xmm3,%xmm2

# qhasm:                   u = t
# asm 1: movdqa <t=int6464#3,>u=int6464#5
# asm 2: movdqa <t=%xmm2,>u=%xmm4
movdqa %xmm2,%xmm4

# qhasm: uint32323232      t >>= 23
# asm 1: psrld $23,<t=int6464#3
# asm 2: psrld $23,<t=%xmm2
psrld $23,%xmm2

# qhasm:                   r ^= t
# asm 1: pxor  <t=int6464#3,<r=int6464#2
# asm 2: pxor  <t=%xmm2,<r=%xmm1
pxor  %xmm2,%xmm1

# qhasm: uint32323232      u <<= 9
# asm 1: pslld $9,<u=int6464#5
# asm 2: pslld $9,<u=%xmm4
pslld $9,%xmm4

# qhasm:                   r ^= u
# asm 1: pxor  <u=int6464#5,<r=int6464#2
# asm 2: pxor  <u=%xmm4,<r=%xmm1
pxor  %xmm4,%xmm1

# qhasm:                   z2_stack = r
# asm 1: movdqa <r=int6464#2,>z2_stack=stack128#31
# asm 2: movdqa <r=%xmm1,>z2_stack=512(%esp)
movdqa %xmm1,512(%esp)

# qhasm: uint32323232      q += r
# asm 1: paddd <r=int6464#2,<q=int6464#4
# asm 2: paddd <r=%xmm1,<q=%xmm3
paddd %xmm1,%xmm3

# qhasm:                   u = q
# asm 1: movdqa <q=int6464#4,>u=int6464#3
# asm 2: movdqa <q=%xmm3,>u=%xmm2
movdqa %xmm3,%xmm2

# qhasm: uint32323232      q >>= 19
# asm 1: psrld $19,<q=int6464#4
# asm 2: psrld $19,<q=%xmm3
psrld $19,%xmm3

# qhasm:                   s ^= q
# asm 1: pxor  <q=int6464#4,<s=int6464#7
# asm 2: pxor  <q=%xmm3,<s=%xmm6
pxor  %xmm3,%xmm6

# qhasm: uint32323232      u <<= 13
# asm 1: pslld $13,<u=int6464#3
# asm 2: pslld $13,<u=%xmm2
pslld $13,%xmm2

# qhasm:                   s ^= u
# asm 1: pxor  <u=int6464#3,<s=int6464#7
# asm 2: pxor  <u=%xmm2,<s=%xmm6
pxor  %xmm2,%xmm6

# qhasm:                                   mt = z4_stack
# asm 1: movdqa <z4_stack=stack128#33,>mt=int6464#3
# asm 2: movdqa <z4_stack=544(%esp),>mt=%xmm2
movdqa 544(%esp),%xmm2

# qhasm:                                   mp = z5_stack
# asm 1: movdqa <z5_stack=stack128#24,>mp=int6464#5
# asm 2: movdqa <z5_stack=400(%esp),>mp=%xmm4
movdqa 400(%esp),%xmm4

# qhasm:                                   mq = z6_stack
# asm 1: movdqa <z6_stack=stack128#23,>mq=int6464#4
# asm 2: movdqa <z6_stack=384(%esp),>mq=%xmm3
movdqa 384(%esp),%xmm3

# qhasm:                                   mr = z7_stack
# asm 1: movdqa <z7_stack=stack128#29,>mr=int6464#6
# asm 2: movdqa <z7_stack=480(%esp),>mr=%xmm5
movdqa 480(%esp),%xmm5

# qhasm:                   z3_stack = s
# asm 1: movdqa <s=int6464#7,>z3_stack=stack128#25
# asm 2: movdqa <s=%xmm6,>z3_stack=416(%esp)
movdqa %xmm6,416(%esp)

# qhasm: uint32323232      r += s
# asm 1: paddd <s=int6464#7,<r=int6464#2
# asm 2: paddd <s=%xmm6,<r=%xmm1
paddd %xmm6,%xmm1

# qhasm:                   u = r
# asm 1: movdqa <r=int6464#2,>u=int6464#7
# asm 2: movdqa <r=%xmm1,>u=%xmm6
movdqa %xmm1,%xmm6

# qhasm: uint32323232      r >>= 14
# asm 1: psrld $14,<r=int6464#2
# asm 2: psrld $14,<r=%xmm1
psrld $14,%xmm1

# qhasm:                   p ^= r
# asm 1: pxor  <r=int6464#2,<p=int6464#1
# asm 2: pxor  <r=%xmm1,<p=%xmm0
pxor  %xmm1,%xmm0

# qhasm: uint32323232      u <<= 18
# asm 1: pslld $18,<u=int6464#7
# asm 2: pslld $18,<u=%xmm6
pslld $18,%xmm6

# qhasm:                   p ^= u
# asm 1: pxor  <u=int6464#7,<p=int6464#1
# asm 2: pxor  <u=%xmm6,<p=%xmm0
pxor  %xmm6,%xmm0

# qhasm:                   z0_stack = p
# asm 1: movdqa <p=int6464#1,>z0_stack=stack128#33
# asm 2: movdqa <p=%xmm0,>z0_stack=544(%esp)
movdqa %xmm0,544(%esp)

# qhasm:                                   assign xmm2 to mt

# qhasm:                                   assign xmm3 to mq

# qhasm:                                   assign xmm4 to mp

# qhasm:                                   assign xmm5 to mr

# qhasm:                                   ms = mt
# asm 1: movdqa <mt=int6464#3,>ms=int6464#7
# asm 2: movdqa <mt=%xmm2,>ms=%xmm6
movdqa %xmm2,%xmm6

# qhasm: uint32323232                      mt += mp
# asm 1: paddd <mp=int6464#5,<mt=int6464#3
# asm 2: paddd <mp=%xmm4,<mt=%xmm2
paddd %xmm4,%xmm2

# qhasm:                                   mu = mt
# asm 1: movdqa <mt=int6464#3,>mu=int6464#1
# asm 2: movdqa <mt=%xmm2,>mu=%xmm0
movdqa %xmm2,%xmm0

# qhasm: uint32323232                      mt >>= 25
# asm 1: psrld $25,<mt=int6464#3
# asm 2: psrld $25,<mt=%xmm2
psrld $25,%xmm2

# qhasm:                                   mq ^= mt
# asm 1: pxor  <mt=int6464#3,<mq=int6464#4
# asm 2: pxor  <mt=%xmm2,<mq=%xmm3
pxor  %xmm2,%xmm3

# qhasm: uint32323232                      mu <<= 7
# asm 1: pslld $7,<mu=int6464#1
# asm 2: pslld $7,<mu=%xmm0
pslld $7,%xmm0

# qhasm:                                   mq ^= mu
# asm 1: pxor  <mu=int6464#1,<mq=int6464#4
# asm 2: pxor  <mu=%xmm0,<mq=%xmm3
pxor  %xmm0,%xmm3

# qhasm:                                   z6_stack = mq
# asm 1: movdqa <mq=int6464#4,>z6_stack=stack128#26
# asm 2: movdqa <mq=%xmm3,>z6_stack=432(%esp)
movdqa %xmm3,432(%esp)

# qhasm:                                   mt = mp
# asm 1: movdqa <mp=int6464#5,>mt=int6464#1
# asm 2: movdqa <mp=%xmm4,>mt=%xmm0
movdqa %xmm4,%xmm0

# qhasm: uint32323232                      mt += mq
# asm 1: paddd <mq=int6464#4,<mt=int6464#1
# asm 2: paddd <mq=%xmm3,<mt=%xmm0
paddd %xmm3,%xmm0

# qhasm:                                   mu = mt
# asm 1: movdqa <mt=int6464#1,>mu=int6464#2
# asm 2: movdqa <mt=%xmm0,>mu=%xmm1
movdqa %xmm0,%xmm1

# qhasm: uint32323232                      mt >>= 23
# asm 1: psrld $23,<mt=int6464#1
# asm 2: psrld $23,<mt=%xmm0
psrld $23,%xmm0

# qhasm:                                   mr ^= mt
# asm 1: pxor  <mt=int6464#1,<mr=int6464#6
# asm 2: pxor  <mt=%xmm0,<mr=%xmm5
pxor  %xmm0,%xmm5

# qhasm: uint32323232                      mu <<= 9
# asm 1: pslld $9,<mu=int6464#2
# asm 2: pslld $9,<mu=%xmm1
pslld $9,%xmm1

# qhasm:                                   mr ^= mu
# asm 1: pxor  <mu=int6464#2,<mr=int6464#6
# asm 2: pxor  <mu=%xmm1,<mr=%xmm5
pxor  %xmm1,%xmm5

# qhasm:                                   z7_stack = mr
# asm 1: movdqa <mr=int6464#6,>z7_stack=stack128#29
# asm 2: movdqa <mr=%xmm5,>z7_stack=480(%esp)
movdqa %xmm5,480(%esp)

# qhasm: uint32323232                      mq += mr
# asm 1: paddd <mr=int6464#6,<mq=int6464#4
# asm 2: paddd <mr=%xmm5,<mq=%xmm3
paddd %xmm5,%xmm3

# qhasm:                                   mu = mq
# asm 1: movdqa <mq=int6464#4,>mu=int6464#1
# asm 2: movdqa <mq=%xmm3,>mu=%xmm0
movdqa %xmm3,%xmm0

# qhasm: uint32323232                      mq >>= 19
# asm 1: psrld $19,<mq=int6464#4
# asm 2: psrld $19,<mq=%xmm3
psrld $19,%xmm3

# qhasm:                                   ms ^= mq
# asm 1: pxor  <mq=int6464#4,<ms=int6464#7
# asm 2: pxor  <mq=%xmm3,<ms=%xmm6
pxor  %xmm3,%xmm6

# qhasm: uint32323232                      mu <<= 13
# asm 1: pslld $13,<mu=int6464#1
# asm 2: pslld $13,<mu=%xmm0
pslld $13,%xmm0

# qhasm:                                   ms ^= mu
# asm 1: pxor  <mu=int6464#1,<ms=int6464#7
# asm 2: pxor  <mu=%xmm0,<ms=%xmm6
pxor  %xmm0,%xmm6

# qhasm:                                                   t = z9_stack
# asm 1: movdqa <z9_stack=stack128#32,>t=int6464#3
# asm 2: movdqa <z9_stack=528(%esp),>t=%xmm2
movdqa 528(%esp),%xmm2

# qhasm:                                                   p = z10_stack
# asm 1: movdqa <z10_stack=stack128#27,>p=int6464#1
# asm 2: movdqa <z10_stack=448(%esp),>p=%xmm0
movdqa 448(%esp),%xmm0

# qhasm:                                                   q = z11_stack
# asm 1: movdqa <z11_stack=stack128#21,>q=int6464#4
# asm 2: movdqa <z11_stack=352(%esp),>q=%xmm3
movdqa 352(%esp),%xmm3

# qhasm:                                                   r = z8_stack
# asm 1: movdqa <z8_stack=stack128#34,>r=int6464#2
# asm 2: movdqa <z8_stack=560(%esp),>r=%xmm1
movdqa 560(%esp),%xmm1

# qhasm:                                   z4_stack = ms
# asm 1: movdqa <ms=int6464#7,>z4_stack=stack128#34
# asm 2: movdqa <ms=%xmm6,>z4_stack=560(%esp)
movdqa %xmm6,560(%esp)

# qhasm: uint32323232                      mr += ms
# asm 1: paddd <ms=int6464#7,<mr=int6464#6
# asm 2: paddd <ms=%xmm6,<mr=%xmm5
paddd %xmm6,%xmm5

# qhasm:                                   mu = mr
# asm 1: movdqa <mr=int6464#6,>mu=int6464#7
# asm 2: movdqa <mr=%xmm5,>mu=%xmm6
movdqa %xmm5,%xmm6

# qhasm: uint32323232                      mr >>= 14
# asm 1: psrld $14,<mr=int6464#6
# asm 2: psrld $14,<mr=%xmm5
psrld $14,%xmm5

# qhasm:                                   mp ^= mr
# asm 1: pxor  <mr=int6464#6,<mp=int6464#5
# asm 2: pxor  <mr=%xmm5,<mp=%xmm4
pxor  %xmm5,%xmm4

# qhasm: uint32323232                      mu <<= 18
# asm 1: pslld $18,<mu=int6464#7
# asm 2: pslld $18,<mu=%xmm6
pslld $18,%xmm6

# qhasm:                                   mp ^= mu
# asm 1: pxor  <mu=int6464#7,<mp=int6464#5
# asm 2: pxor  <mu=%xmm6,<mp=%xmm4
pxor  %xmm6,%xmm4

# qhasm:                                   z5_stack = mp
# asm 1: movdqa <mp=int6464#5,>z5_stack=stack128#21
# asm 2: movdqa <mp=%xmm4,>z5_stack=352(%esp)
movdqa %xmm4,352(%esp)

# qhasm:                                                   assign xmm0 to p

# qhasm:                                                   assign xmm1 to r

# qhasm:                                                   assign xmm2 to t

# qhasm:                                                   assign xmm3 to q

# qhasm:                                                   s = t
# asm 1: movdqa <t=int6464#3,>s=int6464#7
# asm 2: movdqa <t=%xmm2,>s=%xmm6
movdqa %xmm2,%xmm6

# qhasm: uint32323232                                      t += p
# asm 1: paddd <p=int6464#1,<t=int6464#3
# asm 2: paddd <p=%xmm0,<t=%xmm2
paddd %xmm0,%xmm2

# qhasm:                                                   u = t
# asm 1: movdqa <t=int6464#3,>u=int6464#5
# asm 2: movdqa <t=%xmm2,>u=%xmm4
movdqa %xmm2,%xmm4

# qhasm: uint32323232                                      t >>= 25
# asm 1: psrld $25,<t=int6464#3
# asm 2: psrld $25,<t=%xmm2
psrld $25,%xmm2

# qhasm:                                                   q ^= t
# asm 1: pxor  <t=int6464#3,<q=int6464#4
# asm 2: pxor  <t=%xmm2,<q=%xmm3
pxor  %xmm2,%xmm3

# qhasm: uint32323232                                      u <<= 7
# asm 1: pslld $7,<u=int6464#5
# asm 2: pslld $7,<u=%xmm4
pslld $7,%xmm4

# qhasm:                                                   q ^= u
# asm 1: pxor  <u=int6464#5,<q=int6464#4
# asm 2: pxor  <u=%xmm4,<q=%xmm3
pxor  %xmm4,%xmm3

# qhasm:                                                   z11_stack = q
# asm 1: movdqa <q=int6464#4,>z11_stack=stack128#27
# asm 2: movdqa <q=%xmm3,>z11_stack=448(%esp)
movdqa %xmm3,448(%esp)

# qhasm:                                                   t = p
# asm 1: movdqa <p=int6464#1,>t=int6464#3
# asm 2: movdqa <p=%xmm0,>t=%xmm2
movdqa %xmm0,%xmm2

# qhasm: uint32323232                                      t += q
# asm 1: paddd <q=int6464#4,<t=int6464#3
# asm 2: paddd <q=%xmm3,<t=%xmm2
paddd %xmm3,%xmm2

# qhasm:                                                   u = t
# asm 1: movdqa <t=int6464#3,>u=int6464#5
# asm 2: movdqa <t=%xmm2,>u=%xmm4
movdqa %xmm2,%xmm4

# qhasm: uint32323232                                      t >>= 23
# asm 1: psrld $23,<t=int6464#3
# asm 2: psrld $23,<t=%xmm2
psrld $23,%xmm2

# qhasm:                                                   r ^= t
# asm 1: pxor  <t=int6464#3,<r=int6464#2
# asm 2: pxor  <t=%xmm2,<r=%xmm1
pxor  %xmm2,%xmm1

# qhasm: uint32323232                                      u <<= 9
# asm 1: pslld $9,<u=int6464#5
# asm 2: pslld $9,<u=%xmm4
pslld $9,%xmm4

# qhasm:                                                   r ^= u
# asm 1: pxor  <u=int6464#5,<r=int6464#2
# asm 2: pxor  <u=%xmm4,<r=%xmm1
pxor  %xmm4,%xmm1

# qhasm:                                                   z8_stack = r
# asm 1: movdqa <r=int6464#2,>z8_stack=stack128#37
# asm 2: movdqa <r=%xmm1,>z8_stack=608(%esp)
movdqa %xmm1,608(%esp)

# qhasm: uint32323232                                      q += r
# asm 1: paddd <r=int6464#2,<q=int6464#4
# asm 2: paddd <r=%xmm1,<q=%xmm3
paddd %xmm1,%xmm3

# qhasm:                                                   u = q
# asm 1: movdqa <q=int6464#4,>u=int6464#3
# asm 2: movdqa <q=%xmm3,>u=%xmm2
movdqa %xmm3,%xmm2

# qhasm: uint32323232                                      q >>= 19
# asm 1: psrld $19,<q=int6464#4
# asm 2: psrld $19,<q=%xmm3
psrld $19,%xmm3

# qhasm:                                                   s ^= q
# asm 1: pxor  <q=int6464#4,<s=int6464#7
# asm 2: pxor  <q=%xmm3,<s=%xmm6
pxor  %xmm3,%xmm6

# qhasm: uint32323232                                      u <<= 13
# asm 1: pslld $13,<u=int6464#3
# asm 2: pslld $13,<u=%xmm2
pslld $13,%xmm2

# qhasm:                                                   s ^= u
# asm 1: pxor  <u=int6464#3,<s=int6464#7
# asm 2: pxor  <u=%xmm2,<s=%xmm6
pxor  %xmm2,%xmm6

# qhasm:                                                                   mt = z14_stack
# asm 1: movdqa <z14_stack=stack128#36,>mt=int6464#3
# asm 2: movdqa <z14_stack=592(%esp),>mt=%xmm2
movdqa 592(%esp),%xmm2

# qhasm:                                                                   mp = z15_stack
# asm 1: movdqa <z15_stack=stack128#22,>mp=int6464#5
# asm 2: movdqa <z15_stack=368(%esp),>mp=%xmm4
movdqa 368(%esp),%xmm4

# qhasm:                                                                   mq = z12_stack
# asm 1: movdqa <z12_stack=stack128#30,>mq=int6464#4
# asm 2: movdqa <z12_stack=496(%esp),>mq=%xmm3
movdqa 496(%esp),%xmm3

# qhasm:                                                                   mr = z13_stack
# asm 1: movdqa <z13_stack=stack128#35,>mr=int6464#6
# asm 2: movdqa <z13_stack=576(%esp),>mr=%xmm5
movdqa 576(%esp),%xmm5

# qhasm:                                                   z9_stack = s
# asm 1: movdqa <s=int6464#7,>z9_stack=stack128#32
# asm 2: movdqa <s=%xmm6,>z9_stack=528(%esp)
movdqa %xmm6,528(%esp)

# qhasm: uint32323232                                      r += s
# asm 1: paddd <s=int6464#7,<r=int6464#2
# asm 2: paddd <s=%xmm6,<r=%xmm1
paddd %xmm6,%xmm1

# qhasm:                                                   u = r
# asm 1: movdqa <r=int6464#2,>u=int6464#7
# asm 2: movdqa <r=%xmm1,>u=%xmm6
movdqa %xmm1,%xmm6

# qhasm: uint32323232                                      r >>= 14
# asm 1: psrld $14,<r=int6464#2
# asm 2: psrld $14,<r=%xmm1
psrld $14,%xmm1

# qhasm:                                                   p ^= r
# asm 1: pxor  <r=int6464#2,<p=int6464#1
# asm 2: pxor  <r=%xmm1,<p=%xmm0
pxor  %xmm1,%xmm0

# qhasm: uint32323232                                      u <<= 18
# asm 1: pslld $18,<u=int6464#7
# asm 2: pslld $18,<u=%xmm6
pslld $18,%xmm6

# qhasm:                                                   p ^= u
# asm 1: pxor  <u=int6464#7,<p=int6464#1
# asm 2: pxor  <u=%xmm6,<p=%xmm0
pxor  %xmm6,%xmm0

# qhasm:                                                   z10_stack = p
# asm 1: movdqa <p=int6464#1,>z10_stack=stack128#22
# asm 2: movdqa <p=%xmm0,>z10_stack=368(%esp)
movdqa %xmm0,368(%esp)

# qhasm:                                                                   assign xmm2 to mt

# qhasm:                                                                   assign xmm3 to mq

# qhasm:                                                                   assign xmm4 to mp

# qhasm:                                                                   assign xmm5 to mr

# qhasm:                                                                   ms = mt
# asm 1: movdqa <mt=int6464#3,>ms=int6464#7
# asm 2: movdqa <mt=%xmm2,>ms=%xmm6
movdqa %xmm2,%xmm6

# qhasm: uint32323232                                                      mt += mp
# asm 1: paddd <mp=int6464#5,<mt=int6464#3
# asm 2: paddd <mp=%xmm4,<mt=%xmm2
paddd %xmm4,%xmm2

# qhasm:                                                                   mu = mt
# asm 1: movdqa <mt=int6464#3,>mu=int6464#1
# asm 2: movdqa <mt=%xmm2,>mu=%xmm0
movdqa %xmm2,%xmm0

# qhasm: uint32323232                                                      mt >>= 25
# asm 1: psrld $25,<mt=int6464#3
# asm 2: psrld $25,<mt=%xmm2
psrld $25,%xmm2

# qhasm:                                                                   mq ^= mt
# asm 1: pxor  <mt=int6464#3,<mq=int6464#4
# asm 2: pxor  <mt=%xmm2,<mq=%xmm3
pxor  %xmm2,%xmm3

# qhasm: uint32323232                                                      mu <<= 7
# asm 1: pslld $7,<mu=int6464#1
# asm 2: pslld $7,<mu=%xmm0
pslld $7,%xmm0

# qhasm:                                                                   mq ^= mu
# asm 1: pxor  <mu=int6464#1,<mq=int6464#4
# asm 2: pxor  <mu=%xmm0,<mq=%xmm3
pxor  %xmm0,%xmm3

# qhasm:                                                                   z12_stack = mq
# asm 1: movdqa <mq=int6464#4,>z12_stack=stack128#35
# asm 2: movdqa <mq=%xmm3,>z12_stack=576(%esp)
movdqa %xmm3,576(%esp)

# qhasm:                                                                   mt = mp
# asm 1: movdqa <mp=int6464#5,>mt=int6464#1
# asm 2: movdqa <mp=%xmm4,>mt=%xmm0
movdqa %xmm4,%xmm0

# qhasm: uint32323232                                                      mt += mq
# asm 1: paddd <mq=int6464#4,<mt=int6464#1
# asm 2: paddd <mq=%xmm3,<mt=%xmm0
paddd %xmm3,%xmm0

# qhasm:                                                                   mu = mt
# asm 1: movdqa <mt=int6464#1,>mu=int6464#2
# asm 2: movdqa <mt=%xmm0,>mu=%xmm1
movdqa %xmm0,%xmm1

# qhasm: uint32323232                                                      mt >>= 23
# asm 1: psrld $23,<mt=int6464#1
# asm 2: psrld $23,<mt=%xmm0
psrld $23,%xmm0

# qhasm:                                                                   mr ^= mt
# asm 1: pxor  <mt=int6464#1,<mr=int6464#6
# asm 2: pxor  <mt=%xmm0,<mr=%xmm5
pxor  %xmm0,%xmm5

# qhasm: uint32323232                                                      mu <<= 9
# asm 1: pslld $9,<mu=int6464#2
# asm 2: pslld $9,<mu=%xmm1
pslld $9,%xmm1

# qhasm:                                                                   mr ^= mu
# asm 1: pxor  <mu=int6464#2,<mr=int6464#6
# asm 2: pxor  <mu=%xmm1,<mr=%xmm5
pxor  %xmm1,%xmm5

# qhasm:                                                                   z13_stack = mr
# asm 1: movdqa <mr=int6464#6,>z13_stack=stack128#30
# asm 2: movdqa <mr=%xmm5,>z13_stack=496(%esp)
movdqa %xmm5,496(%esp)

# qhasm: uint32323232                                                      mq += mr
# asm 1: paddd <mr=int6464#6,<mq=int6464#4
# asm 2: paddd <mr=%xmm5,<mq=%xmm3
paddd %xmm5,%xmm3

# qhasm:                                                                   mu = mq
# asm 1: movdqa <mq=int6464#4,>mu=int6464#1
# asm 2: movdqa <mq=%xmm3,>mu=%xmm0
movdqa %xmm3,%xmm0

# qhasm: uint32323232                                                      mq >>= 19
# asm 1: psrld $19,<mq=int6464#4
# asm 2: psrld $19,<mq=%xmm3
psrld $19,%xmm3

# qhasm:                                                                   ms ^= mq
# asm 1: pxor  <mq=int6464#4,<ms=int6464#7
# asm 2: pxor  <mq=%xmm3,<ms=%xmm6
pxor  %xmm3,%xmm6

# qhasm: uint32323232                                                      mu <<= 13
# asm 1: pslld $13,<mu=int6464#1
# asm 2: pslld $13,<mu=%xmm0
pslld $13,%xmm0

# qhasm:                                                                   ms ^= mu
# asm 1: pxor  <mu=int6464#1,<ms=int6464#7
# asm 2: pxor  <mu=%xmm0,<ms=%xmm6
pxor  %xmm0,%xmm6

# qhasm:                   t = z12_stack
# asm 1: movdqa <z12_stack=stack128#35,>t=int6464#3
# asm 2: movdqa <z12_stack=576(%esp),>t=%xmm2
movdqa 576(%esp),%xmm2

# qhasm:                   p = z0_stack
# asm 1: movdqa <z0_stack=stack128#33,>p=int6464#1
# asm 2: movdqa <z0_stack=544(%esp),>p=%xmm0
movdqa 544(%esp),%xmm0

# qhasm:                   q = z4_stack
# asm 1: movdqa <z4_stack=stack128#34,>q=int6464#4
# asm 2: movdqa <z4_stack=560(%esp),>q=%xmm3
movdqa 560(%esp),%xmm3

# qhasm:                   r = z8_stack
# asm 1: movdqa <z8_stack=stack128#37,>r=int6464#2
# asm 2: movdqa <z8_stack=608(%esp),>r=%xmm1
movdqa 608(%esp),%xmm1

# qhasm:                                                                   z14_stack = ms
# asm 1: movdqa <ms=int6464#7,>z14_stack=stack128#24
# asm 2: movdqa <ms=%xmm6,>z14_stack=400(%esp)
movdqa %xmm6,400(%esp)

# qhasm: uint32323232                                                      mr += ms
# asm 1: paddd <ms=int6464#7,<mr=int6464#6
# asm 2: paddd <ms=%xmm6,<mr=%xmm5
paddd %xmm6,%xmm5

# qhasm:                                                                   mu = mr
# asm 1: movdqa <mr=int6464#6,>mu=int6464#7
# asm 2: movdqa <mr=%xmm5,>mu=%xmm6
movdqa %xmm5,%xmm6

# qhasm: uint32323232                                                      mr >>= 14
# asm 1: psrld $14,<mr=int6464#6
# asm 2: psrld $14,<mr=%xmm5
psrld $14,%xmm5

# qhasm:                                                                   mp ^= mr
# asm 1: pxor  <mr=int6464#6,<mp=int6464#5
# asm 2: pxor  <mr=%xmm5,<mp=%xmm4
pxor  %xmm5,%xmm4

# qhasm: uint32323232                                                      mu <<= 18
# asm 1: pslld $18,<mu=int6464#7
# asm 2: pslld $18,<mu=%xmm6
pslld $18,%xmm6

# qhasm:                                                                   mp ^= mu
# asm 1: pxor  <mu=int6464#7,<mp=int6464#5
# asm 2: pxor  <mu=%xmm6,<mp=%xmm4
pxor  %xmm6,%xmm4

# qhasm:                                                                   z15_stack = mp
# asm 1: movdqa <mp=int6464#5,>z15_stack=stack128#23
# asm 2: movdqa <mp=%xmm4,>z15_stack=384(%esp)
movdqa %xmm4,384(%esp)

# qhasm:                   unsigned>? i -= 2
# asm 1: sub  $2,<i=int32#1
# asm 2: sub  $2,<i=%eax
sub  $2,%eax
# comment:fp stack unchanged by jump

# qhasm: goto mainloop1 if unsigned>
ja ._mainloop1

# qhasm:   out = out_stack
# asm 1: movl <out_stack=stack32#6,>out=int32#6
# asm 2: movl <out_stack=20(%esp),>out=%edi
movl 20(%esp),%edi

# qhasm:   z0 = z0_stack
# asm 1: movdqa <z0_stack=stack128#33,>z0=int6464#1
# asm 2: movdqa <z0_stack=544(%esp),>z0=%xmm0
movdqa 544(%esp),%xmm0

# qhasm:   z1 = z1_stack
# asm 1: movdqa <z1_stack=stack128#28,>z1=int6464#2
# asm 2: movdqa <z1_stack=464(%esp),>z1=%xmm1
movdqa 464(%esp),%xmm1

# qhasm:   z2 = z2_stack
# asm 1: movdqa <z2_stack=stack128#31,>z2=int6464#3
# asm 2: movdqa <z2_stack=512(%esp),>z2=%xmm2
movdqa 512(%esp),%xmm2

# qhasm:   z3 = z3_stack
# asm 1: movdqa <z3_stack=stack128#25,>z3=int6464#4
# asm 2: movdqa <z3_stack=416(%esp),>z3=%xmm3
movdqa 416(%esp),%xmm3

# qhasm:   uint32323232 z0 += orig0
# asm 1: paddd <orig0=stack128#8,<z0=int6464#1
# asm 2: paddd <orig0=144(%esp),<z0=%xmm0
paddd 144(%esp),%xmm0

# qhasm:   uint32323232 z1 += orig1
# asm 1: paddd <orig1=stack128#12,<z1=int6464#2
# asm 2: paddd <orig1=208(%esp),<z1=%xmm1
paddd 208(%esp),%xmm1

# qhasm:   uint32323232 z2 += orig2
# asm 1: paddd <orig2=stack128#15,<z2=int6464#3
# asm 2: paddd <orig2=256(%esp),<z2=%xmm2
paddd 256(%esp),%xmm2

# qhasm:   uint32323232 z3 += orig3
# asm 1: paddd <orig3=stack128#18,<z3=int6464#4
# asm 2: paddd <orig3=304(%esp),<z3=%xmm3
paddd 304(%esp),%xmm3

# qhasm:   in0 = z0
# asm 1: movd   <z0=int6464#1,>in0=int32#1
# asm 2: movd   <z0=%xmm0,>in0=%eax
movd   %xmm0,%eax

# qhasm:   in1 = z1
# asm 1: movd   <z1=int6464#2,>in1=int32#2
# asm 2: movd   <z1=%xmm1,>in1=%ecx
movd   %xmm1,%ecx

# qhasm:   in2 = z2
# asm 1: movd   <z2=int6464#3,>in2=int32#3
# asm 2: movd   <z2=%xmm2,>in2=%edx
movd   %xmm2,%edx

# qhasm:   in3 = z3
# asm 1: movd   <z3=int6464#4,>in3=int32#4
# asm 2: movd   <z3=%xmm3,>in3=%ebx
movd   %xmm3,%ebx

# qhasm:   z0 <<<= 96
# asm 1: pshufd $0x39,<z0=int6464#1,<z0=int6464#1
# asm 2: pshufd $0x39,<z0=%xmm0,<z0=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm:   z1 <<<= 96
# asm 1: pshufd $0x39,<z1=int6464#2,<z1=int6464#2
# asm 2: pshufd $0x39,<z1=%xmm1,<z1=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm:   z2 <<<= 96
# asm 1: pshufd $0x39,<z2=int6464#3,<z2=int6464#3
# asm 2: pshufd $0x39,<z2=%xmm2,<z2=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm:   z3 <<<= 96
# asm 1: pshufd $0x39,<z3=int6464#4,<z3=int6464#4
# asm 2: pshufd $0x39,<z3=%xmm3,<z3=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm:   in0 ^= *(uint32 *) (m + 0)
# asm 1: xorl 0(<m=int32#5),<in0=int32#1
# asm 2: xorl 0(<m=%esi),<in0=%eax
xorl 0(%esi),%eax

# qhasm:   in1 ^= *(uint32 *) (m + 4)
# asm 1: xorl 4(<m=int32#5),<in1=int32#2
# asm 2: xorl 4(<m=%esi),<in1=%ecx
xorl 4(%esi),%ecx

# qhasm:   in2 ^= *(uint32 *) (m + 8)
# asm 1: xorl 8(<m=int32#5),<in2=int32#3
# asm 2: xorl 8(<m=%esi),<in2=%edx
xorl 8(%esi),%edx

# qhasm:   in3 ^= *(uint32 *) (m + 12)
# asm 1: xorl 12(<m=int32#5),<in3=int32#4
# asm 2: xorl 12(<m=%esi),<in3=%ebx
xorl 12(%esi),%ebx

# qhasm:   *(uint32 *) (out + 0) = in0
# asm 1: movl <in0=int32#1,0(<out=int32#6)
# asm 2: movl <in0=%eax,0(<out=%edi)
movl %eax,0(%edi)

# qhasm:   *(uint32 *) (out + 4) = in1
# asm 1: movl <in1=int32#2,4(<out=int32#6)
# asm 2: movl <in1=%ecx,4(<out=%edi)
movl %ecx,4(%edi)

# qhasm:   *(uint32 *) (out + 8) = in2
# asm 1: movl <in2=int32#3,8(<out=int32#6)
# asm 2: movl <in2=%edx,8(<out=%edi)
movl %edx,8(%edi)

# qhasm:   *(uint32 *) (out + 12) = in3
# asm 1: movl <in3=int32#4,12(<out=int32#6)
# asm 2: movl <in3=%ebx,12(<out=%edi)
movl %ebx,12(%edi)

# qhasm:   in0 = z0
# asm 1: movd   <z0=int6464#1,>in0=int32#1
# asm 2: movd   <z0=%xmm0,>in0=%eax
movd   %xmm0,%eax

# qhasm:   in1 = z1
# asm 1: movd   <z1=int6464#2,>in1=int32#2
# asm 2: movd   <z1=%xmm1,>in1=%ecx
movd   %xmm1,%ecx

# qhasm:   in2 = z2
# asm 1: movd   <z2=int6464#3,>in2=int32#3
# asm 2: movd   <z2=%xmm2,>in2=%edx
movd   %xmm2,%edx

# qhasm:   in3 = z3
# asm 1: movd   <z3=int6464#4,>in3=int32#4
# asm 2: movd   <z3=%xmm3,>in3=%ebx
movd   %xmm3,%ebx

# qhasm:   z0 <<<= 96
# asm 1: pshufd $0x39,<z0=int6464#1,<z0=int6464#1
# asm 2: pshufd $0x39,<z0=%xmm0,<z0=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm:   z1 <<<= 96
# asm 1: pshufd $0x39,<z1=int6464#2,<z1=int6464#2
# asm 2: pshufd $0x39,<z1=%xmm1,<z1=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm:   z2 <<<= 96
# asm 1: pshufd $0x39,<z2=int6464#3,<z2=int6464#3
# asm 2: pshufd $0x39,<z2=%xmm2,<z2=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm:   z3 <<<= 96
# asm 1: pshufd $0x39,<z3=int6464#4,<z3=int6464#4
# asm 2: pshufd $0x39,<z3=%xmm3,<z3=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm:   in0 ^= *(uint32 *) (m + 64)
# asm 1: xorl 64(<m=int32#5),<in0=int32#1
# asm 2: xorl 64(<m=%esi),<in0=%eax
xorl 64(%esi),%eax

# qhasm:   in1 ^= *(uint32 *) (m + 68)
# asm 1: xorl 68(<m=int32#5),<in1=int32#2
# asm 2: xorl 68(<m=%esi),<in1=%ecx
xorl 68(%esi),%ecx

# qhasm:   in2 ^= *(uint32 *) (m + 72)
# asm 1: xorl 72(<m=int32#5),<in2=int32#3
# asm 2: xorl 72(<m=%esi),<in2=%edx
xorl 72(%esi),%edx

# qhasm:   in3 ^= *(uint32 *) (m + 76)
# asm 1: xorl 76(<m=int32#5),<in3=int32#4
# asm 2: xorl 76(<m=%esi),<in3=%ebx
xorl 76(%esi),%ebx

# qhasm:   *(uint32 *) (out + 64) = in0
# asm 1: movl <in0=int32#1,64(<out=int32#6)
# asm 2: movl <in0=%eax,64(<out=%edi)
movl %eax,64(%edi)

# qhasm:   *(uint32 *) (out + 68) = in1
# asm 1: movl <in1=int32#2,68(<out=int32#6)
# asm 2: movl <in1=%ecx,68(<out=%edi)
movl %ecx,68(%edi)

# qhasm:   *(uint32 *) (out + 72) = in2
# asm 1: movl <in2=int32#3,72(<out=int32#6)
# asm 2: movl <in2=%edx,72(<out=%edi)
movl %edx,72(%edi)

# qhasm:   *(uint32 *) (out + 76) = in3
# asm 1: movl <in3=int32#4,76(<out=int32#6)
# asm 2: movl <in3=%ebx,76(<out=%edi)
movl %ebx,76(%edi)

# qhasm:   in0 = z0
# asm 1: movd   <z0=int6464#1,>in0=int32#1
# asm 2: movd   <z0=%xmm0,>in0=%eax
movd   %xmm0,%eax

# qhasm:   in1 = z1
# asm 1: movd   <z1=int6464#2,>in1=int32#2
# asm 2: movd   <z1=%xmm1,>in1=%ecx
movd   %xmm1,%ecx

# qhasm:   in2 = z2
# asm 1: movd   <z2=int6464#3,>in2=int32#3
# asm 2: movd   <z2=%xmm2,>in2=%edx
movd   %xmm2,%edx

# qhasm:   in3 = z3
# asm 1: movd   <z3=int6464#4,>in3=int32#4
# asm 2: movd   <z3=%xmm3,>in3=%ebx
movd   %xmm3,%ebx

# qhasm:   z0 <<<= 96
# asm 1: pshufd $0x39,<z0=int6464#1,<z0=int6464#1
# asm 2: pshufd $0x39,<z0=%xmm0,<z0=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm:   z1 <<<= 96
# asm 1: pshufd $0x39,<z1=int6464#2,<z1=int6464#2
# asm 2: pshufd $0x39,<z1=%xmm1,<z1=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm:   z2 <<<= 96
# asm 1: pshufd $0x39,<z2=int6464#3,<z2=int6464#3
# asm 2: pshufd $0x39,<z2=%xmm2,<z2=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm:   z3 <<<= 96
# asm 1: pshufd $0x39,<z3=int6464#4,<z3=int6464#4
# asm 2: pshufd $0x39,<z3=%xmm3,<z3=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm:   in0 ^= *(uint32 *) (m + 128)
# asm 1: xorl 128(<m=int32#5),<in0=int32#1
# asm 2: xorl 128(<m=%esi),<in0=%eax
xorl 128(%esi),%eax

# qhasm:   in1 ^= *(uint32 *) (m + 132)
# asm 1: xorl 132(<m=int32#5),<in1=int32#2
# asm 2: xorl 132(<m=%esi),<in1=%ecx
xorl 132(%esi),%ecx

# qhasm:   in2 ^= *(uint32 *) (m + 136)
# asm 1: xorl 136(<m=int32#5),<in2=int32#3
# asm 2: xorl 136(<m=%esi),<in2=%edx
xorl 136(%esi),%edx

# qhasm:   in3 ^= *(uint32 *) (m + 140)
# asm 1: xorl 140(<m=int32#5),<in3=int32#4
# asm 2: xorl 140(<m=%esi),<in3=%ebx
xorl 140(%esi),%ebx

# qhasm:   *(uint32 *) (out + 128) = in0
# asm 1: movl <in0=int32#1,128(<out=int32#6)
# asm 2: movl <in0=%eax,128(<out=%edi)
movl %eax,128(%edi)

# qhasm:   *(uint32 *) (out + 132) = in1
# asm 1: movl <in1=int32#2,132(<out=int32#6)
# asm 2: movl <in1=%ecx,132(<out=%edi)
movl %ecx,132(%edi)

# qhasm:   *(uint32 *) (out + 136) = in2
# asm 1: movl <in2=int32#3,136(<out=int32#6)
# asm 2: movl <in2=%edx,136(<out=%edi)
movl %edx,136(%edi)

# qhasm:   *(uint32 *) (out + 140) = in3
# asm 1: movl <in3=int32#4,140(<out=int32#6)
# asm 2: movl <in3=%ebx,140(<out=%edi)
movl %ebx,140(%edi)

# qhasm:   in0 = z0
# asm 1: movd   <z0=int6464#1,>in0=int32#1
# asm 2: movd   <z0=%xmm0,>in0=%eax
movd   %xmm0,%eax

# qhasm:   in1 = z1
# asm 1: movd   <z1=int6464#2,>in1=int32#2
# asm 2: movd   <z1=%xmm1,>in1=%ecx
movd   %xmm1,%ecx

# qhasm:   in2 = z2
# asm 1: movd   <z2=int6464#3,>in2=int32#3
# asm 2: movd   <z2=%xmm2,>in2=%edx
movd   %xmm2,%edx

# qhasm:   in3 = z3
# asm 1: movd   <z3=int6464#4,>in3=int32#4
# asm 2: movd   <z3=%xmm3,>in3=%ebx
movd   %xmm3,%ebx

# qhasm:   in0 ^= *(uint32 *) (m + 192)
# asm 1: xorl 192(<m=int32#5),<in0=int32#1
# asm 2: xorl 192(<m=%esi),<in0=%eax
xorl 192(%esi),%eax

# qhasm:   in1 ^= *(uint32 *) (m + 196)
# asm 1: xorl 196(<m=int32#5),<in1=int32#2
# asm 2: xorl 196(<m=%esi),<in1=%ecx
xorl 196(%esi),%ecx

# qhasm:   in2 ^= *(uint32 *) (m + 200)
# asm 1: xorl 200(<m=int32#5),<in2=int32#3
# asm 2: xorl 200(<m=%esi),<in2=%edx
xorl 200(%esi),%edx

# qhasm:   in3 ^= *(uint32 *) (m + 204)
# asm 1: xorl 204(<m=int32#5),<in3=int32#4
# asm 2: xorl 204(<m=%esi),<in3=%ebx
xorl 204(%esi),%ebx

# qhasm:   *(uint32 *) (out + 192) = in0
# asm 1: movl <in0=int32#1,192(<out=int32#6)
# asm 2: movl <in0=%eax,192(<out=%edi)
movl %eax,192(%edi)

# qhasm:   *(uint32 *) (out + 196) = in1
# asm 1: movl <in1=int32#2,196(<out=int32#6)
# asm 2: movl <in1=%ecx,196(<out=%edi)
movl %ecx,196(%edi)

# qhasm:   *(uint32 *) (out + 200) = in2
# asm 1: movl <in2=int32#3,200(<out=int32#6)
# asm 2: movl <in2=%edx,200(<out=%edi)
movl %edx,200(%edi)

# qhasm:   *(uint32 *) (out + 204) = in3
# asm 1: movl <in3=int32#4,204(<out=int32#6)
# asm 2: movl <in3=%ebx,204(<out=%edi)
movl %ebx,204(%edi)

# qhasm:   z4 = z4_stack
# asm 1: movdqa <z4_stack=stack128#34,>z4=int6464#1
# asm 2: movdqa <z4_stack=560(%esp),>z4=%xmm0
movdqa 560(%esp),%xmm0

# qhasm:   z5 = z5_stack
# asm 1: movdqa <z5_stack=stack128#21,>z5=int6464#2
# asm 2: movdqa <z5_stack=352(%esp),>z5=%xmm1
movdqa 352(%esp),%xmm1

# qhasm:   z6 = z6_stack
# asm 1: movdqa <z6_stack=stack128#26,>z6=int6464#3
# asm 2: movdqa <z6_stack=432(%esp),>z6=%xmm2
movdqa 432(%esp),%xmm2

# qhasm:   z7 = z7_stack
# asm 1: movdqa <z7_stack=stack128#29,>z7=int6464#4
# asm 2: movdqa <z7_stack=480(%esp),>z7=%xmm3
movdqa 480(%esp),%xmm3

# qhasm:   uint32323232 z4 += orig4
# asm 1: paddd <orig4=stack128#16,<z4=int6464#1
# asm 2: paddd <orig4=272(%esp),<z4=%xmm0
paddd 272(%esp),%xmm0

# qhasm:   uint32323232 z5 += orig5
# asm 1: paddd <orig5=stack128#5,<z5=int6464#2
# asm 2: paddd <orig5=96(%esp),<z5=%xmm1
paddd 96(%esp),%xmm1

# qhasm:   uint32323232 z6 += orig6
# asm 1: paddd <orig6=stack128#9,<z6=int6464#3
# asm 2: paddd <orig6=160(%esp),<z6=%xmm2
paddd 160(%esp),%xmm2

# qhasm:   uint32323232 z7 += orig7
# asm 1: paddd <orig7=stack128#13,<z7=int6464#4
# asm 2: paddd <orig7=224(%esp),<z7=%xmm3
paddd 224(%esp),%xmm3

# qhasm:   in4 = z4
# asm 1: movd   <z4=int6464#1,>in4=int32#1
# asm 2: movd   <z4=%xmm0,>in4=%eax
movd   %xmm0,%eax

# qhasm:   in5 = z5
# asm 1: movd   <z5=int6464#2,>in5=int32#2
# asm 2: movd   <z5=%xmm1,>in5=%ecx
movd   %xmm1,%ecx

# qhasm:   in6 = z6
# asm 1: movd   <z6=int6464#3,>in6=int32#3
# asm 2: movd   <z6=%xmm2,>in6=%edx
movd   %xmm2,%edx

# qhasm:   in7 = z7
# asm 1: movd   <z7=int6464#4,>in7=int32#4
# asm 2: movd   <z7=%xmm3,>in7=%ebx
movd   %xmm3,%ebx

# qhasm:   z4 <<<= 96
# asm 1: pshufd $0x39,<z4=int6464#1,<z4=int6464#1
# asm 2: pshufd $0x39,<z4=%xmm0,<z4=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm:   z5 <<<= 96
# asm 1: pshufd $0x39,<z5=int6464#2,<z5=int6464#2
# asm 2: pshufd $0x39,<z5=%xmm1,<z5=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm:   z6 <<<= 96
# asm 1: pshufd $0x39,<z6=int6464#3,<z6=int6464#3
# asm 2: pshufd $0x39,<z6=%xmm2,<z6=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm:   z7 <<<= 96
# asm 1: pshufd $0x39,<z7=int6464#4,<z7=int6464#4
# asm 2: pshufd $0x39,<z7=%xmm3,<z7=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm:   in4 ^= *(uint32 *) (m + 16)
# asm 1: xorl 16(<m=int32#5),<in4=int32#1
# asm 2: xorl 16(<m=%esi),<in4=%eax
xorl 16(%esi),%eax

# qhasm:   in5 ^= *(uint32 *) (m + 20)
# asm 1: xorl 20(<m=int32#5),<in5=int32#2
# asm 2: xorl 20(<m=%esi),<in5=%ecx
xorl 20(%esi),%ecx

# qhasm:   in6 ^= *(uint32 *) (m + 24)
# asm 1: xorl 24(<m=int32#5),<in6=int32#3
# asm 2: xorl 24(<m=%esi),<in6=%edx
xorl 24(%esi),%edx

# qhasm:   in7 ^= *(uint32 *) (m + 28)
# asm 1: xorl 28(<m=int32#5),<in7=int32#4
# asm 2: xorl 28(<m=%esi),<in7=%ebx
xorl 28(%esi),%ebx

# qhasm:   *(uint32 *) (out + 16) = in4
# asm 1: movl <in4=int32#1,16(<out=int32#6)
# asm 2: movl <in4=%eax,16(<out=%edi)
movl %eax,16(%edi)

# qhasm:   *(uint32 *) (out + 20) = in5
# asm 1: movl <in5=int32#2,20(<out=int32#6)
# asm 2: movl <in5=%ecx,20(<out=%edi)
movl %ecx,20(%edi)

# qhasm:   *(uint32 *) (out + 24) = in6
# asm 1: movl <in6=int32#3,24(<out=int32#6)
# asm 2: movl <in6=%edx,24(<out=%edi)
movl %edx,24(%edi)

# qhasm:   *(uint32 *) (out + 28) = in7
# asm 1: movl <in7=int32#4,28(<out=int32#6)
# asm 2: movl <in7=%ebx,28(<out=%edi)
movl %ebx,28(%edi)

# qhasm:   in4 = z4
# asm 1: movd   <z4=int6464#1,>in4=int32#1
# asm 2: movd   <z4=%xmm0,>in4=%eax
movd   %xmm0,%eax

# qhasm:   in5 = z5
# asm 1: movd   <z5=int6464#2,>in5=int32#2
# asm 2: movd   <z5=%xmm1,>in5=%ecx
movd   %xmm1,%ecx

# qhasm:   in6 = z6
# asm 1: movd   <z6=int6464#3,>in6=int32#3
# asm 2: movd   <z6=%xmm2,>in6=%edx
movd   %xmm2,%edx

# qhasm:   in7 = z7
# asm 1: movd   <z7=int6464#4,>in7=int32#4
# asm 2: movd   <z7=%xmm3,>in7=%ebx
movd   %xmm3,%ebx

# qhasm:   z4 <<<= 96
# asm 1: pshufd $0x39,<z4=int6464#1,<z4=int6464#1
# asm 2: pshufd $0x39,<z4=%xmm0,<z4=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm:   z5 <<<= 96
# asm 1: pshufd $0x39,<z5=int6464#2,<z5=int6464#2
# asm 2: pshufd $0x39,<z5=%xmm1,<z5=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm:   z6 <<<= 96
# asm 1: pshufd $0x39,<z6=int6464#3,<z6=int6464#3
# asm 2: pshufd $0x39,<z6=%xmm2,<z6=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm:   z7 <<<= 96
# asm 1: pshufd $0x39,<z7=int6464#4,<z7=int6464#4
# asm 2: pshufd $0x39,<z7=%xmm3,<z7=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm:   in4 ^= *(uint32 *) (m + 80)
# asm 1: xorl 80(<m=int32#5),<in4=int32#1
# asm 2: xorl 80(<m=%esi),<in4=%eax
xorl 80(%esi),%eax

# qhasm:   in5 ^= *(uint32 *) (m + 84)
# asm 1: xorl 84(<m=int32#5),<in5=int32#2
# asm 2: xorl 84(<m=%esi),<in5=%ecx
xorl 84(%esi),%ecx

# qhasm:   in6 ^= *(uint32 *) (m + 88)
# asm 1: xorl 88(<m=int32#5),<in6=int32#3
# asm 2: xorl 88(<m=%esi),<in6=%edx
xorl 88(%esi),%edx

# qhasm:   in7 ^= *(uint32 *) (m + 92)
# asm 1: xorl 92(<m=int32#5),<in7=int32#4
# asm 2: xorl 92(<m=%esi),<in7=%ebx
xorl 92(%esi),%ebx

# qhasm:   *(uint32 *) (out + 80) = in4
# asm 1: movl <in4=int32#1,80(<out=int32#6)
# asm 2: movl <in4=%eax,80(<out=%edi)
movl %eax,80(%edi)

# qhasm:   *(uint32 *) (out + 84) = in5
# asm 1: movl <in5=int32#2,84(<out=int32#6)
# asm 2: movl <in5=%ecx,84(<out=%edi)
movl %ecx,84(%edi)

# qhasm:   *(uint32 *) (out + 88) = in6
# asm 1: movl <in6=int32#3,88(<out=int32#6)
# asm 2: movl <in6=%edx,88(<out=%edi)
movl %edx,88(%edi)

# qhasm:   *(uint32 *) (out + 92) = in7
# asm 1: movl <in7=int32#4,92(<out=int32#6)
# asm 2: movl <in7=%ebx,92(<out=%edi)
movl %ebx,92(%edi)

# qhasm:   in4 = z4
# asm 1: movd   <z4=int6464#1,>in4=int32#1
# asm 2: movd   <z4=%xmm0,>in4=%eax
movd   %xmm0,%eax

# qhasm:   in5 = z5
# asm 1: movd   <z5=int6464#2,>in5=int32#2
# asm 2: movd   <z5=%xmm1,>in5=%ecx
movd   %xmm1,%ecx

# qhasm:   in6 = z6
# asm 1: movd   <z6=int6464#3,>in6=int32#3
# asm 2: movd   <z6=%xmm2,>in6=%edx
movd   %xmm2,%edx

# qhasm:   in7 = z7
# asm 1: movd   <z7=int6464#4,>in7=int32#4
# asm 2: movd   <z7=%xmm3,>in7=%ebx
movd   %xmm3,%ebx

# qhasm:   z4 <<<= 96
# asm 1: pshufd $0x39,<z4=int6464#1,<z4=int6464#1
# asm 2: pshufd $0x39,<z4=%xmm0,<z4=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm:   z5 <<<= 96
# asm 1: pshufd $0x39,<z5=int6464#2,<z5=int6464#2
# asm 2: pshufd $0x39,<z5=%xmm1,<z5=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm:   z6 <<<= 96
# asm 1: pshufd $0x39,<z6=int6464#3,<z6=int6464#3
# asm 2: pshufd $0x39,<z6=%xmm2,<z6=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm:   z7 <<<= 96
# asm 1: pshufd $0x39,<z7=int6464#4,<z7=int6464#4
# asm 2: pshufd $0x39,<z7=%xmm3,<z7=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm:   in4 ^= *(uint32 *) (m + 144)
# asm 1: xorl 144(<m=int32#5),<in4=int32#1
# asm 2: xorl 144(<m=%esi),<in4=%eax
xorl 144(%esi),%eax

# qhasm:   in5 ^= *(uint32 *) (m + 148)
# asm 1: xorl 148(<m=int32#5),<in5=int32#2
# asm 2: xorl 148(<m=%esi),<in5=%ecx
xorl 148(%esi),%ecx

# qhasm:   in6 ^= *(uint32 *) (m + 152)
# asm 1: xorl 152(<m=int32#5),<in6=int32#3
# asm 2: xorl 152(<m=%esi),<in6=%edx
xorl 152(%esi),%edx

# qhasm:   in7 ^= *(uint32 *) (m + 156)
# asm 1: xorl 156(<m=int32#5),<in7=int32#4
# asm 2: xorl 156(<m=%esi),<in7=%ebx
xorl 156(%esi),%ebx

# qhasm:   *(uint32 *) (out + 144) = in4
# asm 1: movl <in4=int32#1,144(<out=int32#6)
# asm 2: movl <in4=%eax,144(<out=%edi)
movl %eax,144(%edi)

# qhasm:   *(uint32 *) (out + 148) = in5
# asm 1: movl <in5=int32#2,148(<out=int32#6)
# asm 2: movl <in5=%ecx,148(<out=%edi)
movl %ecx,148(%edi)

# qhasm:   *(uint32 *) (out + 152) = in6
# asm 1: movl <in6=int32#3,152(<out=int32#6)
# asm 2: movl <in6=%edx,152(<out=%edi)
movl %edx,152(%edi)

# qhasm:   *(uint32 *) (out + 156) = in7
# asm 1: movl <in7=int32#4,156(<out=int32#6)
# asm 2: movl <in7=%ebx,156(<out=%edi)
movl %ebx,156(%edi)

# qhasm:   in4 = z4
# asm 1: movd   <z4=int6464#1,>in4=int32#1
# asm 2: movd   <z4=%xmm0,>in4=%eax
movd   %xmm0,%eax

# qhasm:   in5 = z5
# asm 1: movd   <z5=int6464#2,>in5=int32#2
# asm 2: movd   <z5=%xmm1,>in5=%ecx
movd   %xmm1,%ecx

# qhasm:   in6 = z6
# asm 1: movd   <z6=int6464#3,>in6=int32#3
# asm 2: movd   <z6=%xmm2,>in6=%edx
movd   %xmm2,%edx

# qhasm:   in7 = z7
# asm 1: movd   <z7=int6464#4,>in7=int32#4
# asm 2: movd   <z7=%xmm3,>in7=%ebx
movd   %xmm3,%ebx

# qhasm:   in4 ^= *(uint32 *) (m + 208)
# asm 1: xorl 208(<m=int32#5),<in4=int32#1
# asm 2: xorl 208(<m=%esi),<in4=%eax
xorl 208(%esi),%eax

# qhasm:   in5 ^= *(uint32 *) (m + 212)
# asm 1: xorl 212(<m=int32#5),<in5=int32#2
# asm 2: xorl 212(<m=%esi),<in5=%ecx
xorl 212(%esi),%ecx

# qhasm:   in6 ^= *(uint32 *) (m + 216)
# asm 1: xorl 216(<m=int32#5),<in6=int32#3
# asm 2: xorl 216(<m=%esi),<in6=%edx
xorl 216(%esi),%edx

# qhasm:   in7 ^= *(uint32 *) (m + 220)
# asm 1: xorl 220(<m=int32#5),<in7=int32#4
# asm 2: xorl 220(<m=%esi),<in7=%ebx
xorl 220(%esi),%ebx

# qhasm:   *(uint32 *) (out + 208) = in4
# asm 1: movl <in4=int32#1,208(<out=int32#6)
# asm 2: movl <in4=%eax,208(<out=%edi)
movl %eax,208(%edi)

# qhasm:   *(uint32 *) (out + 212) = in5
# asm 1: movl <in5=int32#2,212(<out=int32#6)
# asm 2: movl <in5=%ecx,212(<out=%edi)
movl %ecx,212(%edi)

# qhasm:   *(uint32 *) (out + 216) = in6
# asm 1: movl <in6=int32#3,216(<out=int32#6)
# asm 2: movl <in6=%edx,216(<out=%edi)
movl %edx,216(%edi)

# qhasm:   *(uint32 *) (out + 220) = in7
# asm 1: movl <in7=int32#4,220(<out=int32#6)
# asm 2: movl <in7=%ebx,220(<out=%edi)
movl %ebx,220(%edi)

# qhasm:   z8 = z8_stack
# asm 1: movdqa <z8_stack=stack128#37,>z8=int6464#1
# asm 2: movdqa <z8_stack=608(%esp),>z8=%xmm0
movdqa 608(%esp),%xmm0

# qhasm:   z9 = z9_stack
# asm 1: movdqa <z9_stack=stack128#32,>z9=int6464#2
# asm 2: movdqa <z9_stack=528(%esp),>z9=%xmm1
movdqa 528(%esp),%xmm1

# qhasm:   z10 = z10_stack
# asm 1: movdqa <z10_stack=stack128#22,>z10=int6464#3
# asm 2: movdqa <z10_stack=368(%esp),>z10=%xmm2
movdqa 368(%esp),%xmm2

# qhasm:   z11 = z11_stack
# asm 1: movdqa <z11_stack=stack128#27,>z11=int6464#4
# asm 2: movdqa <z11_stack=448(%esp),>z11=%xmm3
movdqa 448(%esp),%xmm3

# qhasm:   uint32323232 z8 += orig8
# asm 1: paddd <orig8=stack128#19,<z8=int6464#1
# asm 2: paddd <orig8=320(%esp),<z8=%xmm0
paddd 320(%esp),%xmm0

# qhasm:   uint32323232 z9 += orig9
# asm 1: paddd <orig9=stack128#20,<z9=int6464#2
# asm 2: paddd <orig9=336(%esp),<z9=%xmm1
paddd 336(%esp),%xmm1

# qhasm:   uint32323232 z10 += orig10
# asm 1: paddd <orig10=stack128#6,<z10=int6464#3
# asm 2: paddd <orig10=112(%esp),<z10=%xmm2
paddd 112(%esp),%xmm2

# qhasm:   uint32323232 z11 += orig11
# asm 1: paddd <orig11=stack128#10,<z11=int6464#4
# asm 2: paddd <orig11=176(%esp),<z11=%xmm3
paddd 176(%esp),%xmm3

# qhasm:   in8 = z8
# asm 1: movd   <z8=int6464#1,>in8=int32#1
# asm 2: movd   <z8=%xmm0,>in8=%eax
movd   %xmm0,%eax

# qhasm:   in9 = z9
# asm 1: movd   <z9=int6464#2,>in9=int32#2
# asm 2: movd   <z9=%xmm1,>in9=%ecx
movd   %xmm1,%ecx

# qhasm:   in10 = z10
# asm 1: movd   <z10=int6464#3,>in10=int32#3
# asm 2: movd   <z10=%xmm2,>in10=%edx
movd   %xmm2,%edx

# qhasm:   in11 = z11
# asm 1: movd   <z11=int6464#4,>in11=int32#4
# asm 2: movd   <z11=%xmm3,>in11=%ebx
movd   %xmm3,%ebx

# qhasm:   z8 <<<= 96
# asm 1: pshufd $0x39,<z8=int6464#1,<z8=int6464#1
# asm 2: pshufd $0x39,<z8=%xmm0,<z8=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm:   z9 <<<= 96
# asm 1: pshufd $0x39,<z9=int6464#2,<z9=int6464#2
# asm 2: pshufd $0x39,<z9=%xmm1,<z9=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm:   z10 <<<= 96
# asm 1: pshufd $0x39,<z10=int6464#3,<z10=int6464#3
# asm 2: pshufd $0x39,<z10=%xmm2,<z10=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm:   z11 <<<= 96
# asm 1: pshufd $0x39,<z11=int6464#4,<z11=int6464#4
# asm 2: pshufd $0x39,<z11=%xmm3,<z11=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm:   in8 ^= *(uint32 *) (m + 32)
# asm 1: xorl 32(<m=int32#5),<in8=int32#1
# asm 2: xorl 32(<m=%esi),<in8=%eax
xorl 32(%esi),%eax

# qhasm:   in9 ^= *(uint32 *) (m + 36)
# asm 1: xorl 36(<m=int32#5),<in9=int32#2
# asm 2: xorl 36(<m=%esi),<in9=%ecx
xorl 36(%esi),%ecx

# qhasm:   in10 ^= *(uint32 *) (m + 40)
# asm 1: xorl 40(<m=int32#5),<in10=int32#3
# asm 2: xorl 40(<m=%esi),<in10=%edx
xorl 40(%esi),%edx

# qhasm:   in11 ^= *(uint32 *) (m + 44)
# asm 1: xorl 44(<m=int32#5),<in11=int32#4
# asm 2: xorl 44(<m=%esi),<in11=%ebx
xorl 44(%esi),%ebx

# qhasm:   *(uint32 *) (out + 32) = in8
# asm 1: movl <in8=int32#1,32(<out=int32#6)
# asm 2: movl <in8=%eax,32(<out=%edi)
movl %eax,32(%edi)

# qhasm:   *(uint32 *) (out + 36) = in9
# asm 1: movl <in9=int32#2,36(<out=int32#6)
# asm 2: movl <in9=%ecx,36(<out=%edi)
movl %ecx,36(%edi)

# qhasm:   *(uint32 *) (out + 40) = in10
# asm 1: movl <in10=int32#3,40(<out=int32#6)
# asm 2: movl <in10=%edx,40(<out=%edi)
movl %edx,40(%edi)

# qhasm:   *(uint32 *) (out + 44) = in11
# asm 1: movl <in11=int32#4,44(<out=int32#6)
# asm 2: movl <in11=%ebx,44(<out=%edi)
movl %ebx,44(%edi)

# qhasm:   in8 = z8
# asm 1: movd   <z8=int6464#1,>in8=int32#1
# asm 2: movd   <z8=%xmm0,>in8=%eax
movd   %xmm0,%eax

# qhasm:   in9 = z9
# asm 1: movd   <z9=int6464#2,>in9=int32#2
# asm 2: movd   <z9=%xmm1,>in9=%ecx
movd   %xmm1,%ecx

# qhasm:   in10 = z10
# asm 1: movd   <z10=int6464#3,>in10=int32#3
# asm 2: movd   <z10=%xmm2,>in10=%edx
movd   %xmm2,%edx

# qhasm:   in11 = z11
# asm 1: movd   <z11=int6464#4,>in11=int32#4
# asm 2: movd   <z11=%xmm3,>in11=%ebx
movd   %xmm3,%ebx

# qhasm:   z8 <<<= 96
# asm 1: pshufd $0x39,<z8=int6464#1,<z8=int6464#1
# asm 2: pshufd $0x39,<z8=%xmm0,<z8=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm:   z9 <<<= 96
# asm 1: pshufd $0x39,<z9=int6464#2,<z9=int6464#2
# asm 2: pshufd $0x39,<z9=%xmm1,<z9=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm:   z10 <<<= 96
# asm 1: pshufd $0x39,<z10=int6464#3,<z10=int6464#3
# asm 2: pshufd $0x39,<z10=%xmm2,<z10=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm:   z11 <<<= 96
# asm 1: pshufd $0x39,<z11=int6464#4,<z11=int6464#4
# asm 2: pshufd $0x39,<z11=%xmm3,<z11=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm:   in8 ^= *(uint32 *) (m + 96)
# asm 1: xorl 96(<m=int32#5),<in8=int32#1
# asm 2: xorl 96(<m=%esi),<in8=%eax
xorl 96(%esi),%eax

# qhasm:   in9 ^= *(uint32 *) (m + 100)
# asm 1: xorl 100(<m=int32#5),<in9=int32#2
# asm 2: xorl 100(<m=%esi),<in9=%ecx
xorl 100(%esi),%ecx

# qhasm:   in10 ^= *(uint32 *) (m + 104)
# asm 1: xorl 104(<m=int32#5),<in10=int32#3
# asm 2: xorl 104(<m=%esi),<in10=%edx
xorl 104(%esi),%edx

# qhasm:   in11 ^= *(uint32 *) (m + 108)
# asm 1: xorl 108(<m=int32#5),<in11=int32#4
# asm 2: xorl 108(<m=%esi),<in11=%ebx
xorl 108(%esi),%ebx

# qhasm:   *(uint32 *) (out + 96) = in8
# asm 1: movl <in8=int32#1,96(<out=int32#6)
# asm 2: movl <in8=%eax,96(<out=%edi)
movl %eax,96(%edi)

# qhasm:   *(uint32 *) (out + 100) = in9
# asm 1: movl <in9=int32#2,100(<out=int32#6)
# asm 2: movl <in9=%ecx,100(<out=%edi)
movl %ecx,100(%edi)

# qhasm:   *(uint32 *) (out + 104) = in10
# asm 1: movl <in10=int32#3,104(<out=int32#6)
# asm 2: movl <in10=%edx,104(<out=%edi)
movl %edx,104(%edi)

# qhasm:   *(uint32 *) (out + 108) = in11
# asm 1: movl <in11=int32#4,108(<out=int32#6)
# asm 2: movl <in11=%ebx,108(<out=%edi)
movl %ebx,108(%edi)

# qhasm:   in8 = z8
# asm 1: movd   <z8=int6464#1,>in8=int32#1
# asm 2: movd   <z8=%xmm0,>in8=%eax
movd   %xmm0,%eax

# qhasm:   in9 = z9
# asm 1: movd   <z9=int6464#2,>in9=int32#2
# asm 2: movd   <z9=%xmm1,>in9=%ecx
movd   %xmm1,%ecx

# qhasm:   in10 = z10
# asm 1: movd   <z10=int6464#3,>in10=int32#3
# asm 2: movd   <z10=%xmm2,>in10=%edx
movd   %xmm2,%edx

# qhasm:   in11 = z11
# asm 1: movd   <z11=int6464#4,>in11=int32#4
# asm 2: movd   <z11=%xmm3,>in11=%ebx
movd   %xmm3,%ebx

# qhasm:   z8 <<<= 96
# asm 1: pshufd $0x39,<z8=int6464#1,<z8=int6464#1
# asm 2: pshufd $0x39,<z8=%xmm0,<z8=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm:   z9 <<<= 96
# asm 1: pshufd $0x39,<z9=int6464#2,<z9=int6464#2
# asm 2: pshufd $0x39,<z9=%xmm1,<z9=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm:   z10 <<<= 96
# asm 1: pshufd $0x39,<z10=int6464#3,<z10=int6464#3
# asm 2: pshufd $0x39,<z10=%xmm2,<z10=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm:   z11 <<<= 96
# asm 1: pshufd $0x39,<z11=int6464#4,<z11=int6464#4
# asm 2: pshufd $0x39,<z11=%xmm3,<z11=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm:   in8 ^= *(uint32 *) (m + 160)
# asm 1: xorl 160(<m=int32#5),<in8=int32#1
# asm 2: xorl 160(<m=%esi),<in8=%eax
xorl 160(%esi),%eax

# qhasm:   in9 ^= *(uint32 *) (m + 164)
# asm 1: xorl 164(<m=int32#5),<in9=int32#2
# asm 2: xorl 164(<m=%esi),<in9=%ecx
xorl 164(%esi),%ecx

# qhasm:   in10 ^= *(uint32 *) (m + 168)
# asm 1: xorl 168(<m=int32#5),<in10=int32#3
# asm 2: xorl 168(<m=%esi),<in10=%edx
xorl 168(%esi),%edx

# qhasm:   in11 ^= *(uint32 *) (m + 172)
# asm 1: xorl 172(<m=int32#5),<in11=int32#4
# asm 2: xorl 172(<m=%esi),<in11=%ebx
xorl 172(%esi),%ebx

# qhasm:   *(uint32 *) (out + 160) = in8
# asm 1: movl <in8=int32#1,160(<out=int32#6)
# asm 2: movl <in8=%eax,160(<out=%edi)
movl %eax,160(%edi)

# qhasm:   *(uint32 *) (out + 164) = in9
# asm 1: movl <in9=int32#2,164(<out=int32#6)
# asm 2: movl <in9=%ecx,164(<out=%edi)
movl %ecx,164(%edi)

# qhasm:   *(uint32 *) (out + 168) = in10
# asm 1: movl <in10=int32#3,168(<out=int32#6)
# asm 2: movl <in10=%edx,168(<out=%edi)
movl %edx,168(%edi)

# qhasm:   *(uint32 *) (out + 172) = in11
# asm 1: movl <in11=int32#4,172(<out=int32#6)
# asm 2: movl <in11=%ebx,172(<out=%edi)
movl %ebx,172(%edi)

# qhasm:   in8 = z8
# asm 1: movd   <z8=int6464#1,>in8=int32#1
# asm 2: movd   <z8=%xmm0,>in8=%eax
movd   %xmm0,%eax

# qhasm:   in9 = z9
# asm 1: movd   <z9=int6464#2,>in9=int32#2
# asm 2: movd   <z9=%xmm1,>in9=%ecx
movd   %xmm1,%ecx

# qhasm:   in10 = z10
# asm 1: movd   <z10=int6464#3,>in10=int32#3
# asm 2: movd   <z10=%xmm2,>in10=%edx
movd   %xmm2,%edx

# qhasm:   in11 = z11
# asm 1: movd   <z11=int6464#4,>in11=int32#4
# asm 2: movd   <z11=%xmm3,>in11=%ebx
movd   %xmm3,%ebx

# qhasm:   in8 ^= *(uint32 *) (m + 224)
# asm 1: xorl 224(<m=int32#5),<in8=int32#1
# asm 2: xorl 224(<m=%esi),<in8=%eax
xorl 224(%esi),%eax

# qhasm:   in9 ^= *(uint32 *) (m + 228)
# asm 1: xorl 228(<m=int32#5),<in9=int32#2
# asm 2: xorl 228(<m=%esi),<in9=%ecx
xorl 228(%esi),%ecx

# qhasm:   in10 ^= *(uint32 *) (m + 232)
# asm 1: xorl 232(<m=int32#5),<in10=int32#3
# asm 2: xorl 232(<m=%esi),<in10=%edx
xorl 232(%esi),%edx

# qhasm:   in11 ^= *(uint32 *) (m + 236)
# asm 1: xorl 236(<m=int32#5),<in11=int32#4
# asm 2: xorl 236(<m=%esi),<in11=%ebx
xorl 236(%esi),%ebx

# qhasm:   *(uint32 *) (out + 224) = in8
# asm 1: movl <in8=int32#1,224(<out=int32#6)
# asm 2: movl <in8=%eax,224(<out=%edi)
movl %eax,224(%edi)

# qhasm:   *(uint32 *) (out + 228) = in9
# asm 1: movl <in9=int32#2,228(<out=int32#6)
# asm 2: movl <in9=%ecx,228(<out=%edi)
movl %ecx,228(%edi)

# qhasm:   *(uint32 *) (out + 232) = in10
# asm 1: movl <in10=int32#3,232(<out=int32#6)
# asm 2: movl <in10=%edx,232(<out=%edi)
movl %edx,232(%edi)

# qhasm:   *(uint32 *) (out + 236) = in11
# asm 1: movl <in11=int32#4,236(<out=int32#6)
# asm 2: movl <in11=%ebx,236(<out=%edi)
movl %ebx,236(%edi)

# qhasm:   z12 = z12_stack
# asm 1: movdqa <z12_stack=stack128#35,>z12=int6464#1
# asm 2: movdqa <z12_stack=576(%esp),>z12=%xmm0
movdqa 576(%esp),%xmm0

# qhasm:   z13 = z13_stack
# asm 1: movdqa <z13_stack=stack128#30,>z13=int6464#2
# asm 2: movdqa <z13_stack=496(%esp),>z13=%xmm1
movdqa 496(%esp),%xmm1

# qhasm:   z14 = z14_stack
# asm 1: movdqa <z14_stack=stack128#24,>z14=int6464#3
# asm 2: movdqa <z14_stack=400(%esp),>z14=%xmm2
movdqa 400(%esp),%xmm2

# qhasm:   z15 = z15_stack
# asm 1: movdqa <z15_stack=stack128#23,>z15=int6464#4
# asm 2: movdqa <z15_stack=384(%esp),>z15=%xmm3
movdqa 384(%esp),%xmm3

# qhasm:   uint32323232 z12 += orig12
# asm 1: paddd <orig12=stack128#11,<z12=int6464#1
# asm 2: paddd <orig12=192(%esp),<z12=%xmm0
paddd 192(%esp),%xmm0

# qhasm:   uint32323232 z13 += orig13
# asm 1: paddd <orig13=stack128#14,<z13=int6464#2
# asm 2: paddd <orig13=240(%esp),<z13=%xmm1
paddd 240(%esp),%xmm1

# qhasm:   uint32323232 z14 += orig14
# asm 1: paddd <orig14=stack128#17,<z14=int6464#3
# asm 2: paddd <orig14=288(%esp),<z14=%xmm2
paddd 288(%esp),%xmm2

# qhasm:   uint32323232 z15 += orig15
# asm 1: paddd <orig15=stack128#7,<z15=int6464#4
# asm 2: paddd <orig15=128(%esp),<z15=%xmm3
paddd 128(%esp),%xmm3

# qhasm:   in12 = z12
# asm 1: movd   <z12=int6464#1,>in12=int32#1
# asm 2: movd   <z12=%xmm0,>in12=%eax
movd   %xmm0,%eax

# qhasm:   in13 = z13
# asm 1: movd   <z13=int6464#2,>in13=int32#2
# asm 2: movd   <z13=%xmm1,>in13=%ecx
movd   %xmm1,%ecx

# qhasm:   in14 = z14
# asm 1: movd   <z14=int6464#3,>in14=int32#3
# asm 2: movd   <z14=%xmm2,>in14=%edx
movd   %xmm2,%edx

# qhasm:   in15 = z15
# asm 1: movd   <z15=int6464#4,>in15=int32#4
# asm 2: movd   <z15=%xmm3,>in15=%ebx
movd   %xmm3,%ebx

# qhasm:   z12 <<<= 96
# asm 1: pshufd $0x39,<z12=int6464#1,<z12=int6464#1
# asm 2: pshufd $0x39,<z12=%xmm0,<z12=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm:   z13 <<<= 96
# asm 1: pshufd $0x39,<z13=int6464#2,<z13=int6464#2
# asm 2: pshufd $0x39,<z13=%xmm1,<z13=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm:   z14 <<<= 96
# asm 1: pshufd $0x39,<z14=int6464#3,<z14=int6464#3
# asm 2: pshufd $0x39,<z14=%xmm2,<z14=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm:   z15 <<<= 96
# asm 1: pshufd $0x39,<z15=int6464#4,<z15=int6464#4
# asm 2: pshufd $0x39,<z15=%xmm3,<z15=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm:   in12 ^= *(uint32 *) (m + 48)
# asm 1: xorl 48(<m=int32#5),<in12=int32#1
# asm 2: xorl 48(<m=%esi),<in12=%eax
xorl 48(%esi),%eax

# qhasm:   in13 ^= *(uint32 *) (m + 52)
# asm 1: xorl 52(<m=int32#5),<in13=int32#2
# asm 2: xorl 52(<m=%esi),<in13=%ecx
xorl 52(%esi),%ecx

# qhasm:   in14 ^= *(uint32 *) (m + 56)
# asm 1: xorl 56(<m=int32#5),<in14=int32#3
# asm 2: xorl 56(<m=%esi),<in14=%edx
xorl 56(%esi),%edx

# qhasm:   in15 ^= *(uint32 *) (m + 60)
# asm 1: xorl 60(<m=int32#5),<in15=int32#4
# asm 2: xorl 60(<m=%esi),<in15=%ebx
xorl 60(%esi),%ebx

# qhasm:   *(uint32 *) (out + 48) = in12
# asm 1: movl <in12=int32#1,48(<out=int32#6)
# asm 2: movl <in12=%eax,48(<out=%edi)
movl %eax,48(%edi)

# qhasm:   *(uint32 *) (out + 52) = in13
# asm 1: movl <in13=int32#2,52(<out=int32#6)
# asm 2: movl <in13=%ecx,52(<out=%edi)
movl %ecx,52(%edi)

# qhasm:   *(uint32 *) (out + 56) = in14
# asm 1: movl <in14=int32#3,56(<out=int32#6)
# asm 2: movl <in14=%edx,56(<out=%edi)
movl %edx,56(%edi)

# qhasm:   *(uint32 *) (out + 60) = in15
# asm 1: movl <in15=int32#4,60(<out=int32#6)
# asm 2: movl <in15=%ebx,60(<out=%edi)
movl %ebx,60(%edi)

# qhasm:   in12 = z12
# asm 1: movd   <z12=int6464#1,>in12=int32#1
# asm 2: movd   <z12=%xmm0,>in12=%eax
movd   %xmm0,%eax

# qhasm:   in13 = z13
# asm 1: movd   <z13=int6464#2,>in13=int32#2
# asm 2: movd   <z13=%xmm1,>in13=%ecx
movd   %xmm1,%ecx

# qhasm:   in14 = z14
# asm 1: movd   <z14=int6464#3,>in14=int32#3
# asm 2: movd   <z14=%xmm2,>in14=%edx
movd   %xmm2,%edx

# qhasm:   in15 = z15
# asm 1: movd   <z15=int6464#4,>in15=int32#4
# asm 2: movd   <z15=%xmm3,>in15=%ebx
movd   %xmm3,%ebx

# qhasm:   z12 <<<= 96
# asm 1: pshufd $0x39,<z12=int6464#1,<z12=int6464#1
# asm 2: pshufd $0x39,<z12=%xmm0,<z12=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm:   z13 <<<= 96
# asm 1: pshufd $0x39,<z13=int6464#2,<z13=int6464#2
# asm 2: pshufd $0x39,<z13=%xmm1,<z13=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm:   z14 <<<= 96
# asm 1: pshufd $0x39,<z14=int6464#3,<z14=int6464#3
# asm 2: pshufd $0x39,<z14=%xmm2,<z14=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm:   z15 <<<= 96
# asm 1: pshufd $0x39,<z15=int6464#4,<z15=int6464#4
# asm 2: pshufd $0x39,<z15=%xmm3,<z15=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm:   in12 ^= *(uint32 *) (m + 112)
# asm 1: xorl 112(<m=int32#5),<in12=int32#1
# asm 2: xorl 112(<m=%esi),<in12=%eax
xorl 112(%esi),%eax

# qhasm:   in13 ^= *(uint32 *) (m + 116)
# asm 1: xorl 116(<m=int32#5),<in13=int32#2
# asm 2: xorl 116(<m=%esi),<in13=%ecx
xorl 116(%esi),%ecx

# qhasm:   in14 ^= *(uint32 *) (m + 120)
# asm 1: xorl 120(<m=int32#5),<in14=int32#3
# asm 2: xorl 120(<m=%esi),<in14=%edx
xorl 120(%esi),%edx

# qhasm:   in15 ^= *(uint32 *) (m + 124)
# asm 1: xorl 124(<m=int32#5),<in15=int32#4
# asm 2: xorl 124(<m=%esi),<in15=%ebx
xorl 124(%esi),%ebx

# qhasm:   *(uint32 *) (out + 112) = in12
# asm 1: movl <in12=int32#1,112(<out=int32#6)
# asm 2: movl <in12=%eax,112(<out=%edi)
movl %eax,112(%edi)

# qhasm:   *(uint32 *) (out + 116) = in13
# asm 1: movl <in13=int32#2,116(<out=int32#6)
# asm 2: movl <in13=%ecx,116(<out=%edi)
movl %ecx,116(%edi)

# qhasm:   *(uint32 *) (out + 120) = in14
# asm 1: movl <in14=int32#3,120(<out=int32#6)
# asm 2: movl <in14=%edx,120(<out=%edi)
movl %edx,120(%edi)

# qhasm:   *(uint32 *) (out + 124) = in15
# asm 1: movl <in15=int32#4,124(<out=int32#6)
# asm 2: movl <in15=%ebx,124(<out=%edi)
movl %ebx,124(%edi)

# qhasm:   in12 = z12
# asm 1: movd   <z12=int6464#1,>in12=int32#1
# asm 2: movd   <z12=%xmm0,>in12=%eax
movd   %xmm0,%eax

# qhasm:   in13 = z13
# asm 1: movd   <z13=int6464#2,>in13=int32#2
# asm 2: movd   <z13=%xmm1,>in13=%ecx
movd   %xmm1,%ecx

# qhasm:   in14 = z14
# asm 1: movd   <z14=int6464#3,>in14=int32#3
# asm 2: movd   <z14=%xmm2,>in14=%edx
movd   %xmm2,%edx

# qhasm:   in15 = z15
# asm 1: movd   <z15=int6464#4,>in15=int32#4
# asm 2: movd   <z15=%xmm3,>in15=%ebx
movd   %xmm3,%ebx

# qhasm:   z12 <<<= 96
# asm 1: pshufd $0x39,<z12=int6464#1,<z12=int6464#1
# asm 2: pshufd $0x39,<z12=%xmm0,<z12=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm:   z13 <<<= 96
# asm 1: pshufd $0x39,<z13=int6464#2,<z13=int6464#2
# asm 2: pshufd $0x39,<z13=%xmm1,<z13=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm:   z14 <<<= 96
# asm 1: pshufd $0x39,<z14=int6464#3,<z14=int6464#3
# asm 2: pshufd $0x39,<z14=%xmm2,<z14=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm:   z15 <<<= 96
# asm 1: pshufd $0x39,<z15=int6464#4,<z15=int6464#4
# asm 2: pshufd $0x39,<z15=%xmm3,<z15=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm:   in12 ^= *(uint32 *) (m + 176)
# asm 1: xorl 176(<m=int32#5),<in12=int32#1
# asm 2: xorl 176(<m=%esi),<in12=%eax
xorl 176(%esi),%eax

# qhasm:   in13 ^= *(uint32 *) (m + 180)
# asm 1: xorl 180(<m=int32#5),<in13=int32#2
# asm 2: xorl 180(<m=%esi),<in13=%ecx
xorl 180(%esi),%ecx

# qhasm:   in14 ^= *(uint32 *) (m + 184)
# asm 1: xorl 184(<m=int32#5),<in14=int32#3
# asm 2: xorl 184(<m=%esi),<in14=%edx
xorl 184(%esi),%edx

# qhasm:   in15 ^= *(uint32 *) (m + 188)
# asm 1: xorl 188(<m=int32#5),<in15=int32#4
# asm 2: xorl 188(<m=%esi),<in15=%ebx
xorl 188(%esi),%ebx

# qhasm:   *(uint32 *) (out + 176) = in12
# asm 1: movl <in12=int32#1,176(<out=int32#6)
# asm 2: movl <in12=%eax,176(<out=%edi)
movl %eax,176(%edi)

# qhasm:   *(uint32 *) (out + 180) = in13
# asm 1: movl <in13=int32#2,180(<out=int32#6)
# asm 2: movl <in13=%ecx,180(<out=%edi)
movl %ecx,180(%edi)

# qhasm:   *(uint32 *) (out + 184) = in14
# asm 1: movl <in14=int32#3,184(<out=int32#6)
# asm 2: movl <in14=%edx,184(<out=%edi)
movl %edx,184(%edi)

# qhasm:   *(uint32 *) (out + 188) = in15
# asm 1: movl <in15=int32#4,188(<out=int32#6)
# asm 2: movl <in15=%ebx,188(<out=%edi)
movl %ebx,188(%edi)

# qhasm:   in12 = z12
# asm 1: movd   <z12=int6464#1,>in12=int32#1
# asm 2: movd   <z12=%xmm0,>in12=%eax
movd   %xmm0,%eax

# qhasm:   in13 = z13
# asm 1: movd   <z13=int6464#2,>in13=int32#2
# asm 2: movd   <z13=%xmm1,>in13=%ecx
movd   %xmm1,%ecx

# qhasm:   in14 = z14
# asm 1: movd   <z14=int6464#3,>in14=int32#3
# asm 2: movd   <z14=%xmm2,>in14=%edx
movd   %xmm2,%edx

# qhasm:   in15 = z15
# asm 1: movd   <z15=int6464#4,>in15=int32#4
# asm 2: movd   <z15=%xmm3,>in15=%ebx
movd   %xmm3,%ebx

# qhasm:   in12 ^= *(uint32 *) (m + 240)
# asm 1: xorl 240(<m=int32#5),<in12=int32#1
# asm 2: xorl 240(<m=%esi),<in12=%eax
xorl 240(%esi),%eax

# qhasm:   in13 ^= *(uint32 *) (m + 244)
# asm 1: xorl 244(<m=int32#5),<in13=int32#2
# asm 2: xorl 244(<m=%esi),<in13=%ecx
xorl 244(%esi),%ecx

# qhasm:   in14 ^= *(uint32 *) (m + 248)
# asm 1: xorl 248(<m=int32#5),<in14=int32#3
# asm 2: xorl 248(<m=%esi),<in14=%edx
xorl 248(%esi),%edx

# qhasm:   in15 ^= *(uint32 *) (m + 252)
# asm 1: xorl 252(<m=int32#5),<in15=int32#4
# asm 2: xorl 252(<m=%esi),<in15=%ebx
xorl 252(%esi),%ebx

# qhasm:   *(uint32 *) (out + 240) = in12
# asm 1: movl <in12=int32#1,240(<out=int32#6)
# asm 2: movl <in12=%eax,240(<out=%edi)
movl %eax,240(%edi)

# qhasm:   *(uint32 *) (out + 244) = in13
# asm 1: movl <in13=int32#2,244(<out=int32#6)
# asm 2: movl <in13=%ecx,244(<out=%edi)
movl %ecx,244(%edi)

# qhasm:   *(uint32 *) (out + 248) = in14
# asm 1: movl <in14=int32#3,248(<out=int32#6)
# asm 2: movl <in14=%edx,248(<out=%edi)
movl %edx,248(%edi)

# qhasm:   *(uint32 *) (out + 252) = in15
# asm 1: movl <in15=int32#4,252(<out=int32#6)
# asm 2: movl <in15=%ebx,252(<out=%edi)
movl %ebx,252(%edi)

# qhasm:   bytes = bytes_stack
# asm 1: movl <bytes_stack=stack32#7,>bytes=int32#1
# asm 2: movl <bytes_stack=24(%esp),>bytes=%eax
movl 24(%esp),%eax

# qhasm:   bytes -= 256
# asm 1: sub  $256,<bytes=int32#1
# asm 2: sub  $256,<bytes=%eax
sub  $256,%eax

# qhasm:   m += 256
# asm 1: add  $256,<m=int32#5
# asm 2: add  $256,<m=%esi
add  $256,%esi

# qhasm:   out += 256
# asm 1: add  $256,<out=int32#6
# asm 2: add  $256,<out=%edi
add  $256,%edi

# qhasm:   out_stack = out
# asm 1: movl <out=int32#6,>out_stack=stack32#6
# asm 2: movl <out=%edi,>out_stack=20(%esp)
movl %edi,20(%esp)

# qhasm:                            unsigned<? bytes - 256
# asm 1: cmp  $256,<bytes=int32#1
# asm 2: cmp  $256,<bytes=%eax
cmp  $256,%eax
# comment:fp stack unchanged by jump

# qhasm:   goto bytesatleast256 if !unsigned<
jae ._bytesatleast256

# qhasm:                 unsigned>? bytes - 0
# asm 1: cmp  $0,<bytes=int32#1
# asm 2: cmp  $0,<bytes=%eax
cmp  $0,%eax
# comment:fp stack unchanged by jump

# qhasm:   goto done if !unsigned>
jbe ._done
# comment:fp stack unchanged by fallthrough

# qhasm: bytesbetween1and255:
._bytesbetween1and255:

# qhasm:                   unsigned<? bytes - 64
# asm 1: cmp  $64,<bytes=int32#1
# asm 2: cmp  $64,<bytes=%eax
cmp  $64,%eax
# comment:fp stack unchanged by jump

# qhasm:   goto nocopy if !unsigned<
jae ._nocopy

# qhasm:     ctarget = out
# asm 1: movl <out=int32#6,>ctarget=stack32#6
# asm 2: movl <out=%edi,>ctarget=20(%esp)
movl %edi,20(%esp)

# qhasm:     out = &tmp
# asm 1: leal <tmp=stack512#1,>out=int32#6
# asm 2: leal <tmp=640(%esp),>out=%edi
leal 640(%esp),%edi

# qhasm:     i = bytes
# asm 1: mov  <bytes=int32#1,>i=int32#2
# asm 2: mov  <bytes=%eax,>i=%ecx
mov  %eax,%ecx

# qhasm:     while (i) { *out++ = *m++; --i }
rep movsb

# qhasm:     out = &tmp
# asm 1: leal <tmp=stack512#1,>out=int32#6
# asm 2: leal <tmp=640(%esp),>out=%edi
leal 640(%esp),%edi

# qhasm:     m = &tmp
# asm 1: leal <tmp=stack512#1,>m=int32#5
# asm 2: leal <tmp=640(%esp),>m=%esi
leal 640(%esp),%esi
# comment:fp stack unchanged by fallthrough

# qhasm:   nocopy:
._nocopy:

# qhasm:   bytes_stack = bytes
# asm 1: movl <bytes=int32#1,>bytes_stack=stack32#7
# asm 2: movl <bytes=%eax,>bytes_stack=24(%esp)
movl %eax,24(%esp)

# qhasm: diag0 = x0
# asm 1: movdqa <x0=stack128#3,>diag0=int6464#1
# asm 2: movdqa <x0=64(%esp),>diag0=%xmm0
movdqa 64(%esp),%xmm0

# qhasm: diag1 = x1
# asm 1: movdqa <x1=stack128#2,>diag1=int6464#2
# asm 2: movdqa <x1=48(%esp),>diag1=%xmm1
movdqa 48(%esp),%xmm1

# qhasm: diag2 = x2
# asm 1: movdqa <x2=stack128#4,>diag2=int6464#3
# asm 2: movdqa <x2=80(%esp),>diag2=%xmm2
movdqa 80(%esp),%xmm2

# qhasm: diag3 = x3
# asm 1: movdqa <x3=stack128#1,>diag3=int6464#4
# asm 2: movdqa <x3=32(%esp),>diag3=%xmm3
movdqa 32(%esp),%xmm3

# qhasm:                     a0 = diag1
# asm 1: movdqa <diag1=int6464#2,>a0=int6464#5
# asm 2: movdqa <diag1=%xmm1,>a0=%xmm4
movdqa %xmm1,%xmm4

# qhasm: i = 12
# asm 1: mov  $12,>i=int32#1
# asm 2: mov  $12,>i=%eax
mov  $12,%eax

# qhasm: mainloop2:
._mainloop2:

# qhasm: uint32323232        a0 += diag0
# asm 1: paddd <diag0=int6464#1,<a0=int6464#5
# asm 2: paddd <diag0=%xmm0,<a0=%xmm4
paddd %xmm0,%xmm4

# qhasm:                                 a1 = diag0
# asm 1: movdqa <diag0=int6464#1,>a1=int6464#6
# asm 2: movdqa <diag0=%xmm0,>a1=%xmm5
movdqa %xmm0,%xmm5

# qhasm:                     b0 = a0
# asm 1: movdqa <a0=int6464#5,>b0=int6464#7
# asm 2: movdqa <a0=%xmm4,>b0=%xmm6
movdqa %xmm4,%xmm6

# qhasm: uint32323232        a0 <<= 7
# asm 1: pslld $7,<a0=int6464#5
# asm 2: pslld $7,<a0=%xmm4
pslld $7,%xmm4

# qhasm: uint32323232        b0 >>= 25
# asm 1: psrld $25,<b0=int6464#7
# asm 2: psrld $25,<b0=%xmm6
psrld $25,%xmm6

# qhasm:                 diag3 ^= a0
# asm 1: pxor  <a0=int6464#5,<diag3=int6464#4
# asm 2: pxor  <a0=%xmm4,<diag3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:                 diag3 ^= b0
# asm 1: pxor  <b0=int6464#7,<diag3=int6464#4
# asm 2: pxor  <b0=%xmm6,<diag3=%xmm3
pxor  %xmm6,%xmm3

# qhasm: uint32323232                        a1 += diag3
# asm 1: paddd <diag3=int6464#4,<a1=int6464#6
# asm 2: paddd <diag3=%xmm3,<a1=%xmm5
paddd %xmm3,%xmm5

# qhasm:                                                 a2 = diag3
# asm 1: movdqa <diag3=int6464#4,>a2=int6464#5
# asm 2: movdqa <diag3=%xmm3,>a2=%xmm4
movdqa %xmm3,%xmm4

# qhasm:                                     b1 = a1
# asm 1: movdqa <a1=int6464#6,>b1=int6464#7
# asm 2: movdqa <a1=%xmm5,>b1=%xmm6
movdqa %xmm5,%xmm6

# qhasm: uint32323232                        a1 <<= 9
# asm 1: pslld $9,<a1=int6464#6
# asm 2: pslld $9,<a1=%xmm5
pslld $9,%xmm5

# qhasm: uint32323232                        b1 >>= 23
# asm 1: psrld $23,<b1=int6464#7
# asm 2: psrld $23,<b1=%xmm6
psrld $23,%xmm6

# qhasm:                                 diag2 ^= a1
# asm 1: pxor  <a1=int6464#6,<diag2=int6464#3
# asm 2: pxor  <a1=%xmm5,<diag2=%xmm2
pxor  %xmm5,%xmm2

# qhasm:                 diag3 <<<= 32
# asm 1: pshufd $0x93,<diag3=int6464#4,<diag3=int6464#4
# asm 2: pshufd $0x93,<diag3=%xmm3,<diag3=%xmm3
pshufd $0x93,%xmm3,%xmm3

# qhasm:                                 diag2 ^= b1
# asm 1: pxor  <b1=int6464#7,<diag2=int6464#3
# asm 2: pxor  <b1=%xmm6,<diag2=%xmm2
pxor  %xmm6,%xmm2

# qhasm: uint32323232                                        a2 += diag2
# asm 1: paddd <diag2=int6464#3,<a2=int6464#5
# asm 2: paddd <diag2=%xmm2,<a2=%xmm4
paddd %xmm2,%xmm4

# qhasm:                                                                 a3 = diag2
# asm 1: movdqa <diag2=int6464#3,>a3=int6464#6
# asm 2: movdqa <diag2=%xmm2,>a3=%xmm5
movdqa %xmm2,%xmm5

# qhasm:                                                     b2 = a2
# asm 1: movdqa <a2=int6464#5,>b2=int6464#7
# asm 2: movdqa <a2=%xmm4,>b2=%xmm6
movdqa %xmm4,%xmm6

# qhasm: uint32323232                                        a2 <<= 13
# asm 1: pslld $13,<a2=int6464#5
# asm 2: pslld $13,<a2=%xmm4
pslld $13,%xmm4

# qhasm: uint32323232                                        b2 >>= 19
# asm 1: psrld $19,<b2=int6464#7
# asm 2: psrld $19,<b2=%xmm6
psrld $19,%xmm6

# qhasm:                                                 diag1 ^= a2
# asm 1: pxor  <a2=int6464#5,<diag1=int6464#2
# asm 2: pxor  <a2=%xmm4,<diag1=%xmm1
pxor  %xmm4,%xmm1

# qhasm:                                 diag2 <<<= 64
# asm 1: pshufd $0x4e,<diag2=int6464#3,<diag2=int6464#3
# asm 2: pshufd $0x4e,<diag2=%xmm2,<diag2=%xmm2
pshufd $0x4e,%xmm2,%xmm2

# qhasm:                                                 diag1 ^= b2
# asm 1: pxor  <b2=int6464#7,<diag1=int6464#2
# asm 2: pxor  <b2=%xmm6,<diag1=%xmm1
pxor  %xmm6,%xmm1

# qhasm: uint32323232                                                        a3 += diag1
# asm 1: paddd <diag1=int6464#2,<a3=int6464#6
# asm 2: paddd <diag1=%xmm1,<a3=%xmm5
paddd %xmm1,%xmm5

# qhasm:                 a4 = diag3
# asm 1: movdqa <diag3=int6464#4,>a4=int6464#5
# asm 2: movdqa <diag3=%xmm3,>a4=%xmm4
movdqa %xmm3,%xmm4

# qhasm:                                                                     b3 = a3
# asm 1: movdqa <a3=int6464#6,>b3=int6464#7
# asm 2: movdqa <a3=%xmm5,>b3=%xmm6
movdqa %xmm5,%xmm6

# qhasm: uint32323232                                                        a3 <<= 18
# asm 1: pslld $18,<a3=int6464#6
# asm 2: pslld $18,<a3=%xmm5
pslld $18,%xmm5

# qhasm: uint32323232                                                        b3 >>= 14
# asm 1: psrld $14,<b3=int6464#7
# asm 2: psrld $14,<b3=%xmm6
psrld $14,%xmm6

# qhasm:                                                                 diag0 ^= a3
# asm 1: pxor  <a3=int6464#6,<diag0=int6464#1
# asm 2: pxor  <a3=%xmm5,<diag0=%xmm0
pxor  %xmm5,%xmm0

# qhasm:                                                 diag1 <<<= 96
# asm 1: pshufd $0x39,<diag1=int6464#2,<diag1=int6464#2
# asm 2: pshufd $0x39,<diag1=%xmm1,<diag1=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm:                                                                 diag0 ^= b3
# asm 1: pxor  <b3=int6464#7,<diag0=int6464#1
# asm 2: pxor  <b3=%xmm6,<diag0=%xmm0
pxor  %xmm6,%xmm0

# qhasm: uint32323232        a4 += diag0
# asm 1: paddd <diag0=int6464#1,<a4=int6464#5
# asm 2: paddd <diag0=%xmm0,<a4=%xmm4
paddd %xmm0,%xmm4

# qhasm:                                 a5 = diag0
# asm 1: movdqa <diag0=int6464#1,>a5=int6464#6
# asm 2: movdqa <diag0=%xmm0,>a5=%xmm5
movdqa %xmm0,%xmm5

# qhasm:                     b4 = a4
# asm 1: movdqa <a4=int6464#5,>b4=int6464#7
# asm 2: movdqa <a4=%xmm4,>b4=%xmm6
movdqa %xmm4,%xmm6

# qhasm: uint32323232        a4 <<= 7
# asm 1: pslld $7,<a4=int6464#5
# asm 2: pslld $7,<a4=%xmm4
pslld $7,%xmm4

# qhasm: uint32323232        b4 >>= 25
# asm 1: psrld $25,<b4=int6464#7
# asm 2: psrld $25,<b4=%xmm6
psrld $25,%xmm6

# qhasm:                 diag1 ^= a4
# asm 1: pxor  <a4=int6464#5,<diag1=int6464#2
# asm 2: pxor  <a4=%xmm4,<diag1=%xmm1
pxor  %xmm4,%xmm1

# qhasm:                 diag1 ^= b4
# asm 1: pxor  <b4=int6464#7,<diag1=int6464#2
# asm 2: pxor  <b4=%xmm6,<diag1=%xmm1
pxor  %xmm6,%xmm1

# qhasm: uint32323232                        a5 += diag1
# asm 1: paddd <diag1=int6464#2,<a5=int6464#6
# asm 2: paddd <diag1=%xmm1,<a5=%xmm5
paddd %xmm1,%xmm5

# qhasm:                                                 a6 = diag1
# asm 1: movdqa <diag1=int6464#2,>a6=int6464#5
# asm 2: movdqa <diag1=%xmm1,>a6=%xmm4
movdqa %xmm1,%xmm4

# qhasm:                                     b5 = a5
# asm 1: movdqa <a5=int6464#6,>b5=int6464#7
# asm 2: movdqa <a5=%xmm5,>b5=%xmm6
movdqa %xmm5,%xmm6

# qhasm: uint32323232                        a5 <<= 9
# asm 1: pslld $9,<a5=int6464#6
# asm 2: pslld $9,<a5=%xmm5
pslld $9,%xmm5

# qhasm: uint32323232                        b5 >>= 23
# asm 1: psrld $23,<b5=int6464#7
# asm 2: psrld $23,<b5=%xmm6
psrld $23,%xmm6

# qhasm:                                 diag2 ^= a5
# asm 1: pxor  <a5=int6464#6,<diag2=int6464#3
# asm 2: pxor  <a5=%xmm5,<diag2=%xmm2
pxor  %xmm5,%xmm2

# qhasm:                 diag1 <<<= 32
# asm 1: pshufd $0x93,<diag1=int6464#2,<diag1=int6464#2
# asm 2: pshufd $0x93,<diag1=%xmm1,<diag1=%xmm1
pshufd $0x93,%xmm1,%xmm1

# qhasm:                                 diag2 ^= b5
# asm 1: pxor  <b5=int6464#7,<diag2=int6464#3
# asm 2: pxor  <b5=%xmm6,<diag2=%xmm2
pxor  %xmm6,%xmm2

# qhasm: uint32323232                                        a6 += diag2
# asm 1: paddd <diag2=int6464#3,<a6=int6464#5
# asm 2: paddd <diag2=%xmm2,<a6=%xmm4
paddd %xmm2,%xmm4

# qhasm:                                                                 a7 = diag2
# asm 1: movdqa <diag2=int6464#3,>a7=int6464#6
# asm 2: movdqa <diag2=%xmm2,>a7=%xmm5
movdqa %xmm2,%xmm5

# qhasm:                                                     b6 = a6
# asm 1: movdqa <a6=int6464#5,>b6=int6464#7
# asm 2: movdqa <a6=%xmm4,>b6=%xmm6
movdqa %xmm4,%xmm6

# qhasm: uint32323232                                        a6 <<= 13
# asm 1: pslld $13,<a6=int6464#5
# asm 2: pslld $13,<a6=%xmm4
pslld $13,%xmm4

# qhasm: uint32323232                                        b6 >>= 19
# asm 1: psrld $19,<b6=int6464#7
# asm 2: psrld $19,<b6=%xmm6
psrld $19,%xmm6

# qhasm:                                                 diag3 ^= a6
# asm 1: pxor  <a6=int6464#5,<diag3=int6464#4
# asm 2: pxor  <a6=%xmm4,<diag3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:                                 diag2 <<<= 64
# asm 1: pshufd $0x4e,<diag2=int6464#3,<diag2=int6464#3
# asm 2: pshufd $0x4e,<diag2=%xmm2,<diag2=%xmm2
pshufd $0x4e,%xmm2,%xmm2

# qhasm:                                                 diag3 ^= b6
# asm 1: pxor  <b6=int6464#7,<diag3=int6464#4
# asm 2: pxor  <b6=%xmm6,<diag3=%xmm3
pxor  %xmm6,%xmm3

# qhasm: uint32323232                                                        a7 += diag3
# asm 1: paddd <diag3=int6464#4,<a7=int6464#6
# asm 2: paddd <diag3=%xmm3,<a7=%xmm5
paddd %xmm3,%xmm5

# qhasm:                 a0 = diag1
# asm 1: movdqa <diag1=int6464#2,>a0=int6464#5
# asm 2: movdqa <diag1=%xmm1,>a0=%xmm4
movdqa %xmm1,%xmm4

# qhasm:                                                                     b7 = a7
# asm 1: movdqa <a7=int6464#6,>b7=int6464#7
# asm 2: movdqa <a7=%xmm5,>b7=%xmm6
movdqa %xmm5,%xmm6

# qhasm: uint32323232                                                        a7 <<= 18
# asm 1: pslld $18,<a7=int6464#6
# asm 2: pslld $18,<a7=%xmm5
pslld $18,%xmm5

# qhasm: uint32323232                                                        b7 >>= 14
# asm 1: psrld $14,<b7=int6464#7
# asm 2: psrld $14,<b7=%xmm6
psrld $14,%xmm6

# qhasm:                                                                 diag0 ^= a7
# asm 1: pxor  <a7=int6464#6,<diag0=int6464#1
# asm 2: pxor  <a7=%xmm5,<diag0=%xmm0
pxor  %xmm5,%xmm0

# qhasm:                                                 diag3 <<<= 96
# asm 1: pshufd $0x39,<diag3=int6464#4,<diag3=int6464#4
# asm 2: pshufd $0x39,<diag3=%xmm3,<diag3=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm:                                                                 diag0 ^= b7
# asm 1: pxor  <b7=int6464#7,<diag0=int6464#1
# asm 2: pxor  <b7=%xmm6,<diag0=%xmm0
pxor  %xmm6,%xmm0

# qhasm: uint32323232        a0 += diag0
# asm 1: paddd <diag0=int6464#1,<a0=int6464#5
# asm 2: paddd <diag0=%xmm0,<a0=%xmm4
paddd %xmm0,%xmm4

# qhasm:                                 a1 = diag0
# asm 1: movdqa <diag0=int6464#1,>a1=int6464#6
# asm 2: movdqa <diag0=%xmm0,>a1=%xmm5
movdqa %xmm0,%xmm5

# qhasm:                     b0 = a0
# asm 1: movdqa <a0=int6464#5,>b0=int6464#7
# asm 2: movdqa <a0=%xmm4,>b0=%xmm6
movdqa %xmm4,%xmm6

# qhasm: uint32323232        a0 <<= 7
# asm 1: pslld $7,<a0=int6464#5
# asm 2: pslld $7,<a0=%xmm4
pslld $7,%xmm4

# qhasm: uint32323232        b0 >>= 25
# asm 1: psrld $25,<b0=int6464#7
# asm 2: psrld $25,<b0=%xmm6
psrld $25,%xmm6

# qhasm:                 diag3 ^= a0
# asm 1: pxor  <a0=int6464#5,<diag3=int6464#4
# asm 2: pxor  <a0=%xmm4,<diag3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:                 diag3 ^= b0
# asm 1: pxor  <b0=int6464#7,<diag3=int6464#4
# asm 2: pxor  <b0=%xmm6,<diag3=%xmm3
pxor  %xmm6,%xmm3

# qhasm: uint32323232                        a1 += diag3
# asm 1: paddd <diag3=int6464#4,<a1=int6464#6
# asm 2: paddd <diag3=%xmm3,<a1=%xmm5
paddd %xmm3,%xmm5

# qhasm:                                                 a2 = diag3
# asm 1: movdqa <diag3=int6464#4,>a2=int6464#5
# asm 2: movdqa <diag3=%xmm3,>a2=%xmm4
movdqa %xmm3,%xmm4

# qhasm:                                     b1 = a1
# asm 1: movdqa <a1=int6464#6,>b1=int6464#7
# asm 2: movdqa <a1=%xmm5,>b1=%xmm6
movdqa %xmm5,%xmm6

# qhasm: uint32323232                        a1 <<= 9
# asm 1: pslld $9,<a1=int6464#6
# asm 2: pslld $9,<a1=%xmm5
pslld $9,%xmm5

# qhasm: uint32323232                        b1 >>= 23
# asm 1: psrld $23,<b1=int6464#7
# asm 2: psrld $23,<b1=%xmm6
psrld $23,%xmm6

# qhasm:                                 diag2 ^= a1
# asm 1: pxor  <a1=int6464#6,<diag2=int6464#3
# asm 2: pxor  <a1=%xmm5,<diag2=%xmm2
pxor  %xmm5,%xmm2

# qhasm:                 diag3 <<<= 32
# asm 1: pshufd $0x93,<diag3=int6464#4,<diag3=int6464#4
# asm 2: pshufd $0x93,<diag3=%xmm3,<diag3=%xmm3
pshufd $0x93,%xmm3,%xmm3

# qhasm:                                 diag2 ^= b1
# asm 1: pxor  <b1=int6464#7,<diag2=int6464#3
# asm 2: pxor  <b1=%xmm6,<diag2=%xmm2
pxor  %xmm6,%xmm2

# qhasm: uint32323232                                        a2 += diag2
# asm 1: paddd <diag2=int6464#3,<a2=int6464#5
# asm 2: paddd <diag2=%xmm2,<a2=%xmm4
paddd %xmm2,%xmm4

# qhasm:                                                                 a3 = diag2
# asm 1: movdqa <diag2=int6464#3,>a3=int6464#6
# asm 2: movdqa <diag2=%xmm2,>a3=%xmm5
movdqa %xmm2,%xmm5

# qhasm:                                                     b2 = a2
# asm 1: movdqa <a2=int6464#5,>b2=int6464#7
# asm 2: movdqa <a2=%xmm4,>b2=%xmm6
movdqa %xmm4,%xmm6

# qhasm: uint32323232                                        a2 <<= 13
# asm 1: pslld $13,<a2=int6464#5
# asm 2: pslld $13,<a2=%xmm4
pslld $13,%xmm4

# qhasm: uint32323232                                        b2 >>= 19
# asm 1: psrld $19,<b2=int6464#7
# asm 2: psrld $19,<b2=%xmm6
psrld $19,%xmm6

# qhasm:                                                 diag1 ^= a2
# asm 1: pxor  <a2=int6464#5,<diag1=int6464#2
# asm 2: pxor  <a2=%xmm4,<diag1=%xmm1
pxor  %xmm4,%xmm1

# qhasm:                                 diag2 <<<= 64
# asm 1: pshufd $0x4e,<diag2=int6464#3,<diag2=int6464#3
# asm 2: pshufd $0x4e,<diag2=%xmm2,<diag2=%xmm2
pshufd $0x4e,%xmm2,%xmm2

# qhasm:                                                 diag1 ^= b2
# asm 1: pxor  <b2=int6464#7,<diag1=int6464#2
# asm 2: pxor  <b2=%xmm6,<diag1=%xmm1
pxor  %xmm6,%xmm1

# qhasm: uint32323232                                                        a3 += diag1
# asm 1: paddd <diag1=int6464#2,<a3=int6464#6
# asm 2: paddd <diag1=%xmm1,<a3=%xmm5
paddd %xmm1,%xmm5

# qhasm:                 a4 = diag3
# asm 1: movdqa <diag3=int6464#4,>a4=int6464#5
# asm 2: movdqa <diag3=%xmm3,>a4=%xmm4
movdqa %xmm3,%xmm4

# qhasm:                                                                     b3 = a3
# asm 1: movdqa <a3=int6464#6,>b3=int6464#7
# asm 2: movdqa <a3=%xmm5,>b3=%xmm6
movdqa %xmm5,%xmm6

# qhasm: uint32323232                                                        a3 <<= 18
# asm 1: pslld $18,<a3=int6464#6
# asm 2: pslld $18,<a3=%xmm5
pslld $18,%xmm5

# qhasm: uint32323232                                                        b3 >>= 14
# asm 1: psrld $14,<b3=int6464#7
# asm 2: psrld $14,<b3=%xmm6
psrld $14,%xmm6

# qhasm:                                                                 diag0 ^= a3
# asm 1: pxor  <a3=int6464#6,<diag0=int6464#1
# asm 2: pxor  <a3=%xmm5,<diag0=%xmm0
pxor  %xmm5,%xmm0

# qhasm:                                                 diag1 <<<= 96
# asm 1: pshufd $0x39,<diag1=int6464#2,<diag1=int6464#2
# asm 2: pshufd $0x39,<diag1=%xmm1,<diag1=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm:                                                                 diag0 ^= b3
# asm 1: pxor  <b3=int6464#7,<diag0=int6464#1
# asm 2: pxor  <b3=%xmm6,<diag0=%xmm0
pxor  %xmm6,%xmm0

# qhasm: uint32323232        a4 += diag0
# asm 1: paddd <diag0=int6464#1,<a4=int6464#5
# asm 2: paddd <diag0=%xmm0,<a4=%xmm4
paddd %xmm0,%xmm4

# qhasm:                                 a5 = diag0
# asm 1: movdqa <diag0=int6464#1,>a5=int6464#6
# asm 2: movdqa <diag0=%xmm0,>a5=%xmm5
movdqa %xmm0,%xmm5

# qhasm:                     b4 = a4
# asm 1: movdqa <a4=int6464#5,>b4=int6464#7
# asm 2: movdqa <a4=%xmm4,>b4=%xmm6
movdqa %xmm4,%xmm6

# qhasm: uint32323232        a4 <<= 7
# asm 1: pslld $7,<a4=int6464#5
# asm 2: pslld $7,<a4=%xmm4
pslld $7,%xmm4

# qhasm: uint32323232        b4 >>= 25
# asm 1: psrld $25,<b4=int6464#7
# asm 2: psrld $25,<b4=%xmm6
psrld $25,%xmm6

# qhasm:                 diag1 ^= a4
# asm 1: pxor  <a4=int6464#5,<diag1=int6464#2
# asm 2: pxor  <a4=%xmm4,<diag1=%xmm1
pxor  %xmm4,%xmm1

# qhasm:                 diag1 ^= b4
# asm 1: pxor  <b4=int6464#7,<diag1=int6464#2
# asm 2: pxor  <b4=%xmm6,<diag1=%xmm1
pxor  %xmm6,%xmm1

# qhasm: uint32323232                        a5 += diag1
# asm 1: paddd <diag1=int6464#2,<a5=int6464#6
# asm 2: paddd <diag1=%xmm1,<a5=%xmm5
paddd %xmm1,%xmm5

# qhasm:                                                 a6 = diag1
# asm 1: movdqa <diag1=int6464#2,>a6=int6464#5
# asm 2: movdqa <diag1=%xmm1,>a6=%xmm4
movdqa %xmm1,%xmm4

# qhasm:                                     b5 = a5
# asm 1: movdqa <a5=int6464#6,>b5=int6464#7
# asm 2: movdqa <a5=%xmm5,>b5=%xmm6
movdqa %xmm5,%xmm6

# qhasm: uint32323232                        a5 <<= 9
# asm 1: pslld $9,<a5=int6464#6
# asm 2: pslld $9,<a5=%xmm5
pslld $9,%xmm5

# qhasm: uint32323232                        b5 >>= 23
# asm 1: psrld $23,<b5=int6464#7
# asm 2: psrld $23,<b5=%xmm6
psrld $23,%xmm6

# qhasm:                                 diag2 ^= a5
# asm 1: pxor  <a5=int6464#6,<diag2=int6464#3
# asm 2: pxor  <a5=%xmm5,<diag2=%xmm2
pxor  %xmm5,%xmm2

# qhasm:                 diag1 <<<= 32
# asm 1: pshufd $0x93,<diag1=int6464#2,<diag1=int6464#2
# asm 2: pshufd $0x93,<diag1=%xmm1,<diag1=%xmm1
pshufd $0x93,%xmm1,%xmm1

# qhasm:                                 diag2 ^= b5
# asm 1: pxor  <b5=int6464#7,<diag2=int6464#3
# asm 2: pxor  <b5=%xmm6,<diag2=%xmm2
pxor  %xmm6,%xmm2

# qhasm: uint32323232                                        a6 += diag2
# asm 1: paddd <diag2=int6464#3,<a6=int6464#5
# asm 2: paddd <diag2=%xmm2,<a6=%xmm4
paddd %xmm2,%xmm4

# qhasm:                                                                 a7 = diag2
# asm 1: movdqa <diag2=int6464#3,>a7=int6464#6
# asm 2: movdqa <diag2=%xmm2,>a7=%xmm5
movdqa %xmm2,%xmm5

# qhasm:                                                     b6 = a6
# asm 1: movdqa <a6=int6464#5,>b6=int6464#7
# asm 2: movdqa <a6=%xmm4,>b6=%xmm6
movdqa %xmm4,%xmm6

# qhasm: uint32323232                                        a6 <<= 13
# asm 1: pslld $13,<a6=int6464#5
# asm 2: pslld $13,<a6=%xmm4
pslld $13,%xmm4

# qhasm: uint32323232                                        b6 >>= 19
# asm 1: psrld $19,<b6=int6464#7
# asm 2: psrld $19,<b6=%xmm6
psrld $19,%xmm6

# qhasm:                                                 diag3 ^= a6
# asm 1: pxor  <a6=int6464#5,<diag3=int6464#4
# asm 2: pxor  <a6=%xmm4,<diag3=%xmm3
pxor  %xmm4,%xmm3

# qhasm:                                 diag2 <<<= 64
# asm 1: pshufd $0x4e,<diag2=int6464#3,<diag2=int6464#3
# asm 2: pshufd $0x4e,<diag2=%xmm2,<diag2=%xmm2
pshufd $0x4e,%xmm2,%xmm2

# qhasm:                                                 diag3 ^= b6
# asm 1: pxor  <b6=int6464#7,<diag3=int6464#4
# asm 2: pxor  <b6=%xmm6,<diag3=%xmm3
pxor  %xmm6,%xmm3

# qhasm:                  unsigned>? i -= 4
# asm 1: sub  $4,<i=int32#1
# asm 2: sub  $4,<i=%eax
sub  $4,%eax

# qhasm: uint32323232                                                        a7 += diag3
# asm 1: paddd <diag3=int6464#4,<a7=int6464#6
# asm 2: paddd <diag3=%xmm3,<a7=%xmm5
paddd %xmm3,%xmm5

# qhasm:                 a0 = diag1
# asm 1: movdqa <diag1=int6464#2,>a0=int6464#5
# asm 2: movdqa <diag1=%xmm1,>a0=%xmm4
movdqa %xmm1,%xmm4

# qhasm:                                                                     b7 = a7
# asm 1: movdqa <a7=int6464#6,>b7=int6464#7
# asm 2: movdqa <a7=%xmm5,>b7=%xmm6
movdqa %xmm5,%xmm6

# qhasm: uint32323232                                                        a7 <<= 18
# asm 1: pslld $18,<a7=int6464#6
# asm 2: pslld $18,<a7=%xmm5
pslld $18,%xmm5

# qhasm:                 b0 = 0
# asm 1: pxor   >b0=int6464#8,>b0=int6464#8
# asm 2: pxor   >b0=%xmm7,>b0=%xmm7
pxor   %xmm7,%xmm7

# qhasm: uint32323232                                                        b7 >>= 14
# asm 1: psrld $14,<b7=int6464#7
# asm 2: psrld $14,<b7=%xmm6
psrld $14,%xmm6

# qhasm:                                                                 diag0 ^= a7
# asm 1: pxor  <a7=int6464#6,<diag0=int6464#1
# asm 2: pxor  <a7=%xmm5,<diag0=%xmm0
pxor  %xmm5,%xmm0

# qhasm:                                                 diag3 <<<= 96
# asm 1: pshufd $0x39,<diag3=int6464#4,<diag3=int6464#4
# asm 2: pshufd $0x39,<diag3=%xmm3,<diag3=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm:                                                                 diag0 ^= b7
# asm 1: pxor  <b7=int6464#7,<diag0=int6464#1
# asm 2: pxor  <b7=%xmm6,<diag0=%xmm0
pxor  %xmm6,%xmm0
# comment:fp stack unchanged by jump

# qhasm: goto mainloop2 if unsigned>
ja ._mainloop2

# qhasm: uint32323232 diag0 += x0
# asm 1: paddd <x0=stack128#3,<diag0=int6464#1
# asm 2: paddd <x0=64(%esp),<diag0=%xmm0
paddd 64(%esp),%xmm0

# qhasm: uint32323232 diag1 += x1
# asm 1: paddd <x1=stack128#2,<diag1=int6464#2
# asm 2: paddd <x1=48(%esp),<diag1=%xmm1
paddd 48(%esp),%xmm1

# qhasm: uint32323232 diag2 += x2
# asm 1: paddd <x2=stack128#4,<diag2=int6464#3
# asm 2: paddd <x2=80(%esp),<diag2=%xmm2
paddd 80(%esp),%xmm2

# qhasm: uint32323232 diag3 += x3
# asm 1: paddd <x3=stack128#1,<diag3=int6464#4
# asm 2: paddd <x3=32(%esp),<diag3=%xmm3
paddd 32(%esp),%xmm3

# qhasm: in0 = diag0
# asm 1: movd   <diag0=int6464#1,>in0=int32#1
# asm 2: movd   <diag0=%xmm0,>in0=%eax
movd   %xmm0,%eax

# qhasm: in12 = diag1
# asm 1: movd   <diag1=int6464#2,>in12=int32#2
# asm 2: movd   <diag1=%xmm1,>in12=%ecx
movd   %xmm1,%ecx

# qhasm: in8 = diag2
# asm 1: movd   <diag2=int6464#3,>in8=int32#3
# asm 2: movd   <diag2=%xmm2,>in8=%edx
movd   %xmm2,%edx

# qhasm: in4 = diag3
# asm 1: movd   <diag3=int6464#4,>in4=int32#4
# asm 2: movd   <diag3=%xmm3,>in4=%ebx
movd   %xmm3,%ebx

# qhasm: diag0 <<<= 96
# asm 1: pshufd $0x39,<diag0=int6464#1,<diag0=int6464#1
# asm 2: pshufd $0x39,<diag0=%xmm0,<diag0=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm: diag1 <<<= 96
# asm 1: pshufd $0x39,<diag1=int6464#2,<diag1=int6464#2
# asm 2: pshufd $0x39,<diag1=%xmm1,<diag1=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm: diag2 <<<= 96
# asm 1: pshufd $0x39,<diag2=int6464#3,<diag2=int6464#3
# asm 2: pshufd $0x39,<diag2=%xmm2,<diag2=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm: diag3 <<<= 96
# asm 1: pshufd $0x39,<diag3=int6464#4,<diag3=int6464#4
# asm 2: pshufd $0x39,<diag3=%xmm3,<diag3=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm: in0 ^= *(uint32 *) (m + 0)
# asm 1: xorl 0(<m=int32#5),<in0=int32#1
# asm 2: xorl 0(<m=%esi),<in0=%eax
xorl 0(%esi),%eax

# qhasm: in12 ^= *(uint32 *) (m + 48)
# asm 1: xorl 48(<m=int32#5),<in12=int32#2
# asm 2: xorl 48(<m=%esi),<in12=%ecx
xorl 48(%esi),%ecx

# qhasm: in8 ^= *(uint32 *) (m + 32)
# asm 1: xorl 32(<m=int32#5),<in8=int32#3
# asm 2: xorl 32(<m=%esi),<in8=%edx
xorl 32(%esi),%edx

# qhasm: in4 ^= *(uint32 *) (m + 16)
# asm 1: xorl 16(<m=int32#5),<in4=int32#4
# asm 2: xorl 16(<m=%esi),<in4=%ebx
xorl 16(%esi),%ebx

# qhasm: *(uint32 *) (out + 0) = in0
# asm 1: movl <in0=int32#1,0(<out=int32#6)
# asm 2: movl <in0=%eax,0(<out=%edi)
movl %eax,0(%edi)

# qhasm: *(uint32 *) (out + 48) = in12
# asm 1: movl <in12=int32#2,48(<out=int32#6)
# asm 2: movl <in12=%ecx,48(<out=%edi)
movl %ecx,48(%edi)

# qhasm: *(uint32 *) (out + 32) = in8
# asm 1: movl <in8=int32#3,32(<out=int32#6)
# asm 2: movl <in8=%edx,32(<out=%edi)
movl %edx,32(%edi)

# qhasm: *(uint32 *) (out + 16) = in4
# asm 1: movl <in4=int32#4,16(<out=int32#6)
# asm 2: movl <in4=%ebx,16(<out=%edi)
movl %ebx,16(%edi)

# qhasm: in5 = diag0
# asm 1: movd   <diag0=int6464#1,>in5=int32#1
# asm 2: movd   <diag0=%xmm0,>in5=%eax
movd   %xmm0,%eax

# qhasm: in1 = diag1
# asm 1: movd   <diag1=int6464#2,>in1=int32#2
# asm 2: movd   <diag1=%xmm1,>in1=%ecx
movd   %xmm1,%ecx

# qhasm: in13 = diag2
# asm 1: movd   <diag2=int6464#3,>in13=int32#3
# asm 2: movd   <diag2=%xmm2,>in13=%edx
movd   %xmm2,%edx

# qhasm: in9 = diag3
# asm 1: movd   <diag3=int6464#4,>in9=int32#4
# asm 2: movd   <diag3=%xmm3,>in9=%ebx
movd   %xmm3,%ebx

# qhasm: diag0 <<<= 96
# asm 1: pshufd $0x39,<diag0=int6464#1,<diag0=int6464#1
# asm 2: pshufd $0x39,<diag0=%xmm0,<diag0=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm: diag1 <<<= 96
# asm 1: pshufd $0x39,<diag1=int6464#2,<diag1=int6464#2
# asm 2: pshufd $0x39,<diag1=%xmm1,<diag1=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm: diag2 <<<= 96
# asm 1: pshufd $0x39,<diag2=int6464#3,<diag2=int6464#3
# asm 2: pshufd $0x39,<diag2=%xmm2,<diag2=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm: diag3 <<<= 96
# asm 1: pshufd $0x39,<diag3=int6464#4,<diag3=int6464#4
# asm 2: pshufd $0x39,<diag3=%xmm3,<diag3=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm: in5 ^= *(uint32 *) (m + 20)
# asm 1: xorl 20(<m=int32#5),<in5=int32#1
# asm 2: xorl 20(<m=%esi),<in5=%eax
xorl 20(%esi),%eax

# qhasm: in1 ^= *(uint32 *) (m + 4)
# asm 1: xorl 4(<m=int32#5),<in1=int32#2
# asm 2: xorl 4(<m=%esi),<in1=%ecx
xorl 4(%esi),%ecx

# qhasm: in13 ^= *(uint32 *) (m + 52)
# asm 1: xorl 52(<m=int32#5),<in13=int32#3
# asm 2: xorl 52(<m=%esi),<in13=%edx
xorl 52(%esi),%edx

# qhasm: in9 ^= *(uint32 *) (m + 36)
# asm 1: xorl 36(<m=int32#5),<in9=int32#4
# asm 2: xorl 36(<m=%esi),<in9=%ebx
xorl 36(%esi),%ebx

# qhasm: *(uint32 *) (out + 20) = in5
# asm 1: movl <in5=int32#1,20(<out=int32#6)
# asm 2: movl <in5=%eax,20(<out=%edi)
movl %eax,20(%edi)

# qhasm: *(uint32 *) (out + 4) = in1
# asm 1: movl <in1=int32#2,4(<out=int32#6)
# asm 2: movl <in1=%ecx,4(<out=%edi)
movl %ecx,4(%edi)

# qhasm: *(uint32 *) (out + 52) = in13
# asm 1: movl <in13=int32#3,52(<out=int32#6)
# asm 2: movl <in13=%edx,52(<out=%edi)
movl %edx,52(%edi)

# qhasm: *(uint32 *) (out + 36) = in9
# asm 1: movl <in9=int32#4,36(<out=int32#6)
# asm 2: movl <in9=%ebx,36(<out=%edi)
movl %ebx,36(%edi)

# qhasm: in10 = diag0
# asm 1: movd   <diag0=int6464#1,>in10=int32#1
# asm 2: movd   <diag0=%xmm0,>in10=%eax
movd   %xmm0,%eax

# qhasm: in6 = diag1
# asm 1: movd   <diag1=int6464#2,>in6=int32#2
# asm 2: movd   <diag1=%xmm1,>in6=%ecx
movd   %xmm1,%ecx

# qhasm: in2 = diag2
# asm 1: movd   <diag2=int6464#3,>in2=int32#3
# asm 2: movd   <diag2=%xmm2,>in2=%edx
movd   %xmm2,%edx

# qhasm: in14 = diag3
# asm 1: movd   <diag3=int6464#4,>in14=int32#4
# asm 2: movd   <diag3=%xmm3,>in14=%ebx
movd   %xmm3,%ebx

# qhasm: diag0 <<<= 96
# asm 1: pshufd $0x39,<diag0=int6464#1,<diag0=int6464#1
# asm 2: pshufd $0x39,<diag0=%xmm0,<diag0=%xmm0
pshufd $0x39,%xmm0,%xmm0

# qhasm: diag1 <<<= 96
# asm 1: pshufd $0x39,<diag1=int6464#2,<diag1=int6464#2
# asm 2: pshufd $0x39,<diag1=%xmm1,<diag1=%xmm1
pshufd $0x39,%xmm1,%xmm1

# qhasm: diag2 <<<= 96
# asm 1: pshufd $0x39,<diag2=int6464#3,<diag2=int6464#3
# asm 2: pshufd $0x39,<diag2=%xmm2,<diag2=%xmm2
pshufd $0x39,%xmm2,%xmm2

# qhasm: diag3 <<<= 96
# asm 1: pshufd $0x39,<diag3=int6464#4,<diag3=int6464#4
# asm 2: pshufd $0x39,<diag3=%xmm3,<diag3=%xmm3
pshufd $0x39,%xmm3,%xmm3

# qhasm: in10 ^= *(uint32 *) (m + 40)
# asm 1: xorl 40(<m=int32#5),<in10=int32#1
# asm 2: xorl 40(<m=%esi),<in10=%eax
xorl 40(%esi),%eax

# qhasm: in6 ^= *(uint32 *) (m + 24)
# asm 1: xorl 24(<m=int32#5),<in6=int32#2
# asm 2: xorl 24(<m=%esi),<in6=%ecx
xorl 24(%esi),%ecx

# qhasm: in2 ^= *(uint32 *) (m + 8)
# asm 1: xorl 8(<m=int32#5),<in2=int32#3
# asm 2: xorl 8(<m=%esi),<in2=%edx
xorl 8(%esi),%edx

# qhasm: in14 ^= *(uint32 *) (m + 56)
# asm 1: xorl 56(<m=int32#5),<in14=int32#4
# asm 2: xorl 56(<m=%esi),<in14=%ebx
xorl 56(%esi),%ebx

# qhasm: *(uint32 *) (out + 40) = in10
# asm 1: movl <in10=int32#1,40(<out=int32#6)
# asm 2: movl <in10=%eax,40(<out=%edi)
movl %eax,40(%edi)

# qhasm: *(uint32 *) (out + 24) = in6
# asm 1: movl <in6=int32#2,24(<out=int32#6)
# asm 2: movl <in6=%ecx,24(<out=%edi)
movl %ecx,24(%edi)

# qhasm: *(uint32 *) (out + 8) = in2
# asm 1: movl <in2=int32#3,8(<out=int32#6)
# asm 2: movl <in2=%edx,8(<out=%edi)
movl %edx,8(%edi)

# qhasm: *(uint32 *) (out + 56) = in14
# asm 1: movl <in14=int32#4,56(<out=int32#6)
# asm 2: movl <in14=%ebx,56(<out=%edi)
movl %ebx,56(%edi)

# qhasm: in15 = diag0
# asm 1: movd   <diag0=int6464#1,>in15=int32#1
# asm 2: movd   <diag0=%xmm0,>in15=%eax
movd   %xmm0,%eax

# qhasm: in11 = diag1
# asm 1: movd   <diag1=int6464#2,>in11=int32#2
# asm 2: movd   <diag1=%xmm1,>in11=%ecx
movd   %xmm1,%ecx

# qhasm: in7 = diag2
# asm 1: movd   <diag2=int6464#3,>in7=int32#3
# asm 2: movd   <diag2=%xmm2,>in7=%edx
movd   %xmm2,%edx

# qhasm: in3 = diag3
# asm 1: movd   <diag3=int6464#4,>in3=int32#4
# asm 2: movd   <diag3=%xmm3,>in3=%ebx
movd   %xmm3,%ebx

# qhasm: in15 ^= *(uint32 *) (m + 60)
# asm 1: xorl 60(<m=int32#5),<in15=int32#1
# asm 2: xorl 60(<m=%esi),<in15=%eax
xorl 60(%esi),%eax

# qhasm: in11 ^= *(uint32 *) (m + 44)
# asm 1: xorl 44(<m=int32#5),<in11=int32#2
# asm 2: xorl 44(<m=%esi),<in11=%ecx
xorl 44(%esi),%ecx

# qhasm: in7 ^= *(uint32 *) (m + 28)
# asm 1: xorl 28(<m=int32#5),<in7=int32#3
# asm 2: xorl 28(<m=%esi),<in7=%edx
xorl 28(%esi),%edx

# qhasm: in3 ^= *(uint32 *) (m + 12)
# asm 1: xorl 12(<m=int32#5),<in3=int32#4
# asm 2: xorl 12(<m=%esi),<in3=%ebx
xorl 12(%esi),%ebx

# qhasm: *(uint32 *) (out + 60) = in15
# asm 1: movl <in15=int32#1,60(<out=int32#6)
# asm 2: movl <in15=%eax,60(<out=%edi)
movl %eax,60(%edi)

# qhasm: *(uint32 *) (out + 44) = in11
# asm 1: movl <in11=int32#2,44(<out=int32#6)
# asm 2: movl <in11=%ecx,44(<out=%edi)
movl %ecx,44(%edi)

# qhasm: *(uint32 *) (out + 28) = in7
# asm 1: movl <in7=int32#3,28(<out=int32#6)
# asm 2: movl <in7=%edx,28(<out=%edi)
movl %edx,28(%edi)

# qhasm: *(uint32 *) (out + 12) = in3
# asm 1: movl <in3=int32#4,12(<out=int32#6)
# asm 2: movl <in3=%ebx,12(<out=%edi)
movl %ebx,12(%edi)

# qhasm:   bytes = bytes_stack
# asm 1: movl <bytes_stack=stack32#7,>bytes=int32#1
# asm 2: movl <bytes_stack=24(%esp),>bytes=%eax
movl 24(%esp),%eax

# qhasm:   in8 = ((uint32 *)&x2)[0]
# asm 1: movl <x2=stack128#4,>in8=int32#2
# asm 2: movl <x2=80(%esp),>in8=%ecx
movl 80(%esp),%ecx

# qhasm:   in9 = ((uint32 *)&x3)[1]
# asm 1: movl 4+<x3=stack128#1,>in9=int32#3
# asm 2: movl 4+<x3=32(%esp),>in9=%edx
movl 4+32(%esp),%edx

# qhasm:   carry? in8 += 1
# asm 1: add  $1,<in8=int32#2
# asm 2: add  $1,<in8=%ecx
add  $1,%ecx

# qhasm:   in9 += 0 + carry
# asm 1: adc $0,<in9=int32#3
# asm 2: adc $0,<in9=%edx
adc $0,%edx

# qhasm:   ((uint32 *)&x2)[0] = in8
# asm 1: movl <in8=int32#2,>x2=stack128#4
# asm 2: movl <in8=%ecx,>x2=80(%esp)
movl %ecx,80(%esp)

# qhasm:   ((uint32 *)&x3)[1] = in9
# asm 1: movl <in9=int32#3,4+<x3=stack128#1
# asm 2: movl <in9=%edx,4+<x3=32(%esp)
movl %edx,4+32(%esp)

# qhasm:                          unsigned>? unsigned<? bytes - 64
# asm 1: cmp  $64,<bytes=int32#1
# asm 2: cmp  $64,<bytes=%eax
cmp  $64,%eax
# comment:fp stack unchanged by jump

# qhasm:   goto bytesatleast65 if unsigned>
ja ._bytesatleast65
# comment:fp stack unchanged by jump

# qhasm:     goto bytesatleast64 if !unsigned<
jae ._bytesatleast64

# qhasm:       m = out
# asm 1: mov  <out=int32#6,>m=int32#5
# asm 2: mov  <out=%edi,>m=%esi
mov  %edi,%esi

# qhasm:       out = ctarget
# asm 1: movl <ctarget=stack32#6,>out=int32#6
# asm 2: movl <ctarget=20(%esp),>out=%edi
movl 20(%esp),%edi

# qhasm:       i = bytes
# asm 1: mov  <bytes=int32#1,>i=int32#2
# asm 2: mov  <bytes=%eax,>i=%ecx
mov  %eax,%ecx

# qhasm:       while (i) { *out++ = *m++; --i }
rep movsb
# comment:fp stack unchanged by fallthrough

# qhasm:     bytesatleast64:
._bytesatleast64:
# comment:fp stack unchanged by fallthrough

# qhasm:     done:
._done:

# qhasm:     eax = eax_stack
# asm 1: movl <eax_stack=stack32#1,>eax=int32#1
# asm 2: movl <eax_stack=0(%esp),>eax=%eax
movl 0(%esp),%eax

# qhasm:     ebx = ebx_stack
# asm 1: movl <ebx_stack=stack32#2,>ebx=int32#4
# asm 2: movl <ebx_stack=4(%esp),>ebx=%ebx
movl 4(%esp),%ebx

# qhasm:     esi = esi_stack
# asm 1: movl <esi_stack=stack32#3,>esi=int32#5
# asm 2: movl <esi_stack=8(%esp),>esi=%esi
movl 8(%esp),%esi

# qhasm:     edi = edi_stack
# asm 1: movl <edi_stack=stack32#4,>edi=int32#6
# asm 2: movl <edi_stack=12(%esp),>edi=%edi
movl 12(%esp),%edi

# qhasm:     ebp = ebp_stack
# asm 1: movl <ebp_stack=stack32#5,>ebp=int32#7
# asm 2: movl <ebp_stack=16(%esp),>ebp=%ebp
movl 16(%esp),%ebp

# qhasm:     leave
add %eax,%esp
xor %eax,%eax
ret

# qhasm:   bytesatleast65:
._bytesatleast65:

# qhasm:   bytes -= 64
# asm 1: sub  $64,<bytes=int32#1
# asm 2: sub  $64,<bytes=%eax
sub  $64,%eax

# qhasm:   out += 64
# asm 1: add  $64,<out=int32#6
# asm 2: add  $64,<out=%edi
add  $64,%edi

# qhasm:   m += 64
# asm 1: add  $64,<m=int32#5
# asm 2: add  $64,<m=%esi
add  $64,%esi
# comment:fp stack unchanged by jump

# qhasm: goto bytesbetween1and255
jmp ._bytesbetween1and255
