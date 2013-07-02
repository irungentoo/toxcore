
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

# qhasm: stack64 r11_stack

# qhasm: stack64 r12_stack

# qhasm: stack64 r13_stack

# qhasm: stack64 r14_stack

# qhasm: stack64 r15_stack

# qhasm: stack64 rbx_stack

# qhasm: stack64 rbp_stack

# qhasm: int64 out

# qhasm: stack64 out_stack

# qhasm: int64 m

# qhasm: int64 l

# qhasm: int64 k

# qhasm: stack64 k_stack

# qhasm: int64 m0

# qhasm: int64 m1

# qhasm: int64 m2

# qhasm: int64 m3

# qhasm: float80 a0

# qhasm: float80 a1

# qhasm: float80 a2

# qhasm: float80 a3

# qhasm: float80 h0

# qhasm: float80 h1

# qhasm: float80 h2

# qhasm: float80 h3

# qhasm: float80 x0

# qhasm: float80 x1

# qhasm: float80 x2

# qhasm: float80 x3

# qhasm: float80 y0

# qhasm: float80 y1

# qhasm: float80 y2

# qhasm: float80 y3

# qhasm: float80 r0x0

# qhasm: float80 r1x0

# qhasm: float80 r2x0

# qhasm: float80 r3x0

# qhasm: float80 r0x1

# qhasm: float80 r1x1

# qhasm: float80 r2x1

# qhasm: float80 sr3x1

# qhasm: float80 r0x2

# qhasm: float80 r1x2

# qhasm: float80 sr2x2

# qhasm: float80 sr3x2

# qhasm: float80 r0x3

# qhasm: float80 sr1x3

# qhasm: float80 sr2x3

# qhasm: float80 sr3x3

# qhasm: stack64 d0

# qhasm: stack64 d1

# qhasm: stack64 d2

# qhasm: stack64 d3

# qhasm: stack64 r0

# qhasm: stack64 r1

# qhasm: stack64 r2

# qhasm: stack64 r3

# qhasm: stack64 sr1

# qhasm: stack64 sr2

# qhasm: stack64 sr3

# qhasm: enter crypto_onetimeauth_poly1305_amd64
.text
.p2align 5
.globl _crypto_onetimeauth_poly1305_amd64
.globl crypto_onetimeauth_poly1305_amd64
_crypto_onetimeauth_poly1305_amd64:
crypto_onetimeauth_poly1305_amd64:
mov %rsp,%r11
and $31,%r11
add $192,%r11
sub %r11,%rsp

# qhasm: input out

# qhasm: input m

# qhasm: input l

# qhasm: input k

# qhasm: r11_stack = r11_caller
# asm 1: movq <r11_caller=int64#9,>r11_stack=stack64#1
# asm 2: movq <r11_caller=%r11,>r11_stack=32(%rsp)
movq %r11,32(%rsp)

# qhasm: r12_stack = r12_caller
# asm 1: movq <r12_caller=int64#10,>r12_stack=stack64#2
# asm 2: movq <r12_caller=%r12,>r12_stack=40(%rsp)
movq %r12,40(%rsp)

# qhasm: r13_stack = r13_caller
# asm 1: movq <r13_caller=int64#11,>r13_stack=stack64#3
# asm 2: movq <r13_caller=%r13,>r13_stack=48(%rsp)
movq %r13,48(%rsp)

# qhasm: r14_stack = r14_caller
# asm 1: movq <r14_caller=int64#12,>r14_stack=stack64#4
# asm 2: movq <r14_caller=%r14,>r14_stack=56(%rsp)
movq %r14,56(%rsp)

# qhasm: r15_stack = r15_caller
# asm 1: movq <r15_caller=int64#13,>r15_stack=stack64#5
# asm 2: movq <r15_caller=%r15,>r15_stack=64(%rsp)
movq %r15,64(%rsp)

# qhasm: rbx_stack = rbx_caller
# asm 1: movq <rbx_caller=int64#14,>rbx_stack=stack64#6
# asm 2: movq <rbx_caller=%rbx,>rbx_stack=72(%rsp)
movq %rbx,72(%rsp)

# qhasm: rbp_stack = rbp_caller
# asm 1: movq <rbp_caller=int64#15,>rbp_stack=stack64#7
# asm 2: movq <rbp_caller=%rbp,>rbp_stack=80(%rsp)
movq %rbp,80(%rsp)

# qhasm:   round *(uint16 *) &crypto_onetimeauth_poly1305_amd64_rounding
fldcw crypto_onetimeauth_poly1305_amd64_rounding(%rip)

# qhasm:   m0 = *(uint32 *) (k + 0)
# asm 1: movl   0(<k=int64#4),>m0=int64#5d
# asm 2: movl   0(<k=%rcx),>m0=%r8d
movl   0(%rcx),%r8d

# qhasm:   m1 = *(uint32 *) (k + 4)
# asm 1: movl   4(<k=int64#4),>m1=int64#6d
# asm 2: movl   4(<k=%rcx),>m1=%r9d
movl   4(%rcx),%r9d

# qhasm:   m2 = *(uint32 *) (k + 8)
# asm 1: movl   8(<k=int64#4),>m2=int64#7d
# asm 2: movl   8(<k=%rcx),>m2=%eax
movl   8(%rcx),%eax

# qhasm:   m3 = *(uint32 *) (k + 12)
# asm 1: movl   12(<k=int64#4),>m3=int64#8d
# asm 2: movl   12(<k=%rcx),>m3=%r10d
movl   12(%rcx),%r10d

# qhasm:   out_stack = out
# asm 1: movq <out=int64#1,>out_stack=stack64#8
# asm 2: movq <out=%rdi,>out_stack=88(%rsp)
movq %rdi,88(%rsp)

# qhasm:   k_stack = k
# asm 1: movq <k=int64#4,>k_stack=stack64#9
# asm 2: movq <k=%rcx,>k_stack=96(%rsp)
movq %rcx,96(%rsp)

# qhasm:   d0 top = 0x43300000
# asm 1: movl  $0x43300000,>d0=stack64#10
# asm 2: movl  $0x43300000,>d0=108(%rsp)
movl  $0x43300000,108(%rsp)

# qhasm:   d1 top = 0x45300000
# asm 1: movl  $0x45300000,>d1=stack64#11
# asm 2: movl  $0x45300000,>d1=116(%rsp)
movl  $0x45300000,116(%rsp)

# qhasm:   d2 top = 0x47300000
# asm 1: movl  $0x47300000,>d2=stack64#12
# asm 2: movl  $0x47300000,>d2=124(%rsp)
movl  $0x47300000,124(%rsp)

# qhasm:   d3 top = 0x49300000
# asm 1: movl  $0x49300000,>d3=stack64#13
# asm 2: movl  $0x49300000,>d3=132(%rsp)
movl  $0x49300000,132(%rsp)

# qhasm:   (uint32) m0 &= 0x0fffffff
# asm 1: and  $0x0fffffff,<m0=int64#5d
# asm 2: and  $0x0fffffff,<m0=%r8d
and  $0x0fffffff,%r8d

# qhasm:   (uint32) m1 &= 0x0ffffffc
# asm 1: and  $0x0ffffffc,<m1=int64#6d
# asm 2: and  $0x0ffffffc,<m1=%r9d
and  $0x0ffffffc,%r9d

# qhasm:   (uint32) m2 &= 0x0ffffffc
# asm 1: and  $0x0ffffffc,<m2=int64#7d
# asm 2: and  $0x0ffffffc,<m2=%eax
and  $0x0ffffffc,%eax

# qhasm:   (uint32) m3 &= 0x0ffffffc
# asm 1: and  $0x0ffffffc,<m3=int64#8d
# asm 2: and  $0x0ffffffc,<m3=%r10d
and  $0x0ffffffc,%r10d

# qhasm:   inplace d0 bottom = m0
# asm 1: movl <m0=int64#5d,<d0=stack64#10
# asm 2: movl <m0=%r8d,<d0=104(%rsp)
movl %r8d,104(%rsp)

# qhasm:   inplace d1 bottom = m1
# asm 1: movl <m1=int64#6d,<d1=stack64#11
# asm 2: movl <m1=%r9d,<d1=112(%rsp)
movl %r9d,112(%rsp)

# qhasm:   inplace d2 bottom = m2
# asm 1: movl <m2=int64#7d,<d2=stack64#12
# asm 2: movl <m2=%eax,<d2=120(%rsp)
movl %eax,120(%rsp)

# qhasm:   inplace d3 bottom = m3
# asm 1: movl <m3=int64#8d,<d3=stack64#13
# asm 2: movl <m3=%r10d,<d3=128(%rsp)
movl %r10d,128(%rsp)

# qhasm:   a0 = *(float64 *) &d0
# asm 1: fldl <d0=stack64#10
# asm 2: fldl <d0=104(%rsp)
fldl 104(%rsp)
# comment:fpstackfrombottom:<a0#28:

# qhasm:   a0 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset0
fsubl crypto_onetimeauth_poly1305_amd64_doffset0(%rip)
# comment:fpstackfrombottom:<a0#28:

# qhasm:   a1 = *(float64 *) &d1
# asm 1: fldl <d1=stack64#11
# asm 2: fldl <d1=112(%rsp)
fldl 112(%rsp)
# comment:fpstackfrombottom:<a0#28:<a1#29:

# qhasm:   a1 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset1
fsubl crypto_onetimeauth_poly1305_amd64_doffset1(%rip)
# comment:fpstackfrombottom:<a0#28:<a1#29:

# qhasm:   a2 = *(float64 *) &d2
# asm 1: fldl <d2=stack64#12
# asm 2: fldl <d2=120(%rsp)
fldl 120(%rsp)
# comment:fpstackfrombottom:<a0#28:<a1#29:<a2#30:

# qhasm:   a2 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset2
fsubl crypto_onetimeauth_poly1305_amd64_doffset2(%rip)
# comment:fpstackfrombottom:<a0#28:<a1#29:<a2#30:

# qhasm:   a3 = *(float64 *) &d3
# asm 1: fldl <d3=stack64#13
# asm 2: fldl <d3=128(%rsp)
fldl 128(%rsp)
# comment:fpstackfrombottom:<a0#28:<a1#29:<a2#30:<a3#31:

# qhasm:   a3 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset3
fsubl crypto_onetimeauth_poly1305_amd64_doffset3(%rip)
# comment:fpstackfrombottom:<a0#28:<a1#29:<a2#30:<a3#31:

# qhasm: internal stacktop a0
# asm 1: fxch <a0=float80#4
# asm 2: fxch <a0=%st(3)
fxch %st(3)

# qhasm:   *(float64 *) &r0 = a0
# asm 1: fstpl >r0=stack64#14
# asm 2: fstpl >r0=136(%rsp)
fstpl 136(%rsp)
# comment:fpstackfrombottom:<a3#31:<a1#29:<a2#30:

# qhasm: internal stacktop a1
# asm 1: fxch <a1=float80#2
# asm 2: fxch <a1=%st(1)
fxch %st(1)

# qhasm:   *(float64 *) &r1 = a1
# asm 1: fstl >r1=stack64#15
# asm 2: fstl >r1=144(%rsp)
fstl 144(%rsp)
# comment:fpstackfrombottom:<a3#31:<a2#30:<a1#29:

# qhasm:   a1 *= *(float64 *) &crypto_onetimeauth_poly1305_amd64_scale
fmull crypto_onetimeauth_poly1305_amd64_scale(%rip)
# comment:fpstackfrombottom:<a3#31:<a2#30:<a1#29:

# qhasm:   *(float64 *) &sr1 = a1
# asm 1: fstpl >sr1=stack64#16
# asm 2: fstpl >sr1=152(%rsp)
fstpl 152(%rsp)
# comment:fpstackfrombottom:<a3#31:<a2#30:

# qhasm:   *(float64 *) &r2 = a2
# asm 1: fstl >r2=stack64#17
# asm 2: fstl >r2=160(%rsp)
fstl 160(%rsp)
# comment:fpstackfrombottom:<a3#31:<a2#30:

# qhasm:   a2 *= *(float64 *) &crypto_onetimeauth_poly1305_amd64_scale
fmull crypto_onetimeauth_poly1305_amd64_scale(%rip)
# comment:fpstackfrombottom:<a3#31:<a2#30:

# qhasm:   *(float64 *) &sr2 = a2
# asm 1: fstpl >sr2=stack64#18
# asm 2: fstpl >sr2=168(%rsp)
fstpl 168(%rsp)
# comment:fpstackfrombottom:<a3#31:

# qhasm:   *(float64 *) &r3 = a3
# asm 1: fstl >r3=stack64#19
# asm 2: fstl >r3=176(%rsp)
fstl 176(%rsp)
# comment:fpstackfrombottom:<a3#31:

# qhasm:   a3 *= *(float64 *) &crypto_onetimeauth_poly1305_amd64_scale
fmull crypto_onetimeauth_poly1305_amd64_scale(%rip)
# comment:fpstackfrombottom:<a3#31:

# qhasm:   *(float64 *) &sr3 = a3
# asm 1: fstpl >sr3=stack64#20
# asm 2: fstpl >sr3=184(%rsp)
fstpl 184(%rsp)
# comment:fpstackfrombottom:

# qhasm:   h3 = 0
fldz
# comment:fpstackfrombottom:<h3#39:

# qhasm:   h2 = 0
fldz
# comment:fpstackfrombottom:<h3#39:<h2#40:

# qhasm:   h1 = 0
fldz
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:

# qhasm:   h0 = 0
fldz
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:                          unsigned<? l - 16
# asm 1: cmp  $16,<l=int64#3
# asm 2: cmp  $16,<l=%rdx
cmp  $16,%rdx
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:
# comment:fp stack unchanged by jump
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm: goto addatmost15bytes if unsigned<
jb ._addatmost15bytes
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm: initialatleast16bytes:
._initialatleast16bytes:
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   m3 = *(uint32 *) (m + 12)
# asm 1: movl   12(<m=int64#2),>m3=int64#1d
# asm 2: movl   12(<m=%rsi),>m3=%edi
movl   12(%rsi),%edi
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   m2 = *(uint32 *) (m + 8)
# asm 1: movl   8(<m=int64#2),>m2=int64#4d
# asm 2: movl   8(<m=%rsi),>m2=%ecx
movl   8(%rsi),%ecx
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   m1 = *(uint32 *) (m + 4)
# asm 1: movl   4(<m=int64#2),>m1=int64#5d
# asm 2: movl   4(<m=%rsi),>m1=%r8d
movl   4(%rsi),%r8d
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   m0 = *(uint32 *) (m + 0)
# asm 1: movl   0(<m=int64#2),>m0=int64#6d
# asm 2: movl   0(<m=%rsi),>m0=%r9d
movl   0(%rsi),%r9d
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   inplace d3 bottom = m3
# asm 1: movl <m3=int64#1d,<d3=stack64#13
# asm 2: movl <m3=%edi,<d3=128(%rsp)
movl %edi,128(%rsp)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   inplace d2 bottom = m2
# asm 1: movl <m2=int64#4d,<d2=stack64#12
# asm 2: movl <m2=%ecx,<d2=120(%rsp)
movl %ecx,120(%rsp)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   inplace d1 bottom = m1
# asm 1: movl <m1=int64#5d,<d1=stack64#11
# asm 2: movl <m1=%r8d,<d1=112(%rsp)
movl %r8d,112(%rsp)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   inplace d0 bottom = m0
# asm 1: movl <m0=int64#6d,<d0=stack64#10
# asm 2: movl <m0=%r9d,<d0=104(%rsp)
movl %r9d,104(%rsp)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   m += 16
# asm 1: add  $16,<m=int64#2
# asm 2: add  $16,<m=%rsi
add  $16,%rsi
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   l -= 16
# asm 1: sub  $16,<l=int64#3
# asm 2: sub  $16,<l=%rdx
sub  $16,%rdx
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm: internal stacktop h3
# asm 1: fxch <h3=float80#4
# asm 2: fxch <h3=%st(3)
fxch %st(3)

# qhasm:   h3 += *(float64 *) &d3
# asm 1: faddl <d3=stack64#13
# asm 2: faddl <d3=128(%rsp)
faddl 128(%rsp)
# comment:fpstackfrombottom:<h0#42:<h2#40:<h1#41:<h3#39:

# qhasm:   h3 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset3minustwo128
fsubl crypto_onetimeauth_poly1305_amd64_doffset3minustwo128(%rip)
# comment:fpstackfrombottom:<h0#42:<h2#40:<h1#41:<h3#39:

# qhasm: internal stacktop h1
# asm 1: fxch <h1=float80#2
# asm 2: fxch <h1=%st(1)
fxch %st(1)

# qhasm:   h1 += *(float64 *) &d1
# asm 1: faddl <d1=stack64#11
# asm 2: faddl <d1=112(%rsp)
faddl 112(%rsp)
# comment:fpstackfrombottom:<h0#42:<h2#40:<h3#39:<h1#41:

# qhasm:   h1 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset1
fsubl crypto_onetimeauth_poly1305_amd64_doffset1(%rip)
# comment:fpstackfrombottom:<h0#42:<h2#40:<h3#39:<h1#41:

# qhasm: internal stacktop h2
# asm 1: fxch <h2=float80#3
# asm 2: fxch <h2=%st(2)
fxch %st(2)

# qhasm:   h2 += *(float64 *) &d2
# asm 1: faddl <d2=stack64#12
# asm 2: faddl <d2=120(%rsp)
faddl 120(%rsp)
# comment:fpstackfrombottom:<h0#42:<h1#41:<h3#39:<h2#40:

# qhasm:   h2 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset2
fsubl crypto_onetimeauth_poly1305_amd64_doffset2(%rip)
# comment:fpstackfrombottom:<h0#42:<h1#41:<h3#39:<h2#40:

# qhasm: internal stacktop h0
# asm 1: fxch <h0=float80#4
# asm 2: fxch <h0=%st(3)
fxch %st(3)

# qhasm:   h0 += *(float64 *) &d0
# asm 1: faddl <d0=stack64#10
# asm 2: faddl <d0=104(%rsp)
faddl 104(%rsp)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:   h0 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset0
fsubl crypto_onetimeauth_poly1305_amd64_doffset0(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:                                  unsigned<? l - 16
# asm 1: cmp  $16,<l=int64#3
# asm 2: cmp  $16,<l=%rdx
cmp  $16,%rdx
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:
# comment:fp stack unchanged by jump
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm: goto multiplyaddatmost15bytes if unsigned<
jb ._multiplyaddatmost15bytes
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm: multiplyaddatleast16bytes:
._multiplyaddatleast16bytes:
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:   m3 = *(uint32 *) (m + 12)
# asm 1: movl   12(<m=int64#2),>m3=int64#1d
# asm 2: movl   12(<m=%rsi),>m3=%edi
movl   12(%rsi),%edi
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:   m2 = *(uint32 *) (m + 8)
# asm 1: movl   8(<m=int64#2),>m2=int64#4d
# asm 2: movl   8(<m=%rsi),>m2=%ecx
movl   8(%rsi),%ecx
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:   m1 = *(uint32 *) (m + 4)
# asm 1: movl   4(<m=int64#2),>m1=int64#5d
# asm 2: movl   4(<m=%rsi),>m1=%r8d
movl   4(%rsi),%r8d
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:   m0 = *(uint32 *) (m + 0)
# asm 1: movl   0(<m=int64#2),>m0=int64#6d
# asm 2: movl   0(<m=%rsi),>m0=%r9d
movl   0(%rsi),%r9d
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:   inplace d3 bottom = m3
# asm 1: movl <m3=int64#1d,<d3=stack64#13
# asm 2: movl <m3=%edi,<d3=128(%rsp)
movl %edi,128(%rsp)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:   inplace d2 bottom = m2
# asm 1: movl <m2=int64#4d,<d2=stack64#12
# asm 2: movl <m2=%ecx,<d2=120(%rsp)
movl %ecx,120(%rsp)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:   inplace d1 bottom = m1
# asm 1: movl <m1=int64#5d,<d1=stack64#11
# asm 2: movl <m1=%r8d,<d1=112(%rsp)
movl %r8d,112(%rsp)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:   inplace d0 bottom = m0
# asm 1: movl <m0=int64#6d,<d0=stack64#10
# asm 2: movl <m0=%r9d,<d0=104(%rsp)
movl %r9d,104(%rsp)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:   m += 16
# asm 1: add  $16,<m=int64#2
# asm 2: add  $16,<m=%rsi
add  $16,%rsi
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:   l -= 16
# asm 1: sub  $16,<l=int64#3
# asm 2: sub  $16,<l=%rdx
sub  $16,%rdx
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:   x0 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha130
fldl crypto_onetimeauth_poly1305_amd64_alpha130(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#53:

# qhasm:   x0 += h3
# asm 1: fadd <h3=float80#3,<x0=float80#1
# asm 2: fadd <h3=%st(2),<x0=%st(0)
fadd %st(2),%st(0)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#53:

# qhasm:   x0 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha130
fsubl crypto_onetimeauth_poly1305_amd64_alpha130(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#53:

# qhasm:   h3 -= x0
# asm 1: fsubr <x0=float80#1,<h3=float80#3
# asm 2: fsubr <x0=%st(0),<h3=%st(2)
fsubr %st(0),%st(2)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#53:

# qhasm:   x0 *= *(float64 *) &crypto_onetimeauth_poly1305_amd64_scale
fmull crypto_onetimeauth_poly1305_amd64_scale(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#53:

# qhasm:   x1 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha32
fldl crypto_onetimeauth_poly1305_amd64_alpha32(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#53:<x1#54:

# qhasm:   x1 += h0
# asm 1: fadd <h0=float80#3,<x1=float80#1
# asm 2: fadd <h0=%st(2),<x1=%st(0)
fadd %st(2),%st(0)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#53:<x1#54:

# qhasm:   x1 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha32
fsubl crypto_onetimeauth_poly1305_amd64_alpha32(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#53:<x1#54:

# qhasm:   h0 -= x1
# asm 1: fsubr <x1=float80#1,<h0=float80#3
# asm 2: fsubr <x1=%st(0),<h0=%st(2)
fsubr %st(0),%st(2)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#53:<x1#54:

# qhasm: internal stacktop h0
# asm 1: fxch <h0=float80#3
# asm 2: fxch <h0=%st(2)
fxch %st(2)

# qhasm:   x0 += h0
# asm 1: faddp <h0=float80#1,<x0=float80#2
# asm 2: faddp <h0=%st(0),<x0=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<x1#54:<x0#53:

# qhasm:   x2 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha64
fldl crypto_onetimeauth_poly1305_amd64_alpha64(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<x1#54:<x0#53:<x2#55:

# qhasm:   x2 += h1
# asm 1: fadd <h1=float80#5,<x2=float80#1
# asm 2: fadd <h1=%st(4),<x2=%st(0)
fadd %st(4),%st(0)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<x1#54:<x0#53:<x2#55:

# qhasm:   x2 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha64
fsubl crypto_onetimeauth_poly1305_amd64_alpha64(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<x1#54:<x0#53:<x2#55:

# qhasm:   h1 -= x2
# asm 1: fsubr <x2=float80#1,<h1=float80#5
# asm 2: fsubr <x2=%st(0),<h1=%st(4)
fsubr %st(0),%st(4)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<x1#54:<x0#53:<x2#55:

# qhasm:   x3 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha96
fldl crypto_onetimeauth_poly1305_amd64_alpha96(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<x1#54:<x0#53:<x2#55:<x3#56:

# qhasm:   x3 += h2
# asm 1: fadd <h2=float80#7,<x3=float80#1
# asm 2: fadd <h2=%st(6),<x3=%st(0)
fadd %st(6),%st(0)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<x1#54:<x0#53:<x2#55:<x3#56:

# qhasm:   x3 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha96
fsubl crypto_onetimeauth_poly1305_amd64_alpha96(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<x1#54:<x0#53:<x2#55:<x3#56:

# qhasm:   h2 -= x3
# asm 1: fsubr <x3=float80#1,<h2=float80#7
# asm 2: fsubr <x3=%st(0),<h2=%st(6)
fsubr %st(0),%st(6)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<x1#54:<x0#53:<x2#55:<x3#56:

# qhasm: internal stacktop h2
# asm 1: fxch <h2=float80#7
# asm 2: fxch <h2=%st(6)
fxch %st(6)

# qhasm:   x2 += h2
# asm 1: faddp <h2=float80#1,<x2=float80#2
# asm 2: faddp <h2=%st(0),<x2=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#56:<h1#41:<h3#39:<x1#54:<x0#53:<x2#55:

# qhasm: internal stacktop h3
# asm 1: fxch <h3=float80#4
# asm 2: fxch <h3=%st(3)
fxch %st(3)

# qhasm:   x3 += h3
# asm 1: faddp <h3=float80#1,<x3=float80#6
# asm 2: faddp <h3=%st(0),<x3=%st(5)
faddp %st(0),%st(5)
# comment:fpstackfrombottom:<x3#56:<h1#41:<x2#55:<x1#54:<x0#53:

# qhasm: internal stacktop h1
# asm 1: fxch <h1=float80#4
# asm 2: fxch <h1=%st(3)
fxch %st(3)

# qhasm:   x1 += h1
# asm 1: faddp <h1=float80#1,<x1=float80#2
# asm 2: faddp <h1=%st(0),<x1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#56:<x0#53:<x2#55:<x1#54:

# qhasm:   h3 = *(float64 *) &r3
# asm 1: fldl <r3=stack64#19
# asm 2: fldl <r3=176(%rsp)
fldl 176(%rsp)
# comment:fpstackfrombottom:<x3#56:<x0#53:<x2#55:<x1#54:<h3#39:

# qhasm:   h3 *= x0
# asm 1: fmul <x0=float80#4,<h3=float80#1
# asm 2: fmul <x0=%st(3),<h3=%st(0)
fmul %st(3),%st(0)
# comment:fpstackfrombottom:<x3#56:<x0#53:<x2#55:<x1#54:<h3#39:

# qhasm:   h2 = *(float64 *) &r2
# asm 1: fldl <r2=stack64#17
# asm 2: fldl <r2=160(%rsp)
fldl 160(%rsp)
# comment:fpstackfrombottom:<x3#56:<x0#53:<x2#55:<x1#54:<h3#39:<h2#40:

# qhasm:   h2 *= x0
# asm 1: fmul <x0=float80#5,<h2=float80#1
# asm 2: fmul <x0=%st(4),<h2=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x3#56:<x0#53:<x2#55:<x1#54:<h3#39:<h2#40:

# qhasm:   h1 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#15
# asm 2: fldl <r1=144(%rsp)
fldl 144(%rsp)
# comment:fpstackfrombottom:<x3#56:<x0#53:<x2#55:<x1#54:<h3#39:<h2#40:<h1#41:

# qhasm:   h1 *= x0
# asm 1: fmul <x0=float80#6,<h1=float80#1
# asm 2: fmul <x0=%st(5),<h1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#56:<x0#53:<x2#55:<x1#54:<h3#39:<h2#40:<h1#41:

# qhasm:   h0 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#14
# asm 2: fldl <r0=136(%rsp)
fldl 136(%rsp)
# comment:fpstackfrombottom:<x3#56:<x0#53:<x2#55:<x1#54:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   h0 *= x0
# asm 1: fmulp <x0=float80#1,<h0=float80#7
# asm 2: fmulp <x0=%st(0),<h0=%st(6)
fmulp %st(0),%st(6)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<x1#54:<h3#39:<h2#40:<h1#41:

# qhasm:   r2x1 = *(float64 *) &r2
# asm 1: fldl <r2=stack64#17
# asm 2: fldl <r2=160(%rsp)
fldl 160(%rsp)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<x1#54:<h3#39:<h2#40:<h1#41:<r2x1#57:

# qhasm:   r2x1 *= x1
# asm 1: fmul <x1=float80#5,<r2x1=float80#1
# asm 2: fmul <x1=%st(4),<r2x1=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<x1#54:<h3#39:<h2#40:<h1#41:<r2x1#57:

# qhasm:   h3 += r2x1
# asm 1: faddp <r2x1=float80#1,<h3=float80#4
# asm 2: faddp <r2x1=%st(0),<h3=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<x1#54:<h3#39:<h2#40:<h1#41:

# qhasm:   r1x1 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#15
# asm 2: fldl <r1=144(%rsp)
fldl 144(%rsp)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<x1#54:<h3#39:<h2#40:<h1#41:<r1x1#58:

# qhasm:   r1x1 *= x1
# asm 1: fmul <x1=float80#5,<r1x1=float80#1
# asm 2: fmul <x1=%st(4),<r1x1=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<x1#54:<h3#39:<h2#40:<h1#41:<r1x1#58:

# qhasm:   h2 += r1x1
# asm 1: faddp <r1x1=float80#1,<h2=float80#3
# asm 2: faddp <r1x1=%st(0),<h2=%st(2)
faddp %st(0),%st(2)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<x1#54:<h3#39:<h2#40:<h1#41:

# qhasm:   r0x1 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#14
# asm 2: fldl <r0=136(%rsp)
fldl 136(%rsp)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<x1#54:<h3#39:<h2#40:<h1#41:<r0x1#59:

# qhasm:   r0x1 *= x1
# asm 1: fmul <x1=float80#5,<r0x1=float80#1
# asm 2: fmul <x1=%st(4),<r0x1=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<x1#54:<h3#39:<h2#40:<h1#41:<r0x1#59:

# qhasm:   h1 += r0x1
# asm 1: faddp <r0x1=float80#1,<h1=float80#2
# asm 2: faddp <r0x1=%st(0),<h1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<x1#54:<h3#39:<h2#40:<h1#41:

# qhasm:   sr3x1 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#20
# asm 2: fldl <sr3=184(%rsp)
fldl 184(%rsp)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<x1#54:<h3#39:<h2#40:<h1#41:<sr3x1#60:

# qhasm:   sr3x1 *= x1
# asm 1: fmulp <x1=float80#1,<sr3x1=float80#5
# asm 2: fmulp <x1=%st(0),<sr3x1=%st(4)
fmulp %st(0),%st(4)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<sr3x1#60:<h3#39:<h2#40:<h1#41:

# qhasm: internal stacktop sr3x1
# asm 1: fxch <sr3x1=float80#4
# asm 2: fxch <sr3x1=%st(3)
fxch %st(3)

# qhasm:   h0 += sr3x1
# asm 1: faddp <sr3x1=float80#1,<h0=float80#6
# asm 2: faddp <sr3x1=%st(0),<h0=%st(5)
faddp %st(0),%st(5)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<h1#41:<h3#39:<h2#40:

# qhasm:   r1x2 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#15
# asm 2: fldl <r1=144(%rsp)
fldl 144(%rsp)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<h1#41:<h3#39:<h2#40:<r1x2#61:

# qhasm:   r1x2 *= x2
# asm 1: fmul <x2=float80#5,<r1x2=float80#1
# asm 2: fmul <x2=%st(4),<r1x2=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<h1#41:<h3#39:<h2#40:<r1x2#61:

# qhasm:   h3 += r1x2
# asm 1: faddp <r1x2=float80#1,<h3=float80#3
# asm 2: faddp <r1x2=%st(0),<h3=%st(2)
faddp %st(0),%st(2)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<h1#41:<h3#39:<h2#40:

# qhasm:   r0x2 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#14
# asm 2: fldl <r0=136(%rsp)
fldl 136(%rsp)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<h1#41:<h3#39:<h2#40:<r0x2#62:

# qhasm:   r0x2 *= x2
# asm 1: fmul <x2=float80#5,<r0x2=float80#1
# asm 2: fmul <x2=%st(4),<r0x2=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<h1#41:<h3#39:<h2#40:<r0x2#62:

# qhasm:   h2 += r0x2
# asm 1: faddp <r0x2=float80#1,<h2=float80#2
# asm 2: faddp <r0x2=%st(0),<h2=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<h1#41:<h3#39:<h2#40:

# qhasm:   sr3x2 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#20
# asm 2: fldl <sr3=184(%rsp)
fldl 184(%rsp)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<h1#41:<h3#39:<h2#40:<sr3x2#63:

# qhasm:   sr3x2 *= x2
# asm 1: fmul <x2=float80#5,<sr3x2=float80#1
# asm 2: fmul <x2=%st(4),<sr3x2=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<h1#41:<h3#39:<h2#40:<sr3x2#63:

# qhasm:   h1 += sr3x2
# asm 1: faddp <sr3x2=float80#1,<h1=float80#4
# asm 2: faddp <sr3x2=%st(0),<h1=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<h1#41:<h3#39:<h2#40:

# qhasm:   sr2x2 = *(float64 *) &sr2
# asm 1: fldl <sr2=stack64#18
# asm 2: fldl <sr2=168(%rsp)
fldl 168(%rsp)
# comment:fpstackfrombottom:<x3#56:<h0#42:<x2#55:<h1#41:<h3#39:<h2#40:<sr2x2#64:

# qhasm:   sr2x2 *= x2
# asm 1: fmulp <x2=float80#1,<sr2x2=float80#5
# asm 2: fmulp <x2=%st(0),<sr2x2=%st(4)
fmulp %st(0),%st(4)
# comment:fpstackfrombottom:<x3#56:<h0#42:<sr2x2#64:<h1#41:<h3#39:<h2#40:

# qhasm: internal stacktop sr2x2
# asm 1: fxch <sr2x2=float80#4
# asm 2: fxch <sr2x2=%st(3)
fxch %st(3)

# qhasm:   h0 += sr2x2
# asm 1: faddp <sr2x2=float80#1,<h0=float80#5
# asm 2: faddp <sr2x2=%st(0),<h0=%st(4)
faddp %st(0),%st(4)
# comment:fpstackfrombottom:<x3#56:<h0#42:<h2#40:<h1#41:<h3#39:

# qhasm:   r0x3 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#14
# asm 2: fldl <r0=136(%rsp)
fldl 136(%rsp)
# comment:fpstackfrombottom:<x3#56:<h0#42:<h2#40:<h1#41:<h3#39:<r0x3#65:

# qhasm:   r0x3 *= x3
# asm 1: fmul <x3=float80#6,<r0x3=float80#1
# asm 2: fmul <x3=%st(5),<r0x3=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#56:<h0#42:<h2#40:<h1#41:<h3#39:<r0x3#65:

# qhasm:   h3 += r0x3
# asm 1: faddp <r0x3=float80#1,<h3=float80#2
# asm 2: faddp <r0x3=%st(0),<h3=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#56:<h0#42:<h2#40:<h1#41:<h3#39:

# qhasm:   stacktop h0
# asm 1: fxch <h0=float80#4
# asm 2: fxch <h0=%st(3)
fxch %st(3)
# comment:fpstackfrombottom:<x3#56:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   sr3x3 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#20
# asm 2: fldl <sr3=184(%rsp)
fldl 184(%rsp)
# comment:fpstackfrombottom:<x3#56:<h3#39:<h2#40:<h1#41:<h0#42:<sr3x3#66:

# qhasm:   sr3x3 *= x3
# asm 1: fmul <x3=float80#6,<sr3x3=float80#1
# asm 2: fmul <x3=%st(5),<sr3x3=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#56:<h3#39:<h2#40:<h1#41:<h0#42:<sr3x3#66:

# qhasm:   h2 += sr3x3
# asm 1: faddp <sr3x3=float80#1,<h2=float80#4
# asm 2: faddp <sr3x3=%st(0),<h2=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x3#56:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   stacktop h1
# asm 1: fxch <h1=float80#2
# asm 2: fxch <h1=%st(1)
fxch %st(1)
# comment:fpstackfrombottom:<x3#56:<h3#39:<h2#40:<h0#42:<h1#41:

# qhasm:   sr2x3 = *(float64 *) &sr2
# asm 1: fldl <sr2=stack64#18
# asm 2: fldl <sr2=168(%rsp)
fldl 168(%rsp)
# comment:fpstackfrombottom:<x3#56:<h3#39:<h2#40:<h0#42:<h1#41:<sr2x3#67:

# qhasm:   sr2x3 *= x3
# asm 1: fmul <x3=float80#6,<sr2x3=float80#1
# asm 2: fmul <x3=%st(5),<sr2x3=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#56:<h3#39:<h2#40:<h0#42:<h1#41:<sr2x3#67:

# qhasm:   h1 += sr2x3
# asm 1: faddp <sr2x3=float80#1,<h1=float80#2
# asm 2: faddp <sr2x3=%st(0),<h1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#56:<h3#39:<h2#40:<h0#42:<h1#41:

# qhasm:   sr1x3 = *(float64 *) &sr1
# asm 1: fldl <sr1=stack64#16
# asm 2: fldl <sr1=152(%rsp)
fldl 152(%rsp)
# comment:fpstackfrombottom:<x3#56:<h3#39:<h2#40:<h0#42:<h1#41:<sr1x3#68:

# qhasm:   sr1x3 *= x3
# asm 1: fmulp <x3=float80#1,<sr1x3=float80#6
# asm 2: fmulp <x3=%st(0),<sr1x3=%st(5)
fmulp %st(0),%st(5)
# comment:fpstackfrombottom:<sr1x3#68:<h3#39:<h2#40:<h0#42:<h1#41:

# qhasm: internal stacktop sr1x3
# asm 1: fxch <sr1x3=float80#5
# asm 2: fxch <sr1x3=%st(4)
fxch %st(4)

# qhasm:   h0 += sr1x3
# asm 1: faddp <sr1x3=float80#1,<h0=float80#2
# asm 2: faddp <sr1x3=%st(0),<h0=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:

# qhasm:                                    unsigned<? l - 16
# asm 1: cmp  $16,<l=int64#3
# asm 2: cmp  $16,<l=%rdx
cmp  $16,%rdx
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:

# qhasm:   stacktop h3
# asm 1: fxch <h3=float80#3
# asm 2: fxch <h3=%st(2)
fxch %st(2)
# comment:fpstackfrombottom:<h1#41:<h0#42:<h2#40:<h3#39:

# qhasm:   y3 = *(float64 *) &d3
# asm 1: fldl <d3=stack64#13
# asm 2: fldl <d3=128(%rsp)
fldl 128(%rsp)
# comment:fpstackfrombottom:<h1#41:<h0#42:<h2#40:<h3#39:<y3#70:

# qhasm:   y3 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset3minustwo128
fsubl crypto_onetimeauth_poly1305_amd64_doffset3minustwo128(%rip)
# comment:fpstackfrombottom:<h1#41:<h0#42:<h2#40:<h3#39:<y3#70:

# qhasm:   h3 += y3
# asm 1: faddp <y3=float80#1,<h3=float80#2
# asm 2: faddp <y3=%st(0),<h3=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h1#41:<h0#42:<h2#40:<h3#39:

# qhasm:   stacktop h2
# asm 1: fxch <h2=float80#2
# asm 2: fxch <h2=%st(1)
fxch %st(1)
# comment:fpstackfrombottom:<h1#41:<h0#42:<h3#39:<h2#40:

# qhasm:   y2 = *(float64 *) &d2
# asm 1: fldl <d2=stack64#12
# asm 2: fldl <d2=120(%rsp)
fldl 120(%rsp)
# comment:fpstackfrombottom:<h1#41:<h0#42:<h3#39:<h2#40:<y2#71:

# qhasm:   y2 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset2
fsubl crypto_onetimeauth_poly1305_amd64_doffset2(%rip)
# comment:fpstackfrombottom:<h1#41:<h0#42:<h3#39:<h2#40:<y2#71:

# qhasm:   h2 += y2
# asm 1: faddp <y2=float80#1,<h2=float80#2
# asm 2: faddp <y2=%st(0),<h2=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h1#41:<h0#42:<h3#39:<h2#40:

# qhasm:   stacktop h1
# asm 1: fxch <h1=float80#4
# asm 2: fxch <h1=%st(3)
fxch %st(3)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h3#39:<h1#41:

# qhasm:   y1 = *(float64 *) &d1
# asm 1: fldl <d1=stack64#11
# asm 2: fldl <d1=112(%rsp)
fldl 112(%rsp)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h3#39:<h1#41:<y1#72:

# qhasm:   y1 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset1
fsubl crypto_onetimeauth_poly1305_amd64_doffset1(%rip)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h3#39:<h1#41:<y1#72:

# qhasm:   h1 += y1
# asm 1: faddp <y1=float80#1,<h1=float80#2
# asm 2: faddp <y1=%st(0),<h1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h3#39:<h1#41:

# qhasm:   stacktop h0
# asm 1: fxch <h0=float80#3
# asm 2: fxch <h0=%st(2)
fxch %st(2)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:   y0 = *(float64 *) &d0
# asm 1: fldl <d0=stack64#10
# asm 2: fldl <d0=104(%rsp)
fldl 104(%rsp)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<y0#73:

# qhasm:   y0 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset0
fsubl crypto_onetimeauth_poly1305_amd64_doffset0(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<y0#73:

# qhasm:   h0 += y0
# asm 1: faddp <y0=float80#1,<h0=float80#2
# asm 2: faddp <y0=%st(0),<h0=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:
# comment:fp stack unchanged by jump
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm: goto multiplyaddatleast16bytes if !unsigned<
jae ._multiplyaddatleast16bytes
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:
# comment:fp stack unchanged by fallthrough
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm: multiplyaddatmost15bytes:
._multiplyaddatmost15bytes:
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:

# qhasm:   x0 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha130
fldl crypto_onetimeauth_poly1305_amd64_alpha130(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:

# qhasm:   x0 += h3
# asm 1: fadd <h3=float80#3,<x0=float80#1
# asm 2: fadd <h3=%st(2),<x0=%st(0)
fadd %st(2),%st(0)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:

# qhasm:   x0 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha130
fsubl crypto_onetimeauth_poly1305_amd64_alpha130(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:

# qhasm:   h3 -= x0
# asm 1: fsubr <x0=float80#1,<h3=float80#3
# asm 2: fsubr <x0=%st(0),<h3=%st(2)
fsubr %st(0),%st(2)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:

# qhasm:   x0 *= *(float64 *) &crypto_onetimeauth_poly1305_amd64_scale
fmull crypto_onetimeauth_poly1305_amd64_scale(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:

# qhasm:   x1 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha32
fldl crypto_onetimeauth_poly1305_amd64_alpha32(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:<x1#75:

# qhasm:   x1 += h0
# asm 1: fadd <h0=float80#3,<x1=float80#1
# asm 2: fadd <h0=%st(2),<x1=%st(0)
fadd %st(2),%st(0)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:<x1#75:

# qhasm:   x1 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha32
fsubl crypto_onetimeauth_poly1305_amd64_alpha32(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:<x1#75:

# qhasm:   h0 -= x1
# asm 1: fsubr <x1=float80#1,<h0=float80#3
# asm 2: fsubr <x1=%st(0),<h0=%st(2)
fsubr %st(0),%st(2)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:<x1#75:

# qhasm:   x2 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha64
fldl crypto_onetimeauth_poly1305_amd64_alpha64(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:<x1#75:<x2#76:

# qhasm:   x2 += h1
# asm 1: fadd <h1=float80#6,<x2=float80#1
# asm 2: fadd <h1=%st(5),<x2=%st(0)
fadd %st(5),%st(0)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:<x1#75:<x2#76:

# qhasm:   x2 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha64
fsubl crypto_onetimeauth_poly1305_amd64_alpha64(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:<x1#75:<x2#76:

# qhasm:   h1 -= x2
# asm 1: fsubr <x2=float80#1,<h1=float80#6
# asm 2: fsubr <x2=%st(0),<h1=%st(5)
fsubr %st(0),%st(5)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:<x1#75:<x2#76:

# qhasm:   x3 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha96
fldl crypto_onetimeauth_poly1305_amd64_alpha96(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:<x1#75:<x2#76:<x3#77:

# qhasm:   x3 += h2
# asm 1: fadd <h2=float80#8,<x3=float80#1
# asm 2: fadd <h2=%st(7),<x3=%st(0)
fadd %st(7),%st(0)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:<x1#75:<x2#76:<x3#77:

# qhasm:   x3 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha96
fsubl crypto_onetimeauth_poly1305_amd64_alpha96(%rip)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:<x1#75:<x2#76:<x3#77:

# qhasm:   h2 -= x3
# asm 1: fsubr <x3=float80#1,<h2=float80#8
# asm 2: fsubr <x3=%st(0),<h2=%st(7)
fsubr %st(0),%st(7)
# comment:fpstackfrombottom:<h2#40:<h1#41:<h3#39:<h0#42:<x0#74:<x1#75:<x2#76:<x3#77:

# qhasm: internal stacktop h2
# asm 1: fxch <h2=float80#8
# asm 2: fxch <h2=%st(7)
fxch %st(7)

# qhasm:   x2 += h2
# asm 1: faddp <h2=float80#1,<x2=float80#2
# asm 2: faddp <h2=%st(0),<x2=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#77:<h1#41:<h3#39:<h0#42:<x0#74:<x1#75:<x2#76:

# qhasm: internal stacktop h1
# asm 1: fxch <h1=float80#6
# asm 2: fxch <h1=%st(5)
fxch %st(5)

# qhasm:   x1 += h1
# asm 1: faddp <h1=float80#1,<x1=float80#2
# asm 2: faddp <h1=%st(0),<x1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#77:<x2#76:<h3#39:<h0#42:<x0#74:<x1#75:

# qhasm: internal stacktop h3
# asm 1: fxch <h3=float80#4
# asm 2: fxch <h3=%st(3)
fxch %st(3)

# qhasm:   x3 += h3
# asm 1: faddp <h3=float80#1,<x3=float80#6
# asm 2: faddp <h3=%st(0),<x3=%st(5)
faddp %st(0),%st(5)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<h0#42:<x0#74:

# qhasm:   x0 += h0
# asm 1: faddp <h0=float80#1,<x0=float80#2
# asm 2: faddp <h0=%st(0),<x0=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<x0#74:

# qhasm:   h3 = *(float64 *) &r3
# asm 1: fldl <r3=stack64#19
# asm 2: fldl <r3=176(%rsp)
fldl 176(%rsp)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<x0#74:<h3#39:

# qhasm:   h3 *= x0
# asm 1: fmul <x0=float80#2,<h3=float80#1
# asm 2: fmul <x0=%st(1),<h3=%st(0)
fmul %st(1),%st(0)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<x0#74:<h3#39:

# qhasm:   h2 = *(float64 *) &r2
# asm 1: fldl <r2=stack64#17
# asm 2: fldl <r2=160(%rsp)
fldl 160(%rsp)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<x0#74:<h3#39:<h2#40:

# qhasm:   h2 *= x0
# asm 1: fmul <x0=float80#3,<h2=float80#1
# asm 2: fmul <x0=%st(2),<h2=%st(0)
fmul %st(2),%st(0)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<x0#74:<h3#39:<h2#40:

# qhasm:   h1 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#15
# asm 2: fldl <r1=144(%rsp)
fldl 144(%rsp)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<x0#74:<h3#39:<h2#40:<h1#41:

# qhasm:   h1 *= x0
# asm 1: fmul <x0=float80#4,<h1=float80#1
# asm 2: fmul <x0=%st(3),<h1=%st(0)
fmul %st(3),%st(0)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<x0#74:<h3#39:<h2#40:<h1#41:

# qhasm:   h0 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#14
# asm 2: fldl <r0=136(%rsp)
fldl 136(%rsp)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<x0#74:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   h0 *= x0
# asm 1: fmulp <x0=float80#1,<h0=float80#5
# asm 2: fmulp <x0=%st(0),<h0=%st(4)
fmulp %st(0),%st(4)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<h0#42:<h3#39:<h2#40:<h1#41:

# qhasm:   r2x1 = *(float64 *) &r2
# asm 1: fldl <r2=stack64#17
# asm 2: fldl <r2=160(%rsp)
fldl 160(%rsp)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<h0#42:<h3#39:<h2#40:<h1#41:<r2x1#78:

# qhasm:   r2x1 *= x1
# asm 1: fmul <x1=float80#6,<r2x1=float80#1
# asm 2: fmul <x1=%st(5),<r2x1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<h0#42:<h3#39:<h2#40:<h1#41:<r2x1#78:

# qhasm:   h3 += r2x1
# asm 1: faddp <r2x1=float80#1,<h3=float80#4
# asm 2: faddp <r2x1=%st(0),<h3=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<h0#42:<h3#39:<h2#40:<h1#41:

# qhasm:   r1x1 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#15
# asm 2: fldl <r1=144(%rsp)
fldl 144(%rsp)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<h0#42:<h3#39:<h2#40:<h1#41:<r1x1#79:

# qhasm:   r1x1 *= x1
# asm 1: fmul <x1=float80#6,<r1x1=float80#1
# asm 2: fmul <x1=%st(5),<r1x1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<h0#42:<h3#39:<h2#40:<h1#41:<r1x1#79:

# qhasm:   h2 += r1x1
# asm 1: faddp <r1x1=float80#1,<h2=float80#3
# asm 2: faddp <r1x1=%st(0),<h2=%st(2)
faddp %st(0),%st(2)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<h0#42:<h3#39:<h2#40:<h1#41:

# qhasm:   r0x1 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#14
# asm 2: fldl <r0=136(%rsp)
fldl 136(%rsp)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<h0#42:<h3#39:<h2#40:<h1#41:<r0x1#80:

# qhasm:   r0x1 *= x1
# asm 1: fmul <x1=float80#6,<r0x1=float80#1
# asm 2: fmul <x1=%st(5),<r0x1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<h0#42:<h3#39:<h2#40:<h1#41:<r0x1#80:

# qhasm:   h1 += r0x1
# asm 1: faddp <r0x1=float80#1,<h1=float80#2
# asm 2: faddp <r0x1=%st(0),<h1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<h0#42:<h3#39:<h2#40:<h1#41:

# qhasm:   sr3x1 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#20
# asm 2: fldl <sr3=184(%rsp)
fldl 184(%rsp)
# comment:fpstackfrombottom:<x3#77:<x2#76:<x1#75:<h0#42:<h3#39:<h2#40:<h1#41:<sr3x1#81:

# qhasm:   sr3x1 *= x1
# asm 1: fmulp <x1=float80#1,<sr3x1=float80#6
# asm 2: fmulp <x1=%st(0),<sr3x1=%st(5)
fmulp %st(0),%st(5)
# comment:fpstackfrombottom:<x3#77:<x2#76:<sr3x1#81:<h0#42:<h3#39:<h2#40:<h1#41:

# qhasm: internal stacktop sr3x1
# asm 1: fxch <sr3x1=float80#5
# asm 2: fxch <sr3x1=%st(4)
fxch %st(4)

# qhasm:   h0 += sr3x1
# asm 1: faddp <sr3x1=float80#1,<h0=float80#4
# asm 2: faddp <sr3x1=%st(0),<h0=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x3#77:<x2#76:<h1#41:<h0#42:<h3#39:<h2#40:

# qhasm:   r1x2 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#15
# asm 2: fldl <r1=144(%rsp)
fldl 144(%rsp)
# comment:fpstackfrombottom:<x3#77:<x2#76:<h1#41:<h0#42:<h3#39:<h2#40:<r1x2#82:

# qhasm:   r1x2 *= x2
# asm 1: fmul <x2=float80#6,<r1x2=float80#1
# asm 2: fmul <x2=%st(5),<r1x2=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#77:<x2#76:<h1#41:<h0#42:<h3#39:<h2#40:<r1x2#82:

# qhasm:   h3 += r1x2
# asm 1: faddp <r1x2=float80#1,<h3=float80#3
# asm 2: faddp <r1x2=%st(0),<h3=%st(2)
faddp %st(0),%st(2)
# comment:fpstackfrombottom:<x3#77:<x2#76:<h1#41:<h0#42:<h3#39:<h2#40:

# qhasm:   r0x2 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#14
# asm 2: fldl <r0=136(%rsp)
fldl 136(%rsp)
# comment:fpstackfrombottom:<x3#77:<x2#76:<h1#41:<h0#42:<h3#39:<h2#40:<r0x2#83:

# qhasm:   r0x2 *= x2
# asm 1: fmul <x2=float80#6,<r0x2=float80#1
# asm 2: fmul <x2=%st(5),<r0x2=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#77:<x2#76:<h1#41:<h0#42:<h3#39:<h2#40:<r0x2#83:

# qhasm:   h2 += r0x2
# asm 1: faddp <r0x2=float80#1,<h2=float80#2
# asm 2: faddp <r0x2=%st(0),<h2=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#77:<x2#76:<h1#41:<h0#42:<h3#39:<h2#40:

# qhasm:   sr3x2 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#20
# asm 2: fldl <sr3=184(%rsp)
fldl 184(%rsp)
# comment:fpstackfrombottom:<x3#77:<x2#76:<h1#41:<h0#42:<h3#39:<h2#40:<sr3x2#84:

# qhasm:   sr3x2 *= x2
# asm 1: fmul <x2=float80#6,<sr3x2=float80#1
# asm 2: fmul <x2=%st(5),<sr3x2=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#77:<x2#76:<h1#41:<h0#42:<h3#39:<h2#40:<sr3x2#84:

# qhasm:   h1 += sr3x2
# asm 1: faddp <sr3x2=float80#1,<h1=float80#5
# asm 2: faddp <sr3x2=%st(0),<h1=%st(4)
faddp %st(0),%st(4)
# comment:fpstackfrombottom:<x3#77:<x2#76:<h1#41:<h0#42:<h3#39:<h2#40:

# qhasm:   sr2x2 = *(float64 *) &sr2
# asm 1: fldl <sr2=stack64#18
# asm 2: fldl <sr2=168(%rsp)
fldl 168(%rsp)
# comment:fpstackfrombottom:<x3#77:<x2#76:<h1#41:<h0#42:<h3#39:<h2#40:<sr2x2#85:

# qhasm:   sr2x2 *= x2
# asm 1: fmulp <x2=float80#1,<sr2x2=float80#6
# asm 2: fmulp <x2=%st(0),<sr2x2=%st(5)
fmulp %st(0),%st(5)
# comment:fpstackfrombottom:<x3#77:<sr2x2#85:<h1#41:<h0#42:<h3#39:<h2#40:

# qhasm: internal stacktop sr2x2
# asm 1: fxch <sr2x2=float80#5
# asm 2: fxch <sr2x2=%st(4)
fxch %st(4)

# qhasm:   h0 += sr2x2
# asm 1: faddp <sr2x2=float80#1,<h0=float80#3
# asm 2: faddp <sr2x2=%st(0),<h0=%st(2)
faddp %st(0),%st(2)
# comment:fpstackfrombottom:<x3#77:<h2#40:<h1#41:<h0#42:<h3#39:

# qhasm:   r0x3 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#14
# asm 2: fldl <r0=136(%rsp)
fldl 136(%rsp)
# comment:fpstackfrombottom:<x3#77:<h2#40:<h1#41:<h0#42:<h3#39:<r0x3#86:

# qhasm:   r0x3 *= x3
# asm 1: fmul <x3=float80#6,<r0x3=float80#1
# asm 2: fmul <x3=%st(5),<r0x3=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#77:<h2#40:<h1#41:<h0#42:<h3#39:<r0x3#86:

# qhasm:   h3 += r0x3
# asm 1: faddp <r0x3=float80#1,<h3=float80#2
# asm 2: faddp <r0x3=%st(0),<h3=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#77:<h2#40:<h1#41:<h0#42:<h3#39:

# qhasm:   sr3x3 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#20
# asm 2: fldl <sr3=184(%rsp)
fldl 184(%rsp)
# comment:fpstackfrombottom:<x3#77:<h2#40:<h1#41:<h0#42:<h3#39:<sr3x3#87:

# qhasm:   sr3x3 *= x3
# asm 1: fmul <x3=float80#6,<sr3x3=float80#1
# asm 2: fmul <x3=%st(5),<sr3x3=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#77:<h2#40:<h1#41:<h0#42:<h3#39:<sr3x3#87:

# qhasm:   h2 += sr3x3
# asm 1: faddp <sr3x3=float80#1,<h2=float80#5
# asm 2: faddp <sr3x3=%st(0),<h2=%st(4)
faddp %st(0),%st(4)
# comment:fpstackfrombottom:<x3#77:<h2#40:<h1#41:<h0#42:<h3#39:

# qhasm:   sr2x3 = *(float64 *) &sr2
# asm 1: fldl <sr2=stack64#18
# asm 2: fldl <sr2=168(%rsp)
fldl 168(%rsp)
# comment:fpstackfrombottom:<x3#77:<h2#40:<h1#41:<h0#42:<h3#39:<sr2x3#88:

# qhasm:   sr2x3 *= x3
# asm 1: fmul <x3=float80#6,<sr2x3=float80#1
# asm 2: fmul <x3=%st(5),<sr2x3=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#77:<h2#40:<h1#41:<h0#42:<h3#39:<sr2x3#88:

# qhasm:   h1 += sr2x3
# asm 1: faddp <sr2x3=float80#1,<h1=float80#4
# asm 2: faddp <sr2x3=%st(0),<h1=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x3#77:<h2#40:<h1#41:<h0#42:<h3#39:

# qhasm:   sr1x3 = *(float64 *) &sr1
# asm 1: fldl <sr1=stack64#16
# asm 2: fldl <sr1=152(%rsp)
fldl 152(%rsp)
# comment:fpstackfrombottom:<x3#77:<h2#40:<h1#41:<h0#42:<h3#39:<sr1x3#89:

# qhasm:   sr1x3 *= x3
# asm 1: fmulp <x3=float80#1,<sr1x3=float80#6
# asm 2: fmulp <x3=%st(0),<sr1x3=%st(5)
fmulp %st(0),%st(5)
# comment:fpstackfrombottom:<sr1x3#89:<h2#40:<h1#41:<h0#42:<h3#39:

# qhasm: internal stacktop sr1x3
# asm 1: fxch <sr1x3=float80#5
# asm 2: fxch <sr1x3=%st(4)
fxch %st(4)

# qhasm:   h0 += sr1x3
# asm 1: faddp <sr1x3=float80#1,<h0=float80#2
# asm 2: faddp <sr1x3=%st(0),<h0=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:
# comment:fp stack unchanged by fallthrough
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm: addatmost15bytes:
._addatmost15bytes:
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:                     =? l - 0
# asm 1: cmp  $0,<l=int64#3
# asm 2: cmp  $0,<l=%rdx
cmp  $0,%rdx
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:
# comment:fp stack unchanged by jump
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm: goto nomorebytes if =
je ._nomorebytes
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm: stack128 lastchunk
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm: int64 destination
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm: int64 numbytes
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   ((uint32 *)&lastchunk)[0] = 0
# asm 1: movl $0,>lastchunk=stack128#1
# asm 2: movl $0,>lastchunk=0(%rsp)
movl $0,0(%rsp)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   ((uint32 *)&lastchunk)[1] = 0
# asm 1: movl $0,4+<lastchunk=stack128#1
# asm 2: movl $0,4+<lastchunk=0(%rsp)
movl $0,4+0(%rsp)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   ((uint32 *)&lastchunk)[2] = 0
# asm 1: movl $0,8+<lastchunk=stack128#1
# asm 2: movl $0,8+<lastchunk=0(%rsp)
movl $0,8+0(%rsp)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   ((uint32 *)&lastchunk)[3] = 0
# asm 1: movl $0,12+<lastchunk=stack128#1
# asm 2: movl $0,12+<lastchunk=0(%rsp)
movl $0,12+0(%rsp)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   destination = &lastchunk
# asm 1: leaq <lastchunk=stack128#1,>destination=int64#1
# asm 2: leaq <lastchunk=0(%rsp),>destination=%rdi
leaq 0(%rsp),%rdi
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   numbytes = l
# asm 1: mov  <l=int64#3,>numbytes=int64#4
# asm 2: mov  <l=%rdx,>numbytes=%rcx
mov  %rdx,%rcx
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   while (numbytes) { *destination++ = *m++; --numbytes }
rep movsb
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   *(uint8 *) (destination + 0) = 1
# asm 1: movb   $1,0(<destination=int64#1)
# asm 2: movb   $1,0(<destination=%rdi)
movb   $1,0(%rdi)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   m3 = ((uint32 *)&lastchunk)[3]
# asm 1: movl 12+<lastchunk=stack128#1,>m3=int64#1d
# asm 2: movl 12+<lastchunk=0(%rsp),>m3=%edi
movl 12+0(%rsp),%edi
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   m2 = ((uint32 *)&lastchunk)[2]
# asm 1: movl 8+<lastchunk=stack128#1,>m2=int64#2d
# asm 2: movl 8+<lastchunk=0(%rsp),>m2=%esi
movl 8+0(%rsp),%esi
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   m1 = ((uint32 *)&lastchunk)[1]
# asm 1: movl 4+<lastchunk=stack128#1,>m1=int64#3d
# asm 2: movl 4+<lastchunk=0(%rsp),>m1=%edx
movl 4+0(%rsp),%edx
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   m0 = ((uint32 *)&lastchunk)[0]
# asm 1: movl <lastchunk=stack128#1,>m0=int64#4d
# asm 2: movl <lastchunk=0(%rsp),>m0=%ecx
movl 0(%rsp),%ecx
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   inplace d3 bottom = m3
# asm 1: movl <m3=int64#1d,<d3=stack64#13
# asm 2: movl <m3=%edi,<d3=128(%rsp)
movl %edi,128(%rsp)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   inplace d2 bottom = m2
# asm 1: movl <m2=int64#2d,<d2=stack64#12
# asm 2: movl <m2=%esi,<d2=120(%rsp)
movl %esi,120(%rsp)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   inplace d1 bottom = m1
# asm 1: movl <m1=int64#3d,<d1=stack64#11
# asm 2: movl <m1=%edx,<d1=112(%rsp)
movl %edx,112(%rsp)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   inplace d0 bottom = m0
# asm 1: movl <m0=int64#4d,<d0=stack64#10
# asm 2: movl <m0=%ecx,<d0=104(%rsp)
movl %ecx,104(%rsp)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm: internal stacktop h3
# asm 1: fxch <h3=float80#4
# asm 2: fxch <h3=%st(3)
fxch %st(3)

# qhasm:   h3 += *(float64 *) &d3
# asm 1: faddl <d3=stack64#13
# asm 2: faddl <d3=128(%rsp)
faddl 128(%rsp)
# comment:fpstackfrombottom:<h0#42:<h2#40:<h1#41:<h3#39:

# qhasm:   h3 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset3
fsubl crypto_onetimeauth_poly1305_amd64_doffset3(%rip)
# comment:fpstackfrombottom:<h0#42:<h2#40:<h1#41:<h3#39:

# qhasm: internal stacktop h2
# asm 1: fxch <h2=float80#3
# asm 2: fxch <h2=%st(2)
fxch %st(2)

# qhasm:   h2 += *(float64 *) &d2
# asm 1: faddl <d2=stack64#12
# asm 2: faddl <d2=120(%rsp)
faddl 120(%rsp)
# comment:fpstackfrombottom:<h0#42:<h3#39:<h1#41:<h2#40:

# qhasm:   h2 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset2
fsubl crypto_onetimeauth_poly1305_amd64_doffset2(%rip)
# comment:fpstackfrombottom:<h0#42:<h3#39:<h1#41:<h2#40:

# qhasm: internal stacktop h1
# asm 1: fxch <h1=float80#2
# asm 2: fxch <h1=%st(1)
fxch %st(1)

# qhasm:   h1 += *(float64 *) &d1
# asm 1: faddl <d1=stack64#11
# asm 2: faddl <d1=112(%rsp)
faddl 112(%rsp)
# comment:fpstackfrombottom:<h0#42:<h3#39:<h2#40:<h1#41:

# qhasm:   h1 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset1
fsubl crypto_onetimeauth_poly1305_amd64_doffset1(%rip)
# comment:fpstackfrombottom:<h0#42:<h3#39:<h2#40:<h1#41:

# qhasm: internal stacktop h0
# asm 1: fxch <h0=float80#4
# asm 2: fxch <h0=%st(3)
fxch %st(3)

# qhasm:   h0 += *(float64 *) &d0
# asm 1: faddl <d0=stack64#10
# asm 2: faddl <d0=104(%rsp)
faddl 104(%rsp)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:

# qhasm:   h0 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_doffset0
fsubl crypto_onetimeauth_poly1305_amd64_doffset0(%rip)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:

# qhasm:   x0 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha130
fldl crypto_onetimeauth_poly1305_amd64_alpha130(%rip)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:

# qhasm:   x0 += h3
# asm 1: fadd <h3=float80#4,<x0=float80#1
# asm 2: fadd <h3=%st(3),<x0=%st(0)
fadd %st(3),%st(0)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:

# qhasm:   x0 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha130
fsubl crypto_onetimeauth_poly1305_amd64_alpha130(%rip)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:

# qhasm:   h3 -= x0
# asm 1: fsubr <x0=float80#1,<h3=float80#4
# asm 2: fsubr <x0=%st(0),<h3=%st(3)
fsubr %st(0),%st(3)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:

# qhasm:   x0 *= *(float64 *) &crypto_onetimeauth_poly1305_amd64_scale
fmull crypto_onetimeauth_poly1305_amd64_scale(%rip)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:

# qhasm:   x1 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha32
fldl crypto_onetimeauth_poly1305_amd64_alpha32(%rip)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:<x1#99:

# qhasm:   x1 += h0
# asm 1: fadd <h0=float80#3,<x1=float80#1
# asm 2: fadd <h0=%st(2),<x1=%st(0)
fadd %st(2),%st(0)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:<x1#99:

# qhasm:   x1 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha32
fsubl crypto_onetimeauth_poly1305_amd64_alpha32(%rip)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:<x1#99:

# qhasm:   h0 -= x1
# asm 1: fsubr <x1=float80#1,<h0=float80#3
# asm 2: fsubr <x1=%st(0),<h0=%st(2)
fsubr %st(0),%st(2)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:<x1#99:

# qhasm:   x2 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha64
fldl crypto_onetimeauth_poly1305_amd64_alpha64(%rip)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:<x1#99:<x2#100:

# qhasm:   x2 += h1
# asm 1: fadd <h1=float80#7,<x2=float80#1
# asm 2: fadd <h1=%st(6),<x2=%st(0)
fadd %st(6),%st(0)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:<x1#99:<x2#100:

# qhasm:   x2 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha64
fsubl crypto_onetimeauth_poly1305_amd64_alpha64(%rip)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:<x1#99:<x2#100:

# qhasm:   h1 -= x2
# asm 1: fsubr <x2=float80#1,<h1=float80#7
# asm 2: fsubr <x2=%st(0),<h1=%st(6)
fsubr %st(0),%st(6)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:<x1#99:<x2#100:

# qhasm:   x3 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha96
fldl crypto_onetimeauth_poly1305_amd64_alpha96(%rip)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:<x1#99:<x2#100:<x3#101:

# qhasm:   x3 += h2
# asm 1: fadd <h2=float80#6,<x3=float80#1
# asm 2: fadd <h2=%st(5),<x3=%st(0)
fadd %st(5),%st(0)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:<x1#99:<x2#100:<x3#101:

# qhasm:   x3 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha96
fsubl crypto_onetimeauth_poly1305_amd64_alpha96(%rip)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:<x1#99:<x2#100:<x3#101:

# qhasm:   h2 -= x3
# asm 1: fsubr <x3=float80#1,<h2=float80#6
# asm 2: fsubr <x3=%st(0),<h2=%st(5)
fsubr %st(0),%st(5)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<h0#42:<x0#98:<x1#99:<x2#100:<x3#101:

# qhasm: internal stacktop h0
# asm 1: fxch <h0=float80#5
# asm 2: fxch <h0=%st(4)
fxch %st(4)

# qhasm:   x0 += h0
# asm 1: faddp <h0=float80#1,<x0=float80#4
# asm 2: faddp <h0=%st(0),<x0=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<h1#41:<h3#39:<h2#40:<x3#101:<x0#98:<x1#99:<x2#100:

# qhasm: internal stacktop h1
# asm 1: fxch <h1=float80#7
# asm 2: fxch <h1=%st(6)
fxch %st(6)

# qhasm:   x1 += h1
# asm 1: faddp <h1=float80#1,<x1=float80#2
# asm 2: faddp <h1=%st(0),<x1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x2#100:<h3#39:<h2#40:<x3#101:<x0#98:<x1#99:

# qhasm: internal stacktop h2
# asm 1: fxch <h2=float80#4
# asm 2: fxch <h2=%st(3)
fxch %st(3)

# qhasm:   x2 += h2
# asm 1: faddp <h2=float80#1,<x2=float80#6
# asm 2: faddp <h2=%st(0),<x2=%st(5)
faddp %st(0),%st(5)
# comment:fpstackfrombottom:<x2#100:<h3#39:<x1#99:<x3#101:<x0#98:

# qhasm: internal stacktop h3
# asm 1: fxch <h3=float80#4
# asm 2: fxch <h3=%st(3)
fxch %st(3)

# qhasm:   x3 += h3
# asm 1: faddp <h3=float80#1,<x3=float80#2
# asm 2: faddp <h3=%st(0),<x3=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:

# qhasm:   h3 = *(float64 *) &r3
# asm 1: fldl <r3=stack64#19
# asm 2: fldl <r3=176(%rsp)
fldl 176(%rsp)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:<h3#39:

# qhasm:   h3 *= x0
# asm 1: fmul <x0=float80#4,<h3=float80#1
# asm 2: fmul <x0=%st(3),<h3=%st(0)
fmul %st(3),%st(0)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:<h3#39:

# qhasm:   h2 = *(float64 *) &r2
# asm 1: fldl <r2=stack64#17
# asm 2: fldl <r2=160(%rsp)
fldl 160(%rsp)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:<h3#39:<h2#40:

# qhasm:   h2 *= x0
# asm 1: fmul <x0=float80#5,<h2=float80#1
# asm 2: fmul <x0=%st(4),<h2=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:<h3#39:<h2#40:

# qhasm:   h1 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#15
# asm 2: fldl <r1=144(%rsp)
fldl 144(%rsp)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:<h3#39:<h2#40:<h1#41:

# qhasm:   h1 *= x0
# asm 1: fmul <x0=float80#6,<h1=float80#1
# asm 2: fmul <x0=%st(5),<h1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:<h3#39:<h2#40:<h1#41:

# qhasm:   h0 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#14
# asm 2: fldl <r0=136(%rsp)
fldl 136(%rsp)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   h0 *= x0
# asm 1: fmulp <x0=float80#1,<h0=float80#7
# asm 2: fmulp <x0=%st(0),<h0=%st(6)
fmulp %st(0),%st(6)
# comment:fpstackfrombottom:<x2#100:<h0#42:<x1#99:<x3#101:<h3#39:<h2#40:<h1#41:

# qhasm:   r2x1 = *(float64 *) &r2
# asm 1: fldl <r2=stack64#17
# asm 2: fldl <r2=160(%rsp)
fldl 160(%rsp)
# comment:fpstackfrombottom:<x2#100:<h0#42:<x1#99:<x3#101:<h3#39:<h2#40:<h1#41:<r2x1#102:

# qhasm:   r2x1 *= x1
# asm 1: fmul <x1=float80#6,<r2x1=float80#1
# asm 2: fmul <x1=%st(5),<r2x1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x2#100:<h0#42:<x1#99:<x3#101:<h3#39:<h2#40:<h1#41:<r2x1#102:

# qhasm:   h3 += r2x1
# asm 1: faddp <r2x1=float80#1,<h3=float80#4
# asm 2: faddp <r2x1=%st(0),<h3=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x2#100:<h0#42:<x1#99:<x3#101:<h3#39:<h2#40:<h1#41:

# qhasm:   r1x1 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#15
# asm 2: fldl <r1=144(%rsp)
fldl 144(%rsp)
# comment:fpstackfrombottom:<x2#100:<h0#42:<x1#99:<x3#101:<h3#39:<h2#40:<h1#41:<r1x1#103:

# qhasm:   r1x1 *= x1
# asm 1: fmul <x1=float80#6,<r1x1=float80#1
# asm 2: fmul <x1=%st(5),<r1x1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x2#100:<h0#42:<x1#99:<x3#101:<h3#39:<h2#40:<h1#41:<r1x1#103:

# qhasm:   h2 += r1x1
# asm 1: faddp <r1x1=float80#1,<h2=float80#3
# asm 2: faddp <r1x1=%st(0),<h2=%st(2)
faddp %st(0),%st(2)
# comment:fpstackfrombottom:<x2#100:<h0#42:<x1#99:<x3#101:<h3#39:<h2#40:<h1#41:

# qhasm:   r0x1 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#14
# asm 2: fldl <r0=136(%rsp)
fldl 136(%rsp)
# comment:fpstackfrombottom:<x2#100:<h0#42:<x1#99:<x3#101:<h3#39:<h2#40:<h1#41:<r0x1#104:

# qhasm:   r0x1 *= x1
# asm 1: fmul <x1=float80#6,<r0x1=float80#1
# asm 2: fmul <x1=%st(5),<r0x1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x2#100:<h0#42:<x1#99:<x3#101:<h3#39:<h2#40:<h1#41:<r0x1#104:

# qhasm:   h1 += r0x1
# asm 1: faddp <r0x1=float80#1,<h1=float80#2
# asm 2: faddp <r0x1=%st(0),<h1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x2#100:<h0#42:<x1#99:<x3#101:<h3#39:<h2#40:<h1#41:

# qhasm:   sr3x1 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#20
# asm 2: fldl <sr3=184(%rsp)
fldl 184(%rsp)
# comment:fpstackfrombottom:<x2#100:<h0#42:<x1#99:<x3#101:<h3#39:<h2#40:<h1#41:<sr3x1#105:

# qhasm:   sr3x1 *= x1
# asm 1: fmulp <x1=float80#1,<sr3x1=float80#6
# asm 2: fmulp <x1=%st(0),<sr3x1=%st(5)
fmulp %st(0),%st(5)
# comment:fpstackfrombottom:<x2#100:<h0#42:<sr3x1#105:<x3#101:<h3#39:<h2#40:<h1#41:

# qhasm: internal stacktop sr3x1
# asm 1: fxch <sr3x1=float80#5
# asm 2: fxch <sr3x1=%st(4)
fxch %st(4)

# qhasm:   h0 += sr3x1
# asm 1: faddp <sr3x1=float80#1,<h0=float80#6
# asm 2: faddp <sr3x1=%st(0),<h0=%st(5)
faddp %st(0),%st(5)
# comment:fpstackfrombottom:<x2#100:<h0#42:<h1#41:<x3#101:<h3#39:<h2#40:

# qhasm:   r1x2 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#15
# asm 2: fldl <r1=144(%rsp)
fldl 144(%rsp)
# comment:fpstackfrombottom:<x2#100:<h0#42:<h1#41:<x3#101:<h3#39:<h2#40:<r1x2#106:

# qhasm:   r1x2 *= x2
# asm 1: fmul <x2=float80#7,<r1x2=float80#1
# asm 2: fmul <x2=%st(6),<r1x2=%st(0)
fmul %st(6),%st(0)
# comment:fpstackfrombottom:<x2#100:<h0#42:<h1#41:<x3#101:<h3#39:<h2#40:<r1x2#106:

# qhasm:   h3 += r1x2
# asm 1: faddp <r1x2=float80#1,<h3=float80#3
# asm 2: faddp <r1x2=%st(0),<h3=%st(2)
faddp %st(0),%st(2)
# comment:fpstackfrombottom:<x2#100:<h0#42:<h1#41:<x3#101:<h3#39:<h2#40:

# qhasm:   r0x2 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#14
# asm 2: fldl <r0=136(%rsp)
fldl 136(%rsp)
# comment:fpstackfrombottom:<x2#100:<h0#42:<h1#41:<x3#101:<h3#39:<h2#40:<r0x2#107:

# qhasm:   r0x2 *= x2
# asm 1: fmul <x2=float80#7,<r0x2=float80#1
# asm 2: fmul <x2=%st(6),<r0x2=%st(0)
fmul %st(6),%st(0)
# comment:fpstackfrombottom:<x2#100:<h0#42:<h1#41:<x3#101:<h3#39:<h2#40:<r0x2#107:

# qhasm:   h2 += r0x2
# asm 1: faddp <r0x2=float80#1,<h2=float80#2
# asm 2: faddp <r0x2=%st(0),<h2=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x2#100:<h0#42:<h1#41:<x3#101:<h3#39:<h2#40:

# qhasm:   sr3x2 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#20
# asm 2: fldl <sr3=184(%rsp)
fldl 184(%rsp)
# comment:fpstackfrombottom:<x2#100:<h0#42:<h1#41:<x3#101:<h3#39:<h2#40:<sr3x2#108:

# qhasm:   sr3x2 *= x2
# asm 1: fmul <x2=float80#7,<sr3x2=float80#1
# asm 2: fmul <x2=%st(6),<sr3x2=%st(0)
fmul %st(6),%st(0)
# comment:fpstackfrombottom:<x2#100:<h0#42:<h1#41:<x3#101:<h3#39:<h2#40:<sr3x2#108:

# qhasm:   h1 += sr3x2
# asm 1: faddp <sr3x2=float80#1,<h1=float80#5
# asm 2: faddp <sr3x2=%st(0),<h1=%st(4)
faddp %st(0),%st(4)
# comment:fpstackfrombottom:<x2#100:<h0#42:<h1#41:<x3#101:<h3#39:<h2#40:

# qhasm:   sr2x2 = *(float64 *) &sr2
# asm 1: fldl <sr2=stack64#18
# asm 2: fldl <sr2=168(%rsp)
fldl 168(%rsp)
# comment:fpstackfrombottom:<x2#100:<h0#42:<h1#41:<x3#101:<h3#39:<h2#40:<sr2x2#109:

# qhasm:   sr2x2 *= x2
# asm 1: fmulp <x2=float80#1,<sr2x2=float80#7
# asm 2: fmulp <x2=%st(0),<sr2x2=%st(6)
fmulp %st(0),%st(6)
# comment:fpstackfrombottom:<sr2x2#109:<h0#42:<h1#41:<x3#101:<h3#39:<h2#40:

# qhasm: internal stacktop sr2x2
# asm 1: fxch <sr2x2=float80#6
# asm 2: fxch <sr2x2=%st(5)
fxch %st(5)

# qhasm:   h0 += sr2x2
# asm 1: faddp <sr2x2=float80#1,<h0=float80#5
# asm 2: faddp <sr2x2=%st(0),<h0=%st(4)
faddp %st(0),%st(4)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h1#41:<x3#101:<h3#39:

# qhasm:   r0x3 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#14
# asm 2: fldl <r0=136(%rsp)
fldl 136(%rsp)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h1#41:<x3#101:<h3#39:<r0x3#110:

# qhasm:   r0x3 *= x3
# asm 1: fmul <x3=float80#3,<r0x3=float80#1
# asm 2: fmul <x3=%st(2),<r0x3=%st(0)
fmul %st(2),%st(0)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h1#41:<x3#101:<h3#39:<r0x3#110:

# qhasm:   h3 += r0x3
# asm 1: faddp <r0x3=float80#1,<h3=float80#2
# asm 2: faddp <r0x3=%st(0),<h3=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h1#41:<x3#101:<h3#39:

# qhasm:   sr3x3 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#20
# asm 2: fldl <sr3=184(%rsp)
fldl 184(%rsp)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h1#41:<x3#101:<h3#39:<sr3x3#111:

# qhasm:   sr3x3 *= x3
# asm 1: fmul <x3=float80#3,<sr3x3=float80#1
# asm 2: fmul <x3=%st(2),<sr3x3=%st(0)
fmul %st(2),%st(0)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h1#41:<x3#101:<h3#39:<sr3x3#111:

# qhasm:   h2 += sr3x3
# asm 1: faddp <sr3x3=float80#1,<h2=float80#6
# asm 2: faddp <sr3x3=%st(0),<h2=%st(5)
faddp %st(0),%st(5)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h1#41:<x3#101:<h3#39:

# qhasm:   sr2x3 = *(float64 *) &sr2
# asm 1: fldl <sr2=stack64#18
# asm 2: fldl <sr2=168(%rsp)
fldl 168(%rsp)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h1#41:<x3#101:<h3#39:<sr2x3#112:

# qhasm:   sr2x3 *= x3
# asm 1: fmul <x3=float80#3,<sr2x3=float80#1
# asm 2: fmul <x3=%st(2),<sr2x3=%st(0)
fmul %st(2),%st(0)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h1#41:<x3#101:<h3#39:<sr2x3#112:

# qhasm:   h1 += sr2x3
# asm 1: faddp <sr2x3=float80#1,<h1=float80#4
# asm 2: faddp <sr2x3=%st(0),<h1=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h1#41:<x3#101:<h3#39:

# qhasm:   sr1x3 = *(float64 *) &sr1
# asm 1: fldl <sr1=stack64#16
# asm 2: fldl <sr1=152(%rsp)
fldl 152(%rsp)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h1#41:<x3#101:<h3#39:<sr1x3#113:

# qhasm:   sr1x3 *= x3
# asm 1: fmulp <x3=float80#1,<sr1x3=float80#3
# asm 2: fmulp <x3=%st(0),<sr1x3=%st(2)
fmulp %st(0),%st(2)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h1#41:<sr1x3#113:<h3#39:

# qhasm: internal stacktop sr1x3
# asm 1: fxch <sr1x3=float80#2
# asm 2: fxch <sr1x3=%st(1)
fxch %st(1)

# qhasm:   h0 += sr1x3
# asm 1: faddp <sr1x3=float80#1,<h0=float80#4
# asm 2: faddp <sr1x3=%st(0),<h0=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<h2#40:<h0#42:<h1#41:<h3#39:
# comment:automatically reorganizing fp stack for fallthrough

# qhasm: internal stacktop h2
# asm 1: fxch <h2=float80#4
# asm 2: fxch <h2=%st(3)
fxch %st(3)
# comment:fpstackfrombottom:<h3#39:<h0#42:<h1#41:<h2#40:

# qhasm: internal stacktop h0
# asm 1: fxch <h0=float80#3
# asm 2: fxch <h0=%st(2)
fxch %st(2)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm: nomorebytes:
._nomorebytes:
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:

# qhasm:   x0 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha130
fldl crypto_onetimeauth_poly1305_amd64_alpha130(%rip)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:

# qhasm:   x0 += h3
# asm 1: fadd <h3=float80#5,<x0=float80#1
# asm 2: fadd <h3=%st(4),<x0=%st(0)
fadd %st(4),%st(0)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:

# qhasm:   x0 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha130
fsubl crypto_onetimeauth_poly1305_amd64_alpha130(%rip)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:

# qhasm:   h3 -= x0
# asm 1: fsubr <x0=float80#1,<h3=float80#5
# asm 2: fsubr <x0=%st(0),<h3=%st(4)
fsubr %st(0),%st(4)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:

# qhasm:   x0 *= *(float64 *) &crypto_onetimeauth_poly1305_amd64_scale
fmull crypto_onetimeauth_poly1305_amd64_scale(%rip)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:

# qhasm:   x1 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha32
fldl crypto_onetimeauth_poly1305_amd64_alpha32(%rip)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:<x1#115:

# qhasm:   x1 += h0
# asm 1: fadd <h0=float80#3,<x1=float80#1
# asm 2: fadd <h0=%st(2),<x1=%st(0)
fadd %st(2),%st(0)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:<x1#115:

# qhasm:   x1 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha32
fsubl crypto_onetimeauth_poly1305_amd64_alpha32(%rip)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:<x1#115:

# qhasm:   h0 -= x1
# asm 1: fsubr <x1=float80#1,<h0=float80#3
# asm 2: fsubr <x1=%st(0),<h0=%st(2)
fsubr %st(0),%st(2)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:<x1#115:

# qhasm:   x2 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha64
fldl crypto_onetimeauth_poly1305_amd64_alpha64(%rip)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:<x1#115:<x2#116:

# qhasm:   x2 += h1
# asm 1: fadd <h1=float80#5,<x2=float80#1
# asm 2: fadd <h1=%st(4),<x2=%st(0)
fadd %st(4),%st(0)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:<x1#115:<x2#116:

# qhasm:   x2 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha64
fsubl crypto_onetimeauth_poly1305_amd64_alpha64(%rip)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:<x1#115:<x2#116:

# qhasm:   h1 -= x2
# asm 1: fsubr <x2=float80#1,<h1=float80#5
# asm 2: fsubr <x2=%st(0),<h1=%st(4)
fsubr %st(0),%st(4)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:<x1#115:<x2#116:

# qhasm:   x3 = *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha96
fldl crypto_onetimeauth_poly1305_amd64_alpha96(%rip)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:<x1#115:<x2#116:<x3#117:

# qhasm:   x3 += h2
# asm 1: fadd <h2=float80#7,<x3=float80#1
# asm 2: fadd <h2=%st(6),<x3=%st(0)
fadd %st(6),%st(0)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:<x1#115:<x2#116:<x3#117:

# qhasm:   x3 -= *(float64 *) &crypto_onetimeauth_poly1305_amd64_alpha96
fsubl crypto_onetimeauth_poly1305_amd64_alpha96(%rip)
# comment:fpstackfrombottom:<h3#39:<h2#40:<h1#41:<h0#42:<x0#114:<x1#115:<x2#116:<x3#117:

# qhasm:   stacktop h2
# asm 1: fxch <h2=float80#7
# asm 2: fxch <h2=%st(6)
fxch %st(6)
# comment:fpstackfrombottom:<h3#39:<x3#117:<h1#41:<h0#42:<x0#114:<x1#115:<x2#116:<h2#40:

# qhasm:   h2 -= x3
# asm 1: fsub <x3=float80#7,<h2=float80#1
# asm 2: fsub <x3=%st(6),<h2=%st(0)
fsub %st(6),%st(0)
# comment:fpstackfrombottom:<h3#39:<x3#117:<h1#41:<h0#42:<x0#114:<x1#115:<x2#116:<h2#40:

# qhasm: internal stacktop h0
# asm 1: fxch <h0=float80#5
# asm 2: fxch <h0=%st(4)
fxch %st(4)

# qhasm:   x0 += h0
# asm 1: faddp <h0=float80#1,<x0=float80#4
# asm 2: faddp <h0=%st(0),<x0=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<h3#39:<x3#117:<h1#41:<h2#40:<x0#114:<x1#115:<x2#116:

# qhasm: internal stacktop h1
# asm 1: fxch <h1=float80#5
# asm 2: fxch <h1=%st(4)
fxch %st(4)

# qhasm:   x1 += h1
# asm 1: faddp <h1=float80#1,<x1=float80#2
# asm 2: faddp <h1=%st(0),<x1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h3#39:<x3#117:<x2#116:<h2#40:<x0#114:<x1#115:

# qhasm: internal stacktop h2
# asm 1: fxch <h2=float80#3
# asm 2: fxch <h2=%st(2)
fxch %st(2)

# qhasm:   x2 += h2
# asm 1: faddp <h2=float80#1,<x2=float80#4
# asm 2: faddp <h2=%st(0),<x2=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<h3#39:<x3#117:<x2#116:<x1#115:<x0#114:

# qhasm: internal stacktop h3
# asm 1: fxch <h3=float80#5
# asm 2: fxch <h3=%st(4)
fxch %st(4)

# qhasm:   x3 += h3
# asm 1: faddp <h3=float80#1,<x3=float80#4
# asm 2: faddp <h3=%st(0),<x3=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x0#114:<x3#117:<x2#116:<x1#115:

# qhasm: internal stacktop x0
# asm 1: fxch <x0=float80#4
# asm 2: fxch <x0=%st(3)
fxch %st(3)

# qhasm:   x0 += *(float64 *) &crypto_onetimeauth_poly1305_amd64_hoffset0
faddl crypto_onetimeauth_poly1305_amd64_hoffset0(%rip)
# comment:fpstackfrombottom:<x1#115:<x3#117:<x2#116:<x0#114:

# qhasm: internal stacktop x1
# asm 1: fxch <x1=float80#4
# asm 2: fxch <x1=%st(3)
fxch %st(3)

# qhasm:   x1 += *(float64 *) &crypto_onetimeauth_poly1305_amd64_hoffset1
faddl crypto_onetimeauth_poly1305_amd64_hoffset1(%rip)
# comment:fpstackfrombottom:<x0#114:<x3#117:<x2#116:<x1#115:

# qhasm: internal stacktop x2
# asm 1: fxch <x2=float80#2
# asm 2: fxch <x2=%st(1)
fxch %st(1)

# qhasm:   x2 += *(float64 *) &crypto_onetimeauth_poly1305_amd64_hoffset2
faddl crypto_onetimeauth_poly1305_amd64_hoffset2(%rip)
# comment:fpstackfrombottom:<x0#114:<x3#117:<x1#115:<x2#116:

# qhasm: internal stacktop x3
# asm 1: fxch <x3=float80#3
# asm 2: fxch <x3=%st(2)
fxch %st(2)

# qhasm:   x3 += *(float64 *) &crypto_onetimeauth_poly1305_amd64_hoffset3
faddl crypto_onetimeauth_poly1305_amd64_hoffset3(%rip)
# comment:fpstackfrombottom:<x0#114:<x2#116:<x1#115:<x3#117:

# qhasm: internal stacktop x0
# asm 1: fxch <x0=float80#4
# asm 2: fxch <x0=%st(3)
fxch %st(3)

# qhasm:   *(float64 *) &d0 = x0
# asm 1: fstpl >d0=stack64#10
# asm 2: fstpl >d0=104(%rsp)
fstpl 104(%rsp)
# comment:fpstackfrombottom:<x3#117:<x2#116:<x1#115:

# qhasm:   *(float64 *) &d1 = x1
# asm 1: fstpl >d1=stack64#11
# asm 2: fstpl >d1=112(%rsp)
fstpl 112(%rsp)
# comment:fpstackfrombottom:<x3#117:<x2#116:

# qhasm:   *(float64 *) &d2 = x2
# asm 1: fstpl >d2=stack64#12
# asm 2: fstpl >d2=120(%rsp)
fstpl 120(%rsp)
# comment:fpstackfrombottom:<x3#117:

# qhasm:   *(float64 *) &d3 = x3
# asm 1: fstpl >d3=stack64#13
# asm 2: fstpl >d3=128(%rsp)
fstpl 128(%rsp)
# comment:fpstackfrombottom:

# qhasm: int64 f0

# qhasm: int64 f1

# qhasm: int64 f2

# qhasm: int64 f3

# qhasm: int64 f4

# qhasm: int64 g0

# qhasm: int64 g1

# qhasm: int64 g2

# qhasm: int64 g3

# qhasm: int64 f

# qhasm: int64 notf

# qhasm: stack64 f1_stack

# qhasm: stack64 f2_stack

# qhasm: stack64 f3_stack

# qhasm: stack64 f4_stack

# qhasm: stack64 g0_stack

# qhasm: stack64 g1_stack

# qhasm: stack64 g2_stack

# qhasm: stack64 g3_stack

# qhasm:   g0 = top d0
# asm 1: movl <d0=stack64#10,>g0=int64#1d
# asm 2: movl <d0=108(%rsp),>g0=%edi
movl 108(%rsp),%edi

# qhasm:   (uint32) g0 &= 63
# asm 1: and  $63,<g0=int64#1d
# asm 2: and  $63,<g0=%edi
and  $63,%edi

# qhasm:   g1 = top d1
# asm 1: movl <d1=stack64#11,>g1=int64#2d
# asm 2: movl <d1=116(%rsp),>g1=%esi
movl 116(%rsp),%esi

# qhasm:   (uint32) g1 &= 63
# asm 1: and  $63,<g1=int64#2d
# asm 2: and  $63,<g1=%esi
and  $63,%esi

# qhasm:   g2 = top d2
# asm 1: movl <d2=stack64#12,>g2=int64#3d
# asm 2: movl <d2=124(%rsp),>g2=%edx
movl 124(%rsp),%edx

# qhasm:   (uint32) g2 &= 63
# asm 1: and  $63,<g2=int64#3d
# asm 2: and  $63,<g2=%edx
and  $63,%edx

# qhasm:   g3 = top d3
# asm 1: movl <d3=stack64#13,>g3=int64#4d
# asm 2: movl <d3=132(%rsp),>g3=%ecx
movl 132(%rsp),%ecx

# qhasm:   (uint32) g3 &= 63
# asm 1: and  $63,<g3=int64#4d
# asm 2: and  $63,<g3=%ecx
and  $63,%ecx

# qhasm:   f1 = bottom d1
# asm 1: movl <d1=stack64#11,>f1=int64#5d
# asm 2: movl <d1=112(%rsp),>f1=%r8d
movl 112(%rsp),%r8d

# qhasm:   carry? (uint32) f1 += g0
# asm 1: add <g0=int64#1d,<f1=int64#5d
# asm 2: add <g0=%edi,<f1=%r8d
add %edi,%r8d

# qhasm:   f1_stack = f1
# asm 1: movq <f1=int64#5,>f1_stack=stack64#11
# asm 2: movq <f1=%r8,>f1_stack=112(%rsp)
movq %r8,112(%rsp)

# qhasm:   f2 = bottom d2
# asm 1: movl <d2=stack64#12,>f2=int64#1d
# asm 2: movl <d2=120(%rsp),>f2=%edi
movl 120(%rsp),%edi

# qhasm:   carry? (uint32) f2 += g1 + carry
# asm 1: adc <g1=int64#2d,<f2=int64#1d
# asm 2: adc <g1=%esi,<f2=%edi
adc %esi,%edi

# qhasm:   f2_stack = f2
# asm 1: movq <f2=int64#1,>f2_stack=stack64#12
# asm 2: movq <f2=%rdi,>f2_stack=120(%rsp)
movq %rdi,120(%rsp)

# qhasm:   f3 = bottom d3
# asm 1: movl <d3=stack64#13,>f3=int64#1d
# asm 2: movl <d3=128(%rsp),>f3=%edi
movl 128(%rsp),%edi

# qhasm:   carry? (uint32) f3 += g2 + carry
# asm 1: adc <g2=int64#3d,<f3=int64#1d
# asm 2: adc <g2=%edx,<f3=%edi
adc %edx,%edi

# qhasm:   f3_stack = f3
# asm 1: movq <f3=int64#1,>f3_stack=stack64#13
# asm 2: movq <f3=%rdi,>f3_stack=128(%rsp)
movq %rdi,128(%rsp)

# qhasm:   f4 = 0
# asm 1: mov  $0,>f4=int64#1
# asm 2: mov  $0,>f4=%rdi
mov  $0,%rdi

# qhasm:   carry? (uint32) f4 += g3 + carry
# asm 1: adc <g3=int64#4d,<f4=int64#1d
# asm 2: adc <g3=%ecx,<f4=%edi
adc %ecx,%edi

# qhasm:   f4_stack = f4
# asm 1: movq <f4=int64#1,>f4_stack=stack64#14
# asm 2: movq <f4=%rdi,>f4_stack=136(%rsp)
movq %rdi,136(%rsp)

# qhasm:   g0 = 5
# asm 1: mov  $5,>g0=int64#1
# asm 2: mov  $5,>g0=%rdi
mov  $5,%rdi

# qhasm:   f0 = bottom d0
# asm 1: movl <d0=stack64#10,>f0=int64#2d
# asm 2: movl <d0=104(%rsp),>f0=%esi
movl 104(%rsp),%esi

# qhasm:   carry? (uint32) g0 += f0
# asm 1: add <f0=int64#2d,<g0=int64#1d
# asm 2: add <f0=%esi,<g0=%edi
add %esi,%edi

# qhasm:   g0_stack = g0
# asm 1: movq <g0=int64#1,>g0_stack=stack64#10
# asm 2: movq <g0=%rdi,>g0_stack=104(%rsp)
movq %rdi,104(%rsp)

# qhasm:   g1 = 0
# asm 1: mov  $0,>g1=int64#1
# asm 2: mov  $0,>g1=%rdi
mov  $0,%rdi

# qhasm:   f1 = f1_stack
# asm 1: movq <f1_stack=stack64#11,>f1=int64#3
# asm 2: movq <f1_stack=112(%rsp),>f1=%rdx
movq 112(%rsp),%rdx

# qhasm:   carry? (uint32) g1 += f1 + carry
# asm 1: adc <f1=int64#3d,<g1=int64#1d
# asm 2: adc <f1=%edx,<g1=%edi
adc %edx,%edi

# qhasm:   g1_stack = g1
# asm 1: movq <g1=int64#1,>g1_stack=stack64#11
# asm 2: movq <g1=%rdi,>g1_stack=112(%rsp)
movq %rdi,112(%rsp)

# qhasm:   g2 = 0
# asm 1: mov  $0,>g2=int64#1
# asm 2: mov  $0,>g2=%rdi
mov  $0,%rdi

# qhasm:   f2 = f2_stack
# asm 1: movq <f2_stack=stack64#12,>f2=int64#4
# asm 2: movq <f2_stack=120(%rsp),>f2=%rcx
movq 120(%rsp),%rcx

# qhasm:   carry? (uint32) g2 += f2 + carry
# asm 1: adc <f2=int64#4d,<g2=int64#1d
# asm 2: adc <f2=%ecx,<g2=%edi
adc %ecx,%edi

# qhasm:   g2_stack = g2
# asm 1: movq <g2=int64#1,>g2_stack=stack64#12
# asm 2: movq <g2=%rdi,>g2_stack=120(%rsp)
movq %rdi,120(%rsp)

# qhasm:   g3 = 0
# asm 1: mov  $0,>g3=int64#1
# asm 2: mov  $0,>g3=%rdi
mov  $0,%rdi

# qhasm:   f3 = f3_stack
# asm 1: movq <f3_stack=stack64#13,>f3=int64#5
# asm 2: movq <f3_stack=128(%rsp),>f3=%r8
movq 128(%rsp),%r8

# qhasm:   carry? (uint32) g3 += f3 + carry
# asm 1: adc <f3=int64#5d,<g3=int64#1d
# asm 2: adc <f3=%r8d,<g3=%edi
adc %r8d,%edi

# qhasm:   g3_stack = g3
# asm 1: movq <g3=int64#1,>g3_stack=stack64#13
# asm 2: movq <g3=%rdi,>g3_stack=128(%rsp)
movq %rdi,128(%rsp)

# qhasm:   f = 0xfffffffc
# asm 1: mov  $0xfffffffc,>f=int64#1
# asm 2: mov  $0xfffffffc,>f=%rdi
mov  $0xfffffffc,%rdi

# qhasm:   f4 = f4_stack
# asm 1: movq <f4_stack=stack64#14,>f4=int64#6
# asm 2: movq <f4_stack=136(%rsp),>f4=%r9
movq 136(%rsp),%r9

# qhasm:   carry? (uint32) f += f4 + carry
# asm 1: adc <f4=int64#6d,<f=int64#1d
# asm 2: adc <f4=%r9d,<f=%edi
adc %r9d,%edi

# qhasm:   (int32) f >>= 16
# asm 1: sar  $16,<f=int64#1d
# asm 2: sar  $16,<f=%edi
sar  $16,%edi

# qhasm:   notf = f
# asm 1: mov  <f=int64#1,>notf=int64#6
# asm 2: mov  <f=%rdi,>notf=%r9
mov  %rdi,%r9

# qhasm:   (uint32) notf ^= 0xffffffff
# asm 1: xor  $0xffffffff,<notf=int64#6d
# asm 2: xor  $0xffffffff,<notf=%r9d
xor  $0xffffffff,%r9d

# qhasm:   f0 &= f
# asm 1: and  <f=int64#1,<f0=int64#2
# asm 2: and  <f=%rdi,<f0=%rsi
and  %rdi,%rsi

# qhasm:   g0 = g0_stack
# asm 1: movq <g0_stack=stack64#10,>g0=int64#7
# asm 2: movq <g0_stack=104(%rsp),>g0=%rax
movq 104(%rsp),%rax

# qhasm:   g0 &= notf
# asm 1: and  <notf=int64#6,<g0=int64#7
# asm 2: and  <notf=%r9,<g0=%rax
and  %r9,%rax

# qhasm:   f0 |= g0
# asm 1: or   <g0=int64#7,<f0=int64#2
# asm 2: or   <g0=%rax,<f0=%rsi
or   %rax,%rsi

# qhasm:   f1 &= f
# asm 1: and  <f=int64#1,<f1=int64#3
# asm 2: and  <f=%rdi,<f1=%rdx
and  %rdi,%rdx

# qhasm:   g1 = g1_stack
# asm 1: movq <g1_stack=stack64#11,>g1=int64#7
# asm 2: movq <g1_stack=112(%rsp),>g1=%rax
movq 112(%rsp),%rax

# qhasm:   g1 &= notf
# asm 1: and  <notf=int64#6,<g1=int64#7
# asm 2: and  <notf=%r9,<g1=%rax
and  %r9,%rax

# qhasm:   f1 |= g1
# asm 1: or   <g1=int64#7,<f1=int64#3
# asm 2: or   <g1=%rax,<f1=%rdx
or   %rax,%rdx

# qhasm:   f2 &= f
# asm 1: and  <f=int64#1,<f2=int64#4
# asm 2: and  <f=%rdi,<f2=%rcx
and  %rdi,%rcx

# qhasm:   g2 = g2_stack
# asm 1: movq <g2_stack=stack64#12,>g2=int64#7
# asm 2: movq <g2_stack=120(%rsp),>g2=%rax
movq 120(%rsp),%rax

# qhasm:   g2 &= notf
# asm 1: and  <notf=int64#6,<g2=int64#7
# asm 2: and  <notf=%r9,<g2=%rax
and  %r9,%rax

# qhasm:   f2 |= g2
# asm 1: or   <g2=int64#7,<f2=int64#4
# asm 2: or   <g2=%rax,<f2=%rcx
or   %rax,%rcx

# qhasm:   f3 &= f
# asm 1: and  <f=int64#1,<f3=int64#5
# asm 2: and  <f=%rdi,<f3=%r8
and  %rdi,%r8

# qhasm:   g3 = g3_stack
# asm 1: movq <g3_stack=stack64#13,>g3=int64#1
# asm 2: movq <g3_stack=128(%rsp),>g3=%rdi
movq 128(%rsp),%rdi

# qhasm:   g3 &= notf
# asm 1: and  <notf=int64#6,<g3=int64#1
# asm 2: and  <notf=%r9,<g3=%rdi
and  %r9,%rdi

# qhasm:   f3 |= g3
# asm 1: or   <g3=int64#1,<f3=int64#5
# asm 2: or   <g3=%rdi,<f3=%r8
or   %rdi,%r8

# qhasm:   out = out_stack
# asm 1: movq <out_stack=stack64#8,>out=int64#1
# asm 2: movq <out_stack=88(%rsp),>out=%rdi
movq 88(%rsp),%rdi

# qhasm:   k = k_stack
# asm 1: movq <k_stack=stack64#9,>k=int64#6
# asm 2: movq <k_stack=96(%rsp),>k=%r9
movq 96(%rsp),%r9

# qhasm:   carry? (uint32) f0 += *(uint32 *) (k + 16)
# asm 1: addl 16(<k=int64#6),<f0=int64#2d
# asm 2: addl 16(<k=%r9),<f0=%esi
addl 16(%r9),%esi

# qhasm:   carry? (uint32) f1 += *(uint32 *) (k + 20) + carry
# asm 1: adcl 20(<k=int64#6),<f1=int64#3d
# asm 2: adcl 20(<k=%r9),<f1=%edx
adcl 20(%r9),%edx

# qhasm:   carry? (uint32) f2 += *(uint32 *) (k + 24) + carry
# asm 1: adcl 24(<k=int64#6),<f2=int64#4d
# asm 2: adcl 24(<k=%r9),<f2=%ecx
adcl 24(%r9),%ecx

# qhasm:   carry? (uint32) f3 += *(uint32 *) (k + 28) + carry
# asm 1: adcl 28(<k=int64#6),<f3=int64#5d
# asm 2: adcl 28(<k=%r9),<f3=%r8d
adcl 28(%r9),%r8d

# qhasm:   *(uint32 *) (out + 0) = f0
# asm 1: movl   <f0=int64#2d,0(<out=int64#1)
# asm 2: movl   <f0=%esi,0(<out=%rdi)
movl   %esi,0(%rdi)

# qhasm:   *(uint32 *) (out + 4) = f1
# asm 1: movl   <f1=int64#3d,4(<out=int64#1)
# asm 2: movl   <f1=%edx,4(<out=%rdi)
movl   %edx,4(%rdi)

# qhasm:   *(uint32 *) (out + 8) = f2
# asm 1: movl   <f2=int64#4d,8(<out=int64#1)
# asm 2: movl   <f2=%ecx,8(<out=%rdi)
movl   %ecx,8(%rdi)

# qhasm:   *(uint32 *) (out + 12) = f3
# asm 1: movl   <f3=int64#5d,12(<out=int64#1)
# asm 2: movl   <f3=%r8d,12(<out=%rdi)
movl   %r8d,12(%rdi)

# qhasm: r11_caller = r11_stack
# asm 1: movq <r11_stack=stack64#1,>r11_caller=int64#9
# asm 2: movq <r11_stack=32(%rsp),>r11_caller=%r11
movq 32(%rsp),%r11

# qhasm: r12_caller = r12_stack
# asm 1: movq <r12_stack=stack64#2,>r12_caller=int64#10
# asm 2: movq <r12_stack=40(%rsp),>r12_caller=%r12
movq 40(%rsp),%r12

# qhasm: r13_caller = r13_stack
# asm 1: movq <r13_stack=stack64#3,>r13_caller=int64#11
# asm 2: movq <r13_stack=48(%rsp),>r13_caller=%r13
movq 48(%rsp),%r13

# qhasm: r14_caller = r14_stack
# asm 1: movq <r14_stack=stack64#4,>r14_caller=int64#12
# asm 2: movq <r14_stack=56(%rsp),>r14_caller=%r14
movq 56(%rsp),%r14

# qhasm: r15_caller = r15_stack
# asm 1: movq <r15_stack=stack64#5,>r15_caller=int64#13
# asm 2: movq <r15_stack=64(%rsp),>r15_caller=%r15
movq 64(%rsp),%r15

# qhasm: rbx_caller = rbx_stack
# asm 1: movq <rbx_stack=stack64#6,>rbx_caller=int64#14
# asm 2: movq <rbx_stack=72(%rsp),>rbx_caller=%rbx
movq 72(%rsp),%rbx

# qhasm: rbp_caller = rbp_stack
# asm 1: movq <rbp_stack=stack64#7,>rbp_caller=int64#15
# asm 2: movq <rbp_stack=80(%rsp),>rbp_caller=%rbp
movq 80(%rsp),%rbp

# qhasm: leave
add %r11,%rsp
xor %rax,%rax
xor %rdx,%rdx
ret
