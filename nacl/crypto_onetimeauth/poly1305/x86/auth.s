
# qhasm: stack32 arg_out

# qhasm: stack32 arg_m

# qhasm: stack32 arg_l

# qhasm: stack32 arg_ltop

# qhasm: stack32 arg_k

# qhasm: input arg_out

# qhasm: input arg_m

# qhasm: input arg_l

# qhasm: input arg_ltop

# qhasm: input arg_k

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

# qhasm: stack32 eax_stack

# qhasm: stack32 ebx_stack

# qhasm: stack32 esi_stack

# qhasm: stack32 edi_stack

# qhasm: stack32 ebp_stack

# qhasm: int32 out

# qhasm: stack32 out_stack

# qhasm: int32 k

# qhasm: stack32 k_stack

# qhasm: int32 m

# qhasm: int32 l

# qhasm: int32 m0

# qhasm: int32 m1

# qhasm: int32 m2

# qhasm: int32 m3

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

# qhasm: enter crypto_onetimeauth_poly1305_x86 stackaligned4096 crypto_onetimeauth_poly1305_x86_constants
.text
.p2align 5
.globl _crypto_onetimeauth_poly1305_x86
.globl crypto_onetimeauth_poly1305_x86
_crypto_onetimeauth_poly1305_x86:
crypto_onetimeauth_poly1305_x86:
mov %esp,%eax
sub $crypto_onetimeauth_poly1305_x86_constants,%eax
and $4095,%eax
add $192,%eax
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

# qhasm:   round *(uint16 *) &crypto_onetimeauth_poly1305_x86_rounding
fldcw crypto_onetimeauth_poly1305_x86_rounding

# qhasm:   k = arg_k
# asm 1: movl <arg_k=stack32#-5,>k=int32#3
# asm 2: movl <arg_k=20(%esp,%eax),>k=%edx
movl 20(%esp,%eax),%edx

# qhasm:   m0 = *(uint32 *) (k + 0)
# asm 1: movl 0(<k=int32#3),>m0=int32#2
# asm 2: movl 0(<k=%edx),>m0=%ecx
movl 0(%edx),%ecx

# qhasm:   m1 = *(uint32 *) (k + 4)
# asm 1: movl 4(<k=int32#3),>m1=int32#4
# asm 2: movl 4(<k=%edx),>m1=%ebx
movl 4(%edx),%ebx

# qhasm:   m2 = *(uint32 *) (k + 8)
# asm 1: movl 8(<k=int32#3),>m2=int32#5
# asm 2: movl 8(<k=%edx),>m2=%esi
movl 8(%edx),%esi

# qhasm:   m3 = *(uint32 *) (k + 12)
# asm 1: movl 12(<k=int32#3),>m3=int32#6
# asm 2: movl 12(<k=%edx),>m3=%edi
movl 12(%edx),%edi

# qhasm:   d0 top = 0x43300000
# asm 1: movl  $0x43300000,>d0=stack64#1
# asm 2: movl  $0x43300000,>d0=100(%esp)
movl  $0x43300000,100(%esp)

# qhasm:   d1 top = 0x45300000
# asm 1: movl  $0x45300000,>d1=stack64#2
# asm 2: movl  $0x45300000,>d1=108(%esp)
movl  $0x45300000,108(%esp)

# qhasm:   d2 top = 0x47300000
# asm 1: movl  $0x47300000,>d2=stack64#3
# asm 2: movl  $0x47300000,>d2=116(%esp)
movl  $0x47300000,116(%esp)

# qhasm:   d3 top = 0x49300000
# asm 1: movl  $0x49300000,>d3=stack64#4
# asm 2: movl  $0x49300000,>d3=124(%esp)
movl  $0x49300000,124(%esp)

# qhasm:   m0 &= 0x0fffffff
# asm 1: and  $0x0fffffff,<m0=int32#2
# asm 2: and  $0x0fffffff,<m0=%ecx
and  $0x0fffffff,%ecx

# qhasm:   m1 &= 0x0ffffffc
# asm 1: and  $0x0ffffffc,<m1=int32#4
# asm 2: and  $0x0ffffffc,<m1=%ebx
and  $0x0ffffffc,%ebx

# qhasm:   m2 &= 0x0ffffffc
# asm 1: and  $0x0ffffffc,<m2=int32#5
# asm 2: and  $0x0ffffffc,<m2=%esi
and  $0x0ffffffc,%esi

# qhasm:   m3 &= 0x0ffffffc
# asm 1: and  $0x0ffffffc,<m3=int32#6
# asm 2: and  $0x0ffffffc,<m3=%edi
and  $0x0ffffffc,%edi

# qhasm:   inplace d0 bottom = m0
# asm 1: movl <m0=int32#2,<d0=stack64#1
# asm 2: movl <m0=%ecx,<d0=96(%esp)
movl %ecx,96(%esp)

# qhasm:   inplace d1 bottom = m1
# asm 1: movl <m1=int32#4,<d1=stack64#2
# asm 2: movl <m1=%ebx,<d1=104(%esp)
movl %ebx,104(%esp)

# qhasm:   inplace d2 bottom = m2
# asm 1: movl <m2=int32#5,<d2=stack64#3
# asm 2: movl <m2=%esi,<d2=112(%esp)
movl %esi,112(%esp)

# qhasm:   inplace d3 bottom = m3
# asm 1: movl <m3=int32#6,<d3=stack64#4
# asm 2: movl <m3=%edi,<d3=120(%esp)
movl %edi,120(%esp)

# qhasm:   a0 = *(float64 *) &d0
# asm 1: fldl <d0=stack64#1
# asm 2: fldl <d0=96(%esp)
fldl 96(%esp)
# comment:fpstackfrombottom:<a0#24:

# qhasm:   a0 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset0
fsubl crypto_onetimeauth_poly1305_x86_doffset0
# comment:fpstackfrombottom:<a0#24:

# qhasm:   a1 = *(float64 *) &d1
# asm 1: fldl <d1=stack64#2
# asm 2: fldl <d1=104(%esp)
fldl 104(%esp)
# comment:fpstackfrombottom:<a0#24:<a1#25:

# qhasm:   a1 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset1
fsubl crypto_onetimeauth_poly1305_x86_doffset1
# comment:fpstackfrombottom:<a0#24:<a1#25:

# qhasm:   a2 = *(float64 *) &d2
# asm 1: fldl <d2=stack64#3
# asm 2: fldl <d2=112(%esp)
fldl 112(%esp)
# comment:fpstackfrombottom:<a0#24:<a1#25:<a2#26:

# qhasm:   a2 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset2
fsubl crypto_onetimeauth_poly1305_x86_doffset2
# comment:fpstackfrombottom:<a0#24:<a1#25:<a2#26:

# qhasm:   a3 = *(float64 *) &d3
# asm 1: fldl <d3=stack64#4
# asm 2: fldl <d3=120(%esp)
fldl 120(%esp)
# comment:fpstackfrombottom:<a0#24:<a1#25:<a2#26:<a3#27:

# qhasm:   a3 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset3
fsubl crypto_onetimeauth_poly1305_x86_doffset3
# comment:fpstackfrombottom:<a0#24:<a1#25:<a2#26:<a3#27:

# qhasm: internal stacktop a0
# asm 1: fxch <a0=float80#4
# asm 2: fxch <a0=%st(3)
fxch %st(3)

# qhasm:   *(float64 *) &r0 = a0
# asm 1: fstpl >r0=stack64#5
# asm 2: fstpl >r0=128(%esp)
fstpl 128(%esp)
# comment:fpstackfrombottom:<a3#27:<a1#25:<a2#26:

# qhasm: internal stacktop a1
# asm 1: fxch <a1=float80#2
# asm 2: fxch <a1=%st(1)
fxch %st(1)

# qhasm:   *(float64 *) &r1 = a1
# asm 1: fstl >r1=stack64#6
# asm 2: fstl >r1=136(%esp)
fstl 136(%esp)
# comment:fpstackfrombottom:<a3#27:<a2#26:<a1#25:

# qhasm:   a1 *= *(float64 *) &crypto_onetimeauth_poly1305_x86_scale
fmull crypto_onetimeauth_poly1305_x86_scale
# comment:fpstackfrombottom:<a3#27:<a2#26:<a1#25:

# qhasm:   *(float64 *) &sr1 = a1
# asm 1: fstpl >sr1=stack64#7
# asm 2: fstpl >sr1=144(%esp)
fstpl 144(%esp)
# comment:fpstackfrombottom:<a3#27:<a2#26:

# qhasm:   *(float64 *) &r2 = a2
# asm 1: fstl >r2=stack64#8
# asm 2: fstl >r2=152(%esp)
fstl 152(%esp)
# comment:fpstackfrombottom:<a3#27:<a2#26:

# qhasm:   a2 *= *(float64 *) &crypto_onetimeauth_poly1305_x86_scale
fmull crypto_onetimeauth_poly1305_x86_scale
# comment:fpstackfrombottom:<a3#27:<a2#26:

# qhasm:   *(float64 *) &sr2 = a2
# asm 1: fstpl >sr2=stack64#9
# asm 2: fstpl >sr2=160(%esp)
fstpl 160(%esp)
# comment:fpstackfrombottom:<a3#27:

# qhasm:   *(float64 *) &r3 = a3
# asm 1: fstl >r3=stack64#10
# asm 2: fstl >r3=168(%esp)
fstl 168(%esp)
# comment:fpstackfrombottom:<a3#27:

# qhasm:   a3 *= *(float64 *) &crypto_onetimeauth_poly1305_x86_scale
fmull crypto_onetimeauth_poly1305_x86_scale
# comment:fpstackfrombottom:<a3#27:

# qhasm:   *(float64 *) &sr3 = a3
# asm 1: fstpl >sr3=stack64#11
# asm 2: fstpl >sr3=176(%esp)
fstpl 176(%esp)
# comment:fpstackfrombottom:

# qhasm:   out = arg_out
# asm 1: movl <arg_out=stack32#-1,>out=int32#4
# asm 2: movl <arg_out=4(%esp,%eax),>out=%ebx
movl 4(%esp,%eax),%ebx

# qhasm:   m = arg_m
# asm 1: movl <arg_m=stack32#-2,>m=int32#5
# asm 2: movl <arg_m=8(%esp,%eax),>m=%esi
movl 8(%esp,%eax),%esi

# qhasm:   l = arg_l
# asm 1: movl <arg_l=stack32#-3,>l=int32#2
# asm 2: movl <arg_l=12(%esp,%eax),>l=%ecx
movl 12(%esp,%eax),%ecx

# qhasm:   h3 = 0
fldz
# comment:fpstackfrombottom:<h3#38:

# qhasm:   h2 = 0
fldz
# comment:fpstackfrombottom:<h3#38:<h2#39:

# qhasm:   h1 = 0
fldz
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:

# qhasm:   h0 = 0
fldz
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   k_stack = k
# asm 1: movl <k=int32#3,>k_stack=stack32#6
# asm 2: movl <k=%edx,>k_stack=20(%esp)
movl %edx,20(%esp)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   out_stack = out
# asm 1: movl <out=int32#4,>out_stack=stack32#7
# asm 2: movl <out=%ebx,>out_stack=24(%esp)
movl %ebx,24(%esp)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:                          unsigned<? l - 16
# asm 1: cmp  $16,<l=int32#2
# asm 2: cmp  $16,<l=%ecx
cmp  $16,%ecx
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:
# comment:fp stack unchanged by jump
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm: goto addatmost15bytes if unsigned<
jb ._addatmost15bytes
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm: initialatleast16bytes:
._initialatleast16bytes:
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   m3 = *(uint32 *) (m + 12)
# asm 1: movl 12(<m=int32#5),>m3=int32#1
# asm 2: movl 12(<m=%esi),>m3=%eax
movl 12(%esi),%eax
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   m2 = *(uint32 *) (m + 8)
# asm 1: movl 8(<m=int32#5),>m2=int32#3
# asm 2: movl 8(<m=%esi),>m2=%edx
movl 8(%esi),%edx
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   m1 = *(uint32 *) (m + 4)
# asm 1: movl 4(<m=int32#5),>m1=int32#4
# asm 2: movl 4(<m=%esi),>m1=%ebx
movl 4(%esi),%ebx
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   m0 = *(uint32 *) (m + 0)
# asm 1: movl 0(<m=int32#5),>m0=int32#6
# asm 2: movl 0(<m=%esi),>m0=%edi
movl 0(%esi),%edi
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   inplace d3 bottom = m3
# asm 1: movl <m3=int32#1,<d3=stack64#4
# asm 2: movl <m3=%eax,<d3=120(%esp)
movl %eax,120(%esp)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   inplace d2 bottom = m2
# asm 1: movl <m2=int32#3,<d2=stack64#3
# asm 2: movl <m2=%edx,<d2=112(%esp)
movl %edx,112(%esp)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   inplace d1 bottom = m1
# asm 1: movl <m1=int32#4,<d1=stack64#2
# asm 2: movl <m1=%ebx,<d1=104(%esp)
movl %ebx,104(%esp)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   inplace d0 bottom = m0
# asm 1: movl <m0=int32#6,<d0=stack64#1
# asm 2: movl <m0=%edi,<d0=96(%esp)
movl %edi,96(%esp)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   m += 16
# asm 1: add  $16,<m=int32#5
# asm 2: add  $16,<m=%esi
add  $16,%esi
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   l -= 16
# asm 1: sub  $16,<l=int32#2
# asm 2: sub  $16,<l=%ecx
sub  $16,%ecx
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm: internal stacktop h3
# asm 1: fxch <h3=float80#4
# asm 2: fxch <h3=%st(3)
fxch %st(3)

# qhasm:   h3 += *(float64 *) &d3
# asm 1: faddl <d3=stack64#4
# asm 2: faddl <d3=120(%esp)
faddl 120(%esp)
# comment:fpstackfrombottom:<h0#41:<h2#39:<h1#40:<h3#38:

# qhasm:   h3 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset3minustwo128
fsubl crypto_onetimeauth_poly1305_x86_doffset3minustwo128
# comment:fpstackfrombottom:<h0#41:<h2#39:<h1#40:<h3#38:

# qhasm: internal stacktop h1
# asm 1: fxch <h1=float80#2
# asm 2: fxch <h1=%st(1)
fxch %st(1)

# qhasm:   h1 += *(float64 *) &d1
# asm 1: faddl <d1=stack64#2
# asm 2: faddl <d1=104(%esp)
faddl 104(%esp)
# comment:fpstackfrombottom:<h0#41:<h2#39:<h3#38:<h1#40:

# qhasm:   h1 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset1
fsubl crypto_onetimeauth_poly1305_x86_doffset1
# comment:fpstackfrombottom:<h0#41:<h2#39:<h3#38:<h1#40:

# qhasm: internal stacktop h2
# asm 1: fxch <h2=float80#3
# asm 2: fxch <h2=%st(2)
fxch %st(2)

# qhasm:   h2 += *(float64 *) &d2
# asm 1: faddl <d2=stack64#3
# asm 2: faddl <d2=112(%esp)
faddl 112(%esp)
# comment:fpstackfrombottom:<h0#41:<h1#40:<h3#38:<h2#39:

# qhasm:   h2 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset2
fsubl crypto_onetimeauth_poly1305_x86_doffset2
# comment:fpstackfrombottom:<h0#41:<h1#40:<h3#38:<h2#39:

# qhasm: internal stacktop h0
# asm 1: fxch <h0=float80#4
# asm 2: fxch <h0=%st(3)
fxch %st(3)

# qhasm:   h0 += *(float64 *) &d0
# asm 1: faddl <d0=stack64#1
# asm 2: faddl <d0=96(%esp)
faddl 96(%esp)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:   h0 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset0
fsubl crypto_onetimeauth_poly1305_x86_doffset0
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:                                  unsigned<? l - 16
# asm 1: cmp  $16,<l=int32#2
# asm 2: cmp  $16,<l=%ecx
cmp  $16,%ecx
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:
# comment:fp stack unchanged by jump
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm: goto multiplyaddatmost15bytes if unsigned<
jb ._multiplyaddatmost15bytes
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm: multiplyaddatleast16bytes:
._multiplyaddatleast16bytes:
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:   m3 = *(uint32 *) (m + 12)
# asm 1: movl 12(<m=int32#5),>m3=int32#1
# asm 2: movl 12(<m=%esi),>m3=%eax
movl 12(%esi),%eax
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:   m2 = *(uint32 *) (m + 8)
# asm 1: movl 8(<m=int32#5),>m2=int32#3
# asm 2: movl 8(<m=%esi),>m2=%edx
movl 8(%esi),%edx
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:   m1 = *(uint32 *) (m + 4)
# asm 1: movl 4(<m=int32#5),>m1=int32#4
# asm 2: movl 4(<m=%esi),>m1=%ebx
movl 4(%esi),%ebx
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:   m0 = *(uint32 *) (m + 0)
# asm 1: movl 0(<m=int32#5),>m0=int32#6
# asm 2: movl 0(<m=%esi),>m0=%edi
movl 0(%esi),%edi
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:   inplace d3 bottom = m3
# asm 1: movl <m3=int32#1,<d3=stack64#4
# asm 2: movl <m3=%eax,<d3=120(%esp)
movl %eax,120(%esp)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:   inplace d2 bottom = m2
# asm 1: movl <m2=int32#3,<d2=stack64#3
# asm 2: movl <m2=%edx,<d2=112(%esp)
movl %edx,112(%esp)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:   inplace d1 bottom = m1
# asm 1: movl <m1=int32#4,<d1=stack64#2
# asm 2: movl <m1=%ebx,<d1=104(%esp)
movl %ebx,104(%esp)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:   inplace d0 bottom = m0
# asm 1: movl <m0=int32#6,<d0=stack64#1
# asm 2: movl <m0=%edi,<d0=96(%esp)
movl %edi,96(%esp)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:   m += 16
# asm 1: add  $16,<m=int32#5
# asm 2: add  $16,<m=%esi
add  $16,%esi
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:   l -= 16
# asm 1: sub  $16,<l=int32#2
# asm 2: sub  $16,<l=%ecx
sub  $16,%ecx
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:   x0 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha130
fldl crypto_onetimeauth_poly1305_x86_alpha130
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#54:

# qhasm:   x0 += h3
# asm 1: fadd <h3=float80#3,<x0=float80#1
# asm 2: fadd <h3=%st(2),<x0=%st(0)
fadd %st(2),%st(0)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#54:

# qhasm:   x0 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha130
fsubl crypto_onetimeauth_poly1305_x86_alpha130
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#54:

# qhasm:   h3 -= x0
# asm 1: fsubr <x0=float80#1,<h3=float80#3
# asm 2: fsubr <x0=%st(0),<h3=%st(2)
fsubr %st(0),%st(2)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#54:

# qhasm:   x0 *= *(float64 *) &crypto_onetimeauth_poly1305_x86_scale
fmull crypto_onetimeauth_poly1305_x86_scale
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#54:

# qhasm:   x1 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha32
fldl crypto_onetimeauth_poly1305_x86_alpha32
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#54:<x1#55:

# qhasm:   x1 += h0
# asm 1: fadd <h0=float80#3,<x1=float80#1
# asm 2: fadd <h0=%st(2),<x1=%st(0)
fadd %st(2),%st(0)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#54:<x1#55:

# qhasm:   x1 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha32
fsubl crypto_onetimeauth_poly1305_x86_alpha32
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#54:<x1#55:

# qhasm:   h0 -= x1
# asm 1: fsubr <x1=float80#1,<h0=float80#3
# asm 2: fsubr <x1=%st(0),<h0=%st(2)
fsubr %st(0),%st(2)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#54:<x1#55:

# qhasm: internal stacktop h0
# asm 1: fxch <h0=float80#3
# asm 2: fxch <h0=%st(2)
fxch %st(2)

# qhasm:   x0 += h0
# asm 1: faddp <h0=float80#1,<x0=float80#2
# asm 2: faddp <h0=%st(0),<x0=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<x1#55:<x0#54:

# qhasm:   x2 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha64
fldl crypto_onetimeauth_poly1305_x86_alpha64
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<x1#55:<x0#54:<x2#56:

# qhasm:   x2 += h1
# asm 1: fadd <h1=float80#5,<x2=float80#1
# asm 2: fadd <h1=%st(4),<x2=%st(0)
fadd %st(4),%st(0)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<x1#55:<x0#54:<x2#56:

# qhasm:   x2 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha64
fsubl crypto_onetimeauth_poly1305_x86_alpha64
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<x1#55:<x0#54:<x2#56:

# qhasm:   h1 -= x2
# asm 1: fsubr <x2=float80#1,<h1=float80#5
# asm 2: fsubr <x2=%st(0),<h1=%st(4)
fsubr %st(0),%st(4)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<x1#55:<x0#54:<x2#56:

# qhasm:   x3 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha96
fldl crypto_onetimeauth_poly1305_x86_alpha96
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<x1#55:<x0#54:<x2#56:<x3#57:

# qhasm:   x3 += h2
# asm 1: fadd <h2=float80#7,<x3=float80#1
# asm 2: fadd <h2=%st(6),<x3=%st(0)
fadd %st(6),%st(0)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<x1#55:<x0#54:<x2#56:<x3#57:

# qhasm:   x3 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha96
fsubl crypto_onetimeauth_poly1305_x86_alpha96
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<x1#55:<x0#54:<x2#56:<x3#57:

# qhasm:   h2 -= x3
# asm 1: fsubr <x3=float80#1,<h2=float80#7
# asm 2: fsubr <x3=%st(0),<h2=%st(6)
fsubr %st(0),%st(6)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<x1#55:<x0#54:<x2#56:<x3#57:

# qhasm: internal stacktop h2
# asm 1: fxch <h2=float80#7
# asm 2: fxch <h2=%st(6)
fxch %st(6)

# qhasm:   x2 += h2
# asm 1: faddp <h2=float80#1,<x2=float80#2
# asm 2: faddp <h2=%st(0),<x2=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#57:<h1#40:<h3#38:<x1#55:<x0#54:<x2#56:

# qhasm: internal stacktop h3
# asm 1: fxch <h3=float80#4
# asm 2: fxch <h3=%st(3)
fxch %st(3)

# qhasm:   x3 += h3
# asm 1: faddp <h3=float80#1,<x3=float80#6
# asm 2: faddp <h3=%st(0),<x3=%st(5)
faddp %st(0),%st(5)
# comment:fpstackfrombottom:<x3#57:<h1#40:<x2#56:<x1#55:<x0#54:

# qhasm: internal stacktop h1
# asm 1: fxch <h1=float80#4
# asm 2: fxch <h1=%st(3)
fxch %st(3)

# qhasm:   x1 += h1
# asm 1: faddp <h1=float80#1,<x1=float80#2
# asm 2: faddp <h1=%st(0),<x1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#57:<x0#54:<x2#56:<x1#55:

# qhasm:   h3 = *(float64 *) &r3
# asm 1: fldl <r3=stack64#10
# asm 2: fldl <r3=168(%esp)
fldl 168(%esp)
# comment:fpstackfrombottom:<x3#57:<x0#54:<x2#56:<x1#55:<h3#38:

# qhasm:   h3 *= x0
# asm 1: fmul <x0=float80#4,<h3=float80#1
# asm 2: fmul <x0=%st(3),<h3=%st(0)
fmul %st(3),%st(0)
# comment:fpstackfrombottom:<x3#57:<x0#54:<x2#56:<x1#55:<h3#38:

# qhasm:   h2 = *(float64 *) &r2
# asm 1: fldl <r2=stack64#8
# asm 2: fldl <r2=152(%esp)
fldl 152(%esp)
# comment:fpstackfrombottom:<x3#57:<x0#54:<x2#56:<x1#55:<h3#38:<h2#39:

# qhasm:   h2 *= x0
# asm 1: fmul <x0=float80#5,<h2=float80#1
# asm 2: fmul <x0=%st(4),<h2=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x3#57:<x0#54:<x2#56:<x1#55:<h3#38:<h2#39:

# qhasm:   h1 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#6
# asm 2: fldl <r1=136(%esp)
fldl 136(%esp)
# comment:fpstackfrombottom:<x3#57:<x0#54:<x2#56:<x1#55:<h3#38:<h2#39:<h1#40:

# qhasm:   h1 *= x0
# asm 1: fmul <x0=float80#6,<h1=float80#1
# asm 2: fmul <x0=%st(5),<h1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#57:<x0#54:<x2#56:<x1#55:<h3#38:<h2#39:<h1#40:

# qhasm:   h0 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#5
# asm 2: fldl <r0=128(%esp)
fldl 128(%esp)
# comment:fpstackfrombottom:<x3#57:<x0#54:<x2#56:<x1#55:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   h0 *= x0
# asm 1: fmulp <x0=float80#1,<h0=float80#7
# asm 2: fmulp <x0=%st(0),<h0=%st(6)
fmulp %st(0),%st(6)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<x1#55:<h3#38:<h2#39:<h1#40:

# qhasm:   r2x1 = *(float64 *) &r2
# asm 1: fldl <r2=stack64#8
# asm 2: fldl <r2=152(%esp)
fldl 152(%esp)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<x1#55:<h3#38:<h2#39:<h1#40:<r2x1#58:

# qhasm:   r2x1 *= x1
# asm 1: fmul <x1=float80#5,<r2x1=float80#1
# asm 2: fmul <x1=%st(4),<r2x1=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<x1#55:<h3#38:<h2#39:<h1#40:<r2x1#58:

# qhasm:   h3 += r2x1
# asm 1: faddp <r2x1=float80#1,<h3=float80#4
# asm 2: faddp <r2x1=%st(0),<h3=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<x1#55:<h3#38:<h2#39:<h1#40:

# qhasm:   r1x1 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#6
# asm 2: fldl <r1=136(%esp)
fldl 136(%esp)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<x1#55:<h3#38:<h2#39:<h1#40:<r1x1#59:

# qhasm:   r1x1 *= x1
# asm 1: fmul <x1=float80#5,<r1x1=float80#1
# asm 2: fmul <x1=%st(4),<r1x1=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<x1#55:<h3#38:<h2#39:<h1#40:<r1x1#59:

# qhasm:   h2 += r1x1
# asm 1: faddp <r1x1=float80#1,<h2=float80#3
# asm 2: faddp <r1x1=%st(0),<h2=%st(2)
faddp %st(0),%st(2)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<x1#55:<h3#38:<h2#39:<h1#40:

# qhasm:   r0x1 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#5
# asm 2: fldl <r0=128(%esp)
fldl 128(%esp)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<x1#55:<h3#38:<h2#39:<h1#40:<r0x1#60:

# qhasm:   r0x1 *= x1
# asm 1: fmul <x1=float80#5,<r0x1=float80#1
# asm 2: fmul <x1=%st(4),<r0x1=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<x1#55:<h3#38:<h2#39:<h1#40:<r0x1#60:

# qhasm:   h1 += r0x1
# asm 1: faddp <r0x1=float80#1,<h1=float80#2
# asm 2: faddp <r0x1=%st(0),<h1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<x1#55:<h3#38:<h2#39:<h1#40:

# qhasm:   sr3x1 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#11
# asm 2: fldl <sr3=176(%esp)
fldl 176(%esp)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<x1#55:<h3#38:<h2#39:<h1#40:<sr3x1#61:

# qhasm:   sr3x1 *= x1
# asm 1: fmulp <x1=float80#1,<sr3x1=float80#5
# asm 2: fmulp <x1=%st(0),<sr3x1=%st(4)
fmulp %st(0),%st(4)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<sr3x1#61:<h3#38:<h2#39:<h1#40:

# qhasm: internal stacktop sr3x1
# asm 1: fxch <sr3x1=float80#4
# asm 2: fxch <sr3x1=%st(3)
fxch %st(3)

# qhasm:   h0 += sr3x1
# asm 1: faddp <sr3x1=float80#1,<h0=float80#6
# asm 2: faddp <sr3x1=%st(0),<h0=%st(5)
faddp %st(0),%st(5)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<h1#40:<h3#38:<h2#39:

# qhasm:   r1x2 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#6
# asm 2: fldl <r1=136(%esp)
fldl 136(%esp)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<h1#40:<h3#38:<h2#39:<r1x2#62:

# qhasm:   r1x2 *= x2
# asm 1: fmul <x2=float80#5,<r1x2=float80#1
# asm 2: fmul <x2=%st(4),<r1x2=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<h1#40:<h3#38:<h2#39:<r1x2#62:

# qhasm:   h3 += r1x2
# asm 1: faddp <r1x2=float80#1,<h3=float80#3
# asm 2: faddp <r1x2=%st(0),<h3=%st(2)
faddp %st(0),%st(2)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<h1#40:<h3#38:<h2#39:

# qhasm:   r0x2 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#5
# asm 2: fldl <r0=128(%esp)
fldl 128(%esp)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<h1#40:<h3#38:<h2#39:<r0x2#63:

# qhasm:   r0x2 *= x2
# asm 1: fmul <x2=float80#5,<r0x2=float80#1
# asm 2: fmul <x2=%st(4),<r0x2=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<h1#40:<h3#38:<h2#39:<r0x2#63:

# qhasm:   h2 += r0x2
# asm 1: faddp <r0x2=float80#1,<h2=float80#2
# asm 2: faddp <r0x2=%st(0),<h2=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<h1#40:<h3#38:<h2#39:

# qhasm:   sr3x2 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#11
# asm 2: fldl <sr3=176(%esp)
fldl 176(%esp)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<h1#40:<h3#38:<h2#39:<sr3x2#64:

# qhasm:   sr3x2 *= x2
# asm 1: fmul <x2=float80#5,<sr3x2=float80#1
# asm 2: fmul <x2=%st(4),<sr3x2=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<h1#40:<h3#38:<h2#39:<sr3x2#64:

# qhasm:   h1 += sr3x2
# asm 1: faddp <sr3x2=float80#1,<h1=float80#4
# asm 2: faddp <sr3x2=%st(0),<h1=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<h1#40:<h3#38:<h2#39:

# qhasm:   sr2x2 = *(float64 *) &sr2
# asm 1: fldl <sr2=stack64#9
# asm 2: fldl <sr2=160(%esp)
fldl 160(%esp)
# comment:fpstackfrombottom:<x3#57:<h0#41:<x2#56:<h1#40:<h3#38:<h2#39:<sr2x2#65:

# qhasm:   sr2x2 *= x2
# asm 1: fmulp <x2=float80#1,<sr2x2=float80#5
# asm 2: fmulp <x2=%st(0),<sr2x2=%st(4)
fmulp %st(0),%st(4)
# comment:fpstackfrombottom:<x3#57:<h0#41:<sr2x2#65:<h1#40:<h3#38:<h2#39:

# qhasm: internal stacktop sr2x2
# asm 1: fxch <sr2x2=float80#4
# asm 2: fxch <sr2x2=%st(3)
fxch %st(3)

# qhasm:   h0 += sr2x2
# asm 1: faddp <sr2x2=float80#1,<h0=float80#5
# asm 2: faddp <sr2x2=%st(0),<h0=%st(4)
faddp %st(0),%st(4)
# comment:fpstackfrombottom:<x3#57:<h0#41:<h2#39:<h1#40:<h3#38:

# qhasm:   r0x3 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#5
# asm 2: fldl <r0=128(%esp)
fldl 128(%esp)
# comment:fpstackfrombottom:<x3#57:<h0#41:<h2#39:<h1#40:<h3#38:<r0x3#66:

# qhasm:   r0x3 *= x3
# asm 1: fmul <x3=float80#6,<r0x3=float80#1
# asm 2: fmul <x3=%st(5),<r0x3=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#57:<h0#41:<h2#39:<h1#40:<h3#38:<r0x3#66:

# qhasm:   h3 += r0x3
# asm 1: faddp <r0x3=float80#1,<h3=float80#2
# asm 2: faddp <r0x3=%st(0),<h3=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#57:<h0#41:<h2#39:<h1#40:<h3#38:

# qhasm:   stacktop h0
# asm 1: fxch <h0=float80#4
# asm 2: fxch <h0=%st(3)
fxch %st(3)
# comment:fpstackfrombottom:<x3#57:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   sr3x3 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#11
# asm 2: fldl <sr3=176(%esp)
fldl 176(%esp)
# comment:fpstackfrombottom:<x3#57:<h3#38:<h2#39:<h1#40:<h0#41:<sr3x3#67:

# qhasm:   sr3x3 *= x3
# asm 1: fmul <x3=float80#6,<sr3x3=float80#1
# asm 2: fmul <x3=%st(5),<sr3x3=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#57:<h3#38:<h2#39:<h1#40:<h0#41:<sr3x3#67:

# qhasm:   h2 += sr3x3
# asm 1: faddp <sr3x3=float80#1,<h2=float80#4
# asm 2: faddp <sr3x3=%st(0),<h2=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x3#57:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   stacktop h1
# asm 1: fxch <h1=float80#2
# asm 2: fxch <h1=%st(1)
fxch %st(1)
# comment:fpstackfrombottom:<x3#57:<h3#38:<h2#39:<h0#41:<h1#40:

# qhasm:   sr2x3 = *(float64 *) &sr2
# asm 1: fldl <sr2=stack64#9
# asm 2: fldl <sr2=160(%esp)
fldl 160(%esp)
# comment:fpstackfrombottom:<x3#57:<h3#38:<h2#39:<h0#41:<h1#40:<sr2x3#68:

# qhasm:   sr2x3 *= x3
# asm 1: fmul <x3=float80#6,<sr2x3=float80#1
# asm 2: fmul <x3=%st(5),<sr2x3=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#57:<h3#38:<h2#39:<h0#41:<h1#40:<sr2x3#68:

# qhasm:   h1 += sr2x3
# asm 1: faddp <sr2x3=float80#1,<h1=float80#2
# asm 2: faddp <sr2x3=%st(0),<h1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#57:<h3#38:<h2#39:<h0#41:<h1#40:

# qhasm:   sr1x3 = *(float64 *) &sr1
# asm 1: fldl <sr1=stack64#7
# asm 2: fldl <sr1=144(%esp)
fldl 144(%esp)
# comment:fpstackfrombottom:<x3#57:<h3#38:<h2#39:<h0#41:<h1#40:<sr1x3#69:

# qhasm:   sr1x3 *= x3
# asm 1: fmulp <x3=float80#1,<sr1x3=float80#6
# asm 2: fmulp <x3=%st(0),<sr1x3=%st(5)
fmulp %st(0),%st(5)
# comment:fpstackfrombottom:<sr1x3#69:<h3#38:<h2#39:<h0#41:<h1#40:

# qhasm: internal stacktop sr1x3
# asm 1: fxch <sr1x3=float80#5
# asm 2: fxch <sr1x3=%st(4)
fxch %st(4)

# qhasm:   h0 += sr1x3
# asm 1: faddp <sr1x3=float80#1,<h0=float80#2
# asm 2: faddp <sr1x3=%st(0),<h0=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:

# qhasm:                                    unsigned<? l - 16
# asm 1: cmp  $16,<l=int32#2
# asm 2: cmp  $16,<l=%ecx
cmp  $16,%ecx
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:

# qhasm:   stacktop h3
# asm 1: fxch <h3=float80#3
# asm 2: fxch <h3=%st(2)
fxch %st(2)
# comment:fpstackfrombottom:<h1#40:<h0#41:<h2#39:<h3#38:

# qhasm:   y3 = *(float64 *) &d3
# asm 1: fldl <d3=stack64#4
# asm 2: fldl <d3=120(%esp)
fldl 120(%esp)
# comment:fpstackfrombottom:<h1#40:<h0#41:<h2#39:<h3#38:<y3#71:

# qhasm:   y3 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset3minustwo128
fsubl crypto_onetimeauth_poly1305_x86_doffset3minustwo128
# comment:fpstackfrombottom:<h1#40:<h0#41:<h2#39:<h3#38:<y3#71:

# qhasm:   h3 += y3
# asm 1: faddp <y3=float80#1,<h3=float80#2
# asm 2: faddp <y3=%st(0),<h3=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h1#40:<h0#41:<h2#39:<h3#38:

# qhasm:   stacktop h2
# asm 1: fxch <h2=float80#2
# asm 2: fxch <h2=%st(1)
fxch %st(1)
# comment:fpstackfrombottom:<h1#40:<h0#41:<h3#38:<h2#39:

# qhasm:   y2 = *(float64 *) &d2
# asm 1: fldl <d2=stack64#3
# asm 2: fldl <d2=112(%esp)
fldl 112(%esp)
# comment:fpstackfrombottom:<h1#40:<h0#41:<h3#38:<h2#39:<y2#72:

# qhasm:   y2 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset2
fsubl crypto_onetimeauth_poly1305_x86_doffset2
# comment:fpstackfrombottom:<h1#40:<h0#41:<h3#38:<h2#39:<y2#72:

# qhasm:   h2 += y2
# asm 1: faddp <y2=float80#1,<h2=float80#2
# asm 2: faddp <y2=%st(0),<h2=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h1#40:<h0#41:<h3#38:<h2#39:

# qhasm:   stacktop h1
# asm 1: fxch <h1=float80#4
# asm 2: fxch <h1=%st(3)
fxch %st(3)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h3#38:<h1#40:

# qhasm:   y1 = *(float64 *) &d1
# asm 1: fldl <d1=stack64#2
# asm 2: fldl <d1=104(%esp)
fldl 104(%esp)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h3#38:<h1#40:<y1#73:

# qhasm:   y1 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset1
fsubl crypto_onetimeauth_poly1305_x86_doffset1
# comment:fpstackfrombottom:<h2#39:<h0#41:<h3#38:<h1#40:<y1#73:

# qhasm:   h1 += y1
# asm 1: faddp <y1=float80#1,<h1=float80#2
# asm 2: faddp <y1=%st(0),<h1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h3#38:<h1#40:

# qhasm:   stacktop h0
# asm 1: fxch <h0=float80#3
# asm 2: fxch <h0=%st(2)
fxch %st(2)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:   y0 = *(float64 *) &d0
# asm 1: fldl <d0=stack64#1
# asm 2: fldl <d0=96(%esp)
fldl 96(%esp)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<y0#74:

# qhasm:   y0 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset0
fsubl crypto_onetimeauth_poly1305_x86_doffset0
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<y0#74:

# qhasm:   h0 += y0
# asm 1: faddp <y0=float80#1,<h0=float80#2
# asm 2: faddp <y0=%st(0),<h0=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:
# comment:fp stack unchanged by jump
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm: goto multiplyaddatleast16bytes if !unsigned<
jae ._multiplyaddatleast16bytes
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:
# comment:fp stack unchanged by fallthrough
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm: multiplyaddatmost15bytes:
._multiplyaddatmost15bytes:
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:

# qhasm:   x0 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha130
fldl crypto_onetimeauth_poly1305_x86_alpha130
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:

# qhasm:   x0 += h3
# asm 1: fadd <h3=float80#3,<x0=float80#1
# asm 2: fadd <h3=%st(2),<x0=%st(0)
fadd %st(2),%st(0)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:

# qhasm:   x0 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha130
fsubl crypto_onetimeauth_poly1305_x86_alpha130
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:

# qhasm:   h3 -= x0
# asm 1: fsubr <x0=float80#1,<h3=float80#3
# asm 2: fsubr <x0=%st(0),<h3=%st(2)
fsubr %st(0),%st(2)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:

# qhasm:   x0 *= *(float64 *) &crypto_onetimeauth_poly1305_x86_scale
fmull crypto_onetimeauth_poly1305_x86_scale
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:

# qhasm:   x1 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha32
fldl crypto_onetimeauth_poly1305_x86_alpha32
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:<x1#76:

# qhasm:   x1 += h0
# asm 1: fadd <h0=float80#3,<x1=float80#1
# asm 2: fadd <h0=%st(2),<x1=%st(0)
fadd %st(2),%st(0)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:<x1#76:

# qhasm:   x1 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha32
fsubl crypto_onetimeauth_poly1305_x86_alpha32
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:<x1#76:

# qhasm:   h0 -= x1
# asm 1: fsubr <x1=float80#1,<h0=float80#3
# asm 2: fsubr <x1=%st(0),<h0=%st(2)
fsubr %st(0),%st(2)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:<x1#76:

# qhasm:   x2 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha64
fldl crypto_onetimeauth_poly1305_x86_alpha64
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:<x1#76:<x2#77:

# qhasm:   x2 += h1
# asm 1: fadd <h1=float80#6,<x2=float80#1
# asm 2: fadd <h1=%st(5),<x2=%st(0)
fadd %st(5),%st(0)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:<x1#76:<x2#77:

# qhasm:   x2 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha64
fsubl crypto_onetimeauth_poly1305_x86_alpha64
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:<x1#76:<x2#77:

# qhasm:   h1 -= x2
# asm 1: fsubr <x2=float80#1,<h1=float80#6
# asm 2: fsubr <x2=%st(0),<h1=%st(5)
fsubr %st(0),%st(5)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:<x1#76:<x2#77:

# qhasm:   x3 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha96
fldl crypto_onetimeauth_poly1305_x86_alpha96
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:<x1#76:<x2#77:<x3#78:

# qhasm:   x3 += h2
# asm 1: fadd <h2=float80#8,<x3=float80#1
# asm 2: fadd <h2=%st(7),<x3=%st(0)
fadd %st(7),%st(0)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:<x1#76:<x2#77:<x3#78:

# qhasm:   x3 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha96
fsubl crypto_onetimeauth_poly1305_x86_alpha96
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:<x1#76:<x2#77:<x3#78:

# qhasm:   h2 -= x3
# asm 1: fsubr <x3=float80#1,<h2=float80#8
# asm 2: fsubr <x3=%st(0),<h2=%st(7)
fsubr %st(0),%st(7)
# comment:fpstackfrombottom:<h2#39:<h1#40:<h3#38:<h0#41:<x0#75:<x1#76:<x2#77:<x3#78:

# qhasm: internal stacktop h2
# asm 1: fxch <h2=float80#8
# asm 2: fxch <h2=%st(7)
fxch %st(7)

# qhasm:   x2 += h2
# asm 1: faddp <h2=float80#1,<x2=float80#2
# asm 2: faddp <h2=%st(0),<x2=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#78:<h1#40:<h3#38:<h0#41:<x0#75:<x1#76:<x2#77:

# qhasm: internal stacktop h1
# asm 1: fxch <h1=float80#6
# asm 2: fxch <h1=%st(5)
fxch %st(5)

# qhasm:   x1 += h1
# asm 1: faddp <h1=float80#1,<x1=float80#2
# asm 2: faddp <h1=%st(0),<x1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#78:<x2#77:<h3#38:<h0#41:<x0#75:<x1#76:

# qhasm: internal stacktop h3
# asm 1: fxch <h3=float80#4
# asm 2: fxch <h3=%st(3)
fxch %st(3)

# qhasm:   x3 += h3
# asm 1: faddp <h3=float80#1,<x3=float80#6
# asm 2: faddp <h3=%st(0),<x3=%st(5)
faddp %st(0),%st(5)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<h0#41:<x0#75:

# qhasm:   x0 += h0
# asm 1: faddp <h0=float80#1,<x0=float80#2
# asm 2: faddp <h0=%st(0),<x0=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<x0#75:

# qhasm:   h3 = *(float64 *) &r3
# asm 1: fldl <r3=stack64#10
# asm 2: fldl <r3=168(%esp)
fldl 168(%esp)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<x0#75:<h3#38:

# qhasm:   h3 *= x0
# asm 1: fmul <x0=float80#2,<h3=float80#1
# asm 2: fmul <x0=%st(1),<h3=%st(0)
fmul %st(1),%st(0)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<x0#75:<h3#38:

# qhasm:   h2 = *(float64 *) &r2
# asm 1: fldl <r2=stack64#8
# asm 2: fldl <r2=152(%esp)
fldl 152(%esp)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<x0#75:<h3#38:<h2#39:

# qhasm:   h2 *= x0
# asm 1: fmul <x0=float80#3,<h2=float80#1
# asm 2: fmul <x0=%st(2),<h2=%st(0)
fmul %st(2),%st(0)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<x0#75:<h3#38:<h2#39:

# qhasm:   h1 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#6
# asm 2: fldl <r1=136(%esp)
fldl 136(%esp)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<x0#75:<h3#38:<h2#39:<h1#40:

# qhasm:   h1 *= x0
# asm 1: fmul <x0=float80#4,<h1=float80#1
# asm 2: fmul <x0=%st(3),<h1=%st(0)
fmul %st(3),%st(0)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<x0#75:<h3#38:<h2#39:<h1#40:

# qhasm:   h0 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#5
# asm 2: fldl <r0=128(%esp)
fldl 128(%esp)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<x0#75:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   h0 *= x0
# asm 1: fmulp <x0=float80#1,<h0=float80#5
# asm 2: fmulp <x0=%st(0),<h0=%st(4)
fmulp %st(0),%st(4)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<h0#41:<h3#38:<h2#39:<h1#40:

# qhasm:   r2x1 = *(float64 *) &r2
# asm 1: fldl <r2=stack64#8
# asm 2: fldl <r2=152(%esp)
fldl 152(%esp)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<h0#41:<h3#38:<h2#39:<h1#40:<r2x1#79:

# qhasm:   r2x1 *= x1
# asm 1: fmul <x1=float80#6,<r2x1=float80#1
# asm 2: fmul <x1=%st(5),<r2x1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<h0#41:<h3#38:<h2#39:<h1#40:<r2x1#79:

# qhasm:   h3 += r2x1
# asm 1: faddp <r2x1=float80#1,<h3=float80#4
# asm 2: faddp <r2x1=%st(0),<h3=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<h0#41:<h3#38:<h2#39:<h1#40:

# qhasm:   r1x1 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#6
# asm 2: fldl <r1=136(%esp)
fldl 136(%esp)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<h0#41:<h3#38:<h2#39:<h1#40:<r1x1#80:

# qhasm:   r1x1 *= x1
# asm 1: fmul <x1=float80#6,<r1x1=float80#1
# asm 2: fmul <x1=%st(5),<r1x1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<h0#41:<h3#38:<h2#39:<h1#40:<r1x1#80:

# qhasm:   h2 += r1x1
# asm 1: faddp <r1x1=float80#1,<h2=float80#3
# asm 2: faddp <r1x1=%st(0),<h2=%st(2)
faddp %st(0),%st(2)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<h0#41:<h3#38:<h2#39:<h1#40:

# qhasm:   r0x1 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#5
# asm 2: fldl <r0=128(%esp)
fldl 128(%esp)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<h0#41:<h3#38:<h2#39:<h1#40:<r0x1#81:

# qhasm:   r0x1 *= x1
# asm 1: fmul <x1=float80#6,<r0x1=float80#1
# asm 2: fmul <x1=%st(5),<r0x1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<h0#41:<h3#38:<h2#39:<h1#40:<r0x1#81:

# qhasm:   h1 += r0x1
# asm 1: faddp <r0x1=float80#1,<h1=float80#2
# asm 2: faddp <r0x1=%st(0),<h1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<h0#41:<h3#38:<h2#39:<h1#40:

# qhasm:   sr3x1 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#11
# asm 2: fldl <sr3=176(%esp)
fldl 176(%esp)
# comment:fpstackfrombottom:<x3#78:<x2#77:<x1#76:<h0#41:<h3#38:<h2#39:<h1#40:<sr3x1#82:

# qhasm:   sr3x1 *= x1
# asm 1: fmulp <x1=float80#1,<sr3x1=float80#6
# asm 2: fmulp <x1=%st(0),<sr3x1=%st(5)
fmulp %st(0),%st(5)
# comment:fpstackfrombottom:<x3#78:<x2#77:<sr3x1#82:<h0#41:<h3#38:<h2#39:<h1#40:

# qhasm: internal stacktop sr3x1
# asm 1: fxch <sr3x1=float80#5
# asm 2: fxch <sr3x1=%st(4)
fxch %st(4)

# qhasm:   h0 += sr3x1
# asm 1: faddp <sr3x1=float80#1,<h0=float80#4
# asm 2: faddp <sr3x1=%st(0),<h0=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x3#78:<x2#77:<h1#40:<h0#41:<h3#38:<h2#39:

# qhasm:   r1x2 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#6
# asm 2: fldl <r1=136(%esp)
fldl 136(%esp)
# comment:fpstackfrombottom:<x3#78:<x2#77:<h1#40:<h0#41:<h3#38:<h2#39:<r1x2#83:

# qhasm:   r1x2 *= x2
# asm 1: fmul <x2=float80#6,<r1x2=float80#1
# asm 2: fmul <x2=%st(5),<r1x2=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#78:<x2#77:<h1#40:<h0#41:<h3#38:<h2#39:<r1x2#83:

# qhasm:   h3 += r1x2
# asm 1: faddp <r1x2=float80#1,<h3=float80#3
# asm 2: faddp <r1x2=%st(0),<h3=%st(2)
faddp %st(0),%st(2)
# comment:fpstackfrombottom:<x3#78:<x2#77:<h1#40:<h0#41:<h3#38:<h2#39:

# qhasm:   r0x2 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#5
# asm 2: fldl <r0=128(%esp)
fldl 128(%esp)
# comment:fpstackfrombottom:<x3#78:<x2#77:<h1#40:<h0#41:<h3#38:<h2#39:<r0x2#84:

# qhasm:   r0x2 *= x2
# asm 1: fmul <x2=float80#6,<r0x2=float80#1
# asm 2: fmul <x2=%st(5),<r0x2=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#78:<x2#77:<h1#40:<h0#41:<h3#38:<h2#39:<r0x2#84:

# qhasm:   h2 += r0x2
# asm 1: faddp <r0x2=float80#1,<h2=float80#2
# asm 2: faddp <r0x2=%st(0),<h2=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#78:<x2#77:<h1#40:<h0#41:<h3#38:<h2#39:

# qhasm:   sr3x2 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#11
# asm 2: fldl <sr3=176(%esp)
fldl 176(%esp)
# comment:fpstackfrombottom:<x3#78:<x2#77:<h1#40:<h0#41:<h3#38:<h2#39:<sr3x2#85:

# qhasm:   sr3x2 *= x2
# asm 1: fmul <x2=float80#6,<sr3x2=float80#1
# asm 2: fmul <x2=%st(5),<sr3x2=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#78:<x2#77:<h1#40:<h0#41:<h3#38:<h2#39:<sr3x2#85:

# qhasm:   h1 += sr3x2
# asm 1: faddp <sr3x2=float80#1,<h1=float80#5
# asm 2: faddp <sr3x2=%st(0),<h1=%st(4)
faddp %st(0),%st(4)
# comment:fpstackfrombottom:<x3#78:<x2#77:<h1#40:<h0#41:<h3#38:<h2#39:

# qhasm:   sr2x2 = *(float64 *) &sr2
# asm 1: fldl <sr2=stack64#9
# asm 2: fldl <sr2=160(%esp)
fldl 160(%esp)
# comment:fpstackfrombottom:<x3#78:<x2#77:<h1#40:<h0#41:<h3#38:<h2#39:<sr2x2#86:

# qhasm:   sr2x2 *= x2
# asm 1: fmulp <x2=float80#1,<sr2x2=float80#6
# asm 2: fmulp <x2=%st(0),<sr2x2=%st(5)
fmulp %st(0),%st(5)
# comment:fpstackfrombottom:<x3#78:<sr2x2#86:<h1#40:<h0#41:<h3#38:<h2#39:

# qhasm: internal stacktop sr2x2
# asm 1: fxch <sr2x2=float80#5
# asm 2: fxch <sr2x2=%st(4)
fxch %st(4)

# qhasm:   h0 += sr2x2
# asm 1: faddp <sr2x2=float80#1,<h0=float80#3
# asm 2: faddp <sr2x2=%st(0),<h0=%st(2)
faddp %st(0),%st(2)
# comment:fpstackfrombottom:<x3#78:<h2#39:<h1#40:<h0#41:<h3#38:

# qhasm:   r0x3 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#5
# asm 2: fldl <r0=128(%esp)
fldl 128(%esp)
# comment:fpstackfrombottom:<x3#78:<h2#39:<h1#40:<h0#41:<h3#38:<r0x3#87:

# qhasm:   r0x3 *= x3
# asm 1: fmul <x3=float80#6,<r0x3=float80#1
# asm 2: fmul <x3=%st(5),<r0x3=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#78:<h2#39:<h1#40:<h0#41:<h3#38:<r0x3#87:

# qhasm:   h3 += r0x3
# asm 1: faddp <r0x3=float80#1,<h3=float80#2
# asm 2: faddp <r0x3=%st(0),<h3=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x3#78:<h2#39:<h1#40:<h0#41:<h3#38:

# qhasm:   sr3x3 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#11
# asm 2: fldl <sr3=176(%esp)
fldl 176(%esp)
# comment:fpstackfrombottom:<x3#78:<h2#39:<h1#40:<h0#41:<h3#38:<sr3x3#88:

# qhasm:   sr3x3 *= x3
# asm 1: fmul <x3=float80#6,<sr3x3=float80#1
# asm 2: fmul <x3=%st(5),<sr3x3=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#78:<h2#39:<h1#40:<h0#41:<h3#38:<sr3x3#88:

# qhasm:   h2 += sr3x3
# asm 1: faddp <sr3x3=float80#1,<h2=float80#5
# asm 2: faddp <sr3x3=%st(0),<h2=%st(4)
faddp %st(0),%st(4)
# comment:fpstackfrombottom:<x3#78:<h2#39:<h1#40:<h0#41:<h3#38:

# qhasm:   sr2x3 = *(float64 *) &sr2
# asm 1: fldl <sr2=stack64#9
# asm 2: fldl <sr2=160(%esp)
fldl 160(%esp)
# comment:fpstackfrombottom:<x3#78:<h2#39:<h1#40:<h0#41:<h3#38:<sr2x3#89:

# qhasm:   sr2x3 *= x3
# asm 1: fmul <x3=float80#6,<sr2x3=float80#1
# asm 2: fmul <x3=%st(5),<sr2x3=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x3#78:<h2#39:<h1#40:<h0#41:<h3#38:<sr2x3#89:

# qhasm:   h1 += sr2x3
# asm 1: faddp <sr2x3=float80#1,<h1=float80#4
# asm 2: faddp <sr2x3=%st(0),<h1=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x3#78:<h2#39:<h1#40:<h0#41:<h3#38:

# qhasm:   sr1x3 = *(float64 *) &sr1
# asm 1: fldl <sr1=stack64#7
# asm 2: fldl <sr1=144(%esp)
fldl 144(%esp)
# comment:fpstackfrombottom:<x3#78:<h2#39:<h1#40:<h0#41:<h3#38:<sr1x3#90:

# qhasm:   sr1x3 *= x3
# asm 1: fmulp <x3=float80#1,<sr1x3=float80#6
# asm 2: fmulp <x3=%st(0),<sr1x3=%st(5)
fmulp %st(0),%st(5)
# comment:fpstackfrombottom:<sr1x3#90:<h2#39:<h1#40:<h0#41:<h3#38:

# qhasm: internal stacktop sr1x3
# asm 1: fxch <sr1x3=float80#5
# asm 2: fxch <sr1x3=%st(4)
fxch %st(4)

# qhasm:   h0 += sr1x3
# asm 1: faddp <sr1x3=float80#1,<h0=float80#2
# asm 2: faddp <sr1x3=%st(0),<h0=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:
# comment:fp stack unchanged by fallthrough
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm: addatmost15bytes:
._addatmost15bytes:
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:                     =? l - 0
# asm 1: cmp  $0,<l=int32#2
# asm 2: cmp  $0,<l=%ecx
cmp  $0,%ecx
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:
# comment:fp stack unchanged by jump
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm: goto nomorebytes if =
je ._nomorebytes
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm: stack128 lastchunk
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm: int32 destination
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   ((uint32 *)&lastchunk)[0] = 0
# asm 1: movl $0,>lastchunk=stack128#1
# asm 2: movl $0,>lastchunk=64(%esp)
movl $0,64(%esp)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   ((uint32 *)&lastchunk)[1] = 0
# asm 1: movl $0,4+<lastchunk=stack128#1
# asm 2: movl $0,4+<lastchunk=64(%esp)
movl $0,4+64(%esp)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   ((uint32 *)&lastchunk)[2] = 0
# asm 1: movl $0,8+<lastchunk=stack128#1
# asm 2: movl $0,8+<lastchunk=64(%esp)
movl $0,8+64(%esp)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   ((uint32 *)&lastchunk)[3] = 0
# asm 1: movl $0,12+<lastchunk=stack128#1
# asm 2: movl $0,12+<lastchunk=64(%esp)
movl $0,12+64(%esp)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   destination = &lastchunk
# asm 1: leal <lastchunk=stack128#1,>destination=int32#6
# asm 2: leal <lastchunk=64(%esp),>destination=%edi
leal 64(%esp),%edi
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   while (l) { *destination++ = *m++; --l }
rep movsb
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   *(uint8 *) (destination + 0) = 1
# asm 1: movb $1,0(<destination=int32#6)
# asm 2: movb $1,0(<destination=%edi)
movb $1,0(%edi)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   m3 = ((uint32 *)&lastchunk)[3]
# asm 1: movl 12+<lastchunk=stack128#1,>m3=int32#1
# asm 2: movl 12+<lastchunk=64(%esp),>m3=%eax
movl 12+64(%esp),%eax
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   m2 = ((uint32 *)&lastchunk)[2]
# asm 1: movl 8+<lastchunk=stack128#1,>m2=int32#2
# asm 2: movl 8+<lastchunk=64(%esp),>m2=%ecx
movl 8+64(%esp),%ecx
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   m1 = ((uint32 *)&lastchunk)[1]
# asm 1: movl 4+<lastchunk=stack128#1,>m1=int32#3
# asm 2: movl 4+<lastchunk=64(%esp),>m1=%edx
movl 4+64(%esp),%edx
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   m0 = ((uint32 *)&lastchunk)[0]
# asm 1: movl <lastchunk=stack128#1,>m0=int32#4
# asm 2: movl <lastchunk=64(%esp),>m0=%ebx
movl 64(%esp),%ebx
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   inplace d3 bottom = m3
# asm 1: movl <m3=int32#1,<d3=stack64#4
# asm 2: movl <m3=%eax,<d3=120(%esp)
movl %eax,120(%esp)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   inplace d2 bottom = m2
# asm 1: movl <m2=int32#2,<d2=stack64#3
# asm 2: movl <m2=%ecx,<d2=112(%esp)
movl %ecx,112(%esp)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   inplace d1 bottom = m1
# asm 1: movl <m1=int32#3,<d1=stack64#2
# asm 2: movl <m1=%edx,<d1=104(%esp)
movl %edx,104(%esp)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   inplace d0 bottom = m0
# asm 1: movl <m0=int32#4,<d0=stack64#1
# asm 2: movl <m0=%ebx,<d0=96(%esp)
movl %ebx,96(%esp)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm: internal stacktop h3
# asm 1: fxch <h3=float80#4
# asm 2: fxch <h3=%st(3)
fxch %st(3)

# qhasm:   h3 += *(float64 *) &d3
# asm 1: faddl <d3=stack64#4
# asm 2: faddl <d3=120(%esp)
faddl 120(%esp)
# comment:fpstackfrombottom:<h0#41:<h2#39:<h1#40:<h3#38:

# qhasm:   h3 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset3
fsubl crypto_onetimeauth_poly1305_x86_doffset3
# comment:fpstackfrombottom:<h0#41:<h2#39:<h1#40:<h3#38:

# qhasm: internal stacktop h2
# asm 1: fxch <h2=float80#3
# asm 2: fxch <h2=%st(2)
fxch %st(2)

# qhasm:   h2 += *(float64 *) &d2
# asm 1: faddl <d2=stack64#3
# asm 2: faddl <d2=112(%esp)
faddl 112(%esp)
# comment:fpstackfrombottom:<h0#41:<h3#38:<h1#40:<h2#39:

# qhasm:   h2 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset2
fsubl crypto_onetimeauth_poly1305_x86_doffset2
# comment:fpstackfrombottom:<h0#41:<h3#38:<h1#40:<h2#39:

# qhasm: internal stacktop h1
# asm 1: fxch <h1=float80#2
# asm 2: fxch <h1=%st(1)
fxch %st(1)

# qhasm:   h1 += *(float64 *) &d1
# asm 1: faddl <d1=stack64#2
# asm 2: faddl <d1=104(%esp)
faddl 104(%esp)
# comment:fpstackfrombottom:<h0#41:<h3#38:<h2#39:<h1#40:

# qhasm:   h1 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset1
fsubl crypto_onetimeauth_poly1305_x86_doffset1
# comment:fpstackfrombottom:<h0#41:<h3#38:<h2#39:<h1#40:

# qhasm: internal stacktop h0
# asm 1: fxch <h0=float80#4
# asm 2: fxch <h0=%st(3)
fxch %st(3)

# qhasm:   h0 += *(float64 *) &d0
# asm 1: faddl <d0=stack64#1
# asm 2: faddl <d0=96(%esp)
faddl 96(%esp)
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:

# qhasm:   h0 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_doffset0
fsubl crypto_onetimeauth_poly1305_x86_doffset0
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:

# qhasm:   x0 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha130
fldl crypto_onetimeauth_poly1305_x86_alpha130
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:

# qhasm:   x0 += h3
# asm 1: fadd <h3=float80#4,<x0=float80#1
# asm 2: fadd <h3=%st(3),<x0=%st(0)
fadd %st(3),%st(0)
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:

# qhasm:   x0 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha130
fsubl crypto_onetimeauth_poly1305_x86_alpha130
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:

# qhasm:   h3 -= x0
# asm 1: fsubr <x0=float80#1,<h3=float80#4
# asm 2: fsubr <x0=%st(0),<h3=%st(3)
fsubr %st(0),%st(3)
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:

# qhasm:   x0 *= *(float64 *) &crypto_onetimeauth_poly1305_x86_scale
fmull crypto_onetimeauth_poly1305_x86_scale
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:

# qhasm:   x1 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha32
fldl crypto_onetimeauth_poly1305_x86_alpha32
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:<x1#99:

# qhasm:   x1 += h0
# asm 1: fadd <h0=float80#3,<x1=float80#1
# asm 2: fadd <h0=%st(2),<x1=%st(0)
fadd %st(2),%st(0)
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:<x1#99:

# qhasm:   x1 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha32
fsubl crypto_onetimeauth_poly1305_x86_alpha32
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:<x1#99:

# qhasm:   h0 -= x1
# asm 1: fsubr <x1=float80#1,<h0=float80#3
# asm 2: fsubr <x1=%st(0),<h0=%st(2)
fsubr %st(0),%st(2)
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:<x1#99:

# qhasm:   x2 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha64
fldl crypto_onetimeauth_poly1305_x86_alpha64
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:<x1#99:<x2#100:

# qhasm:   x2 += h1
# asm 1: fadd <h1=float80#7,<x2=float80#1
# asm 2: fadd <h1=%st(6),<x2=%st(0)
fadd %st(6),%st(0)
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:<x1#99:<x2#100:

# qhasm:   x2 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha64
fsubl crypto_onetimeauth_poly1305_x86_alpha64
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:<x1#99:<x2#100:

# qhasm:   h1 -= x2
# asm 1: fsubr <x2=float80#1,<h1=float80#7
# asm 2: fsubr <x2=%st(0),<h1=%st(6)
fsubr %st(0),%st(6)
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:<x1#99:<x2#100:

# qhasm:   x3 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha96
fldl crypto_onetimeauth_poly1305_x86_alpha96
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:<x1#99:<x2#100:<x3#101:

# qhasm:   x3 += h2
# asm 1: fadd <h2=float80#6,<x3=float80#1
# asm 2: fadd <h2=%st(5),<x3=%st(0)
fadd %st(5),%st(0)
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:<x1#99:<x2#100:<x3#101:

# qhasm:   x3 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha96
fsubl crypto_onetimeauth_poly1305_x86_alpha96
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:<x1#99:<x2#100:<x3#101:

# qhasm:   h2 -= x3
# asm 1: fsubr <x3=float80#1,<h2=float80#6
# asm 2: fsubr <x3=%st(0),<h2=%st(5)
fsubr %st(0),%st(5)
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<h0#41:<x0#98:<x1#99:<x2#100:<x3#101:

# qhasm: internal stacktop h0
# asm 1: fxch <h0=float80#5
# asm 2: fxch <h0=%st(4)
fxch %st(4)

# qhasm:   x0 += h0
# asm 1: faddp <h0=float80#1,<x0=float80#4
# asm 2: faddp <h0=%st(0),<x0=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<h1#40:<h3#38:<h2#39:<x3#101:<x0#98:<x1#99:<x2#100:

# qhasm: internal stacktop h1
# asm 1: fxch <h1=float80#7
# asm 2: fxch <h1=%st(6)
fxch %st(6)

# qhasm:   x1 += h1
# asm 1: faddp <h1=float80#1,<x1=float80#2
# asm 2: faddp <h1=%st(0),<x1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x2#100:<h3#38:<h2#39:<x3#101:<x0#98:<x1#99:

# qhasm: internal stacktop h2
# asm 1: fxch <h2=float80#4
# asm 2: fxch <h2=%st(3)
fxch %st(3)

# qhasm:   x2 += h2
# asm 1: faddp <h2=float80#1,<x2=float80#6
# asm 2: faddp <h2=%st(0),<x2=%st(5)
faddp %st(0),%st(5)
# comment:fpstackfrombottom:<x2#100:<h3#38:<x1#99:<x3#101:<x0#98:

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
# asm 1: fldl <r3=stack64#10
# asm 2: fldl <r3=168(%esp)
fldl 168(%esp)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:<h3#38:

# qhasm:   h3 *= x0
# asm 1: fmul <x0=float80#4,<h3=float80#1
# asm 2: fmul <x0=%st(3),<h3=%st(0)
fmul %st(3),%st(0)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:<h3#38:

# qhasm:   h2 = *(float64 *) &r2
# asm 1: fldl <r2=stack64#8
# asm 2: fldl <r2=152(%esp)
fldl 152(%esp)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:<h3#38:<h2#39:

# qhasm:   h2 *= x0
# asm 1: fmul <x0=float80#5,<h2=float80#1
# asm 2: fmul <x0=%st(4),<h2=%st(0)
fmul %st(4),%st(0)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:<h3#38:<h2#39:

# qhasm:   h1 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#6
# asm 2: fldl <r1=136(%esp)
fldl 136(%esp)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:<h3#38:<h2#39:<h1#40:

# qhasm:   h1 *= x0
# asm 1: fmul <x0=float80#6,<h1=float80#1
# asm 2: fmul <x0=%st(5),<h1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:<h3#38:<h2#39:<h1#40:

# qhasm:   h0 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#5
# asm 2: fldl <r0=128(%esp)
fldl 128(%esp)
# comment:fpstackfrombottom:<x2#100:<x0#98:<x1#99:<x3#101:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   h0 *= x0
# asm 1: fmulp <x0=float80#1,<h0=float80#7
# asm 2: fmulp <x0=%st(0),<h0=%st(6)
fmulp %st(0),%st(6)
# comment:fpstackfrombottom:<x2#100:<h0#41:<x1#99:<x3#101:<h3#38:<h2#39:<h1#40:

# qhasm:   r2x1 = *(float64 *) &r2
# asm 1: fldl <r2=stack64#8
# asm 2: fldl <r2=152(%esp)
fldl 152(%esp)
# comment:fpstackfrombottom:<x2#100:<h0#41:<x1#99:<x3#101:<h3#38:<h2#39:<h1#40:<r2x1#102:

# qhasm:   r2x1 *= x1
# asm 1: fmul <x1=float80#6,<r2x1=float80#1
# asm 2: fmul <x1=%st(5),<r2x1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x2#100:<h0#41:<x1#99:<x3#101:<h3#38:<h2#39:<h1#40:<r2x1#102:

# qhasm:   h3 += r2x1
# asm 1: faddp <r2x1=float80#1,<h3=float80#4
# asm 2: faddp <r2x1=%st(0),<h3=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<x2#100:<h0#41:<x1#99:<x3#101:<h3#38:<h2#39:<h1#40:

# qhasm:   r1x1 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#6
# asm 2: fldl <r1=136(%esp)
fldl 136(%esp)
# comment:fpstackfrombottom:<x2#100:<h0#41:<x1#99:<x3#101:<h3#38:<h2#39:<h1#40:<r1x1#103:

# qhasm:   r1x1 *= x1
# asm 1: fmul <x1=float80#6,<r1x1=float80#1
# asm 2: fmul <x1=%st(5),<r1x1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x2#100:<h0#41:<x1#99:<x3#101:<h3#38:<h2#39:<h1#40:<r1x1#103:

# qhasm:   h2 += r1x1
# asm 1: faddp <r1x1=float80#1,<h2=float80#3
# asm 2: faddp <r1x1=%st(0),<h2=%st(2)
faddp %st(0),%st(2)
# comment:fpstackfrombottom:<x2#100:<h0#41:<x1#99:<x3#101:<h3#38:<h2#39:<h1#40:

# qhasm:   r0x1 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#5
# asm 2: fldl <r0=128(%esp)
fldl 128(%esp)
# comment:fpstackfrombottom:<x2#100:<h0#41:<x1#99:<x3#101:<h3#38:<h2#39:<h1#40:<r0x1#104:

# qhasm:   r0x1 *= x1
# asm 1: fmul <x1=float80#6,<r0x1=float80#1
# asm 2: fmul <x1=%st(5),<r0x1=%st(0)
fmul %st(5),%st(0)
# comment:fpstackfrombottom:<x2#100:<h0#41:<x1#99:<x3#101:<h3#38:<h2#39:<h1#40:<r0x1#104:

# qhasm:   h1 += r0x1
# asm 1: faddp <r0x1=float80#1,<h1=float80#2
# asm 2: faddp <r0x1=%st(0),<h1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x2#100:<h0#41:<x1#99:<x3#101:<h3#38:<h2#39:<h1#40:

# qhasm:   sr3x1 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#11
# asm 2: fldl <sr3=176(%esp)
fldl 176(%esp)
# comment:fpstackfrombottom:<x2#100:<h0#41:<x1#99:<x3#101:<h3#38:<h2#39:<h1#40:<sr3x1#105:

# qhasm:   sr3x1 *= x1
# asm 1: fmulp <x1=float80#1,<sr3x1=float80#6
# asm 2: fmulp <x1=%st(0),<sr3x1=%st(5)
fmulp %st(0),%st(5)
# comment:fpstackfrombottom:<x2#100:<h0#41:<sr3x1#105:<x3#101:<h3#38:<h2#39:<h1#40:

# qhasm: internal stacktop sr3x1
# asm 1: fxch <sr3x1=float80#5
# asm 2: fxch <sr3x1=%st(4)
fxch %st(4)

# qhasm:   h0 += sr3x1
# asm 1: faddp <sr3x1=float80#1,<h0=float80#6
# asm 2: faddp <sr3x1=%st(0),<h0=%st(5)
faddp %st(0),%st(5)
# comment:fpstackfrombottom:<x2#100:<h0#41:<h1#40:<x3#101:<h3#38:<h2#39:

# qhasm:   r1x2 = *(float64 *) &r1
# asm 1: fldl <r1=stack64#6
# asm 2: fldl <r1=136(%esp)
fldl 136(%esp)
# comment:fpstackfrombottom:<x2#100:<h0#41:<h1#40:<x3#101:<h3#38:<h2#39:<r1x2#106:

# qhasm:   r1x2 *= x2
# asm 1: fmul <x2=float80#7,<r1x2=float80#1
# asm 2: fmul <x2=%st(6),<r1x2=%st(0)
fmul %st(6),%st(0)
# comment:fpstackfrombottom:<x2#100:<h0#41:<h1#40:<x3#101:<h3#38:<h2#39:<r1x2#106:

# qhasm:   h3 += r1x2
# asm 1: faddp <r1x2=float80#1,<h3=float80#3
# asm 2: faddp <r1x2=%st(0),<h3=%st(2)
faddp %st(0),%st(2)
# comment:fpstackfrombottom:<x2#100:<h0#41:<h1#40:<x3#101:<h3#38:<h2#39:

# qhasm:   r0x2 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#5
# asm 2: fldl <r0=128(%esp)
fldl 128(%esp)
# comment:fpstackfrombottom:<x2#100:<h0#41:<h1#40:<x3#101:<h3#38:<h2#39:<r0x2#107:

# qhasm:   r0x2 *= x2
# asm 1: fmul <x2=float80#7,<r0x2=float80#1
# asm 2: fmul <x2=%st(6),<r0x2=%st(0)
fmul %st(6),%st(0)
# comment:fpstackfrombottom:<x2#100:<h0#41:<h1#40:<x3#101:<h3#38:<h2#39:<r0x2#107:

# qhasm:   h2 += r0x2
# asm 1: faddp <r0x2=float80#1,<h2=float80#2
# asm 2: faddp <r0x2=%st(0),<h2=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<x2#100:<h0#41:<h1#40:<x3#101:<h3#38:<h2#39:

# qhasm:   sr3x2 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#11
# asm 2: fldl <sr3=176(%esp)
fldl 176(%esp)
# comment:fpstackfrombottom:<x2#100:<h0#41:<h1#40:<x3#101:<h3#38:<h2#39:<sr3x2#108:

# qhasm:   sr3x2 *= x2
# asm 1: fmul <x2=float80#7,<sr3x2=float80#1
# asm 2: fmul <x2=%st(6),<sr3x2=%st(0)
fmul %st(6),%st(0)
# comment:fpstackfrombottom:<x2#100:<h0#41:<h1#40:<x3#101:<h3#38:<h2#39:<sr3x2#108:

# qhasm:   h1 += sr3x2
# asm 1: faddp <sr3x2=float80#1,<h1=float80#5
# asm 2: faddp <sr3x2=%st(0),<h1=%st(4)
faddp %st(0),%st(4)
# comment:fpstackfrombottom:<x2#100:<h0#41:<h1#40:<x3#101:<h3#38:<h2#39:

# qhasm:   sr2x2 = *(float64 *) &sr2
# asm 1: fldl <sr2=stack64#9
# asm 2: fldl <sr2=160(%esp)
fldl 160(%esp)
# comment:fpstackfrombottom:<x2#100:<h0#41:<h1#40:<x3#101:<h3#38:<h2#39:<sr2x2#109:

# qhasm:   sr2x2 *= x2
# asm 1: fmulp <x2=float80#1,<sr2x2=float80#7
# asm 2: fmulp <x2=%st(0),<sr2x2=%st(6)
fmulp %st(0),%st(6)
# comment:fpstackfrombottom:<sr2x2#109:<h0#41:<h1#40:<x3#101:<h3#38:<h2#39:

# qhasm: internal stacktop sr2x2
# asm 1: fxch <sr2x2=float80#6
# asm 2: fxch <sr2x2=%st(5)
fxch %st(5)

# qhasm:   h0 += sr2x2
# asm 1: faddp <sr2x2=float80#1,<h0=float80#5
# asm 2: faddp <sr2x2=%st(0),<h0=%st(4)
faddp %st(0),%st(4)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h1#40:<x3#101:<h3#38:

# qhasm:   r0x3 = *(float64 *) &r0
# asm 1: fldl <r0=stack64#5
# asm 2: fldl <r0=128(%esp)
fldl 128(%esp)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h1#40:<x3#101:<h3#38:<r0x3#110:

# qhasm:   r0x3 *= x3
# asm 1: fmul <x3=float80#3,<r0x3=float80#1
# asm 2: fmul <x3=%st(2),<r0x3=%st(0)
fmul %st(2),%st(0)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h1#40:<x3#101:<h3#38:<r0x3#110:

# qhasm:   h3 += r0x3
# asm 1: faddp <r0x3=float80#1,<h3=float80#2
# asm 2: faddp <r0x3=%st(0),<h3=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h1#40:<x3#101:<h3#38:

# qhasm:   sr3x3 = *(float64 *) &sr3
# asm 1: fldl <sr3=stack64#11
# asm 2: fldl <sr3=176(%esp)
fldl 176(%esp)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h1#40:<x3#101:<h3#38:<sr3x3#111:

# qhasm:   sr3x3 *= x3
# asm 1: fmul <x3=float80#3,<sr3x3=float80#1
# asm 2: fmul <x3=%st(2),<sr3x3=%st(0)
fmul %st(2),%st(0)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h1#40:<x3#101:<h3#38:<sr3x3#111:

# qhasm:   h2 += sr3x3
# asm 1: faddp <sr3x3=float80#1,<h2=float80#6
# asm 2: faddp <sr3x3=%st(0),<h2=%st(5)
faddp %st(0),%st(5)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h1#40:<x3#101:<h3#38:

# qhasm:   sr2x3 = *(float64 *) &sr2
# asm 1: fldl <sr2=stack64#9
# asm 2: fldl <sr2=160(%esp)
fldl 160(%esp)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h1#40:<x3#101:<h3#38:<sr2x3#112:

# qhasm:   sr2x3 *= x3
# asm 1: fmul <x3=float80#3,<sr2x3=float80#1
# asm 2: fmul <x3=%st(2),<sr2x3=%st(0)
fmul %st(2),%st(0)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h1#40:<x3#101:<h3#38:<sr2x3#112:

# qhasm:   h1 += sr2x3
# asm 1: faddp <sr2x3=float80#1,<h1=float80#4
# asm 2: faddp <sr2x3=%st(0),<h1=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h1#40:<x3#101:<h3#38:

# qhasm:   sr1x3 = *(float64 *) &sr1
# asm 1: fldl <sr1=stack64#7
# asm 2: fldl <sr1=144(%esp)
fldl 144(%esp)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h1#40:<x3#101:<h3#38:<sr1x3#113:

# qhasm:   sr1x3 *= x3
# asm 1: fmulp <x3=float80#1,<sr1x3=float80#3
# asm 2: fmulp <x3=%st(0),<sr1x3=%st(2)
fmulp %st(0),%st(2)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h1#40:<sr1x3#113:<h3#38:

# qhasm: internal stacktop sr1x3
# asm 1: fxch <sr1x3=float80#2
# asm 2: fxch <sr1x3=%st(1)
fxch %st(1)

# qhasm:   h0 += sr1x3
# asm 1: faddp <sr1x3=float80#1,<h0=float80#4
# asm 2: faddp <sr1x3=%st(0),<h0=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<h2#39:<h0#41:<h1#40:<h3#38:
# comment:automatically reorganizing fp stack for fallthrough

# qhasm: internal stacktop h2
# asm 1: fxch <h2=float80#4
# asm 2: fxch <h2=%st(3)
fxch %st(3)
# comment:fpstackfrombottom:<h3#38:<h0#41:<h1#40:<h2#39:

# qhasm: internal stacktop h0
# asm 1: fxch <h0=float80#3
# asm 2: fxch <h0=%st(2)
fxch %st(2)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm: nomorebytes:
._nomorebytes:
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:

# qhasm:   x0 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha130
fldl crypto_onetimeauth_poly1305_x86_alpha130
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:

# qhasm:   x0 += h3
# asm 1: fadd <h3=float80#5,<x0=float80#1
# asm 2: fadd <h3=%st(4),<x0=%st(0)
fadd %st(4),%st(0)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:

# qhasm:   x0 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha130
fsubl crypto_onetimeauth_poly1305_x86_alpha130
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:

# qhasm:   h3 -= x0
# asm 1: fsubr <x0=float80#1,<h3=float80#5
# asm 2: fsubr <x0=%st(0),<h3=%st(4)
fsubr %st(0),%st(4)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:

# qhasm:   x0 *= *(float64 *) &crypto_onetimeauth_poly1305_x86_scale
fmull crypto_onetimeauth_poly1305_x86_scale
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:

# qhasm:   x1 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha32
fldl crypto_onetimeauth_poly1305_x86_alpha32
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:<x1#115:

# qhasm:   x1 += h0
# asm 1: fadd <h0=float80#3,<x1=float80#1
# asm 2: fadd <h0=%st(2),<x1=%st(0)
fadd %st(2),%st(0)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:<x1#115:

# qhasm:   x1 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha32
fsubl crypto_onetimeauth_poly1305_x86_alpha32
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:<x1#115:

# qhasm:   h0 -= x1
# asm 1: fsubr <x1=float80#1,<h0=float80#3
# asm 2: fsubr <x1=%st(0),<h0=%st(2)
fsubr %st(0),%st(2)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:<x1#115:

# qhasm:   x2 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha64
fldl crypto_onetimeauth_poly1305_x86_alpha64
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:<x1#115:<x2#116:

# qhasm:   x2 += h1
# asm 1: fadd <h1=float80#5,<x2=float80#1
# asm 2: fadd <h1=%st(4),<x2=%st(0)
fadd %st(4),%st(0)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:<x1#115:<x2#116:

# qhasm:   x2 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha64
fsubl crypto_onetimeauth_poly1305_x86_alpha64
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:<x1#115:<x2#116:

# qhasm:   h1 -= x2
# asm 1: fsubr <x2=float80#1,<h1=float80#5
# asm 2: fsubr <x2=%st(0),<h1=%st(4)
fsubr %st(0),%st(4)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:<x1#115:<x2#116:

# qhasm:   x3 = *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha96
fldl crypto_onetimeauth_poly1305_x86_alpha96
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:<x1#115:<x2#116:<x3#117:

# qhasm:   x3 += h2
# asm 1: fadd <h2=float80#7,<x3=float80#1
# asm 2: fadd <h2=%st(6),<x3=%st(0)
fadd %st(6),%st(0)
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:<x1#115:<x2#116:<x3#117:

# qhasm:   x3 -= *(float64 *) &crypto_onetimeauth_poly1305_x86_alpha96
fsubl crypto_onetimeauth_poly1305_x86_alpha96
# comment:fpstackfrombottom:<h3#38:<h2#39:<h1#40:<h0#41:<x0#114:<x1#115:<x2#116:<x3#117:

# qhasm:   stacktop h2
# asm 1: fxch <h2=float80#7
# asm 2: fxch <h2=%st(6)
fxch %st(6)
# comment:fpstackfrombottom:<h3#38:<x3#117:<h1#40:<h0#41:<x0#114:<x1#115:<x2#116:<h2#39:

# qhasm:   h2 -= x3
# asm 1: fsub <x3=float80#7,<h2=float80#1
# asm 2: fsub <x3=%st(6),<h2=%st(0)
fsub %st(6),%st(0)
# comment:fpstackfrombottom:<h3#38:<x3#117:<h1#40:<h0#41:<x0#114:<x1#115:<x2#116:<h2#39:

# qhasm: internal stacktop h0
# asm 1: fxch <h0=float80#5
# asm 2: fxch <h0=%st(4)
fxch %st(4)

# qhasm:   x0 += h0
# asm 1: faddp <h0=float80#1,<x0=float80#4
# asm 2: faddp <h0=%st(0),<x0=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<h3#38:<x3#117:<h1#40:<h2#39:<x0#114:<x1#115:<x2#116:

# qhasm: internal stacktop h1
# asm 1: fxch <h1=float80#5
# asm 2: fxch <h1=%st(4)
fxch %st(4)

# qhasm:   x1 += h1
# asm 1: faddp <h1=float80#1,<x1=float80#2
# asm 2: faddp <h1=%st(0),<x1=%st(1)
faddp %st(0),%st(1)
# comment:fpstackfrombottom:<h3#38:<x3#117:<x2#116:<h2#39:<x0#114:<x1#115:

# qhasm: internal stacktop h2
# asm 1: fxch <h2=float80#3
# asm 2: fxch <h2=%st(2)
fxch %st(2)

# qhasm:   x2 += h2
# asm 1: faddp <h2=float80#1,<x2=float80#4
# asm 2: faddp <h2=%st(0),<x2=%st(3)
faddp %st(0),%st(3)
# comment:fpstackfrombottom:<h3#38:<x3#117:<x2#116:<x1#115:<x0#114:

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

# qhasm:   x0 += *(float64 *) &crypto_onetimeauth_poly1305_x86_hoffset0
faddl crypto_onetimeauth_poly1305_x86_hoffset0
# comment:fpstackfrombottom:<x1#115:<x3#117:<x2#116:<x0#114:

# qhasm: internal stacktop x1
# asm 1: fxch <x1=float80#4
# asm 2: fxch <x1=%st(3)
fxch %st(3)

# qhasm:   x1 += *(float64 *) &crypto_onetimeauth_poly1305_x86_hoffset1
faddl crypto_onetimeauth_poly1305_x86_hoffset1
# comment:fpstackfrombottom:<x0#114:<x3#117:<x2#116:<x1#115:

# qhasm: internal stacktop x2
# asm 1: fxch <x2=float80#2
# asm 2: fxch <x2=%st(1)
fxch %st(1)

# qhasm:   x2 += *(float64 *) &crypto_onetimeauth_poly1305_x86_hoffset2
faddl crypto_onetimeauth_poly1305_x86_hoffset2
# comment:fpstackfrombottom:<x0#114:<x3#117:<x1#115:<x2#116:

# qhasm: internal stacktop x3
# asm 1: fxch <x3=float80#3
# asm 2: fxch <x3=%st(2)
fxch %st(2)

# qhasm:   x3 += *(float64 *) &crypto_onetimeauth_poly1305_x86_hoffset3
faddl crypto_onetimeauth_poly1305_x86_hoffset3
# comment:fpstackfrombottom:<x0#114:<x2#116:<x1#115:<x3#117:

# qhasm: internal stacktop x0
# asm 1: fxch <x0=float80#4
# asm 2: fxch <x0=%st(3)
fxch %st(3)

# qhasm:   *(float64 *) &d0 = x0
# asm 1: fstpl >d0=stack64#1
# asm 2: fstpl >d0=96(%esp)
fstpl 96(%esp)
# comment:fpstackfrombottom:<x3#117:<x2#116:<x1#115:

# qhasm:   *(float64 *) &d1 = x1
# asm 1: fstpl >d1=stack64#2
# asm 2: fstpl >d1=104(%esp)
fstpl 104(%esp)
# comment:fpstackfrombottom:<x3#117:<x2#116:

# qhasm:   *(float64 *) &d2 = x2
# asm 1: fstpl >d2=stack64#3
# asm 2: fstpl >d2=112(%esp)
fstpl 112(%esp)
# comment:fpstackfrombottom:<x3#117:

# qhasm:   *(float64 *) &d3 = x3
# asm 1: fstpl >d3=stack64#4
# asm 2: fstpl >d3=120(%esp)
fstpl 120(%esp)
# comment:fpstackfrombottom:

# qhasm: int32 f0

# qhasm: int32 f1

# qhasm: int32 f2

# qhasm: int32 f3

# qhasm: int32 f4

# qhasm: int32 g0

# qhasm: int32 g1

# qhasm: int32 g2

# qhasm: int32 g3

# qhasm: int32 f

# qhasm: int32 notf

# qhasm: stack32 f1_stack

# qhasm: stack32 f2_stack

# qhasm: stack32 f3_stack

# qhasm: stack32 f4_stack

# qhasm: stack32 g0_stack

# qhasm: stack32 g1_stack

# qhasm: stack32 g2_stack

# qhasm: stack32 g3_stack

# qhasm:   g0 = top d0
# asm 1: movl <d0=stack64#1,>g0=int32#1
# asm 2: movl <d0=100(%esp),>g0=%eax
movl 100(%esp),%eax

# qhasm:   g0 &= 63
# asm 1: and  $63,<g0=int32#1
# asm 2: and  $63,<g0=%eax
and  $63,%eax

# qhasm:   g1 = top d1
# asm 1: movl <d1=stack64#2,>g1=int32#2
# asm 2: movl <d1=108(%esp),>g1=%ecx
movl 108(%esp),%ecx

# qhasm:   g1 &= 63
# asm 1: and  $63,<g1=int32#2
# asm 2: and  $63,<g1=%ecx
and  $63,%ecx

# qhasm:   g2 = top d2
# asm 1: movl <d2=stack64#3,>g2=int32#3
# asm 2: movl <d2=116(%esp),>g2=%edx
movl 116(%esp),%edx

# qhasm:   g2 &= 63
# asm 1: and  $63,<g2=int32#3
# asm 2: and  $63,<g2=%edx
and  $63,%edx

# qhasm:   g3 = top d3
# asm 1: movl <d3=stack64#4,>g3=int32#4
# asm 2: movl <d3=124(%esp),>g3=%ebx
movl 124(%esp),%ebx

# qhasm:   g3 &= 63
# asm 1: and  $63,<g3=int32#4
# asm 2: and  $63,<g3=%ebx
and  $63,%ebx

# qhasm:   f1 = bottom d1
# asm 1: movl <d1=stack64#2,>f1=int32#5
# asm 2: movl <d1=104(%esp),>f1=%esi
movl 104(%esp),%esi

# qhasm:   carry? f1 += g0
# asm 1: addl <g0=int32#1,<f1=int32#5
# asm 2: addl <g0=%eax,<f1=%esi
addl %eax,%esi

# qhasm:   f1_stack = f1
# asm 1: movl <f1=int32#5,>f1_stack=stack32#8
# asm 2: movl <f1=%esi,>f1_stack=28(%esp)
movl %esi,28(%esp)

# qhasm:   f2 = bottom d2
# asm 1: movl <d2=stack64#3,>f2=int32#1
# asm 2: movl <d2=112(%esp),>f2=%eax
movl 112(%esp),%eax

# qhasm:   carry? f2 += g1 + carry
# asm 1: adcl <g1=int32#2,<f2=int32#1
# asm 2: adcl <g1=%ecx,<f2=%eax
adcl %ecx,%eax

# qhasm:   f2_stack = f2
# asm 1: movl <f2=int32#1,>f2_stack=stack32#9
# asm 2: movl <f2=%eax,>f2_stack=32(%esp)
movl %eax,32(%esp)

# qhasm:   f3 = bottom d3
# asm 1: movl <d3=stack64#4,>f3=int32#1
# asm 2: movl <d3=120(%esp),>f3=%eax
movl 120(%esp),%eax

# qhasm:   carry? f3 += g2 + carry
# asm 1: adcl <g2=int32#3,<f3=int32#1
# asm 2: adcl <g2=%edx,<f3=%eax
adcl %edx,%eax

# qhasm:   f3_stack = f3
# asm 1: movl <f3=int32#1,>f3_stack=stack32#10
# asm 2: movl <f3=%eax,>f3_stack=36(%esp)
movl %eax,36(%esp)

# qhasm:   f4 = 0
# asm 1: mov  $0,>f4=int32#1
# asm 2: mov  $0,>f4=%eax
mov  $0,%eax

# qhasm:   carry? f4 += g3 + carry
# asm 1: adcl <g3=int32#4,<f4=int32#1
# asm 2: adcl <g3=%ebx,<f4=%eax
adcl %ebx,%eax

# qhasm:   f4_stack = f4
# asm 1: movl <f4=int32#1,>f4_stack=stack32#11
# asm 2: movl <f4=%eax,>f4_stack=40(%esp)
movl %eax,40(%esp)

# qhasm:   g0 = 5
# asm 1: mov  $5,>g0=int32#1
# asm 2: mov  $5,>g0=%eax
mov  $5,%eax

# qhasm:   f0 = bottom d0
# asm 1: movl <d0=stack64#1,>f0=int32#2
# asm 2: movl <d0=96(%esp),>f0=%ecx
movl 96(%esp),%ecx

# qhasm:   carry? g0 += f0
# asm 1: addl <f0=int32#2,<g0=int32#1
# asm 2: addl <f0=%ecx,<g0=%eax
addl %ecx,%eax

# qhasm:   g0_stack = g0
# asm 1: movl <g0=int32#1,>g0_stack=stack32#12
# asm 2: movl <g0=%eax,>g0_stack=44(%esp)
movl %eax,44(%esp)

# qhasm:   g1 = 0
# asm 1: mov  $0,>g1=int32#1
# asm 2: mov  $0,>g1=%eax
mov  $0,%eax

# qhasm:   f1 = f1_stack
# asm 1: movl <f1_stack=stack32#8,>f1=int32#3
# asm 2: movl <f1_stack=28(%esp),>f1=%edx
movl 28(%esp),%edx

# qhasm:   carry? g1 += f1 + carry
# asm 1: adcl <f1=int32#3,<g1=int32#1
# asm 2: adcl <f1=%edx,<g1=%eax
adcl %edx,%eax

# qhasm:   g1_stack = g1
# asm 1: movl <g1=int32#1,>g1_stack=stack32#8
# asm 2: movl <g1=%eax,>g1_stack=28(%esp)
movl %eax,28(%esp)

# qhasm:   g2 = 0
# asm 1: mov  $0,>g2=int32#1
# asm 2: mov  $0,>g2=%eax
mov  $0,%eax

# qhasm:   f2 = f2_stack
# asm 1: movl <f2_stack=stack32#9,>f2=int32#4
# asm 2: movl <f2_stack=32(%esp),>f2=%ebx
movl 32(%esp),%ebx

# qhasm:   carry? g2 += f2 + carry
# asm 1: adcl <f2=int32#4,<g2=int32#1
# asm 2: adcl <f2=%ebx,<g2=%eax
adcl %ebx,%eax

# qhasm:   g2_stack = g2
# asm 1: movl <g2=int32#1,>g2_stack=stack32#9
# asm 2: movl <g2=%eax,>g2_stack=32(%esp)
movl %eax,32(%esp)

# qhasm:   g3 = 0
# asm 1: mov  $0,>g3=int32#1
# asm 2: mov  $0,>g3=%eax
mov  $0,%eax

# qhasm:   f3 = f3_stack
# asm 1: movl <f3_stack=stack32#10,>f3=int32#5
# asm 2: movl <f3_stack=36(%esp),>f3=%esi
movl 36(%esp),%esi

# qhasm:   carry? g3 += f3 + carry
# asm 1: adcl <f3=int32#5,<g3=int32#1
# asm 2: adcl <f3=%esi,<g3=%eax
adcl %esi,%eax

# qhasm:   g3_stack = g3
# asm 1: movl <g3=int32#1,>g3_stack=stack32#10
# asm 2: movl <g3=%eax,>g3_stack=36(%esp)
movl %eax,36(%esp)

# qhasm:   f = 0xfffffffc
# asm 1: mov  $0xfffffffc,>f=int32#1
# asm 2: mov  $0xfffffffc,>f=%eax
mov  $0xfffffffc,%eax

# qhasm:   f4 = f4_stack
# asm 1: movl <f4_stack=stack32#11,>f4=int32#6
# asm 2: movl <f4_stack=40(%esp),>f4=%edi
movl 40(%esp),%edi

# qhasm:   carry? f += f4 + carry
# asm 1: adcl <f4=int32#6,<f=int32#1
# asm 2: adcl <f4=%edi,<f=%eax
adcl %edi,%eax

# qhasm:   (int32) f >>= 16
# asm 1: sar  $16,<f=int32#1
# asm 2: sar  $16,<f=%eax
sar  $16,%eax

# qhasm:   notf = f
# asm 1: mov  <f=int32#1,>notf=int32#6
# asm 2: mov  <f=%eax,>notf=%edi
mov  %eax,%edi

# qhasm:   notf ^= 0xffffffff
# asm 1: xor  $0xffffffff,<notf=int32#6
# asm 2: xor  $0xffffffff,<notf=%edi
xor  $0xffffffff,%edi

# qhasm:   f0 &= f
# asm 1: andl <f=int32#1,<f0=int32#2
# asm 2: andl <f=%eax,<f0=%ecx
andl %eax,%ecx

# qhasm:   g0 = g0_stack
# asm 1: movl <g0_stack=stack32#12,>g0=int32#7
# asm 2: movl <g0_stack=44(%esp),>g0=%ebp
movl 44(%esp),%ebp

# qhasm:   g0 &= notf
# asm 1: andl <notf=int32#6,<g0=int32#7
# asm 2: andl <notf=%edi,<g0=%ebp
andl %edi,%ebp

# qhasm:   f0 |= g0
# asm 1: orl  <g0=int32#7,<f0=int32#2
# asm 2: orl  <g0=%ebp,<f0=%ecx
orl  %ebp,%ecx

# qhasm:   f1 &= f
# asm 1: andl <f=int32#1,<f1=int32#3
# asm 2: andl <f=%eax,<f1=%edx
andl %eax,%edx

# qhasm:   g1 = g1_stack
# asm 1: movl <g1_stack=stack32#8,>g1=int32#7
# asm 2: movl <g1_stack=28(%esp),>g1=%ebp
movl 28(%esp),%ebp

# qhasm:   g1 &= notf
# asm 1: andl <notf=int32#6,<g1=int32#7
# asm 2: andl <notf=%edi,<g1=%ebp
andl %edi,%ebp

# qhasm:   f1 |= g1
# asm 1: orl  <g1=int32#7,<f1=int32#3
# asm 2: orl  <g1=%ebp,<f1=%edx
orl  %ebp,%edx

# qhasm:   f2 &= f
# asm 1: andl <f=int32#1,<f2=int32#4
# asm 2: andl <f=%eax,<f2=%ebx
andl %eax,%ebx

# qhasm:   g2 = g2_stack
# asm 1: movl <g2_stack=stack32#9,>g2=int32#7
# asm 2: movl <g2_stack=32(%esp),>g2=%ebp
movl 32(%esp),%ebp

# qhasm:   g2 &= notf
# asm 1: andl <notf=int32#6,<g2=int32#7
# asm 2: andl <notf=%edi,<g2=%ebp
andl %edi,%ebp

# qhasm:   f2 |= g2
# asm 1: orl  <g2=int32#7,<f2=int32#4
# asm 2: orl  <g2=%ebp,<f2=%ebx
orl  %ebp,%ebx

# qhasm:   f3 &= f
# asm 1: andl <f=int32#1,<f3=int32#5
# asm 2: andl <f=%eax,<f3=%esi
andl %eax,%esi

# qhasm:   g3 = g3_stack
# asm 1: movl <g3_stack=stack32#10,>g3=int32#1
# asm 2: movl <g3_stack=36(%esp),>g3=%eax
movl 36(%esp),%eax

# qhasm:   g3 &= notf
# asm 1: andl <notf=int32#6,<g3=int32#1
# asm 2: andl <notf=%edi,<g3=%eax
andl %edi,%eax

# qhasm:   f3 |= g3
# asm 1: orl  <g3=int32#1,<f3=int32#5
# asm 2: orl  <g3=%eax,<f3=%esi
orl  %eax,%esi

# qhasm:   k = k_stack
# asm 1: movl <k_stack=stack32#6,>k=int32#1
# asm 2: movl <k_stack=20(%esp),>k=%eax
movl 20(%esp),%eax

# qhasm:   carry? f0 += *(uint32 *) (k + 16)
# asm 1: addl 16(<k=int32#1),<f0=int32#2
# asm 2: addl 16(<k=%eax),<f0=%ecx
addl 16(%eax),%ecx

# qhasm:   carry? f1 += *(uint32 *) (k + 20) + carry
# asm 1: adcl 20(<k=int32#1),<f1=int32#3
# asm 2: adcl 20(<k=%eax),<f1=%edx
adcl 20(%eax),%edx

# qhasm:   carry? f2 += *(uint32 *) (k + 24) + carry
# asm 1: adcl 24(<k=int32#1),<f2=int32#4
# asm 2: adcl 24(<k=%eax),<f2=%ebx
adcl 24(%eax),%ebx

# qhasm:   carry? f3 += *(uint32 *) (k + 28) + carry
# asm 1: adcl 28(<k=int32#1),<f3=int32#5
# asm 2: adcl 28(<k=%eax),<f3=%esi
adcl 28(%eax),%esi

# qhasm:   out = out_stack
# asm 1: movl <out_stack=stack32#7,>out=int32#1
# asm 2: movl <out_stack=24(%esp),>out=%eax
movl 24(%esp),%eax

# qhasm:   *(uint32 *) (out + 0) = f0
# asm 1: movl <f0=int32#2,0(<out=int32#1)
# asm 2: movl <f0=%ecx,0(<out=%eax)
movl %ecx,0(%eax)

# qhasm:   *(uint32 *) (out + 4) = f1
# asm 1: movl <f1=int32#3,4(<out=int32#1)
# asm 2: movl <f1=%edx,4(<out=%eax)
movl %edx,4(%eax)

# qhasm:   *(uint32 *) (out + 8) = f2
# asm 1: movl <f2=int32#4,8(<out=int32#1)
# asm 2: movl <f2=%ebx,8(<out=%eax)
movl %ebx,8(%eax)

# qhasm:   *(uint32 *) (out + 12) = f3
# asm 1: movl <f3=int32#5,12(<out=int32#1)
# asm 2: movl <f3=%esi,12(<out=%eax)
movl %esi,12(%eax)

# qhasm: eax = eax_stack
# asm 1: movl <eax_stack=stack32#1,>eax=int32#1
# asm 2: movl <eax_stack=0(%esp),>eax=%eax
movl 0(%esp),%eax

# qhasm: ebx = ebx_stack
# asm 1: movl <ebx_stack=stack32#2,>ebx=int32#4
# asm 2: movl <ebx_stack=4(%esp),>ebx=%ebx
movl 4(%esp),%ebx

# qhasm: esi = esi_stack
# asm 1: movl <esi_stack=stack32#3,>esi=int32#5
# asm 2: movl <esi_stack=8(%esp),>esi=%esi
movl 8(%esp),%esi

# qhasm: edi = edi_stack
# asm 1: movl <edi_stack=stack32#4,>edi=int32#6
# asm 2: movl <edi_stack=12(%esp),>edi=%edi
movl 12(%esp),%edi

# qhasm: ebp = ebp_stack
# asm 1: movl <ebp_stack=stack32#5,>ebp=int32#7
# asm 2: movl <ebp_stack=16(%esp),>ebp=%ebp
movl 16(%esp),%ebp

# qhasm: leave
add %eax,%esp
xor %eax,%eax
ret
