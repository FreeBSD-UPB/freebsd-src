/*-
 * Copyright (c) 2000 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD$
 */

#include <machine/asm.h>
#include <machine/mutex.h>
#include "assym.s"

/*
 * savectx: save process context, i.e. callee-saved registers
 *
 * Arguments:
 *	in0	'struct pcb *' of the process that needs its context saved
 *
 * Return:
 *	ret0	0.  (note that for child processes, it seems
 *		like savectx() returns 1, because the return address
 *		in the PCB is set to the return address from savectx().)
 */

LEAF(savectx, 1)
	flushrs				// push out caller's dirty regs
	mov	r3=ar.unat		// caller's value for ar.unat
	;;
	mov	ar.rsc=0		// stop the RSE after the flush
	;;
	mov	r16=ar.rnat		// read RSE's NaT collection
	mov	r17=in0
	mov	r18=ar.bspstore
	mov	r19=b0
	mov	r20=b1
	mov	r21=b2
	mov	r22=b3
	mov	r23=b4
	mov	r24=b5
	;;	
	st8.spill [r17]=r4,8 ;;		// save r4..r6 
	st8.spill [r17]=r5,8 ;;		// and accumulate NaT bits
	st8.spill [r17]=r6,8 ;;
	st8.spill [r17]=r7,8 ;;
	
	stf.spill [r17]=f2,16 ;;	// save f2..f5 with NaTVals
	stf.spill [r17]=f3,16 ;;
	stf.spill [r17]=f4,16 ;;
	stf.spill [r17]=f5,16 ;;

	st8	[r17]=r19,8 ;;		// save b0..b5
	st8	[r17]=r20,8 ;;
	st8	[r17]=r21,8 ;;
	st8	[r17]=r22,8 ;;
	st8	[r17]=r23,8 ;;
	st8	[r17]=r24,8 ;;
	
	mov	r19=ar.unat		// NaT bits for r4..r6
	mov	r20=pr
	mov	ret0=r0			// return zero

	st8	[r17]=r3,8 ;;		// save caller's ar.unat
	st8	[r17]=sp,8 ;;		// stack pointer
	st8	[r17]=r2,8 ;;		// ar.pfs
	st8	[r17]=r18,8 ;;		// ar.bspstore
	st8	[r17]=r19,8 ;;		// our NaT bits
	st8	[r17]=r16,8 ;;		// ar.rnat
	st8	[r17]=r20,8 ;;		// pr

	mov	ar.rsc=3		// turn RSE back on

	br.ret.sptk.few rp
	END(savectx)

/*
 * restorectx: restore process context, i.e. callee-saved registers
 *
 * Arguments:
 *	in0	'struct pcb *' of the process being restored
 *
 * Return:
 *	Does not return. We arrange things so that savectx appears to
 *	return a second time with a non-zero return value.
 */

LEAF(restorectx, 1)
	add	r3=U_PCB_UNAT,in0	// point at NaT for r4..r7
	mov	ar.rsc=0 ;;		// switch off the RSE
	ld8	r16=[r3]		// load NaT for r4..r7
	;;
	mov	ar.unat=r16
	;;
	ld8.fill r4=[in0],8 ;;		// restore r4
	ld8.fill r5=[in0],8 ;;		// restore r5
	ld8.fill r6=[in0],8 ;;		// restore r6
	ld8.fill r7=[in0],8 ;;		// restore r7

	ldf.fill f2=[in0],16 ;;		// restore f2
	ldf.fill f3=[in0],16 ;;		// restore f3
	ldf.fill f4=[in0],16 ;;		// restore f4
	ldf.fill f5=[in0],16 ;;		// restore f5

	ld8	r16=[in0],8 ;;		// restore b0
	ld8	r17=[in0],8 ;;		// restore b1
	ld8	r18=[in0],8 ;;		// restore b2
	ld8	r19=[in0],8 ;;		// restore b3
	ld8	r20=[in0],8 ;;		// restore b4
	ld8	r21=[in0],8 ;;		// restore b5

	mov	b0=r16
	mov	b1=r17
	mov	b2=r18
	mov	b3=r19
	mov	b4=r20
	mov	b5=r21

	ld8	r16=[in0],8 ;;		// caller's ar.unat
	ld8	sp=[in0],8 ;;		// stack pointer
	ld8	r17=[in0],8 ;;		// ar.pfs
	ld8	r18=[in0],16 ;;		// ar.bspstore, skip ar.unat
	ld8	r19=[in0],8 ;;		// ar.rnat
	ld8	r20=[in0],8 ;;		// pr

	mov	ar.unat=r16
	mov	ar.pfs=r17
	mov	ar.bspstore=r18 ;;
	mov	ar.rnat=r19
	mov	pr=r20,0x1ffff
	mov	ret0=r18		// non-zero return
	;;
	loadrs
	mov	ar.rsc=3		// restart RSE
	invala
	;;
	br.ret.sptk.few rp
	END(restorectx)	

/*
 * switch_trampoline()
 *
 * Arrange for a function to be invoked neatly, after a cpu_switch().
 *
 * Invokes the function specified by the r4 register with the return
 * address specified by the r5 register and with one argument, taken
 * from r6.
 */
LEAF(switch_trampoline, 0)
	MTX_EXIT(sched_lock, r14, r15)

	alloc	r16=ar.pfs,0,0,1,0
	mov	b7=r4
	mov	b0=r5
	mov	out0=r6
	;;
	br.call.sptk.few b6=b7

	END(switch_trampoline)

