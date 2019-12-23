// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *     Anup Patel <anup.patel@wdc.com>
 */

#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <asm/csr.h>

#define INSN_MATCH_LB		0x3
#define INSN_MASK_LB		0x707f
#define INSN_MATCH_LH		0x1003
#define INSN_MASK_LH		0x707f
#define INSN_MATCH_LW		0x2003
#define INSN_MASK_LW		0x707f
#define INSN_MATCH_LD		0x3003
#define INSN_MASK_LD		0x707f
#define INSN_MATCH_LBU		0x4003
#define INSN_MASK_LBU		0x707f
#define INSN_MATCH_LHU		0x5003
#define INSN_MASK_LHU		0x707f
#define INSN_MATCH_LWU		0x6003
#define INSN_MASK_LWU		0x707f
#define INSN_MATCH_SB		0x23
#define INSN_MASK_SB		0x707f
#define INSN_MATCH_SH		0x1023
#define INSN_MASK_SH		0x707f
#define INSN_MATCH_SW		0x2023
#define INSN_MASK_SW		0x707f
#define INSN_MATCH_SD		0x3023
#define INSN_MASK_SD		0x707f

#define INSN_MATCH_C_LD		0x6000
#define INSN_MASK_C_LD		0xe003
#define INSN_MATCH_C_SD		0xe000
#define INSN_MASK_C_SD		0xe003
#define INSN_MATCH_C_LW		0x4000
#define INSN_MASK_C_LW		0xe003
#define INSN_MATCH_C_SW		0xc000
#define INSN_MASK_C_SW		0xe003
#define INSN_MATCH_C_LDSP	0x6002
#define INSN_MASK_C_LDSP	0xe003
#define INSN_MATCH_C_SDSP	0xe002
#define INSN_MASK_C_SDSP	0xe003
#define INSN_MATCH_C_LWSP	0x4002
#define INSN_MASK_C_LWSP	0xe003
#define INSN_MATCH_C_SWSP	0xc002
#define INSN_MASK_C_SWSP	0xe003

#define INSN_16BIT_MASK		0x3

#define INSN_IS_16BIT(insn)	(((insn) & INSN_16BIT_MASK) != INSN_16BIT_MASK)

#define INSN_LEN(insn)		(INSN_IS_16BIT(insn) ? 2 : 4)

#ifdef CONFIG_64BIT
#define LOG_REGBYTES		3
#else
#define LOG_REGBYTES		2
#endif
#define REGBYTES		(1 << LOG_REGBYTES)

#define SH_RD			7
#define SH_RS1			15
#define SH_RS2			20
#define SH_RS2C			2

#define RV_X(x, s, n)		(((x) >> (s)) & ((1 << (n)) - 1))
#define RVC_LW_IMM(x)		((RV_X(x, 6, 1) << 2) | \
				 (RV_X(x, 10, 3) << 3) | \
				 (RV_X(x, 5, 1) << 6))
#define RVC_LD_IMM(x)		((RV_X(x, 10, 3) << 3) | \
				 (RV_X(x, 5, 2) << 6))
#define RVC_LWSP_IMM(x)		((RV_X(x, 4, 3) << 2) | \
				 (RV_X(x, 12, 1) << 5) | \
				 (RV_X(x, 2, 2) << 6))
#define RVC_LDSP_IMM(x)		((RV_X(x, 5, 2) << 3) | \
				 (RV_X(x, 12, 1) << 5) | \
				 (RV_X(x, 2, 3) << 6))
#define RVC_SWSP_IMM(x)		((RV_X(x, 9, 4) << 2) | \
				 (RV_X(x, 7, 2) << 6))
#define RVC_SDSP_IMM(x)		((RV_X(x, 10, 3) << 3) | \
				 (RV_X(x, 7, 3) << 6))
#define RVC_RS1S(insn)		(8 + RV_X(insn, SH_RD, 3))
#define RVC_RS2S(insn)		(8 + RV_X(insn, SH_RS2C, 3))
#define RVC_RS2(insn)		RV_X(insn, SH_RS2C, 5)

#define SHIFT_RIGHT(x, y)		\
	((y) < 0 ? ((x) << -(y)) : ((x) >> (y)))

#define REG_MASK			\
	((1 << (5 + LOG_REGBYTES)) - (1 << LOG_REGBYTES))

#define REG_OFFSET(insn, pos)		\
	(SHIFT_RIGHT((insn), (pos) - LOG_REGBYTES) & REG_MASK)

#define REG_PTR(insn, pos, regs)	\
	(ulong *)((ulong)(regs) + REG_OFFSET(insn, pos))

#define GET_RM(insn)		(((insn) >> 12) & 7)

#define GET_RS1(insn, regs)	(*REG_PTR(insn, SH_RS1, regs))
#define GET_RS2(insn, regs)	(*REG_PTR(insn, SH_RS2, regs))
#define GET_RS1S(insn, regs)	(*REG_PTR(RVC_RS1S(insn), 0, regs))
#define GET_RS2S(insn, regs)	(*REG_PTR(RVC_RS2S(insn), 0, regs))
#define GET_RS2C(insn, regs)	(*REG_PTR(insn, SH_RS2C, regs))
#define GET_SP(regs)		(*REG_PTR(2, 0, regs))
#define SET_RD(insn, regs, val)	(*REG_PTR(insn, SH_RD, regs) = (val))
#define IMM_I(insn)		((s32)(insn) >> 20)
#define IMM_S(insn)		(((s32)(insn) >> 25 << 5) | \
				 (s32)(((insn) >> 7) & 0x1f))
#define MASK_FUNCT3		0x7000

static int emulate_load(struct kvm_vcpu *vcpu, struct kvm_run *run,
			unsigned long fault_addr, unsigned long htinst)
{
	int shift = 0, len = 0;
	unsigned long insn, ut_scause = 0;
	struct kvm_cpu_context *ct = &vcpu->arch.guest_context;

	/* Determine trapped instruction */
	if (htinst & 0x1) {
		/*
		 * Bit[0] == 1 implies trapped instruction value is
		 * transformed instruction or custom instruction.
		 */
		insn = htinst | INSN_16BIT_MASK;
	} else {
		/*
		 * Bit[0] == 0 implies trapped instruction value is
		 * zero or special value.
		 */
		insn = kvm_riscv_vcpu_unpriv_read(vcpu, true, ct->sepc,
						  &ut_scause);
		if (ut_scause) {
			/* Redirect trap if we failed to read instruction */
			if (ut_scause == EXC_LOAD_PAGE_FAULT)
				ut_scause = EXC_INST_PAGE_FAULT;
			kvm_riscv_vcpu_trap_redirect(vcpu, ut_scause, ct->sepc);
			return 1;
		}
	}

	/* Decode length of MMIO and shift */
	if ((insn & INSN_MASK_LW) == INSN_MATCH_LW) {
		len = 4;
		shift = 8 * (sizeof(ulong) - len);
	} else if ((insn & INSN_MASK_LB) == INSN_MATCH_LB) {
		len = 1;
		shift = 8 * (sizeof(ulong) - len);
	} else if ((insn & INSN_MASK_LBU) == INSN_MATCH_LBU) {
		len = 1;
		shift = 8 * (sizeof(ulong) - len);
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_LD) == INSN_MATCH_LD) {
		len = 8;
		shift = 8 * (sizeof(ulong) - len);
	} else if ((insn & INSN_MASK_LWU) == INSN_MATCH_LWU) {
		len = 4;
#endif
	} else if ((insn & INSN_MASK_LH) == INSN_MATCH_LH) {
		len = 2;
		shift = 8 * (sizeof(ulong) - len);
	} else if ((insn & INSN_MASK_LHU) == INSN_MATCH_LHU) {
		len = 2;
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_C_LD) == INSN_MATCH_C_LD) {
		len = 8;
		shift = 8 * (sizeof(ulong) - len);
		insn = RVC_RS2S(insn) << SH_RD;
	} else if ((insn & INSN_MASK_C_LDSP) == INSN_MATCH_C_LDSP &&
		   ((insn >> SH_RD) & 0x1f)) {
		len = 8;
		shift = 8 * (sizeof(ulong) - len);
#endif
	} else if ((insn & INSN_MASK_C_LW) == INSN_MATCH_C_LW) {
		len = 4;
		shift = 8 * (sizeof(ulong) - len);
		insn = RVC_RS2S(insn) << SH_RD;
	} else if ((insn & INSN_MASK_C_LWSP) == INSN_MATCH_C_LWSP &&
		   ((insn >> SH_RD) & 0x1f)) {
		len = 4;
		shift = 8 * (sizeof(ulong) - len);
	} else {
		return -ENOTSUPP;
	}

	/* Fault address should be aligned to length of MMIO */
	if (fault_addr & (len - 1))
		return -EIO;

	/* Save instruction decode info */
	vcpu->arch.mmio_decode.insn = insn;
	vcpu->arch.mmio_decode.shift = shift;
	vcpu->arch.mmio_decode.len = len;
	vcpu->arch.mmio_decode.return_handled = 0;

	/* Exit to userspace for MMIO emulation */
	vcpu->stat.mmio_exit_user++;
	run->exit_reason = KVM_EXIT_MMIO;
	run->mmio.is_write = false;
	run->mmio.phys_addr = fault_addr;
	run->mmio.len = len;

	return 0;
}

static int emulate_store(struct kvm_vcpu *vcpu, struct kvm_run *run,
			 unsigned long fault_addr, unsigned long htinst)
{
	u8 data8;
	u16 data16;
	u32 data32;
	u64 data64;
	ulong data;
	int len = 0;
	unsigned long insn, ut_scause = 0;
	struct kvm_cpu_context *ct = &vcpu->arch.guest_context;

	/* Determine trapped instruction */
	if (htinst & 0x1) {
		/*
		 * Bit[0] == 1 implies trapped instruction value is
		 * transformed instruction or custom instruction.
		 */
		insn = htinst | INSN_16BIT_MASK;
	} else {
		/*
		 * Bit[0] == 0 implies trapped instruction value is
		 * zero or special value.
		 */
		insn = kvm_riscv_vcpu_unpriv_read(vcpu, true, ct->sepc,
						  &ut_scause);
		if (ut_scause) {
			/* Redirect trap if we failed to read instruction */
			if (ut_scause == EXC_LOAD_PAGE_FAULT)
				ut_scause = EXC_INST_PAGE_FAULT;
			kvm_riscv_vcpu_trap_redirect(vcpu, ut_scause, ct->sepc);
			return 1;
		}
	}

	data = GET_RS2(insn, &vcpu->arch.guest_context);
	data8 = data16 = data32 = data64 = data;

	if ((insn & INSN_MASK_SW) == INSN_MATCH_SW) {
		len = 4;
	} else if ((insn & INSN_MASK_SB) == INSN_MATCH_SB) {
		len = 1;
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_SD) == INSN_MATCH_SD) {
		len = 8;
#endif
	} else if ((insn & INSN_MASK_SH) == INSN_MATCH_SH) {
		len = 2;
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_C_SD) == INSN_MATCH_C_SD) {
		len = 8;
		data64 = GET_RS2S(insn, &vcpu->arch.guest_context);
	} else if ((insn & INSN_MASK_C_SDSP) == INSN_MATCH_C_SDSP &&
		   ((insn >> SH_RD) & 0x1f)) {
		len = 8;
		data64 = GET_RS2C(insn, &vcpu->arch.guest_context);
#endif
	} else if ((insn & INSN_MASK_C_SW) == INSN_MATCH_C_SW) {
		len = 4;
		data32 = GET_RS2S(insn, &vcpu->arch.guest_context);
	} else if ((insn & INSN_MASK_C_SWSP) == INSN_MATCH_C_SWSP &&
		   ((insn >> SH_RD) & 0x1f)) {
		len = 4;
		data32 = GET_RS2C(insn, &vcpu->arch.guest_context);
	} else {
		return -ENOTSUPP;
	}

	/* Fault address should be aligned to length of MMIO */
	if (fault_addr & (len - 1))
		return -EIO;

	/* Save instruction decode info */
	vcpu->arch.mmio_decode.insn = insn;
	vcpu->arch.mmio_decode.shift = 0;
	vcpu->arch.mmio_decode.len = len;
	vcpu->arch.mmio_decode.return_handled = 0;

	/* Copy data to kvm_run instance */
	switch (len) {
	case 1:
		*((u8 *)run->mmio.data) = data8;
		break;
	case 2:
		*((u16 *)run->mmio.data) = data16;
		break;
	case 4:
		*((u32 *)run->mmio.data) = data32;
		break;
	case 8:
		*((u64 *)run->mmio.data) = data64;
		break;
	default:
		return -ENOTSUPP;
	};

	/* Exit to userspace for MMIO emulation */
	vcpu->stat.mmio_exit_user++;
	run->exit_reason = KVM_EXIT_MMIO;
	run->mmio.is_write = true;
	run->mmio.phys_addr = fault_addr;
	run->mmio.len = len;

	return 0;
}

static int stage2_page_fault(struct kvm_vcpu *vcpu, struct kvm_run *run,
			     unsigned long scause, unsigned long stval,
			     unsigned long htval, unsigned long htinst)
{
	struct kvm_memory_slot *memslot;
	unsigned long hva, fault_addr;
	bool writable;
	gfn_t gfn;
	int ret;

	fault_addr = (htval << 2) | (stval & 0x3);
	gfn = fault_addr >> PAGE_SHIFT;
	memslot = gfn_to_memslot(vcpu->kvm, gfn);
	hva = gfn_to_hva_memslot_prot(memslot, gfn, &writable);

	if (kvm_is_error_hva(hva) ||
	    (scause == EXC_STORE_GUEST_PAGE_FAULT && !writable)) {
		switch (scause) {
		case EXC_LOAD_GUEST_PAGE_FAULT:
			return emulate_load(vcpu, run, fault_addr, htinst);
		case EXC_STORE_GUEST_PAGE_FAULT:
			return emulate_store(vcpu, run, fault_addr, htinst);
		default:
			return -ENOTSUPP;
		};
	}

	ret = kvm_riscv_stage2_map(vcpu, fault_addr, hva,
			(scause == EXC_STORE_GUEST_PAGE_FAULT) ? true : false);
	if (ret < 0)
		return ret;

	return 1;
}

#define STR(x)		XSTR(x)
#define XSTR(x)		#x

/**
 * kvm_riscv_vcpu_unpriv_read -- Read machine word from Guest memory
 *
 * @vcpu: The VCPU pointer
 * @read_insn: Flag representing whether we are reading instruction
 * @guest_addr: Guest address to read
 * @trap_scause: Output pointer for unprivilege trap cause
 */
unsigned long kvm_riscv_vcpu_unpriv_read(struct kvm_vcpu *vcpu,
					 bool read_insn,
					 unsigned long guest_addr,
					 unsigned long *trap_scause)
{
	register unsigned long tscause asm("a0");
	register unsigned long val asm("a1");
	register unsigned long addr asm("a2") = guest_addr;
	unsigned long guest_sstatus =
		vcpu->arch.guest_context.sstatus | ((read_insn) ? SR_MXR : 0);
	unsigned long guest_hstatus =
		vcpu->arch.guest_context.hstatus | HSTATUS_SPRV;
	unsigned long old_stvec, tmp;

	BUG_ON(guest_sstatus & SR_SIE);

	guest_sstatus = csr_swap(CSR_SSTATUS, guest_sstatus);
	old_stvec = csr_swap(CSR_STVEC, (ulong)&__kvm_riscv_unpriv_trap);

	if (read_insn) {
		asm volatile ("\n"
			"csrrw %[hstatus], " STR(CSR_HSTATUS) ", %[hstatus]\n"
			"li %[tscause], 0\n"
			"lhu %[val], (%[addr])\n"
			"andi %[tmp], %[val], 3\n"
			"addi %[tmp], %[tmp], -3\n"
			"bne %[tmp], zero, 2f\n"
			"lhu %[tmp], 2(%[addr])\n"
			"sll %[tmp], %[tmp], 16\n"
			"add %[val], %[val], %[tmp]\n"
			"2: csrw " STR(CSR_HSTATUS) ", %[hstatus]"
		: [hstatus] "+&r"(guest_hstatus), [val] "=&r" (val),
		  [tmp] "=&r" (tmp), [tscause] "+&r" (tscause)
		: [addr] "r" (addr));
	} else {
		asm volatile ("\n"
			"csrrw %[hstatus], " STR(CSR_HSTATUS) ", %[hstatus]\n"
			"li %[tscause], 0\n"
			".option push\n"
			".option norvc\n"
#ifdef CONFIG_64BIT
			"ld %[val], (%[addr])\n"
#else
			"lw %[val], (%[addr])\n"
#endif
			".option pop\n"
			"csrw " STR(CSR_HSTATUS) ", %[hstatus]"
		: [hstatus] "+&r"(guest_hstatus),
		  [val] "=&r" (val), [tscause] "+&r" (tscause)
		: [addr] "r" (addr));
	}

	csr_write(CSR_STVEC, old_stvec);
	csr_write(CSR_SSTATUS, guest_sstatus);

	*trap_scause = tscause;

	return val;
}

/**
 * kvm_riscv_vcpu_trap_redirect -- Redirect trap to Guest
 *
 * @vcpu: The VCPU pointer
 * @scause: Trap exception cause
 * @stval: Trap value
 */
void kvm_riscv_vcpu_trap_redirect(struct kvm_vcpu *vcpu,
				  unsigned long scause, unsigned long stval)
{
	unsigned long vsstatus = csr_read(CSR_VSSTATUS);

	/* Change Guest SSTATUS.SPP bit */
	vsstatus &= ~SR_SPP;
	if (vcpu->arch.guest_context.sstatus & SR_SPP)
		vsstatus |= SR_SPP;

	/* Change Guest SSTATUS.SPIE bit */
	vsstatus &= ~SR_SPIE;
	if (vsstatus & SR_SIE)
		vsstatus |= SR_SPIE;

	/* Clear Guest SSTATUS.SIE bit */
	vsstatus &= ~SR_SIE;

	/* Update Guest SSTATUS */
	csr_write(CSR_VSSTATUS, vsstatus);

	/* Update Guest SCAUSE, STVAL, and SEPC */
	csr_write(CSR_VSCAUSE, scause);
	csr_write(CSR_VSTVAL, stval);
	csr_write(CSR_VSEPC, vcpu->arch.guest_context.sepc);

	/* Set Guest PC to Guest exception vector */
	vcpu->arch.guest_context.sepc = csr_read(CSR_VSTVEC);
}

/**
 * kvm_riscv_vcpu_mmio_return -- Handle MMIO loads after user space emulation
 *			     or in-kernel IO emulation
 *
 * @vcpu: The VCPU pointer
 * @run:  The VCPU run struct containing the mmio data
 */
int kvm_riscv_vcpu_mmio_return(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	u8 data8;
	u16 data16;
	u32 data32;
	u64 data64;
	ulong insn;
	int len, shift;

	if (vcpu->arch.mmio_decode.return_handled)
		return 0;

	vcpu->arch.mmio_decode.return_handled = 1;
	insn = vcpu->arch.mmio_decode.insn;

	if (run->mmio.is_write)
		goto done;

	len = vcpu->arch.mmio_decode.len;
	shift = vcpu->arch.mmio_decode.shift;

	switch (len) {
	case 1:
		data8 = *((u8 *)run->mmio.data);
		SET_RD(insn, &vcpu->arch.guest_context,
			(ulong)data8 << shift >> shift);
		break;
	case 2:
		data16 = *((u16 *)run->mmio.data);
		SET_RD(insn, &vcpu->arch.guest_context,
			(ulong)data16 << shift >> shift);
		break;
	case 4:
		data32 = *((u32 *)run->mmio.data);
		SET_RD(insn, &vcpu->arch.guest_context,
			(ulong)data32 << shift >> shift);
		break;
	case 8:
		data64 = *((u64 *)run->mmio.data);
		SET_RD(insn, &vcpu->arch.guest_context,
			(ulong)data64 << shift >> shift);
		break;
	default:
		return -ENOTSUPP;
	};

done:
	/* Move to next instruction */
	vcpu->arch.guest_context.sepc += INSN_LEN(insn);

	return 0;
}

/*
 * Return > 0 to return to guest, < 0 on error, 0 (and set exit_reason) on
 * proper exit to userspace.
 */
int kvm_riscv_vcpu_exit(struct kvm_vcpu *vcpu, struct kvm_run *run,
			unsigned long scause, unsigned long stval,
			unsigned long htval, unsigned long htinst)
{
	int ret;

	/* If we got host interrupt then do nothing */
	if (scause & CAUSE_IRQ_FLAG)
		return 1;

	/* Handle guest traps */
	ret = -EFAULT;
	run->exit_reason = KVM_EXIT_UNKNOWN;
	switch (scause) {
	case EXC_INST_GUEST_PAGE_FAULT:
	case EXC_LOAD_GUEST_PAGE_FAULT:
	case EXC_STORE_GUEST_PAGE_FAULT:
		if (vcpu->arch.guest_context.hstatus & HSTATUS_SPV)
			ret = stage2_page_fault(vcpu, run, scause, stval,
						htval, htinst);
		break;
	default:
		break;
	};

	/* Print details in-case of error */
	if (ret < 0) {
		kvm_err("VCPU exit error %d\n", ret);
		kvm_err("SEPC=0x%lx SSTATUS=0x%lx HSTATUS=0x%lx\n",
			vcpu->arch.guest_context.sepc,
			vcpu->arch.guest_context.sstatus,
			vcpu->arch.guest_context.hstatus);
		kvm_err("SCAUSE=0x%lx STVAL=0x%lx\n",
			scause, stval);
	}

	return ret;
}
