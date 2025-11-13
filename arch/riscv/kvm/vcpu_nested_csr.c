// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#include <linux/kvm_host.h>
#include <asm/csr.h>
#include <asm/pgtable.h>

#define NESTED_SIE_WRITEABLE		(BIT(IRQ_S_SOFT) | BIT(IRQ_S_TIMER) | BIT(IRQ_S_EXT))
#define NESTED_HVIP_WRITEABLE		(BIT(IRQ_VS_SOFT) | BIT(IRQ_VS_TIMER) | BIT(IRQ_VS_EXT))
#define NESTED_HIDELEG_WRITEABLE	NESTED_HVIP_WRITEABLE
#define NESTED_HEDELEG_WRITEABLE	\
	(BIT(EXC_INST_MISALIGNED) |	\
	 BIT(EXC_INST_ACCESS) |		\
	 BIT(EXC_INST_ILLEGAL) |	\
	 BIT(EXC_BREAKPOINT) |		\
	 BIT(EXC_LOAD_MISALIGNED) |	\
	 BIT(EXC_LOAD_ACCESS) |		\
	 BIT(EXC_STORE_MISALIGNED) |	\
	 BIT(EXC_STORE_ACCESS) |	\
	 BIT(EXC_SYSCALL) |		\
	 BIT(EXC_INST_PAGE_FAULT) |	\
	 BIT(EXC_LOAD_PAGE_FAULT) |	\
	 BIT(EXC_STORE_PAGE_FAULT))
#define NESTED_HCOUNTEREN_WRITEABLE	-1UL
#define NESTED_VSIE_WRITEABLE		NESTED_SIE_WRITEABLE
#define NESTED_VSCAUSE_WRITEABLE	GENMASK(4, 0)

int kvm_riscv_vcpu_nested_smode_csr_rmw(struct kvm_vcpu *vcpu, unsigned int csr_num,
				        unsigned long *val, unsigned long new_val,
				        unsigned long wr_mask)
{
	struct kvm_vcpu_nested_csr *nsc = &vcpu->arch.nested.csr;
	unsigned long *csr, tmpcsr = 0, csr_rdor = 0;
	unsigned long writeable_mask = 0;
#ifdef CONFIG_32BIT
	unsigned long zero = 0;
#endif
	int csr_shift = 0;
	u64 tmp64;

	/*
	 * These CSRs should never trap for virtual-HS/U modes because
	 * we only emulate these CSRs for virtual-VS/VU modes.
	 */
	if (!kvm_riscv_vcpu_nested_virt(vcpu))
		return -EINVAL;

	/*
	 * Access of these CSRs from virtual-VU mode should be forwarded
	 * as illegal instruction trap to virtual-HS mode.
	 */
	if (!(vcpu->arch.guest_context.hstatus & HSTATUS_SPVP))
		return KVM_INSN_ILLEGAL_TRAP;

	switch (csr_num) {
	case CSR_SIE:
		csr = &nsc->vsie;
		writeable_mask = NESTED_SIE_WRITEABLE & (nsc->hideleg >> VSIP_TO_HVIP_SHIFT);
		break;
#ifdef CONFIG_32BIT
	case CSR_SIEH:
		csr = &zero;
		break;
#endif
	case CSR_SIP:
		csr = &nsc->hvip;
		csr_rdor = kvm_riscv_vcpu_nested_timer_irq(vcpu) ? BIT(IRQ_VS_TIMER) : 0;
		csr_shift = VSIP_TO_HVIP_SHIFT;
		writeable_mask = BIT(IRQ_VS_EXT) & nsc->hideleg;
		break;
#ifdef CONFIG_32BIT
	case CSR_SIPH:
		csr = &zero;
		break;
#endif
	case CSR_STIMECMP:
		if (!riscv_isa_extension_available(vcpu->arch.isa, SSTC))
			return KVM_INSN_ILLEGAL_TRAP;
#ifdef CONFIG_32BIT
		if (!(nsc->henvcfgh & (ENVCFG_STCE >> 32)))
#else
		if (!(nsc->henvcfg & ENVCFG_STCE))
#endif
			return KVM_INSN_VIRTUAL_TRAP;
		tmpcsr = kvm_riscv_vcpu_nested_timer_cycles(vcpu);
		csr = &tmpcsr;
		writeable_mask = -1UL;
		break;
#ifdef CONFIG_32BIT
	case CSR_STIMECMPH:
		if (!riscv_isa_extension_available(vcpu->arch.isa, SSTC))
			return KVM_INSN_ILLEGAL_TRAP;
		if (!(nsc->henvcfgh & (ENVCFG_STCE >> 32)))
			return KVM_INSN_VIRTUAL_TRAP;
		tmpcsr = kvm_riscv_vcpu_nested_timer_cycles(vcpu) >> 32;
		csr = &tmpcsr;
		writeable_mask = -1UL;
		break;
#endif
	default:
		return KVM_INSN_ILLEGAL_TRAP;
	}

	if (val)
		*val = (csr_shift < 0) ? (*csr | csr_rdor) << -csr_shift :
					 (*csr | csr_rdor) >> csr_shift;

	if (wr_mask) {
		writeable_mask = (csr_shift < 0) ?
				  writeable_mask >> -csr_shift :
				  writeable_mask << csr_shift;
		wr_mask = (csr_shift < 0) ?
			   wr_mask >> -csr_shift : wr_mask << csr_shift;
		new_val = (csr_shift < 0) ?
			   new_val >> -csr_shift : new_val << csr_shift;
		wr_mask &= writeable_mask;
		*csr = (*csr & ~wr_mask) | (new_val & wr_mask);

		switch (csr_num) {
		case CSR_STIMECMP:
#ifdef CONFIG_32BIT
			tmp64 = kvm_riscv_vcpu_nested_timer_cycles(vcpu);
			tmp64 &= ~0xffffffffULL;
			tmp64 |= tmpcsr;
#else
			tmp64 = tmpcsr;
#endif
			kvm_riscv_vcpu_nested_timer_start(vcpu, tmp64);
			break;
#ifdef CONFIG_32BIT
		case CSR_STIMECMPH:
			tmp64 = kvm_riscv_vcpu_nested_timer_cycles(vcpu);
			tmp64 &= ~0xffffffff00000000ULL;
			tmp64 |= ((u64)tmpcsr) << 32;
			kvm_riscv_vcpu_nested_timer_start(vcpu, tmp64);
			break;
#endif
		default:
			break;
		}
	}

	return KVM_INSN_CONTINUE_NEXT_SEPC;
}

static int __riscv_vcpu_nested_hext_csr_rmw(struct kvm_vcpu *vcpu,
					    bool priv_check, unsigned int csr_num,
					    unsigned long *val, unsigned long new_val,
					    unsigned long wr_mask)
{
	unsigned int csr_priv = (csr_num >> CSR_NUM_PRIV_SHIFT) & CSR_NUM_PRIV_MASK;
	struct kvm_vcpu_nested_csr *nsc = &vcpu->arch.nested.csr;
	unsigned long mode, zero = 0, writeable_mask = 0;
	unsigned long *csr, tmpcsr = 0, csr_rdor = 0;
	bool read_only = false, nuke_swtlb = false;
	int csr_shift = 0;
	u64 tmp64;

	/*
	 * If H-extension is not available for VCPU then forward trap
	 * as illegal instruction trap to virtual-HS mode.
	 */
	if (!riscv_isa_extension_available(vcpu->arch.isa, h))
		return KVM_INSN_ILLEGAL_TRAP;

	/*
	 * Trap from virtual-VS and virtual-VU modes should be forwarded
	 * to virtual-HS mode as a virtual instruction trap.
	 */
	if (kvm_riscv_vcpu_nested_virt(vcpu))
		return (csr_priv == CSR_PRIV_HYPERVISOR) ?
			KVM_INSN_VIRTUAL_TRAP : KVM_INSN_ILLEGAL_TRAP;

	/*
	 * H-extension CSRs not allowed in virtual-U mode so forward trap
	 * as illegal instruction trap to virtual-HS mode.
	 */
	if (priv_check && !(vcpu->arch.guest_context.hstatus & HSTATUS_SPVP))
		return KVM_INSN_ILLEGAL_TRAP;

	switch (csr_num) {
	case CSR_HSTATUS:
		csr = &nsc->hstatus;
		writeable_mask = HSTATUS_VTSR | HSTATUS_VTW | HSTATUS_VTVM |
				 HSTATUS_HU | HSTATUS_SPVP | HSTATUS_SPV |
				 HSTATUS_GVA;
		if (wr_mask & HSTATUS_SPV) {
			/*
			 * If hstatus.SPV == 1 then enable host SRET
			 * trapping for the virtual-HS mode which will
			 * allow host to do nested world-switch upon
			 * next SRET instruction executed by the
			 * virtual-HS-mode.
			 *
			 * If hstatus.SPV == 0 then disable host SRET
			 * trapping for the virtual-HS mode which will
			 * ensure that host does not do any nested
			 * world-switch for SRET instruction executed
			 * virtual-HS mode for general interrupt and
			 * trap handling.
			 */
			vcpu->arch.guest_context.hstatus &= ~HSTATUS_VTSR;
			vcpu->arch.guest_context.hstatus |= (new_val & HSTATUS_SPV) ?
							    HSTATUS_VTSR : 0;
		}
		break;
	case CSR_HEDELEG:
		csr = &nsc->hedeleg;
		writeable_mask = NESTED_HEDELEG_WRITEABLE;
		break;
	case CSR_HIDELEG:
		csr = &nsc->hideleg;
		writeable_mask = NESTED_HIDELEG_WRITEABLE;
		break;
	case CSR_HVIP:
		csr = &nsc->hvip;
		writeable_mask = NESTED_HVIP_WRITEABLE;
		break;
	case CSR_HIE:
		csr = &nsc->vsie;
		csr_shift = -VSIP_TO_HVIP_SHIFT;
		writeable_mask = NESTED_HVIP_WRITEABLE;
		break;
	case CSR_HIP:
		csr = &nsc->hvip;
		csr_rdor = kvm_riscv_vcpu_nested_timer_irq(vcpu) ? BIT(IRQ_VS_TIMER) : 0;
		writeable_mask = BIT(IRQ_VS_SOFT);
		break;
	case CSR_HGEIP:
		csr = &zero;
		read_only = true;
		break;
	case CSR_HGEIE:
		csr = &zero;
		break;
	case CSR_HCOUNTEREN:
		csr = &nsc->hcounteren;
		writeable_mask = NESTED_HCOUNTEREN_WRITEABLE;
		break;
	case CSR_HTIMEDELTA:
		csr = &nsc->htimedelta;
		writeable_mask = -1UL;
		break;
#ifndef CONFIG_64BIT
	case CSR_HTIMEDELTAH:
		csr = &nsc->htimedeltah;
		writeable_mask = -1UL;
		break;
#endif
	case CSR_HTVAL:
		csr = &nsc->htval;
		writeable_mask = -1UL;
		break;
	case CSR_HTINST:
		csr = &nsc->htinst;
		writeable_mask = -1UL;
		break;
	case CSR_HGATP:
		csr = &nsc->hgatp;
		writeable_mask = HGATP_MODE | HGATP_VMID | HGATP_PPN;
		if (wr_mask & HGATP_MODE) {
			mode = (new_val & HGATP_MODE) >> HGATP_MODE_SHIFT;
			switch (mode) {
			/*
			 * Intentionally support only Sv39x4 on RV64 and
			 * Sv32x4 on RV32 for guest G-stage so that software
			 * page table walks on guest G-stage are faster.
			 */
#ifdef CONFIG_64BIT
			case HGATP_MODE_SV39X4:
				if (kvm_riscv_gstage_mode != HGATP_MODE_SV57X4 &&
				    kvm_riscv_gstage_mode != HGATP_MODE_SV48X4 &&
				    kvm_riscv_gstage_mode != HGATP_MODE_SV39X4)
					mode = HGATP_MODE_OFF;
				break;
#else
			case HGATP_MODE_SV32X4:
				if (kvm_riscv_gstage_mode != HGATP_MODE_SV32X4)
					mode = HGATP_MODE_OFF;
				break;
#endif
			default:
				mode = HGATP_MODE_OFF;
				break;
			}
			new_val &= ~HGATP_MODE;
			new_val |= (mode << HGATP_MODE_SHIFT) & HGATP_MODE;
			if ((new_val ^ nsc->hgatp) & HGATP_MODE)
				nuke_swtlb = true;
		}
		if (wr_mask & HGATP_VMID) {
			if ((new_val ^ nsc->hgatp) & HGATP_VMID)
				nuke_swtlb = true;
		}
		break;
	case CSR_HENVCFG:
		csr = &nsc->henvcfg;
#ifdef CONFIG_64BIT
		writeable_mask = ENVCFG_STCE;
#endif
		break;
#ifdef CONFIG_32BIT
	case CSR_HENVCFGH:
		csr = &nsc->henvcfgh;
		writeable_mask = ENVCFG_STCE >> 32;
		break;
#endif
	case CSR_VSSTATUS:
		csr = &nsc->vsstatus;
		writeable_mask = SR_SIE | SR_SPIE | SR_SPP | SR_SUM | SR_MXR | SR_FS | SR_VS;
		break;
	case CSR_VSIP:
		csr = &nsc->hvip;
		csr_rdor = kvm_riscv_vcpu_nested_timer_irq(vcpu) ? BIT(IRQ_VS_TIMER) : 0;
		csr_shift = VSIP_TO_HVIP_SHIFT;
		writeable_mask = BIT(IRQ_VS_SOFT) & nsc->hideleg;
		break;
	case CSR_VSIE:
		csr = &nsc->vsie;
		writeable_mask = NESTED_VSIE_WRITEABLE & (nsc->hideleg >> VSIP_TO_HVIP_SHIFT);
		break;
	case CSR_VSTVEC:
		csr = &nsc->vstvec;
		writeable_mask = -1UL;
		break;
	case CSR_VSSCRATCH:
		csr = &nsc->vsscratch;
		writeable_mask = -1UL;
		break;
	case CSR_VSEPC:
		csr = &nsc->vsepc;
		writeable_mask = -1UL;
		break;
	case CSR_VSCAUSE:
		csr = &nsc->vscause;
		writeable_mask = NESTED_VSCAUSE_WRITEABLE;
		break;
	case CSR_VSTVAL:
		csr = &nsc->vstval;
		writeable_mask = -1UL;
		break;
	case CSR_VSATP:
		csr = &nsc->vsatp;
		writeable_mask = SATP_MODE | SATP_ASID | SATP_PPN;
		if (wr_mask & SATP_MODE) {
			mode = new_val & SATP_MODE;
			switch (mode) {
#ifdef CONFIG_64BIT
			case SATP_MODE_57:
				if (!pgtable_l5_enabled)
					mode = SATP_MODE_OFF;
				break;
			case SATP_MODE_48:
				if (!pgtable_l5_enabled && !pgtable_l4_enabled)
					mode = SATP_MODE_OFF;
				break;
			case SATP_MODE_39:
				break;
#else
			case SATP_MODE_32:
				break;
#endif
			default:
				mode = SATP_MODE_OFF;
				break;
			}
			new_val &= ~SATP_MODE;
			new_val |= mode & SATP_MODE;
		}
		break;
	case CSR_VSTIMECMP:
		if (!riscv_isa_extension_available(vcpu->arch.isa, SSTC))
			return KVM_INSN_ILLEGAL_TRAP;
		tmpcsr = kvm_riscv_vcpu_nested_timer_cycles(vcpu);
		csr = &tmpcsr;
		writeable_mask = -1UL;
		break;
#ifdef CONFIG_32BIT
	case CSR_VSTIMECMPH:
		if (!riscv_isa_extension_available(vcpu->arch.isa, SSTC))
			return KVM_INSN_ILLEGAL_TRAP;
		tmpcsr = kvm_riscv_vcpu_nested_timer_cycles(vcpu) >> 32;
		csr = &tmpcsr;
		writeable_mask = -1UL;
		break;
#endif
	default:
		return KVM_INSN_ILLEGAL_TRAP;
	}

	if (val)
		*val = (csr_shift < 0) ? (*csr | csr_rdor) << -csr_shift :
					 (*csr | csr_rdor) >> csr_shift;

	if (read_only) {
		return KVM_INSN_ILLEGAL_TRAP;
	} else if (wr_mask) {
		writeable_mask = (csr_shift < 0) ?
				  writeable_mask >> -csr_shift :
				  writeable_mask << csr_shift;
		wr_mask = (csr_shift < 0) ?
			   wr_mask >> -csr_shift : wr_mask << csr_shift;
		new_val = (csr_shift < 0) ?
			   new_val >> -csr_shift : new_val << csr_shift;
		wr_mask &= writeable_mask;
		*csr = (*csr & ~wr_mask) | (new_val & wr_mask);

		switch (csr_num) {
		case CSR_VSTIMECMP:
#ifdef CONFIG_32BIT
			tmp64 = kvm_riscv_vcpu_nested_timer_cycles(vcpu);
			tmp64 &= ~0xffffffffULL;
			tmp64 |= tmpcsr;
#else
			tmp64 = tmpcsr;
#endif
			kvm_riscv_vcpu_nested_timer_start(vcpu, tmp64);
			break;
#ifdef CONFIG_32BIT
		case CSR_VSTIMECMPH:
			tmp64 = kvm_riscv_vcpu_nested_timer_cycles(vcpu);
			tmp64 &= ~0xffffffff00000000ULL;
			tmp64 |= ((u64)tmpcsr) << 32;
			kvm_riscv_vcpu_nested_timer_start(vcpu, tmp64);
			break;
#endif
		case CSR_HTIMEDELTA:
			if (riscv_isa_extension_available(vcpu->arch.isa, SSTC))
				kvm_riscv_vcpu_nested_timer_restart(vcpu);
			break;
#ifdef CONFIG_32BIT
		case CSR_HTIMEDELTAH:
			if (riscv_isa_extension_available(vcpu->arch.isa, SSTC))
				kvm_riscv_vcpu_timer_vs_restart(vcpu);
			break;
#endif
		default:
			break;
		}
	}

	if (nuke_swtlb)
		kvm_riscv_vcpu_nested_swtlb_gvma_flush(vcpu, 0, 0, 0);

	return KVM_INSN_CONTINUE_NEXT_SEPC;
}

int kvm_riscv_vcpu_nested_hext_csr_rmw(struct kvm_vcpu *vcpu, unsigned int csr_num,
				       unsigned long *val, unsigned long new_val,
				       unsigned long wr_mask)
{
	return __riscv_vcpu_nested_hext_csr_rmw(vcpu, true, csr_num, val, new_val, wr_mask);
}

void kvm_riscv_vcpu_nested_csr_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_csr *nsc = &vcpu->arch.nested.csr;

	memset(nsc, 0, sizeof(*nsc));
}
