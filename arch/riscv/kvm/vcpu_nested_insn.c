// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#include <linux/kvm_host.h>
#include <asm/kvm_nacl.h>
#include <asm/kvm_vcpu_insn.h>

int kvm_riscv_vcpu_nested_insn_sret(struct kvm_vcpu *vcpu, struct kvm_run *run, ulong insn)
{
	unsigned long vsstatus, next_sepc, next_spp;
	bool next_virt;

	/*
	 * Trap from virtual-VS/VU modes should be forwarded to
	 * virtual-HS mode as a virtual instruction trap.
	 */
	if (kvm_riscv_vcpu_nested_virt(vcpu))
		return KVM_INSN_VIRTUAL_TRAP;

	/*
	 * Trap from virtual-U mode should be forwarded to
	 * virtual-HS mode as illegal instruction trap.
	 */
	if (!(vcpu->arch.guest_context.hstatus & HSTATUS_SPVP))
		return KVM_INSN_ILLEGAL_TRAP;

	vsstatus = ncsr_read(CSR_VSSTATUS);

	/*
	 * Find next nested virtualization mode, next privilege mode,
	 * and next sepc
	 */
	next_virt = (vcpu->arch.nested.csr.hstatus & HSTATUS_SPV) ? true : false;
	next_sepc = ncsr_read(CSR_VSEPC);
	next_spp = vsstatus & SR_SPP;

	/* Update Guest sstatus.sie */
	vsstatus &= ~SR_SIE;
	vsstatus |= (vsstatus & SR_SPIE) ? SR_SIE : 0;
	ncsr_write(CSR_VSSTATUS, vsstatus);

	/* Update return address and return privilege mode*/
	vcpu->arch.guest_context.sepc = next_sepc;
	vcpu->arch.guest_context.sstatus &= ~SR_SPP;
	vcpu->arch.guest_context.sstatus |= next_spp;

	/* Set nested virtualization state based on guest hstatus.SPV */
	kvm_riscv_vcpu_nested_set_virt(vcpu, NESTED_SET_VIRT_EVENT_SRET,
				       next_virt, false, false);

	return KVM_INSN_CONTINUE_SAME_SEPC;
}
