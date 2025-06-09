// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#include <linux/smp.h>
#include <linux/kvm_host.h>
#include <asm/kvm_nacl.h>

DEFINE_STATIC_KEY_FALSE(kvm_riscv_nested_available);

static bool __read_mostly enable_nested_virt;
module_param(enable_nested_virt, bool, 0644);

void kvm_riscv_vcpu_nested_set_virt(struct kvm_vcpu *vcpu,
				    enum kvm_vcpu_nested_set_virt_event event,
				    bool virt, bool spvp, bool gva)
{
	struct kvm_vcpu_nested *ns = &vcpu->arch.nested;
	struct kvm_vcpu_nested_csr *nsc = &ns->csr;
	unsigned long tmp, sr_fs_vs_mask = 0;
	int cpu;

	/* If H-extension is not available for VCPU then do nothing */
	if (!riscv_isa_extension_available(vcpu->arch.isa, h))
		return;

	/* Grab the CPU to ensure we remain on same CPU */
	cpu = get_cpu();

	/* Skip hardware CSR update if no change in virt state */
	if (virt == ns->virt)
		goto skip_csr_update;

	/* TODO: */

	/* Swap hardware vs<xyz> CSRs except vsie and vsstatus */
	nsc->vstvec = ncsr_swap(CSR_VSTVEC, nsc->vstvec);
	nsc->vsscratch = ncsr_swap(CSR_VSSCRATCH, nsc->vsscratch);
	nsc->vsepc = ncsr_swap(CSR_VSEPC, nsc->vsepc);
	nsc->vscause = ncsr_swap(CSR_VSCAUSE, nsc->vscause);
	nsc->vstval = ncsr_swap(CSR_VSTVAL, nsc->vstval);
	nsc->vsatp = ncsr_swap(CSR_VSATP, nsc->vsatp);

	/* Update vsstatus CSR */
	if (riscv_isa_extension_available(vcpu->arch.isa, f) ||
	    riscv_isa_extension_available(vcpu->arch.isa, d))
		sr_fs_vs_mask |= SR_FS;
	if (riscv_isa_extension_available(vcpu->arch.isa, v))
		sr_fs_vs_mask |= SR_VS;
	if (virt) {
		/*
		 * Update vsstatus in following manner:
		 * 1) Swap hardware vsstatus (i.e. virtual-HS mode sstatus) with
		 *    vsstatus in nested virtualization context (i.e. virtual-VS
		 *    mode sstatus)
		 * 2) Swap host sstatus.[FS|VS] (i.e. HS mode sstatus.[FS|VS])
		 *    with the vsstatus.[FS|VS] saved in nested virtualization
		 *    context (i.e. virtual-HS mode sstatus.[FS|VS])
		 */
		nsc->vsstatus = ncsr_swap(CSR_VSSTATUS, nsc->vsstatus);
		tmp = vcpu->arch.guest_context.sstatus & sr_fs_vs_mask;
		vcpu->arch.guest_context.sstatus &= ~sr_fs_vs_mask;
		vcpu->arch.guest_context.sstatus |= (nsc->vsstatus & sr_fs_vs_mask);
		nsc->vsstatus &= ~sr_fs_vs_mask;
		nsc->vsstatus |= tmp;
	} else {
		/*
		 * Update vsstatus in following manner:
		 * 1) Swap host sstatus.[FS|VS] (i.e. virtual-HS mode sstatus.[FS|VS])
		 *    with vsstatus.[FS|VS] saved in the nested virtualization context
		 *    context (i.e. HS mode sstatus.[FS|VS])
		 * 2) Swap hardware vsstatus (i.e. virtual-VS mode sstatus) with
		 *    vsstatus in nested virtualization context (i.e. virtual-HS
		 *    mode sstatus)
		 */
		tmp = vcpu->arch.guest_context.sstatus & sr_fs_vs_mask;
		vcpu->arch.guest_context.sstatus &= ~sr_fs_vs_mask;
		vcpu->arch.guest_context.sstatus |= (nsc->vsstatus & sr_fs_vs_mask);
		nsc->vsstatus &= ~sr_fs_vs_mask;
		nsc->vsstatus |= tmp;
		nsc->vsstatus = ncsr_swap(CSR_VSSTATUS, nsc->vsstatus);
	}

skip_csr_update:
	if (event != NESTED_SET_VIRT_EVENT_SRET) {
		/* Update guest hstatus.SPV bit */
		nsc->hstatus &= ~HSTATUS_SPV;
		nsc->hstatus |= (ns->virt) ? HSTATUS_SPV : 0;

		/* Update guest hstatus.SPVP bit */
		if (ns->virt) {
			nsc->hstatus &= ~HSTATUS_SPVP;
			if (spvp)
				nsc->hstatus |= HSTATUS_SPVP;
		}

		/* Update guest hstatus.GVA bit */
		if (event == NESTED_SET_VIRT_EVENT_TRAP) {
			nsc->hstatus &= ~HSTATUS_GVA;
			nsc->hstatus |= (gva) ? HSTATUS_GVA : 0;
		}
	}

	/* Update host SRET trapping */
	vcpu->arch.guest_context.hstatus &= ~HSTATUS_VTSR;
	if (virt) {
		if (nsc->hstatus & HSTATUS_VTSR)
			vcpu->arch.guest_context.hstatus |= HSTATUS_VTSR;
	} else {
		if (nsc->hstatus & HSTATUS_SPV)
			vcpu->arch.guest_context.hstatus |= HSTATUS_VTSR;
	}

	/* Update host VM trapping */
	vcpu->arch.guest_context.hstatus &= ~HSTATUS_VTVM;
	if (virt && (nsc->hstatus & HSTATUS_VTVM))
		vcpu->arch.guest_context.hstatus |= HSTATUS_VTVM;

	/* Update virt flag */
	ns->virt = virt;

	/* Release CPU */
	put_cpu();
}

void kvm_riscv_vcpu_nested_trap_redirect(struct kvm_vcpu *vcpu,
					 struct kvm_cpu_trap *trap,
					 bool prev_priv)
{
	bool gva;

	/* Do nothing if H-extension is not available for VCPU */
	if (!riscv_isa_extension_available(vcpu->arch.isa, h))
		return;

	/* Determine GVA bit state */
	gva = false;
	switch (trap->scause) {
	case EXC_INST_MISALIGNED:
	case EXC_INST_ACCESS:
	case EXC_LOAD_MISALIGNED:
	case EXC_LOAD_ACCESS:
	case EXC_STORE_MISALIGNED:
	case EXC_STORE_ACCESS:
	case EXC_INST_PAGE_FAULT:
	case EXC_LOAD_PAGE_FAULT:
	case EXC_STORE_PAGE_FAULT:
	case EXC_INST_GUEST_PAGE_FAULT:
	case EXC_LOAD_GUEST_PAGE_FAULT:
	case EXC_STORE_GUEST_PAGE_FAULT:
		gva = true;
		break;
	default:
		break;
	}

	/* Update Guest HTVAL and HTINST */
	vcpu->arch.nested.csr.htval = trap->htval;
	vcpu->arch.nested.csr.htinst = trap->htinst;

	/* Turn-off nested virtualization for virtual-HS mode */
	kvm_riscv_vcpu_nested_set_virt(vcpu, NESTED_SET_VIRT_EVENT_TRAP,
				       false, prev_priv, gva);
}

void kvm_riscv_vcpu_nested_vsirq_process(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested *ns = &vcpu->arch.nested;

	/* Do nothing if nested virtualization is OFF */
	if (!ns->virt)
		return;

	/* TODO: */
}

void kvm_riscv_vcpu_nested_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested *ns = &vcpu->arch.nested;
	struct kvm_vcpu_nested_csr *ncsr = &vcpu->arch.nested.csr;

	ns->virt = false;
	kvm_riscv_vcpu_nested_swtlb_reset(vcpu);
	memset(ncsr, 0, sizeof(*ncsr));
}

void kvm_riscv_nested_init(void)
{
	/*
	 * Nested virtualization uses hvictl CSR hence only
	 * available when AIA is available.
	 */
	if (!kvm_riscv_aia_available())
		return;

	/* Check state of module parameter */
	if (!enable_nested_virt)
		return;

	/* Enable KVM nested virtualization support */
	static_branch_enable(&kvm_riscv_nested_available);
}
