// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#include <linux/kvm_host.h>
#include <asm/kvm_nacl.h>

int kvm_riscv_vcpu_nested_swtlb_xlate(struct kvm_vcpu *vcpu,
				      const struct kvm_cpu_trap *trap,
				      struct kvm_gstage_mapping *out_map,
				      struct kvm_cpu_trap *out_trap)
{
	/* TODO: */
	return 0;
}

void kvm_riscv_vcpu_nested_swtlb_vvma_flush(struct kvm_vcpu *vcpu,
					    unsigned long vaddr, unsigned long size,
					    unsigned long order, unsigned long vmid)
{
	struct kvm_vcpu_nested *ns = &vcpu->arch.nested;
	struct kvm_vmid *v = &vcpu->kvm->arch.vmid;

	if (vmid != -1UL && ((ns->csr.hgatp & HGATP_VMID) >> HGATP_VMID_SHIFT) != vmid)
		return;

	vmid = kvm_riscv_gstage_nested_vmid(READ_ONCE(v->vmid));
	if (!vaddr && !size && !order) {
		if (kvm_riscv_nacl_available())
			nacl_hfence_vvma_all(nacl_shmem(), vmid);
		else
			kvm_riscv_local_hfence_vvma_all(vmid);
	} else {
		if (kvm_riscv_nacl_available())
			nacl_hfence_vvma(nacl_shmem(), vmid, vaddr, size, order);
		else
			kvm_riscv_local_hfence_vvma_gva(vmid, vaddr, size, order);
	}
}

void kvm_riscv_vcpu_nested_swtlb_vvma_flush_asid(struct kvm_vcpu *vcpu,
						 unsigned long vaddr, unsigned long size,
						 unsigned long order, unsigned long vmid,
						 unsigned long asid)
{
	struct kvm_vcpu_nested *ns = &vcpu->arch.nested;
	struct kvm_vmid *v = &vcpu->kvm->arch.vmid;

	if (vmid != -1UL && ((ns->csr.hgatp & HGATP_VMID) >> HGATP_VMID_SHIFT) != vmid)
		return;

	vmid = kvm_riscv_gstage_nested_vmid(READ_ONCE(v->vmid));
	if (!vaddr && !size && !order) {
		if (kvm_riscv_nacl_available())
			nacl_hfence_vvma_asid_all(nacl_shmem(), vmid, asid);
		else
			kvm_riscv_local_hfence_vvma_asid_all(vmid, asid);
	} else {
		if (kvm_riscv_nacl_available())
			nacl_hfence_vvma_asid(nacl_shmem(), vmid, asid,
					      vaddr, size, order);
		else
			kvm_riscv_local_hfence_vvma_asid_gva(vmid, asid, vaddr,
							     size, order);
	}
}

void kvm_riscv_vcpu_nested_swtlb_gvma_flush(struct kvm_vcpu *vcpu,
					    gpa_t addr, gpa_t size, unsigned long order)
{
	/* TODO: */
}

void kvm_riscv_vcpu_nested_swtlb_gvma_flush_vmid(struct kvm_vcpu *vcpu,
						 gpa_t addr, gpa_t size, unsigned long order,
						 unsigned long vmid)
{
	struct kvm_vcpu_nested *ns = &vcpu->arch.nested;

	if (vmid != -1UL && ((ns->csr.hgatp & HGATP_VMID) >> HGATP_VMID_SHIFT) != vmid)
		return;

	kvm_riscv_vcpu_nested_swtlb_gvma_flush(vcpu, addr, size, order);
}

void kvm_riscv_vcpu_nested_swtlb_host_flush(struct kvm_vcpu *vcpu,
					    gpa_t addr, gpa_t size, unsigned long order)
{
	/* TODO: */
}

void kvm_riscv_vcpu_nested_swtlb_process(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_swtlb *nst = &vcpu->arch.nested.swtlb;

	WARN_ON(!nst->request.pending);

	/* TODO: */

	nst->request.pending = false;
}

void kvm_riscv_vcpu_nested_swtlb_request(struct kvm_vcpu *vcpu,
					 const struct kvm_gstage_mapping *guest_map,
					 const struct kvm_gstage_mapping *host_map)
{
	struct kvm_vcpu_nested_swtlb *nst = &vcpu->arch.nested.swtlb;

	WARN_ON(nst->request.pending);

	nst->request.pending = true;
	memcpy(&nst->request.guest, guest_map, sizeof(*guest_map));
	memcpy(&nst->request.host, host_map, sizeof(*host_map));

	kvm_make_request(KVM_REQ_NESTED_SWTLB, vcpu);
}

void kvm_riscv_vcpu_nested_swtlb_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_swtlb *nst = &vcpu->arch.nested.swtlb;

	memset(nst, 0, sizeof(*nst));
}
