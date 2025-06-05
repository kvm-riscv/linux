// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *     Anup Patel <anup.patel@wdc.com>
 */

#include <linux/bitops.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/kvm_host.h>
#include <asm/csr.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_tlb.h>
#include <asm/kvm_vmid.h>

static unsigned long vmid_version = 1;
static unsigned long vmid_next;
static unsigned long vmid_bits __ro_after_init;
static DEFINE_SPINLOCK(vmid_lock);

void __init kvm_riscv_gstage_vmid_detect(void)
{
	unsigned long min_vmids;

	/* Figure-out number of VMID bits in HW */
	csr_write(CSR_HGATP, (kvm_riscv_gstage_mode << HGATP_MODE_SHIFT) | HGATP_VMID);
	vmid_bits = csr_read(CSR_HGATP);
	vmid_bits = (vmid_bits & HGATP_VMID) >> HGATP_VMID_SHIFT;
	vmid_bits = fls_long(vmid_bits);
	csr_write(CSR_HGATP, 0);

	/* We polluted local TLB so flush all guest TLB */
	kvm_riscv_local_hfence_gvma_all();

	/*
	 * A single guest with nested virtualization needs two
	 * VMIDs: one for the guest hypervisor (L1) and another
	 * for the nested guest (L2).
	 *
	 * Potentially, we can have a separate guest running on
	 * each host CPU so the number of VMIDs should not be:
	 *
	 * 1. less than the number of host CPUs for
	 *    nested virtualization disabled
	 * 2. less than twice the number of host CPUs for
	 *    nested virtualization enabled
	 */
	min_vmids = num_possible_cpus();
	if (kvm_riscv_nested_available())
		min_vmids = min_vmids * 2;
	if (BIT(vmid_bits) < min_vmids)
		vmid_bits = 0;
}

unsigned long kvm_riscv_gstage_vmid_bits(void)
{
	return vmid_bits;
}

unsigned long kvm_riscv_gstage_nested_vmid(unsigned long vmid)
{
	if (kvm_riscv_nested_available())
		return vmid | BIT(vmid_bits - 1);
	return vmid;
}

int kvm_riscv_gstage_vmid_init(struct kvm *kvm)
{
	/* Mark the initial VMID and VMID version invalid */
	kvm->arch.vmid.vmid_version = 0;
	kvm->arch.vmid.vmid = 0;

	return 0;
}

bool kvm_riscv_gstage_vmid_ver_changed(struct kvm_vmid *vmid)
{
	if (!vmid_bits)
		return false;

	return unlikely(READ_ONCE(vmid->vmid_version) !=
			READ_ONCE(vmid_version));
}

static void __local_hfence_gvma_all(void *info)
{
	kvm_riscv_local_hfence_gvma_all();
}

void kvm_riscv_gstage_vmid_update(struct kvm_vcpu *vcpu)
{
	unsigned long i;
	struct kvm_vcpu *v;
	struct kvm_vmid *vmid = &vcpu->kvm->arch.vmid;

	if (!kvm_riscv_gstage_vmid_ver_changed(vmid))
		return;

	spin_lock(&vmid_lock);

	/*
	 * We need to re-check the vmid_version here to ensure that if
	 * another vcpu already allocated a valid vmid for this vm.
	 */
	if (!kvm_riscv_gstage_vmid_ver_changed(vmid)) {
		spin_unlock(&vmid_lock);
		return;
	}

	/* First user of a new VMID version? */
	if (unlikely(vmid_next == 0)) {
		WRITE_ONCE(vmid_version, READ_ONCE(vmid_version) + 1);
		vmid_next = 1;

		/*
		 * We ran out of VMIDs so we increment vmid_version and
		 * start assigning VMIDs from 1.
		 *
		 * This also means existing VMIDs assignment to all Guest
		 * instances is invalid and we have force VMID re-assignement
		 * for all Guest instances. The Guest instances that were not
		 * running will automatically pick-up new VMIDs because will
		 * call kvm_riscv_gstage_vmid_update() whenever they enter
		 * in-kernel run loop. For Guest instances that are already
		 * running, we force VM exits on all host CPUs using IPI and
		 * flush all Guest TLBs.
		 */
		on_each_cpu_mask(cpu_online_mask, __local_hfence_gvma_all,
				 NULL, 1);
	}

	vmid->vmid = vmid_next;
	vmid_next++;
	if (kvm_riscv_nested_available())
		vmid_next &= BIT(vmid_bits - 1) - 1;
	else
		vmid_next &= BIT(vmid_bits) - 1;

	WRITE_ONCE(vmid->vmid_version, READ_ONCE(vmid_version));

	spin_unlock(&vmid_lock);

	/* Request G-stage page table update for all VCPUs */
	kvm_for_each_vcpu(i, v, vcpu->kvm)
		kvm_make_request(KVM_REQ_UPDATE_HGATP, v);
}

void kvm_riscv_gstage_vmid_sanitize(struct kvm_vcpu *vcpu)
{
	unsigned long vmid, nvmid;

	if (!kvm_riscv_gstage_vmid_bits() ||
	    vcpu->arch.last_exit_cpu == vcpu->cpu)
		return;

	/*
	 * On RISC-V platforms with hardware VMID support, we share same
	 * VMID for all VCPUs of a particular Guest/VM. This means we might
	 * have stale G-stage TLB entries on the current Host CPU due to
	 * some other VCPU of the same Guest which ran previously on the
	 * current Host CPU.
	 *
	 * To cleanup stale TLB entries, we simply flush all G-stage TLB
	 * entries by VMID whenever underlying Host CPU changes for a VCPU.
	 */

	vmid = READ_ONCE(vcpu->kvm->arch.vmid.vmid);
	kvm_riscv_local_hfence_gvma_vmid_all(vmid);

	nvmid = kvm_riscv_gstage_nested_vmid(vmid);
	if (vmid != nvmid)
		kvm_riscv_local_hfence_gvma_vmid_all(nvmid);
}
