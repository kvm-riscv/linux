/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#ifndef __RISCV_VCPU_NESTED_H__
#define __RISCV_VCPU_NESTED_H__

#include <linux/jump_label.h>
#include <linux/kvm_types.h>
#include <asm/kvm_mmu.h>

DECLARE_STATIC_KEY_FALSE(kvm_riscv_nested_available);
#define kvm_riscv_nested_available() \
	static_branch_unlikely(&kvm_riscv_nested_available)

struct kvm_vcpu_nested_swtlb {
	struct {
		bool pending;
		struct kvm_gstage_mapping guest;
		struct kvm_gstage_mapping host;
	} request;
};

struct kvm_vcpu_nested_csr {
	unsigned long hstatus;
	unsigned long hedeleg;
	unsigned long hideleg;
	unsigned long hvip;
	unsigned long hcounteren;
	unsigned long htimedelta;
	unsigned long htimedeltah;
	unsigned long htval;
	unsigned long htinst;
	unsigned long henvcfg;
	unsigned long henvcfgh;
	unsigned long hgatp;
	unsigned long vsstatus;
	unsigned long vsie;
	unsigned long vstvec;
	unsigned long vsscratch;
	unsigned long vsepc;
	unsigned long vscause;
	unsigned long vstval;
	unsigned long vsatp;
};

struct kvm_vcpu_nested {
	/* Nested virt state */
	bool virt;

	/* Nested software TLB request */
	struct kvm_vcpu_nested_swtlb swtlb;

	/* Nested CSR state */
	struct kvm_vcpu_nested_csr csr;
};

#define kvm_riscv_vcpu_nested_virt(__vcpu) ((__vcpu)->arch.nested.virt)

int kvm_riscv_vcpu_nested_insn_sret(struct kvm_vcpu *vcpu, struct kvm_run *run, ulong insn);

int kvm_riscv_vcpu_nested_swtlb_xlate(struct kvm_vcpu *vcpu,
				      const struct kvm_cpu_trap *trap,
				      struct kvm_gstage_mapping *out_map,
				      struct kvm_cpu_trap *out_trap);
void kvm_riscv_vcpu_nested_swtlb_process(struct kvm_vcpu *vcpu);
void kvm_riscv_vcpu_nested_swtlb_request(struct kvm_vcpu *vcpu,
					 const struct kvm_gstage_mapping *guest_map,
					 const struct kvm_gstage_mapping *host_map);
void kvm_riscv_vcpu_nested_swtlb_reset(struct kvm_vcpu *vcpu);

enum kvm_vcpu_nested_set_virt_event {
	NESTED_SET_VIRT_EVENT_TRAP = 0,
	NESTED_SET_VIRT_EVENT_SRET
};

void kvm_riscv_vcpu_nested_set_virt(struct kvm_vcpu *vcpu,
				    enum kvm_vcpu_nested_set_virt_event event,
				    bool virt, bool spvp, bool gva);
void kvm_riscv_vcpu_nested_trap_redirect(struct kvm_vcpu *vcpu,
					 struct kvm_cpu_trap *trap,
					 bool prev_priv);

void kvm_riscv_vcpu_nested_vsirq_process(struct kvm_vcpu *vcpu);
void kvm_riscv_vcpu_nested_reset(struct kvm_vcpu *vcpu);
void kvm_riscv_nested_init(void);

#endif
