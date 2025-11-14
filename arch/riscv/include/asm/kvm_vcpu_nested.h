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

static inline bool kvm_riscv_vcpu_nested_timer_irq(struct kvm_vcpu *vcpu)
{
	/* TODO: */
	return false;
}
static inline u64 kvm_riscv_vcpu_nested_timer_cycles(struct kvm_vcpu *vcpu)
{
	/* TODO: */
	return 0;
}
static inline void kvm_riscv_vcpu_nested_timer_restart(struct kvm_vcpu *vcpu)
{
	/* TODO: */
}
static inline void kvm_riscv_vcpu_nested_timer_start(struct kvm_vcpu *vcpu, u64 next_vs_cycle)
{
	/* TODO: */
}

int kvm_riscv_vcpu_nested_insn_sret(struct kvm_vcpu *vcpu, struct kvm_run *run, ulong insn);
int kvm_riscv_vcpu_nested_insn_hfence_vvma(struct kvm_vcpu *vcpu, struct kvm_run *run,
					   ulong insn);
int kvm_riscv_vcpu_nested_insn_hfence_gvma(struct kvm_vcpu *vcpu, struct kvm_run *run,
					   ulong insn);

int kvm_riscv_vcpu_nested_smode_csr_rmw(struct kvm_vcpu *vcpu, unsigned int csr_num,
				        unsigned long *val, unsigned long new_val,
				        unsigned long wr_mask);
int kvm_riscv_vcpu_nested_hext_csr_rmw(struct kvm_vcpu *vcpu, unsigned int csr_num,
				       unsigned long *val, unsigned long new_val,
				       unsigned long wr_mask);

#define KVM_RISCV_VCPU_NESTED_SMODE_CSR_FUNCS \
{ .base = CSR_SIE,      .count = 1, .func = kvm_riscv_vcpu_nested_smode_csr_rmw }, \
{ .base = CSR_SIEH,     .count = 1, .func = kvm_riscv_vcpu_nested_smode_csr_rmw }, \
{ .base = CSR_SIP,      .count = 1, .func = kvm_riscv_vcpu_nested_smode_csr_rmw }, \
{ .base = CSR_SIPH,     .count = 1, .func = kvm_riscv_vcpu_nested_smode_csr_rmw }, \
{ .base = CSR_STIMECMP, .count = 1, .func = kvm_riscv_vcpu_nested_smode_csr_rmw }, \
{ .base = CSR_STIMECMPH,.count = 1, .func = kvm_riscv_vcpu_nested_smode_csr_rmw },

#define KVM_RISCV_VCPU_NESTED_HEXT_CSR_FUNCS \
{ .base = CSR_HSTATUS,  .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HEDELEG,  .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HIDELEG,  .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HIE,      .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HTIMEDELTA, .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HCOUNTEREN, .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HGEIE,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HENVCFG,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HTIMEDELTAH,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HENVCFGH,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HTVAL,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HIP,      .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HVIP,     .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HTINST,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HGATP,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_HGEIP,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_VSSTATUS,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_VSIE,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_VSTVEC,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_VSSCRATCH,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_VSEPC,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_VSCAUSE,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_VSTVAL,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_VSIP,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_VSATP,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_VSTIMECMP,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw }, \
{ .base = CSR_VSTIMECMPH,    .count = 1, .func = kvm_riscv_vcpu_nested_hext_csr_rmw },

void kvm_riscv_vcpu_nested_csr_reset(struct kvm_vcpu *vcpu);

int kvm_riscv_vcpu_nested_swtlb_xlate(struct kvm_vcpu *vcpu,
				      const struct kvm_cpu_trap *trap,
				      struct kvm_gstage_mapping *out_map,
				      struct kvm_cpu_trap *out_trap);
void kvm_riscv_vcpu_nested_swtlb_vvma_flush(struct kvm_vcpu *vcpu,
					    unsigned long vaddr, unsigned long size,
					    unsigned long order, unsigned long vmid);
void kvm_riscv_vcpu_nested_swtlb_vvma_flush_asid(struct kvm_vcpu *vcpu,
						 unsigned long vaddr, unsigned long size,
						 unsigned long order, unsigned long vmid,
						 unsigned long asid);
void kvm_riscv_vcpu_nested_swtlb_gvma_flush(struct kvm_vcpu *vcpu,
					    gpa_t addr, gpa_t size, unsigned long order);
void kvm_riscv_vcpu_nested_swtlb_gvma_flush_vmid(struct kvm_vcpu *vcpu,
						 gpa_t addr, gpa_t size, unsigned long order,
						 unsigned long vmid);
void kvm_riscv_vcpu_nested_swtlb_host_flush(struct kvm_vcpu *vcpu,
					    gpa_t addr, gpa_t size, unsigned long order);
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
