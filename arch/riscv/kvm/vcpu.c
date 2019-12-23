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
#include <linux/kdebug.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/kvm_host.h>
#include <asm/csr.h>
#include <asm/hwcap.h>

#define VCPU_STAT(x) { #x, offsetof(struct kvm_vcpu, stat.x), KVM_STAT_VCPU }

struct kvm_stats_debugfs_item debugfs_entries[] = {
	VCPU_STAT(ecall_exit_stat),
	VCPU_STAT(wfi_exit_stat),
	VCPU_STAT(mmio_exit_user),
	VCPU_STAT(mmio_exit_kernel),
	VCPU_STAT(exits),
	{ NULL }
};

#ifdef CONFIG_FPU
static void kvm_riscv_vcpu_fp_reset(struct kvm_vcpu *vcpu)
{
	unsigned long isa = vcpu->arch.isa;
	struct kvm_cpu_context *cntx = &vcpu->arch.guest_context;

	cntx->sstatus &= ~SR_FS;
	if (riscv_isa_extension_available(&isa, f) ||
	    riscv_isa_extension_available(&isa, d))
		cntx->sstatus |= SR_FS_INITIAL;
	else
		cntx->sstatus |= SR_FS_OFF;
}

static void kvm_riscv_vcpu_fp_clean(struct kvm_cpu_context *cntx)
{
	cntx->sstatus &= ~SR_FS;
	cntx->sstatus |= SR_FS_CLEAN;
}

static void kvm_riscv_vcpu_guest_fp_save(struct kvm_cpu_context *cntx,
					 unsigned long isa)
{
	if ((cntx->sstatus & SR_FS) == SR_FS_DIRTY) {
		if (riscv_isa_extension_available(&isa, d))
			__kvm_riscv_fp_d_save(cntx);
		else if (riscv_isa_extension_available(&isa, f))
			__kvm_riscv_fp_f_save(cntx);
		kvm_riscv_vcpu_fp_clean(cntx);
	}
}

static void kvm_riscv_vcpu_guest_fp_restore(struct kvm_cpu_context *cntx,
					    unsigned long isa)
{
	if ((cntx->sstatus & SR_FS) != SR_FS_OFF) {
		if (riscv_isa_extension_available(&isa, d))
			__kvm_riscv_fp_d_restore(cntx);
		else if (riscv_isa_extension_available(&isa, f))
			__kvm_riscv_fp_f_restore(cntx);
		kvm_riscv_vcpu_fp_clean(cntx);
	}
}

static void kvm_riscv_vcpu_host_fp_save(struct kvm_cpu_context *cntx)
{
	/* No need to check host sstatus as it can be modified outside */
	if (riscv_isa_extension_available(NULL, d))
		__kvm_riscv_fp_d_save(cntx);
	else if (riscv_isa_extension_available(NULL, f))
		__kvm_riscv_fp_f_save(cntx);
}

static void kvm_riscv_vcpu_host_fp_restore(struct kvm_cpu_context *cntx)
{
	if (riscv_isa_extension_available(NULL, d))
		__kvm_riscv_fp_d_restore(cntx);
	else if (riscv_isa_extension_available(NULL, f))
		__kvm_riscv_fp_f_restore(cntx);
}
#else
static void kvm_riscv_vcpu_fp_reset(struct kvm_vcpu *vcpu) {}
static void kvm_riscv_vcpu_guest_fp_save(struct kvm_cpu_context *cntx,
					 unsigned long isa) {}
static void kvm_riscv_vcpu_guest_fp_restore(struct kvm_cpu_context *cntx,
					    unsigned long isa) {}
static void kvm_riscv_vcpu_host_fp_save(struct kvm_cpu_context *cntx) {}
static void kvm_riscv_vcpu_host_fp_restore(struct kvm_cpu_context *cntx) {}
#endif

#define KVM_RISCV_ISA_ALLOWED	(riscv_isa_extension_mask(a) | \
				 riscv_isa_extension_mask(c) | \
				 riscv_isa_extension_mask(d) | \
				 riscv_isa_extension_mask(f) | \
				 riscv_isa_extension_mask(i) | \
				 riscv_isa_extension_mask(m) | \
				 riscv_isa_extension_mask(s) | \
				 riscv_isa_extension_mask(u))

static void kvm_riscv_reset_vcpu(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_csr *csr = &vcpu->arch.guest_csr;
	struct kvm_vcpu_csr *reset_csr = &vcpu->arch.guest_reset_csr;
	struct kvm_cpu_context *cntx = &vcpu->arch.guest_context;
	struct kvm_cpu_context *reset_cntx = &vcpu->arch.guest_reset_context;

	memcpy(csr, reset_csr, sizeof(*csr));

	memcpy(cntx, reset_cntx, sizeof(*cntx));

	kvm_riscv_vcpu_fp_reset(vcpu);

	kvm_riscv_vcpu_timer_reset(vcpu);

	WRITE_ONCE(vcpu->arch.irqs_pending, 0);
	WRITE_ONCE(vcpu->arch.irqs_pending_mask, 0);
}

struct kvm_vcpu *kvm_arch_vcpu_create(struct kvm *kvm, unsigned int id)
{
	int err;
	struct kvm_vcpu *vcpu;

	vcpu = kmem_cache_zalloc(kvm_vcpu_cache, GFP_KERNEL);
	if (!vcpu) {
		err = -ENOMEM;
		goto out;
	}

	err = kvm_vcpu_init(vcpu, kvm, id);
	if (err)
		goto free_vcpu;

	return vcpu;

free_vcpu:
	kmem_cache_free(kvm_vcpu_cache, vcpu);
out:
	return ERR_PTR(err);
}

int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	return 0;
}

void kvm_arch_vcpu_postcreate(struct kvm_vcpu *vcpu)
{
}

int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *cntx;

	/* Mark this VCPU never ran */
	vcpu->arch.ran_atleast_once = false;

	/* Setup ISA features available to VCPU */
	vcpu->arch.isa = riscv_isa_extension_base(NULL) & KVM_RISCV_ISA_ALLOWED;

	/* Setup reset state of shadow SSTATUS and HSTATUS CSRs */
	cntx = &vcpu->arch.guest_reset_context;
	cntx->sstatus = SR_SPP | SR_SPIE;
	cntx->hstatus = 0;
	cntx->hstatus |= HSTATUS_SP2V;
	cntx->hstatus |= HSTATUS_SP2P;
	cntx->hstatus |= HSTATUS_SPV;

	/* Setup VCPU timer */
	kvm_riscv_vcpu_timer_init(vcpu);

	/* Reset VCPU */
	kvm_riscv_reset_vcpu(vcpu);

	return 0;
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	kvm_riscv_vcpu_timer_deinit(vcpu);
	kvm_riscv_stage2_flush_cache(vcpu);
	kmem_cache_free(kvm_vcpu_cache, vcpu);
}

int kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu)
{
	return kvm_riscv_vcpu_has_interrupts(vcpu, 1UL << IRQ_VS_TIMER);
}

void kvm_arch_vcpu_blocking(struct kvm_vcpu *vcpu)
{
}

void kvm_arch_vcpu_unblocking(struct kvm_vcpu *vcpu)
{
}

int kvm_arch_vcpu_runnable(struct kvm_vcpu *vcpu)
{
	return (kvm_riscv_vcpu_has_interrupts(vcpu, -1UL) &&
		!vcpu->arch.power_off && !vcpu->arch.pause);
}

int kvm_arch_vcpu_should_kick(struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_exiting_guest_mode(vcpu) == IN_GUEST_MODE;
}

bool kvm_arch_vcpu_in_kernel(struct kvm_vcpu *vcpu)
{
	return (vcpu->arch.guest_context.sstatus & SR_SPP) ? true : false;
}

bool kvm_arch_has_vcpu_debugfs(void)
{
	return false;
}

int kvm_arch_create_vcpu_debugfs(struct kvm_vcpu *vcpu)
{
	return 0;
}

vm_fault_t kvm_arch_vcpu_fault(struct kvm_vcpu *vcpu, struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

static int kvm_riscv_vcpu_get_reg_config(struct kvm_vcpu *vcpu,
					 const struct kvm_one_reg *reg)
{
	unsigned long __user *uaddr =
			(unsigned long __user *)(unsigned long)reg->addr;
	unsigned long reg_num = reg->id & ~(KVM_REG_ARCH_MASK |
					    KVM_REG_SIZE_MASK |
					    KVM_REG_RISCV_CONFIG);
	unsigned long reg_val;

	if (KVM_REG_SIZE(reg->id) != sizeof(unsigned long))
		return -EINVAL;

	switch (reg_num) {
	case KVM_REG_RISCV_CONFIG_REG(isa):
		reg_val = vcpu->arch.isa;
		break;
	default:
		return -EINVAL;
	};

	if (copy_to_user(uaddr, &reg_val, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	return 0;
}

static int kvm_riscv_vcpu_set_reg_config(struct kvm_vcpu *vcpu,
					 const struct kvm_one_reg *reg)
{
	unsigned long __user *uaddr =
			(unsigned long __user *)(unsigned long)reg->addr;
	unsigned long reg_num = reg->id & ~(KVM_REG_ARCH_MASK |
					    KVM_REG_SIZE_MASK |
					    KVM_REG_RISCV_CONFIG);
	unsigned long reg_val;

	if (KVM_REG_SIZE(reg->id) != sizeof(unsigned long))
		return -EINVAL;

	if (copy_from_user(&reg_val, uaddr, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	switch (reg_num) {
	case KVM_REG_RISCV_CONFIG_REG(isa):
		if (!vcpu->arch.ran_atleast_once) {
			vcpu->arch.isa = reg_val;
			vcpu->arch.isa &= riscv_isa_extension_base(NULL);
			vcpu->arch.isa &= KVM_RISCV_ISA_ALLOWED;
			kvm_riscv_vcpu_fp_reset(vcpu);
		} else {
			return -ENOTSUPP;
		}
		break;
	default:
		return -EINVAL;
	};

	return 0;
}

static int kvm_riscv_vcpu_get_reg_core(struct kvm_vcpu *vcpu,
				       const struct kvm_one_reg *reg)
{
	struct kvm_cpu_context *cntx = &vcpu->arch.guest_context;
	unsigned long __user *uaddr =
			(unsigned long __user *)(unsigned long)reg->addr;
	unsigned long reg_num = reg->id & ~(KVM_REG_ARCH_MASK |
					    KVM_REG_SIZE_MASK |
					    KVM_REG_RISCV_CORE);
	unsigned long reg_val;

	if (KVM_REG_SIZE(reg->id) != sizeof(unsigned long))
		return -EINVAL;
	if (reg_num >= sizeof(struct kvm_riscv_core) / sizeof(unsigned long))
		return -EINVAL;

	if (reg_num == KVM_REG_RISCV_CORE_REG(regs.pc))
		reg_val = cntx->sepc;
	else if (KVM_REG_RISCV_CORE_REG(regs.pc) < reg_num &&
		 reg_num <= KVM_REG_RISCV_CORE_REG(regs.t6))
		reg_val = ((unsigned long *)cntx)[reg_num];
	else if (reg_num == KVM_REG_RISCV_CORE_REG(mode))
		reg_val = (cntx->sstatus & SR_SPP) ?
				KVM_RISCV_MODE_S : KVM_RISCV_MODE_U;
	else
		return -EINVAL;

	if (copy_to_user(uaddr, &reg_val, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	return 0;
}

static int kvm_riscv_vcpu_set_reg_core(struct kvm_vcpu *vcpu,
				       const struct kvm_one_reg *reg)
{
	struct kvm_cpu_context *cntx = &vcpu->arch.guest_context;
	unsigned long __user *uaddr =
			(unsigned long __user *)(unsigned long)reg->addr;
	unsigned long reg_num = reg->id & ~(KVM_REG_ARCH_MASK |
					    KVM_REG_SIZE_MASK |
					    KVM_REG_RISCV_CORE);
	unsigned long reg_val;

	if (KVM_REG_SIZE(reg->id) != sizeof(unsigned long))
		return -EINVAL;
	if (reg_num >= sizeof(struct kvm_riscv_core) / sizeof(unsigned long))
		return -EINVAL;

	if (copy_from_user(&reg_val, uaddr, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	if (reg_num == KVM_REG_RISCV_CORE_REG(regs.pc))
		cntx->sepc = reg_val;
	else if (KVM_REG_RISCV_CORE_REG(regs.pc) < reg_num &&
		 reg_num <= KVM_REG_RISCV_CORE_REG(regs.t6))
		((unsigned long *)cntx)[reg_num] = reg_val;
	else if (reg_num == KVM_REG_RISCV_CORE_REG(mode)) {
		if (reg_val == KVM_RISCV_MODE_S)
			cntx->sstatus |= SR_SPP;
		else
			cntx->sstatus &= ~SR_SPP;
	} else
		return -EINVAL;

	return 0;
}

static int kvm_riscv_vcpu_get_reg_csr(struct kvm_vcpu *vcpu,
				      const struct kvm_one_reg *reg)
{
	struct kvm_vcpu_csr *csr = &vcpu->arch.guest_csr;
	unsigned long __user *uaddr =
			(unsigned long __user *)(unsigned long)reg->addr;
	unsigned long reg_num = reg->id & ~(KVM_REG_ARCH_MASK |
					    KVM_REG_SIZE_MASK |
					    KVM_REG_RISCV_CSR);
	unsigned long reg_val;

	if (KVM_REG_SIZE(reg->id) != sizeof(unsigned long))
		return -EINVAL;
	if (reg_num >= sizeof(struct kvm_riscv_csr) / sizeof(unsigned long))
		return -EINVAL;

	if (reg_num == KVM_REG_RISCV_CSR_REG(sip)) {
		kvm_riscv_vcpu_flush_interrupts(vcpu);
		reg_val = csr->hip >> VSIP_TO_HIP_SHIFT;
		reg_val = reg_val & VSIP_VALID_MASK;
	} else if (reg_num == KVM_REG_RISCV_CSR_REG(sie)) {
		reg_val = csr->hie >> VSIP_TO_HIP_SHIFT;
		reg_val = reg_val & VSIP_VALID_MASK;
	} else
		reg_val = ((unsigned long *)csr)[reg_num];

	if (copy_to_user(uaddr, &reg_val, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	return 0;
}

static int kvm_riscv_vcpu_set_reg_csr(struct kvm_vcpu *vcpu,
				      const struct kvm_one_reg *reg)
{
	struct kvm_vcpu_csr *csr = &vcpu->arch.guest_csr;
	unsigned long __user *uaddr =
			(unsigned long __user *)(unsigned long)reg->addr;
	unsigned long reg_num = reg->id & ~(KVM_REG_ARCH_MASK |
					    KVM_REG_SIZE_MASK |
					    KVM_REG_RISCV_CSR);
	unsigned long reg_val;

	if (KVM_REG_SIZE(reg->id) != sizeof(unsigned long))
		return -EINVAL;
	if (reg_num >= sizeof(struct kvm_riscv_csr) / sizeof(unsigned long))
		return -EINVAL;

	if (copy_from_user(&reg_val, uaddr, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	if (reg_num == KVM_REG_RISCV_CSR_REG(sip) ||
	    reg_num == KVM_REG_RISCV_CSR_REG(sie)) {
		reg_val = reg_val << VSIP_TO_HIP_SHIFT;
		reg_val = reg_val & VSIP_VALID_MASK;
	}

	((unsigned long *)csr)[reg_num] = reg_val;

	if (reg_num == KVM_REG_RISCV_CSR_REG(sip))
		WRITE_ONCE(vcpu->arch.irqs_pending_mask, 0);

	return 0;
}

static int kvm_riscv_vcpu_get_reg_fp(struct kvm_vcpu *vcpu,
				     const struct kvm_one_reg *reg,
				     unsigned long rtype)
{
	struct kvm_cpu_context *cntx = &vcpu->arch.guest_context;
	unsigned long isa = vcpu->arch.isa;
	unsigned long __user *uaddr =
			(unsigned long __user *)(unsigned long)reg->addr;
	unsigned long reg_num = reg->id & ~(KVM_REG_ARCH_MASK |
					    KVM_REG_SIZE_MASK |
					    rtype);
	void *reg_val;

	if ((rtype == KVM_REG_RISCV_FP_F) &&
	    riscv_isa_extension_available(&isa, f)) {
		if (KVM_REG_SIZE(reg->id) != sizeof(u32))
			return -EINVAL;
		if (reg_num == KVM_REG_RISCV_FP_F_REG(fcsr))
			reg_val = &cntx->fp.f.fcsr;
		else if ((KVM_REG_RISCV_FP_F_REG(f[0]) <= reg_num) &&
			  reg_num <= KVM_REG_RISCV_FP_F_REG(f[31]))
			reg_val = &cntx->fp.f.f[reg_num];
		else
			return -EINVAL;
	} else if ((rtype == KVM_REG_RISCV_FP_D) &&
		   riscv_isa_extension_available(&isa, d)) {
		if (reg_num == KVM_REG_RISCV_FP_D_REG(fcsr)) {
			if (KVM_REG_SIZE(reg->id) != sizeof(u32))
				return -EINVAL;
			reg_val = &cntx->fp.d.fcsr;
		} else if ((KVM_REG_RISCV_FP_D_REG(f[0]) <= reg_num) &&
			   reg_num <= KVM_REG_RISCV_FP_D_REG(f[31])) {
			if (KVM_REG_SIZE(reg->id) != sizeof(u64))
				return -EINVAL;
			reg_val = &cntx->fp.d.f[reg_num];
		} else
			return -EINVAL;
	} else
		return -EINVAL;

	if (copy_to_user(uaddr, reg_val, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	return 0;
}

static int kvm_riscv_vcpu_set_reg_fp(struct kvm_vcpu *vcpu,
				     const struct kvm_one_reg *reg,
				     unsigned long rtype)
{
	struct kvm_cpu_context *cntx = &vcpu->arch.guest_context;
	unsigned long isa = vcpu->arch.isa;
	unsigned long __user *uaddr =
			(unsigned long __user *)(unsigned long)reg->addr;
	unsigned long reg_num = reg->id & ~(KVM_REG_ARCH_MASK |
					    KVM_REG_SIZE_MASK |
					    rtype);
	void *reg_val;

	if ((rtype == KVM_REG_RISCV_FP_F) &&
	    riscv_isa_extension_available(&isa, f)) {
		if (KVM_REG_SIZE(reg->id) != sizeof(u32))
			return -EINVAL;
		if (reg_num == KVM_REG_RISCV_FP_F_REG(fcsr))
			reg_val = &cntx->fp.f.fcsr;
		else if ((KVM_REG_RISCV_FP_F_REG(f[0]) <= reg_num) &&
			  reg_num <= KVM_REG_RISCV_FP_F_REG(f[31]))
			reg_val = &cntx->fp.f.f[reg_num];
		else
			return -EINVAL;
	} else if ((rtype == KVM_REG_RISCV_FP_D) &&
		   riscv_isa_extension_available(&isa, d)) {
		if (reg_num == KVM_REG_RISCV_FP_D_REG(fcsr)) {
			if (KVM_REG_SIZE(reg->id) != sizeof(u32))
				return -EINVAL;
			reg_val = &cntx->fp.d.fcsr;
		} else if ((KVM_REG_RISCV_FP_D_REG(f[0]) <= reg_num) &&
			   reg_num <= KVM_REG_RISCV_FP_D_REG(f[31])) {
			if (KVM_REG_SIZE(reg->id) != sizeof(u64))
				return -EINVAL;
			reg_val = &cntx->fp.d.f[reg_num];
		} else
			return -EINVAL;
	} else
		return -EINVAL;

	if (copy_from_user(reg_val, uaddr, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	return 0;
}

static int kvm_riscv_vcpu_set_reg(struct kvm_vcpu *vcpu,
				  const struct kvm_one_reg *reg)
{
	if ((reg->id & KVM_REG_RISCV_TYPE_MASK) == KVM_REG_RISCV_CONFIG)
		return kvm_riscv_vcpu_set_reg_config(vcpu, reg);
	else if ((reg->id & KVM_REG_RISCV_TYPE_MASK) == KVM_REG_RISCV_CORE)
		return kvm_riscv_vcpu_set_reg_core(vcpu, reg);
	else if ((reg->id & KVM_REG_RISCV_TYPE_MASK) == KVM_REG_RISCV_CSR)
		return kvm_riscv_vcpu_set_reg_csr(vcpu, reg);
	else if ((reg->id & KVM_REG_RISCV_TYPE_MASK) == KVM_REG_RISCV_TIMER)
		return kvm_riscv_vcpu_set_reg_timer(vcpu, reg);
	else if ((reg->id & KVM_REG_RISCV_TYPE_MASK) == KVM_REG_RISCV_FP_F)
		return kvm_riscv_vcpu_set_reg_fp(vcpu, reg,
						 KVM_REG_RISCV_FP_F);
	else if ((reg->id & KVM_REG_RISCV_TYPE_MASK) == KVM_REG_RISCV_FP_D)
		return kvm_riscv_vcpu_set_reg_fp(vcpu, reg,
						 KVM_REG_RISCV_FP_D);

	return -EINVAL;
}

static int kvm_riscv_vcpu_get_reg(struct kvm_vcpu *vcpu,
				  const struct kvm_one_reg *reg)
{
	if ((reg->id & KVM_REG_RISCV_TYPE_MASK) == KVM_REG_RISCV_CONFIG)
		return kvm_riscv_vcpu_get_reg_config(vcpu, reg);
	else if ((reg->id & KVM_REG_RISCV_TYPE_MASK) == KVM_REG_RISCV_CORE)
		return kvm_riscv_vcpu_get_reg_core(vcpu, reg);
	else if ((reg->id & KVM_REG_RISCV_TYPE_MASK) == KVM_REG_RISCV_CSR)
		return kvm_riscv_vcpu_get_reg_csr(vcpu, reg);
	else if ((reg->id & KVM_REG_RISCV_TYPE_MASK) == KVM_REG_RISCV_TIMER)
		return kvm_riscv_vcpu_get_reg_timer(vcpu, reg);
	else if ((reg->id & KVM_REG_RISCV_TYPE_MASK) == KVM_REG_RISCV_FP_F)
		return kvm_riscv_vcpu_get_reg_fp(vcpu, reg,
						 KVM_REG_RISCV_FP_F);
	else if ((reg->id & KVM_REG_RISCV_TYPE_MASK) == KVM_REG_RISCV_FP_D)
		return kvm_riscv_vcpu_get_reg_fp(vcpu, reg,
						 KVM_REG_RISCV_FP_D);

	return -EINVAL;
}

long kvm_arch_vcpu_async_ioctl(struct file *filp,
			       unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;

	if (ioctl == KVM_INTERRUPT) {
		struct kvm_interrupt irq;

		if (copy_from_user(&irq, argp, sizeof(irq)))
			return -EFAULT;

		if (irq.irq == KVM_INTERRUPT_SET)
			return kvm_riscv_vcpu_set_interrupt(vcpu, IRQ_VS_EXT);
		else
			return kvm_riscv_vcpu_unset_interrupt(vcpu, IRQ_VS_EXT);
	}

	return -ENOIOCTLCMD;
}

long kvm_arch_vcpu_ioctl(struct file *filp,
			 unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	long r = -EINVAL;

	switch (ioctl) {
	case KVM_SET_ONE_REG:
	case KVM_GET_ONE_REG: {
		struct kvm_one_reg reg;

		r = -EFAULT;
		if (copy_from_user(&reg, argp, sizeof(reg)))
			break;

		if (ioctl == KVM_SET_ONE_REG)
			r = kvm_riscv_vcpu_set_reg(vcpu, &reg);
		else
			r = kvm_riscv_vcpu_get_reg(vcpu, &reg);
		break;
	}
	default:
		break;
	}

	return r;
}

int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
				  struct kvm_translation *tr)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	return -EINVAL;
}

void kvm_riscv_vcpu_flush_interrupts(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_csr *csr = &vcpu->arch.guest_csr;
	unsigned long mask, val;

	if (READ_ONCE(vcpu->arch.irqs_pending_mask)) {
		mask = xchg_acquire(&vcpu->arch.irqs_pending_mask, 0);
		val = READ_ONCE(vcpu->arch.irqs_pending) & mask;

		csr->hip &= ~mask;
		csr->hip |= val;
	}
}

void kvm_riscv_vcpu_sync_interrupts(struct kvm_vcpu *vcpu)
{
	unsigned long hip;
	struct kvm_vcpu_arch *v = &vcpu->arch;
	struct kvm_vcpu_csr *csr = &vcpu->arch.guest_csr;

	/* Read current HIP and HIE CSRs */
	hip = csr_read(CSR_HIP);
	csr->hie = csr_read(CSR_HIE);

	/* Sync-up HIP.VSSIP bit changes does by Guest */
	if ((csr->hip ^ hip) & (1UL << IRQ_VS_SOFT)) {
		if (hip & (1UL << IRQ_VS_SOFT)) {
			if (!test_and_set_bit(IRQ_VS_SOFT,
					      &v->irqs_pending_mask))
				set_bit(IRQ_VS_SOFT, &v->irqs_pending);
		} else {
			if (!test_and_set_bit(IRQ_VS_SOFT,
					      &v->irqs_pending_mask))
				clear_bit(IRQ_VS_SOFT, &v->irqs_pending);
		}
	}
}

int kvm_riscv_vcpu_set_interrupt(struct kvm_vcpu *vcpu, unsigned int irq)
{
	if (irq != IRQ_VS_SOFT &&
	    irq != IRQ_VS_TIMER &&
	    irq != IRQ_VS_EXT)
		return -EINVAL;

	set_bit(irq, &vcpu->arch.irqs_pending);
	smp_mb__before_atomic();
	set_bit(irq, &vcpu->arch.irqs_pending_mask);

	kvm_vcpu_kick(vcpu);

	return 0;
}

int kvm_riscv_vcpu_unset_interrupt(struct kvm_vcpu *vcpu, unsigned int irq)
{
	if (irq != IRQ_VS_SOFT &&
	    irq != IRQ_VS_TIMER &&
	    irq != IRQ_VS_EXT)
		return -EINVAL;

	clear_bit(irq, &vcpu->arch.irqs_pending);
	smp_mb__before_atomic();
	set_bit(irq, &vcpu->arch.irqs_pending_mask);

	return 0;
}

bool kvm_riscv_vcpu_has_interrupts(struct kvm_vcpu *vcpu, unsigned long mask)
{
	return (READ_ONCE(vcpu->arch.irqs_pending) &
		vcpu->arch.guest_csr.hie & mask) ? true : false;
}

void kvm_riscv_vcpu_power_off(struct kvm_vcpu *vcpu)
{
	vcpu->arch.power_off = true;
	kvm_make_request(KVM_REQ_SLEEP, vcpu);
	kvm_vcpu_kick(vcpu);
}

void kvm_riscv_vcpu_power_on(struct kvm_vcpu *vcpu)
{
	vcpu->arch.power_off = false;
	kvm_vcpu_wake_up(vcpu);
}

int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	if (vcpu->arch.power_off)
		mp_state->mp_state = KVM_MP_STATE_STOPPED;
	else
		mp_state->mp_state = KVM_MP_STATE_RUNNABLE;

	return 0;
}

int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	int ret = 0;

	switch (mp_state->mp_state) {
	case KVM_MP_STATE_RUNNABLE:
		vcpu->arch.power_off = false;
		break;
	case KVM_MP_STATE_STOPPED:
		kvm_riscv_vcpu_power_off(vcpu);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
					struct kvm_guest_debug *dbg)
{
	/* TODO; To be implemented later. */
	return -EINVAL;
}

void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct kvm_vcpu_csr *csr = &vcpu->arch.guest_csr;

	csr_write(CSR_VSSTATUS, csr->vsstatus);
	csr_write(CSR_HIE, csr->hie);
	csr_write(CSR_VSTVEC, csr->vstvec);
	csr_write(CSR_VSSCRATCH, csr->vsscratch);
	csr_write(CSR_VSEPC, csr->vsepc);
	csr_write(CSR_VSCAUSE, csr->vscause);
	csr_write(CSR_VSTVAL, csr->vstval);
	csr_write(CSR_HIP, csr->hip);
	csr_write(CSR_VSATP, csr->vsatp);

	kvm_riscv_stage2_update_hgatp(vcpu);

	kvm_riscv_vcpu_timer_restore(vcpu);

	kvm_riscv_vcpu_host_fp_save(&vcpu->arch.host_context);
	kvm_riscv_vcpu_guest_fp_restore(&vcpu->arch.guest_context,
					vcpu->arch.isa);

	vcpu->cpu = cpu;
}

void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_csr *csr = &vcpu->arch.guest_csr;

	vcpu->cpu = -1;

	kvm_riscv_vcpu_guest_fp_save(&vcpu->arch.guest_context,
				     vcpu->arch.isa);
	kvm_riscv_vcpu_host_fp_restore(&vcpu->arch.host_context);

	csr_write(CSR_HGATP, 0);

	csr->vsstatus = csr_read(CSR_VSSTATUS);
	csr->hie = csr_read(CSR_HIE);
	csr->vstvec = csr_read(CSR_VSTVEC);
	csr->vsscratch = csr_read(CSR_VSSCRATCH);
	csr->vsepc = csr_read(CSR_VSEPC);
	csr->vscause = csr_read(CSR_VSCAUSE);
	csr->vstval = csr_read(CSR_VSTVAL);
	csr->hip = csr_read(CSR_HIP);
	csr->vsatp = csr_read(CSR_VSATP);
}

static void kvm_riscv_check_vcpu_requests(struct kvm_vcpu *vcpu)
{
	struct swait_queue_head *wq = kvm_arch_vcpu_wq(vcpu);

	if (kvm_request_pending(vcpu)) {
		if (kvm_check_request(KVM_REQ_SLEEP, vcpu)) {
			swait_event_interruptible_exclusive(*wq,
						((!vcpu->arch.power_off) &&
						(!vcpu->arch.pause)));

			if (vcpu->arch.power_off || vcpu->arch.pause) {
				/*
				 * Awaken to handle a signal, request to
				 * sleep again later.
				 */
				kvm_make_request(KVM_REQ_SLEEP, vcpu);
			}
		}

		if (kvm_check_request(KVM_REQ_VCPU_RESET, vcpu))
			kvm_riscv_reset_vcpu(vcpu);

		if (kvm_check_request(KVM_REQ_UPDATE_HGATP, vcpu))
			kvm_riscv_stage2_update_hgatp(vcpu);

		if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu))
			__kvm_riscv_hfence_gvma_all();
	}
}

static void kvm_riscv_update_hip(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_csr *csr = &vcpu->arch.guest_csr;

	csr_write(CSR_HIP, csr->hip);
}

int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	int ret;
	unsigned long scause, stval, htval, htinst;

	/* Mark this VCPU ran atleast once */
	vcpu->arch.ran_atleast_once = true;

	vcpu->arch.srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);

	/* Process MMIO value returned from user-space */
	if (run->exit_reason == KVM_EXIT_MMIO) {
		ret = kvm_riscv_vcpu_mmio_return(vcpu, vcpu->run);
		if (ret) {
			srcu_read_unlock(&vcpu->kvm->srcu, vcpu->arch.srcu_idx);
			return ret;
		}
	}

	/* Process SBI value returned from user-space */
	if (run->exit_reason == KVM_EXIT_RISCV_SBI) {
		ret = kvm_riscv_vcpu_sbi_return(vcpu, vcpu->run);
		if (ret) {
			srcu_read_unlock(&vcpu->kvm->srcu, vcpu->arch.srcu_idx);
			return ret;
		}
	}

	if (run->immediate_exit) {
		srcu_read_unlock(&vcpu->kvm->srcu, vcpu->arch.srcu_idx);
		return -EINTR;
	}

	vcpu_load(vcpu);

	kvm_sigset_activate(vcpu);

	ret = 1;
	run->exit_reason = KVM_EXIT_UNKNOWN;
	while (ret > 0) {
		/* Check conditions before entering the guest */
		cond_resched();

		kvm_riscv_stage2_vmid_update(vcpu);

		kvm_riscv_check_vcpu_requests(vcpu);

		preempt_disable();

		local_irq_disable();

		/*
		 * Exit if we have a signal pending so that we can deliver
		 * the signal to user space.
		 */
		if (signal_pending(current)) {
			ret = -EINTR;
			run->exit_reason = KVM_EXIT_INTR;
		}

		/*
		 * Ensure we set mode to IN_GUEST_MODE after we disable
		 * interrupts and before the final VCPU requests check.
		 * See the comment in kvm_vcpu_exiting_guest_mode() and
		 * Documentation/virtual/kvm/vcpu-requests.rst
		 */
		vcpu->mode = IN_GUEST_MODE;

		srcu_read_unlock(&vcpu->kvm->srcu, vcpu->arch.srcu_idx);
		smp_mb__after_srcu_read_unlock();

		/*
		 * We might have got VCPU interrupts updated asynchronously
		 * so update it in HW.
		 */
		kvm_riscv_vcpu_flush_interrupts(vcpu);

		/* Update HIP CSR for current CPU */
		kvm_riscv_update_hip(vcpu);

		if (ret <= 0 ||
		    kvm_riscv_stage2_vmid_ver_changed(&vcpu->kvm->arch.vmid) ||
		    kvm_request_pending(vcpu)) {
			vcpu->mode = OUTSIDE_GUEST_MODE;
			local_irq_enable();
			preempt_enable();
			vcpu->arch.srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);
			continue;
		}

		guest_enter_irqoff();

		__kvm_riscv_switch_to(&vcpu->arch);

		vcpu->mode = OUTSIDE_GUEST_MODE;
		vcpu->stat.exits++;

		/*
		 * Save SCAUSE, STVAL, HTVAL, and HTINST because we might
		 * get an interrupt between __kvm_riscv_switch_to() and
		 * local_irq_enable() which can potentially change CSRs.
		 */
		scause = csr_read(CSR_SCAUSE);
		stval = csr_read(CSR_STVAL);
		htval = csr_read(CSR_HTVAL);
		htinst = csr_read(CSR_HTINST);

		/* Syncup interrupts state with HW */
		kvm_riscv_vcpu_sync_interrupts(vcpu);

		/*
		 * We may have taken a host interrupt in VS/VU-mode (i.e.
		 * while executing the guest). This interrupt is still
		 * pending, as we haven't serviced it yet!
		 *
		 * We're now back in HS-mode with interrupts disabled
		 * so enabling the interrupts now will have the effect
		 * of taking the interrupt again, in HS-mode this time.
		 */
		local_irq_enable();

		/*
		 * We do local_irq_enable() before calling guest_exit() so
		 * that if a timer interrupt hits while running the guest
		 * we account that tick as being spent in the guest. We
		 * enable preemption after calling guest_exit() so that if
		 * we get preempted we make sure ticks after that is not
		 * counted as guest time.
		 */
		guest_exit();

		preempt_enable();

		vcpu->arch.srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);

		ret = kvm_riscv_vcpu_exit(vcpu, run,
					  scause, stval, htval, htinst);
	}

	kvm_sigset_deactivate(vcpu);

	vcpu_put(vcpu);

	srcu_read_unlock(&vcpu->kvm->srcu, vcpu->arch.srcu_idx);

	return ret;
}
