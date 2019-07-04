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
#include <linux/hugetlb.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/kvm_host.h>
#include <linux/sched/signal.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/sbi.h>

#ifdef CONFIG_64BIT
#define stage2_have_pmd		true
#define stage2_gpa_size		((phys_addr_t)(1ULL << 39))
#define stage2_pgd_levels	3
#define stage2_index_bits	9
#else
#define stage2_have_pmd		false
#define stage2_gpa_size		((phys_addr_t)(1ULL << 32))
#define stage2_pgd_levels	2
#define stage2_index_bits	10
#endif

#define stage2_pte_index(addr, level) \
(((addr) >> (PAGE_SHIFT + stage2_index_bits * (level))) & (PTRS_PER_PTE - 1))

static inline unsigned long stage2_pte_page_vaddr(pte_t pte)
{
	return (unsigned long)pfn_to_virt(pte_val(pte) >> _PAGE_PFN_SHIFT);
}

static int stage2_page_size_to_level(unsigned long page_size, u32 *out_level)
{
	if (page_size == PAGE_SIZE)
		*out_level = 0;
	else if (page_size == PMD_SIZE)
		*out_level = 1;
	else if (page_size == PGDIR_SIZE)
		*out_level = (stage2_have_pmd) ? 2 : 1;
	else
		return -EINVAL;

	return 0;
}

static int stage2_level_to_page_size(u32 level, unsigned long *out_pgsize)
{
	switch (level) {
	case 0:
		*out_pgsize = PAGE_SIZE;
		break;
	case 1:
		*out_pgsize = (stage2_have_pmd) ? PMD_SIZE : PGDIR_SIZE;
		break;
	case 2:
		*out_pgsize = PGDIR_SIZE;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int stage2_cache_topup(struct kvm_mmu_page_cache *pcache,
			      int min, int max)
{
	void *page;

	BUG_ON(max > KVM_MMU_PAGE_CACHE_NR_OBJS);
	if (pcache->nobjs >= min)
		return 0;
	while (pcache->nobjs < max) {
		page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
		if (!page)
			return -ENOMEM;
		pcache->objects[pcache->nobjs++] = page;
	}

	return 0;
}

static void stage2_cache_flush(struct kvm_mmu_page_cache *pcache)
{
	while (pcache && pcache->nobjs)
		free_page((unsigned long)pcache->objects[--pcache->nobjs]);
}

static void *stage2_cache_alloc(struct kvm_mmu_page_cache *pcache)
{
	void *p;

	if (!pcache)
		return NULL;

	BUG_ON(!pcache->nobjs);
	p = pcache->objects[--pcache->nobjs];

	return p;
}

static bool stage2_get_leaf_entry(struct kvm *kvm, gpa_t addr,
				  pte_t **ptepp, u32 *ptep_level)
{
	pte_t *ptep;
	u32 current_level = stage2_pgd_levels - 1;

	*ptep_level = current_level;
	ptep = (pte_t *)kvm->arch.pgd;
	ptep = &ptep[stage2_pte_index(addr, current_level)];
	while (ptep && pte_val(*ptep)) {
		if (pte_val(*ptep) & _PAGE_LEAF) {
			*ptep_level = current_level;
			*ptepp = ptep;
			return true;
		}

		if (current_level) {
			current_level--;
			*ptep_level = current_level;
			ptep = (pte_t *)stage2_pte_page_vaddr(*ptep);
			ptep = &ptep[stage2_pte_index(addr, current_level)];
		} else {
			ptep = NULL;
		}
	}

	return false;
}

static void stage2_remote_tlb_flush(struct kvm *kvm, u32 level, gpa_t addr)
{
	struct cpumask hmask;
	unsigned long size = PAGE_SIZE;
	struct kvm_vmid *vmid = &kvm->arch.vmid;

	if (stage2_level_to_page_size(level, &size))
		return;
	addr &= ~(size - 1);

	/*
	 * TODO: Instead of cpu_online_mask, we should only target CPUs
	 * where the Guest/VM is running.
	 */
	preempt_disable();
	riscv_cpuid_to_hartid_mask(cpu_online_mask, &hmask);
	sbi_remote_hfence_gvma_vmid(cpumask_bits(&hmask), addr, size,
				    READ_ONCE(vmid->vmid));
	preempt_enable();
}

static int stage2_set_pte(struct kvm *kvm, u32 level,
			   struct kvm_mmu_page_cache *pcache,
			   gpa_t addr, const pte_t *new_pte)
{
	u32 current_level = stage2_pgd_levels - 1;
	pte_t *next_ptep = (pte_t *)kvm->arch.pgd;
	pte_t *ptep = &next_ptep[stage2_pte_index(addr, current_level)];

	if (current_level < level)
		return -EINVAL;

	while (current_level != level) {
		if (pte_val(*ptep) & _PAGE_LEAF)
			return -EEXIST;

		if (!pte_val(*ptep)) {
			next_ptep = stage2_cache_alloc(pcache);
			if (!next_ptep)
				return -ENOMEM;
			*ptep = pfn_pte(PFN_DOWN(__pa(next_ptep)),
					__pgprot(_PAGE_TABLE));
		} else {
			if (pte_val(*ptep) & _PAGE_LEAF)
				return -EEXIST;
			next_ptep = (pte_t *)stage2_pte_page_vaddr(*ptep);
		}

		current_level--;
		ptep = &next_ptep[stage2_pte_index(addr, current_level)];
	}

	*ptep = *new_pte;
	if (pte_val(*ptep) & _PAGE_LEAF)
		stage2_remote_tlb_flush(kvm, current_level, addr);

	return 0;
}

static int stage2_map_page(struct kvm *kvm,
			   struct kvm_mmu_page_cache *pcache,
			   gpa_t gpa, phys_addr_t hpa,
			   unsigned long page_size, pgprot_t prot)
{
	int ret;
	u32 level = 0;
	pte_t new_pte;

	ret = stage2_page_size_to_level(page_size, &level);
	if (ret)
		return ret;

	new_pte = pfn_pte(PFN_DOWN(hpa), prot);
	return stage2_set_pte(kvm, level, pcache, gpa, &new_pte);
}

enum stage2_op {
	STAGE2_OP_NOP = 0,	/* Nothing */
	STAGE2_OP_CLEAR,	/* Clear/Unmap */
	STAGE2_OP_WP,		/* Write-protect */
};

static void stage2_op_pte(struct kvm *kvm, gpa_t addr,
			  pte_t *ptep, u32 ptep_level, enum stage2_op op)
{
	int i, ret;
	pte_t *next_ptep;
	u32 next_ptep_level;
	unsigned long next_page_size, page_size;

	ret = stage2_level_to_page_size(ptep_level, &page_size);
	if (ret)
		return;

	BUG_ON(addr & (page_size - 1));

	if (!pte_val(*ptep))
		return;

	if (ptep_level && !(pte_val(*ptep) & _PAGE_LEAF)) {
		next_ptep = (pte_t *)stage2_pte_page_vaddr(*ptep);
		next_ptep_level = ptep_level - 1;
		ret = stage2_level_to_page_size(next_ptep_level,
						&next_page_size);
		if (ret)
			return;

		if (op == STAGE2_OP_CLEAR)
			set_pte(ptep, __pte(0));
		for (i = 0; i < PTRS_PER_PTE; i++)
			stage2_op_pte(kvm, addr + i * next_page_size,
					&next_ptep[i], next_ptep_level, op);
		if (op == STAGE2_OP_CLEAR)
			put_page(virt_to_page(next_ptep));
	} else {
		if (op == STAGE2_OP_CLEAR)
			set_pte(ptep, __pte(0));
		else if (op == STAGE2_OP_WP)
			set_pte(ptep, __pte(pte_val(*ptep) & ~_PAGE_WRITE));
		stage2_remote_tlb_flush(kvm, ptep_level, addr);
	}
}

static void stage2_unmap_range(struct kvm *kvm, gpa_t start, gpa_t size)
{
	int ret;
	pte_t *ptep;
	u32 ptep_level;
	bool found_leaf;
	unsigned long page_size;
	gpa_t addr = start, end = start + size;

	while (addr < end) {
		found_leaf = stage2_get_leaf_entry(kvm, addr,
						   &ptep, &ptep_level);
		ret = stage2_level_to_page_size(ptep_level, &page_size);
		if (ret)
			break;

		if (!found_leaf)
			goto next;

		if (!(addr & (page_size - 1)) && ((end - addr) >= page_size))
			stage2_op_pte(kvm, addr, ptep,
				      ptep_level, STAGE2_OP_CLEAR);

next:
		addr += page_size;
	}
}

static void stage2_wp_range(struct kvm *kvm, gpa_t start, gpa_t end)
{
	int ret;
	pte_t *ptep;
	u32 ptep_level;
	bool found_leaf;
	gpa_t addr = start;
	unsigned long page_size;

	while (addr < end) {
		found_leaf = stage2_get_leaf_entry(kvm, addr,
						   &ptep, &ptep_level);
		ret = stage2_level_to_page_size(ptep_level, &page_size);
		if (ret)
			break;

		if (!found_leaf)
			goto next;

		if (!(addr & (page_size - 1)) && ((end - addr) >= page_size))
			stage2_op_pte(kvm, addr, ptep,
				      ptep_level, STAGE2_OP_WP);

next:
		addr += page_size;
	}
}

void stage2_wp_memory_region(struct kvm *kvm, int slot)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	struct kvm_memory_slot *memslot = id_to_memslot(slots, slot);
	phys_addr_t start = memslot->base_gfn << PAGE_SHIFT;
	phys_addr_t end = (memslot->base_gfn + memslot->npages) << PAGE_SHIFT;

	spin_lock(&kvm->mmu_lock);
	stage2_wp_range(kvm, start, end);
	spin_unlock(&kvm->mmu_lock);
	kvm_flush_remote_tlbs(kvm);
}

int stage2_ioremap(struct kvm *kvm, gpa_t gpa, phys_addr_t hpa,
		   unsigned long size, bool writable)
{
	pte_t pte;
	int ret = 0;
	unsigned long pfn;
	phys_addr_t addr, end;
	struct kvm_mmu_page_cache pcache = { 0, };

	end = (gpa + size + PAGE_SIZE - 1) & PAGE_MASK;
	pfn = __phys_to_pfn(hpa);

	for (addr = gpa; addr < end; addr += PAGE_SIZE) {
		pte = pfn_pte(pfn, PAGE_KERNEL);

		if (!writable)
			pte = pte_wrprotect(pte);

		ret = stage2_cache_topup(&pcache,
					 stage2_pgd_levels,
					 KVM_MMU_PAGE_CACHE_NR_OBJS);
		if (ret)
			goto out;

		spin_lock(&kvm->mmu_lock);
		ret = stage2_set_pte(kvm, 0, &pcache, addr, &pte);
		spin_unlock(&kvm->mmu_lock);
		if (ret)
			goto out;

		pfn++;
	}

out:
	stage2_cache_flush(&pcache);
	return ret;

}

void kvm_arch_free_memslot(struct kvm *kvm, struct kvm_memory_slot *free,
			   struct kvm_memory_slot *dont)
{
}

int kvm_arch_create_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
			    unsigned long npages)
{
	return 0;
}

void kvm_arch_memslots_updated(struct kvm *kvm, u64 gen)
{
}

void kvm_arch_flush_shadow_all(struct kvm *kvm)
{
	kvm_riscv_stage2_free_pgd(kvm);
}

void kvm_arch_flush_shadow_memslot(struct kvm *kvm,
				   struct kvm_memory_slot *slot)
{
}

void kvm_arch_commit_memory_region(struct kvm *kvm,
				const struct kvm_userspace_memory_region *mem,
				const struct kvm_memory_slot *old,
				const struct kvm_memory_slot *new,
				enum kvm_mr_change change)
{
	/*
	 * At this point memslot has been committed and there is an
	 * allocated dirty_bitmap[], dirty pages will be be tracked while the
	 * memory slot is write protected.
	 */
	if (change != KVM_MR_DELETE && mem->flags & KVM_MEM_LOG_DIRTY_PAGES)
		stage2_wp_memory_region(kvm, mem->slot);
}

int kvm_arch_prepare_memory_region(struct kvm *kvm,
				struct kvm_memory_slot *memslot,
				const struct kvm_userspace_memory_region *mem,
				enum kvm_mr_change change)
{
	hva_t hva = mem->userspace_addr;
	hva_t reg_end = hva + mem->memory_size;
	bool writable = !(mem->flags & KVM_MEM_READONLY);
	int ret = 0;

	if (change != KVM_MR_CREATE && change != KVM_MR_MOVE &&
			change != KVM_MR_FLAGS_ONLY)
		return 0;

	/*
	 * Prevent userspace from creating a memory region outside of the GPA
	 * space addressable by the KVM guest GPA space.
	 */
	if ((memslot->base_gfn + memslot->npages) >=
	    (stage2_gpa_size >> PAGE_SHIFT))
		return -EFAULT;

	down_read(&current->mm->mmap_sem);

	/*
	 * A memory region could potentially cover multiple VMAs, and
	 * any holes between them, so iterate over all of them to find
	 * out if we can map any of them right now.
	 *
	 *     +--------------------------------------------+
	 * +---------------+----------------+   +----------------+
	 * |   : VMA 1     |      VMA 2     |   |    VMA 3  :    |
	 * +---------------+----------------+   +----------------+
	 *     |               memory region                |
	 *     +--------------------------------------------+
	 */
	do {
		struct vm_area_struct *vma = find_vma(current->mm, hva);
		hva_t vm_start, vm_end;

		if (!vma || vma->vm_start >= reg_end)
			break;

		/*
		 * Mapping a read-only VMA is only allowed if the
		 * memory region is configured as read-only.
		 */
		if (writable && !(vma->vm_flags & VM_WRITE)) {
			ret = -EPERM;
			break;
		}

		/* Take the intersection of this VMA with the memory region */
		vm_start = max(hva, vma->vm_start);
		vm_end = min(reg_end, vma->vm_end);

		if (vma->vm_flags & VM_PFNMAP) {
			gpa_t gpa = mem->guest_phys_addr +
				    (vm_start - mem->userspace_addr);
			phys_addr_t pa;

			pa = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;
			pa += vm_start - vma->vm_start;

			/* IO region dirty page logging not allowed */
			if (memslot->flags & KVM_MEM_LOG_DIRTY_PAGES) {
				ret = -EINVAL;
				goto out;
			}

			ret = stage2_ioremap(kvm, gpa, pa,
					     vm_end - vm_start, writable);
			if (ret)
				break;
		}
		hva = vm_end;
	} while (hva < reg_end);

	if (change == KVM_MR_FLAGS_ONLY)
		goto out;

	spin_lock(&kvm->mmu_lock);
	if (ret)
		stage2_unmap_range(kvm, mem->guest_phys_addr,
				   mem->memory_size);
	spin_unlock(&kvm->mmu_lock);

out:
	up_read(&current->mm->mmap_sem);
	return ret;
}

int kvm_riscv_stage2_map(struct kvm_vcpu *vcpu, gpa_t gpa, unsigned long hva,
			 bool is_write)
{
	int ret;
	short lsb;
	kvm_pfn_t hfn;
	bool writeable;
	gfn_t gfn = gpa >> PAGE_SHIFT;
	struct vm_area_struct *vma;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_mmu_page_cache *pcache = &vcpu->arch.mmu_page_cache;
	unsigned long vma_pagesize;

	down_read(&current->mm->mmap_sem);

	vma = find_vma_intersection(current->mm, hva, hva + 1);
	if (unlikely(!vma)) {
		kvm_err("Failed to find VMA for hva 0x%lx\n", hva);
		up_read(&current->mm->mmap_sem);
		return -EFAULT;
	}

	vma_pagesize = vma_kernel_pagesize(vma);

	if (vma_pagesize == PMD_SIZE || vma_pagesize == PGDIR_SIZE)
		gfn = (gpa & huge_page_mask(hstate_vma(vma))) >> PAGE_SHIFT;

	up_read(&current->mm->mmap_sem);

	if (vma_pagesize != PGDIR_SIZE &&
	    vma_pagesize != PMD_SIZE &&
	    vma_pagesize != PAGE_SIZE) {
		kvm_err("Invalid VMA page size 0x%lx\n", vma_pagesize);
		return -EFAULT;
	}

	/* We need minimum second+third level pages */
	ret = stage2_cache_topup(pcache, stage2_pgd_levels,
				 KVM_MMU_PAGE_CACHE_NR_OBJS);
	if (ret) {
		kvm_err("Failed to topup stage2 cache\n");
		return ret;
	}

	hfn = gfn_to_pfn_prot(kvm, gfn, is_write, &writeable);
	if (hfn == KVM_PFN_ERR_HWPOISON) {
		if (is_vm_hugetlb_page(vma))
			lsb = huge_page_shift(hstate_vma(vma));
		else
			lsb = PAGE_SHIFT;

		send_sig_mceerr(BUS_MCEERR_AR, (void __user *)hva,
				lsb, current);
		return 0;
	}
	if (is_error_noslot_pfn(hfn))
		return -EFAULT;
	if (!writeable && is_write)
		return -EPERM;

	spin_lock(&kvm->mmu_lock);

	if (writeable) {
		kvm_set_pfn_dirty(hfn);
		ret = stage2_map_page(kvm, pcache, gpa, hfn << PAGE_SHIFT,
				      vma_pagesize, PAGE_WRITE_EXEC);
	} else {
		ret = stage2_map_page(kvm, pcache, gpa, hfn << PAGE_SHIFT,
				      vma_pagesize, PAGE_READ_EXEC);
	}

	if (ret)
		kvm_err("Failed to map in stage2\n");

	spin_unlock(&kvm->mmu_lock);
	kvm_set_pfn_accessed(hfn);
	kvm_release_pfn_clean(hfn);
	return ret;
}

void kvm_riscv_stage2_flush_cache(struct kvm_vcpu *vcpu)
{
	stage2_cache_flush(&vcpu->arch.mmu_page_cache);
}

int kvm_riscv_stage2_alloc_pgd(struct kvm *kvm)
{
	if (kvm->arch.pgd != NULL) {
		kvm_err("kvm_arch already initialized?\n");
		return -EINVAL;
	}

	kvm->arch.pgd = alloc_pages_exact(PAGE_SIZE, GFP_KERNEL | __GFP_ZERO);
	if (!kvm->arch.pgd)
		return -ENOMEM;
	kvm->arch.pgd_phys = virt_to_phys(kvm->arch.pgd);

	return 0;
}

void kvm_riscv_stage2_free_pgd(struct kvm *kvm)
{
	void *pgd = NULL;

	spin_lock(&kvm->mmu_lock);
	if (kvm->arch.pgd) {
		stage2_unmap_range(kvm, 0UL, stage2_gpa_size);
		pgd = READ_ONCE(kvm->arch.pgd);
		kvm->arch.pgd = NULL;
		kvm->arch.pgd_phys = 0;
	}
	spin_unlock(&kvm->mmu_lock);

	/* Free the HW pgd, one page at a time */
	if (pgd)
		free_pages_exact(pgd, PAGE_SIZE);
}

void kvm_riscv_stage2_update_hgatp(struct kvm_vcpu *vcpu)
{
	unsigned long hgatp = HGATP_MODE;
	struct kvm_arch *k = &vcpu->kvm->arch;

	hgatp |= (READ_ONCE(k->vmid.vmid) << HGATP_VMID_SHIFT) &
		 HGATP_VMID_MASK;
	hgatp |= (k->pgd_phys >> PAGE_SHIFT) & HGATP_PPN;

	csr_write(CSR_HGATP, hgatp);

	if (!kvm_riscv_stage2_vmid_bits())
		__kvm_riscv_hfence_gvma_all();
}
