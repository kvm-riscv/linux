/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *     Anup Patel <anup.patel@wdc.com>
 */

#include <linux/linkage.h>
#include <asm/asm.h>

	.text
	.altmacro
	.option norelax

	/*
	 * Instruction encoding of hfence.gvma is:
	 * 0110001 rs2(5) rs1(5) 000 00000 1110011
	 */

ENTRY(__kvm_riscv_hfence_gvma_vmid_gpa)
	/* hfence.gvma a1, a0 */
	.word 0x62a60073
	ret
ENDPROC(__kvm_riscv_hfence_gvma_vmid_gpa)

ENTRY(__kvm_riscv_hfence_gvma_vmid)
	/* hfence.gvma zero, a0 */
	.word 0x62a00073
	ret
ENDPROC(__kvm_riscv_hfence_gvma_vmid)

ENTRY(__kvm_riscv_hfence_gvma_gpa)
	/* hfence.gvma a0 */
	.word 0x62050073
	ret
ENDPROC(__kvm_riscv_hfence_gvma_gpa)

ENTRY(__kvm_riscv_hfence_gvma_all)
	/* hfence.gvma */
	.word 0x62000073
	ret
ENDPROC(__kvm_riscv_hfence_gvma_all)
