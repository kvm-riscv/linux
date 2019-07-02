# SPDX-License-Identifier: GPL-2.0
# Makefile for RISC-V KVM support
#

common-objs-y = $(addprefix ../../../virt/kvm/, kvm_main.o coalesced_mmio.o)

ccflags-y := -Ivirt/kvm -Iarch/riscv/kvm

kvm-objs := $(common-objs-y)

kvm-objs += main.o vm.o mmu.o vcpu.o vcpu_exit.o vcpu_switch.o

obj-$(CONFIG_KVM)	+= kvm.o
