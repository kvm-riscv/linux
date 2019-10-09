// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/of.h>
#include <asm/smp.h>

int riscv_read_check_isa(struct device_node *node, const char **isa)
{
	u32 hart;

	if (of_property_read_u32(node, "reg", &hart)) {
		pr_warn("Found CPU without hart ID\n");
		return -ENODEV;
	}

	if (of_property_read_string(node, "riscv,isa", isa)) {
		pr_warn("CPU with hartid=%d has no \"riscv,isa\" property\n",
			hart);
		return -ENODEV;
	}
	/*
	 * Linux doesn't support rv32e or rv128i, and we only support booting
	 * kernels on harts with the same ISA that the kernel is compiled for.
	 */
	if (IS_ENABLED(CONFIG_32BIT) && (strncmp(*isa, "rv32i", 5) != 0)) {
		pr_warn("hartid=%d has an invalid ISA \"%s\" for 32bit config\n",
			hart, *isa);
		return -ENODEV;
	} else if (IS_ENABLED(CONFIG_64BIT) &&
		  (strncmp(*isa, "rv64i", 5) != 0)) {
		pr_warn("hartid=%d has an invalid ISA \"%s\" for 64bit config\n",
			hart, *isa);
		return -ENODEV;
	}
	return 0;
}

/*
 * Returns the hart ID of the given device tree node, or -ENODEV if the node
 * isn't an enabled and valid RISC-V hart node.
 */
int riscv_of_processor_hartid(struct device_node *node)
{
	u32 hart;

	if (!of_device_is_compatible(node, "riscv")) {
		pr_warn("Found incompatible CPU\n");
		return -ENODEV;
	}

	if (of_property_read_u32(node, "reg", &hart)) {
		pr_warn("Found CPU without hart ID\n");
		return -ENODEV;
	}

	if (!of_device_is_available(node)) {
		pr_info("CPU with hartid=%d is not available\n", hart);
		return -ENODEV;
	}

	return hart;
}

#ifdef CONFIG_PROC_FS

static void print_isa(struct seq_file *f, const char *isa)
{
	/* Print the entire ISA as it is */
	seq_puts(f, "isa\t\t: ");
	seq_write(f, isa, strlen(isa));
	seq_puts(f, "\n");
}

static void print_mmu(struct seq_file *f, const char *mmu_type)
{
#if defined(CONFIG_32BIT)
	if (strcmp(mmu_type, "riscv,sv32") != 0)
		return;
#elif defined(CONFIG_64BIT)
	if (strcmp(mmu_type, "riscv,sv39") != 0 &&
	    strcmp(mmu_type, "riscv,sv48") != 0)
		return;
#endif

	seq_printf(f, "mmu\t\t: %s\n", mmu_type+6);
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	*pos = cpumask_next(*pos - 1, cpu_online_mask);
	if ((*pos) < nr_cpu_ids)
		return (void *)(uintptr_t)(1 + *pos);
	return NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
}

static int c_show(struct seq_file *m, void *v)
{
	unsigned long cpu_id = (unsigned long)v - 1;
	struct device_node *node = of_get_cpu_node(cpu_id, NULL);
	const char *compat, *isa, *mmu;

	seq_printf(m, "processor\t: %lu\n", cpu_id);
	seq_printf(m, "hart\t\t: %lu\n", cpuid_to_hartid_map(cpu_id));
	if (!of_property_read_string(node, "riscv,isa", &isa))
		print_isa(m, isa);
	if (!of_property_read_string(node, "mmu-type", &mmu))
		print_mmu(m, mmu);
	if (!of_property_read_string(node, "compatible", &compat)
	    && strcmp(compat, "riscv"))
		seq_printf(m, "uarch\t\t: %s\n", compat);
	seq_puts(m, "\n");
	of_node_put(node);

	return 0;
}

const struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= c_show
};

#endif /* CONFIG_PROC_FS */
