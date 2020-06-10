每个页的大小： 2^12 = 4096 Bytes

每个地址的大小： 8 Bytes

每个页能容纳：2^9 = 512 个地址

需要一个 9bit 的字段来索引映射表

一般来说，如果页面大小为 2^k，那么一个页面可以容纳 k-3 个指针

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/export.h>

static unsigned long cr0;
static unsigned long cr3;

static unsigned long vaddr = 0;

static void get_pgtable_macro(void)
{
        cr0 = read_cr0();
        cr3 = read_cr3_pa();

        printk("cr0 = 0x%lx, cr3 = 0x%lx\n", cr0, cr3);

        printk("PGDIR_SHIFT = %d\n", PGDIR_SHIFT);
        printk("P4D_SHIFT = %d\n", P4D_SHIFT);
        printk("PUD_SHIFT = %d\n", PUD_SHIFT);
        printk("PMD_SHIFT = %d\n", PMD_SHIFT);
        printk("PAGE_SHIFT = %d\n", PAGE_SHIFT);

        //页目录表中项的个数
        printk("PTRS_PER_PGD = %d\n", PTRS_PER_PGD);
        printk("PTRS_PER_P4D = %d\n", PTRS_PER_P4D);
        printk("PTRS_PER_PUD = %d\n", PTRS_PER_PUD);
        printk("PTRS_PER_PMD = %d\n", PTRS_PER_PMD);
        printk("PTRS_PER_PTE = %d\n", PTRS_PER_PTE);

        //页内偏移掩码，用来屏蔽 page_offset
        printk("PAGEMASK = 0x%lx\n", PAGE_MASK);
}

void vaddr2paddr(unsigned long vaddr)
{
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;

        unsigned long paddr = 0;
        unsigned long page_addr = 0;
        unsigned long page_offset = 0;

        //取得页全局目录项
        pgd = pgd_offset(current->mm, vaddr);
        printk("pgd_val = 0x%lx, pgd_index = %lu\n", pgd_val(*pgd), pgd_index(vaddr));

        //取得 p4d
        p4d = p4d_offset(pgd, vaddr);
        printk("p4d_val = 0x%lx, p4d_index = %lu\n", p4d_val(*p4d), p4d_index(vaddr));

        //取得页上级目录项
        pud = pud_offset(p4d, vaddr);
        printk("pud_val = 0x%lx, pud_index = %lu\n", pud_val(*pud), pud_index(vaddr));

        //取得页中间目录项
        pmd = pmd_offset(pud, vaddr);
        printk("pmd_val = 0x%lx, pmd_index = %lu\n", pmd_val(*pmd), pmd_index(vaddr));

        //取得页表（在主内核页表中查找）
        pte = pte_offset_kernel(pmd, vaddr);
        printk("pte_val = 0x%lx, pte_index = %lu\n", pte_val(*pte), pte_index(vaddr));

        //取得的页表项的低 12 位放的是页属性
        //所以用 PAGE_MASK 来清除
        page_addr = pte_val(*pte) & PAGE_MASK;
        
        //取得页内偏移 page_offset
        //也就是只取虚拟地址的地 12 位
        page_offset = vaddr & ~PAGE_MASK;

        //然后和并页表地址和页内偏移取得物理地址
        paddr = page_addr | page_offset;

        printk("page_addr = 0x%lx, page_offset = 0x%lx\n", page_addr, page_offset);
        printk("virtual address = 0x%lx, physical address = 0x%lx\n", vaddr, paddr);

}

static int __init v2p_init(void)
{
        unsigned long vaddr = 0;
        printk("vritual address to physical address module is running..\n");
        get_pgtable_macro();
        printk("\n");
        vaddr = __get_free_page(GFP_KERNEL);
        if(vaddr == 0)
        {
                printk("__get_free_page failed..\n");
                return 0;
        }
        printk("get_page_vaddr = 0x%lx\n", vaddr);
        vaddr2paddr(vaddr);
        return 0;
}

static void __exit v2p_exit(void)
{
        free_page(vaddr);
        printk("module is leaving...\n");
}


module_init(v2p_init);
module_exit(v2p_exit);
```

