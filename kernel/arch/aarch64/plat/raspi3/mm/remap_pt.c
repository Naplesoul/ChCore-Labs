#include <common/util.h>
#include <common/vars.h>
#include <common/macro.h>
#include <common/types.h>
#include <common/errno.h>
#include <lib/printk.h>
#include <mm/kmalloc.h>
#include <mm/mm.h>
#include <arch/mmu.h>

#define PHYSMEM_START           (0x0UL)
#define PERIPHERAL_BASE         (0x3F000000UL)
#define PHYSMEM_END             (0x40000000UL)
#define LOCAL_PERIPHERAL_END    (0x80000000UL)

extern char text_start;
extern char data_start;
extern char rodata_start;
extern char bss_start;

int remap_kernel_page_table()
{
        paddr_t text_start_pa = (paddr_t)&text_start;
        paddr_t data_start_pa = (paddr_t)&data_start;
        paddr_t rodata_start_pa = (paddr_t)&rodata_start;
        paddr_t bss_start_pa = (paddr_t)&bss_start;

        void *new_pgtbl = get_pages(0);
        memset((void *)new_pgtbl, 0, PAGE_SIZE);

        int ret = 0;
        
        // map physical memory before .text section
        // rw
        ret = map_range_in_pgtbl_huge(new_pgtbl,
                KBASE + PHYSMEM_START, PHYSMEM_START,
                text_start_pa - PHYSMEM_START,
                VMR_READ | VMR_WRITE | VMR_KERNEL);
        if (ret < 0) return ret;

        // map physical memory of .text section
        // re
        ret = map_range_in_pgtbl_huge(new_pgtbl,
                KBASE + text_start_pa, text_start_pa,
                data_start_pa - text_start_pa,
                VMR_READ | VMR_EXEC | VMR_KERNEL);
        if (ret < 0) return ret;

        // map physical memory of .data section
        // rw
        ret = map_range_in_pgtbl_huge(new_pgtbl,
                KBASE + data_start_pa, data_start_pa,
                rodata_start_pa - data_start_pa, 
                VMR_READ | VMR_WRITE | VMR_KERNEL);
        if (ret < 0) return ret;

        // map physical memory of .rodata section
        // ro
        ret = map_range_in_pgtbl_huge(new_pgtbl,
                KBASE + rodata_start_pa, rodata_start_pa,
                bss_start_pa - rodata_start_pa,
                VMR_READ | VMR_KERNEL);
        if (ret < 0) return ret;

        // map physical memory from .bss start to periperal base
        // rw
        ret = map_range_in_pgtbl_huge(new_pgtbl,
                KBASE + bss_start_pa, bss_start_pa,
                PERIPHERAL_BASE - bss_start_pa,
                VMR_READ | VMR_WRITE | VMR_KERNEL);
        if (ret < 0) return ret;

        // map shared device memory from periperal base to physmem end
        // rw
        ret = map_range_in_pgtbl_huge(new_pgtbl,
                KBASE + PERIPHERAL_BASE, PERIPHERAL_BASE,
                PHYSMEM_END - PERIPHERAL_BASE,
                VMR_READ | VMR_WRITE | VMR_DEVICE | VMR_KERNEL);
        if (ret < 0) return ret;

        // map local peripherals from physmem end to local peripheral end
        // rw
        ret = map_range_in_pgtbl_huge(new_pgtbl,
                KBASE + PHYSMEM_END, PHYSMEM_END,
                LOCAL_PERIPHERAL_END - PHYSMEM_END,
                VMR_READ | VMR_WRITE | VMR_DEVICE | VMR_KERNEL);
        if (ret < 0) return ret;

        paddr_t new_pgtbl_pa = virt_to_phys(new_pgtbl);

        // write into ttbr1_el1 register
        // flush tlb
        asm volatile("msr ttbr1_el1, %0\n"
                     "tlbi vmalle1is\n"
                     "dsb sy\n"
                     "isb" :: "r"(new_pgtbl_pa));
        
        return 0;
}

#ifdef CHCORE_KERNEL_TEST
void lab2_test_kernel_page_table_remap(void)
{
        // just a addr in .text section
        void *text_test = &text_start + KBASE + 8;
        // test readable
        printk("[TEST] .text section readable: 0x%lx\n", *(u64 *)text_test);
        // test not writable
        *(u64 *)text_test = 1;

        // just a addr in .data section
        void *data_test = &data_start + KBASE + 8;
        // test readable
        printk("[TEST] .data section readable: 0x%lx\n", *(u64 *)data_test);
        // test not excutable
        asm volatile("blr %0" :: "r"(data_test));
}
#endif /* CHCORE_KERNEL_TEST */
