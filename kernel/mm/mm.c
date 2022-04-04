#include <mm/mm.h>
#include <mm/mm_check.h>
#include <common/kprint.h>
#include <common/macro.h>
#include <mm/buddy.h>
#include <mm/slab.h>
#include <mm/swap.h>

extern void parse_mem_map(void);
extern int remap_kernel_page_table(void);

#ifdef CHCORE_KERNEL_TEST
extern void lab2_test_kernel_page_table_remap(void);
#endif /* CHCORE_KERNEL_TEST */


/* On raspi3, the size of physical memory pool only need to be 1 */
#define PHYS_MEM_POOL_SIZE 1
struct phys_mem_pool global_mem[PHYS_MEM_POOL_SIZE];
int physmem_map_num;
u64 physmem_map[PHYS_MEM_POOL_SIZE][2]; /* [start, end) */

/*
 * Layout:
 *
 * | metadata (npages * sizeof(struct page)) | start_vaddr ... (npages *
 * PAGE_SIZE) |
 *
 */

void mm_init(void)
{
        vaddr_t free_mem_start = 0;
        vaddr_t free_mem_end = 0;
        struct page *page_meta_start = NULL;
        u64 npages = 0;
        u64 start_vaddr = 0;

        physmem_map_num = 0;
        parse_mem_map();

        if (physmem_map_num == 1) {
                free_mem_start = phys_to_virt(physmem_map[0][0]);
                free_mem_end = phys_to_virt(physmem_map[0][1]);

                npages = (free_mem_end - free_mem_start)
                         / (PAGE_SIZE + sizeof(struct page));
                start_vaddr =
                        ROUND_UP(free_mem_start + npages * sizeof(struct page),
                                 PAGE_SIZE);
                kdebug("[CHCORE] mm: free_mem_start is 0x%lx, free_mem_end is 0x%lx\n",
                       free_mem_start,
                       free_mem_end);

                page_meta_start = (struct page *)free_mem_start;
                kdebug("page_meta_start: 0x%lx, real_start_vaddr: 0x%lx\n"
                       "npages: 0x%lx, page_meta_size: 0x%lx\n",
                       page_meta_start,
                       start_vaddr,
                       npages,
                       sizeof(struct page));

                /* buddy alloctor for managing physical memory */
                init_buddy(
                        &global_mem[0], page_meta_start, start_vaddr, npages);
        } else {
                BUG("Unsupported physmem_map_num\n");
        }

#ifdef CHCORE_KERNEL_TEST
        void lab2_test_buddy(void);
        lab2_test_buddy();
#endif /* CHCORE_KERNEL_TEST */

        /* slab alloctor for allocating small memory regions */
        init_slab();

        if (remap_kernel_page_table() >= 0)
                kinfo("[ChCore] kernel page table remapped\n");
        else
                BUG("Fail to remap kernel page table\n");

#if ENABLE_SWAP
        if (swap_init() >= 0)
                kinfo("[ChCore] swap init\n");
        else
                BUG("Fail to init swap\n");
#endif

#ifdef CHCORE_KERNEL_TEST
        // lab2_test_kernel_page_table_remap();
#endif /* CHCORE_KERNEL_TEST */
}
