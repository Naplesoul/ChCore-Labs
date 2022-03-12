#pragma once

#ifndef KBASE
#define KBASE              0xFFFFFF0000000000
#define PHYSICAL_ADDR_MASK (40)
#endif // KBASE

#ifndef __ASM__

#include <common/types.h>
typedef u64 vmr_prop_t;
#define VMR_READ    (1 << 0)
#define VMR_WRITE   (1 << 1)
#define VMR_EXEC    (1 << 2)
#define VMR_DEVICE  (1 << 3)
#define VMR_NOCACHE (1 << 4)
#define VMR_KERNEL  (1 << 5)

/* functions */
int map_range_in_pgtbl(void *pgtbl, vaddr_t va, paddr_t pa, size_t len,
                       vmr_prop_t flags);
int unmap_range_in_pgtbl(void *pgtbl, vaddr_t va, size_t len);

#define PHYSMEM_START           (0x0UL)
#define PERIPHERAL_BASE         (0x3F000000UL)
#define PHYSMEM_END             (0x40000000UL)
#define LOCAL_PERIPHERAL_END    (0x80000000UL)

int remap_kernel_page_table();

#define phys_to_virt(x) ((vaddr_t)((paddr_t)(x) + KBASE))
#define virt_to_phys(x) ((paddr_t)((vaddr_t)(x)-KBASE))

#endif // __ASM__
