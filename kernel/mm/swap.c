#include <mm/mm.h>
#include <mm/swap.h>
#include <common/kprint.h>
#include <common/radix.h>
#include <common/util.h>
#include <arch/mm/page_table.h>

#define BLOCK_NUM 0x1000
#define BLOCK_SIZE 0X1000

static struct radix *blockid_radix;
static u8 disk_bitmap[BLOCK_NUM / 8];
static u8 disk[BLOCK_NUM][BLOCK_SIZE];

static int alloc_block(u64 *block_id)
{
        int found = 0;
        for (u32 i = 0; i < BLOCK_NUM / 8; ++i) {
                u8 bits = disk_bitmap[i];
                if (bits < 0xff) {
                        for (u32 j = 0; j < 8; ++j) {
                                u8 bit = (bits >> (7 - j)) & 0x1;
                                if (bit == 0) {
                                        found = 1;
                                        bits = bits | (0x1 << (7 - j));
                                        disk_bitmap[i] = bits;
                                        *block_id = i * 8 + j;
                                        break;
                                }
                        }
                        break;
                }
        }

        if (found) return 0;
        return -1;
}

static int free_block(u64 block_id)
{
        u32 i = block_id / 8;
        u32 j = block_id % 8;
        u8 bits = disk_bitmap[i];
        bits = bits | (0x1 << (7 - j));
        disk_bitmap[i] = bits;
}

static int write(u64 block_id, void *data)
{
        memcpy(disk[block_id], data, PAGE_SIZE);
}

static int read(u64 block_id, void *data)
{
        memcpy(data, disk[block_id], PAGE_SIZE);
}

int swap_init()
{
        blockid_radix = new_radix();
        init_radix(blockid_radix);
        memset(disk_bitmap, 0, BLOCK_NUM / 8);
        return swap_strategy_init();
}

static int swap_write_fs(void *vict_pte, void *vict_pg)
{
        int r;
        u64 *block_id = kmalloc(sizeof(u64));

        r = alloc_block(block_id);
        if (r < 0) {
                kwarn("[swap] fail to alloc a disk block\n");
                return r;
        }

        r = write(*block_id, vict_pg);
        if (r < 0) {
                kwarn("[swap] fail to write a disk block\n");
                return r;
        }

        r = radix_add(blockid_radix, (u64)vict_pte, block_id);
        if (r < 0) {
                kwarn("[swap] fail to add blockid_radix\n");
                free_block(*block_id);
                return r;
        }

        return 0;
}

static int swap_read_fs(void *pte, void *pg)
{
        int r;

        u64 *block_id = radix_get(blockid_radix, (u64)pte);

        if (block_id == NULL) {
                kwarn("[swap] fail to get blockid_radix\n");
                return -1;
        }

        r = radix_del(blockid_radix, (u64)pte);

        if (r < 0) {
                kwarn("[swap] fail to del blockid_radix\n");
                return r;
        }

        r = read(*block_id, pg);
        if (r < 0) {
                kwarn("[swap] fail to read a disk block\n");
                return r;
        }

        r = free_block(*block_id);
        if (r < 0) {
                kwarn("[swap] fail to free a disk block\n");
                return r;
        }

        return 0;
}

int swap_out(void **vict_page)
{
        int r;
        void *vict_pte = NULL;

        r = swap_select_victim(&vict_pte, vict_page);
        if (r < 0) {
                kwarn("[swap] fail to select a victim page\n");
                return r;
        }

        r = swap_write_fs(vict_pte, *vict_page);
        if (r < 0) {
                kwarn("[swap] fail to write a page to fs\n");
                return r;
        }

        // page access fault will first trigger and page trans fault later
        // next time when the page needs to be swapped in,
        // it will be accessed immediately
        // and does not need to trigger page access fault first
        set_access_flag(vict_pte);
        clear_present_flag(vict_pte);

        kinfo("[swap] swapped out a page\n");
        return 0;
}

int swap_in(void *pte, void *page)
{
        int r;

        r = swap_read_fs(pte, page);
        if (r < 0) {
                kwarn("[swap] fail to read a page from fs\n\n");
                return r;
        }

        set_map_paddr(pte, virt_to_phys(page));
        swap_listen_map(pte, page);
        // the page swapped in will be accessed
        // just after page fault handler exits
        set_access_flag(pte);
        set_present_flag(pte);

        kinfo("[swap] swapped in a page\n");
        return 0;
}