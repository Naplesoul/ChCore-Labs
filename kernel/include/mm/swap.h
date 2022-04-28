#include <common/types.h>
#include <mm/buddy.h>

#define ENABLE_SWAP 1

int swap_init();
int swap_strategy_init();

// record map actions
// the page recorded will be a candidate to swap out
int swap_listen_map(void *pte, void *page);

// record unmap actions
// the page recorded will be remove from the candidates
int swap_listen_unmap(void *pte);

int swap_select_victim(void **vict_pte, void **vict_page);

// select and swap out a page
// vict_page will be set to the vaddr of the victim page (pa is virt_to_phys(vict_page))
// tlb flush is required after function returns
int swap_out(void **vict_page);

// select and swap in the page pointed by pte to vaddr page
// tlb flush is required after function returns
int swap_in(void *pte, void *page);