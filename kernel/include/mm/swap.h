#include <common/types.h>
#include <mm/buddy.h>

#define ENABLE_SWAP 1

int swap_init();
int swap_strategy_init();

int swap_listen_map(void *pte, void *page);
int swap_listen_unmap(void *pte);

int swap_select_victim(void **vict_pte, void **vict_page);

int swap_out(void **vict_page);
int swap_in(void *pte, void *page);