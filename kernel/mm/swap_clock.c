#include <mm/swap.h>
#include <mm/kmalloc.h>
#include <arch/mm/page_table.h>

struct clock_node
{
        void *pte;
        void *page;
        struct clock_node *next;
};

static struct clock_node *cur_node;

int swap_strategy_init()
{
        cur_node = NULL;
        return 0;
}

int swap_listen_map(void *pte, void *page)
{
        if (!cur_node) {
                cur_node = kmalloc(sizeof(struct clock_node));
                cur_node->pte = pte;
                cur_node->page = page;
                cur_node->next = cur_node;
        } else {
                struct clock_node *new_node = kmalloc(sizeof(struct clock_node));
                new_node->pte = pte;
                new_node->page = page;
                new_node->next = cur_node->next;
                cur_node->next = new_node;
                cur_node = new_node;
        }

        return 0;
}

int swap_listen_unmap(void *pte)
{
        if (!cur_node) return 0;

        struct clock_node *n = cur_node->next;
        struct clock_node *prev_n = cur_node;

        while (n != cur_node) {
                if (n->pte == pte) break;
                prev_n = n;
                n = n->next;
        }

        if (n->pte != pte) return 0;

        if (prev_n == n) {
                // there is only one node
                kfree(n);
                cur_node = NULL;
        } else {
                if (cur_node == n) {
                        cur_node = prev_n;
                }
                prev_n->next = n->next;
                kfree(n);
        }

        return 0;
}

int swap_select_victim(void **vict_pte, void **vict_page)
{
        if (!cur_node) return -1;

        struct clock_node *prev_node = cur_node;
        cur_node = cur_node->next;

        while (is_page_accessed(cur_node->pte)) {
                clear_access_flag(cur_node->pte);
                prev_node = cur_node;
                cur_node = cur_node->next;
        }

        *vict_pte = cur_node->pte;
        *vict_page = cur_node->page;

        if (prev_node == cur_node) {
                // there is only one node
                kfree(cur_node);
                cur_node = NULL;
        } else {
                prev_node->next = cur_node->next;
                kfree(cur_node);
                cur_node = prev_node;
        }

        return 0;
}