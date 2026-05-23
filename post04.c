#include <stddef.h>
#define _DEFAULT_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ALIGNMENT 16           /* Alineacion de payload (bytes) */
#define BLOCK_MAGIC 0xDEADBEEF /* deteccion de corrupcion */
#define FLAG_IN_USE 0x1        /* bit 0: bloque en uso */

/*
 * block_header_t: metadata que precede a cada payload.
 *
 * Layout en memoria:
 *   [block_header_t][padding?][payload...............]
 *   ^header         ^payload (alineado a ALIGNMENT)
 *
 * size = tamaño del payload (ya alineado hacia arriba).
 * flags = bit 0: in_use. bits 1-7: reservados (Post 3: free,
 *         Post 8+: GC mark bits).
 * magic = 0xDEADBEEF. Si difiere, alguien corrompio el header.
 */
typedef struct {
    size_t size;    /* payload size (aligned) */
    uint32_t flags; /* bit 0: in_use. bits 1-7: reservados */
    uint32_t magic; /* 0xDEADBEEF, deteccion de corrupcion */
} block_header_t;

typedef struct {
    size_t size;
} block_footer_t;

typedef struct {
    block_header_t *next; /* siguiente bloque libre */
} free_block_t;

/*
 * heap_t: identica a Post 1.
 */
typedef struct {
    void *start;
    void *brk;
    size_t capacity;
    size_t used;
    block_header_t *free_list_head;
} heap_t;

static inline size_t align_up(size_t n, size_t align) {
    return (n + align - 1) & ~(align - 1);
}

#define HEADER_SIZE (align_up(sizeof(block_header_t), ALIGNMENT))
#define FOOTER_SIZE (align_up(sizeof(block_footer_t), ALIGNMENT))
#define MIN_BLOCK_SIZE (HEADER_SIZE + ALIGNMENT + FOOTER_SIZE)

/* Payload pointer desde un header */
static inline void *payload_of(block_header_t *hdr) {
    return (char *)hdr + HEADER_SIZE;
}

/* Header desde un payload */
static inline block_header_t *header_of(void *payload) {
    return (block_header_t *)((char *)payload - HEADER_SIZE);
}

/* free_block_t que vive dentro del payload de un bloque libre */
static inline free_block_t *free_node_of(block_header_t *hdr) {
    return (free_block_t *)payload_of(hdr);
}

static inline block_footer_t *footer_of(block_header_t *hdr) {
    return (block_footer_t *)((char *)hdr + HEADER_SIZE + hdr->size);
}

static inline size_t block_total(block_header_t *hdr) {
    return HEADER_SIZE + hdr->size + FOOTER_SIZE;
}

static inline int block_is_valid(block_header_t *hdr) {
    return hdr->magic == BLOCK_MAGIC;
}

static inline block_header_t *header_after(block_header_t *hdr, const heap_t *h) {
    char *next = (char *)hdr + block_total(hdr);
    char *heap_end = (char *)h->start + h->used;
    if (next + HEADER_SIZE > heap_end) {
        return NULL;
    }
    return (block_header_t *)next;
}

static inline block_header_t *header_before(block_header_t *hdr, const heap_t *h) {
    if ((char *)hdr <= (char *)h->start) {
        return NULL;
    }

    block_footer_t *prev_ftr = (block_footer_t *)((char *)hdr - FOOTER_SIZE);

    char *prev_start = (char *)hdr - FOOTER_SIZE - prev_ftr->size - HEADER_SIZE;

    if (prev_start < (char *)h->start) {
        return NULL;
    }

    return (block_header_t *)prev_start;
}

static void insert_to_free_list(heap_t *h, block_header_t *hdr) {
    free_block_t *node = free_node_of(hdr);
    node->next = h->free_list_head;
    h->free_list_head = hdr;
}

static void remove_from_free_list(heap_t *h, block_header_t *target) {
    block_header_t *prev = NULL;
    block_header_t *curr = h->free_list_head;

    while (curr != NULL) {
        if (curr == target) {
            if (prev == NULL) {
                h->free_list_head = free_node_of(curr)->next;
            } else {
                free_node_of(prev)->next = free_node_of(curr)->next;
            }
            return;
        }
        prev = curr;
        curr = free_node_of(curr)->next;
    }
}

heap_t heap_init(size_t initial_size) {
    heap_t h;

    h.start = sbrk(0);
    if (h.start == (void *)-1) {
        h.start = NULL;
        h.brk = NULL;
        h.capacity = 0;
        h.used = 0;
        h.free_list_head = NULL;
        return h;
    }

    void *result = sbrk((intptr_t)initial_size);
    if (result == (void *)-1) {
        h.start = NULL;
        h.brk = NULL;
        h.capacity = 0;
        h.used = 0;
        h.free_list_head = NULL;
        return h;
    }

    h.brk = (char *)h.start + initial_size;
    h.capacity = initial_size;
    h.used = 0;
    h.free_list_head = NULL;
    return h;
}

block_header_t *header_from_payload(void *ptr) {
    if (ptr == NULL) return NULL;

    block_header_t *hdr = header_of(ptr);
    if (hdr->magic != BLOCK_MAGIC) {
        fprintf(stderr, "  [CORRUPCION] magic esperado 0x%X, encontrado 0x%X en %p\n", BLOCK_MAGIC,
                hdr->magic, (void *)hdr);
        return NULL;
    }
    return hdr;
}

void heap_free(heap_t *h, void *ptr) {
    if (ptr == NULL) return;

    block_header_t *hdr = header_from_payload(ptr);
    if (hdr == NULL) return;

    if (!(hdr->flags & FLAG_IN_USE)) {
        fprintf(stderr, "  [DOUBLE-FREE] bloque en %p ya estaba libre\n", (void *)hdr);
        return;
    }

    /* Marcar como libre */
    hdr->flags &= ~FLAG_IN_USE;

    /* Escribir el footer */
    block_footer_t *ftr = footer_of(hdr);
    ftr->size = hdr->size;

    /* Coalescing con el bloque siguiente */
    block_header_t *next_hdr = header_after(hdr, h);
    if (next_hdr != NULL && block_is_valid(next_hdr) && !(next_hdr->flags & FLAG_IN_USE)) {
        size_t merged = hdr->size + FOOTER_SIZE + HEADER_SIZE + next_hdr->size;
        hdr->size = merged;
        remove_from_free_list(h, next_hdr);
        ftr = footer_of(hdr);
        ftr->size = hdr->size;
    }

    /* Coalescing con el bloque anterior */
    block_header_t *prev_hdr = header_before(hdr, h);
    if (prev_hdr != NULL && block_is_valid(prev_hdr) && !(prev_hdr->flags & FLAG_IN_USE)) {
        size_t merged = prev_hdr->size + FOOTER_SIZE + HEADER_SIZE + hdr->size;
        prev_hdr->size = merged;
        remove_from_free_list(h, prev_hdr);
        ftr = footer_of(prev_hdr);
        ftr->size = prev_hdr->size;
        hdr = prev_hdr;
    }

    /* Insertar bloque (fusionado o no) en la free list */
    insert_to_free_list(h, hdr);
}

void *heap_alloc(heap_t *h, size_t size) {
    if (h->start == NULL) return NULL;
    if (size == 0) return NULL;

    size_t aligned_size = align_up(size, ALIGNMENT);
    size_t total_needed = HEADER_SIZE + aligned_size + FOOTER_SIZE;

    /* Fase 1: buscar en la free list (first-fit) */
    block_header_t *prev = NULL;
    block_header_t *curr = h->free_list_head;

    while (curr != NULL) {
        if (curr->magic != BLOCK_MAGIC) {
            fprintf(stderr, "  [CORRUPCION] free list corrupta en %p\n", (void *)curr);
            break;
        }

        size_t curr_total = block_total(curr);
        if (curr_total >= total_needed) {
            /* Encontrado: sacar de la free list */
            if (prev == NULL) {
                h->free_list_head = free_node_of(curr)->next;
            } else {
                free_node_of(prev)->next = free_node_of(curr)->next;
            }

            /* SPLITTING */
            size_t remaining = curr_total - total_needed;

            if (remaining >= MIN_BLOCK_SIZE) {
                block_header_t *new_hdr = (block_header_t *)((char *)curr + total_needed);
                new_hdr->size = remaining - HEADER_SIZE - FOOTER_SIZE;
                new_hdr->flags = 0;
                new_hdr->magic = BLOCK_MAGIC;

                block_footer_t *new_ftr = footer_of(new_hdr);
                new_ftr->size = new_hdr->size;

                insert_to_free_list(h, new_hdr);

                curr->size = aligned_size;
            }
            curr->flags = FLAG_IN_USE;
            block_footer_t *ftr = footer_of(curr);
            ftr->size = curr->size;

            return payload_of(curr);
        }
        prev = curr;
        curr = free_node_of(curr)->next;
    }

    /* Fase 2: fallback al bump allocator */
    if (h->used + total_needed > h->capacity) {
        size_t grow = total_needed;
        if (grow < h->capacity) grow = h->capacity;

        void *result = sbrk((intptr_t)grow);
        if (result == (void *)-1) return NULL;

        h->capacity += grow;
        h->brk = (char *)h->start + h->capacity;
    }

    block_header_t *hdr = (block_header_t *)((char *)h->start + h->used);
    hdr->size = aligned_size;
    hdr->flags = FLAG_IN_USE;
    hdr->magic = BLOCK_MAGIC;

    block_footer_t *ftr = footer_of(hdr);
    ftr->size = aligned_size;

    h->used += total_needed;
    return payload_of(hdr);
}

void heap_walk(const heap_t *h, void (*cb)(block_header_t *, void *, int, void *),
               void *user_data) {
    if (h->start == NULL) return;

    size_t offset = 0;
    int index = 0;

    while (offset + HEADER_SIZE <= h->used) {
        block_header_t *hdr = (block_header_t *)((char *)h->start + offset);

        if (hdr->magic != BLOCK_MAGIC) {
            fprintf(stderr, "  [CORRUPCION] bloque %d en offset %zu\n", index, offset);
            break;
        }

        void *payload = payload_of(hdr);
        cb(hdr, payload, index, user_data);

        offset += block_total(hdr);
        index++;
    }
}

#define BOX_W 62

static void box_row(const char *text) {
    int len = (int)strlen(text);
    int pad = BOX_W - len;
    if (pad < 0) pad = 0;
    printf("  ║ %s", text);
    for (int i = 0; i < pad; i++) putchar(' ');
    printf(" ║\n");
}

static void box_top(void) {
    printf("  ╔");
    for (int i = 0; i < BOX_W + 2; i++) printf("═");
    printf("╗\n");
}

static void box_mid(void) {
    printf("  ╠");
    for (int i = 0; i < BOX_W + 2; i++) printf("═");
    printf("╣\n");
}

static void box_bot(void) {
    printf("  ╚");
    for (int i = 0; i < BOX_W + 2; i++) printf("═");
    printf("╝\n");
}

/* Callback para imprimir cada bloque en el dump */
static void dump_block_cb(block_header_t *hdr, void *payload, int index, void *user_data) {
    const heap_t *h = (const heap_t *)user_data;
    size_t offset = (size_t)((char *)hdr - (char *)h->start);
    int in_use = hdr->flags & FLAG_IN_USE;
    block_footer_t *ftr = footer_of(hdr);

    char buf[128];
    const char *ftr_ok = (ftr->size == hdr->size) ? "ok" : "!!";

    snprintf(buf, sizeof(buf), " Blk %d: off=%-4zu pay=%-4zu [%s] ftr=%s", index, offset, hdr->size,
             in_use ? "IN_USE" : "FREE  ", ftr_ok);
    box_row(buf);
    (void)payload;
}

void heap_dump(const heap_t *h) {
    if (h->start == NULL) {
        printf("  [heap no inicializado]\n");
        return;
    }

    /* --- Contabilidad --- */
    size_t block_count = 0;
    size_t used_blocks = 0;
    size_t free_blocks = 0;
    size_t used_payload = 0;
    size_t free_payload = 0;
    size_t meta_bytes = 0; /* headers + footers */
    size_t largest_free = 0;

    {
        size_t off = 0;
        while (off + HEADER_SIZE <= h->used) {
            block_header_t *hdr = (block_header_t *)((char *)h->start + off);
            if (hdr->magic != BLOCK_MAGIC) break;

            meta_bytes += HEADER_SIZE + FOOTER_SIZE;
            block_count++;

            if (hdr->flags & FLAG_IN_USE) {
                used_blocks++;
                used_payload += hdr->size;
            } else {
                free_blocks++;
                free_payload += hdr->size;
                if (hdr->size > largest_free) largest_free = hdr->size;
            }
            off += block_total(hdr);
        }
    }

    size_t wilderness = h->capacity - h->used;
    double pct = h->capacity > 0 ? (double)h->used / (double)h->capacity * 100.0 : 0.0;

    char buf[128];

    printf("\n");
    box_top();
    box_row("      HEAP DUMP -- Post 4 (Coalescing & Splitting)");
    box_mid();

    snprintf(buf, sizeof(buf), "Heap base:     %p", h->start);
    box_row(buf);
    snprintf(buf, sizeof(buf), "Capacity:      %zu bytes", h->capacity);
    box_row(buf);
    snprintf(buf, sizeof(buf), "Used region:   %zu bytes (%5.1f%%)", h->used, pct);
    box_row(buf);
    snprintf(buf, sizeof(buf), "Wilderness:    %zu bytes", wilderness);
    box_row(buf);

    box_mid();

    snprintf(buf, sizeof(buf), "Bloques: %-3zu  (ocupados: %zu, libres: %zu)", block_count,
             used_blocks, free_blocks);
    box_row(buf);
    snprintf(buf, sizeof(buf), "Payload usado:  %-6zu B   Payload libre: %-6zu B", used_payload,
             free_payload);
    box_row(buf);
    snprintf(buf, sizeof(buf), "Metadata (hdr+ftr): %-5zu B   Mayor libre: %-5zu B", meta_bytes,
             largest_free);
    box_row(buf);

    /* --- Bloques individuales --- */
    box_mid();
    heap_walk(h, dump_block_cb, (void *)h);

    /* --- Barra visual --- */
    box_mid();

    const int BAR = 50;
    char bar_buf[128];
    int pos = 0;
    bar_buf[pos++] = '[';
    {
        size_t off = 0;
        int chars_printed = 0;
        while (off + HEADER_SIZE <= h->used && chars_printed < BAR) {
            block_header_t *hdr = (block_header_t *)((char *)h->start + off);
            if (hdr->magic != BLOCK_MAGIC) break;

            size_t bt = block_total(hdr);
            int bchars = (int)((double)bt / (double)h->capacity * BAR);
            if (bchars < 1) bchars = 1;
            if (chars_printed + bchars > BAR) bchars = BAR - chars_printed;

            char ch = (hdr->flags & FLAG_IN_USE) ? '=' : '.';
            for (int i = 0; i < bchars; i++) bar_buf[pos++] = ch;
            chars_printed += bchars;
            off += bt;
        }
        for (int i = chars_printed; i < BAR; i++) bar_buf[pos++] = '-';
    }
    bar_buf[pos++] = ']';
    bar_buf[pos] = '\0';
    box_row(bar_buf);
    box_row("= ocupado   . libre   - wilderness");

    /* --- Free list chain --- */
    box_mid();

    if (h->free_list_head == NULL) {
        box_row("Free list: (vacia)");
    } else {
        box_row("Free list:");
        block_header_t *fl = h->free_list_head;
        int fi = 0;
        while (fl != NULL && fi < 20) {
            size_t fl_off = (size_t)((char *)fl - (char *)h->start);
            snprintf(buf, sizeof(buf), "  [%d] offset=%-5zu  size=%-5zu  -> %s", fi, fl_off,
                     fl->size, free_node_of(fl)->next ? "next" : "NULL");
            box_row(buf);
            fl = free_node_of(fl)->next;
            fi++;
        }
    }

    box_bot();
    printf("\n");
}

int main(void) {
    printf("=== Post 4: Coalescing & Splitting ===\n\n");
    printf("sizeof(block_header_t) = %zu\n", sizeof(block_header_t));
    printf("sizeof(block_footer_t) = %zu\n", sizeof(block_footer_t));
    printf("HEADER_SIZE (aligned)  = %zu\n", (size_t)HEADER_SIZE);
    printf("FOOTER_SIZE (aligned)  = %zu\n", (size_t)FOOTER_SIZE);
    printf("MIN_BLOCK_SIZE         = %zu\n", (size_t)MIN_BLOCK_SIZE);
    printf("ALIGNMENT              = %d\n\n", ALIGNMENT);

    heap_t h = heap_init(4096);
    if (h.start == NULL) {
        fprintf(stderr, "heap_init fallo\n");
        return 1;
    }

    /* ── Paso 1: tres allocaciones ──────────────────────── */
    void *a = heap_alloc(&h, 40);
    void *b = heap_alloc(&h, 128);
    void *c = heap_alloc(&h, 64);

    printf("=== Paso 1: Tras alloc(a=40, b=128, c=64) ===\n");
    heap_dump(&h);

    /* ── Paso 2: liberar B ─────────────────────────────── */
    heap_free(&h, b);
    printf("=== Paso 2: Tras free(b) ===\n");
    printf("  B queda libre entre A (usado) y C (usado).\n");
    printf("  No hay vecinos libres: sin coalescencia.\n");
    heap_dump(&h);

    /* ── Paso 3: liberar C → coalescencia con B ────────── */
    heap_free(&h, c);
    printf("=== Paso 3: Tras free(c) -- COALESCENCIA con B ===\n");
    printf("  C era adyacente a B (libre). Se fusionan en un\n");
    printf("  unico bloque libre.\n");
    heap_dump(&h);

    /* ── Paso 4: alloc(50) → splitting del bloque B+C ─── */
    void *d = heap_alloc(&h, 50);
    printf("=== Paso 4: Tras alloc(d=50) -- SPLITTING ===\n");
    printf("  El bloque fusionado B+C es mas grande que 50.\n");
    printf("  Se divide: 50 bytes para D, el resto queda libre.\n");
    heap_dump(&h);

    /* ── Paso 5: alloc(100) → usa el remanente ─────────── */
    void *e = heap_alloc(&h, 100);
    printf("=== Paso 5: Tras alloc(e=100) ===\n");
    printf("  Usa el remanente del split o pide al bump.\n");
    heap_dump(&h);

    /* ── Paso 6: free(a) → standalone, sin vecinos ─────── */
    heap_free(&h, a);
    printf("=== Paso 6: Tras free(a) -- STANDALONE ===\n");
    printf("  A no tiene vecinos libres. Queda solo en la\n");
    printf("  free list.\n");
    heap_dump(&h);

    /* ── Paso 7: free(d) → posible coalescencia con A ─── */
    heap_free(&h, d);
    printf("=== Paso 7: Tras free(d) -- COALESCENCIA con A ===\n");
    printf("  D es adyacente a A (libre). Se fusionan.\n");
    heap_dump(&h);

    /* ── Paso 8: free(e) → coalescencia triple ─────────── */
    heap_free(&h, e);
    printf("=== Paso 8: Tras free(e) -- COALESCENCIA TOTAL ===\n");
    printf("  E es adyacente al bloque A+D (libre) y al\n");
    printf("  remanente (libre). Fusion de los tres.\n");
    heap_dump(&h);

    /* Suprimir warnings de variables no usadas */
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    (void)e;

    return 0;
}
