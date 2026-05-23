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

    /* Insertar al inicio de la free list (O(1)) */
    free_block_t *node = free_node_of(hdr);
    node->next = h->free_list_head;
    h->free_list_head = hdr;
}

void *heap_alloc(heap_t *h, size_t size) {
    if (h->start == NULL) return NULL;
    if (size == 0) return NULL;

    size_t aligned_size = align_up(size, ALIGNMENT);

    /* Fase 1: buscar en la free list (first-fit) */
    block_header_t *prev = NULL;
    block_header_t *curr = h->free_list_head;

    while (curr != NULL) {
        if (curr->magic != BLOCK_MAGIC) {
            fprintf(stderr, "  [CORRUPCION] free list corrupta en %p\n", (void *)curr);
            break;
        }

        if (curr->size >= aligned_size) {
            /* Encontrado: sacar de la free list */
            free_block_t *node = free_node_of(curr);

            if (prev == NULL) {
                h->free_list_head = node->next;
            } else {
                free_node_of(prev)->next = node->next;
            }

            curr->flags |= FLAG_IN_USE;
            return payload_of(curr);
        }

        prev = curr;
        curr = free_node_of(curr)->next;
    }

    /* Fase 2: fallback al bump allocator */
    size_t total = HEADER_SIZE + aligned_size;

    if (h->used + total > h->capacity) {
        size_t grow = total;
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

    h->used += total;
    return payload_of(hdr);
}

void heap_walk(const heap_t *h,
               void (*callback)(block_header_t *hdr, void *payload, int index, void *user_data),
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
        callback(hdr, payload, index, user_data);

        offset += HEADER_SIZE + hdr->size;
        index++;
    }
}
/* Ancho interno de la caja en columnas visibles */
#define BOX_W 62

/* Imprime una fila: "  ║ " + contenido paddeado a BOX_W + " ║" */
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

    char buf[128];
    snprintf(buf, sizeof(buf), " Bloque %d: offset=%-5zu  payload=%-5zu  [%s]", index, offset,
             hdr->size, in_use ? "IN_USE" : "FREE  ");
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
    size_t header_bytes = 0;
    size_t largest_free = 0;
    size_t smallest_free = (size_t)-1;

    {
        size_t off = 0;
        while (off + HEADER_SIZE <= h->used) {
            block_header_t *hdr = (block_header_t *)((char *)h->start + off);
            if (hdr->magic != BLOCK_MAGIC) break;

            header_bytes += HEADER_SIZE;
            block_count++;

            if (hdr->flags & FLAG_IN_USE) {
                used_blocks++;
                used_payload += hdr->size;
            } else {
                free_blocks++;
                free_payload += hdr->size;
                if (hdr->size > largest_free) largest_free = hdr->size;
                if (hdr->size < smallest_free) smallest_free = hdr->size;
            }
            off += HEADER_SIZE + hdr->size;
        }
    }
    if (free_blocks == 0) smallest_free = 0;

    size_t wilderness = h->capacity - h->used;
    double pct_used = h->capacity > 0 ? (double)h->used / (double)h->capacity * 100.0 : 0.0;

    char buf[128];

    printf("\n");
    box_top();

    /* Titulo: usa -- en vez de — para mantener pure-ASCII */
    box_row("      HEAP DUMP -- Post 3 (Free List)");

    box_mid();

    snprintf(buf, sizeof(buf), "Heap base:     %p", h->start);
    box_row(buf);
    snprintf(buf, sizeof(buf), "Current break: %p", h->brk);
    box_row(buf);
    snprintf(buf, sizeof(buf), "Capacity:      %zu bytes", h->capacity);
    box_row(buf);
    snprintf(buf, sizeof(buf), "Used region:   %zu bytes (%5.1f%%)", h->used, pct_used);
    box_row(buf);
    snprintf(buf, sizeof(buf), "Wilderness:    %zu bytes", wilderness);
    box_row(buf);

    box_mid();

    snprintf(buf, sizeof(buf), "Bloques: %-3zu  (ocupados: %zu, libres: %zu)", block_count,
             used_blocks, free_blocks);
    box_row(buf);

    snprintf(buf, sizeof(buf), "Payload ocupado: %-6zu B   Payload libre: %-6zu B", used_payload,
             free_payload);
    box_row(buf);

    snprintf(buf, sizeof(buf), "Header overhead: %-6zu B   (%5.1f%%)", header_bytes,
             (header_bytes + used_payload + free_payload) > 0
                 ? (double)header_bytes / (double)(header_bytes + used_payload + free_payload) *
                       100.0
                 : 0.0);
    box_row(buf);

    if (free_blocks > 0) {
        snprintf(buf, sizeof(buf), "Fragmentos libres: %zu  (mayor: %zu B, menor: %zu B)",
                 free_blocks, largest_free, smallest_free);
        box_row(buf);
    }

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

            size_t block_total = HEADER_SIZE + hdr->size;
            int block_chars = (int)((double)block_total / (double)h->capacity * BAR);
            if (block_chars < 1) block_chars = 1;
            if (chars_printed + block_chars > BAR) block_chars = BAR - chars_printed;

            char ch = (hdr->flags & FLAG_IN_USE) ? '=' : '.';
            for (int i = 0; i < block_chars; i++) bar_buf[pos++] = ch;
            chars_printed += block_chars;
            off += block_total;
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
    printf("sizeof(block_header_t) = %zu\n", sizeof(block_header_t));
    printf("sizeof(free_block_t)   = %zu\n", sizeof(free_block_t));
    printf("HEADER_SIZE (aligned)  = %zu\n", (size_t)HEADER_SIZE);
    printf("ALIGNMENT              = %d\n\n", ALIGNMENT);

    /* ── Ejemplo 1: Alloc + Free simple ────────────────── */
    printf("=== Ejemplo 1: Alloc + Free simple ===\n");
    printf("  Allocamos 64 bytes, liberamos, vemos el bloque"
           " en la free list.\n\n");
    {
        heap_t h = heap_init(1024);
        if (h.start == NULL) {
            fprintf(stderr, "heap_init fallo\n");
            return 1;
        }

        char *p = heap_alloc(&h, 64);
        strcpy(p, "Este bloque sera liberado pronto");

        printf("  Antes de free:\n");
        heap_dump(&h);

        heap_free(&h, p);

        printf("  Despues de free:\n");
        heap_dump(&h);
    }

    /* -- Ejemplo 2: Fragmentacion visible ------------ */
    printf("=== Ejemplo 2: Fragmentacion visible ===\n");
    printf("  Tres allocaciones, liberamos la del medio y la primera.\n\n");
    {
        heap_t h = heap_init(1024);
        if (h.start == NULL) {
            fprintf(stderr, "heap_init fallo\n");
            return 1;
        }

        void *a = heap_alloc(&h, 50);
        void *b = heap_alloc(&h, 100);
        void *c = heap_alloc(&h, 50);

        printf("  Tres bloques allocados:\n");
        heap_dump(&h);

        heap_free(&h, b);
        printf("  Tras liberar B (100 bytes):\n");
        heap_dump(&h);

        heap_free(&h, a);
        printf("  Tras liberar A (50 bytes):\n");
        heap_dump(&h);

        (void)c;
    }

    /* -- Ejemplo 3: Reutilizacion de la free list -------- */
    printf("=== Ejemplo 3: Reutilizacion de bloques libres ===\n");
    printf("  Liberamos un bloque de 128B, luego allocamos 40B: first-fit lo reutiliza.\n\n");
    {
        heap_t h = heap_init(1024);
        if (h.start == NULL) {
            fprintf(stderr, "heap_init fallo\n");
            return 1;
        }

        void *a = heap_alloc(&h, 128);
        void *b = heap_alloc(&h, 64);
        (void)b;

        printf("  Dos bloques allocados (128 + 64):\n");
        heap_dump(&h);

        heap_free(&h, a);
        printf("  Tras liberar A (128B) -- bloque en free list:\n");
        heap_dump(&h);

        void *c = heap_alloc(&h, 40);
        printf("  Tras allocar 40B -- reutiliza el bloque de 128B (sin splitting):\n");
        heap_dump(&h);

        printf("  Direccion original de A: %p\n", a);
        printf("  Direccion de C (reuso): %p\n", c);
        printf("  %s\n\n", a == c ? ">> REUTILIZADO (misma direccion)" : ">> No reutilizado");
    }

    /* -- Ejemplo 4: Deteccion de double-free ---------- */
    printf("=== Ejemplo 4: Deteccion de double-free ===\n");
    printf("  Intentamos liberar el mismo puntero dos veces.\n\n");
    {
        heap_t h = heap_init(1024);
        if (h.start == NULL) {
            fprintf(stderr, "heap_init fallo\n");
            return 1;
        }

        void *p = heap_alloc(&h, 48);

        printf("  Primera liberacion (OK):\n");
        heap_free(&h, p);
        heap_dump(&h);

        printf("  Segunda liberacion (debe detectar double-free):\n");
        heap_free(&h, p);
        printf("\n");
    }

    return 0;
}
