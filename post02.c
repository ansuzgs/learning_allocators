#define _DEFAULT_SOURCE

/*
 * post02.c - Block Headers & Metadata Tax (Serie: Memory Allocation & GC en C)
 *
 * Evolucion del bump allocator del Post 1. Ahora cada allocacion
 * lleva un header con tamaño, flags y un magic number. Todos los
 * payloads se alinean a 16 bytes.
 *
 * Compilar: gcc -Wall -Wextra -std=c99 -g post02.c -o post02
 * Ejecutar: ./post02
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

/* ───────────────────────────────────────────────────────────
 * Constantes
 * ─────────────────────────────────────────────────────────── */
#define ALIGNMENT 16 /* Alineacion de payload (bytes) */
#define BLOCK_MAGIC 0xDEADBEEF /* deteccion de corrupcion */
#define FLAG_IN_USE 0x1 /* bit 0: bloque en uso */

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
	size_t size; /* payload size (aligned) */
	uint32_t flags; /* bit 0: in_use. bits 1-7: reservados */
	uint32_t magic; /* 0xDEADBEEF, deteccion de corrupcion */
} block_header_t;

/*
 * heap_t: identica a Post 1.
 */
typedef struct {
    void  *start;
    void  *brk;
    size_t capacity;
    size_t used;
} heap_t;

/*
 * align_up: redondea 'n' al siguiente multiplo de 'align'.
 *
 * Truco clasico con bitmask: (n + align - 1) & ~(align - 1).
 * Requiere que 'align' sea potencia de 2.
 */
static inline size_t align_up(size_t n, size_t align) {
	return (n + align - 1) & ~(align - 1);
}

/*
 * HEADER_SIZE: tamaño del header alineado a ALIGNMENT.
 *
 * sizeof(block_header_t) = 16 en x86-64 (8 + 4 + 4)-
 * Con ALIGNMENT=16, HEADER_SIZE = 16. Si cambiamos la struct
 * o el alignment, esta macro se dapta automaticamente
 */
#define HEADER_SIZE (align_up(sizeof(block_header_t), ALIGNMENT))

/*
 * heap_init: igual que Post 1.
 */
heap_t heap_init(size_t initial_size)
{
    heap_t h;

    h.start = sbrk(0);
    if (h.start == (void *)-1) {
        h.start = NULL;  h.brk = NULL;
        h.capacity = 0;  h.used = 0;
        return h;
    }

    void *result = sbrk((intptr_t)initial_size);
    if (result == (void *)-1) {
        h.start = NULL;  h.brk = NULL;
        h.capacity = 0;  h.used = 0;
        return h;
    }

    h.brk      = (char *)h.start + initial_size;
    h.capacity = initial_size;
    h.used     = 0;
    return h;
}

/*
 * heap_alloc: asigna 'size' bytes con header y alineacion
 *
 * Layout de cada bloque:
 *   [HEADER_SIZE bytes: block_header_t][payload: aligned_size bytes]
 *
 * Retorna un puntero al payload, no al header
 */
void *heap_alloc(heap_t *h, size_t size) {
	if (h->start == NULL) return NULL;
	if (size == 0) return NULL;

	size_t aligned_size = align_up(size, ALIGNMENT);
	size_t total = HEADER_SIZE + aligned_size;

	/* ¿Cabe en la capacidad actual? */
	if (h->used + total > h->capacity) {
		size_t grow = total;
		if (grow < h->capacity) {
			grow = h->capacity;
		}

		void *result = sbrk((intptr_t)grow);
		if (result == (void *)-1) return NULL;

		h->capacity += grow;
		h->brk = (char *)h->start + h->capacity;
	}

	/* Escribir el header */
	block_header_t *hdr = (block_header_t *)((char *)h->start + h->used);
	hdr->size = aligned_size;
	hdr->flags = FLAG_IN_USE;
	hdr->magic = BLOCK_MAGIC;

	/* El payload empieza justo detras del header alineado */
	void *payload = (char *)hdr + HEADER_SIZE;
	h->used += total;
	return payload;
}

/*
 * header_from_payload: recupera el header desde un puntero
 * de usuario. Verifica el magic number.
 *
 * Retorna NULL si el magic no coincide (corrupcion probable)
 */
block_header_t *header_from_payload(void *ptr) {
	if (ptr == NULL) return NULL;

	block_header_t *hdr = (block_header_t *)((char *)ptr - HEADER_SIZE);
	if (hdr->magic != BLOCK_MAGIC) {
		fprintf(stderr, "  [CORRUPCION] magic esperado 0x%X, encontrado 0x%X, en %p", BLOCK_MAGIC, hdr->magic, (void *)hdr);
		return NULL;
	}
	return hdr;
}

/*
 * heap_walk: recorre todos los bloques del heap, invocando
 * 'callback' para cada uno.
 *
 * Parametros del callback:
 *   - block_header_t *hdr: el header del bloque actual.
 *   - void *payload: puntero al payload.
 *   - int index: numero de bloque (empezando en 0).
 *   - void *user_data: dato opaco del llamante.
 */
void heap_walk(const heap_t *h,
				void (*callback)(block_header_t *hdr, void *payload, int index, void *user_data),
				void *user_data) {
	if (h->start == NULL) return;

	size_t offset = 0;
	int index = 0;

	while (offset + HEADER_SIZE <= h->used) {
		block_header_t *hdr = (block_header_t *)((char *)h->start + offset);

		/* Verificar magic number antes de confiar en size */
		if (hdr->magic != BLOCK_MAGIC) {
			fprintf(stderr, "  [CORRUPCION] bloque %d en offset %zu: magic 0x%X != 0x%X\n", index, offset, hdr->magic, BLOCK_MAGIC);
			break;
		}

		void *payload = (char *)hdr + HEADER_SIZE;
		callback(hdr, payload, index, user_data);

		offset += HEADER_SIZE + hdr->size;
		index++;
	}
}

/*
 * heap_dump: visualizacion mejorada con desglose per-bloque.
 */

/* Callback interno para heap_dump: imprime info de cada bloque */
static void dump_block_cb(block_header_t *hdr, void *payload, int index, void *user_data) {
    char buf[128];
    const heap_t *h = (const heap_t *)user_data;
    size_t offset = (size_t)((char *)hdr - (char *)h->start);

    snprintf(buf, sizeof(buf), "Bloque %d: offset=%-5zu hdr=%-2zu payload=%-5zu flags=0x%02X [%s]",
             index,
             offset,
             (size_t)HEADER_SIZE,
             hdr->size,
             hdr->flags,
             (hdr->flags & FLAG_IN_USE) ? "IN_USE" : "FREE  ");

    printf("  ║ %-66s ║\n", buf);
    (void)payload;
}

void heap_dump(const heap_t *h)
{
    if (h->start == NULL) {
        printf("  [heap no inicializado]\n");
        return;
    }

    double pct_used = h->capacity > 0 ? (double)h->used / (double)h->capacity * 100.0 : 0.0;
    size_t free_bytes = h->capacity - h->used;

    /* Contabilidad de overhead */
    size_t total_header_bytes = 0;
    size_t total_payload_bytes = 0;
    size_t block_count = 0;
    {
        size_t off = 0;
        while (off + HEADER_SIZE <= h->used) {
            block_header_t *hdr = (block_header_t *)((char *)h->start + off);
            if (hdr->magic != BLOCK_MAGIC) break;
            total_header_bytes += HEADER_SIZE;
            total_payload_bytes += hdr->size;
            block_count++;
            off += HEADER_SIZE + hdr->size;
        }
    }
    double overhead_pct = (total_header_bytes + total_payload_bytes) > 0
        ? (double)total_header_bytes / (double)(total_header_bytes + total_payload_bytes) * 100.0
        : 0.0;

    // --- GEOMETRÍA CORREGIDA ---
    const int CONTENT_WIDTH = 66; // Tamaño del string interno
    const int BOX_WIDTH     = 68; // CONTENT_WIDTH + 2 (por los márgenes derecho e izquierdo)
    const int BAR_WIDTH     = 50;

    int used_bar = h->capacity > 0 ? (int)((double)h->used / (double)h->capacity * BAR_WIDTH) : 0;
    int free_bar = BAR_WIDTH - used_bar;

    char buf[128];

    printf("\n");
    printf("  ╔"); for (int i = 0; i < BOX_WIDTH; i++) printf("═"); printf("╗\n");

    snprintf(buf, sizeof(buf), "         HEAP DUMP — Post 2 (Block Headers)  ");
    printf("  ║ %-68s ║\n", buf);
    printf("  ╠"); for (int i = 0; i < BOX_WIDTH; i++) printf("═"); printf("╣\n");

    snprintf(buf, sizeof(buf), "Heap base:      %p", h->start);
    printf("  ║ %-66s ║\n", buf);

    snprintf(buf, sizeof(buf), "Current break:  %p", h->brk);
    printf("  ║ %-66s ║\n", buf);

    snprintf(buf, sizeof(buf), "Capacity:       %zu bytes", h->capacity);
    printf("  ║ %-66s ║\n", buf);

    snprintf(buf, sizeof(buf), "Used:           %zu bytes (%5.1f%%)", h->used, pct_used);
    printf("  ║ %-66s ║\n", buf);

    snprintf(buf, sizeof(buf), "Free:           %zu bytes (%5.1f%%)", free_bytes, 100.0 - pct_used);
    printf("  ║ %-66s ║\n", buf);

    printf("  ╠"); for (int i = 0; i < BOX_WIDTH; i++) printf("═"); printf("╣\n");

    snprintf(buf, sizeof(buf), "Bloques: %-3zu   Header: %-4zu B   Payload: %-5zu B",
             block_count, total_header_bytes, total_payload_bytes);
    printf("  ║ %-66s ║\n", buf);

    snprintf(buf, sizeof(buf), "Metadata overhead: %5.1f%%", overhead_pct);
    printf("  ║ %-66s ║\n", buf);

    printf("  ╠"); for (int i = 0; i < BOX_WIDTH; i++) printf("═"); printf("╣\n");

    heap_walk(h, dump_block_cb, (void *)h);

    printf("  ╠"); for (int i = 0; i < BOX_WIDTH; i++) printf("═"); printf("╣\n");

    // --- SECCIÓN DE LA BARRA ---
    // Imprimimos el '[' inicial, los 50 bloques, el ']' final y los 14 espacios restantes
    // Total: 1 + 50 + 1 + 14 = 66 caracteres exactos.
    printf("  ║ [");
    for (int i = 0; i < used_bar; i++) printf("█");
    for (int i = 0; i < free_bar; i++) printf("░");
    printf("]");
    for (int i = 0; i < 14; i++) printf(" ");
    printf(" ║\n");

    // --- TRACK DE PUNTEROS DIGITAL (Con Anti-Colisión) ---
    char ptr_line[128];
    memset(ptr_line, ' ', CONTENT_WIDTH);
    ptr_line[CONTENT_WIDTH] = '\0';

    int base_pos = 0;
    int brk_pos  = BAR_WIDTH + 1; // Índice 51 (justo debajo del ']')
    int used_pos = used_bar;      // Justo donde termina la zona usada

    // Lógica anti-colisión: Si ^used se acerca demasiado a ^base o a ^brk, lo desplazamos
    if (used_pos < base_pos + 6) used_pos = base_pos + 6;
    if (used_pos > brk_pos - 6)  used_pos = brk_pos - 6;

    memcpy(&ptr_line[base_pos], "^base", 5);
    memcpy(&ptr_line[used_pos], "^used", 5);
    memcpy(&ptr_line[brk_pos],  "^brk",  4);

    printf("  ║ %s ║\n", ptr_line);

    printf("  ╚"); for (int i = 0; i < BOX_WIDTH; i++) printf("═"); printf("╝\n");
    printf("\n");
}

/* Callback para Ejemplo 3: imprime cada bloque durante heap-walk */
static void walk_print_cb(block_header_t *hdr, void *payload, int index, void *user_data) {
	(void)user_data;
	printf("    [%d] payload=%p  size=%-5zu  flags=0x%02X  magic=0x%X\n",
		   index, payload, hdr->size, hdr->flags, hdr->magic);
}

int main(void) {
	printf("sizeof(block_header_t) = %zu\n", sizeof(block_header_t));
	printf("HEADER_SIZE (aligned)  = %zu\n", (size_t)HEADER_SIZE);
	printf("ALIGNMENT              = %zu\n", (size_t)ALIGNMENT);

	/* -- Ejemplo 1: Alineacion visible ---------- */
	printf("=== Ejemplo 1: Alineacion visible ===\n");
	printf("  Pedimos 3, 7 y 5 bytes, todos se alinean a %d\n\n", ALIGNMENT);
	{
		heap_t h = heap_init(1024);
		if (h.start == NULL) {
			fprintf(stderr, "heap_init fallo\n");
			return 1;
		}

		char *a = heap_alloc(&h, 3);
		char *b = heap_alloc(&h, 7);
		char *c = heap_alloc(&h, 5);

		/* Escribir en los payloads para demostrar que funcionan */
		strcpy(a, "Hi");
		strcpy(b, "World!");
		strcpy(c, "OK");

		heap_dump(&h);

		printf("  a = \"%s\" (pedia 3, payload alineado a %zu)\n",
               a, header_from_payload(a)->size);
        printf("  b = \"%s\" (pedia 7, payload alineado a %zu)\n",
               b, header_from_payload(b)->size);
        printf("  c = \"%s\" (pedia 5, payload alineado a %zu)\n\n",
               c, header_from_payload(c)->size);

        /* Offsets: cada bloque = HEADER_SIZE + 16 = 32 bytes */
        printf("  Offset a: %zu\n", (size_t)((char *)a - (char *)h.start));
        printf("  Offset b: %zu\n", (size_t)((char *)b - (char *)h.start));
        printf("  Offset c: %zu\n\n", (size_t)((char *)c - (char *)h.start));
    }


	/* -- Ejemplo 2: Metadata overhead ---------- */
	printf("=== Ejemplo 2: Metadata overhead ===\n");
	printf("  Alocaciones pequeñas: el header pesa proporcionalmente mas.\n\n");
	{
		heap_t h = heap_init(1024);
		if (h.start == NULL) {
			fprintf(stderr, "heap_init fallo\n");
			return 1;
		}

		heap_alloc(&h, 8); /* payload: 16 (alineado), header: 16 -> 50% */
		heap_alloc(&h, 12); /* payload: 16 (alineado), header: 16 -> 50% */
		heap_alloc(&h, 16); /* payload: 16 (exacto), header: 16 -> 50% */
		heap_alloc(&h, 64); /* payload: 64 (exacto), header: 16 -> 20% */
		heap_alloc(&h, 256); /* payload: 256 (exacto), header: 16 -> 5.9% */

		heap_dump(&h);
	}

	printf("=== Ejemplo 3: Recorrer el heap con heap_walk() ===\n");
	{
		heap_t h = heap_init(1024);
		if (h.start == NULL) {
			fprintf(stderr, "head_init fallo\n");
			return 1;
		}

		int *nums = heap_alloc(&h, sizeof(int) * 10); /* 40 → 48 aligned */
		char *msg = heap_alloc(&h, 100);
		void *tiny = heap_alloc(&h, 1);

		for (int i = 0; i < 10; i++) nums[i] = i*i;
		strcpy(msg, "Caminando el heap bloque a bloque");
		*(char *)tiny = 'X';

		printf("  heap_walk() reporta:\n");
		heap_walk(&h, walk_print_cb, NULL);
		printf("\n");

		/* Demostrar header_from_payload */
		block_header_t *h2 = header_from_payload(nums);
		if (h2) {
			printf("  header_from_payload(nums): size=%zu, flags=0x%X, magic=0x%X\n",
                   h2->size, h2->flags, h2->magic);
		}

		block_header_t *h3 = header_from_payload(msg);
		if (h3) {
			printf("  header_from_payload(msg):  size=%zu, flags=0x%X, magic=0x%X\n",
                   h3->size, h3->flags, h3->magic);
        }

        printf("\n");
        heap_dump(&h);
	}
	return 0;
}

