#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct {
	void *start; /* direccion base de la refion sbrk'd */
	void *brk; /* program break actual (start + capacity) */
	size_t capacity; /* bytes totales pedidos al OS */
	size_t used; /* bytes asignados (offset del bump pointer) */
} heap_t;


heap_t heap_init(size_t initial_size) {
	heap_t h;

	h.start = sbrk(0);
	if (h.start == (void *)-1) {
		h.start = NULL;
		h.brk = NULL;
		h.capacity = 0;
		h.used = 0;
		return h;
	}

	void *result = sbrk((intptr_t)initial_size);
	if (result == (void *)-1) {
		h.start = NULL;
		h.brk = NULL;
		h.capacity = 0;
		h.used = 0;
		return h;
	}

	h.brk = (char *)h.start + initial_size;
	h.capacity = initial_size;
	h.used = 0;

	return h;
}

void *heap_alloc(heap_t *h, size_t size) {
	if (h->start == NULL) return NULL;
	if (size == 0) return NULL;

	if (h->used + size > h->capacity) {
		size_t grow = size;
		if (grow < h->capacity) {
			grow = h->capacity;
		}

	 	void *result = sbrk((intptr_t)grow);
		if (result == (void *)-1) {
			return 0;
		}

		h->capacity += grow;
		h->brk = (char *)h->start + h->capacity;
	}

	void *ptr = (char *)h->start + h->used;
	h->used += size;
	return ptr;
}

void heap_dump(const heap_t *h)
{
    if (h->start == NULL) {
        printf("  [heap no inicializado]\n");
        return;
    }

    double pct_used = (double)h->used / (double)h->capacity * 100.0;
    size_t free_bytes = h->capacity - h->used;

    // --- CONFIGURACIÓN DE GEOMETRÍA FIJA ---
    const int INNER_WIDTH   = 64; // Ancho interno total de la caja
    const int MARGIN        = 2;  // Margen de espacios a los lados del texto
    const int CONTENT_WIDTH = INNER_WIDTH - (MARGIN * 2); // 60 caracteres útiles

    // La barra visual medirá exactamente 44 caracteres limpios de resolución
    // [ (1) + usado (X) + " USED ][" (8) + libre (Y) + " FREE ]" (7) = 16 + 44 = 60
    const int BAR_RESOLUTION = 44;
    int used_bar = (int)((double)h->used / (double)h->capacity * BAR_RESOLUTION);
    int free_bar = BAR_RESOLUTION - used_bar;

    // --- 1. SÁNDWICH DE CABECERA ---
    printf("╔"); for (int i = 0; i < INNER_WIDTH; i++) printf("═"); printf("╗\n");
    printf("║              HEAP DUMP - Post 1 (Bump Allocator)               ║\n");
    printf("╠"); for (int i = 0; i < INNER_WIDTH; i++) printf("═"); printf("╣\n");

    // Buffer auxiliar para calcular tamaños dinámicos
    char buf[128];

    // --- 2. SECCIÓN DE DATOS (Auto-alineados a la derecha con %-*s) ---
    snprintf(buf, sizeof(buf), "Heap base:      %p", h->start);
    printf("║  %-*s  ║\n", CONTENT_WIDTH, buf);

    snprintf(buf, sizeof(buf), "Current break:  %p", h->brk);
    printf("║  %-*s  ║\n", CONTENT_WIDTH, buf);

    snprintf(buf, sizeof(buf), "Capacity:       %zu bytes", h->capacity);
    printf("║  %-*s  ║\n", CONTENT_WIDTH, buf);

    snprintf(buf, sizeof(buf), "Used:           %zu bytes (%.1f%%)", h->used, pct_used);
    printf("║  %-*s  ║\n", CONTENT_WIDTH, buf);

    snprintf(buf, sizeof(buf), "Free:           %zu bytes (%.1f%%)", free_bytes, 100.0 - pct_used);
    printf("║  %-*s  ║\n", CONTENT_WIDTH, buf);

    printf("╠"); for (int i = 0; i < INNER_WIDTH; i++) printf("═"); printf("╣\n");

    // --- 3. FILA DE LA BARRA VISUAL ---
    printf("║  [");
    for (int i = 0; i < used_bar; i++) printf("=");
    printf(" USED ][");
    for (int i = 0; i < free_bar; i++) printf("-");
    printf(" FREE ]  ║\n");

    // --- 4. FILA DE INDICADORES DINÁMICOS (^base y ^brk) ---
    // Cálculo de espaciado: '^base' ocupa 5 caracteres.
    // Los caracteres internos de la barra antes de llegar a '][' son exactos: used_bar + 2
    int trailing_spaces = CONTENT_WIDTH - (used_bar + 11);

    printf("║  ^base");
    for (int i = 0; i < used_bar + 2; i++) printf(" ");
    printf("^brk");
    for (int i = 0; i < trailing_spaces; i++) printf(" ");
    printf("  ║\n");

    // --- 5. CIERRE DE LA CAJA ---
    printf("╚"); for (int i = 0; i < INNER_WIDTH; i++) printf("═"); printf("╝\n");
}

int main(void)
{
    /* ── Ejemplo 1: allocaciones básicas ────────────────── */
    printf("=== Ejemplo 1: Allocaciones basicas ===\n");
    {
        heap_t h = heap_init(1024);
        if (h.start == NULL) {
            fprintf(stderr, "heap_init fallo\n");
            return 1;
        }

        int  *nums = heap_alloc(&h, sizeof(int) * 10);
        char *msg  = heap_alloc(&h, 128);

        for (int i = 0; i < 10; i++)
            nums[i] = i * i;
        strcpy(msg, "Hola desde nuestro heap custom!");

        heap_dump(&h);

        printf("  nums[5] = %d\n", nums[5]);
        printf("  msg     = \"%s\"\n\n", msg);
    }

    /* ── Ejemplo 2: patron mixto de tamanos ────────────── */
    printf("=== Ejemplo 2: Multiples allocaciones (variadas) ===\n");
    {
        heap_t h = heap_init(1024);
        if (h.start == NULL) {
            fprintf(stderr, "heap_init fallo\n");
            return 1;
        }

        void *a = heap_alloc(&h, 16);
        void *b = heap_alloc(&h, 32);
        void *c = heap_alloc(&h, 400);
        void *d = heap_alloc(&h, 50);

        (void)a; (void)b; (void)c; (void)d;

        heap_dump(&h);

        printf("  Bloques: 16 + 32 + 400 + 50 = 498 bytes\n");
        printf("  Offset a: %zu\n",  (size_t)((char *)a - (char *)h.start));
        printf("  Offset b: %zu\n",  (size_t)((char *)b - (char *)h.start));
        printf("  Offset c: %zu\n",  (size_t)((char *)c - (char *)h.start));
        printf("  Offset d: %zu\n\n",(size_t)((char *)d - (char *)h.start));
    }

    /* ── Ejemplo 3: crecimiento automatico ─────────────── */
    printf("=== Ejemplo 3: Crecimiento automatico ===\n");
    {
        heap_t h = heap_init(100);
        if (h.start == NULL) {
            fprintf(stderr, "heap_init fallo\n");
            return 1;
        }

        printf("  Capacidad inicial: %zu bytes\n", h.capacity);

        void *big = heap_alloc(&h, 500);
        if (big == NULL) {
            fprintf(stderr, "  heap_alloc fallo (sbrk rechazo)\n");
        } else {
            printf("  Tras allocar 500 bytes:\n");
            heap_dump(&h);
        }
    }

    return 0;
}
