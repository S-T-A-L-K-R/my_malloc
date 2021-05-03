#if !defined(_CUSTOM_HEAP_H_)
#define _CUSTOM_HEAP_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define PAGE_SIZE 4096

#define FENCE_SIZE 16
#define CONTROL_SIZE (int)(sizeof(struct memory_chunk_t))

enum pointer_type_t
{
    /*0*/pointer_null,
    /*1*/pointer_heap_corrupted,
    /*2*/pointer_control_block,
    /*3*/pointer_inside_fences,
    /*4*/pointer_inside_data_block,
    /*5*/pointer_unallocated,
    /*6*/pointer_valid
};

struct memory_fence_t 
{
    uint8_t first_page[FENCE_SIZE];
    uint8_t last_page[FENCE_SIZE];
};

struct memory_manager_t
{
    intptr_t start_brk;
    intptr_t brk;
    struct memory_chunk_t *first_memory_chunk;
	int memory_size;
	struct memory_fence_t fence_heap;
    size_t largest_used_block_size;
};

struct memory_chunk_t
{
	struct memory_chunk_t* prev;
	struct memory_chunk_t* next;
	size_t size;
	int free;
	int checksum;
};

struct memory_manager_t memory_manager;

int heap_setup(void);
void heap_clean(void);
int heap_validate(void);
int fences_check(struct memory_chunk_t* my_memory);
int heap_expand(size_t size);
void* heap_malloc(size_t size);
void* heap_calloc(size_t number, size_t size);
void* heap_realloc(void* memblock, size_t count);
void  heap_free(void* memblock);
size_t heap_get_largest_used_block_size(void);
enum pointer_type_t get_pointer_type(const void* const pointer);
void* heap_malloc_aligned(size_t count);
void* heap_calloc_aligned(size_t number, size_t size);
void* heap_realloc_aligned(void* memblock, size_t size);
void checksum_make(struct memory_chunk_t* my_memory);
int checksum_check(struct memory_chunk_t *my_memory);
#endif
