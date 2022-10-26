/* An implementation of malloc for POSIX-compliant systems.
 * Licensed under the MIT license (c) 2022 Will Brown */

/* TODO:
 * Traverse free blocks only instead of entire heap
 * Better method of finding free space to reduce fragmentation
 * Add mutexes and atomics so multithreading isn't a disaster.
 * Write tests.
 */

#include <stddef.h>
#include <stdalign.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/mman.h>

// Implemented functions so far
void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);

// As of C11, determines the alignment to use for 
#define ALIGNMENT alignof(max_align_t)

// Alignment must be a power of 2.
#define ALIGN(size, alignment) (((size) + alignment - 1) & ~(alignment - 1))

// This struct should be aligned to the same alignment as max_align_t.
struct block_hdr {
	alignas(max_align_t) struct block_hdr *region;
	struct block_hdr *next;
	struct block_hdr *prev;
	// size is tagged such that the LSB denotes whether this block is allocated.
	size_t size;
};

static struct block_hdr block_list = {
	.region = NULL,
	.next = NULL,
	.prev = NULL,
	.size = 1
};

static struct block_hdr *create_region(size_t size) {
	struct block_hdr *new_region = mmap(
		NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
	);
	
	if (new_region == MAP_FAILED) {
		errno = ENOMEM;
		return NULL;
	} else {
		*new_region = (struct block_hdr) {
			.region = new_region,
			.next = NULL,
			.prev = NULL,
			.size = size - sizeof(struct block_hdr)
		};
		
		return new_region;
	}
}

static struct block_hdr *alloc_block(struct block_hdr *block, size_t size) {
	size_t free_block_size = block->size - size;
	if (free_block_size > sizeof(struct block_hdr)) {
		struct block_hdr *free_block = (struct block_hdr *)
			(((char *) block) + sizeof(struct block_hdr) + size);
		
		free_block->region = block->region;
		free_block->next = block->next;
		if (free_block->next) free_block->next->prev = free_block;
		free_block->prev = block;
		free_block->size = free_block_size - sizeof(struct block_hdr);
		
		block->next = free_block;
		block->size = size | 1;
	} else {
		block->size |= 1;
	}
	
	return block;
}

static struct block_hdr *find_block(size_t size) {
	struct block_hdr *block = &block_list;
	
	while (block->next && (block->size & 1 || block->size < size)) 
		block = block->next;
	
	// Not enough free space, create a new region.
	if (block->size & 1 || block->size < size) {
		long pagesize = sysconf(_SC_PAGESIZE);
		size_t region_size = ALIGN(size + sizeof(struct block_hdr), pagesize);
		struct block_hdr *new_region = create_region(region_size);
		if (!new_region) return NULL;
		new_region->prev = block;
		block->next = new_region;
		block = new_region;
	}
	
	return block;
}

void *malloc(size_t size) {
	size = ALIGN(size, ALIGNMENT);
	struct block_hdr *block = find_block(size);
	return block ? alloc_block(block, size) + 1 : NULL;
}

void free(void *ptr) {
	if (!ptr) return;
	
	struct block_hdr *block = (struct block_hdr *) ptr - 1;
	
	// Merge adjacent blocks
	size_t new_block_size = block->size & SIZE_MAX - 1;
	struct block_hdr *new_block = block;
	
	// Previous block is in the same region and free
	if (block->prev->region == block->region && !(block->prev->size & 1)) {
		new_block = block->prev;
		new_block->next = block->next;
		if (new_block->next) new_block->next->prev = new_block;
		new_block_size += new_block->size + sizeof(struct block_hdr);
	}
	
	// Next block exists, is in the same region, and is free
	if (block->next && block->next->region == block->region && !(block->next->size & 1)) {
		new_block->next = block->next->next;
		if (new_block->next) new_block->next->prev = new_block;
		new_block_size += block->next->size + sizeof(struct block_hdr);
	}
	
	// empty region
	if (
		(!new_block->next || new_block->region != new_block->next->region) && 
		new_block->region != new_block->prev->region
	) {
		// remove block from list
		new_block->prev->next = new_block->next;
		if (new_block->next) new_block->next->prev = new_block->prev;
		
		// unmap region
		size_t region_size = new_block_size + sizeof(struct block_hdr);
		munmap(new_block, region_size);
	} else {
		new_block->size = new_block_size;
	}
}

void *calloc(size_t nmemb, size_t size) {
	size_t n;
	if (!__builtin_mul_overflow(nmemb, size, &n)) {
		errno = ENOMEM;
		return NULL;
	} else {
		void *ptr = malloc(n);
		return ptr ? memset(ptr, 0, n) : NULL;
	}
}

void *realloc(void *ptr, size_t size) {
	if (!ptr) return malloc(size);

	size = ALIGN(size, ALIGNMENT);
	struct block_hdr *block = (struct block_hdr *) ptr - 1;
	
	size_t combined_block_size;
	// there is enough adjacent free space, just create a new bigger block.
	if (
		block->next &&
		block->next->region == block->region &&
		!(block->next->size & 1) &&
		(combined_block_size = block->next->size + (block->size & SIZE_MAX - 1) + sizeof(struct block_hdr)) >= size
	) {
		size_t leftover_block_size = combined_block_size - size;
		if (leftover_block_size > sizeof(struct block_hdr)) {
			struct block_hdr *free_block = (struct block_hdr *)
				((char *) block + sizeof(struct block_hdr *) + size);

			free_block->next = block->next->next; // This is first in case the headers overlap
			if (free_block->next) free_block->next->prev = free_block;
			free_block->region = block->region;
			free_block->prev = block;
			free_block->size = leftover_block_size - sizeof(struct block_hdr);
			block->next = free_block;
			block->size = size;
		} else {
			block->next = block->next->next;
			if (block->next) block->next->prev = block;
			block->size = combined_block_size; // avoid leaking memory
		}
		return ptr;
	} else { // not enough space, malloc and copy.
		void *new_ptr = malloc(size);
		if (!new_ptr) return NULL;
		memcpy(new_ptr, ptr, block->size);
		free(ptr);
		return new_ptr;
	}
}
