/* An implementation of malloc for POSIX-compliant systems.
 * Licensed under the MIT license (c) 2022 Will Brown */

/* TODO:
 * Write tests.
 * Get working with general-purpose programs.
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdalign.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/mman.h>

#include <pthread.h>

// Implemented functions so far
void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);

// As of C11, determines the maximum alignment for any data type.
#define ALIGNMENT alignof(max_align_t)

// Alignment must be a power of 2.
#define ALIGN(size, alignment) (((size) + alignment - 1) & ~(alignment - 1))

// All header structs should be aligned to the same alignment as max_align_t.
struct region_hdr {
	alignas(max_align_t) pthread_mutex_t mutex;
	struct block_hdr *largest_free_block;
	struct region_hdr *next;
	struct region_hdr *prev;
	size_t size;
};

struct block_hdr {
	alignas(max_align_t) struct region_hdr *region;
	struct block_hdr *next;
	struct block_hdr *prev;
	// size is tagged such that the LSB denotes whether this block is allocated.
	size_t size;
};

static bool malloc_initialized = false;
static long pagesize;

static struct region_hdr *region_list = NULL;

// This should be locked whenever memory is being allocated or the list is changed.
static pthread_mutex_t malloc_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct region_hdr *create_region(size_t size) {
	struct region_hdr *new_region = mmap(
		NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
	);
	
	if (new_region == MAP_FAILED) {
		errno = ENOMEM;
		return NULL;
	} else {
		struct block_hdr *first_block = (struct block_hdr *) (new_region + 1);
		*first_block = (struct block_hdr) {
			.region = new_region,
			.next = NULL,
			.prev = NULL,
			.size = size - sizeof(struct region_hdr) - sizeof(struct block_hdr)
		};
		
		*new_region = (struct region_hdr) {
			.mutex = PTHREAD_MUTEX_INITIALIZER,
			.largest_free_block = first_block,
			.next = NULL,
			.prev = NULL,
			.size = size
		};
		
		return new_region;
	}
}

static struct block_hdr *alloc_block(struct region_hdr *region, size_t size) {
	pthread_mutex_lock(&region->mutex);
	struct block_hdr *block = region->largest_free_block;
	
	size_t free_block_size = block->size - size;
	if (free_block_size > sizeof(struct block_hdr)) {
		struct block_hdr *free_block = (struct block_hdr *)
			(((char *) block) + sizeof(struct block_hdr) + size);
		
		free_block->region = region;
		free_block->next = block->next;
		if (free_block->next) free_block->next->prev = free_block;
		free_block->prev = block;
		free_block->size = free_block_size - sizeof(struct block_hdr);
		
		block->next = free_block;
		block->size = size | 1;
		region->largest_free_block = free_block;
	} else {
		block->size |= 1;
		region->largest_free_block = NULL;
	}
	
	pthread_mutex_unlock(&region->mutex);
	return block;
}

static struct region_hdr *find_region(size_t size) {
	struct region_hdr *region = region_list;
	
	if (region)
		while (
			region->next &&
			(!region->largest_free_block ||
			region->largest_free_block->size < size)
		) region = region->next;
	
	if (!region || !region->largest_free_block || region->largest_free_block->size < size) {
		if (!malloc_initialized) pagesize = sysconf(_SC_PAGESIZE);
		size_t region_size = ALIGN(size + sizeof(struct region_hdr) + sizeof(struct block_hdr), pagesize);
		struct region_hdr *new_region = create_region(region_size);
		if (!new_region) return NULL;
		
		if (region) region->next = new_region;
		region = new_region;
	}
	
	return region;
}

void *malloc(size_t size) {
	size = ALIGN(size, ALIGNMENT);
	pthread_mutex_lock(&malloc_mutex);
	struct region_hdr *region = find_region(size);
	void *ret = region ? alloc_block(region, size) + 1 : NULL;
	pthread_mutex_unlock(&malloc_mutex);
	return ret;
}

static void destroy_region(struct region_hdr *region) {
	pthread_mutex_lock(&malloc_mutex);
	if (region->next) region->next->prev = region->prev;
	if (region->prev) region->prev->next = region->next;
	if (region == region_list) region_list = region->next;
	pthread_mutex_unlock(&malloc_mutex);
	pthread_mutex_destroy(&region->mutex);
	munmap(region, region->size);
}

void free(void *ptr) {
	if (!ptr) return;
	
	struct block_hdr *block = (struct block_hdr *) ptr - 1;
	struct region_hdr *region = block->region;
	
	// Merge adjacent blocks
	size_t new_block_size = block->size & SIZE_MAX - 1;
	struct block_hdr *new_block = block;
	
	pthread_mutex_lock(&region->mutex);
	
	// Previous block is free
	if (block->prev && !(block->prev->size & 1)) {
		new_block = block->prev;
		new_block->next = block->next;
		if (new_block->next) new_block->next->prev = new_block;
		new_block_size += new_block->size + sizeof(struct block_hdr);
	}
	
	// Next block is free
	if (new_block->next && !(new_block->next->size & 1)) {
		new_block_size += new_block->next->size + sizeof(struct block_hdr);
		new_block->next = new_block->next->next;
		if (new_block->next) new_block->next->prev = new_block;
	}
	
	// empty region
	if (new_block_size == region->size - sizeof(struct region_hdr) - sizeof(struct block_hdr)) {
		pthread_mutex_unlock(&region->mutex);
		destroy_region(region);
	} else {
		new_block->size = new_block_size;
		if (new_block_size > region->largest_free_block->size)
			region->largest_free_block = new_block;
		
		pthread_mutex_unlock(&region->mutex);
	}
}

void *calloc(size_t nmemb, size_t size) {
	size_t n;
	if (__builtin_mul_overflow(nmemb, size, &n)) {
		errno = ENOMEM;
		return NULL;
	} else {
		void *ptr = malloc(n);
		return ptr ? memset(ptr, 0, n) : NULL;
	}
}

static void resize_block(struct block_hdr *block, size_t size) {
	struct region_hdr *region = block->region;
	size_t combined_block_size = block->size;
	bool free_block_overwritten = false;
	
	if (block->next && !(block->next->size & 1)) {
		if (region->largest_free_block == block->next)
			free_block_overwritten = true;
		
		combined_block_size += block->next->size + sizeof(struct block_hdr);
	}
	
	if (combined_block_size != size) {
		size_t leftover_block_size = combined_block_size - size;
		if (leftover_block_size > sizeof(struct block_hdr)) {
			struct block_hdr new_block = {
				.region = region,
				.next = block->next && !(block->next->size & 1) ? 
					block->next->next : block->next,
				.prev = block,
				.size = leftover_block_size
			};
			
			struct block_hdr *free_block = (struct block_hdr *)
				((char *) block + sizeof(struct block_hdr *) + size);

			*free_block = new_block;
			if (free_block->next) free_block->next->prev = free_block;
			
			block->next = free_block;
			block->size = size | 1;
			
			if (free_block_overwritten) region->largest_free_block = free_block;
			else if (free_block->size > region->largest_free_block->size)
				region->largest_free_block = free_block;
		} else {
			struct block_hdr *old_next = block->next;
			block->next = old_next->next;
			if (block->next) block->next->prev = block;
			block->size = combined_block_size | 1; // avoid leaking memory
			
			if (region->largest_free_block == old_next)
				region->largest_free_block = block->next;
		}
	}
}

void *realloc(void *ptr, size_t size) {
	if (!ptr) return malloc(size);

	size = ALIGN(size, ALIGNMENT);
	struct block_hdr *block = (struct block_hdr *) ptr - 1;
	struct region_hdr *region = block->region;
	pthread_mutex_lock(&region->mutex);
	
	// there is enough adjacent free space, just create a new bigger block.
	if (
		size < block->size ||
		block->next &&
		!(block->next->size & 1) &&
		block->size + block->next->size >= size
	) {
		resize_block(block, size);
		pthread_mutex_unlock(&region->mutex);
		return ptr;
	} else { // not enough space, malloc and copy.
		pthread_mutex_unlock(&region->mutex);
		void *new_ptr = malloc(size);
		if (!new_ptr) return NULL;
		memcpy(new_ptr, ptr, block->size);
		free(ptr);
		return new_ptr;
	}
}
