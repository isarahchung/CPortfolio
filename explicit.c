/* File: explicit.c
 * ---------------------
 * This file implements an explicit free list heap allocator.
 * It uses a doubly linked list to track free blocks. Each block 
 * has a header that stores metadata including its size
 * and allocation status. The allocator searches the 
 * explicit free list to find a suitable block.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "./allocator.h"
#include "./debug_break.h"

// Constants
#define HEADER_SIZE ALIGNMENT
#define MIN_PAYLOAD_SIZE (ALIGNMENT*2) 
#define MIN_BLOCK_SIZE (ALIGNMENT*3) 
#define SIZE_MASK ~1L  // mask to extract size from header
#define STATUS_MASK 1  // mask to extract status from header
#define FREE 0  
#define ALLOC 1 
#define BYTES_PER_LINE 32   // used in dump_heap for formatting

typedef size_t header_t;   // type alias for headers

// Block structure used in explicit free list
typedef struct block {
    header_t metadata;
    struct block *prev;
    struct block *next;
} block; 

// Global variables
static block *first_free_block;
static header_t *segment_start;
static size_t segment_size;
static header_t *segment_end;
static size_t freeblocks;

/* Function: set_header
 * ------------------------------
 * Sets the header of 8 bytes to store
 * metadata of payload with specified status and size.
 * 
 * @param b: Ptr to the block header to set
 * @param size: Size to be set in the header
 * @param status: Allocation status of block
 */
void set_header(block *b, size_t size, int status) {
    // Clear the last 1 bit
    size &= SIZE_MASK;
    // Set size and status in header
    if (status == ALLOC) {
        b->metadata = size | STATUS_MASK;  // flip LSB
    } else {
        b->metadata = size;  // keep 0 for free
    }
    b->metadata = size | status;
}

/* Retrieves payload size from a block's header.
 */
size_t get_payload_size(block *b) {
    if (b == NULL) {
        return 0;
    }
    return ((b->metadata) & SIZE_MASK);
}

/*
 * Returns the next block in the heap
 * based on the current block's header.
 */
void *next_block(block *b) {
    // next header = current payload size + header size 
    return ((char *)b + get_payload_size(b) + HEADER_SIZE);
}


/* Function: roundup
 * --------------
 * Rounds up the given number to the 
 * given multiple, which must be a power of 2,
 * and returns the result. 
 *
 */
size_t roundup(size_t sz, size_t mult) {
    return (sz + mult - 1) & ~(mult - 1);
}

/* Function: payload2header
 * -----------------------
 * Converts a payload pointer to its corresponding
 * block header pointer.
 *
 * @param payload Ptr to the payload of a block
 * @return Ptr to corresponding block header.
 */
block *payload2header(void *payload) {
    return (block *)((char*)payload - HEADER_SIZE);
}

/* Helper function that checks if block is free
 * based on its header.
 */
bool is_free(block *b) {
    return (b->metadata & STATUS_MASK) == FREE;
}

/* Function: add_free_block
 * ---------------
 * Adds free block to the free list.
 */
void add_free_block(block *b) {
    if (b == NULL || b < (block *)segment_start || b >= (block *)segment_end) {
        return;
    }
    if (first_free_block != NULL) {
        first_free_block->prev = b;
    }
    b->next = first_free_block;
    b->prev = NULL;
    first_free_block = b;
    freeblocks++;
}

/* Function: detach_free_block
 * ------------------
 * Deletes allocated block from the free list.
 */
void detach_free_block(block *b) {
    if (b == NULL || b < (block *)segment_start || b >= (block *)segment_end) {
        return;
    }

    if (b->prev && b->next) {  // middle block
        b->prev->next = b->next;
        b->next->prev = b->prev;
    } else if (b->prev == NULL && b->next == NULL) {  // b was first, only block
        first_free_block = NULL;  
    } else if (b->next && b->prev == NULL) {   // first block
        first_free_block = b->next;
        b->next->prev = NULL; 
    } else {   // last block deleted
        b->prev->next = NULL;
    }
    freeblocks--; 
}

/*
 * Function: split
 * ------------------------
 * Splits a larger free block into two blocks:
 * one allocated block of requested size and one free
 * block with the remaining space.
 *
 * @param header: Ptr to the block to be split
 * @param requested_size: Size of the new allocated block
 */
void split(block *b, size_t requested_size) {
    size_t original_size = get_payload_size(b);
    
    // Checks if enough space to split
    if (original_size <= requested_size + MIN_BLOCK_SIZE) {
        return;
    }

    // enough room to split
    size_t remaining = original_size - requested_size - HEADER_SIZE; // payload size
    if (remaining >= MIN_BLOCK_SIZE) {
        set_header(b, requested_size, ALLOC);

        block *new_free = (block *)((char *)b + requested_size + HEADER_SIZE);
        set_header(new_free, remaining, FREE);
        new_free->prev = NULL;
        new_free->next = NULL;
        
        add_free_block(new_free);
    } 
}

/* Function: coalesce
 * --------------------
 * Takes in a block to determine whether it can coalesce.
 * Coalesces with the next free block. Deletes node.
 * Returns false if it can't coalesce.
 */
bool coalesce(block *b) {
    block *next = next_block(b);  // jumps to next block in heap
    size_t size = get_payload_size(b);
    
    if (next == NULL || next < (block *)segment_start || next >= (block *)segment_end) {
        return false;
    }
    if (!is_free(next)) {
        return false;
    }
    detach_free_block(next);  // next block is free 
    size += get_payload_size(next) + HEADER_SIZE;
    set_header(b, size, FREE);
    return true;
}

// Sets status depending on what the status is.
void set_status(block *b, int status) {
    b->metadata &= SIZE_MASK;
    b->metadata |= status;
}


/* Function: myinit
 * ------------------------
 * Initializes the heap allocator. Called before
 * any allocation requests, it creates a single large
 * free block that covers entire heap.
 *
 * @param heap_start Ptr to start of heap segment
 * @param heap_size Total size of heap segment
 * @return True if initialization was successful, False otherwise
 */
bool myinit(void *heap_start, size_t heap_size) {
    // checks boundaries
    if (heap_size < MIN_BLOCK_SIZE || heap_start == NULL) {
        return false;
    }

    // initialize global variables
    segment_start = (header_t *)heap_start;
    segment_size = heap_size;
    segment_end = (header_t *)((char *)segment_start + segment_size);
    *segment_start = segment_size - HEADER_SIZE;
    
    // set up first free node in heap
    ((block *)segment_start)->metadata = *segment_start;
    ((block *)segment_start)->prev = NULL;
    ((block *)segment_start)->next = NULL;

    first_free_block = (block *)segment_start;
    
    freeblocks = 1;  // always initalized with one free block
    return true;
}


/* Function: mymalloc
 * -----------------
 * Allocates a block of memory of at least requested_size.
 * Scans heap linearly to find first free block that is large
 * enough, potentially splitting block if it's significantly 
 * larger than requested.
 *
 * @param requested_size Size of memory to allocate
 * @param Pointer to the allocated memory block, NULL if none found
 */
void *mymalloc(size_t requested_size) {
    if (requested_size == 0 || requested_size > MAX_REQUEST_SIZE) {
        return NULL;
    }

    size_t need = roundup(requested_size, MIN_PAYLOAD_SIZE);
    
    block *curBlock = first_free_block;
    while (curBlock != NULL) {   // traverse through every block
        size_t cur_size = get_payload_size(curBlock);
        if (is_free(curBlock) && cur_size >= need) {   // check if big enough and free
            split(curBlock, need);
            detach_free_block(curBlock);
            set_status(curBlock, ALLOC);
            return (char *)(curBlock) + HEADER_SIZE;   // return ptr to payload
        } 
        curBlock = curBlock->next;
    }
    return NULL;
}

/* Function: myfree
 * ------------------
 * Frees a previously allocated block of memory.
 * Marks block as free in heap's implicit list.
 *
 * @param ptr Pointer to memory block to be freed.
 */
void myfree(void *ptr) {
    block *b = payload2header(ptr);
    set_status(b, FREE);  // current block freed
    while (coalesce(b)) {}   // will only coalesce if next to free block  
    add_free_block(b);   // to beginning of free list
} 

/* Function: myrealloc
 * --------------------
 * Reallocates a previously allocated block to a new size.
 * If old_ptr is NULL, behaves like malloc. 
 * If new_size is 0, behaves like free.
 *
 * @param old_ptr Ptr to currently allocated block.
 * @param new_size New size for reallocated block.
 * @param Ptr to the reallocated block, NULL if fails.
 */
void *myrealloc(void *old_ptr, size_t new_size) {
    char *ptr = (char *)old_ptr;
    if (ptr == NULL) {  
        return mymalloc(new_size);
    } else if (new_size == 0 && old_ptr != NULL) {
        myfree(old_ptr);
        return NULL;
    } else if (ptr < (char *)segment_start || ptr >= (char *)segment_end) {  
        return NULL;
    }
    
    block *old_block = payload2header(ptr);
    size_t old_size = get_payload_size(old_block);
    new_size = roundup(new_size, MIN_PAYLOAD_SIZE);
    
    if (old_size >= new_size) {   // case 1: shrinking in place
        split(old_block, new_size);  // if possible, splits block into alloc + free (added to free list)
        return old_ptr;
    }
    
    // case 2: expanding into next block that is free
    while (coalesce(old_block)) {}   // next blocks are merged if free
    if (get_payload_size(old_block) >= new_size) {
       split(old_block, new_size);  
       set_status(old_block, ALLOC);
       return old_ptr;
    }
    // case 3: move to a new place if not enough room
    void *new_ptr = mymalloc(new_size);
    memcpy(new_ptr, old_ptr, new_size);
    if (new_ptr != old_ptr) {
        myfree(old_ptr);
    }
    return new_ptr;
}

/* Function: validate_heap
 * -----------------------
 * This function checks for potential errors/inconsistencies in the heap data
 * structures and returns false if there were issues, or true otherwise.
 * This implementation checks if the allocator has used more space than is
 * available.
 */
bool validate_heap() {
    if (freeblocks > segment_size) {
        printf("\nERROR: Oops! Have used more heap than total available?");
        breakpoint();
        return false;
    }
    block *curBlock = (block *)segment_start;
    size_t total = 0;
    
    // Check if start of heap initalized
    if (curBlock == NULL) {
        printf("\nERROR: Did not initialize heap correctly!");
        breakpoint();
        return false;
    }
    // Linearly scan blocks in heap
    while (curBlock < (block *)segment_end) {
        size_t cur_size = get_payload_size(curBlock);
        total += cur_size + HEADER_SIZE;
        if (cur_size < HEADER_SIZE) {
            printf("\nERROR: Block must be at least 8 bytes");
            breakpoint();
            return false;
        }
        if (curBlock >= (block *)segment_end || curBlock < (block *)segment_start) {
            printf("\nERROR: Block out of bounds!");
            breakpoint();
            return false;
        }
        curBlock = next_block(curBlock);
    }
    if (curBlock != (block *)segment_end) {
        printf("curBlock does not equal segment end");
        breakpoint();
        return false;
    }
    if (total != segment_size) {
        printf("\nERROR: Incorrect heap size!");
        printf("\nTotal size: %lu, Expected size: %lu", total, segment_size);
        breakpoint();
        return false;
    }
    

    // Check if every block in free list is free
    size_t num_free_blocks = 0;
    block *free = first_free_block;

    if (free != NULL && free->prev != NULL) {
        printf("\nERROR: First free block should not have a previous block.");
        breakpoint();
        return false;
    }
    while (free != NULL) {
        num_free_blocks++;

        // Ensure each block in the free list is marked free
        if (!is_free(free)) {
            printf("\nERROR: Block at address %p in free list is not marked free.", free);
            breakpoint();
            return false;
        }

        // Check for circular references or invalid next pointers
        if (free->next && (free->next < (block *)segment_start || free->next >= (block *)segment_end)) {
            printf("\nERROR: Invalid next pointer in free list.");
            breakpoint();
            return false;
        }
        if (free->prev && (free->prev < (block *)segment_start || free->prev >= (block *)segment_end)) {
            printf("\n ERROR: free list prev invalid");
            breakpoint();
            return false;
        }

        free = free->next;
    }
    if (num_free_blocks != freeblocks) {
        printf("\nERROR: Mismatch in count of free blocks. Found: %zu, Expected: %zu", num_free_blocks, freeblocks);
        breakpoint();
        return false;
    }
    return true;
}

/* Function: dump_heap
 * -------------------
 * This function prints out the the block contents of the heap.  It is not
 * called anywhere, but is a useful helper function to call from gdb when
 * tracing through programs.  It prints out the total range of the heap, and
 * information about each block within it.
 */
void dump_heap() {
    printf("Heap segment starts at address %p, ends at %p. %lu bytes currently used.",
           segment_start, (char*)segment_start + segment_size, freeblocks);

    printf("\nHEAP:");
    block *curBlock = (block *)segment_start;
    while (curBlock < (block *)segment_end) {
        size_t cur_size = get_payload_size(curBlock);
        printf("\nBlock %p | Payload size: %ld, ", curBlock, cur_size);
        if (is_free(curBlock)) {
            printf("Status: FREE\n");
        } else {
            printf("Status: ALLOCATED");
        }
        curBlock = next_block(curBlock);
        printf("\n");
    }
    
    printf("\nFREE LIST:\n");
    block *free = first_free_block;
    while (free != NULL) {
        printf("\nFree Block %p | Size: %lu | Status: ", free, get_payload_size(free));
        if (is_free(free)) {
            printf("FREE");
        } else {
            printf("ALLOCATED. ERROR!");
        }
        printf("\nPrev: %p, Next: %p\n", (void *)free->prev, (void *)free->next);
        free = free->next;
    }
}