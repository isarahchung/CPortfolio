/* File: implicit.c
 * -------------------
 * Description: This file implements 
 * an implicit heap allocator with the first-fit method.
 * Scans heap linearly to find first free block
 * by scanning header to determine status and size.
 */
#include "./allocator.h"
#include "./debug_break.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
// Define constants
#define HEADER_SIZE 8
#define MIN_SIZE (ALIGNMENT*2) // minimum block size
#define SIZE_MASK ~1L  // mask to extract size from header
#define STATUS_MASK 1  // mask to extract status from header
#define FREE 0  
#define ALLOC 1 
#define BYTES_PER_LINE 32   // used in dump_heap for formatting

typedef size_t header_t;   // type alias for headers

// Define global variables
static header_t *segment_start;
static size_t segment_size;
static header_t *segment_end;
static size_t nused;

/*
 * Function: set_header
 * ------------------------------
 * Sets the header of 8 bytes to store
 * metadata of payload with specified status and size.
 * 
 * @param header Ptr to the block header to set
 * @param size Size to be set in the header
 * @param status Allocation status of block
 */
void set_header(header_t *header, size_t size, int status) {
    // Clear the last 1 bit
    size &= SIZE_MASK;

    // Set size and status in header
    if (status == ALLOC) {
        *header = size | STATUS_MASK; // flip LSB
    } else {
        *header = size; // keep 0 for free
    }
    *header = size | status;
}

/*
 * Function: myinit
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
    // Validates input parameters
    if (heap_size < MIN_SIZE || heap_start == NULL || heap_size == 0) {
        return false;
    }

    // Initialize global variables
    nused = 0;
    segment_start = (header_t *)heap_start;
    segment_size = heap_size;
    segment_end = (header_t *)((char*)segment_start + segment_size);

    // Create initial free block covering entire heap
    set_header(segment_start, segment_size - HEADER_SIZE, FREE);
 
    return true;
}

/* 
 * Helper function that checks if block is free
 * based on its header.
 */
bool is_free(header_t *header) {
    return (*header & STATUS_MASK) == FREE;
}

/*
 * Retrieves payload size from a block's header.
 */
size_t get_payload_size(header_t *header) {
    return (*header & SIZE_MASK);
}

/*
 * Returns the next block in the heap
 * based on the current block's header.
 */
header_t *next_block(header_t *header) {
    // next header = current payload size + header size 
    return (header_t *)((char *)header + get_payload_size(header) + HEADER_SIZE);
}


/*
 * Function: split
 * ------------------------
 * Splits a larger free block into two blocks:
 * one allocated block of requested size and one free
 * block with the remaining space.
 *
 * @param header Ptr to the block to be split
 * @param requested_size Size of the new allocated block
 */
void split(header_t *header, size_t requested_size) {
    size_t original_size = get_payload_size(header);
    
    // Checks if enough space to split
    if (original_size <= requested_size + HEADER_SIZE) {
        return;
    }

    size_t remaining = original_size - requested_size - HEADER_SIZE;
    if (remaining >= MIN_SIZE) {
        set_header(header, requested_size, ALLOC);
        header_t *new_header = next_block(header);
        set_header(new_header, remaining, FREE);
    }
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
    if (requested_size <= 0 || requested_size > MAX_REQUEST_SIZE) {
        return NULL;
    }
    // Roundup requested size to meet alignment requirements
    size_t need = roundup(requested_size, ALIGNMENT);

    // Check if there's enough space left in heap
    if (need + nused > segment_size) {
        return NULL;
    }

    // Linearly scan heap for a suitable free block
    header_t *curHead = segment_start;
    while (curHead < segment_end) {
        size_t cur_size = get_payload_size(curHead);
        if (is_free(curHead) && (cur_size >= need)) {
            if (cur_size > need + HEADER_SIZE + MIN_SIZE) {  // More than enough space -> split
                split(curHead, need);
            } else { 
                set_header(curHead, cur_size, ALLOC);
            }
            nused += need + HEADER_SIZE;
            return (char*)(curHead) + HEADER_SIZE;
        }
        curHead = next_block(curHead);  // Move to next header
    }
    return NULL;
}

/*
 * Converts a payload pointer to its corresponding
 * block header pointer.
 *
 * @param payload Ptr to the payload of a block
 * @return Ptr to corresponding block header.
 */
header_t *payload2header(void *payload) {
    return (header_t *)((char*)payload - HEADER_SIZE);
}

/*
 * Function: myfree
 * ------------------
 * Frees a previously allocated block of memory.
 * Marks block as free in heap's implicit list.
 *
 * @param ptr Pointer to memory block to be freed.
 */
void myfree(void *ptr) {
    // Validate ptr
    if (!ptr || (header_t *)ptr < segment_start || (header_t *)ptr >= segment_end) {
        return;
    }
    
    // Convert payload ptr to header, mark block as free
    header_t *header = payload2header(ptr);
    size_t size = get_payload_size(header);
    set_header(header, size, FREE);
}

/*
 * Function: myrealloc
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
    if (old_ptr == NULL) {
        return mymalloc(new_size);
    }
    if (new_size == 0 && old_ptr != NULL) {
        free(old_ptr);
        return NULL;
    }
    
    header_t *new_ptr = mymalloc(new_size);
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
    if (nused > segment_size) {
        printf("\nERROR: Oops! Have used more heap than total available?");
        breakpoint();
        return false;
    }

    header_t *curHead = segment_start;
    size_t total = 0;
    
    // Check if start of heap initalized
    if (curHead == NULL) {
        printf("\nERROR: Did not initialize heap correctly!");
        breakpoint();
        return false;
    }

    // Linearly scan blocks in heap
    while (curHead < segment_end) {
        size_t cur_size = get_payload_size(curHead);
        total += cur_size + HEADER_SIZE;
        if (cur_size < HEADER_SIZE) {
            printf("\nERROR: Block must be at least 8 bytes");
            breakpoint();
        }
        curHead = next_block(curHead);
    }

    if (total != segment_size) {
        printf("\nERROR: Incorrect heap size!");
        printf("\nTotal size: %lu, Expected size: %lu", total, segment_size);
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
           segment_start, (char*)segment_start + segment_size, nused);
    for (int i = 0; i < nused; i++) {
        unsigned char *cur = (unsigned char *)segment_start + i;
        if (i % BYTES_PER_LINE == 0) {
            printf("\n%p:", cur);
        }
        printf("%02x", *cur);
    }
    printf("\n");

    header_t *curHead = segment_start;
    while (curHead < segment_end) {
        size_t cur_size = get_payload_size(curHead);
        char *status = is_free(curHead) ? "Free" : "Allocated";
        printf("\nBlock %p | Payload size: %ld, Status: %s\n", curHead, cur_size, status);
        curHead = next_block(curHead);
        printf("\n");
    }
}