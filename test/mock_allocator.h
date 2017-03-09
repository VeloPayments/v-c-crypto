/**
 * \file mock_allocator.h
 *
 * Mock allocator for testing allocator routines.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#ifndef TEST_ALLOCATOR_MOCK_ALLOCATOR_HEADER_GUARD
#define TEST_ALLOCATOR_MOCK_ALLOCATOR_HEADER_GUARD

/**
 * Initialize the mock allocator options.
 */
void mock_allocator_options_init(allocator_options_t* options,
    bool use_reallocate);

/**
 * Set the return value for allocator_allocate.
 */
void mock_allocator_allocate_retval(allocator_options_t* options, void* val);

/**
 * Returns true if allocator_allocate was called with the given arguments.
 */
bool mock_allocator_allocate_called(allocator_options_t* options, size_t size);

/**
 * Returns true if allocator_allocate was called with *ANY* arguments.
 */
bool mock_allocator_allocate_called(allocator_options_t* options);

/**
 * Returns true if allocator_release was called with the given arguments.
 */
bool mock_allocator_release_called(allocator_options_t* options, void* mem);

/**
 * Returns true if allocator_release was called with *ANY* arguments.
 */
bool mock_allocator_release_called(allocator_options_t* options);

/**
 * Set the return value for allocator_reallocate.
 */
void mock_allocator_reallocate_retval(allocator_options_t* options, void* val);

/**
 * Returns true if allocator_reallocate was called with the given arguments.
 */
bool mock_allocator_reallocate_called(allocator_options_t* options, void* mem,
    size_t old_size, size_t new_size);

/**
 * Returns true if allocator_reallocate was called with *ANY* arguments.
 */
bool mock_allocator_reallocate_called(allocator_options_t* options);

#endif  //TEST_ALLOCATOR_MOCK_ALLOCATOR_HEADER_GUARD
