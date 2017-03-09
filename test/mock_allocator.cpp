/**
 * \file mock_allocator.cpp
 *
 * Mock allocator for testing allocator routines.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <cstring>
#include <tuple>
#include <list>
#include <vpr/allocator.h>

#include "mock_allocator.h"

using namespace std;

/**
 * The context for a mock allocator.
 */
struct mock_allocator_context
{
    mock_allocator_context()
        : allocate_retval(nullptr)
        , reallocate_retval(nullptr)
    {
    }

    void* allocate_retval;
    list<tuple<void*, size_t>> allocate_calls;
    list<tuple<void*, void*>> release_calls;
    void* reallocate_retval;
    list<tuple<void*, void*, size_t, size_t>> reallocate_calls;
};

/* forward decls for mock allocator methods */
static void* mock_allocator_allocate(void*, size_t);
static void mock_allocator_release(void*, void*);
static void* mock_allocator_reallocate(void*, void*, size_t, size_t);
static void mock_allocator_options_dispose(allocator_options_t* options);

/**
 * Initialize the mock allocator options.
 */
void mock_allocator_options_init(allocator_options_t* options,
    bool use_reallocate)
{
    memset(options, 0, sizeof(allocator_options_t));
    options->hdr.dispose = (dispose_method_t)&mock_allocator_options_dispose;
    options->allocator_allocate = &mock_allocator_allocate;
    options->allocator_release = &mock_allocator_release;
    options->allocator_reallocate = use_reallocate ? &mock_allocator_reallocate
                                                   : nullptr;
    options->context = (void*)(new mock_allocator_context);
}

/**
 * Dispose of a mock_allocator options structure.
 */
static void mock_allocator_options_dispose(allocator_options_t* options)
{
    //clean up context
    auto ctx = (mock_allocator_context*)options->context;
    delete ctx;

    //clear options structure
    memset(options, 0, sizeof(allocator_options_t));
}

/**
 * Mock allocate call.
 */
static void* mock_allocator_allocate(void* context, size_t size)
{
    auto ctx = (mock_allocator_context*)context;

    ctx->allocate_calls.push_back(make_tuple(context, size));

    return ctx->allocate_retval;
}

/**
 * Mock release call.
 */
static void mock_allocator_release(void* context, void* mem)
{
    auto ctx = (mock_allocator_context*)context;

    ctx->release_calls.push_back(make_tuple(context, mem));
}

/**
 * Mock reallocate call.
 */
static void* mock_allocator_reallocate(void* context, void* mem,
    size_t old_size, size_t new_size)
{
    auto ctx = (mock_allocator_context*)context;

    ctx->reallocate_calls.push_back(
        make_tuple(context, mem, old_size, new_size));

    return ctx->reallocate_retval;
}

/**
 * Set the return value for allocator_allocate.
 */
void mock_allocator_allocate_retval(allocator_options_t* options, void* val)
{
    auto ctx = (mock_allocator_context*)options->context;

    ctx->allocate_retval = val;
}

/**
 * Returns true if allocator_allocate was called with the given arguments.
 */
bool mock_allocator_allocate_called(allocator_options_t* options, size_t size)
{
    bool ret = false;
    auto ctx = (mock_allocator_context*)options->context;

    if (ctx->allocate_calls.size() > 0)
    {
        auto call = ctx->allocate_calls.front();

        if (get<0>(call) == options->context && get<1>(call) == size)
        {
            ret = true;
        }

        ctx->allocate_calls.pop_front();
    }

    return ret;
}

/**
 * Returns true if allocator_allocate was called with *ANY* arguments.
 */
bool mock_allocator_allocate_called(allocator_options_t* options)
{
    bool ret = false;
    auto ctx = (mock_allocator_context*)options->context;

    if (ctx->allocate_calls.size() > 0)
    {
        ret = true;
        ctx->allocate_calls.pop_front();
    }

    return ret;
}

/**
 * Returns true if allocator_release was called with the given arguments.
 */
bool mock_allocator_release_called(allocator_options_t* options, void* mem)
{
    bool ret = false;
    auto ctx = (mock_allocator_context*)options->context;

    if (ctx->release_calls.size() > 0)
    {
        auto call = ctx->release_calls.front();

        if (get<0>(call) == options->context && get<1>(call) == mem)
        {
            ret = true;
        }

        ctx->release_calls.pop_front();
    }

    return ret;
}

/**
 * Returns true if allocator_release was called with *ANY* arguments.
 */
bool mock_allocator_release_called(allocator_options_t* options)
{
    bool ret = false;
    auto ctx = (mock_allocator_context*)options->context;

    if (ctx->release_calls.size() > 0)
    {
        ret = true;
        ctx->release_calls.pop_front();
    }

    return ret;
}

/**
 * Set the return value for allocator_reallocate.
 */
void mock_allocator_reallocate_retval(allocator_options_t* options, void* val)
{
    auto ctx = (mock_allocator_context*)options->context;

    ctx->reallocate_retval = val;
}

/**
 * Returns true if allocator_reallocate was called with the given arguments.
 */
bool mock_allocator_reallocate_called(allocator_options_t* options, void* mem,
    size_t old_size, size_t new_size)
{
    bool ret = false;
    auto ctx = (mock_allocator_context*)options->context;

    if (ctx->reallocate_calls.size() > 0)
    {
        auto call = ctx->reallocate_calls.front();

        if (get<0>(call) == options->context && get<1>(call) == mem && get<2>(call) == old_size && get<3>(call) == new_size)
        {
            ret = true;
        }

        ctx->reallocate_calls.pop_front();
    }

    return ret;
}

/**
 * Returns true if allocator_reallocate was called with *ANY* arguments.
 */
bool mock_allocator_reallocate_called(allocator_options_t* options)
{
    bool ret = false;
    auto ctx = (mock_allocator_context*)options->context;

    if (ctx->reallocate_calls.size() > 0)
    {
        ret = true;
        ctx->reallocate_calls.pop_front();
    }

    return ret;
}
