/**
 * \file buffer/vccrypt_buffer_move.c
 *
 * Move the contents of one buffer to the other.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccrypt/buffer.h>
#include <vpr/parameters.h>

/**
 * \brief Initialize a buffer by moving the contents of a second buffer into it.
 *
 * Note: the new buffer is owned by the caller and must be disposed by calling
 * the \ref dispose() method when no longer needed. The old buffer is disposed
 * as part of this process .
 *
 * \param newbuffer the new buffer, initialized from the old buffer.
 * \param oldbuffer the old buffer, disposed by this method.
 */
void
vccrypt_buffer_move(vccrypt_buffer_t* newbuffer, vccrypt_buffer_t* oldbuffer)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != newbuffer);
    MODEL_ASSERT(NULL != oldbuffer);

    /* move values to the new buffer. */
    newbuffer->hdr.dispose = oldbuffer->hdr.dispose;
    newbuffer->alloc_opts = oldbuffer->alloc_opts;
    newbuffer->size = oldbuffer->size;
    newbuffer->data = oldbuffer->data;

    /* set sentry values to indicate to dispose that oldbuffer is not valid. */
    oldbuffer->data = NULL;
    oldbuffer->size = 0U;
}
