/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#ifndef ARGON2_H
#define ARGON2_H

/* Interface */

/* By default the main hashing functions are not exposed. One or more of
 * the following must be defined before including the header file:
 *
 *   #define ARGON2I
 *   #define ARGON2D
 *   #define ARGON2ID
 *
 * Then also defined one or more of the following to enable to raw or
 * encoded functions:
 *
 *   #define ARGON2_RAW
 *   #define ARGON2_ENCODED
 */

#include <stddef.h>
#include <stdint.h>

/*
 * Argon2 input parameter restrictions
 */

/* Minimum and maximum number of lanes (degree of parallelism) */
#define ARGON2_MIN_LANES UINT32_C(1)
#define ARGON2_MAX_LANES UINT32_C(0xFFFFFF)

/* Minimum and maximum number of threads */
#define ARGON2_MIN_THREADS UINT32_C(1)
#define ARGON2_MAX_THREADS UINT32_C(0xFFFFFF)

/* Number of synchronization points between lanes per pass */
#define ARGON2_SYNC_POINTS UINT32_C(4)

/* Minimum and maximum digest size in bytes */
#define ARGON2_MIN_OUTLEN UINT32_C(4)
#define ARGON2_MAX_OUTLEN UINT32_C(0xFFFFFFFF)

/* Minimum and maximum number of memory blocks (each of BLOCK_SIZE bytes) */
#define ARGON2_MIN_MEMORY (2 * ARGON2_SYNC_POINTS) /* 2 blocks per slice */

#define ARGON2_MIN(a, b) ((a) < (b) ? (a) : (b))
/* Max memory size is addressing-space/2, topping at 2^32 blocks (4 TB) */
#define ARGON2_MAX_MEMORY_BITS                                                 \
    ARGON2_MIN(UINT32_C(32), (sizeof(void *) * CHAR_BIT - 10 - 1))
#define ARGON2_MAX_MEMORY                                                      \
    ARGON2_MIN(UINT32_C(0xFFFFFFFF), UINT64_C(1) << ARGON2_MAX_MEMORY_BITS)

/* Minimum and maximum number of passes */
#define ARGON2_MIN_TIME UINT32_C(1)
#define ARGON2_MAX_TIME UINT32_C(0xFFFFFFFF)

/* Minimum and maximum password length in bytes */
#define ARGON2_MIN_PWD_LENGTH UINT32_C(0)
#define ARGON2_MAX_PWD_LENGTH UINT32_C(0xFFFFFFFF)

/* Minimum and maximum associated data length in bytes */
#define ARGON2_MIN_AD_LENGTH UINT32_C(0)
#define ARGON2_MAX_AD_LENGTH UINT32_C(0xFFFFFFFF)

/* Minimum and maximum salt length in bytes */
#define ARGON2_MIN_SALT_LENGTH UINT32_C(8)
#define ARGON2_MAX_SALT_LENGTH UINT32_C(0xFFFFFFFF)

/* Minimum and maximum key length in bytes */
#define ARGON2_MIN_SECRET UINT32_C(0)
#define ARGON2_MAX_SECRET UINT32_C(0xFFFFFFFF)

/* Flags to determine which fields are securely wiped (default = no wipe). */
#define ARGON2_DEFAULT_FLAGS UINT32_C(0)
#define ARGON2_FLAG_CLEAR_PASSWORD (UINT32_C(1) << 0)
#define ARGON2_FLAG_CLEAR_SECRET (UINT32_C(1) << 1)

/* Error codes */
typedef enum Argon2_ErrorCodes {
    ARGON2_OK = 0,

    ARGON2_OUTPUT_PTR_NULL = -1,

    ARGON2_OUTPUT_TOO_SHORT = -2,
    ARGON2_OUTPUT_TOO_LONG = -3,

    ARGON2_PWD_TOO_LONG = -5,

    ARGON2_SALT_TOO_SHORT = -6,
    ARGON2_SALT_TOO_LONG = -7,

    ARGON2_AD_TOO_LONG = -9,

    ARGON2_SECRET_TOO_LONG = -11,

    ARGON2_TIME_TOO_SMALL = -12,
    ARGON2_TIME_TOO_LARGE = -13,

    ARGON2_MEMORY_TOO_LITTLE = -14,
    ARGON2_MEMORY_TOO_MUCH = -15,

    ARGON2_LANES_TOO_FEW = -16,
    ARGON2_LANES_TOO_MANY = -17,

    ARGON2_PWD_PTR_MISMATCH = -18,    /* NULL ptr with non-zero length */
    ARGON2_SALT_PTR_MISMATCH = -19,   /* NULL ptr with non-zero length */
    ARGON2_SECRET_PTR_MISMATCH = -20, /* NULL ptr with non-zero length */
    ARGON2_AD_PTR_MISMATCH = -21,     /* NULL ptr with non-zero length */

    ARGON2_MEMORY_ALLOCATION_ERROR = -22,

    ARGON2_FREE_MEMORY_CBK_NULL = -23,
    ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24,

    ARGON2_INCORRECT_PARAMETER = -25,
    ARGON2_INCORRECT_TYPE = -26,

    ARGON2_OUT_PTR_MISMATCH = -27,

    ARGON2_THREADS_TOO_FEW = -28,
    ARGON2_THREADS_TOO_MANY = -29,

    ARGON2_MISSING_ARGS = -30,

    ARGON2_ENCODING_FAIL = -31,

    ARGON2_DECODING_FAIL = -32,

    ARGON2_THREAD_FAIL = -33,

    ARGON2_DECODING_LENGTH_FAIL = -34,

    ARGON2_VERIFY_MISMATCH = -35
} argon2_error_codes;

/* Memory allocator types --- for external allocation */
typedef int (*allocate_fptr)(uint8_t **memory, size_t bytes_to_allocate);
typedef void (*deallocate_fptr)(uint8_t *memory, size_t bytes_to_allocate);

/* Argon2 external data structures */

/*
 *****
 * Context: structure to hold Argon2 inputs:
 *  output array and its length,
 *  password and its length,
 *  salt and its length,
 *  secret and its length,
 *  associated data and its length,
 *  number of passes, amount of used memory (in KBytes, can be rounded up a bit)
 *  number of parallel threads that will be run.
 * All the parameters above affect the output hash value.
 * Additionally, two function pointers can be provided to allocate and
 * deallocate the memory (if NULL, memory will be allocated internally).
 * Also, three flags indicate whether to erase password, secret as soon as they
 * are pre-hashed (and thus not needed anymore), and the entire memory
 *****
 * Simplest situation: you have output array out[8], password is stored in
 * pwd[32], salt is stored in salt[16], you do not have keys nor associated
 * data. You need to spend 1 GB of RAM and you run 5 passes of Argon2d with
 * 4 parallel lanes.
 * You want to erase the password, but you're OK with last pass not being
 * erased. You want to use the default memory allocator.
 * Then you initialize:
 Argon2_Context(out,8,pwd,32,salt,16,NULL,0,NULL,0,5,1<<20,4,4,NULL,NULL,true,false,false,false)
 */
typedef struct Argon2_Context {
    uint8_t *out;    /* output array */
    uint32_t outlen; /* digest length */

    uint8_t *pwd;    /* password array */
    uint32_t pwdlen; /* password length */

    uint8_t *salt;    /* salt array */
    uint32_t saltlen; /* salt length */

    uint8_t *secret;    /* key array */
    uint32_t secretlen; /* key length */

    uint8_t *ad;    /* associated data array */
    uint32_t adlen; /* associated data length */

    uint32_t t_cost;  /* number of passes */
    uint32_t m_cost;  /* amount of memory requested (KB) */
    uint32_t lanes;   /* number of lanes */
    uint32_t threads; /* maximum number of threads */

    uint32_t version; /* version number */

    allocate_fptr allocate_cbk; /* pointer to memory allocator */
    deallocate_fptr free_cbk;   /* pointer to memory deallocator */

    uint32_t flags; /* array of bool options */
} argon2_context;

/* Argon2 primitive type */
typedef enum Argon2_type {
  Argon2_d = 0,
  Argon2_i = 1,
  Argon2_id = 2
} argon2_type;

/* Version of the algorithm */
typedef enum Argon2_version {
    ARGON2_VERSION_10 = 0x10,
    ARGON2_VERSION_13 = 0x13,
    ARGON2_VERSION_NUMBER = ARGON2_VERSION_13
} argon2_version;

/*
 * Function that gives the string representation of an argon2_type.
 * @param type The argon2_type that we want the string for
 * @param uppercase Whether the string should have the first letter uppercase
 * @return NULL if invalid type, otherwise the string representation.
 */
static const char *
argon2_type2string(argon2_type type, int uppercase);

/*
 * Function that performs memory-hard hashing with certain degree of parallelism
 * @param  context  Pointer to the Argon2 internal structure
 * @return Error code if smth is wrong, ARGON2_OK otherwise
 */
static int
argon2_ctx(argon2_context *context, argon2_type type);

#ifdef ARGON2I
#ifdef ARGON2_ENCODED
/**
 * Hashes a password with Argon2i, producing an encoded hash
 * @param t_cost Number of iterations
 * @param m_cost Sets memory usage to m_cost kibibytes
 * @param parallelism Number of threads and compute lanes
 * @param pwd Pointer to password
 * @param pwdlen Password size in bytes
 * @param salt Pointer to salt
 * @param saltlen Salt size in bytes
 * @param hashlen Desired length of the hash in bytes
 * @param encoded Buffer where to write the encoded hash
 * @param encodedlen Size of the buffer (thus max size of the encoded hash)
 * @pre   Different parallelism levels will give different results
 * @pre   Returns ARGON2_OK if successful
 */
static int
argon2i_hash_encoded(const uint32_t t_cost,
                     const uint32_t m_cost,
                     const uint32_t parallelism,
                     const void *pwd, const size_t pwdlen,
                     const void *salt, const size_t saltlen,
                     const size_t hashlen, char *encoded,
                     const size_t encodedlen);
#endif /* ARGON2_ENCODED */

#ifdef ARGON2_RAW
/**
 * Hashes a password with Argon2i, producing a raw hash at @hash
 * @param t_cost Number of iterations
 * @param m_cost Sets memory usage to m_cost kibibytes
 * @param parallelism Number of threads and compute lanes
 * @param pwd Pointer to password
 * @param pwdlen Password size in bytes
 * @param salt Pointer to salt
 * @param saltlen Salt size in bytes
 * @param hash Buffer where to write the raw hash - updated by the function
 * @param hashlen Desired length of the hash in bytes
 * @pre   Different parallelism levels will give different results
 * @pre   Returns ARGON2_OK if successful
 */
static int
argon2i_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                 const uint32_t parallelism, const void *pwd,
                 const size_t pwdlen, const void *salt,
                 const size_t saltlen, void *hash,
                 const size_t hashlen);
#endif /* ARGON2_RAW */
#endif /* ARGON2I */

#ifdef ARGON2D
#ifdef ARGON2_ENCODED
static int
argon2d_hash_encoded(const uint32_t t_cost,
                     const uint32_t m_cost,
                     const uint32_t parallelism,
                     const void *pwd, const size_t pwdlen,
                     const void *salt, const size_t saltlen,
                     const size_t hashlen, char *encoded,
                     const size_t encodedlen);
#endif /* ARGON2_ENCODED */

#ifdef ARGON2_RAW
static int
argon2d_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                 const uint32_t parallelism, const void *pwd,
                 const size_t pwdlen, const void *salt,
                 const size_t saltlen, void *hash,
                 const size_t hashlen);
#endif /* ARGON2_RAW */
#endif /* ARGON2D */

#ifdef ARGON2ID
#ifdef ARGON2_ENCODED
static int
argon2id_hash_encoded(const uint32_t t_cost,
                      const uint32_t m_cost,
                      const uint32_t parallelism,
                      const void *pwd, const size_t pwdlen,
                      const void *salt, const size_t saltlen,
                      const size_t hashlen, char *encoded,
                      const size_t encodedlen);
#endif /* ARGON2_ENCODED */

#ifdef ARGON2_RAW
static int
argon2id_hash_raw(const uint32_t t_cost,
                  const uint32_t m_cost,
                  const uint32_t parallelism, const void *pwd,
                  const size_t pwdlen, const void *salt,
                  const size_t saltlen, void *hash,
                  const size_t hashlen);
#endif /* ARGON2_RAW */

/* generic function underlying the above ones */
static int
argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
            const uint32_t parallelism, const void *pwd,
            const size_t pwdlen, const void *salt,
            const size_t saltlen, void *hash,
            const size_t hashlen, char *encoded,
            const size_t encodedlen, argon2_type type,
            const uint32_t version);
#endif /* ARGON2ID */

/**
 * Get the associated error message for given error code
 * @return  The error message associated with the given error code
 */
static const char *
argon2_error_message(int error_code);

#if ARGON2_ENCODED
/**
 * Returns the encoded hash length for the given input parameters
 * @param t_cost  Number of iterations
 * @param m_cost  Memory usage in kibibytes
 * @param parallelism  Number of threads; used to compute lanes
 * @param saltlen  Salt size in bytes
 * @param hashlen  Hash size in bytes
 * @param type The argon2_type that we want the encoded length for
 * @return  The encoded hash length in bytes
 */
static size_t
argon2_encodedlen(uint32_t t_cost, uint32_t m_cost,
                  uint32_t parallelism, uint32_t saltlen,
                  uint32_t hashlen, argon2_type type);
#endif /* ARGON2_ENCODED */

/* Implementation */

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define CONST_CAST(x) (x)(uintptr_t)

/**********************Argon2 internal constants*******************************/

enum argon2_core_constants {
    /* Memory block size in bytes */
    ARGON2_BLOCK_SIZE = 1024,
    ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8,
    ARGON2_OWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 16,
    ARGON2_HWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 32,
    ARGON2_512BIT_WORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 64,

    /* Number of pseudo-random values generated by one call to Blake in Argon2i
       to
       generate reference block positions */
    ARGON2_ADDRESSES_IN_BLOCK = 128,

    /* Pre-hashing digest length and its extension*/
    ARGON2_PREHASH_DIGEST_LENGTH = 64,
    ARGON2_PREHASH_SEED_LENGTH = 72
};

/*************************Argon2 internal data types***********************/

/*
 * Structure for the (1KB) memory block implemented as 128 64-bit words.
 * Memory blocks can be copied, XORed. Internal words can be accessed by [] (no
 * bounds checking).
 */
typedef struct block_ { uint64_t v[ARGON2_QWORDS_IN_BLOCK]; } block;

/*****************Functions that work with the block******************/

/* Initialize each byte of the block with @in */
static void
init_block_value(block *b, uint8_t in);

/* Copy block @src to block @dst */
static void
copy_block(block *dst, const block *src);

/* XOR @src onto @dst bytewise */
static void
xor_block(block *dst, const block *src);

/*
 * Argon2 instance: memory pointer, number of passes, amount of memory, type,
 * and derived values.
 * Used to evaluate the number and location of blocks to construct in each
 * thread
 */
typedef struct Argon2_instance_t {
    block *memory;          /* Memory pointer */
    uint32_t version;
    uint32_t passes;        /* Number of passes */
    uint32_t memory_blocks; /* Number of blocks in memory */
    uint32_t segment_length;
    uint32_t lane_length;
    uint32_t lanes;
    uint32_t threads;
    argon2_type type;
    int print_internals; /* whether to print the memory blocks */
    argon2_context *context_ptr; /* points back to original context */
} argon2_instance_t;

/*
 * Argon2 position: where we construct the block right now. Used to distribute
 * work between threads.
 */
typedef struct Argon2_position_t {
    uint32_t pass;
    uint32_t lane;
    uint8_t slice;
    uint32_t index;
} argon2_position_t;

/*Struct that holds the inputs for thread handling FillSegment*/
typedef struct Argon2_thread_data {
    argon2_instance_t *instance_ptr;
    argon2_position_t pos;
} argon2_thread_data;

/*************************Argon2 core functions********************************/

/* Allocates memory to the given pointer, uses the appropriate allocator as
 * specified in the context. Total allocated memory is num*size.
 * @param context argon2_context which specifies the allocator
 * @param memory pointer to the pointer to the memory
 * @param size the size in bytes for each element to be allocated
 * @param num the number of elements to be allocated
 * @return ARGON2_OK if @memory is a valid pointer and memory is allocated
 */
static int
allocate_memory(const argon2_context *context, uint8_t **memory,
                size_t num, size_t size);

/*
 * Frees memory at the given pointer, uses the appropriate deallocator as
 * specified in the context. Also cleans the memory using clear_internal_memory.
 * @param context argon2_context which specifies the deallocator
 * @param memory pointer to buffer to be freed
 * @param size the size in bytes for each element to be deallocated
 * @param num the number of elements to be deallocated
 */
static void
free_memory(const argon2_context *context, uint8_t *memory,
            size_t num, size_t size);

/* Function that securely cleans the memory. This ignores any flags set
 * regarding clearing memory. Usually one just calls clear_internal_memory.
 * @param mem Pointer to the memory
 * @param s Memory size in bytes
 */
static void
secure_wipe_memory(void *v, size_t n);

/* Function that securely clears the memory if FLAG_clear_internal_memory is
 * set. If the flag isn't set, this function does nothing.
 * @param mem Pointer to the memory
 * @param s Memory size in bytes
 */
static void
clear_internal_memory(void *v, size_t n);

/*
 * Computes absolute position of reference block in the lane following a skewed
 * distribution and using a pseudo-random value as input
 * @param instance Pointer to the current instance
 * @param position Pointer to the current position
 * @param pseudo_rand 32-bit pseudo-random value used to determine the position
 * @param same_lane Indicates if the block will be taken from the current lane.
 * If so we can reference the current segment
 * @pre All pointers must be valid
 */
static uint32_t
index_alpha(const argon2_instance_t *instance,
            const argon2_position_t *position, uint32_t pseudo_rand,
            int same_lane);

/*
 * Function that validates all inputs against predefined restrictions and return
 * an error code
 * @param context Pointer to current Argon2 context
 * @return ARGON2_OK if everything is all right, otherwise one of error codes
 * (all defined in <argon2.h>
 */
static int
validate_inputs(const argon2_context *context);

/*
 * Hashes all the inputs into @a blockhash[PREHASH_DIGEST_LENGTH], clears
 * password and secret if needed
 * @param  context  Pointer to the Argon2 internal structure containing memory
 * pointer, and parameters for time and space requirements.
 * @param  blockhash Buffer for pre-hashing digest
 * @param  type Argon2 type
 * @pre    @a blockhash must have at least @a PREHASH_DIGEST_LENGTH bytes
 * allocated
 */
static void
initial_hash(uint8_t *blockhash, argon2_context *context, argon2_type type);

/*
 * Function creates first 2 blocks per lane
 * @param instance Pointer to the current instance
 * @param blockhash Pointer to the pre-hashing digest
 * @pre blockhash must point to @a PREHASH_SEED_LENGTH allocated values
 */
static void
fill_first_blocks(uint8_t *blockhash, const argon2_instance_t *instance);

/*
 * Function allocates memory, hashes the inputs with Blake,  and creates first
 * two blocks. Returns the pointer to the main memory with 2 blocks per lane
 * initialized
 * @param  context  Pointer to the Argon2 internal structure containing memory
 * pointer, and parameters for time and space requirements.
 * @param  instance Current Argon2 instance
 * @return Zero if successful, -1 if memory failed to allocate. @context->state
 * will be modified if successful.
 */
static int
initialize(argon2_instance_t *instance, argon2_context *context);

/*
 * XORing the last block of each lane, hashing it, making the tag. Deallocates
 * the memory.
 * @param context Pointer to current Argon2 context (use only the out parameters
 * from it)
 * @param instance Pointer to current instance of Argon2
 * @pre instance->state must point to necessary amount of memory
 * @pre context->out must point to outlen bytes of memory
 * @pre if context->free_cbk is not NULL, it should point to a function that
 * deallocates memory
 */
static void
finalize(const argon2_context *context, argon2_instance_t *instance);

/*
 * Function that fills the segment using previous segments also from other
 * threads
 * @param context current context
 * @param instance Pointer to the current instance
 * @param position Current position
 * @pre all block pointers must be valid
 */
static void
fill_segment(const argon2_instance_t *instance, argon2_position_t position);

/*
 * Function that fills the entire memory t_cost times based on the first two
 * blocks in each lane
 * @param instance Pointer to the current instance
 * @return ARGON2_OK if successful, @context->state
 */
static int
fill_memory_blocks(argon2_instance_t *instance);

static uint64_t
load64(const void *src)
{
    const uint8_t *p = (const uint8_t *)src;
    uint64_t w = *p++;
    w |= (uint64_t)(*p++) << 8;
    w |= (uint64_t)(*p++) << 16;
    w |= (uint64_t)(*p++) << 24;
    w |= (uint64_t)(*p++) << 32;
    w |= (uint64_t)(*p++) << 40;
    w |= (uint64_t)(*p++) << 48;
    w |= (uint64_t)(*p++) << 56;
    return w;
}

static void
store32(void *dst, uint32_t w)
{
    uint8_t *p = (uint8_t *)dst;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
}

static void
store64(void *dst, uint64_t w)
{
    uint8_t *p = (uint8_t *)dst;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
}

static uint64_t
rotr64(const uint64_t w, const unsigned c)
{
    return (w >> c) | (w << (64 - c));
}

enum blake2b_constant {
    BLAKE2B_BLOCKBYTES = 128,
    BLAKE2B_OUTBYTES = 64,
    BLAKE2B_KEYBYTES = 64,
    BLAKE2B_SALTBYTES = 16,
    BLAKE2B_PERSONALBYTES = 16
};

#pragma pack(push, 1)
typedef struct __blake2b_param {
    uint8_t digest_length;                   /* 1 */
    uint8_t key_length;                      /* 2 */
    uint8_t fanout;                          /* 3 */
    uint8_t depth;                           /* 4 */
    uint32_t leaf_length;                    /* 8 */
    uint64_t node_offset;                    /* 16 */
    uint8_t node_depth;                      /* 17 */
    uint8_t inner_length;                    /* 18 */
    uint8_t reserved[14];                    /* 32 */
    uint8_t salt[BLAKE2B_SALTBYTES];         /* 48 */
    uint8_t personal[BLAKE2B_PERSONALBYTES]; /* 64 */
} blake2b_param;
#pragma pack(pop)

typedef struct __blake2b_state {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[BLAKE2B_BLOCKBYTES];
    unsigned buflen;
    unsigned outlen;
    uint8_t last_node;
} blake2b_state;

/* Ensure param structs have not been wrongly padded */
/* Poor man's static_assert */
enum {
    blake2_size_check_0 = 1 / !!(CHAR_BIT == 8),
    blake2_size_check_2 =
        1 / !!(sizeof(blake2b_param) == sizeof(uint64_t) * CHAR_BIT)
};

/* Streaming API */
static int blake2b_init(blake2b_state *S, size_t outlen);
static int blake2b_init_key(blake2b_state *S, size_t outlen, const void *key,
                     size_t keylen);
static int blake2b_init_param(blake2b_state *S, const blake2b_param *P);
static int blake2b_update(blake2b_state *S, const void *in, size_t inlen);
static int blake2b_final(blake2b_state *S, void *out, size_t outlen);

/* Simple API */
static int blake2b(void *out, size_t outlen, const void *in, size_t inlen,
                         const void *key, size_t keylen);

/* Argon2 Team - Begin Code */
static int blake2b_long(void *out, size_t outlen, const void *in, size_t inlen);
/* Argon2 Team - End Code */

/* designed by the Lyra PHC team */
static uint64_t fBlaMka(uint64_t x, uint64_t y) {
    const uint64_t m = UINT64_C(0xFFFFFFFF);
    const uint64_t xy = (x & m) * (y & m);
    return x + y + 2 * xy;
}

#define G4(a, b, c, d)                                                         \
    do {                                                                       \
        a = fBlaMka(a, b);                                                     \
        d = rotr64(d ^ a, 32);                                                 \
        c = fBlaMka(c, d);                                                     \
        b = rotr64(b ^ c, 24);                                                 \
        a = fBlaMka(a, b);                                                     \
        d = rotr64(d ^ a, 16);                                                 \
        c = fBlaMka(c, d);                                                     \
        b = rotr64(b ^ c, 63);                                                 \
    } while ((void)0, 0)

#define BLAKE2_ROUND_NOMSG(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11,   \
                           v12, v13, v14, v15)                                 \
    do {                                                                       \
        G4(v0, v4, v8, v12);                                                   \
        G4(v1, v5, v9, v13);                                                   \
        G4(v2, v6, v10, v14);                                                  \
        G4(v3, v7, v11, v15);                                                  \
        G4(v0, v5, v10, v15);                                                  \
        G4(v1, v6, v11, v12);                                                  \
        G4(v2, v7, v8, v13);                                                   \
        G4(v3, v4, v9, v14);                                                   \
    } while ((void)0, 0)

#define ARGON2_MAX_DECODED_LANES UINT32_C(255)
#define ARGON2_MIN_DECODED_SALT_LEN UINT32_C(8)
#define ARGON2_MIN_DECODED_OUT_LEN UINT32_C(12)

/*
* encode an Argon2 hash string into the provided buffer. 'dst_len'
* contains the size, in characters, of the 'dst' buffer; if 'dst_len'
* is less than the number of required characters (including the
* terminating 0), then this function returns ARGON2_ENCODING_ERROR.
*
* on success, ARGON2_OK is returned.
*/
static int
encode_string(char *dst, size_t dst_len, argon2_context *ctx,
              argon2_type type);

#ifdef ARGON2_ENCODED
/* Returns the length of the encoded byte stream with length len */
static size_t
b64len(uint32_t len);

/* Returns the length of the encoded number num */
static size_t
numlen(uint32_t num);
#endif /* ARGON2_ENCODED */

/***************Instance and Position constructors**********/
static void
init_block_value(block *b, uint8_t in)
{
    memset(b->v, in, sizeof(b->v));
}

static void
copy_block(block *dst, const block *src)
{
    memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
}

static void
xor_block(block *dst, const block *src)
{
    int i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        dst->v[i] ^= src->v[i];
    }
}

static void
load_block(block *dst, const void *input)
{
    unsigned i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        dst->v[i] = load64((const uint8_t *)input + i * sizeof(dst->v[i]));
    }
}

static void
store_block(void *output, const block *src)
{
    unsigned i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        store64((uint8_t *)output + i * sizeof(src->v[i]), src->v[i]);
    }
}

/***************Memory functions*****************/

static int
allocate_memory(const argon2_context *context, uint8_t **memory,
                size_t num, size_t size)
{
    size_t memory_size = num*size;
    if (memory == NULL) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    /* 1. Check for multiplication overflow */
    if (size != 0 && memory_size / size != num) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    /* 2. Try to allocate with appropriate allocator */
    if (context->allocate_cbk) {
        (context->allocate_cbk)(memory, memory_size);
    } else {
        *memory = malloc(memory_size);
    }

    if (*memory == NULL) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    return ARGON2_OK;
}

static void
free_memory(const argon2_context *context, uint8_t *memory,
            size_t num, size_t size)
{
    size_t memory_size = num*size;
    clear_internal_memory(memory, memory_size);
    if (context->free_cbk) {
        (context->free_cbk)(memory, memory_size);
    } else {
        free(memory);
    }
}

static void
secure_wipe_memory(void *v, size_t n)
{
    static void *(*const volatile memset_sec)(void *, int, size_t) = &memset;
    memset_sec(v, 0, n);
}

/* Memory clear flag defaults to true. */
static void clear_internal_memory(void *v, size_t n)
{
    if (v) {
        secure_wipe_memory(v, n);
    }
}

static void
finalize(const argon2_context *context, argon2_instance_t *instance)
{
    if (context != NULL && instance != NULL) {
        block blockhash;
        uint32_t l;

        copy_block(&blockhash, instance->memory + instance->lane_length - 1);

        /* XOR the last blocks */
        for (l = 1; l < instance->lanes; ++l) {
            uint32_t last_block_in_lane =
                l * instance->lane_length + (instance->lane_length - 1);
            xor_block(&blockhash, instance->memory + last_block_in_lane);
        }

        /* Hash the result */
        {
            uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
            store_block(blockhash_bytes, &blockhash);
            blake2b_long(context->out, context->outlen, blockhash_bytes,
                    ARGON2_BLOCK_SIZE);
            /* clear blockhash and blockhash_bytes */
            clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
            clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
        }

        free_memory(context, (uint8_t *)instance->memory,
                instance->memory_blocks, sizeof(block));
    }
}

static uint32_t
index_alpha(const argon2_instance_t *instance,
        const argon2_position_t *position, uint32_t pseudo_rand,
        int same_lane)
{
    /*
     * Pass 0:
     *      This lane : all already finished segments plus already constructed
     * blocks in this segment
     *      Other lanes : all already finished segments
     * Pass 1+:
     *      This lane : (SYNC_POINTS - 1) last segments plus already constructed
     * blocks in this segment
     *      Other lanes : (SYNC_POINTS - 1) last segments
     */
    uint32_t reference_area_size;
    uint64_t relative_position;
    uint32_t start_position, absolute_position;

    if (0 == position->pass) {
        /* First pass */
        if (0 == position->slice) {
            /* First slice */
            reference_area_size =
                position->index - 1; /* all but the previous */
        } else {
            if (same_lane) {
                /* The same lane => add current segment */
                reference_area_size =
                    position->slice * instance->segment_length +
                    position->index - 1;
            } else {
                reference_area_size =
                    position->slice * instance->segment_length +
                    ((position->index == 0) ? (-1) : 0);
            }
        }
    } else {
        /* Second pass */
        if (same_lane) {
            reference_area_size = instance->lane_length -
                instance->segment_length + position->index -
                1;
        } else {
            reference_area_size = instance->lane_length -
                instance->segment_length +
                ((position->index == 0) ? (-1) : 0);
        }
    }

    /* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
     * relative position */
    relative_position = pseudo_rand;
    relative_position = relative_position * relative_position >> 32;
    relative_position = reference_area_size - 1 -
        (reference_area_size * relative_position >> 32);

    /* 1.2.5 Computing starting position */
    start_position = 0;

    if (0 != position->pass) {
        start_position = (position->slice == ARGON2_SYNC_POINTS - 1)
            ? 0
            : (position->slice + 1) * instance->segment_length;
    }

    /* 1.2.6. Computing absolute position */
    absolute_position = (start_position + relative_position) %
        instance->lane_length; /* absolute position */
    return absolute_position;
}

/* Single-threaded version for p=1 case */
static int
fill_memory_blocks_st(argon2_instance_t *instance)
{
    uint32_t r, s, l;

    for (r = 0; r < instance->passes; ++r) {
        for (s = 0; s < ARGON2_SYNC_POINTS; ++s) {
            for (l = 0; l < instance->lanes; ++l) {
                argon2_position_t position = {r, l, (uint8_t)s, 0};
                fill_segment(instance, position);
            }
        }
    }
    return ARGON2_OK;
}

static int
fill_memory_blocks(argon2_instance_t *instance)
{
    if (instance == NULL || instance->lanes == 0) {
        return ARGON2_INCORRECT_PARAMETER;
    }
    return fill_memory_blocks_st(instance);
}

static int
validate_inputs(const argon2_context *context)
{
    if (NULL == context) {
        return ARGON2_INCORRECT_PARAMETER;
    }

    if (NULL == context->out) {
        return ARGON2_OUTPUT_PTR_NULL;
    }

    /* Validate output length */
    if (ARGON2_MIN_OUTLEN > context->outlen) {
        return ARGON2_OUTPUT_TOO_SHORT;
    }

    if (ARGON2_MAX_OUTLEN < context->outlen) {
        return ARGON2_OUTPUT_TOO_LONG;
    }

    /* Validate password (required param) */
    if (NULL == context->pwd) {
        if (0 != context->pwdlen) {
            return ARGON2_PWD_PTR_MISMATCH;
        }
    }

    if (ARGON2_MAX_PWD_LENGTH < context->pwdlen) {
        return ARGON2_PWD_TOO_LONG;
    }

    /* Validate salt (required param) */
    if (NULL == context->salt) {
        if (0 != context->saltlen) {
            return ARGON2_SALT_PTR_MISMATCH;
        }
    }

    if (ARGON2_MIN_SALT_LENGTH > context->saltlen) {
        return ARGON2_SALT_TOO_SHORT;
    }

    if (ARGON2_MAX_SALT_LENGTH < context->saltlen) {
        return ARGON2_SALT_TOO_LONG;
    }

    /* Validate secret (optional param) */
    if (NULL == context->secret) {
        if (0 != context->secretlen) {
            return ARGON2_SECRET_PTR_MISMATCH;
        }
    } else {
        if (ARGON2_MAX_SECRET < context->secretlen) {
            return ARGON2_SECRET_TOO_LONG;
        }
    }

    /* Validate associated data (optional param) */
    if (NULL == context->ad) {
        if (0 != context->adlen) {
            return ARGON2_AD_PTR_MISMATCH;
        }
    } else {
        if (ARGON2_MAX_AD_LENGTH < context->adlen) {
            return ARGON2_AD_TOO_LONG;
        }
    }

    /* Validate memory cost */
    if (ARGON2_MIN_MEMORY > context->m_cost) {
        return ARGON2_MEMORY_TOO_LITTLE;
    }

    if (ARGON2_MAX_MEMORY < context->m_cost) {
        return ARGON2_MEMORY_TOO_MUCH;
    }

    if (context->m_cost < 8 * context->lanes) {
        return ARGON2_MEMORY_TOO_LITTLE;
    }

    /* Validate time cost */
    if (ARGON2_MIN_TIME > context->t_cost) {
        return ARGON2_TIME_TOO_SMALL;
    }

    if (ARGON2_MAX_TIME < context->t_cost) {
        return ARGON2_TIME_TOO_LARGE;
    }

    /* Validate lanes */
    if (ARGON2_MIN_LANES > context->lanes) {
        return ARGON2_LANES_TOO_FEW;
    }

    if (ARGON2_MAX_LANES < context->lanes) {
        return ARGON2_LANES_TOO_MANY;
    }

    /* Validate threads */
    if (ARGON2_MIN_THREADS > context->threads) {
        return ARGON2_THREADS_TOO_FEW;
    }

    if (ARGON2_MAX_THREADS < context->threads) {
        return ARGON2_THREADS_TOO_MANY;
    }

    if (NULL != context->allocate_cbk && NULL == context->free_cbk) {
        return ARGON2_FREE_MEMORY_CBK_NULL;
    }

    if (NULL == context->allocate_cbk && NULL != context->free_cbk) {
        return ARGON2_ALLOCATE_MEMORY_CBK_NULL;
    }

    return ARGON2_OK;
}

static void
fill_first_blocks(uint8_t *blockhash, const argon2_instance_t *instance)
{
    uint32_t l;
    /* Make the first and second block in each lane as G(H0||0||i) or
       G(H0||1||i) */
    uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
    for (l = 0; l < instance->lanes; ++l) {

        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0);
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH + 4, l);
        blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash,
                ARGON2_PREHASH_SEED_LENGTH);
        load_block(&instance->memory[l * instance->lane_length + 0],
                blockhash_bytes);

        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 1);
        blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash,
                ARGON2_PREHASH_SEED_LENGTH);
        load_block(&instance->memory[l * instance->lane_length + 1],
                blockhash_bytes);
    }
    clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
}

static void
initial_hash(uint8_t *blockhash, argon2_context *context, argon2_type type)
{
    blake2b_state BlakeHash;
    uint8_t value[sizeof(uint32_t)];

    if (NULL == context || NULL == blockhash) {
        return;
    }

    blake2b_init(&BlakeHash, ARGON2_PREHASH_DIGEST_LENGTH);

    store32(&value, context->lanes);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->outlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->m_cost);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->t_cost);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->version);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, (uint32_t)type);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->pwdlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->pwd != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t *)context->pwd,
                context->pwdlen);

        if (context->flags & ARGON2_FLAG_CLEAR_PASSWORD) {
            secure_wipe_memory(context->pwd, context->pwdlen);
            context->pwdlen = 0;
        }
    }

    store32(&value, context->saltlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->salt != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t *)context->salt,
                context->saltlen);
    }

    store32(&value, context->secretlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->secret != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t *)context->secret,
                context->secretlen);

        if (context->flags & ARGON2_FLAG_CLEAR_SECRET) {
            secure_wipe_memory(context->secret, context->secretlen);
            context->secretlen = 0;
        }
    }

    store32(&value, context->adlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->ad != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t *)context->ad,
                context->adlen);
    }

    blake2b_final(&BlakeHash, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
}

static int
initialize(argon2_instance_t *instance, argon2_context *context)
{
    uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];
    int result = ARGON2_OK;

    if (instance == NULL || context == NULL)
        return ARGON2_INCORRECT_PARAMETER;
    instance->context_ptr = context;

    /* 1. Memory allocation */
    result = allocate_memory(context, (uint8_t **)&(instance->memory),
            instance->memory_blocks, sizeof(block));
    if (result != ARGON2_OK) {
        return result;
    }

    /* 2. Initial hashing */
    /* H_0 + 8 extra bytes to produce the first blocks */
    /* uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH]; */
    /* Hashing all inputs */
    initial_hash(blockhash, context, instance->type);
    /* Zeroing 8 extra bytes */
    clear_internal_memory(blockhash + ARGON2_PREHASH_DIGEST_LENGTH,
            ARGON2_PREHASH_SEED_LENGTH -
            ARGON2_PREHASH_DIGEST_LENGTH);

    /* 3. Creating first blocks, we always have at least two blocks in a slice
    */
    fill_first_blocks(blockhash, instance);
    /* Clearing the hash */
    clear_internal_memory(blockhash, ARGON2_PREHASH_SEED_LENGTH);

    return ARGON2_OK;
}

static const uint64_t blake2b_IV[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)};

static const unsigned int blake2b_sigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

static void
blake2b_set_lastnode(blake2b_state *S)
{
    S->f[1] = (uint64_t)-1;
}

static void
blake2b_set_lastblock(blake2b_state *S)
{
    if (S->last_node) {
        blake2b_set_lastnode(S);
    }
    S->f[0] = (uint64_t)-1;
}

static void
blake2b_increment_counter(blake2b_state *S, uint64_t inc)
{
    S->t[0] += inc;
    S->t[1] += (S->t[0] < inc);
}

static void
blake2b_invalidate_state(blake2b_state *S)
{
    clear_internal_memory(S, sizeof(*S));      /* wipe */
    blake2b_set_lastblock(S); /* invalidate for further use */
}

static void
blake2b_init0(blake2b_state *S)
{
    memset(S, 0, sizeof(*S));
    memcpy(S->h, blake2b_IV, sizeof(S->h));
}

static int
blake2b_init_param(blake2b_state *S, const blake2b_param *P)
{
    const unsigned char *p = (const unsigned char *)P;
    unsigned int i;

    if (NULL == P || NULL == S) {
        return -1;
    }

    blake2b_init0(S);
    /* IV XOR Parameter Block */
    for (i = 0; i < 8; ++i) {
        S->h[i] ^= load64(&p[i * sizeof(S->h[i])]);
    }
    S->outlen = P->digest_length;
    return 0;
}

/* Sequential blake2b initialization */
static int
blake2b_init(blake2b_state *S, size_t outlen)
{
    blake2b_param P;

    if (S == NULL) {
        return -1;
    }

    if ((outlen == 0) || (outlen > BLAKE2B_OUTBYTES)) {
        blake2b_invalidate_state(S);
        return -1;
    }

    /* Setup Parameter Block for unkeyed BLAKE2 */
    P.digest_length = (uint8_t)outlen;
    P.key_length = 0;
    P.fanout = 1;
    P.depth = 1;
    P.leaf_length = 0;
    P.node_offset = 0;
    P.node_depth = 0;
    P.inner_length = 0;
    memset(P.reserved, 0, sizeof(P.reserved));
    memset(P.salt, 0, sizeof(P.salt));
    memset(P.personal, 0, sizeof(P.personal));

    return blake2b_init_param(S, &P);
}

static int
blake2b_init_key(blake2b_state *S, size_t outlen,
                 const void *key, size_t keylen)
{
    blake2b_param P;

    if (S == NULL) {
        return -1;
    }

    if ((outlen == 0) || (outlen > BLAKE2B_OUTBYTES)) {
        blake2b_invalidate_state(S);
        return -1;
    }

    if ((key == 0) || (keylen == 0) || (keylen > BLAKE2B_KEYBYTES)) {
        blake2b_invalidate_state(S);
        return -1;
    }

    /* Setup Parameter Block for keyed BLAKE2 */
    P.digest_length = (uint8_t)outlen;
    P.key_length = (uint8_t)keylen;
    P.fanout = 1;
    P.depth = 1;
    P.leaf_length = 0;
    P.node_offset = 0;
    P.node_depth = 0;
    P.inner_length = 0;
    memset(P.reserved, 0, sizeof(P.reserved));
    memset(P.salt, 0, sizeof(P.salt));
    memset(P.personal, 0, sizeof(P.personal));

    if (blake2b_init_param(S, &P) < 0) {
        blake2b_invalidate_state(S);
        return -1;
    }

    {
        uint8_t block[BLAKE2B_BLOCKBYTES];
        memset(block, 0, BLAKE2B_BLOCKBYTES);
        memcpy(block, key, keylen);
        blake2b_update(S, block, BLAKE2B_BLOCKBYTES);
        /* Burn the key from stack */
        clear_internal_memory(block, BLAKE2B_BLOCKBYTES);
    }
    return 0;
}

static void
blake2b_compress(blake2b_state *S, const uint8_t *block)
{
    uint64_t m[16];
    uint64_t v[16];
    unsigned int i, r;

    for (i = 0; i < 16; ++i) {
        m[i] = load64(block + i * sizeof(m[i]));
    }

    for (i = 0; i < 8; ++i) {
        v[i] = S->h[i];
    }

    v[8] = blake2b_IV[0];
    v[9] = blake2b_IV[1];
    v[10] = blake2b_IV[2];
    v[11] = blake2b_IV[3];
    v[12] = blake2b_IV[4] ^ S->t[0];
    v[13] = blake2b_IV[5] ^ S->t[1];
    v[14] = blake2b_IV[6] ^ S->f[0];
    v[15] = blake2b_IV[7] ^ S->f[1];

#define G6(r, i, a, b, c, d)                                                   \
    do {                                                                       \
        a = a + b + m[blake2b_sigma[r][2 * i + 0]];                            \
        d = rotr64(d ^ a, 32);                                                 \
        c = c + d;                                                             \
        b = rotr64(b ^ c, 24);                                                 \
        a = a + b + m[blake2b_sigma[r][2 * i + 1]];                            \
        d = rotr64(d ^ a, 16);                                                 \
        c = c + d;                                                             \
        b = rotr64(b ^ c, 63);                                                 \
    } while ((void)0, 0)

#define ROUND(r)                                                               \
    do {                                                                       \
        G6(r, 0, v[0], v[4], v[8], v[12]);                                     \
        G6(r, 1, v[1], v[5], v[9], v[13]);                                     \
        G6(r, 2, v[2], v[6], v[10], v[14]);                                    \
        G6(r, 3, v[3], v[7], v[11], v[15]);                                    \
        G6(r, 4, v[0], v[5], v[10], v[15]);                                    \
        G6(r, 5, v[1], v[6], v[11], v[12]);                                    \
        G6(r, 6, v[2], v[7], v[8], v[13]);                                     \
        G6(r, 7, v[3], v[4], v[9], v[14]);                                     \
    } while ((void)0, 0)

    for (r = 0; r < 12; ++r) {
        ROUND(r);
    }

    for (i = 0; i < 8; ++i) {
        S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
    }

#undef G6
#undef ROUND
}

static int
blake2b_update(blake2b_state *S, const void *in, size_t inlen)
{
    const uint8_t *pin = (const uint8_t *)in;

    if (inlen == 0) {
        return 0;
    }

    /* Sanity check */
    if (S == NULL || in == NULL) {
        return -1;
    }

    /* Is this a reused state? */
    if (S->f[0] != 0) {
        return -1;
    }

    if (S->buflen + inlen > BLAKE2B_BLOCKBYTES) {
        /* Complete current block */
        size_t left = S->buflen;
        size_t fill = BLAKE2B_BLOCKBYTES - left;
        memcpy(&S->buf[left], pin, fill);
        blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
        blake2b_compress(S, S->buf);
        S->buflen = 0;
        inlen -= fill;
        pin += fill;
        /* Avoid buffer copies when possible */
        while (inlen > BLAKE2B_BLOCKBYTES) {
            blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
            blake2b_compress(S, pin);
            inlen -= BLAKE2B_BLOCKBYTES;
            pin += BLAKE2B_BLOCKBYTES;
        }
    }
    memcpy(&S->buf[S->buflen], pin, inlen);
    S->buflen += (unsigned int)inlen;
    return 0;
}

static int
blake2b_final(blake2b_state *S, void *out, size_t outlen)
{
    uint8_t buffer[BLAKE2B_OUTBYTES] = {0};
    unsigned int i;

    /* Sanity checks */
    if (S == NULL || out == NULL || outlen < S->outlen) {
        return -1;
    }

    /* Is this a reused state? */
    if (S->f[0] != 0) {
        return -1;
    }

    blake2b_increment_counter(S, S->buflen);
    blake2b_set_lastblock(S);
    memset(&S->buf[S->buflen], 0, BLAKE2B_BLOCKBYTES - S->buflen); /* Padding */
    blake2b_compress(S, S->buf);

    for (i = 0; i < 8; ++i) { /* Output full hash to temp buffer */
        store64(buffer + sizeof(S->h[i]) * i, S->h[i]);
    }

    memcpy(out, buffer, S->outlen);
    clear_internal_memory(buffer, sizeof(buffer));
    clear_internal_memory(S->buf, sizeof(S->buf));
    clear_internal_memory(S->h, sizeof(S->h));
    return 0;
}

static int
blake2b(void *out, size_t outlen, const void *in, size_t inlen,
        const void *key, size_t keylen)
{
    blake2b_state S;
    int ret = -1;

    /* Verify parameters */
    if (NULL == in && inlen > 0) {
        goto fail;
    }

    if (NULL == out || outlen == 0 || outlen > BLAKE2B_OUTBYTES) {
        goto fail;
    }

    if ((NULL == key && keylen > 0) || keylen > BLAKE2B_KEYBYTES) {
        goto fail;
    }

    if (keylen > 0) {
        if (blake2b_init_key(&S, outlen, key, keylen) < 0) {
            goto fail;
        }
    } else {
        if (blake2b_init(&S, outlen) < 0) {
            goto fail;
        }
    }

    if (blake2b_update(&S, in, inlen) < 0) {
        goto fail;
    }
    ret = blake2b_final(&S, out, outlen);

fail:
    clear_internal_memory(&S, sizeof(S));
    return ret;
}

/* Argon2 Team - Begin Code */
static int
blake2b_long(void *pout, size_t outlen, const void *in, size_t inlen)
{
    uint8_t *out = (uint8_t *)pout;
    blake2b_state blake_state;
    uint8_t outlen_bytes[sizeof(uint32_t)] = {0};
    int ret = -1;

    if (outlen > UINT32_MAX) {
        goto fail;
    }

    /* Ensure little-endian byte order! */
    store32(outlen_bytes, (uint32_t)outlen);

#define TRY(statement)                                                         \
    do {                                                                       \
        ret = statement;                                                       \
        if (ret < 0) {                                                         \
            goto fail;                                                         \
        }                                                                      \
    } while ((void)0, 0)

    if (outlen <= BLAKE2B_OUTBYTES) {
        TRY(blake2b_init(&blake_state, outlen));
        TRY(blake2b_update(&blake_state, outlen_bytes, sizeof(outlen_bytes)));
        TRY(blake2b_update(&blake_state, in, inlen));
        TRY(blake2b_final(&blake_state, out, outlen));
    } else {
        uint32_t toproduce;
        uint8_t out_buffer[BLAKE2B_OUTBYTES];
        uint8_t in_buffer[BLAKE2B_OUTBYTES];
        TRY(blake2b_init(&blake_state, BLAKE2B_OUTBYTES));
        TRY(blake2b_update(&blake_state, outlen_bytes, sizeof(outlen_bytes)));
        TRY(blake2b_update(&blake_state, in, inlen));
        TRY(blake2b_final(&blake_state, out_buffer, BLAKE2B_OUTBYTES));
        memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
        out += BLAKE2B_OUTBYTES / 2;
        toproduce = (uint32_t)outlen - BLAKE2B_OUTBYTES / 2;

        while (toproduce > BLAKE2B_OUTBYTES) {
            memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
            TRY(blake2b(out_buffer, BLAKE2B_OUTBYTES, in_buffer,
                        BLAKE2B_OUTBYTES, NULL, 0));
            memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
            out += BLAKE2B_OUTBYTES / 2;
            toproduce -= BLAKE2B_OUTBYTES / 2;
        }

        memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
        TRY(blake2b(out_buffer, toproduce, in_buffer, BLAKE2B_OUTBYTES, NULL,
                    0));
        memcpy(out, out_buffer, toproduce);
    }
fail:
    clear_internal_memory(&blake_state, sizeof(blake_state));
    return ret;
#undef TRY
}
/* Argon2 Team - End Code */

/*
 * Function fills a new memory block and optionally XORs the old block over the new one.
 * @next_block must be initialized.
 * @param prev_block Pointer to the previous block
 * @param ref_block Pointer to the reference block
 * @param next_block Pointer to the block to be constructed
 * @param with_xor Whether to XOR into the new block (1) or just overwrite (0)
 * @pre all block pointers must be valid
 */
static void
fill_block(const block *prev_block, const block *ref_block,
        block *next_block, int with_xor)
{
    block blockR, block_tmp;
    unsigned i;

    copy_block(&blockR, ref_block);
    xor_block(&blockR, prev_block);
    copy_block(&block_tmp, &blockR);
    /* Now blockR = ref_block + prev_block and block_tmp = ref_block + prev_block */
    if (with_xor) {
        /* Saving the next block contents for XOR over: */
        xor_block(&block_tmp, next_block);
        /* Now blockR = ref_block + prev_block and
           block_tmp = ref_block + prev_block + next_block */
    }

    /* Apply Blake2 on columns of 64-bit words: (0,1,...,15) , then
       (16,17,..31)... finally (112,113,...127) */
    for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND_NOMSG(
                blockR.v[16 * i], blockR.v[16 * i + 1], blockR.v[16 * i + 2],
                blockR.v[16 * i + 3], blockR.v[16 * i + 4], blockR.v[16 * i + 5],
                blockR.v[16 * i + 6], blockR.v[16 * i + 7], blockR.v[16 * i + 8],
                blockR.v[16 * i + 9], blockR.v[16 * i + 10], blockR.v[16 * i + 11],
                blockR.v[16 * i + 12], blockR.v[16 * i + 13], blockR.v[16 * i + 14],
                blockR.v[16 * i + 15]);
    }

    /* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), then
       (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */
    for (i = 0; i < 8; i++) {
        BLAKE2_ROUND_NOMSG(
                blockR.v[2 * i], blockR.v[2 * i + 1], blockR.v[2 * i + 16],
                blockR.v[2 * i + 17], blockR.v[2 * i + 32], blockR.v[2 * i + 33],
                blockR.v[2 * i + 48], blockR.v[2 * i + 49], blockR.v[2 * i + 64],
                blockR.v[2 * i + 65], blockR.v[2 * i + 80], blockR.v[2 * i + 81],
                blockR.v[2 * i + 96], blockR.v[2 * i + 97], blockR.v[2 * i + 112],
                blockR.v[2 * i + 113]);
    }

    copy_block(next_block, &block_tmp);
    xor_block(next_block, &blockR);
}

static void
next_addresses(block *address_block, block *input_block,
        const block *zero_block)
{
    input_block->v[6]++;
    fill_block(zero_block, input_block, address_block, 0);
    fill_block(zero_block, address_block, address_block, 0);
}

static void
fill_segment(const argon2_instance_t *instance,
        argon2_position_t position)
{
    block *ref_block = NULL, *curr_block = NULL;
    block address_block, input_block, zero_block;
    uint64_t pseudo_rand, ref_index, ref_lane;
    uint32_t prev_offset, curr_offset;
    uint32_t starting_index;
    uint32_t i;
    int data_independent_addressing;

    if (instance == NULL) {
        return;
    }

    data_independent_addressing =
        (instance->type == Argon2_i) ||
        (instance->type == Argon2_id && (position.pass == 0) &&
         (position.slice < ARGON2_SYNC_POINTS / 2));

    if (data_independent_addressing) {
        init_block_value(&zero_block, 0);
        init_block_value(&input_block, 0);

        input_block.v[0] = position.pass;
        input_block.v[1] = position.lane;
        input_block.v[2] = position.slice;
        input_block.v[3] = instance->memory_blocks;
        input_block.v[4] = instance->passes;
        input_block.v[5] = instance->type;
    }

    starting_index = 0;

    if ((0 == position.pass) && (0 == position.slice)) {
        starting_index = 2; /* we have already generated the first two blocks */

        /* Don't forget to generate the first block of addresses: */
        if (data_independent_addressing) {
            next_addresses(&address_block, &input_block, &zero_block);
        }
    }

    /* Offset of the current block */
    curr_offset = position.lane * instance->lane_length +
        position.slice * instance->segment_length + starting_index;

    if (0 == curr_offset % instance->lane_length) {
        /* Last block in this lane */
        prev_offset = curr_offset + instance->lane_length - 1;
    } else {
        /* Previous block */
        prev_offset = curr_offset - 1;
    }

    for (i = starting_index; i < instance->segment_length;
            ++i, ++curr_offset, ++prev_offset) {
        /*1.1 Rotating prev_offset if needed */
        if (curr_offset % instance->lane_length == 1) {
            prev_offset = curr_offset - 1;
        }

        /* 1.2 Computing the index of the reference block */
        /* 1.2.1 Taking pseudo-random value from the previous block */
        if (data_independent_addressing) {
            if (i % ARGON2_ADDRESSES_IN_BLOCK == 0) {
                next_addresses(&address_block, &input_block, &zero_block);
            }
            pseudo_rand = address_block.v[i % ARGON2_ADDRESSES_IN_BLOCK];
        } else {
            pseudo_rand = instance->memory[prev_offset].v[0];
        }

        /* 1.2.2 Computing the lane of the reference block */
        ref_lane = ((pseudo_rand >> 32)) % instance->lanes;

        if ((position.pass == 0) && (position.slice == 0)) {
            /* Can not reference other lanes yet */
            ref_lane = position.lane;
        }

        /* 1.2.3 Computing the number of possible reference block within the
         * lane.
         */
        position.index = i;
        ref_index = index_alpha(instance, &position, pseudo_rand & 0xFFFFFFFF,
                ref_lane == position.lane);

        /* 2 Creating a new block */
        ref_block =
            instance->memory + instance->lane_length * ref_lane + ref_index;
        curr_block = instance->memory + curr_offset;
        if (ARGON2_VERSION_10 == instance->version) {
            /* version 1.2.1 and earlier: overwrite, not XOR */
            fill_block(instance->memory + prev_offset, ref_block, curr_block, 0);
        } else {
            if(0 == position.pass) {
                fill_block(instance->memory + prev_offset, ref_block,
                        curr_block, 0);
            } else {
                fill_block(instance->memory + prev_offset, ref_block,
                        curr_block, 1);
            }
        }
    }
}

/*
 * Example code for a decoder and encoder of "hash strings", with Argon2
 * parameters.
 *
 * This code comprises three sections:
 *
 *   -- The first section contains generic Base64 encoding and decoding
 *   functions. It is conceptually applicable to any hash function
 *   implementation that uses Base64 to encode and decode parameters,
 *   salts and outputs. It could be made into a library, provided that
 *   the relevant functions are made public (non-static) and be given
 *   reasonable names to avoid collisions with other functions.
 *
 *   -- The second section is specific to Argon2. It encodes and decodes
 *   the parameters, salts and outputs. It does not compute the hash
 *   itself.
 *
 * The code was originally written by Thomas Pornin <pornin@bolet.org>,
 * to whom comments and remarks may be sent. It is released under what
 * should amount to Public Domain or its closest equivalent; the
 * following mantra is supposed to incarnate that fact with all the
 * proper legal rituals:
 *
 * ---------------------------------------------------------------------
 * This file is provided under the terms of Creative Commons CC0 1.0
 * Public Domain Dedication. To the extent possible under law, the
 * author (Thomas Pornin) has waived all copyright and related or
 * neighboring rights to this file. This work is published from: Canada.
 * ---------------------------------------------------------------------
 *
 * Copyright (c) 2015 Thomas Pornin
 */

/* ==================================================================== */
/*
 * Common code; could be shared between different hash functions.
 *
 * Note: the Base64 functions below assume that uppercase letters (resp.
 * lowercase letters) have consecutive numerical codes, that fit on 8
 * bits. All modern systems use ASCII-compatible charsets, where these
 * properties are true. If you are stuck with a dinosaur of a system
 * that still defaults to EBCDIC then you already have much bigger
 * interoperability issues to deal with.
 */

/*
 * Some macros for constant-time comparisons. These work over values in
 * the 0..255 range. Returned value is 0x00 on "false", 0xFF on "true".
 */
#define EQ(x, y) ((((0U - ((unsigned)(x) ^ (unsigned)(y))) >> 8) & 0xFF) ^ 0xFF)
#define GT(x, y) ((((unsigned)(y) - (unsigned)(x)) >> 8) & 0xFF)
#define GE(x, y) (GT(y, x) ^ 0xFF)
#define LT(x, y) GT(y, x)
#define LE(x, y) GE(y, x)

/*
 * Convert value x (0..63) to corresponding Base64 character.
 */
static int
b64_byte_to_char(unsigned x)
{
    return (LT(x, 26) & (x + 'A')) |
        (GE(x, 26) & LT(x, 52) & (x + ('a' - 26))) |
        (GE(x, 52) & LT(x, 62) & (x + ('0' - 52))) | (EQ(x, 62) & '+') |
        (EQ(x, 63) & '/');
}

/*
 * Convert some bytes to Base64. 'dst_len' is the length (in characters)
 * of the output buffer 'dst'; if that buffer is not large enough to
 * receive the result (including the terminating 0), then (size_t)-1
 * is returned. Otherwise, the zero-terminated Base64 string is written
 * in the buffer, and the output length (counted WITHOUT the terminating
 * zero) is returned.
 */
static size_t
to_base64(char *dst, size_t dst_len, const void *src,
        size_t src_len)
{
    size_t olen;
    const unsigned char *buf;
    unsigned acc, acc_len;

    olen = (src_len / 3) << 2;
    switch (src_len % 3) {
        case 2:
            olen++;
            /* fall through */
        case 1:
            olen += 2;
            break;
    }
    if (dst_len <= olen) {
        return (size_t)-1;
    }
    acc = 0;
    acc_len = 0;
    buf = (const unsigned char *)src;
    while (src_len-- > 0) {
        acc = (acc << 8) + (*buf++);
        acc_len += 8;
        while (acc_len >= 6) {
            acc_len -= 6;
            *dst++ = (char)b64_byte_to_char((acc >> acc_len) & 0x3F);
        }
    }
    if (acc_len > 0) {
        *dst++ = (char)b64_byte_to_char((acc << (6 - acc_len)) & 0x3F);
    }
    *dst++ = 0;
    return olen;
}

/* ==================================================================== */
/*
 * Code specific to Argon2.
 *
 * The code below applies the following format:
 *
 *  $argon2<T>[$v=<num>]$m=<num>,t=<num>,p=<num>$<bin>$<bin>
 *
 * where <T> is either 'd', 'id', or 'i', <num> is a decimal integer (positive,
 * fits in an 'unsigned long'), and <bin> is Base64-encoded data (no '=' padding
 * characters, no newline or whitespace).
 *
 * The last two binary chunks (encoded in Base64) are, in that order,
 * the salt and the output. Both are required. The binary salt length and the
 * output length must be in the allowed ranges defined in argon2.h.
 *
 * The ctx struct must contain buffers large enough to hold the salt and pwd
 * when it is fed into decode_string.
 */

static int
encode_string(char *dst, size_t dst_len, argon2_context *ctx,
        argon2_type type)
{
#define SS1(str)                                                                \
    do {                                                                       \
        size_t pp_len = strlen(str);                                           \
        if (pp_len >= dst_len) {                                               \
            return ARGON2_ENCODING_FAIL;                                       \
        }                                                                      \
        memcpy(dst, str, pp_len + 1);                                          \
        dst += pp_len;                                                         \
        dst_len -= pp_len;                                                     \
    } while ((void)0, 0)

#define SX(x)                                                                  \
    do {                                                                       \
        char tmp[30];                                                          \
        sprintf(tmp, "%lu", (unsigned long)(x));                               \
        SS1(tmp);                                                               \
    } while ((void)0, 0)

#define SB(buf, len)                                                           \
    do {                                                                       \
        size_t sb_len = to_base64(dst, dst_len, buf, len);                     \
        if (sb_len == (size_t)-1) {                                            \
            return ARGON2_ENCODING_FAIL;                                       \
        }                                                                      \
        dst += sb_len;                                                         \
        dst_len -= sb_len;                                                     \
    } while ((void)0, 0)

    const char* type_string = argon2_type2string(type, 0);
    int validation_result = validate_inputs(ctx);

    if (!type_string) {
        return ARGON2_ENCODING_FAIL;
    }

    if (validation_result != ARGON2_OK) {
        return validation_result;
    }

    SS1("$");
    SS1(type_string);

    SS1("$v=");
    SX(ctx->version);

    SS1("$m=");
    SX(ctx->m_cost);
    SS1(",t=");
    SX(ctx->t_cost);
    SS1(",p=");
    SX(ctx->lanes);

    SS1("$");
    SB(ctx->salt, ctx->saltlen);

    SS1("$");
    SB(ctx->out, ctx->outlen);
    return ARGON2_OK;

#undef SS1
#undef SX
#undef SB
}

#ifdef ARGON2_ENCODED
static size_t
b64len(uint32_t len)
{
    size_t olen = ((size_t)len / 3) << 2;

    switch (len % 3) {
        case 2:
            olen++;
            /* fall through */
        case 1:
            olen += 2;
            break;
    }

    return olen;
}

static size_t
numlen(uint32_t num)
{
    size_t len = 1;
    while (num >= 10) {
        ++len;
        num = num / 10;
    }
    return len;
}
#endif /* ARGON2_ENCODED */

static const char *
argon2_type2string(argon2_type type, int uppercase)
{
    switch (type) {
        case Argon2_d:
            return uppercase ? "Argon2d" : "argon2d";
        case Argon2_i:
            return uppercase ? "Argon2i" : "argon2i";
        case Argon2_id:
            return uppercase ? "Argon2id" : "argon2id";
    }

    return NULL;
}

static int
argon2_ctx(argon2_context *context, argon2_type type)
{
    /* 1. Validate all inputs */
    int result = validate_inputs(context);
    uint32_t memory_blocks, segment_length;
    argon2_instance_t instance;

    if (ARGON2_OK != result) {
        return result;
    }

    if (Argon2_d != type && Argon2_i != type && Argon2_id != type) {
        return ARGON2_INCORRECT_TYPE;
    }

    /* 2. Align memory size */
    /* Minimum memory_blocks = 8L blocks, where L is the number of lanes */
    memory_blocks = context->m_cost;

    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * context->lanes) {
        memory_blocks = 2 * ARGON2_SYNC_POINTS * context->lanes;
    }

    segment_length = memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
    /* Ensure that all segments have equal length */
    memory_blocks = segment_length * (context->lanes * ARGON2_SYNC_POINTS);

    instance.version = context->version;
    instance.memory = NULL;
    instance.passes = context->t_cost;
    instance.memory_blocks = memory_blocks;
    instance.segment_length = segment_length;
    instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
    instance.lanes = context->lanes;
    instance.threads = context->threads;
    instance.type = type;

    if (instance.threads > instance.lanes) {
        instance.threads = instance.lanes;
    }

    /* 3. Initialization: Hashing inputs, allocating memory, filling first
     * blocks
     */
    result = initialize(&instance, context);

    if (ARGON2_OK != result) {
        return result;
    }

    /* 4. Filling memory */
    result = fill_memory_blocks(&instance);

    if (ARGON2_OK != result) {
        return result;
    }
    /* 5. Finalization */
    finalize(context, &instance);

    return ARGON2_OK;
}

static int
argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
        const uint32_t parallelism, const void *pwd,
        const size_t pwdlen, const void *salt, const size_t saltlen,
        void *hash, const size_t hashlen, char *encoded,
        const size_t encodedlen, argon2_type type,
        const uint32_t version)
{

    argon2_context context;
    int result;
    uint8_t *out;

    if (pwdlen > ARGON2_MAX_PWD_LENGTH) {
        return ARGON2_PWD_TOO_LONG;
    }

    if (saltlen > ARGON2_MAX_SALT_LENGTH) {
        return ARGON2_SALT_TOO_LONG;
    }

    if (hashlen > ARGON2_MAX_OUTLEN) {
        return ARGON2_OUTPUT_TOO_LONG;
    }

    if (hashlen < ARGON2_MIN_OUTLEN) {
        return ARGON2_OUTPUT_TOO_SHORT;
    }

    out = malloc(hashlen);
    if (!out) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    context.out = (uint8_t *)out;
    context.outlen = (uint32_t)hashlen;
    context.pwd = CONST_CAST(uint8_t *)pwd;
    context.pwdlen = (uint32_t)pwdlen;
    context.salt = CONST_CAST(uint8_t *)salt;
    context.saltlen = (uint32_t)saltlen;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = parallelism;
    context.threads = parallelism;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;
    context.version = version;

    result = argon2_ctx(&context, type);

    if (result != ARGON2_OK) {
        clear_internal_memory(out, hashlen);
        free(out);
        return result;
    }

    /* if raw hash requested, write it */
    if (hash) {
        memcpy(hash, out, hashlen);
    }

    /* if encoding requested, write it */
    if (encoded && encodedlen) {
        if (encode_string(encoded, encodedlen, &context, type) != ARGON2_OK) {
            clear_internal_memory(out, hashlen); /* wipe buffers if error */
            clear_internal_memory(encoded, encodedlen);
            free(out);
            return ARGON2_ENCODING_FAIL;
        }
    }
    clear_internal_memory(out, hashlen);
    free(out);

    return ARGON2_OK;
}

#ifdef ARGON2I
#ifdef ARGON2_ENCODED
static int
argon2i_hash_encoded(const uint32_t t_cost, const uint32_t m_cost,
        const uint32_t parallelism, const void *pwd,
        const size_t pwdlen, const void *salt,
        const size_t saltlen, const size_t hashlen,
        char *encoded, const size_t encodedlen)
{
    return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
            NULL, hashlen, encoded, encodedlen, Argon2_i,
            ARGON2_VERSION_NUMBER);
}
#endif /* ARGON2_ENCODED */

#ifdef ARGON2_RAW
static int
argon2i_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
        const uint32_t parallelism, const void *pwd,
        const size_t pwdlen, const void *salt,
        const size_t saltlen, void *hash, const size_t hashlen)
{
    return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
            hash, hashlen, NULL, 0, Argon2_i, ARGON2_VERSION_NUMBER);
}
#endif /* ARGON2_RAW */
#endif /* ARGON2I */

#ifdef ARGON2D
#ifdef ARGON2_ENCODED
static int
argon2d_hash_encoded(const uint32_t t_cost, const uint32_t m_cost,
        const uint32_t parallelism, const void *pwd,
        const size_t pwdlen, const void *salt,
        const size_t saltlen, const size_t hashlen,
        char *encoded, const size_t encodedlen)
{
    return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
            NULL, hashlen, encoded, encodedlen, Argon2_d,
            ARGON2_VERSION_NUMBER);
}
#endif /* ARGON2_ENCODED */

#ifdef ARGON2_RAW
static int
argon2d_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
        const uint32_t parallelism, const void *pwd,
        const size_t pwdlen, const void *salt,
        const size_t saltlen, void *hash, const size_t hashlen)
{
    return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
            hash, hashlen, NULL, 0, Argon2_d, ARGON2_VERSION_NUMBER);
}
#endif /* ARGON2_RAW */
#endif /* ARGON2D */

#ifdef ARGON2ID
#ifdef ARGON2_ENCODED
static int
argon2id_hash_encoded(const uint32_t t_cost, const uint32_t m_cost,
        const uint32_t parallelism, const void *pwd,
        const size_t pwdlen, const void *salt,
        const size_t saltlen, const size_t hashlen,
        char *encoded, const size_t encodedlen)
{
    return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
            NULL, hashlen, encoded, encodedlen, Argon2_id,
            ARGON2_VERSION_NUMBER);
}
#endif /* ARGON2_ENCODED */

#ifdef ARGON2_RAW
static int
argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
        const uint32_t parallelism, const void *pwd,
        const size_t pwdlen, const void *salt,
        const size_t saltlen, void *hash, const size_t hashlen)
{
    return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
            hash, hashlen, NULL, 0, Argon2_id,
            ARGON2_VERSION_NUMBER);
}
#endif /* ARGON2_RAW */
#endif /* ARGON2ID */

static const char *
argon2_error_message(int error_code)
{
    switch (error_code) {
        case ARGON2_OK:
            return "OK";
        case ARGON2_OUTPUT_PTR_NULL:
            return "Output pointer is NULL";
        case ARGON2_OUTPUT_TOO_SHORT:
            return "Output is too short";
        case ARGON2_OUTPUT_TOO_LONG:
            return "Output is too long";
        case ARGON2_PWD_TOO_LONG:
            return "Password is too long";
        case ARGON2_SALT_TOO_SHORT:
            return "Salt is too short";
        case ARGON2_SALT_TOO_LONG:
            return "Salt is too long";
        case ARGON2_AD_TOO_LONG:
            return "Associated data is too long";
        case ARGON2_SECRET_TOO_LONG:
            return "Secret is too long";
        case ARGON2_TIME_TOO_SMALL:
            return "Time cost is too small";
        case ARGON2_TIME_TOO_LARGE:
            return "Time cost is too large";
        case ARGON2_MEMORY_TOO_LITTLE:
            return "Memory cost is too small";
        case ARGON2_MEMORY_TOO_MUCH:
            return "Memory cost is too large";
        case ARGON2_LANES_TOO_FEW:
            return "Too few lanes";
        case ARGON2_LANES_TOO_MANY:
            return "Too many lanes";
        case ARGON2_PWD_PTR_MISMATCH:
            return "Password pointer is NULL, but password length is not 0";
        case ARGON2_SALT_PTR_MISMATCH:
            return "Salt pointer is NULL, but salt length is not 0";
        case ARGON2_SECRET_PTR_MISMATCH:
            return "Secret pointer is NULL, but secret length is not 0";
        case ARGON2_AD_PTR_MISMATCH:
            return "Associated data pointer is NULL, but ad length is not 0";
        case ARGON2_MEMORY_ALLOCATION_ERROR:
            return "Memory allocation error";
        case ARGON2_FREE_MEMORY_CBK_NULL:
            return "The free memory callback is NULL";
        case ARGON2_ALLOCATE_MEMORY_CBK_NULL:
            return "The allocate memory callback is NULL";
        case ARGON2_INCORRECT_PARAMETER:
            return "Argon2_Context context is NULL";
        case ARGON2_INCORRECT_TYPE:
            return "There is no such version of Argon2";
        case ARGON2_OUT_PTR_MISMATCH:
            return "Output pointer mismatch";
        case ARGON2_THREADS_TOO_FEW:
            return "Not enough threads";
        case ARGON2_THREADS_TOO_MANY:
            return "Too many threads";
        case ARGON2_MISSING_ARGS:
            return "Missing arguments";
        case ARGON2_ENCODING_FAIL:
            return "Encoding failed";
        case ARGON2_DECODING_FAIL:
            return "Decoding failed";
        case ARGON2_THREAD_FAIL:
            return "Threading failure";
        case ARGON2_DECODING_LENGTH_FAIL:
            return "Some of encoded parameters are too long or too short";
        case ARGON2_VERIFY_MISMATCH:
            return "The password does not match the supplied hash";
        default:
            return "Unknown error code";
    }
}

#ifdef ARGON2_ENCODED
static size_t
argon2_encodedlen(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
        uint32_t saltlen, uint32_t hashlen, argon2_type type) {
    return strlen("$$v=$m=,t=,p=$$") + strlen(argon2_type2string(type, 0)) +
        numlen(t_cost) + numlen(m_cost) + numlen(parallelism) +
        b64len(saltlen) + b64len(hashlen) + numlen(ARGON2_VERSION_NUMBER) + 1;
}
#endif /* ARGON2_ENCODED */

#endif
