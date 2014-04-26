/**
 * data.h (formerly txd.h, and SCProfileIO.h)
 * Copyright (c) 2014 the Tox developers. All rights reserved.
 * Rest of copyright notice omitted; look at another file.
 */

#ifndef TXD_H
#define TXD_H
#include "tox.h"

/* Data types. */

/**
 * Defines TXD FourCC (4-character code) as uint32_t.
 * This is the type of all TXD magic numbers.
 */
typedef uint32_t txd_fourcc_t;
/**
 * Defines TXD TwoCC (2-character code) as uint16_t.
 * This is the type of FrEx keys.
 */
typedef uint16_t txd_twocc_t;
/**
 * Defines txd_intermediate_t as an opaque pointer to
 * txd_intermediate_s.
 */
typedef struct txd_intermediate *txd_intermediate_t;


/* Format constants. */

/**
 * Defines the 4CC (magic number) of the Binary data format.
 * It is the only one available to Core.
 */
extern const txd_fourcc_t TXD_FORMAT_BINARY1;


/* Error constants. */

/**
 * The envelope has a bad magic number, or it was shorter than the BASE_LEN.
 */
extern const int32_t TXD_ERR_BAD_BLOCK;
/**
 * One of the sizes in the block does not correspond with what we know.
 */
extern const int32_t TXD_ERR_SIZE_MISMATCH;
/**
 * The operation completed successfully (0).
 */
extern const int32_t TXD_ERR_SUCCESS;
/**
 * This function is not implemented yet. Failure is guaranteed
 * for all future calls to this function for this version of the library.
 */
extern const int32_t TXD_ERR_NOT_IMPLEMENTED;


/* Selective archival constants.
 * Use bitwise or to combine flags, then pass them to
 * txd_export_to_buf_ex(). */

/**
 * Save everything that can possibly be saved.
 * This is implied when you call txd_export_to_buf().
 * If you want more control, you should use txd_export_to_buf_ex().
 */
extern const uint32_t TXD_ALL_BLOCKS;

/**
 * Save the self block. It contains name and status.
 */
extern const uint32_t TXD_ARC_SELF_BLOCK;
/**
 * Save the keys block. It contains public and private keys, plus the nospam.
 */
extern const uint32_t TXD_ARC_KEYS_BLOCK;
/**
 * Save the friend block. It contains your friends.
 */
extern const uint32_t TXD_ARC_FRIEND_BLOCK;
/**
 * Save the DHT block. It contains the close nodes known to Tox at the
 * time of archival.
 */
extern const uint32_t TXD_ARC_DHT_BLOCK;

/* Intermediate structure functions. */

/**
 * Create a new intermediate structure from tox. The returned pointer
 * must be freed with a call to txd_intermediate_free.
 * @param tox the Tox API object containing data to initialize the
 *            intermediate structure.
 * @return the initialized txd_intermediate_t.
 */
txd_intermediate_t txd_intermediate_from_tox(Tox *tox);

/**
 * Restore data from the intermediate structure pointed to by interm
 * into the Tox API object tox.
 * @param interm the intermediate structure to restore data from.
 *               It must not be NULL.
 * @param tox the Tox API object receiving the data.
 * @return TXD_ERR_SUCCESS (0) on success, otherwise an error code.
 *         See TXD_ERR_* constants.
 */
int txd_restore_intermediate(txd_intermediate_t interm, Tox *tox);

/**
 * Destroy the intermediate structure pointed to by interm,
 * securely erasing the data from memory before releasing it. When
 * this function returns, interm shall be an invalid pointer.
 * @param interm The intermediate structure to destroy. It must not
 *               be NULL.
 * @return nothing.
 */
void txd_intermediate_free(txd_intermediate_t interm);

/**
 * Extracting data out of the txd_intermediate_t safely.
 * These functions should be self-explanatory.
 * txd_copy_* do not output NULL terminators.
 */
uint32_t txd_get_length_of_name(txd_intermediate_t interm);
void txd_copy_name(txd_intermediate_t interm, uint8_t *out_, uint32_t max_len);
uint32_t txd_get_length_of_status_message(txd_intermediate_t interm);
void txd_copy_status_message(txd_intermediate_t interm, uint8_t *out_, uint32_t max_len);
TOX_USERSTATUS txd_get_user_status(txd_intermediate_t interm);
void txd_copy_public_key(txd_intermediate_t interm, uint8_t *out_);
/* note: use with caution - the secret key should not be copied
 * willy-nilly */
void txd_copy_secret_key(txd_intermediate_t interm, uint8_t *out_);
/* technically a 4-byte int, but we handle it like bytes
 * because core does too */
void txd_copy_nospam(txd_intermediate_t interm, uint8_t *out_);

uint32_t txd_get_number_of_friends(txd_intermediate_t interm);
/* a bad index will give undefined behaviour */
uint32_t txd_get_length_of_friend_name(txd_intermediate_t interm, uint32_t f_n);
void txd_copy_friend_name(txd_intermediate_t interm, uint32_t f_n, uint8_t *out_, uint32_t max_len);
void txd_copy_friend_client_id(txd_intermediate_t interm, uint32_t f_n, uint8_t *out_);
/* do not use this function. */
void txd_copy_friend_address(txd_intermediate_t interm, uint32_t f_n, uint8_t *out_);
uint8_t txd_get_sends_receipts(txd_intermediate_t interm, uint32_t f_n);
uint8_t txd_get_needs_requests(txd_intermediate_t interm, uint32_t f_n);
uint16_t txd_get_length_of_request_data(txd_intermediate_t interm, uint32_t f_n);
void txd_copy_request_data(txd_intermediate_t interm, uint32_t f_n, uint8_t *out_, uint32_t max_len);

uint32_t txd_get_number_of_dht_nodes(txd_intermediate_t interm);
void txd_copy_dht_client_id(txd_intermediate_t interm, uint32_t node, uint8_t *out_);
uint8_t txd_get_dht_has_ip4(txd_intermediate_t interm, uint32_t node);
uint8_t txd_get_dht_has_ip6(txd_intermediate_t interm, uint32_t node);
uint16_t txd_get_dht_port4(txd_intermediate_t interm, uint32_t node);
void txd_copy_dht_ip4(txd_intermediate_t interm, uint32_t node, uint8_t *out_);
uint16_t txd_get_dht_port6(txd_intermediate_t interm, uint32_t node);
void txd_copy_dht_ip6(txd_intermediate_t interm, uint32_t node, uint8_t *out_);

/**
 * Return the size of the buffer required to archive im.
 * @param im the TXD intermediate you [are going to] archive.
 */
uint64_t txd_get_size_of_intermediate(txd_intermediate_t im);
/**
 * Same as txd_get_size_of_intermediate.
 * For arc_blocks, pass in a bitmask of TXD_ARC_* constants,
 * or TXD_ALL_BLOCKS.
 * @param arc_blocks bitmask of TXD_ARC_* representing the blocks you are going
 *                   to archive
 */
uint64_t txd_get_size_of_intermediate_ex(txd_intermediate_t im, uint32_t arc_blocks);
/**
 * Copy the contents of im into memory such that is it safe to shoot over
 * the wire, save on disk, etc.
 * You can re-create im by passing the returned buffer to
 * txd_intermediate_from_buf.
 * @param im the TXD intermediate struct to dump
 * @param buf if this function returns TXD_ERR_SUCCESS, the value it points to
 *            will be a valid pointer to the dumped memory.
 * @param size see above, it will point to the size of buf.
 * @discussion You can pass NULL for buf or size. (e.g. to get the size you
 *             need to allocate, pass NULL for buf and a valid pointer for size)
 */
uint32_t txd_export_to_buf(txd_intermediate_t im, uint8_t **buf, uint64_t *size);
uint32_t txd_export_to_buf_ex(txd_intermediate_t im, uint8_t **buf, uint64_t *size,
                              uint32_t arc_blocks);
/**
 * You should use the functions above instead of this one.
 */
uint32_t txd_export_to_buf_prealloc(txd_intermediate_t im, uint8_t *buf,
                                    uint64_t block_size, uint32_t arc_blocks);
/**
 * Create a new intermediate structure from archived data in buf.
 * must be freed with a call to txd_intermediate_free.
 * @param buf the memory buffer containing data to initialize the
 *            intermediate structure.
 * @param size the size of buf.
 * @param out_ if this function returns TXD_ERR_SUCCESS, points to a valid
 *             txd_intermediate_t structure. You are responsible for releasing
 *             it with a call to txd_intermediate_free. Otherwise, it is undefined.
 * @return an error code. See "Error constants." in this file for possible
 *         values.
 */
uint32_t txd_intermediate_from_buf(uint8_t *buf, uint64_t size, txd_intermediate_t *out_);

#endif
