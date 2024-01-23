/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_BIN_UNPACK_H
#define C_TOXCORE_TOXCORE_BIN_UNPACK_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Binary deserialisation object.
 *
 * User code never creates this object. It is created and destroyed within the below functions,
 * and passed to the callback. This enforces an alloc/dealloc bracket, so user code can never
 * forget to clean up an unpacker.
 */
typedef struct Bin_Unpack Bin_Unpack;

/** @brief Function used to unpack an object.
 *
 * This function would typically cast the `void *` to the actual object pointer type and then call
 * more appropriately typed unpacking functions.
 */
typedef bool bin_unpack_cb(void *obj, Bin_Unpack *bu);

/** @brief Unpack an object from a buffer of a given size.
 *
 * This function creates and initialises a `Bin_Unpack` object, calls the callback with the
 * unpacker object and the to-be-unpacked object, and then cleans up the unpacker object.
 *
 * Unlike `bin_pack_obj`, this function does not support NULL anywhere. The input array
 * must be non-null, even if it is zero-length.
 *
 * @param callback The function called on the created unpacker and unpacked object.
 * @param obj The object to be packed, passed as `obj` to the callback.
 * @param buf A byte array containing the serialised representation of `obj`.
 * @param buf_size The size of the byte array.
 *
 * @retval false if an error occurred (e.g. buffer overrun).
 */
non_null()
bool bin_unpack_obj(bin_unpack_cb *callback, void *obj, const uint8_t *buf, uint32_t buf_size);

/** @brief Start unpacking a MessagePack array.
 *
 * A call to this function must be followed by exactly `size` calls to other functions below.
 *
 * @param size Will contain the number of array elements following the array marker.
 */
non_null() bool bin_unpack_array(Bin_Unpack *bu, uint32_t *size);

/** @brief Start unpacking a fixed size MessagePack array.
 *
 * Fails if the array size is not the required size. If `actual_size` is passed a non-null
 * pointer, the array size is written there.
 *
 * @retval false if the packed array size is not exactly the required size.
 */
non_null(1) nullable(3)
bool bin_unpack_array_fixed(Bin_Unpack *bu, uint32_t required_size, uint32_t *actual_size);

/** @brief Unpack a MessagePack bool. */
non_null() bool bin_unpack_bool(Bin_Unpack *bu, bool *val);
/** @brief Unpack a MessagePack positive int into a `uint8_t`. */
non_null() bool bin_unpack_u08(Bin_Unpack *bu, uint8_t *val);
/** @brief Unpack a MessagePack positive int into a `uint16_t`. */
non_null() bool bin_unpack_u16(Bin_Unpack *bu, uint16_t *val);
/** @brief Unpack a MessagePack positive int into a `uint32_t`. */
non_null() bool bin_unpack_u32(Bin_Unpack *bu, uint32_t *val);
/** @brief Unpack a MessagePack positive int into a `uint64_t`. */
non_null() bool bin_unpack_u64(Bin_Unpack *bu, uint64_t *val);
/** @brief Unpack a Messagepack nil value. */
non_null() bool bin_unpack_nil(Bin_Unpack *bu);

/** @brief Unpack a MessagePack bin into a newly allocated byte array.
 *
 * Allocates a new byte array and stores it into `data_ptr` with its length stored in
 * `data_length_ptr`. This function requires that the unpacking buffer has at least as many bytes
 * remaining to be unpacked as the bin claims to need, so it's not possible to cause an arbitrarily
 * large allocation unless the input array was already that large.
 */
non_null() bool bin_unpack_bin(Bin_Unpack *bu, uint8_t **data_ptr, uint32_t *data_length_ptr);
/** @brief Unpack a variable size MessagePack bin into a fixed size byte array.
 *
 * Stores unpacked data into `data` with its length stored in `data_length_ptr`. This function does
 * not allocate memory and requires that `max_data_length` is less than or equal to `sizeof(arr)`
 * when `arr` is passed as `data` pointer.
 */
non_null() bool bin_unpack_bin_max(Bin_Unpack *bu, uint8_t *data, uint16_t *data_length_ptr, uint16_t max_data_length);
/** @brief Unpack a MessagePack bin of a fixed length into a pre-allocated byte array.
 *
 * Similar to the function above, but doesn't output the data length.
 */
non_null() bool bin_unpack_bin_fixed(Bin_Unpack *bu, uint8_t *data, uint32_t data_length);

/** @brief Start unpacking a custom binary representation.
 *
 * A call to this function must be followed by exactly `size` bytes packed by functions below.
 */
non_null() bool bin_unpack_bin_size(Bin_Unpack *bu, uint32_t *size);

/** @brief Read a `uint8_t` directly from the unpacker, consuming 1 byte. */
non_null() bool bin_unpack_u08_b(Bin_Unpack *bu, uint8_t *val);
/** @brief Read a `uint16_t` as big endian 16 bit int, consuming 2 bytes. */
non_null() bool bin_unpack_u16_b(Bin_Unpack *bu, uint16_t *val);
/** @brief Read a `uint32_t` as big endian 32 bit int, consuming 4 bytes. */
non_null() bool bin_unpack_u32_b(Bin_Unpack *bu, uint32_t *val);
/** @brief Read a `uint64_t` as big endian 64 bit int, consuming 8 bytes. */
non_null() bool bin_unpack_u64_b(Bin_Unpack *bu, uint64_t *val);

/** @brief Read a byte array directly from the packer, consuming `length` bytes. */
non_null() bool bin_unpack_bin_b(Bin_Unpack *bu, uint8_t *data, uint32_t length);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_BIN_UNPACK_H */
