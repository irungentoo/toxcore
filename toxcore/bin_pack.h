/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */
#ifndef C_TOXCORE_TOXCORE_BIN_PACK_H
#define C_TOXCORE_TOXCORE_BIN_PACK_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"
#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Binary serialisation object.
 */
typedef struct Bin_Pack Bin_Pack;

/** @brief Function used to pack an object.
 *
 * This function would typically cast the `void *` to the actual object pointer type and then call
 * more appropriately typed packing functions.
 */
typedef bool bin_pack_cb(Bin_Pack *bp, const Logger *logger, const void *obj);

/** @brief Function used to pack an array of objects.
 *
 * This function would typically cast the `void *` to the actual object pointer type and then call
 * more appropriately typed packing functions.
 *
 * @param arr is the object array as void pointer.
 * @param index is the index in the object array that is currently being packed.
 */
typedef bool bin_pack_array_cb(Bin_Pack *bp, const Logger *logger, const void *arr, uint32_t index);

/** @brief Determine the serialised size of an object.
 *
 * @param callback The function called on the created packer and packed object.
 * @param logger Optional logger object to pass to the callback.
 * @param obj The object to be packed, passed as `obj` to the callback.
 *
 * @return The packed size of the passed object according to the callback.
 * @retval UINT32_MAX in case of errors such as buffer overflow.
 */
non_null(1) nullable(2, 3)
uint32_t bin_pack_obj_size(bin_pack_cb *callback, const Logger *logger, const void *obj);

/** @brief Pack an object into a buffer of a given size.
 *
 * This function creates and initialises a `Bin_Pack` packer object, calls the callback with the
 * packer object and the to-be-packed object, and then cleans up the packer object.
 *
 * You can use `bin_pack_obj_size` to determine the minimum required size of `buf`. If packing
 * overflows `uint32_t`, this function returns `false`.
 *
 * @param callback The function called on the created packer and packed object.
 * @param logger Optional logger object to pass to the callback.
 * @param obj The object to be packed, passed as `obj` to the callback.
 * @param buf A byte array large enough to hold the serialised representation of `obj`.
 * @param buf_size The size of the byte array. Can be `UINT32_MAX` to disable bounds checking.
 *
 * @retval false if an error occurred (e.g. buffer overflow).
 */
non_null(1, 4) nullable(2, 3)
bool bin_pack_obj(bin_pack_cb *callback, const Logger *logger, const void *obj, uint8_t *buf, uint32_t buf_size);

/** @brief Determine the serialised size of an object array.
 *
 * Calls the callback `count` times with increasing `index` argument from 0 to
 * `count`. This function is here just so we don't need to write the same
 * trivial loop many times and so we don't need an extra struct just to contain
 * an array with size so it can be passed to `bin_pack_obj_size`.
 *
 * @param callback The function called on the created packer and each object to
 *   be packed.
 * @param logger Optional logger object to pass to the callback.
 * @param arr The object array to be packed, passed as `arr` to the callback.
 * @param count The number of elements in the object array.
 *
 * @return The packed size of the passed object array according to the callback.
 * @retval UINT32_MAX in case of errors such as buffer overflow.
 */
non_null(1, 3) nullable(2)
uint32_t bin_pack_obj_array_size(bin_pack_array_cb *callback, const Logger *logger, const void *arr, uint32_t count);

/** @brief Pack an object array into a buffer of a given size.
 *
 * Calls the callback `count` times with increasing `index` argument from 0 to
 * `count`. This function is here just so we don't need to write the same
 * trivial loop many times and so we don't need an extra struct just to contain
 * an array with size so it can be passed to `bin_pack_obj`.
 *
 * Similar to `bin_pack_obj` but for arrays. Does not write the array length, so
 * if you need that, write it manually using `bin_pack_array`.
 *
 * @param callback The function called on the created packer and packed object
 *   array.
 * @param logger Optional logger object to pass to the callback.
 * @param arr The object array to be packed, passed as `arr` to the callback.
 * @param count The number of elements in the object array.
 * @param buf A byte array large enough to hold the serialised representation of `arr`.
 * @param buf_size The size of the byte array. Can be `UINT32_MAX` to disable bounds checking.
 *
 * @retval false if an error occurred (e.g. buffer overflow).
 */
non_null(1, 3, 5) nullable(2)
bool bin_pack_obj_array(bin_pack_array_cb *callback, const Logger *logger, const void *arr, uint32_t count, uint8_t *buf, uint32_t buf_size);

/** @brief Allocate a new packer object.
 *
 * This is the only function that allocates memory in this module.
 *
 * @param buf A byte array large enough to hold the serialised representation of `obj`.
 * @param buf_size The size of the byte array. Can be `UINT32_MAX` to disable bounds checking.
 *
 * @retval nullptr on allocation failure.
 */
non_null()
Bin_Pack *bin_pack_new(uint8_t *buf, uint32_t buf_size);

/** @brief Deallocates a packer object.
 *
 * Does not deallocate the buffer inside.
 */
nullable(1)
void bin_pack_free(Bin_Pack *bp);

/** @brief Start packing a MessagePack array.
 *
 * A call to this function must be followed by exactly `size` calls to other functions below.
 */
non_null()
bool bin_pack_array(Bin_Pack *bp, uint32_t size);

/** @brief Pack a MessagePack bool. */
non_null() bool bin_pack_bool(Bin_Pack *bp, bool val);
/** @brief Pack a `uint8_t` as MessagePack positive integer. */
non_null() bool bin_pack_u08(Bin_Pack *bp, uint8_t val);
/** @brief Pack a `uint16_t` as MessagePack positive integer. */
non_null() bool bin_pack_u16(Bin_Pack *bp, uint16_t val);
/** @brief Pack a `uint32_t` as MessagePack positive integer. */
non_null() bool bin_pack_u32(Bin_Pack *bp, uint32_t val);
/** @brief Pack a `uint64_t` as MessagePack positive integer. */
non_null() bool bin_pack_u64(Bin_Pack *bp, uint64_t val);
/** @brief Pack an empty array member as a MessagePack nil value. */
non_null() bool bin_pack_nil(Bin_Pack *bp);
/** @brief Pack a byte array as MessagePack bin. */
non_null() bool bin_pack_bin(Bin_Pack *bp, const uint8_t *data, uint32_t length);
/** @brief Start packing a custom binary representation.
 *
 * A call to this function must be followed by exactly `size` bytes packed by functions below.
 */
non_null() bool bin_pack_bin_marker(Bin_Pack *bp, uint32_t size);

/** @brief Write a `uint8_t` directly to the packer in 1 byte. */
non_null() bool bin_pack_u08_b(Bin_Pack *bp, uint8_t val);
/** @brief Write a `uint16_t` as big endian 16 bit int in 2 bytes. */
non_null() bool bin_pack_u16_b(Bin_Pack *bp, uint16_t val);
/** @brief Write a `uint32_t` as big endian 32 bit int in 4 bytes. */
non_null() bool bin_pack_u32_b(Bin_Pack *bp, uint32_t val);
/** @brief Write a `uint64_t` as big endian 64 bit int in 8 bytes. */
non_null() bool bin_pack_u64_b(Bin_Pack *bp, uint64_t val);

/** @brief Write a byte array directly to the packer in `length` bytes.
 *
 * Note that unless you prepend the array length manually, there is no record of it in the resulting
 * serialised representation.
 */
non_null() bool bin_pack_bin_b(Bin_Pack *bp, const uint8_t *data, uint32_t length);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_BIN_PACK_H
