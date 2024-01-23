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
 *
 * Naming convention:
 * - Functions ending in `_b` (or `_b_size`) are NOT MessagePack, i.e. write
 *   data in plain big endian binary format.
 * - All other functions encode their input in MessagePack format.
 *
 * Some notes on parameter order:
 *
 * - We pass the `obj` pointer as `this`-like pointer first to the callbacks.
 * - Any extra arguments passed to the callback follow the `obj` (and in case of
 *   array packing, the `arr` and `arr_size` parameters).
 * - The packer is passed last.
 *
 * This roughly matches a curried lambda function:
 *
 * @code
 * bin_pack_obj([](const void *obj, const Logger *logger, Bin_Pack *bp) { ... }, obj, logger, buf, buf_size);
 * // Translates roughly to:
 * bin_pack_obj([obj, logger](Bin_Pack *bp) { ... }, buf, buf_size);
 * @endcode
 */
typedef struct Bin_Pack Bin_Pack;

/** @brief Function used to pack an object.
 *
 * This function would typically cast the `void *` to the actual object pointer type and then call
 * more appropriately typed packing functions.
 */
typedef bool bin_pack_cb(const void *obj, const Logger *logger, Bin_Pack *bp);

/** @brief Function used to pack an array of objects.
 *
 * This function would typically cast the `void *` to the actual object pointer type and then call
 * more appropriately typed packing functions.
 *
 * @param arr is the object array as void pointer.
 * @param index is the index in the object array that is currently being packed.
 */
typedef bool bin_pack_array_cb(const void *arr, uint32_t index, const Logger *logger, Bin_Pack *bp);

/** @brief Determine the serialised size of an object.
 *
 * @param callback The function called on the created packer and packed object.
 * @param obj The object to be packed, passed as `obj` to the callback.
 * @param logger Optional logger object to pass to the callback.
 *
 * @return The packed size of the passed object according to the callback.
 * @retval UINT32_MAX in case of errors such as buffer overflow.
 */
non_null(1) nullable(2, 3)
uint32_t bin_pack_obj_size(bin_pack_cb *callback, const void *obj, const Logger *logger);

/** @brief Pack an object into a buffer of a given size.
 *
 * This function creates and initialises a `Bin_Pack` packer object, calls the callback with the
 * packer object and the to-be-packed object, and then cleans up the packer object. Note that
 * there is nothing MessagePack-specific about this function, so it can be used for both custom
 * binary and MessagePack formats.
 *
 * You can use `bin_pack_obj_size` to determine the minimum required size of `buf`. If packing
 * overflows `uint32_t`, this function returns `false`.
 *
 * Passing NULL for `obj` is supported, but requires that the callback supports nullable inputs.
 *
 * @param callback The function called on the created packer and packed object.
 * @param obj The object to be packed, passed as `obj` to the callback.
 * @param logger Optional logger object to pass to the callback.
 * @param buf A byte array large enough to hold the serialised representation of `obj`.
 * @param buf_size The size of the byte array. Can be `UINT32_MAX` to disable bounds checking.
 *
 * @retval false if an error occurred (e.g. buffer overflow).
 */
non_null(1, 4) nullable(2, 3)
bool bin_pack_obj(bin_pack_cb *callback, const void *obj, const Logger *logger, uint8_t *buf, uint32_t buf_size);

/** @brief Determine the serialised size of an object array.
 *
 * Behaves exactly like `bin_pack_obj_b_array` but doesn't write.
 *
 * @param callback The function called on the created packer and each object to
 *   be packed.
 * @param arr The object array to be packed, passed as `arr` to the callback.
 * @param arr_size The number of elements in the object array.
 * @param logger Optional logger object to pass to the callback.
 *
 * @return The packed size of the passed object array according to the callback.
 * @retval UINT32_MAX in case of errors such as buffer overflow.
 */
non_null(1) nullable(2, 4)
uint32_t bin_pack_obj_array_b_size(bin_pack_array_cb *callback, const void *arr, uint32_t arr_size, const Logger *logger);

/** @brief Pack an object array into a buffer of a given size.
 *
 * Similar to `bin_pack_obj_array` but does not write the array length, so
 * if you need that, encoding it is on you.
 *
 * Passing NULL for `arr` has no effect, but requires that `arr_size` is 0.
 *
 * @param callback The function called on the created packer and packed object
 *   array.
 * @param arr The object array to be packed, passed as `arr` to the callback.
 * @param arr_size The number of elements in the object array.
 * @param logger Optional logger object to pass to the callback.
 * @param buf A byte array large enough to hold the serialised representation of `arr`.
 * @param buf_size The size of the byte array. Can be `UINT32_MAX` to disable bounds checking.
 *
 * @retval false if an error occurred (e.g. buffer overflow).
 */
non_null(1, 5) nullable(2, 4)
bool bin_pack_obj_array_b(bin_pack_array_cb *callback, const void *arr, uint32_t arr_size, const Logger *logger, uint8_t *buf, uint32_t buf_size);

/** @brief Encode an object array as MessagePack array into a bin packer.
 *
 * Calls the callback `arr_size` times with increasing `index` argument from 0 to
 * `arr_size`. This function is here just so we don't need to write the same
 * trivial loop many times and so we don't need an extra struct just to contain
 * an array with size so it can be passed to `bin_pack_obj`.
 *
 * Similar to `bin_pack_obj` but for arrays. Note that a `Bin_Pack` object is
 * required here, so it must be called from within a callback to one of the
 * functions above.
 *
 * Passing NULL for `arr` requires that `arr_size` is 0. This will write a 0-size
 * MessagePack array to the packer.
 *
 * @param bp Bin packer object.
 * @param callback The function called on the created packer and packed object
 *   array.
 * @param arr The object array to be packed, passed as `arr` to the callback.
 * @param arr_size The number of elements in the object array.
 * @param logger Optional logger object to pass to the callback.
 *
 * @retval false if an error occurred (e.g. buffer overflow).
 */
non_null(1, 2) nullable(3, 5)
bool bin_pack_obj_array(Bin_Pack *bp, bin_pack_array_cb *callback, const void *arr, uint32_t arr_size, const Logger *logger);

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
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_BIN_PACK_H */
