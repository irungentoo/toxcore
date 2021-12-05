#include <cassert>
#include <cstring>

#include "../../toxcore/tox.h"
#include "fuzz_adapter.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  network_adapter_init(data, size);

  Tox_Err_New error_new;
  Tox *tox = tox_new(NULL, &error_new);

  assert(tox != nullptr);
  assert(error_new == TOX_ERR_NEW_OK);

  uint8_t pub_key[TOX_PUBLIC_KEY_SIZE] = {0};

  bool success = tox_bootstrap(tox, "127.0.0.1", 12345, pub_key, nullptr);
  assert(success);

  /*
   * The iteration count here is a magic value in the literal sense, too small
   * and coverage will be bad, too big and fuzzing will not be efficient.
   * NOTE: This should be fine tuned after gathering some experience.
   */

  for (uint32_t i = 0; i < 100; ++i) {
    tox_iterate(tox, nullptr);
  }

  tox_kill(tox);
  return 0;  // Non-zero return values are reserved for future use.
}
