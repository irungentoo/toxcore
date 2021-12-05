#include "../../toxcore/tox.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  Tox_Err_Options_New error_options;

  struct Tox_Options *tox_options = tox_options_new(&error_options);

  assert(tox_options != nullptr);
  assert(error_options == TOX_ERR_OPTIONS_NEW_OK);

  // pass test data to Tox
  tox_options_set_savedata_data(tox_options, data, size);
  tox_options_set_savedata_type(tox_options, TOX_SAVEDATA_TYPE_TOX_SAVE);

  Tox_Err_New error_new;
  Tox *tox = tox_new(tox_options, &error_new);

  assert(tox != nullptr);
  assert(error_new == TOX_ERR_NEW_OK);

  tox_options_free(tox_options);

  tox_kill(tox);
  return 0;  // Non-zero return values are reserved for future use.
}
