/**
 * @file
 *
 * libFuzzer harness for the strict DER reader.
 *
 * A buffer is corrupt or it is one value. Anything else is a bug.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/der.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  GSEC_Der view;
  GSEC_Result result = gsec_der_tlv(data, size, &view);
  if (result != GSEC_OK && result != GSEC_ERR_CORRUPT) {
    __builtin_trap();
  }
  if (result == GSEC_OK && view.total_len > size) {
    __builtin_trap();
  }
  return 0;
}
