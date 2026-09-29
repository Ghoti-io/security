/**
 * @file
 *
 * libFuzzer harness for PKCS#12.
 *
 * A three- or four-byte INTEGER anywhere in the input is refused here.
 * That is how an iteration count large enough to stall the run is
 * encoded. The library accepts far more.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/pkcs12.h>

static int expensive(const uint8_t * data, size_t size) {
  size_t i;
  for (i = 0; i + 3 < size; i++) {
    if (data[i] == 0x02 && data[i + 1] >= 3 && data[i + 1] <= 4) {
      return 1;
    }
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char scratch[4096];
  GSEC_Pkcs12 bag;
  GSEC_Result result;

  if (size > 4096) {
    size = 4096;
  }
  if (expensive(data, size)) {
    return 0;
  }
  result = gsec_pkcs12_open(data, size, "secret", 6, scratch, sizeof scratch,
      &bag, nullptr);
  if (result != GSEC_OK && result != GSEC_ERR_CORRUPT &&
      result != GSEC_ERR_UNSUPPORTED && result != GSEC_ERR_LIMIT &&
      result != GSEC_ERR_INVALID && result != GSEC_ERR_MISMATCH) {
    __builtin_trap();
  }
  return 0;
}
