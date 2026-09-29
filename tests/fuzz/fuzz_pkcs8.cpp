/**
 * @file
 *
 * libFuzzer harness for unencrypted PKCS#8.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/pkcs8.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  GSEC_Pkcs8 key;
  GSEC_Result result = gsec_pkcs8_parse(data, size, &key);
  if (result != GSEC_OK && result != GSEC_ERR_CORRUPT &&
      result != GSEC_ERR_UNSUPPORTED && result != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  {
    GSEC_Pkcs8 twice;
    if (gsec_pkcs8_parse(data, size, &twice) != result) {
      __builtin_trap();
    }
  }
  return 0;
}
