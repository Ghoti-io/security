/**
 * @file
 *
 * libFuzzer harness for PEM.
 *
 * Decode accepts one block or rejects it. Encode of a short prefix must
 * round-trip when the label is fixed.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/pem.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char der[256];
  char armour[512];
  char label[80];
  size_t n = 0;
  GSEC_Result result;

  result = gsec_pem_decode(data, size, der, sizeof der, &n, label, sizeof label);
  if (result != GSEC_OK && result != GSEC_ERR_CORRUPT &&
      result != GSEC_ERR_LIMIT && result != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  if (size > 48) {
    return 0;
  }
  result = gsec_pem_encode("TEST", data, size, armour, sizeof armour, &n);
  if (result != GSEC_OK) {
    __builtin_trap();
  }
  result = gsec_pem_decode(armour, n, der, sizeof der, &n, nullptr, 0);
  if (result != GSEC_OK || n != size) {
    __builtin_trap();
  }
  return 0;
}
