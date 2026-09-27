/**
 * @file
 *
 * libFuzzer harness for gsec_wipe.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>
#include <vector>

#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (data == nullptr || size == 0) {
    (void)gsec_wipe(nullptr, 0);
    return 0;
  }
  std::vector<unsigned char> buffer(data, data + size);
  if (gsec_wipe(buffer.data(), buffer.size()) == GSEC_OK) {
    for (unsigned char byte : buffer) {
      if (byte != 0) {
        __builtin_trap();
      }
    }
  }
  return 0;
}
