/**
 * @file
 *
 * libFuzzer harness for gsec_equal.
 *
 * The first byte is unused length noise so an empty-ish input still splits.
 * The rest is cut in half. Fixed-shape algorithms fuzz poorly; this harness
 * exists so a comparison that reads off the end is an ASan report, which is
 * the failure a decoder-shaped fuzzer will later be for.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  const uint8_t * a;
  const uint8_t * b;
  size_t n;

  if (data == nullptr || size < 2) {
    (void)gsec_equal(nullptr, nullptr, 0);
    return 0;
  }
  n = (size - 1) / 2;
  a = data + 1;
  b = a + n;
  (void)gsec_equal(a, b, n);
  (void)gsec_equal(a, a, n);
  return 0;
}
