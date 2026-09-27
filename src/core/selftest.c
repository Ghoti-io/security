/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io Security.
 *
 * Ghoti.io Security is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Ghoti.io Security is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Known answers an embedder can run without the test suite.
 *
 * The bytes below are not secret. They are fixed inputs, and nothing here
 * writes them anywhere except into stack buffers that are wiped before return.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/random.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/selftest.h>

GSEC_Result gsec_selftest(void) {
  static const unsigned char left[4] = {0x00, 0x01, 0x02, 0x03};
  static const unsigned char right[4] = {0x00, 0x01, 0x02, 0x04};
  unsigned char buffer[32];
  unsigned char drawn[32];
  size_t i;
  GSEC_Result result;
  unsigned char changed;

  result = gsec_equal(NULL, NULL, 0);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_equal(left, left, sizeof left);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_equal(left, right, sizeof left);
  if (result != GSEC_ERR_MISMATCH) {
    return result == GSEC_OK ? GSEC_ERR_INTERNAL : result;
  }

  for (i = 0; i < sizeof buffer; i++) {
    buffer[i] = 0xA5;
  }
  result = gsec_wipe(buffer, sizeof buffer);
  if (result != GSEC_OK) {
    return result;
  }
  for (i = 0; i < sizeof buffer; i++) {
    if (buffer[i] != 0) {
      return GSEC_ERR_INTERNAL;
    }
  }

  for (i = 0; i < sizeof drawn; i++) {
    drawn[i] = 0xA5;
  }
  result = gsec_random_bytes(drawn, sizeof drawn, NULL);
  if (result != GSEC_OK) {
    return result;
  }
  /* 32 bytes of 0xA5 from the kernel is a possible output. It is not a
   * plausible one, and a generator that failed to write would leave exactly
   * that pattern. Every byte is folded in: stopping at the first difference
   * would be the timing leak this library exists not to write, and the bytes
   * are key material until the wipe below. */
  changed = 0;
  for (i = 0; i < sizeof drawn; i++) {
    changed = (unsigned char)(changed | (unsigned char)(drawn[i] ^ 0xA5));
  }
  result = gsec_wipe(drawn, sizeof drawn);
  if (result != GSEC_OK) {
    return result;
  }
  if (changed == 0) {
    return GSEC_ERR_INTERNAL;
  }
  return GSEC_OK;
}
