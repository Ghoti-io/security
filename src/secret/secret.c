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
 * Constant-time comparison, wiping, and the memcheck marks.
 *
 * The comparison accumulates every byte into one volatile value and only
 * then branches, on that value, which is the public answer. A compiler that
 * rewrites the loop as the C library's early-out byte compare would return
 * at the first difference; the volatile loads and the volatile accumulator
 * are what stop it recognising that idiom. `make check-ct`
 * is the test that this stayed true at the optimisation level that ships.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/secret.h>

#include <string.h>

#if defined(GSEC_CT_TEST)
#include <valgrind/memcheck.h>
#endif

GSEC_Result gsec_equal(const void * a, const void * b, size_t n) {
  const volatile unsigned char * x;
  const volatile unsigned char * y;
  volatile unsigned char diff;
  size_t i;

  if (n == 0) {
    return GSEC_OK;
  }
  if (a == NULL || b == NULL) {
    return GSEC_ERR_INVALID;
  }

  x = (const volatile unsigned char *)a;
  y = (const volatile unsigned char *)b;
  diff = 0;
  for (i = 0; i < n; i++) {
    diff = (unsigned char)(diff | (unsigned char)(x[i] ^ y[i]));
  }

  /* The accumulator is a function of the secret. The branch below is the
   * answer the caller is about to see, so it is public. Without this mark,
   * memcheck reports the branch and a correct comparison looks like a leak. */
#if defined(GSEC_CT_TEST)
  VALGRIND_MAKE_MEM_DEFINED((unsigned char *)&diff, sizeof diff);
#endif

  if (diff == 0) {
    return GSEC_OK;
  }
  return GSEC_ERR_MISMATCH;
}

GSEC_Result gsec_wipe(void * p, size_t n) {
  /* A volatile pointer to memset. The compiler must emit the call because it
   * cannot prove which function it is, and so cannot delete it as a store
   * whose result is unread. */
  static void * (*const volatile wipe)(void *, int, size_t) = memset;

  if (n == 0) {
    return GSEC_OK;
  }
  if (p == NULL) {
    return GSEC_ERR_INVALID;
  }
  wipe(p, 0, n);
#if defined(GSEC_CT_TEST)
  /* The secret is gone. A caller that reads the zeros is not branching on a
   * secret, and memcheck should not say that it is. */
  VALGRIND_MAKE_MEM_DEFINED(p, n);
#endif
  return GSEC_OK;
}

void gsec_poison(void * p, size_t n) {
  if (p == NULL || n == 0) {
    return;
  }
#if defined(GSEC_CT_TEST)
  VALGRIND_MAKE_MEM_UNDEFINED(p, n);
#else
  (void)p;
  (void)n;
#endif
}

void gsec_unpoison(void * p, size_t n) {
  if (p == NULL || n == 0) {
    return;
  }
#if defined(GSEC_CT_TEST)
  VALGRIND_MAKE_MEM_DEFINED(p, n);
#else
  (void)p;
  (void)n;
#endif
}
