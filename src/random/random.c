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
 * Kernel entropy. One implementation, fail closed.
 *
 * No GRND_NONBLOCK: a failure during early boot must not become a reason to
 * read a userspace generator. Not the urandom device node either: a file
 * descriptor has its own failure modes (closed, replaced, exhausted) and
 * getrandom does not.
 */

/* Before any include. -std=c17 hides getrandom unless a feature macro is set,
 * and a feature macro after the first include is ignored. */
#if !defined(_WIN32) && !defined(__APPLE__)
#define _GNU_SOURCE
#endif

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/random.h>
#include <ghoti.io/security/secret.h>

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#elif defined(__APPLE__)
#include <sys/random.h>
#else
#define _GNU_SOURCE
#include <errno.h>
#include <sys/random.h>
#endif

static GSEC_Result wipe_out(void * out, size_t n) {
  if (out == NULL || n == 0) {
    return GSEC_OK;
  }
  return gsec_wipe(out, n);
}

GSEC_Result gsec_random_bytes(void * out, size_t n,
    const GSEC_Limits * limits) {
  GSEC_Limits local;
  const GSEC_Limits * caps;
  unsigned char * p;
  size_t got;

  if (limits == NULL) {
    gsec_limits_default(&local);
    caps = &local;
  } else {
    caps = limits;
  }
  if (n > caps->max_random_bytes) {
    return GSEC_ERR_LIMIT;
  }
  if (n == 0) {
    return GSEC_OK;
  }
  if (out == NULL) {
    return GSEC_ERR_INVALID;
  }

  p = (unsigned char *)out;
  got = 0;

#if defined(_WIN32)
  /* TODO(windows): BCryptGenRandom has not been run. See
   * notes/suite/WINDOWS-TODO.md. */
  {
    NTSTATUS status;

    if (n > (size_t)0xFFFFFFFFu) {
      return GSEC_ERR_LIMIT;
    }
    status = BCryptGenRandom(NULL, p, (ULONG)n,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
      (void)wipe_out(out, n);
      return GSEC_ERR_IO;
    }
  }
#elif defined(__APPLE__)
  while (got < n) {
    size_t chunk = n - got;

    /* getentropy refuses more than 256 bytes in one call. */
    if (chunk > 256) {
      chunk = 256;
    }
    if (getentropy(p + got, chunk) != 0) {
      (void)wipe_out(out, n);
      return GSEC_ERR_IO;
    }
    got += chunk;
  }
#else
  while (got < n) {
    ssize_t wrote = getrandom(p + got, n - got, 0);

    if (wrote < 0) {
      if (errno == EINTR) {
        continue;
      }
      (void)wipe_out(out, n);
      return GSEC_ERR_IO;
    }
    if (wrote == 0) {
      (void)wipe_out(out, n);
      return GSEC_ERR_IO;
    }
    got += (size_t)wrote;
  }
#endif
  return GSEC_OK;
}


static int kernel_fill(void * ctx, void * out, size_t n) {
  (void)ctx;
  return gsec_random_bytes(out, n, NULL) == GSEC_OK ? 0 : -1;
}


GCU_Random * gsec_random_open(void) {
  GCU_Random_Engine engine = { NULL, kernel_fill, NULL };

  return gcu_random_from_engine(&engine);
}
