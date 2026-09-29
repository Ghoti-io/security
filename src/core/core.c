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
 * Result strings and the default limits.
 *
 * The string table is indexed by the enum. A new result that is not added
 * here falls through to "Unknown error", and the unit test that walks
 * GSEC_RESULT_COUNT rejects that.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/core.h>

const char * gsec_result_string(GSEC_Result result) {
  switch (result) {
    case GSEC_OK:
      return "No error";
    case GSEC_ERR_IO:
      return "Input/output error";
    case GSEC_ERR_FORMAT:
      return "Format not recognised";
    case GSEC_ERR_UNSUPPORTED:
      return "Unsupported feature";
    case GSEC_ERR_LIMIT:
      return "Limit exceeded";
    case GSEC_ERR_CORRUPT:
      return "Corrupt input";
    case GSEC_ERR_OOM:
      return "Out of memory";
    case GSEC_ERR_INVALID:
      return "Invalid argument";
    case GSEC_ERR_INTERNAL:
      return "Internal error";
    case GSEC_ERR_MISMATCH:
      return "Verification failed";
    case GSEC_RESULT_COUNT:
      break;
  }
  return "Unknown error";
}

void gsec_limits_default(GSEC_Limits * limits) {
  if (!limits) {
    return;
  }
  /* 1 MiB is more than any key, nonce, or signature this library will be
   * asked to draw in one call. A caller with a real reason passes a limits
   * struct; the default refuses a request that is asking for a pool. */
  limits->max_random_bytes = (size_t)1 << 20;
  limits->max_pbe_iterations = GSEC_PBE_ITERATIONS_DEFAULT;
}
