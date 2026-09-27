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
 * P-384 ECDH. The point arithmetic is src/p384. Inputs are copied so the
 * output may alias either of them.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/ecdh_p384.h>
#include <ghoti.io/security/secret.h>

#include "../p384/p384_point.h"

#include <string.h>

GSEC_Result gsec_ecdh_p384_public(const void * scalar, void * out) {
  unsigned char scalar_copy[GSEC_P384_LEN];
  fe_p384 x;
  fe_p384 y;
  unsigned char raw[GSEC_P384_PUBLIC_LEN];

  if (scalar == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  memcpy(scalar_copy, scalar, GSEC_P384_LEN);
  if (!p384_scalarmult_base(&x, &y, scalar_copy)) {
    gsec_wipe(scalar_copy, sizeof scalar_copy);
    gsec_wipe(out, GSEC_P384_PUBLIC_LEN);
    return GSEC_ERR_INVALID;
  }
  fe_p384_to_bytes(raw, &x);
  fe_p384_to_bytes(raw + GSEC_P384_LEN, &y);
  memcpy(out, raw, GSEC_P384_PUBLIC_LEN);
  gsec_wipe(scalar_copy, sizeof scalar_copy);
  gsec_wipe(&x, sizeof x);
  gsec_wipe(&y, sizeof y);
  gsec_wipe(raw, sizeof raw);
  return GSEC_OK;
}

GSEC_Result gsec_ecdh_p384(const void * scalar, const void * peer, void * out) {
  unsigned char scalar_copy[GSEC_P384_LEN];
  unsigned char peer_copy[GSEC_P384_PUBLIC_LEN];
  p384_point point;
  fe_p384 x;
  fe_p384 y;
  unsigned char raw[GSEC_P384_LEN];

  if (scalar == NULL || peer == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  memcpy(scalar_copy, scalar, GSEC_P384_LEN);
  memcpy(peer_copy, peer, GSEC_P384_PUBLIC_LEN);
  if (!p384_point_decode(&point, peer_copy)) {
    gsec_wipe(scalar_copy, sizeof scalar_copy);
    gsec_wipe(peer_copy, sizeof peer_copy);
    gsec_wipe(out, GSEC_P384_LEN);
    gsec_wipe(&point, sizeof point);
    return GSEC_ERR_INVALID;
  }
  if (!p384_scalarmult(&x, &y, scalar_copy, &point)) {
    gsec_wipe(scalar_copy, sizeof scalar_copy);
    gsec_wipe(peer_copy, sizeof peer_copy);
    gsec_wipe(out, GSEC_P384_LEN);
    gsec_wipe(&point, sizeof point);
    gsec_wipe(&x, sizeof x);
    gsec_wipe(&y, sizeof y);
    return GSEC_ERR_INVALID;
  }
  fe_p384_to_bytes(raw, &x);
  memcpy(out, raw, GSEC_P384_LEN);
  gsec_wipe(scalar_copy, sizeof scalar_copy);
  gsec_wipe(peer_copy, sizeof peer_copy);
  gsec_wipe(&point, sizeof point);
  gsec_wipe(&x, sizeof x);
  gsec_wipe(&y, sizeof y);
  gsec_wipe(raw, sizeof raw);
  return GSEC_OK;
}
