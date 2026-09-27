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
 * Run gsec_selftest and print the status string. Nothing else: the known
 * answers are not the program's to display.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/selftest.h>

#include <stdio.h>

int main(void) {
  GSEC_Result result = gsec_selftest();

  printf("%s\n", gsec_result_string(result));
  return result == GSEC_OK ? 0 : 1;
}
