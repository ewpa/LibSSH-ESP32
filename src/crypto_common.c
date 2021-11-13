/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2020 by Anderson Toshiyuki Sasaki - Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "libssh_esp32_config.h"
#include "libssh/crypto.h"

int secure_memcmp(const void *s1, const void *s2, size_t n)
{
    int rc = 0;
    const unsigned char *p1 = s1;
    const unsigned char *p2 = s2;
    for (; n > 0; --n) {
        rc |= *p1++ ^ *p2++;
    }
    return (rc != 0);
}

