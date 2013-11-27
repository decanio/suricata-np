/* Copyright (C) 2007-2011 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Tom DeCanio <td@npulsetech.com>
 */

#ifndef __UTIL_IPFIX_H__
#define __UTIL_IPFIX_H__

#include "conf.h"            /* ConfNode   */
#include "tm-modules.h"      /* LogFileCtx */

#define SURI_DNS_BASE_TID    0x3200

/* Special dimensions */
#define SURI_IP4		0x0001
#define SURI_IP6		0x0002

int SCConfOpenIPFIX(ConfNode *conf, LogIPFIXCtx *, const char *);

#endif /* __UTIL_IPFIX_H__ */
