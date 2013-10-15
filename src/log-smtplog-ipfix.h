/* Copyright (C) 2007-2013 Open Information Security Foundation
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

#ifndef __LOG_SMTPLOG_IPFIX_H__
#define __LOG_SMTPLOG_IPFIX_H__

void TmModuleLogSmtpLogIPFIXRegister (void);
void TmModuleLogSmtpLogIPFIXIPv4Register (void);
void TmModuleLogSmtpLogIPFIXIPv6Register (void);
OutputCtx *LogSmtpLogIPFIXInitCtx(ConfNode *);

#endif /* __LOG_SMTPLOG_IPFIX_H__ */
