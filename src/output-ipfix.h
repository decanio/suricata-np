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

#ifndef __ALERT_IPFIX_H__
#define __ALERT_IPFIX_H__

void TmModuleOutputIPFIXRegister (void);

#ifdef HAVE_IPFIX

OutputCtx *OutputIPFIXInitCtx(ConfNode *);

/*
 * Global configuration context data
 */
typedef struct OutputIPFIXCtx_ {
    //LogFileCtx *file_ctx;
    LogIPFIXCtx *ipfix_ctx;
    OutputCtx *drop_ctx;
    OutputCtx *files_ctx;
    OutputCtx *http_ctx;
    OutputCtx *tls_ctx;
} OutputIPFIXCtx;

typedef struct AlertIPFIXThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    //LogFileCtx* file_ctx;
    LogIPFIXCtx* ipfix_ctx;

    uint64_t alert_cnt;
    uint64_t dns_cnt;
    uint64_t drop_cnt;
    uint64_t files_cnt;
    uint64_t http_cnt;
    uint64_t tls_cnt;
    OutputCtx *drop_ctx;
    OutputCtx *files_ctx;
    OutputCtx *http_ctx;
    OutputCtx *tls_ctx;
} AlertIPFIXThread;

#endif /* HAVE_IPFIX */

#endif /* __ALERT_IPFIX_H__ */

