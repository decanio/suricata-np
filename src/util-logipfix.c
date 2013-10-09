/* vi: set et ts=4: */
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
 *
 * Logging to IPFIX
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "suricata-common.h" /* errno.h, string.h, etc. */
#include "tm-modules.h"      /* LogFileCtx */
#include "conf.h"            /* ConfNode, etc. */
#include "output.h"          /* DEFAULT_LOG_* */

#include <fixbuf/public.h>

#define CERT_PEN        6871
#define NPULSE_PEN	38885

static fbInfoElement_t info_elements[] = {
    FB_IE_INIT("alertMilliseconds", NPULSE_PEN, 40, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpServerString", CERT_PEN, 110, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpUserAgent", CERT_PEN, 111, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpGet", CERT_PEN, 112, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpConnection", CERT_PEN, 113, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpVersion", CERT_PEN, 114, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpReferer", CERT_PEN, 115, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpLocation", CERT_PEN, 116, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpHost", CERT_PEN, 117, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpContentLength", CERT_PEN, 118, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpAge", CERT_PEN, 119, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpAccept", CERT_PEN, 120, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpAcceptLanguage", CERT_PEN, 121, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpContentType", CERT_PEN, 122, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpResponse", CERT_PEN, 123, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpCookie", CERT_PEN, 220, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpSetCookie", CERT_PEN, 221, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpAuthorization", CERT_PEN, 252, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpVia", CERT_PEN, 253, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpX-Forwarded-For", CERT_PEN, 254, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("httpRefresh", CERT_PEN, 256, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_NULL
};


/** \brief open a generic output "log file", which may be a regular file or a socket
 *  \param conf ConfNode structure for the output section in question
 *  \param log_ctx Log file context allocated by caller
 *  \param default_filename Default name of file to open, if not specified in ConfNode
 *  \retval 0 on success
 *  \retval -1 on error
 */
int
SCConfLogOpenIPFIX(ConfNode *conf,
                   LogIPFIXCtx *ipfix_ctx,
                   const char *default_filename)
{
    char log_path[PATH_MAX];
    char *log_dir;
    const char *filename;
    fbConnSpec_t spec;

    memset(&spec, 0, sizeof(spec));

    // Arg check
    if (conf == NULL || ipfix_ctx == NULL || default_filename == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "SCConfLogOpenIPFIX(conf %p, ctx %p, default %p) "
                   "missing an argument",
                   conf, ipfix_ctx, default_filename);
        return -1;
    }
    if (ipfix_ctx->fb_model != NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "SCConfLogOpenGeneric: previously initialized Log CTX "
                   "encountered");
        return -1;
    }

    // Resolve the given config
    filename = ConfNodeLookupChildValue(conf, "filename");
    if (filename == NULL) {
        const char *transport = ConfNodeLookupChildValue(conf, "transport");
        if (transport == NULL) {
            transport = "udp";
        }
        if (strcmp(transport, "sctp") == 0) {
            spec.transport = FB_SCTP;
        } else if (strcmp(transport, "udp") == 0) {
            spec.transport = FB_UDP;
        } else if (strcmp(transport, "tcp") == 0) {
            spec.transport = FB_TCP;
        }
        const char *host = ConfNodeLookupChildValue(conf, "host");
        if (host == NULL) {
        }
        spec.host = (char *)host;
        const char *ipfix_port = ConfNodeLookupChildValue(conf, "ipfix-port");
        if (ipfix_port == NULL) {
            ipfix_port = "4739";
        }
        spec.svc = (char *)ipfix_port;
    } else {
        log_dir = ConfigGetLogDirectory();

        if (PathIsAbsolute(filename)) {
            snprintf(log_path, PATH_MAX, "%s", filename);
        } else {
            snprintf(log_path, PATH_MAX, "%s/%s", log_dir, filename);
        }
    }

    ipfix_ctx->fb_model = fbInfoModelAlloc();
    SCLogInfo("fbInfoModelAlloc %p", ipfix_ctx->fb_model);
    if (ipfix_ctx->fb_model) {
        fbInfoModelAddElementArray(ipfix_ctx->fb_model, info_elements);
    }

    if (filename == NULL) {
        /* Allocate an exporter with connection to the collector */
        ipfix_ctx->exporter = fbExporterAllocNet(&spec);
    } else {
        /* Allocate an exporter for the file */
        ipfix_ctx->exporter = fbExporterAllocFile(filename);
    }
    SCLogInfo("exporter: %p", ipfix_ctx->exporter);

    return 0;
}
