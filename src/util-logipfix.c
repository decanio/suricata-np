/* vi: set et ts=4: */
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

#if 0
/** \brief connect to the indicated local stream socket, logging any errors
 *  \param path filesystem path to connect to
 *  \retval FILE* on success (fdopen'd wrapper of underlying socket)
 *  \retval NULL on error
 */
static FILE *
SCLogOpenUnixSocketFp(const char *path, int sock_type)
{
    struct sockaddr_un sun;
    int s = -1;
    FILE * ret = NULL;

    memset(&sun, 0x00, sizeof(sun));

    s = socket(PF_UNIX, sock_type, 0);
    if (s < 0) goto err;

    sun.sun_family = AF_UNIX;
    strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

    if (connect(s, (const struct sockaddr *)&sun, sizeof(sun)) < 0)
        goto err;

    ret = fdopen(s, "w");
    if (ret == NULL)
        goto err;

    return ret;

err:
    SCLogError(SC_ERR_SOCKET, "Error connecting to socket \"%s\": %s",
               path, strerror(errno));

    if (s >= 0)
        close(s);

    return NULL;
}

/** \brief open the indicated file, logging any errors
 *  \param path filesystem path to open
 *  \param append_setting open file with O_APPEND: "yes" or "no"
 *  \retval FILE* on success
 *  \retval NULL on error
 */
static FILE *
SCLogOpenFileFp(const char *path, const char *append_setting)
{
    FILE *ret = NULL;

    if (strcasecmp(append_setting, "yes") == 0) {
        ret = fopen(path, "a");
    } else {
        ret = fopen(path, "w");
    }

    if (ret == NULL)
        SCLogError(SC_ERR_FOPEN, "Error opening file: \"%s\": %s",
                   path, strerror(errno));
    return ret;
}
#endif

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
    GError *err = NULL;

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

#if 0
    /* Create a new session */
    uint32_t domain = 0xbeef; /* TBD??? */
    ipfix_ctx->session = InitExporterSession(ipfix_ctx->fb_model, domain,
                                             &err);
    SCLogInfo("session: %p", ipfix_ctx->session);

    ipfix_ctx->fbuf = fBufAllocForExport(ipfix_ctx->session, ipfix_ctx->exporter);
    SCLogInfo("fBufAllocForExport: %p", ipfix_ctx->fbuf);

    if (ipfix_ctx->session && ipfix_ctx->fbuf) {

        /* write templates */
        fbSessionExportTemplates(ipfix_ctx->session, &err);

        /* set internal template */
        if (!fBufSetInternalTemplate(ipfix_ctx->fbuf, SURI_HTTP_BASE_TID, &err)) {
            SCLogInfo("fBufSetInternalTemplate failed");
        }
    }
#endif

#if 0
    if (filename == NULL)
        filename = default_filename;

    log_dir = ConfigGetLogDirectory();

    if (PathIsAbsolute(filename)) {
        snprintf(log_path, PATH_MAX, "%s", filename);
    } else {
        snprintf(log_path, PATH_MAX, "%s/%s", log_dir, filename);
    }
#endif

#if 0
    filetype = ConfNodeLookupChildValue(conf, "filetype");
    if (filetype == NULL)
        filetype = DEFAULT_LOG_FILETYPE;

    // Now, what have we been asked to open?
    if (strcasecmp(filetype, "unix_stream") == 0) {
        log_ctx->fp = SCLogOpenUnixSocketFp(log_path, SOCK_STREAM);
    } else if (strcasecmp(filetype, "unix_dgram") == 0) {
        log_ctx->fp = SCLogOpenUnixSocketFp(log_path, SOCK_DGRAM);
    } else if (strcasecmp(filetype, DEFAULT_LOG_FILETYPE) == 0) {
        const char *append;

        append = ConfNodeLookupChildValue(conf, "append");
        if (append == NULL)
            append = DEFAULT_LOG_MODE_APPEND;
        log_ctx->fp = SCLogOpenFileFp(log_path, append);
    } else {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                   "%s.type.  Expected \"regular\" (default), \"unix_stream\" "
                   "or \"unix_dgram\"",
                   conf->name);
    }

    if (log_ctx->fp == NULL)
        return -1; // Error already logged by Open...Fp routine

    SCLogInfo("%s output device (%s) initialized: %s", conf->name, filetype,
              filename);
#endif

    return 0;
}
