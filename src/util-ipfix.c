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

#define NPULSE_PEN	38885
#if 1
#define CERT_PEN	NPULSE_PEN /* override CERT_PEN with NPULSE_PEN */
#else
#define CERT_PEN        6871
#endif

static fbInfoElement_t info_elements[] = {
    /* nPulse defined IEs */
    FB_IE_INIT("alertMilliseconds", NPULSE_PEN, 40, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("npulseAppLabel", NPULSE_PEN, 32, 2, FB_IE_F_ENDIAN),
#if 1
    FB_IE_INIT("dnsIPv4Address", CERT_PEN, 8, 4, FB_IE_F_ENDIAN),
#else
    FB_IE_INIT("dnsIPv4Address", 0, 8, 4, FB_IE_F_ENDIAN),
#endif

    /* CERT defined IEs */
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
    /* dns IEs */
    FB_IE_INIT("dnsQueryResponse", CERT_PEN, 174, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsQRType", CERT_PEN, 175, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsAuthoritative", CERT_PEN, 176, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsNXDomain", CERT_PEN, 177, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsRRSection", CERT_PEN, 178, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsQName", CERT_PEN, 179, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsCName", CERT_PEN, 180, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsMXPreference", CERT_PEN, 181, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsMXExchange", CERT_PEN, 182, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsNSDName", CERT_PEN, 183, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsPTRDName", CERT_PEN, 184, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsTTL", CERT_PEN, 199, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsTXTData", CERT_PEN, 208, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsSOASerial", CERT_PEN, 209, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSOARefresh", CERT_PEN, 210, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSOARetry", CERT_PEN, 211, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSOAExpire", CERT_PEN, 212, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSOAMinimum", CERT_PEN, 213, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSOAMName", CERT_PEN, 214, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsSOARName", CERT_PEN, 215, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsSRVPriority", CERT_PEN, 216, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSRVWeight", CERT_PEN, 217, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSRVPort", CERT_PEN, 218, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSRVTarget", CERT_PEN, 219, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsID", CERT_PEN, 226, 2, FB_IE_F_ENDIAN),
    /* dnssec IEs */
    FB_IE_INIT("dnsAlgorithm", CERT_PEN, 227, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsKeyTag", CERT_PEN, 228, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSigner", CERT_PEN, 229, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsSignature", CERT_PEN, 230, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsDigest", CERT_PEN, 231, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsPublicKey", CERT_PEN, 232, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsSalt", CERT_PEN, 233, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsHashData", CERT_PEN, 234, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dnsIterations", CERT_PEN, 235, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSignatureExpiration", CERT_PEN, 236, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSignatureInception", CERT_PEN, 237, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsDigestType", CERT_PEN, 238, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsLabels", CERT_PEN, 239, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsTypeCovered", CERT_PEN, 240, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsFlags", CERT_PEN, 241, 2, FB_IE_F_ENDIAN),
    /* FTP IEs */
    FB_IE_INIT("ftpReturn", CERT_PEN, 131, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("ftpUser", CERT_PEN, 132, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("ftpPass", CERT_PEN,133, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("ftpType", CERT_PEN,134, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("ftpRespCode", CERT_PEN,135, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("ftpCmd", NPULSE_PEN,45, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("ftpFilename", NPULSE_PEN,46, FB_IE_VARLEN, FB_IE_F_NONE),
    /* smtp IEs */
    FB_IE_INIT("smtpHello", CERT_PEN, 162, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("smtpFrom", CERT_PEN, 163, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("smtpTo", CERT_PEN, 164, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("smtpContentType", CERT_PEN, 165, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("smtpSubject", CERT_PEN, 166, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("smtpFilename", CERT_PEN, 167, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("smtpContentDisposition", CERT_PEN, 168, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("smtpResponse", CERT_PEN, 169, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("smtpEnhanced", CERT_PEN, 170, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("smtpSize", CERT_PEN, 222, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("smtpDate", CERT_PEN, 251, FB_IE_VARLEN, FB_IE_F_NONE),
    /* tls IEs */
    FB_IE_INIT("tlsVersion", NPULSE_PEN, 41, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("tlsSubject", NPULSE_PEN, 42, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("tlsIssuerDn", NPULSE_PEN, 43, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("tlsFingerprint", NPULSE_PEN, 44, FB_IE_VARLEN, FB_IE_F_NONE),
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
SCConfOpenIPFIX(ConfNode *conf,
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
        ipfix_ctx->exporter = fbExporterAllocFile(log_path);
    }
    SCLogInfo("exporter: %p", ipfix_ctx->exporter);

    return 0;
}
