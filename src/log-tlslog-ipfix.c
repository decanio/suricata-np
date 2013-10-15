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
 * Implements tls logging portion of the engine.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "log-tlslog-ipfix.h"
#include "app-layer-ssl.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logipfix.h"
#include "util-crypt.h"
#include "util-time.h"

#define DEFAULT_LOG_FILENAME "tls-ipfix.log"

static char tls_logfile_base_dir[PATH_MAX] = "/tmp";
SC_ATOMIC_DECLARE(unsigned int, cert_id);

#define MODULE_NAME "LogTlsLogIPFIX"

#if 0
#define OUTPUT_BUFFER_SIZE 65535
#define CERT_ENC_BUFFER_SIZE 2048

#define LOG_TLS_DEFAULT     0
#define LOG_TLS_EXTENDED    1
#endif

TmEcode LogTlsLogIPFIX(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogTlsLogIPFIXIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogTlsLogIPFIXIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogTlsLogIPFIXThreadInit(ThreadVars *, void *, void **);
TmEcode LogTlsLogIPFIXThreadDeinit(ThreadVars *, void *);
void LogTlsLogIPFIXExitPrintStats(ThreadVars *, void *);
static void LogTlsLogIPFIXDeInitCtx(OutputCtx *);

void TmModuleLogTlsLogIPFIXRegister(void)
{
    tmm_modules[TMM_LOGTLSLOGIPFIX].name = MODULE_NAME;
    tmm_modules[TMM_LOGTLSLOGIPFIX].ThreadInit = LogTlsLogIPFIXThreadInit;
    tmm_modules[TMM_LOGTLSLOGIPFIX].Func = LogTlsLogIPFIX;
    tmm_modules[TMM_LOGTLSLOGIPFIX].ThreadExitPrintStats = LogTlsLogIPFIXExitPrintStats;
    tmm_modules[TMM_LOGTLSLOGIPFIX].ThreadDeinit = LogTlsLogIPFIXThreadDeinit;
    tmm_modules[TMM_LOGTLSLOGIPFIX].RegisterTests = NULL;
    tmm_modules[TMM_LOGTLSLOGIPFIX].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "tls-log-ipfix", LogTlsLogIPFIXInitCtx);

    /* enable the logger for the app layer */
    AppLayerRegisterLogger(ALPROTO_TLS);

    SC_ATOMIC_INIT(cert_id);
}

void TmModuleLogTlsLogIPFIXIPv4Register(void)
{
    tmm_modules[TMM_LOGTLSLOGIPFIX4].name = "LogTlsLogIPFIXIPv4";
    tmm_modules[TMM_LOGTLSLOGIPFIX4].ThreadInit = LogTlsLogIPFIXThreadInit;
    tmm_modules[TMM_LOGTLSLOGIPFIX4].Func = LogTlsLogIPFIXIPv4;
    tmm_modules[TMM_LOGTLSLOGIPFIX4].ThreadExitPrintStats = LogTlsLogIPFIXExitPrintStats;
    tmm_modules[TMM_LOGTLSLOGIPFIX4].ThreadDeinit = LogTlsLogIPFIXThreadDeinit;
    tmm_modules[TMM_LOGTLSLOGIPFIX4].RegisterTests = NULL;
}

void TmModuleLogTlsLogIPFIXIPv6Register(void)
{
    tmm_modules[TMM_LOGTLSLOGIPFIX6].name = "LogTlsLogIPFIXIPv6";
    tmm_modules[TMM_LOGTLSLOGIPFIX6].ThreadInit = LogTlsLogIPFIXThreadInit;
    tmm_modules[TMM_LOGTLSLOGIPFIX6].Func = LogTlsLogIPFIXIPv6;
    tmm_modules[TMM_LOGTLSLOGIPFIX6].ThreadExitPrintStats = LogTlsLogIPFIXExitPrintStats;
    tmm_modules[TMM_LOGTLSLOGIPFIX6].ThreadDeinit = LogTlsLogIPFIXThreadDeinit;
    tmm_modules[TMM_LOGTLSLOGIPFIX6].RegisterTests = NULL;
}

typedef struct LogTlsFileCtx_ {
#if 1
    LogIPFIXCtx *ipfix_ctx;
#else
    LogFileCtx *file_ctx;
#endif
    uint32_t flags; /** Store mode */
} LogTlsFileCtx;

/* TBD: move these to util-logipfix.h */
#define SURI_TLS_BASE_TID    0x3300

/* Special dimensions */
#define SURI_IP4		0x0001
#define SURI_IP6		0x0002

/* IPFIX definition of the TLS log record */
static fbInfoElementSpec_t tls_log_int_spec[] = {
    /* Alert Millisecond (epoch) (native time) */
    { "alertMilliseconds",                  0, 0 },
    { "tlsSubject",                         0, 0 },
    { "tlsIssuerDn",                        0, 0 },
    { "tlsFingerprint",                     0, 0 },
    /* 5-tuple */
    { "sourceIPv6Address",                  0, 0 },
    { "destinationIPv6Address",             0, 0 },
    { "sourceIPv4Address",                  0, 0 },
    { "destinationIPv4Address",             0, 0 },
    { "sourceTransportPort",                0, 0 },
    { "destinationTransportPort",           0, 0 },
    { "protocolIdentifier",                 0, 0 },
    { "tlsVersion",                         0, 0 },
    FB_IESPEC_NULL
};
static fbInfoElementSpec_t tls_log_ext_spec[] = {
    /* Alert Millisecond (epoch) (native time) */
    { "alertMilliseconds",                  0, 0 },
    /* 5-tuple */
    { "sourceIPv6Address",                  0, SURI_IP6 },
    { "destinationIPv6Address",             0, SURI_IP6 },
    { "sourceIPv4Address",                  0, SURI_IP4 },
    { "destinationIPv4Address",             0, SURI_IP4 },
    { "sourceTransportPort",                0, 0 },
    { "destinationTransportPort",           0, 0 },
    { "protocolIdentifier",                 0, 0 },
    /* tls info */
    { "tlsSubject",                         0, 0 },
    { "tlsIssuerDn",                        0, 0 },
    { "tlsFingerprint",                     0, 0 },
    { "tlsVersion",                         0, 0 },
    FB_IESPEC_NULL
};

/* TLS Metadata Record */
#pragma pack(push, 1)
typedef struct TlsLog_st {
    uint64_t	 AlertMilliseconds;
    fbVarfield_t tlsSubject;
    fbVarfield_t tlsIssuerDn;
    fbVarfield_t tlsFingerprint;

    uint8_t      sourceIPv6Address[16];
    uint8_t      destinationIPv6Address[16];

    uint32_t     sourceIPv4Address;
    uint32_t     destinationIPv4Address;

    uint16_t     sourceTransportPort;
    uint16_t     destinationTransportPort;
    uint8_t      protocolIdentifier;
    uint16_t     tlsVersion;
} TlsLog_t;
#pragma pack(pop)

static gboolean
SetExportTemplate(
    fbInfoModel_t       *fb_model,
    fBuf_t              *fbuf,
    uint16_t            tid,
    GError              **err)
{
    fbSession_t         *session = NULL;
    fbTemplate_t        *tmpl = NULL;

    /* Try to set export template */
    if (fBufSetExportTemplate(fbuf, tid, err)) {
        return TRUE;
    }

    /* Check for error other than missing template */
    if (!g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
        return FALSE;
    }

    /* Okay. We have a missing template. Clear the Teerror and try to load it. */
    g_clear_error(err);
    session = fBufGetSession(fbuf);
    tmpl = fbTemplateAlloc(fb_model);

    //SCLogInfo("tid: %x Appending tid: %x\n", tid, (tid & (~SURI_TLS_BASE_TID)));
    if (!fbTemplateAppendSpecArray(tmpl, tls_log_ext_spec,
                                   (tid & (~SURI_TLS_BASE_TID)), err))    {
        return FALSE;
    }

    if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, err)) {
        SCLogInfo("failed to add external template");
        return FALSE;
    }

    /* Template should be loaded. Try setting the template again. */
    return fBufSetExportTemplate(fbuf, tid, err);
}

typedef struct LogTlsLogThread_ {
    LogTlsFileCtx *tlslog_ctx;

    /** LogTlsFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t tls_cnt;

#if 0
    MemBuffer *buffer;
    uint8_t*   enc_buf;
    size_t     enc_buf_len;
#endif
} LogTlsLogThread;

#if 0
static void LogTlsLogIPFIXExtended(LogTlsLogThread *aft, SSLState * state)
{
    if (state->server_connp.cert0_fingerprint != NULL) {
#if 1
#else
        MemBufferWriteString(aft->buffer, " SHA1='%s'", state->server_connp.cert0_fingerprint);
#endif
    }
    switch (state->server_connp.version) {
        case TLS_VERSION_UNKNOWN:
#if 1
#else
            MemBufferWriteString(aft->buffer, " VERSION='UNDETERMINED'");
#endif
            break;
        case SSL_VERSION_2:
#if 1
#else
            MemBufferWriteString(aft->buffer, " VERSION='SSLv2'");
#endif
            break;
        case SSL_VERSION_3:
#if 1
#else
            MemBufferWriteString(aft->buffer, " VERSION='SSLv3'");
#endif
            break;
        case TLS_VERSION_10:
#if 1
#else
            MemBufferWriteString(aft->buffer, " VERSION='TLSv1'");
#endif
            break;
        case TLS_VERSION_11:
#if 1
#else
            MemBufferWriteString(aft->buffer, " VERSION='TLS 1.1'");
#endif
            break;
        case TLS_VERSION_12:
#if 1
#else
            MemBufferWriteString(aft->buffer, " VERSION='TLS 1.2'");
#endif
            break;
        default:
#if 1
#else
            MemBufferWriteString(aft->buffer, " VERSION='0x%04x'",
                                 state->server_connp.version);
#endif
            break;
    }
#if 0
    MemBufferWriteString(aft->buffer, "\n");
#endif
}
#endif

#if 1
static int GetIPInformation(Packet *p, TlsLog_t *rec, uint16_t *tid, int ipproto)
{
    if ((PKT_IS_TOSERVER(p))) {
        switch (ipproto) {
            case AF_INET:
                rec->sourceIPv4Address = ntohl(GET_IPV4_SRC_ADDR_U32(p));
                rec->destinationIPv4Address = ntohl(GET_IPV4_DST_ADDR_U32(p));
                *tid = SURI_TLS_BASE_TID | SURI_IP4;
                break;
            case AF_INET6:
                memcpy(rec->sourceIPv6Address, GET_IPV6_SRC_ADDR(p),
                       sizeof(rec->sourceIPv6Address));
                memcpy(rec->destinationIPv6Address, GET_IPV6_DST_ADDR(p),
                       sizeof(rec->destinationIPv6Address));
                *tid = SURI_TLS_BASE_TID | SURI_IP6;
                break;
            default:
                return 0;
        }
        rec->sourceTransportPort = p->sp;
        rec->destinationTransportPort = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                rec->sourceIPv4Address = ntohl(GET_IPV4_DST_ADDR_U32(p));
                rec->destinationIPv4Address = ntohl(GET_IPV4_SRC_ADDR_U32(p));
                *tid = SURI_TLS_BASE_TID | SURI_IP4;
                break;
            case AF_INET6:
                memcpy(rec->sourceIPv6Address, GET_IPV6_DST_ADDR(p),
                       sizeof(rec->sourceIPv6Address));
                memcpy(rec->destinationIPv6Address, GET_IPV6_SRC_ADDR(p),
                       sizeof(rec->destinationIPv6Address));
                *tid = SURI_TLS_BASE_TID | SURI_IP6;
                break;
            default:
                return 0;
        }
        rec->sourceTransportPort = p->dp;
        rec->destinationTransportPort = p->sp;
    }
    rec->protocolIdentifier = IPV4_GET_IPPROTO(p);
    return 1;
}
#else
static int GetIPInformations(Packet *p, char* srcip, size_t srcip_len,
                             Port* sp, char* dstip, size_t dstip_len,
                             Port* dp, int ipproto)
{
    if ((PKT_IS_TOSERVER(p))) {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *) GET_IPV4_SRC_ADDR_PTR(p), srcip, srcip_len);
                PrintInet(AF_INET, (const void *) GET_IPV4_DST_ADDR_PTR(p), dstip, dstip_len);
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *) GET_IPV6_SRC_ADDR(p), srcip, srcip_len);
                PrintInet(AF_INET6, (const void *) GET_IPV6_DST_ADDR(p), dstip, dstip_len);
                break;
            default:
                return 0;
        }
        *sp = p->sp;
        *dp = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *) GET_IPV4_DST_ADDR_PTR(p), srcip, srcip_len);
                PrintInet(AF_INET, (const void *) GET_IPV4_SRC_ADDR_PTR(p), dstip, dstip_len);
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *) GET_IPV6_DST_ADDR(p), srcip, srcip_len);
                PrintInet(AF_INET6, (const void *) GET_IPV6_SRC_ADDR(p), dstip, dstip_len);
                break;
            default:
                return 0;
        }
        *sp = p->dp;
        *dp = p->sp;
    }
    return 1;
}
#endif

#if 0
static int CreateFileName(LogTlsFileCtx *log, Packet *p, SSLState *state, char *filename)
{
#define FILELEN 64  //filename len + extention + ending path / + some space

    int filenamelen = FILELEN + strlen(tls_logfile_base_dir);
    int file_id = SC_ATOMIC_ADD(cert_id, 1);

    if (filenamelen + 1 > PATH_MAX) {
        return 0;
    }

    /* Use format : packet time + incremental ID
     * When running on same pcap it will overwrite
     * On a live device, we will not be able to overwrite */
    snprintf(filename, filenamelen, "%s/%ld.%ld-%d.pem",
             tls_logfile_base_dir,
             p->ts.tv_sec,
             (long int)p->ts.tv_usec,
             file_id);
    return 1;
}
#endif

#if 0
static void LogTlsLogIPFIXPem(LogTlsLogThread *aft, Packet *p, SSLState *state, LogTlsFileCtx *log, int ipproto)
{
    TlsLog_t rec;
#define PEMHEADER "-----BEGIN CERTIFICATE-----\n"
#define PEMFOOTER "-----END CERTIFICATE-----\n"
    //Logging pem certificate
    char filename[PATH_MAX] = "";
    FILE* fp = NULL;
    FILE* fpmeta = NULL;
    unsigned long pemlen;
    unsigned char* pembase64ptr = NULL;
    int ret;
    SSLCertsChain *cert;

    if ((state->server_connp.cert_input == NULL) || (state->server_connp.cert_input_len == 0))
        SCReturn;

    CreateFileName(log, p, state, filename);
    if (strlen(filename) == 0) {
        SCLogWarning(SC_ERR_FOPEN, "Can't create PEM filename");
        SCReturn;
    }

    fp = fopen(filename, "w");
    if (fp == NULL) {
        SCLogWarning(SC_ERR_FOPEN, "Can't create PEM file: %s", filename);
        SCReturn;
    }

    TAILQ_FOREACH(cert, &state->server_connp.certs, next) {
        pemlen = (4 * (cert->cert_len + 2) / 3) +1;
        if (pemlen > aft->enc_buf_len) {
            aft->enc_buf = (uint8_t*) SCRealloc(aft->enc_buf, sizeof(uint8_t) * pemlen);
            if (aft->enc_buf == NULL) {
                SCLogWarning(SC_ERR_MEM_ALLOC, "Can't allocate data for base64 encoding");
                goto end_fp;
            }
            aft->enc_buf_len = pemlen;
        }

        memset(aft->enc_buf, 0, aft->enc_buf_len);

        ret = Base64Encode((unsigned char*) cert->cert_data, cert->cert_len, aft->enc_buf, &pemlen);
        if (ret != SC_BASE64_OK) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "Invalid return of Base64Encode function");
            goto end_fwrite_fp;
        }

        if (fprintf(fp, PEMHEADER)  < 0)
            goto end_fwrite_fp;

        pembase64ptr = aft->enc_buf;
        while (pemlen > 0) {
            size_t loffset = pemlen >= 64 ? 64 : pemlen;
            if (fwrite(pembase64ptr, 1, loffset, fp) != loffset)
                goto end_fwrite_fp;
            if (fwrite("\n", 1, 1, fp) != 1)
                goto end_fwrite_fp;
            pembase64ptr += 64;
            if (pemlen < 64)
                break;
            pemlen -= 64;
        }

        if (fprintf(fp, PEMFOOTER) < 0)
            goto end_fwrite_fp;
    }
    fclose(fp);

    //Logging certificate informations
    memcpy(filename + (strlen(filename) - 3), "meta", 4);
    fpmeta = fopen(filename, "w");
    if (fpmeta != NULL) {
#if 1
        rec.AlertMilliseconds = (p->ts.tv_sec * 1000) + (p->ts.tv_usec / 1000);

        if (!GetIPInformation(p, &rec))
            goto end_fwrite_fpmeta;
#else
        #define PRINT_BUF_LEN 46
        char srcip[PRINT_BUF_LEN], dstip[PRINT_BUF_LEN];
        char timebuf[64];
        Port sp, dp;
        CreateTimeString(&p->ts, timebuf, sizeof(timebuf));
        if (!GetIPInformations(p, srcip, PRINT_BUF_LEN, &sp, dstip, PRINT_BUF_LEN, &dp, ipproto))
            goto end_fwrite_fpmeta;
        if (fprintf(fpmeta, "TIME:              %s\n", timebuf) < 0)
            goto end_fwrite_fpmeta;
        if (p->pcap_cnt > 0) {
            if (fprintf(fpmeta, "PCAP PKT NUM:      %"PRIu64"\n", p->pcap_cnt) < 0)
                goto end_fwrite_fpmeta;
        }
        if (fprintf(fpmeta, "SRC IP:            %s\n", srcip) < 0)
            goto end_fwrite_fpmeta;
        if (fprintf(fpmeta, "DST IP:            %s\n", dstip) < 0)
            goto end_fwrite_fpmeta;
        if (fprintf(fpmeta, "PROTO:             %" PRIu32 "\n", p->proto) < 0)
            goto end_fwrite_fpmeta;
        if (PKT_IS_TCP(p) || PKT_IS_UDP(p)) {
            if (fprintf(fpmeta, "SRC PORT:          %" PRIu16 "\n", sp) < 0)
                goto end_fwrite_fpmeta;
            if (fprintf(fpmeta, "DST PORT:          %" PRIu16 "\n", dp) < 0)
                goto end_fwrite_fpmeta;
        }

        if (fprintf(fpmeta, "TLS SUBJECT:       %s\n"
                    "TLS ISSUERDN:      %s\n"
                    "TLS FINGERPRINT:   %s\n",
                state->server_connp.cert0_subject,
                state->server_connp.cert0_issuerdn,
                state->server_connp.cert0_fingerprint) < 0)
            goto end_fwrite_fpmeta;

        fclose(fpmeta);
#endif
    } else {
        SCLogWarning(SC_ERR_FOPEN, "Can't open meta file: %s",
                     filename); 
        SCReturn;
    }

    /* Reset the store flag */
    state->server_connp.cert_log_flag &= ~SSL_TLS_LOG_PEM;
    SCReturn;

end_fwrite_fp:
    fclose(fp);
    SCLogWarning(SC_ERR_FWRITE, "Unable to write certificate");
end_fwrite_fpmeta:
    if (fpmeta) {
        fclose(fpmeta);
        SCLogWarning(SC_ERR_FWRITE, "Unable to write certificate metafile");
    }
    SCReturn;
end_fp:
    fclose(fp);
}
#endif

static TmEcode LogTlsLogIPFIXIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq, int ipproto)
{

    SCEnter();
    TlsLog_t rec;
    GError *err= NULL;
    uint16_t tid;
    LogTlsLogThread *aft = (LogTlsLogThread *) data;
    LogTlsFileCtx *tlog = aft->tlslog_ctx;

#if 0
    char timebuf[64];
#endif

    /* no flow, no tls state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have TLS state or not */
    FLOWLOCK_WRLOCK(p->flow);
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_TLS)
        goto end;

    SSLState *ssl_state = (SSLState *) AppLayerGetProtoStateFromPacket(p);
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, so no request logging");
        goto end;
    }

    if (ssl_state->server_connp.cert0_issuerdn == NULL || ssl_state->server_connp.cert0_subject == NULL)
        goto end;

#if 0
    if (ssl_state->server_connp.cert_log_flag & SSL_TLS_LOG_PEM) {
        LogTlsLogIPFIXPem(aft, p, ssl_state, hlog, ipproto);
    }
#endif

    if (AppLayerTransactionGetLogId(p->flow) != 0) {
        goto end;
    }

#if 1
    rec.AlertMilliseconds = (p->ts.tv_sec * 1000) + (p->ts.tv_usec / 1000);
    if (!GetIPInformation(p, &rec, &tid, ipproto)) {
        goto end;
    }
    rec.tlsVersion = ssl_state->server_connp.version;
    if (ssl_state->server_connp.cert0_fingerprint != NULL) {
        rec.tlsFingerprint.buf = (uint8_t *)ssl_state->server_connp.cert0_fingerprint;
        rec.tlsFingerprint.len = strlen(ssl_state->server_connp.cert0_fingerprint);
    } else {
        rec.tlsFingerprint.len = 0;
    }
    if (ssl_state->server_connp.cert0_subject != NULL) {
        rec.tlsSubject.buf = (uint8_t *)ssl_state->server_connp.cert0_subject;
        rec.tlsSubject.len = strlen(ssl_state->server_connp.cert0_subject);
    } else {
        rec.tlsSubject.len = 0;
    }
    if (ssl_state->server_connp.cert0_issuerdn != NULL) {
        rec.tlsIssuerDn.buf = (uint8_t *)ssl_state->server_connp.cert0_issuerdn;
        rec.tlsIssuerDn.len = strlen(ssl_state->server_connp.cert0_issuerdn);
    } else {
        rec.tlsIssuerDn.len = 0;
    }
#else
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    #define PRINT_BUF_LEN 46
    char srcip[PRINT_BUF_LEN], dstip[PRINT_BUF_LEN];
    Port sp, dp;
    if (!GetIPInformations(p, srcip, PRINT_BUF_LEN,
                           &sp, dstip, PRINT_BUF_LEN, &dp, ipproto)) {
        goto end;
    }
#endif

    /* reset */
#if 0
    MemBufferReset(aft->buffer);

    MemBufferWriteString(aft->buffer,
                         "%s %s:%d -> %s:%d  TLS: Subject='%s' Issuerdn='%s'",
                         timebuf, srcip, sp, dstip, dp,
                         ssl_state->server_connp.cert0_subject, ssl_state->server_connp.cert0_issuerdn);
#endif

    AppLayerTransactionUpdateLogId(ALPROTO_TLS, p->flow);

#if 0
    if (tlog->flags & LOG_TLS_EXTENDED) {
        LogTlsLogIPFIXExtended(aft, ssl_state);
    } else {
#if 0
        MemBufferWriteString(aft->buffer, "\n");
#endif
    }
#endif

    aft->tls_cnt ++;

    SCMutexLock(&tlog->ipfix_ctx->mutex);
#if 1
    /* Try to set export template */
    if (tlog->ipfix_ctx->fbuf) {
        if (!SetExportTemplate(tlog->ipfix_ctx->fb_model, tlog->ipfix_ctx->fbuf, tid, &err)) {
            SCMutexUnlock(&tlog->ipfix_ctx->mutex);
            SCLogInfo("fBufSetExportTemplate failed");
            goto end;
        }
    } else {
        SCMutexUnlock(&tlog->ipfix_ctx->mutex);
        goto end;
    }

    //SCLogInfo("Appending IPFIX record to log");
    /* Now append the record to the buffer */
    if (!fBufAppend(tlog->ipfix_ctx->fbuf, (uint8_t *)&rec, sizeof(rec), &err)) {
        //SCMutexUnlock(&aft->httplog_ctx->mutex);
        SCLogInfo("fBufAppend failed");
    }

#else
    MemBufferPrintToFPAsString(aft->buffer, hlog->file_ctx->fp);
    fflush(hlog->file_ctx->fp);
#endif
    SCMutexUnlock(&tlog->ipfix_ctx->mutex);

end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);

}

TmEcode LogTlsLogIPFIXIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogTlsLogIPFIXIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

TmEcode LogTlsLogIPFIXIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogTlsLogIPFIXIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

TmEcode LogTlsLogIPFIX(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (PKT_IS_IPV4(p)) {
        SCReturnInt(LogTlsLogIPFIXIPv4(tv, p, data, pq, postpq));
    } else if (PKT_IS_IPV6(p)) {
        SCReturnInt(LogTlsLogIPFIXIPv6(tv, p, data, pq, postpq));
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogTlsLogIPFIXThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogTlsLogThread *aft = SCMalloc(sizeof(LogTlsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogTlsLogThread));

    if (initdata == NULL) {
        SCLogDebug( "Error getting context for TLSLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    struct stat stat_buf;
    if (stat(tls_logfile_base_dir, &stat_buf) != 0) {
        int ret;
        ret = mkdir(tls_logfile_base_dir, S_IRWXU|S_IXGRP|S_IRGRP);
        if (ret != 0) {
            int err = errno;
            if (err != EEXIST) {
                SCLogError(SC_ERR_LOGDIR_CONFIG,
                        "Cannot create certs drop directory %s: %s",
                        tls_logfile_base_dir, strerror(err));
                exit(EXIT_FAILURE);
            }
        } else {
            SCLogInfo("Created certs drop directory %s",
                    tls_logfile_base_dir);
        }

    }

#if 0
    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
#endif

#if 0
    aft->enc_buf = SCMalloc(CERT_ENC_BUFFER_SIZE);
    if (aft->enc_buf == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    aft->enc_buf_len = CERT_ENC_BUFFER_SIZE;
    memset(aft->enc_buf, 0, aft->enc_buf_len);
#endif

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->tlslog_ctx = ((OutputCtx *) initdata)->data;

    *data = (void *) aft;
    return TM_ECODE_OK;
}

TmEcode LogTlsLogIPFIXThreadDeinit(ThreadVars *t, void *data)
{
    LogTlsLogThread *aft = (LogTlsLogThread *) data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

#if 0
    MemBufferFree(aft->buffer);
#endif
    /* clear memory */
    memset(aft, 0, sizeof(LogTlsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void LogTlsLogIPFIXExitPrintStats(ThreadVars *tv, void *data)
{
    LogTlsLogThread *aft = (LogTlsLogThread *) data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("TLS IPFIX logger logged %" PRIu32 " requests", aft->tls_cnt);
}

static fbSession_t *
InitExporterSession(fbInfoModel_t *fb_model, uint32_t domain, GError **err)
{
    fbInfoModel_t   *model = fb_model;
    fbTemplate_t    *int_tmpl = NULL;
    fbTemplate_t    *ext_tmpl = NULL;
    fbSession_t     *session = NULL;

    /* Allocate the session */
    session = fbSessionAlloc(model);

    /* set observation domain */
    fbSessionSetDomain(session, domain);

    /* Create the full record template */
    if ((int_tmpl = fbTemplateAlloc(model)) == NULL) {
        SCLogInfo("fbTemplateAlloc failed");
        return NULL;
    }
    SCLogInfo("int_tmpl: %p", int_tmpl);
    if (!fbTemplateAppendSpecArray(int_tmpl, tls_log_int_spec, SURI_TLS_BASE_TID, err)) {
        SCLogInfo("fbTemplateAppendSpecArray failed");
        return NULL;
    }
    /* Add the full record template to the session */
    if (!fbSessionAddTemplate(session, TRUE, SURI_TLS_BASE_TID, int_tmpl, err)) {
        SCLogInfo("fbSessionAddTemplate failed");
        return NULL;
    }

    /* Create the full record template */
    if ((ext_tmpl = fbTemplateAlloc(model)) == NULL) {
        SCLogInfo("fbTemplateAlloc failed");
        return NULL;
    }
    SCLogInfo("ext_tmpl: %p", ext_tmpl);
    if (!fbTemplateAppendSpecArray(ext_tmpl, tls_log_ext_spec, SURI_TLS_BASE_TID, err)) {
        SCLogInfo("fbTemplateAppendSpecArray failed");
        return NULL;
    }

    return session; 
}

/** \brief Create a new tls log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogTlsLogIPFIXInitCtx(ConfNode *conf)
{
    GError *err = NULL;

    SCLogInfo("TLS IPFIX logger initializing");

#if 1
    LogIPFIXCtx *ipfix_ctx = LogIPFIXNewCtx();
    if  (ipfix_ctx == NULL) {
        SCLogError(SC_ERR_TLS_LOG_GENERIC, "couldn't create new ipfix_ctx");
        return NULL;
    }
    if (SCConfLogOpenIPFIX(conf, ipfix_ctx, DEFAULT_LOG_FILENAME) < 0) {
        return NULL;
    }
#else
    LogFileCtx* file_ctx = LogFileNewCtx();

    if (file_ctx == NULL) {
        SCLogError(SC_ERR_TLS_LOG_GENERIC, "LogTlsLogInitCtx: Couldn't "
        "create new file_ctx");
        return NULL;
    }

    char *s_default_log_dir = NULL;
    s_default_log_dir = ConfigGetLogDirectory();

    const char *s_base_dir = NULL;
    s_base_dir = ConfNodeLookupChildValue(conf, "certs-log-dir");
    if (s_base_dir == NULL || strlen(s_base_dir) == 0) {
        strlcpy(tls_logfile_base_dir,
                s_default_log_dir, sizeof(tls_logfile_base_dir));
    } else {
        if (PathIsAbsolute(s_base_dir)) {
            strlcpy(tls_logfile_base_dir,
                    s_base_dir, sizeof(tls_logfile_base_dir));
        } else {
            snprintf(tls_logfile_base_dir, sizeof(tls_logfile_base_dir),
                    "%s/%s", s_default_log_dir, s_base_dir);
        }
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
        goto filectx_error;
    }
#endif

    LogTlsFileCtx *tlslog_ctx = SCCalloc(1, sizeof(LogTlsFileCtx));
    if (unlikely(tlslog_ctx == NULL))
        goto filectx_error;
    memset(tlslog_ctx, 0x00, sizeof(LogTlsFileCtx));

#if 1
    tlslog_ctx->ipfix_ctx = ipfix_ctx;
#else
    tlslog_ctx->file_ctx = file_ctx;
#endif

#if 0
    const char *extended = ConfNodeLookupChildValue(conf, "extended");
    if (extended == NULL) {
        tlslog_ctx->flags |= LOG_TLS_DEFAULT;
    } else {
        if (ConfValIsTrue(extended)) {
            tlslog_ctx->flags |= LOG_TLS_EXTENDED;
        }
    }
#endif

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        goto tlslog_error;

    /* Create a new session */
    uint32_t domain = 0xbeef; /* TBD??? */
    tlslog_ctx->ipfix_ctx->session = InitExporterSession(tlslog_ctx->ipfix_ctx->fb_model, domain,
                                               &err);
    SCLogInfo("session: %p", tlslog_ctx->ipfix_ctx->session);

    tlslog_ctx->ipfix_ctx->fbuf = fBufAllocForExport(tlslog_ctx->ipfix_ctx->session, tlslog_ctx->ipfix_ctx->exporter);
    SCLogInfo("fBufAllocForExport: %p", tlslog_ctx->ipfix_ctx->fbuf);

    if (tlslog_ctx->ipfix_ctx->session && tlslog_ctx->ipfix_ctx->fbuf) {

        /* write templates */
        fbSessionExportTemplates(tlslog_ctx->ipfix_ctx->session, &err);

        /* set internal template */
        if (!fBufSetInternalTemplate(tlslog_ctx->ipfix_ctx->fbuf, SURI_TLS_BASE_TID, &err)) {
            SCLogInfo("fBufSetInternalTemplate failed");
        }
    }

    output_ctx->data = tlslog_ctx;
    output_ctx->DeInit = LogTlsLogIPFIXDeInitCtx;

    SCLogDebug("TLS IPFIX log output initialized");

    return output_ctx;

tlslog_error:
    SCFree(tlslog_ctx);
filectx_error:
#if 0
    LogFileFreeCtx(file_ctx);
#endif
    return NULL;
}

static void LogTlsLogIPFIXDeInitCtx(OutputCtx *output_ctx)
{
    LogTlsFileCtx *tlslog_ctx = (LogTlsFileCtx *) output_ctx->data;
#if 0
    LogFileFreeCtx(tlslog_ctx->file_ctx);
#endif
    SCFree(tlslog_ctx);
    SCFree(output_ctx);
}
