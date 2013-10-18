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
 * Implements ftp logging portion of the engine.
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
#include "log-ftplog-ipfix.h"
#include "app-layer-ftp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-logipfix.h"

#define DEFAULT_LOG_FILENAME "ftp-ipfix.log"

#define MODULE_NAME "LogFtpLogIPFIX"

#define OUTPUT_BUFFER_SIZE 65535

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */
#define QUERY 0

TmEcode LogFtpLogIPFIX (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFtpLogIPFIXIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFtpLogIPFIXIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFtpLogIPFIXThreadInit(ThreadVars *, void *, void **);
TmEcode LogFtpLogIPFIXThreadDeinit(ThreadVars *, void *);
void LogFtpLogIPFIXExitPrintStats(ThreadVars *, void *);
static void LogFtpLogIPFIXDeInitCtx(OutputCtx *);

void TmModuleLogFtpLogIPFIXRegister (void) {
    tmm_modules[TMM_LOGFTPLOGIPFIX].name = MODULE_NAME;
    tmm_modules[TMM_LOGFTPLOGIPFIX].ThreadInit = LogFtpLogIPFIXThreadInit;
    tmm_modules[TMM_LOGFTPLOGIPFIX].Func = LogFtpLogIPFIX;
    tmm_modules[TMM_LOGFTPLOGIPFIX].ThreadExitPrintStats = LogFtpLogIPFIXExitPrintStats;
    tmm_modules[TMM_LOGFTPLOGIPFIX].ThreadDeinit = LogFtpLogIPFIXThreadDeinit;
    tmm_modules[TMM_LOGFTPLOGIPFIX].RegisterTests = NULL;
    tmm_modules[TMM_LOGFTPLOGIPFIX].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "ftp-log-ipfix", LogFtpLogIPFIXInitCtx);

    /* enable the logger for the app layer */
    AppLayerRegisterLogger(ALPROTO_FTP);
    SCLogInfo("registered %s", MODULE_NAME);
}

typedef struct LogFtpFileCtx_ {
#if 1
    LogIPFIXCtx *ipfix_ctx;
#else
    LogFileCtx *file_ctx;
#endif
    uint32_t flags; /** Store mode */
} LogFtpFileCtx;

#define LOG_FTP_DEFAULT 0
#define LOG_FTP_JSON 1        /* JSON output */
#define LOG_FTP_JSON_SYSLOG 2 /* JSON output via syslog */

typedef struct LogFtpLogThread_ {
    LogFtpFileCtx *ftplog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t ftp_cnt;

    MemBuffer *buffer;
} LogFtpLogThread;

/* TBD: move these to util-logipfix.h */
#define SURI_FTP_BASE_TID    0x3500

/* Special dimensions */
#define SURI_IP4		0x0001
#define SURI_IP6		0x0002


/* IPFIX definition of the FTP log record */
static fbInfoElementSpec_t ftp_log_int_spec[] = {
    /* Alert Millisecond (epoch) (native time) */
    { "alertMilliseconds",                  0, 0 },
    { "ftpCmd",                             0, 0 },
    { "ftpFilename",                        0, 0 },
    /* 5-tuple */
    { "sourceIPv6Address",                  0, 0 },
    { "destinationIPv6Address",             0, 0 },
    { "sourceIPv4Address",                  0, 0 },
    { "destinationIPv4Address",             0, 0 },
    { "sourceTransportPort",                0, 0 },
    { "destinationTransportPort",           0, 0 },
    { "protocolIdentifier",                 0, 0 },
    /* ftp info */
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t ftp_log_ext_spec[] = {
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
    /* ftp info */
    { "ftpCmd",                             0, 0 },
    { "ftpFilename",                        0, 0 },
    FB_IESPEC_NULL
};

/* DNS Metadata Record */
#pragma pack(push, 1)
typedef struct FtpLog_st {
    uint64_t	 AlertMilliseconds;
    fbVarfield_t ftpCmd;
    fbVarfield_t ftpFilename;
    uint8_t      sourceIPv6Address[16];
    uint8_t      destinationIPv6Address[16];

    uint32_t     sourceIPv4Address;
    uint32_t     destinationIPv4Address;

    uint16_t     sourceTransportPort;
    uint16_t     destinationTransportPort;
    uint8_t      protocolIdentifier;
} FtpLog_t;
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

    if (!fbTemplateAppendSpecArray(tmpl, ftp_log_ext_spec,
                                   (tid & (~SURI_FTP_BASE_TID)), err))    {
        return FALSE;
    }

    if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, err)) {
        SCLogInfo("failed to add external template");
        return FALSE;
    }

    /* Template should be loaded. Try setting the template again. */
    return fBufSetExportTemplate(fbuf, tid, err);
}

static TmEcode LogFtpLogIPFIXIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
                            PacketQueue *postpq, int ipproto)
{
    SCEnter();

    FtpLog_t rec;
    GError *err = NULL;
    uint16_t tid;
    LogFtpLogThread *aft = (LogFtpLogThread *)data;
    LogFtpFileCtx *flog = aft->ftplog_ctx;
#if 0
    char timebuf[64];
#endif
    char *s = "";

    /* no flow, no smtp state */
    if (p->flow == NULL) {
        SCLogDebug("no flow");
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have FTP state or not */
    FLOWLOCK_WRLOCK(p->flow); /* WRITE lock before we updated flow logged id */
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_FTP) {
        SCLogDebug("proto not ALPROTO_FTP: %u", proto);
        goto end;
    }
    FtpState *ftp_state = (FtpState *)AppLayerGetProtoStateFromPacket(p);
    if (ftp_state == NULL) {
        SCLogDebug("no smtp state, so no request logging");
        goto end;
    }
    if ((ftp_state->command != FTP_COMMAND_RETR) && 
        (ftp_state->command != FTP_COMMAND_STOR))
        goto end;

    if (ftp_state->line)
        s = strndup((char *)ftp_state->line, ftp_state->line_len);

    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);
#if 1
    rec.AlertMilliseconds = (p->ts.tv_sec * 1000) + (p->ts.tv_usec / 1000);
#else
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[46], dstip[46];
    Port sp, dp;
#endif
    if (!(PKT_IS_TOCLIENT(p))) {
        SCLogInfo("FTP logger is TOCLIENT");
        switch (ipproto) {
            case AF_INET:
#if 1
                rec.sourceIPv4Address = ntohl(GET_IPV4_SRC_ADDR_U32(p));
                rec.destinationIPv4Address = ntohl(GET_IPV4_DST_ADDR_U32(p));
                tid = SURI_FTP_BASE_TID | SURI_IP4;
#else
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
#endif
                break;
            case AF_INET6:
#if 1
                memcpy(rec.sourceIPv6Address, GET_IPV6_SRC_ADDR(p),
                       sizeof(rec.sourceIPv6Address));
                memcpy(rec.destinationIPv6Address, GET_IPV6_DST_ADDR(p),
                       sizeof(rec.destinationIPv6Address));
                tid = SURI_FTP_BASE_TID | SURI_IP6;
#else
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
#endif
                break;
            default:
                goto fend;
        }
#if 1
        rec.sourceTransportPort = p->sp;
        rec.destinationTransportPort = p->dp;
#else
        sp = p->sp;
        dp = p->dp;
#endif
    } else {
        SCLogInfo("FTP logger is TOSERVER");
        switch (ipproto) {
            case AF_INET:
#if 1
                rec.sourceIPv4Address = ntohl(GET_IPV4_DST_ADDR_U32(p));
                rec.destinationIPv4Address = ntohl(GET_IPV4_SRC_ADDR_U32(p));
                tid = SURI_FTP_BASE_TID | SURI_IP4;
#else
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), dstip, sizeof(dstip));
#endif
                break;
            case AF_INET6:
#if 1
                memcpy(rec.sourceIPv6Address, GET_IPV6_DST_ADDR(p),
                       sizeof(rec.sourceIPv6Address));
                memcpy(rec.destinationIPv6Address, GET_IPV6_SRC_ADDR(p),
                       sizeof(rec.destinationIPv6Address));
                tid = SURI_FTP_BASE_TID | SURI_IP6;
#else
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), dstip, sizeof(dstip));
#endif
                break;
            default:
                goto fend;
        }
#if 1
        rec.sourceTransportPort = p->dp;
        rec.destinationTransportPort = p->sp;
#else
        sp = p->dp;
        dp = p->sp;
#endif
    }
    rec.protocolIdentifier = IPV4_GET_IPPROTO(p);

#if 1
    switch (ftp_state->command) {
        case FTP_COMMAND_RETR:
#if 1
            rec.ftpCmd.buf = "retr";
            rec.ftpCmd.len = strlen(rec.ftpCmd.buf);
            rec.ftpFilename.buf = s;
            rec.ftpFilename.len = strlen(s);
#else
            json_object_set_new(fjs, "cmd", json_string("retr"));
            json_object_set_new(fjs, "arg", json_string(s));
#endif
            break;
        case FTP_COMMAND_STOR:
#if 1
            rec.ftpCmd.buf = "stor";
            rec.ftpCmd.len = strlen(rec.ftpCmd.buf);
            rec.ftpFilename.buf = s;
            rec.ftpFilename.len = strlen(s);
#else
            json_object_set_new(fjs, "cmd", json_string("stor"));
            json_object_set_new(fjs, "arg", json_string(s));
#endif
            break;
        default:
            break;
    }
#else
    /* reset */
    MemBufferReset(aft->buffer);

    json_t *js = json_object();
    if (js == NULL)
        goto fend;

    json_t *fjs = json_object();
    if (fjs == NULL) {
        free(js);
        goto fend;
    }

    /* time & tx */
    json_object_set_new(js, "time", json_string(timebuf));

    /* tuple */
    json_object_set_new(js, "srcip", json_string(srcip));
    json_object_set_new(js, "sp", json_integer(sp));
    json_object_set_new(js, "dstip", json_string(dstip));
    json_object_set_new(js, "dp", json_integer(dp));

    switch (ftp_state->command) {
        case FTP_COMMAND_RETR:
            json_object_set_new(fjs, "cmd", json_string("retr"));
            json_object_set_new(fjs, "arg", json_string(s));
            break;
        case FTP_COMMAND_STOR:
            json_object_set_new(fjs, "cmd", json_string("stor"));
            json_object_set_new(fjs, "arg", json_string(s));
            break;
        default:
            break;
    }
    if (ftp_state->line) free(s);

    /* smtp */
    json_object_set_new(js, "ftp", fjs);
    /*char **/s = json_dumps(js, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
    MemBufferWriteString(aft->buffer, "%s", s);
    free(s);
    free(fjs);
    free(js);
#endif

    aft->ftp_cnt++;

    SCMutexLock(&flog->ipfix_ctx->mutex);
#if 1
    /* Try to set export template */
    if (flog->ipfix_ctx->fbuf) {
        if (!SetExportTemplate(flog->ipfix_ctx->fb_model, flog->ipfix_ctx->fbuf, tid, &err)) {
            SCMutexUnlock(&flog->ipfix_ctx->mutex);
            SCLogInfo("fBufSetExportTemplate failed");
            return;
        }
    } else {
            SCMutexUnlock(&flog->ipfix_ctx->mutex);
            SCLogInfo("no fbuf");
            return;
    }

    //SCLogInfo("Appending IPFIX record to log");
    /* Now append the record to the buffer */
    if (!fBufAppend(flog->ipfix_ctx->fbuf, (uint8_t *)&rec, sizeof(rec), &err)) {
        //SCMutexUnlock(&aft->httplog_ctx->mutex);
        SCLogInfo("fBufAppend failed");
    }
#else
#ifdef HAVE_LIBJANSSON
    if (hlog->flags & LOG_FTP_JSON_SYSLOG) {
        syslog(ftp_syslog_level, "%s", (char *)aft->buffer->buffer);
    } else {
        if (hlog->flags & LOG_FTP_JSON) {
            MemBufferWriteString(aft->buffer, "\n");
        }
#endif
        (void)MemBufferPrintToFPAsString(aft->buffer, hlog->file_ctx->fp);
        fflush(hlog->file_ctx->fp);
#ifdef HAVE_LIBJANSSON
    }
#endif
#endif
    SCMutexUnlock(&flog->ipfix_ctx->mutex);
fend:
    if (AppLayerTransactionUpdateLogId(ALPROTO_FTP, p->flow)) {
        ftp_state->command = FTP_COMMAND_UNKNOWN;

        if (ftp_state->line) {
            SCFree(ftp_state->line);
            free(s);
            ftp_state->line = NULL;
            ftp_state->line_len = 0;
        }
    }

end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogFtpLogIPFIXIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogFtpLogIPFIXIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

TmEcode LogFtpLogIPFIXIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogFtpLogIPFIXIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

TmEcode LogFtpLogIPFIX (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();

    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);
    /* no flow, no smtp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (PKT_IS_IPV4(p)) {
        int r  = LogFtpLogIPFIXIPv4(tv, p, data, pq, postpq);
        SCReturnInt(r);
    } else if (PKT_IS_IPV6(p)) {
        int r  = LogFtpLogIPFIXIPv6(tv, p, data, pq, postpq);
        SCReturnInt(r);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogFtpLogIPFIXThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogFtpLogThread *aft = SCMalloc(sizeof(LogFtpLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogFtpLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for DNSLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->ftplog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode LogFtpLogIPFIXThreadDeinit(ThreadVars *t, void *data)
{
    LogFtpLogThread *aft = (LogFtpLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogFtpLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void LogFtpLogIPFIXExitPrintStats(ThreadVars *tv, void *data) {
    LogFtpLogThread *aft = (LogFtpLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("FTP logger logged %" PRIu32 " requests", aft->ftp_cnt);
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
    if (!fbTemplateAppendSpecArray(int_tmpl, ftp_log_int_spec, SURI_FTP_BASE_TID, err)) {
        SCLogInfo("fbTemplateAppendSpecArray failed");
        return NULL;
    }
    /* Add the full record template to the session */
    if (!fbSessionAddTemplate(session, TRUE, SURI_FTP_BASE_TID, int_tmpl, err)) {
        SCLogInfo("fbSessionAddTemplate failed");
        return NULL;
    }

    /* Create the full record template */
    if ((ext_tmpl = fbTemplateAlloc(model)) == NULL) {
        SCLogInfo("fbTemplateAlloc failed");
        return NULL;
    }
    SCLogInfo("ext_tmpl: %p", ext_tmpl);
    if (!fbTemplateAppendSpecArray(ext_tmpl, ftp_log_ext_spec, SURI_FTP_BASE_TID, err)) {
        SCLogInfo("fbTemplateAppendSpecArray failed");
        return NULL;
    }

    return session; 
}

/** \brief Create a new dns log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogFtpLogIPFIXInitCtx(ConfNode *conf)
{
    GError *err = NULL;

    SCLogInfo("FTP IPFIX logger initializing");

#if 1
    LogIPFIXCtx *ipfix_ctx = LogIPFIXNewCtx();
    if(ipfix_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new ipfix_ctx");
        return NULL;
    }
    if (SCConfLogOpenIPFIX(conf, ipfix_ctx, DEFAULT_LOG_FILENAME) < 0) {
        //LogFileFreeCtx(ipfix_ctx);
        return NULL;
    }
#else
    LogFileCtx* file_ctx = LogFileNewCtx();

    if(file_ctx == NULL) {
        SCLogError(SC_ERR_FTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
#endif

    LogFtpFileCtx *ftplog_ctx = SCMalloc(sizeof(LogFtpFileCtx));
    if (unlikely(ftplog_ctx == NULL)) {
#if 0
        LogFileFreeCtx(file_ctx);
#endif
        return NULL;
    }
    memset(ftplog_ctx, 0x00, sizeof(LogFtpFileCtx));

#if 1
    ftplog_ctx->ipfix_ctx = ipfix_ctx;
#else
    ftpplog_ctx->file_ctx = file_ctx;
#endif

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
#if 0
        LogFileFreeCtx(file_ctx);
#endif
        SCFree(ftplog_ctx);
        return NULL;
    }

    /* Create a new session */
    uint32_t domain = 0xbeef; /* TBD??? */
    ftplog_ctx->ipfix_ctx->session = InitExporterSession(ftplog_ctx->ipfix_ctx->fb_model, domain,
                                               &err);
    SCLogInfo("session: %p", ftplog_ctx->ipfix_ctx->session);

    ftplog_ctx->ipfix_ctx->fbuf = fBufAllocForExport(ftplog_ctx->ipfix_ctx->session, ftplog_ctx->ipfix_ctx->exporter);
    SCLogInfo("fBufAllocForExport: %p", ftplog_ctx->ipfix_ctx->fbuf);

    if (ftplog_ctx->ipfix_ctx->session && ftplog_ctx->ipfix_ctx->fbuf) {

        /* write templates */
        fbSessionExportTemplates(ftplog_ctx->ipfix_ctx->session, &err);

        /* set internal template */
        if (!fBufSetInternalTemplate(ftplog_ctx->ipfix_ctx->fbuf, SURI_FTP_BASE_TID, &err)) {
            SCLogInfo("fBufSetInternalTemplate failed");
        }
    }

    output_ctx->data = ftplog_ctx;
    output_ctx->DeInit = LogFtpLogIPFIXDeInitCtx;

    SCLogDebug("FTP log output initialized");

    return output_ctx;
}

static void LogFtpLogIPFIXDeInitCtx(OutputCtx *output_ctx)
{
    LogFtpFileCtx *ftplog_ctx = (LogFtpFileCtx *)output_ctx->data;
#if 0
    LogFileFreeCtx(smtplog_ctx->file_ctx);
#endif
    SCFree(ftplog_ctx);
    SCFree(output_ctx);
}


