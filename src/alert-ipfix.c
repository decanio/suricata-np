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
 * Logs alerts in a IPFIX format either to a file or to an IPFIX collector.
 *
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "util-debug.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"
#include "util-classification-config.h"

#include "output.h"
#include "alert-ipfix.h"

#include "util-cuda.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-logopenfile.h"

#ifndef HAVE_IPFIX
/** Handle the case where no IPFIX support is compiled in.
 *
 */

TmEcode AlertIPFIX (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertIPFIXThreadInit(ThreadVars *, void *, void **);
TmEcode AlertIPFIXThreadDeinit(ThreadVars *, void *);
int AlertIPFIXOpenFileCtx(LogFileCtx *, char *);
void AlertIPFIXRegisterTests(void);

void TmModuleAlertIPFIXRegister (void) {
    tmm_modules[TMM_ALERTIPFIX].name = "AlertIPFIX";
    tmm_modules[TMM_ALERTIPFIX].ThreadInit = AlertIPFIXThreadInit;
    tmm_modules[TMM_ALERTIPFIX].Func = AlertIPFIX;
    tmm_modules[TMM_ALERTIPFIX].ThreadDeinit = AlertIPFIXThreadDeinit;
    tmm_modules[TMM_ALERTIPFIX].RegisterTests = AlertIPFIXRegisterTests;
}

OutputCtx *AlertIPFIXInitCtx(ConfNode *conf)
{
    SCLogDebug("Can't init IPFIX output - IPFIX support was disabled during build.");
    return NULL;
}

TmEcode AlertIPFIXThreadInit(ThreadVars *t, void *initdata, void **data)
{
    SCLogDebug("Can't init IPFIX output thread - IPFIX support was disabled during build.");
    return TM_ECODE_FAILED;
}

TmEcode AlertIPFIX (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return TM_ECODE_OK;
}

TmEcode AlertIPFIXThreadDeinit(ThreadVars *t, void *data)
{
    return TM_ECODE_FAILED;
}

void AlertIPFIXRegisterTests (void) {
}

#else /* implied we do have IPFIX support */

#include <fixbuf/public.h>

#define DEFAULT_LOG_FILENAME "ipfix.log"

#define MODULE_NAME "AlertIPFIX"

TmEcode AlertIPFIX (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertIPFIXIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertIPFIXIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertIPFIXThreadInit(ThreadVars *, void *, void **);
TmEcode AlertIPFIXThreadDeinit(ThreadVars *, void *);
void AlertIPFIXExitPrintStats(ThreadVars *, void *);
void AlertIPFIXRegisterTests(void);
static void AlertIPFIXDeInitCtx(OutputCtx *);

void TmModuleAlertIPFIXRegister (void) {
    tmm_modules[TMM_ALERTIPFIX].name = MODULE_NAME;
    tmm_modules[TMM_ALERTIPFIX].ThreadInit = AlertIPFIXThreadInit;
    tmm_modules[TMM_ALERTIPFIX].Func = AlertIPFIX;
    tmm_modules[TMM_ALERTIPFIX].ThreadExitPrintStats = AlertIPFIXExitPrintStats;
    tmm_modules[TMM_ALERTIPFIX].ThreadDeinit = AlertIPFIXThreadDeinit;
    tmm_modules[TMM_ALERTIPFIX].RegisterTests = AlertIPFIXRegisterTests;
    tmm_modules[TMM_ALERTIPFIX].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "ipfix", AlertIPFIXInitCtx);
}

typedef struct AlertIPFIXCtx_ {
    fbInfoModel_t *fb_model;
    fbExporter_t *exporter;
    fbSession_t *session;
    fBuf_t* fbuf;

    SCMutex mutex;

    /* Alerts on the module */
    uint64_t alerts;
} AlertIPFIXCtx;

typedef struct AlertIPFIXThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    //LogFileCtx* file_ctx;
    /** AlertIPFIXCtx has a mutex to allow multithreading */
    AlertIPFIXCtx *ctx;

    //fBuf_t* fbuf;
} AlertIPFIXThread;

#define NPULSE_PEN	38885

#define SURI_ALERT_BASE_TID	0x3000

/* Special dimensions */
#define SURI_IP4		0x0001
#define SURI_IP6		0x0002

/* IPFIX definition of the Alert record */
static fbInfoElementSpec_t alert_int_spec[] = {
    /* Alert Millisecond (epoch) (native time) */
    { "alertMilliseconds",                  0, 0 },
    /* 5-tuple */
    { "sourceIPv6Address",                  0, 0 },
    { "destinationIPv6Address",             0, 0 },
    { "sourceIPv4Address",                  0, 0 },
    { "destinationIPv4Address",             0, 0 },
    { "sourceTransportPort",                0, 0 },
    { "destinationTransportPort",           0, 0 },
    { "protocolIdentifier",                 0, 0 },
    /* alert info */
    { "suriPad",                            1, 0 },
    { "suriRev",                            1, 0 },
    { "suriPriority",                       1, 0 },
    { "suriSid",                            4, 0 },
#ifdef NOTYET
    { "msg",                                0, 0 },
    { "class_msg",                          0, 0 },
#endif
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t alert_ext_spec[] = {
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
    /* alert info */
    { "suriRev",                            1, 0 },
    { "suriPriority",                       1, 0 },
    { "suriSid",                            4, 0 },
#ifdef NOTYET
    { "msg",                                0, 0 },
    { "class_msg",                          0, 0 },
#endif
    FB_IESPEC_NULL
};

static fbInfoElement_t info_elements[] = {
    FB_IE_INIT("alertMilliseconds", NPULSE_PEN, 40, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("suriPad", NPULSE_PEN, 46, 1, FB_IE_F_ENDIAN | FB_IE_F_ENDIAN),
    FB_IE_INIT("suriRev", NPULSE_PEN, 42, 1, FB_IE_F_ENDIAN | FB_IE_F_ENDIAN),
    FB_IE_INIT("suriPriority", NPULSE_PEN, 43, 1, FB_IE_F_ENDIAN | FB_IE_F_ENDIAN),
    FB_IE_INIT("suriSid", NPULSE_PEN, 41, 4, FB_IE_F_ENDIAN | FB_IE_F_ENDIAN),
#ifdef NOTYET
    FB_IE_INIT("msg", NPULSE_PEN, 44, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("class_msg", NPULSE_PEN, 45, FB_IE_VARLEN, FB_IE_F_NONE),
#endif
    FB_IE_NULL
};

/* Alert Record */
typedef struct IpfixAlert_st {
    uint64_t	AlertMilliseconds;
    uint8_t     sourceIPv6Address[16];
    uint8_t     destinationIPv6Address[16];
    uint32_t    sourceIPv4Address;
    uint32_t    destinationIPv4Address;
    uint16_t    sourceTransportPort;
    uint16_t    destinationTransportPort;
    uint8_t     protocolIdentifier;
    uint8_t	pad;
    uint8_t	rev;
    uint8_t	priority;
    uint32_t	sid;
#ifdef NOTYET
    fbVarfield_t msg;
    fbVarfield_t class_msg;
#endif
} IpFixAlert_t;

gboolean SetExportTemplate(
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

    /* Okay. We have a missing template. Clear the error and try to load it. */
    g_clear_error(err);
    session = fBufGetSession(fbuf);
    tmpl = fbTemplateAlloc(fb_model);

    SCLogInfo("tid: %x Appending tid: %x\n", tid, (tid & (~SURI_ALERT_BASE_TID)));
    if (!fbTemplateAppendSpecArray(tmpl, alert_ext_spec,
                                   (tid & (~SURI_ALERT_BASE_TID)), err))    {
        return FALSE;
    }

    if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, err)) {
        return FALSE;
    }

    /* Template should be loaded. Try setting the template again. */
    return fBufSetExportTemplate(fbuf, tid, err);
}

TmEcode AlertIPFIXIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    IpFixAlert_t rec;
    AlertIPFIXThread *aft = (AlertIPFIXThread *)data;
    int i;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    rec.AlertMilliseconds = (p->ts.tv_sec * 1000) + (p->ts.tv_usec / 1000);

    rec.sourceIPv4Address = ntohl(GET_IPV4_SRC_ADDR_U32(p));
    rec.destinationIPv4Address = ntohl(GET_IPV4_DST_ADDR_U32(p));
    rec.sourceTransportPort = p->sp;
    rec.destinationTransportPort = p->dp;
    rec.protocolIdentifier = IPV4_GET_IPPROTO(p);

    for (i = 0; i < p->alerts.cnt; i++) {

        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        rec.pad = 0x5a;
        rec.sid = pa->s->id;
        rec.rev = pa->s->rev;;
        rec.priority = pa->s->prio;
	SCLogInfo("srcIP: %x: destIP: %x Sp: %d Dp: %d Sid: %x Rev: %x Prio: %x", 
			rec.sourceIPv4Address, rec.destinationIPv4Address,
			rec.sourceTransportPort, rec.destinationTransportPort,
			rec.sid, rec.rev, rec.priority);
#ifdef NOTYET
	rec.msg.buf = (uint8_t *)pa->s->msg;
	rec.msg.len = strlen(pa->s->msg);
	rec.class_msg.buf = (uint8_t *)pa->s->class_msg;
	rec.class_msg.len = strlen(pa->s->class_msg);
	SCLogInfo("msg: \"%s\" class_msg: \"%s\"",
                  pa->s->msg, pa->s->class_msg);
#endif

        uint16_t tid = SURI_ALERT_BASE_TID | SURI_IP4;
        GError *err = NULL;

        SCMutexLock(&aft->ctx->mutex);

        /* Try to set export template */
        if (aft->ctx->fbuf) {
            if (!SetExportTemplate(aft->ctx->fb_model, aft->ctx->fbuf, tid, &err)) {
                SCMutexUnlock(&aft->ctx->mutex);
                SCLogInfo("fBufSetExportTemplate failed");
                return TM_ECODE_FAILED;
            }
        } else {
                SCMutexUnlock(&aft->ctx->mutex);
                SCLogInfo("no fbuf");
                return TM_ECODE_FAILED;
        }

        /* Now append the record to the buffer */
        if (!fBufAppend(aft->ctx->fbuf, (uint8_t *)&rec, sizeof(rec), &err)) {
            SCMutexUnlock(&aft->ctx->mutex);
            SCLogInfo("fBufAppend failed");
            return TM_ECODE_FAILED;
        }
        aft->ctx->alerts++;
        SCMutexUnlock(&aft->ctx->mutex);
    }

    return TM_ECODE_OK;
}

TmEcode AlertIPFIXIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    IpFixAlert_t rec;
    AlertIPFIXThread *aft = (AlertIPFIXThread *)data;
    int i;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    rec.AlertMilliseconds = (p->ts.tv_sec * 1000) + (p->ts.tv_usec / 1000);

    memcpy(rec.sourceIPv6Address, GET_IPV6_SRC_ADDR(p),
           sizeof(rec.sourceIPv6Address));
    memcpy(rec.destinationIPv6Address, GET_IPV6_DST_ADDR(p),
           sizeof(rec.destinationIPv6Address));
    rec.sourceTransportPort = p->sp;
    rec.destinationTransportPort = p->dp;
    rec.protocolIdentifier = IPV4_GET_IPPROTO(p);

    for (i = 0; i < p->alerts.cnt; i++) {

        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        rec.sid = pa->s->id;
        rec.rev = pa->s->rev;;
        rec.priority = pa->s->prio;
	SCLogInfo("Sid: %x Rev: %x Prio: %x", rec.sid, rec.rev, rec.priority);
#ifdef NOTYET
	rec.msg.buf = (uint8_t *)pa->s->msg;
	rec.msg.len = strlen(pa->s->msg);
	rec.class_msg.buf = (uint8_t *)pa->s->class_msg;
	rec.class_msg.len = strlen(pa->s->class_msg);
	SCLogInfo("msg: \"%s\" class_msg: \"%s\"",
                  pa->s->msg, pa->s->class_msg);
#endif

        uint16_t tid = SURI_ALERT_BASE_TID | SURI_IP6;
        GError *err = NULL;

        SCMutexLock(&aft->ctx->mutex);

        /* Try to set export template */
        if (aft->ctx->fbuf) {
            if (!SetExportTemplate(aft->ctx->fb_model, aft->ctx->fbuf, tid, &err)) {
                SCMutexUnlock(&aft->ctx->mutex);
                SCLogInfo("fBufSetExportTemplate failed");
                return TM_ECODE_FAILED;
            }
        } else {
                SCMutexUnlock(&aft->ctx->mutex);
                SCLogInfo("no fbuf");
                return TM_ECODE_FAILED;
        }

        /* Now append the record to the buffer */
        if (!fBufAppend(aft->ctx->fbuf, (uint8_t *)&rec, sizeof(rec), &err)) {
            SCMutexUnlock(&aft->ctx->mutex);
            SCLogInfo("fBufAppend failed");
            return TM_ECODE_FAILED;
        }
        aft->ctx->alerts++;
        SCMutexUnlock(&aft->ctx->mutex);
    }

    return TM_ECODE_OK;
}

TmEcode AlertIPFIX (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    if (PKT_IS_IPV4(p)) {
        return AlertIPFIXIPv4(tv, p, data, pq, postpq);
    } else if (PKT_IS_IPV6(p)) {
        return AlertIPFIXIPv6(tv, p, data, pq, postpq);
    } else {
        /* Can't send any IPFIX if we don't know enough about the packet */
    }

    return TM_ECODE_OK;
}

TmEcode AlertIPFIXThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertIPFIXThread *aft = SCMalloc(sizeof(AlertIPFIXThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(AlertIPFIXThread));
    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for AlertIPFIX.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aft->ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode AlertIPFIXThreadDeinit(ThreadVars *t, void *data)
{
    AlertIPFIXThread *aft = (AlertIPFIXThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(AlertIPFIXThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void AlertIPFIXExitPrintStats(ThreadVars *tv, void *data) {
    AlertIPFIXThread *aft = (AlertIPFIXThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("IPFIX output wrote %" PRIu64 " alerts", aft->ctx->alerts);
}

fbSession_t *InitExporterSession(fbInfoModel_t *fb_model, uint32_t domain,
                                 GError **err)
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
    SCLogInfo("fbTemplateAlloc: %p", int_tmpl);
    if (!fbTemplateAppendSpecArray(int_tmpl, alert_int_spec, SURI_ALERT_BASE_TID, err)) {
        SCLogInfo("fbTemplateAppendSpecArray failed");
        return NULL;
    }
    /* Add the full record template to the session */
    if (!fbSessionAddTemplate(session, TRUE, SURI_ALERT_BASE_TID, int_tmpl, err)) {
        SCLogInfo("fbSessionAddTemplate failed");
        return NULL;
    }

    /* Create the full record template */
    if ((ext_tmpl = fbTemplateAlloc(model)) == NULL) {
        SCLogInfo("fbTemplateAlloc failed");
        return NULL;
    }
    SCLogInfo("fbTemplateAlloc: %p", ext_tmpl);
    if (!fbTemplateAppendSpecArray(ext_tmpl, alert_ext_spec, SURI_ALERT_BASE_TID, err)) {
        SCLogInfo("fbTemplateAppendSpecArray failed");
        return NULL;
    }

    return session; 
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
OutputCtx *AlertIPFIXInitCtx(ConfNode *conf)
{
    fbConnSpec_t spec;
    char *log_dir;

    memset(&spec, 0, sizeof(spec));

    char *filename = (char *)ConfNodeLookupChildValue(conf, "filename");
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
        /* create the filename to use */
        if (ConfGet("default-log-dir", &log_dir) != 1)
            log_dir = DEFAULT_LOG_DIR;
	filename = SCMalloc(PATH_MAX);
        if (filename == NULL)
            return NULL;
        snprintf(filename, PATH_MAX, "%s/%s", log_dir,
                 ConfNodeLookupChildValue(conf, "filename"));
    }

    GError *err = NULL;

    AlertIPFIXCtx *ctx = SCCalloc(1, sizeof(AlertIPFIXCtx));
    if (ctx == NULL) {
        SCLogDebug("Could not allocate AlertIPFIXCtx");
        return NULL;
    }
    SCMutexInit(&ctx->mutex, NULL);

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;

    output_ctx->data = ctx;
    output_ctx->DeInit = AlertIPFIXDeInitCtx;

    ctx->fb_model = fbInfoModelAlloc();    
    SCLogInfo("fbInfoModelAlloc %p", ctx->fb_model);
    if (ctx->fb_model) {
        fbInfoModelAddElementArray(ctx->fb_model, info_elements);
    }

    if (filename == NULL) {
        /* Allocate an exporter with connection to the collector */
        ctx->exporter = fbExporterAllocNet(&spec);
    } else {
        /* Allocate an exporter for the file */
        ctx->exporter = fbExporterAllocFile(filename);
    }
    SCLogInfo("exporter: %p", ctx->exporter);

    /* Create a new session */
    uint32_t domain = 0xbeef; /* TBD??? */
    ctx->session = InitExporterSession(ctx->fb_model, domain, &err);
    SCLogInfo("session: %p", ctx->session);

    ctx->fbuf = fBufAllocForExport(ctx->session, ctx->exporter);
    SCLogInfo("fBufAllocForExport: %p", ctx->fbuf);

    if (ctx->session && ctx->fbuf) {

        /* write templates */
        fbSessionExportTemplates(ctx->session, &err);

        /* set internal template */
        if (!fBufSetInternalTemplate(ctx->fbuf, SURI_ALERT_BASE_TID, &err)) {
            SCLogInfo("fBufSetInternalTemplate failed");
        }
    }
    return output_ctx;
}

static void AlertIPFIXDeInitCtx(OutputCtx *output_ctx)
{
    AlertIPFIXCtx *ctx = (AlertIPFIXCtx *)output_ctx->data;
    SCLogInfo("Freeing fbInfoModel %p", ctx->fb_model);
    if (ctx->fb_model) {
        fbInfoModelFree(ctx->fb_model);
    }
    SCFree(output_ctx);
}

/*------------------------------Unittests-------------------------------------*/

#ifdef UNITTESTS

int AlertIPFIXTest01()
{
    int result = 0;
    uint8_t *buf = (uint8_t *) "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n";

    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return result;
    }

    de_ctx->flags |= DE_QUIET;

    SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx);
    SCClassConfDeleteDummyClassificationConfigFD();

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
            "(msg:\"FastLog test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");
    result = (de_ctx->sig_list != NULL);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1)
        result = (strcmp(p->alerts.alerts[0].s->class_msg, "Unknown are we") == 0);
    else
        result = 0;

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadRC();
    if (SCCudaHlPushCudaContextFromModule("SC_RULES_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    return result;
}

int AlertIPFIXTest02()
{
    int result = 0;
    uint8_t *buf = (uint8_t *) "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return result;
    }

    de_ctx->flags |= DE_QUIET;

    SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx);
    SCClassConfDeleteDummyClassificationConfigFD();

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
            "(msg:\"FastLog test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");
    result = (de_ctx->sig_list != NULL);
    if (result == 0)
        printf("sig parse failed: ");

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1) {
        result = (strcmp(p->alerts.alerts[0].s->class_msg, "Unknown Traffic") != 0);
        if (result == 0)
            printf("p->alerts.alerts[0].class_msg %s: ", p->alerts.alerts[0].s->class_msg);

        result = (strcmp(p->alerts.alerts[0].s->class_msg,
                    "Unknown are we") == 0);
        if (result == 0)
            printf("p->alerts.alerts[0].class_msg %s: ", p->alerts.alerts[0].s->class_msg);
    } else {
        result = 0;
    }

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadRC();
    if (SCCudaHlPushCudaContextFromModule("SC_RULES_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for AlertFastLog API.
 */
void AlertIPFIXRegisterTests(void)
{

#ifdef UNITTESTS

#ifdef __SC_CUDA_SUPPORT__
    UtRegisterTest("AlertFastLogCudaContextInit",
            SCCudaHlTestEnvCudaContextInit, 1);
#endif

    UtRegisterTest("AlertIPFIXTest01", AlertIPFIXTest01, 1);
    UtRegisterTest("AlertIPFIXTest02", AlertIPFIXTest02, 1);

#ifdef __SC_CUDA_SUPPORT__
    UtRegisterTest("AlertFastLogCudaContextDeInit",
            SCCudaHlTestEnvCudaContextDeInit, 1);
#endif

#endif /* UNITTESTS */

}
#endif
