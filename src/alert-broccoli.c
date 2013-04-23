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
 * Logs alerts using Broccoli to Bro.
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
#include "alert-broccoli.h"

#include "util-mpm-b2g-cuda.h"
#include "util-cuda-handlers.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-logopenfile.h"

#ifndef BROCCOLI
/** Handle the case where no Broccoli support is compiled in.
 *
 */

TmEcode AlertBroccoli (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertBroccoliThreadInit(ThreadVars *, void *, void **);
TmEcode AlertBroccoliThreadDeinit(ThreadVars *, void *);
int AlertBroccoliOpenFileCtx(LogFileCtx *, char *);
void AlertBroccoliRegisterTests(void);

void TmModuleAlertBroccoliRegister (void) {
    tmm_modules[TMM_ALERTBROCCOLI].name = "AlertBroccoli";
    tmm_modules[TMM_ALERTBROCCOLI].ThreadInit = AlertBroccoliThreadInit;
    tmm_modules[TMM_ALERTBROCCOLI].Func = AlertBroccoli;
    tmm_modules[TMM_ALERTBROCCOLI].ThreadDeinit = AlertBroccoliThreadDeinit;
    tmm_modules[TMM_ALERTBROCCOLI].RegisterTests = AlertBroccoliRegisterTests;
}

LogFileCtx *AlertBroccoliInitCtx(ConfNode *conf)
{
    SCLogDebug("Can't init Broccoli output - Broccoli support was disabled during build.");
    return NULL;
}

TmEcode AlertBroccoliThreadInit(ThreadVars *t, void *initdata, void **data)
{
    SCLogDebug("Can't init Broccoli output thread - Broccoli support was disabled during build.");
    return TM_ECODE_FAILED;
}

TmEcode AlertBroccoli (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return TM_ECODE_OK;
}

TmEcode AlertBroccoliThreadDeinit(ThreadVars *t, void *data)
{
    return TM_ECODE_FAILED;
}

void AlertBroccoliRegisterTests (void) {
}

#else /* implied we do have Broccoli support */

#include <broccoli.h>


#define MODULE_NAME "AlertBroccoli"

TmEcode AlertBroccoli (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertBroccoliIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertBroccoliIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertBroccoliThreadInit(ThreadVars *, void *, void **);
TmEcode AlertBroccoliThreadDeinit(ThreadVars *, void *);
void AlertBroccoliExitPrintStats(ThreadVars *, void *);
void AlertBroccoliRegisterTests(void);
static void AlertBroccoliDeInitCtx(OutputCtx *);

void TmModuleAlertBroccoliRegister (void) {
    tmm_modules[TMM_ALERTBROCCOLI].name = MODULE_NAME;
    tmm_modules[TMM_ALERTBROCCOLI].ThreadInit = AlertBroccoliThreadInit;
    tmm_modules[TMM_ALERTBROCCOLI].Func = AlertBroccoli;
    tmm_modules[TMM_ALERTBROCCOLI].ThreadExitPrintStats = AlertBroccoliExitPrintStats;
    tmm_modules[TMM_ALERTBROCCOLI].ThreadDeinit = AlertBroccoliThreadDeinit;
    tmm_modules[TMM_ALERTBROCCOLI].RegisterTests = AlertBroccoliRegisterTests;
    tmm_modules[TMM_ALERTBROCCOLI].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "broccoli", AlertBroccoliInitCtx);
}

typedef struct AlertBroccoliCtx_ {
    /* Connection to Bro */
    BroConn *bc;

    SCMutex mutex;

    /* Alerts on the module */
    uint64_t alerts;
} AlertBroccoliCtx;

typedef struct AlertBroccoliThread_ {
    /** AlertBroccoliCtx has a mutex to allow multithreading */
    AlertBroccoliCtx* ctx;
} AlertBroccoliThread;

static void
bro_util_fill_v4_addr(BroAddr *a, uint32 addr)
{
  if ( ! a )
    return;

  memcpy(a->addr, BRO_IPV4_MAPPED_PREFIX, sizeof(BRO_IPV4_MAPPED_PREFIX));
  a->addr[3] = addr;
}

TmEcode AlertBroccoliIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertBroccoliThread *aft = (AlertBroccoliThread *)data;
    BroEvent *ev;
    BroAddr src_ip;
    BroAddr dst_ip;
    BroString msg, class_msg;
    BroPort src_port, dst_port;
    uint64 action=0, prio, gid, sid, rev;
    int i;
    double time;
    extern uint8_t engine_mode;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    for (i = 0; i < p->alerts.cnt; i++) {

        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

    	if (! (ev = bro_event_new("alert"))) {
      	    return TM_ECODE_FAILED;
    	}

        time = bro_util_timeval_to_double(&p->ts);

        bro_event_add_val(ev, BRO_TYPE_TIME, NULL, &time);

#if 1
        if ((pa->action & ACTION_DROP) && IS_ENGINE_MODE_IPS(engine_mode)) {
            action = 1;
        } else if (pa->action & ACTION_DROP) {
            action = 2;
        }

        bro_util_fill_v4_addr(&src_ip, GET_IPV4_SRC_ADDR_U32(p));
        bro_util_fill_v4_addr(&dst_ip, GET_IPV4_DST_ADDR_U32(p));
        src_port.port_num = p->sp;
        src_port.port_proto = IPV4_GET_IPPROTO(p);
        dst_port.port_num = p->dp;
        dst_port.port_proto = IPV4_GET_IPPROTO(p);
	prio = pa->s->prio;
        gid = pa->s->gid;
        sid = pa->s->id;
        rev = pa->s->rev;
        bro_string_init(&msg);
        bro_string_set(&msg, pa->s->msg);
        bro_string_init(&class_msg);
        bro_string_set(&class_msg, pa->s->class_msg);

        bro_event_add_val(ev, BRO_TYPE_IPADDR, NULL, &src_ip);
        bro_event_add_val(ev, BRO_TYPE_IPADDR, NULL, &dst_ip);
        bro_event_add_val(ev, BRO_TYPE_PORT, NULL, &src_port);
        bro_event_add_val(ev, BRO_TYPE_PORT, NULL, &dst_port);
        bro_event_add_val(ev, BRO_TYPE_INT, NULL, &action);
        bro_event_add_val(ev, BRO_TYPE_INT, NULL, &prio);
        bro_event_add_val(ev, BRO_TYPE_INT, NULL, &gid);
        bro_event_add_val(ev, BRO_TYPE_INT, NULL, &sid);
        bro_event_add_val(ev, BRO_TYPE_INT, NULL, &rev);
        bro_event_add_val(ev, BRO_TYPE_STRING, NULL, &msg);
        bro_event_add_val(ev, BRO_TYPE_STRING, NULL, &class_msg);
#endif
        bro_event_send(aft->ctx->bc, ev);
        bro_event_free(ev);
        SCMutexLock(&aft->ctx->mutex);

        aft->ctx->alerts++;
        SCMutexUnlock(&aft->ctx->mutex);
    }

    return TM_ECODE_OK;
}

TmEcode AlertBroccoliIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertBroccoliThread *aft = (AlertBroccoliThread *)data;
    int i;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    for (i = 0; i < p->alerts.cnt; i++) {

        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        SCMutexLock(&aft->ctx->mutex);

        aft->ctx->alerts++;
        SCMutexUnlock(&aft->ctx->mutex);
    }

    return TM_ECODE_OK;
}

TmEcode AlertBroccoliDecoderEvent(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertBroccoliThread *aft = (AlertBroccoliThread *)data;
    int i;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }


        SCMutexLock(&aft->ctx->mutex);
        aft->ctx->alerts++;
        SCMutexUnlock(&aft->ctx->mutex);
    }

    return TM_ECODE_OK;
}

TmEcode AlertBroccoli (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    if (PKT_IS_IPV4(p)) {
        return AlertBroccoliIPv4(tv, p, data, pq, postpq);
    } else if (PKT_IS_IPV6(p)) {
        return AlertBroccoliIPv6(tv, p, data, pq, postpq);
    } else if (p->events.cnt > 0) {
        return AlertBroccoliDecoderEvent(tv, p, data, pq, postpq);
    }

    return TM_ECODE_OK;
}

TmEcode AlertBroccoliThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertBroccoliThread *aft = SCMalloc(sizeof(AlertBroccoliThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(AlertBroccoliThread));
    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for AlertBroccoli.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aft->ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode AlertBroccoliThreadDeinit(ThreadVars *t, void *data)
{
    AlertBroccoliThread *aft = (AlertBroccoliThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    SCFree(aft);
    return TM_ECODE_OK;
}

void AlertBroccoliExitPrintStats(ThreadVars *tv, void *data) {
    AlertBroccoliThread *aft = (AlertBroccoliThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("Broccoli output wrote %" PRIu64 " alerts", aft->ctx->alerts);
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
OutputCtx *AlertBroccoliInitCtx(ConfNode *conf)
{
    char hostname[512];
    int flags = BRO_CFLAG_RECONNECT;

    const char *host = ConfNodeLookupChildValue(conf, "host");
    if (host == NULL) {
	SCLogError(SC_ERR_MISSING_CONFIG_PARAM, "No Broccoli host in config,");
        exit(EXIT_FAILURE);
    }
    const char *port = ConfNodeLookupChildValue(conf, "port");
    if (port == NULL) {
	SCLogError(SC_ERR_MISSING_CONFIG_PARAM, "No Broccoli port in config,");
        exit(EXIT_FAILURE);
    }

    snprintf(hostname, sizeof(hostname), "%s:%s", host, port);

    AlertBroccoliCtx *ctx = SCCalloc(1, sizeof(AlertBroccoliCtx));
    if (unlikely(ctx == NULL)) {
        SCLogDebug("Could not allocate new AlertBroccoliCtx");
        return NULL;
    }

    SCMutexInit(&ctx->mutex, NULL);

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCLogDebug("Could not allocate new OutputCtx");
        return NULL;
    }

    /* Init Bro */
    bro_init(NULL);

    /* Connect to Bro */
    if (! (ctx->bc = bro_conn_new_str(hostname, flags))) {
        SCLogError(SC_ERR_BROCCOLI, "Could not get Bro connection handle");
        return NULL;
    }

    output_ctx->data = ctx;
    output_ctx->DeInit = AlertBroccoliDeInitCtx;

    bro_conn_set_class(ctx->bc, "suricata");

    if (! bro_conn_connect(ctx->bc)) {
        SCLogError(SC_ERR_BROCCOLI, "Could not connect to Bro at %s:%s",
                   host, port);
    }

    return output_ctx;
}

static void AlertBroccoliDeInitCtx(OutputCtx *output_ctx)
{
    AlertBroccoliCtx *ctx = (AlertBroccoliCtx *)output_ctx->data;

    /* Disconnect from Bro and release state. */
    bro_conn_delete(ctx->bc);

    SCFree(ctx);

    SCFree(output_ctx);
}

/*------------------------------Unittests-------------------------------------*/

#ifdef UNITTESTS

int AlertBroccoliTest01()
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

int AlertBroccoliTest02()
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
void AlertBroccoliRegisterTests(void)
{

#ifdef UNITTESTS

#ifdef __SC_CUDA_SUPPORT__
    UtRegisterTest("AlertFastLogCudaContextInit",
            SCCudaHlTestEnvCudaContextInit, 1);
#endif

    UtRegisterTest("AlertBroccoliLogTest01", AlertBroccoliLogTest01, 1);
    UtRegisterTest("AlertBroccoliLogTest02", AlertBroccoliLogTest02, 1);

#ifdef __SC_CUDA_SUPPORT__
    UtRegisterTest("AlertFastLogCudaContextDeInit",
            SCCudaHlTestEnvCudaContextDeInit, 1);
#endif

#endif /* UNITTESTS */

}
#endif
