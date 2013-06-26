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

#include "util-byte.h"
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

OutputCtx *AlertBroccoliInitCtx(ConfNode *conf)
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

/* Default Sensor ID value */
static uint64_t sensor_id = 0;

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
FillIPv4Addr(BroAddr *a, uint32 addr)
{
    if ( ! a )
        return;

    memcpy(a->addr, BRO_IPV4_MAPPED_PREFIX, sizeof(BRO_IPV4_MAPPED_PREFIX));
    a->addr[3] = addr;
}

static void
FillIPv6Addr(BroAddr *a, uint32_t *addr)
{
    if ( ! a )
        return;

    memcpy(a->addr, addr, sizeof(BroAddr));
}

TmEcode AlertBroccoliIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertBroccoliThread *aft = (AlertBroccoliThread *)data;
    BroEvent *ev;
    BroAddr src_ip;
    BroAddr dst_ip;
    BroPort src_p, dst_p;
    uint64 class, prio, gid, sid, rev;
    int i;
    double ts;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    for (i = 0; i < p->alerts.cnt; i++) {

        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        if (! (ev = bro_event_new("suricata_alert"))) {
      	    return TM_ECODE_FAILED;
        }

        /* First value */
        BroRecord *packet_id = bro_record_new();
        src_p.port_num = dst_p.port_num = 0;
        /* Broccoli's protocol handling is sort of broken at the moment
         * it segfaults when doing bro_record_add_val if not tcp, udp, or icmp
         * waiting on ticket: http://tracker.icir.org/bro/ticket/278
         */
        src_p.port_proto = dst_p.port_proto = IPPROTO_TCP;
        if(IPV4_GET_IPPROTO(p) != 255) {
            src_p.port_proto = dst_p.port_proto = IPV4_GET_IPPROTO(p);
            if(PKT_IS_ICMPV4(p)) {
                src_p.port_num = htons(ICMPV4_GET_TYPE(p));
                dst_p.port_num = htons(ICMPV4_GET_CODE(p));
            } else {
                src_p.port_num = p->sp;
                dst_p.port_num = p->dp;
            }
        }
        
        FillIPv4Addr(&src_ip, GET_IPV4_SRC_ADDR_U32(p));
        FillIPv4Addr(&dst_ip, GET_IPV4_DST_ADDR_U32(p));
        bro_record_add_val(packet_id, "src_ip", BRO_TYPE_IPADDR, NULL, &src_ip);
        bro_record_add_val(packet_id, "src_p",  BRO_TYPE_PORT,   NULL, &src_p);
        bro_record_add_val(packet_id, "dst_ip", BRO_TYPE_IPADDR, NULL, &dst_ip);
        bro_record_add_val(packet_id, "dst_p",  BRO_TYPE_PORT,   NULL, &dst_p);
        /*bro_event_add_val(ev, BRO_TYPE_RECORD, "PacketID", packet_id);*/
        bro_event_add_val(ev, BRO_TYPE_RECORD, NULL, packet_id);
        bro_record_free(packet_id);
       
        /* Second value */
        BroRecord *sad = bro_record_new();
        gid = pa->s->gid;
        sid = pa->s->id;
        class = pa->s->class;
        rev = pa->s->rev;
        bro_record_add_val(sad, "sensor_id",          BRO_TYPE_COUNT, NULL, &sensor_id);
        ts = bro_util_timeval_to_double(&p->ts);
        bro_record_add_val(sad, "ts",                 BRO_TYPE_TIME,  NULL, &ts);
        bro_record_add_val(sad, "signature_id",       BRO_TYPE_COUNT, NULL, &sid);
        bro_record_add_val(sad, "generator_id",       BRO_TYPE_COUNT, NULL, &gid);
        bro_record_add_val(sad, "signature_revision", BRO_TYPE_COUNT, NULL, &rev);
        bro_record_add_val(sad, "classification_id",  BRO_TYPE_COUNT, NULL, &class);
        BroString class_bs;
        bro_string_init(&class_bs);
        bro_string_set(&class_bs, pa->s->class_msg);
        bro_record_add_val(sad, "classification",     BRO_TYPE_STRING, NULL, &class_bs);
        bro_string_cleanup(&class_bs);
        bro_record_add_val(sad, "priority_id",        BRO_TYPE_COUNT, NULL, &prio);
        uint64 event_id_hl = 0;
        bro_record_add_val(sad, "event_id",           BRO_TYPE_COUNT, NULL, &event_id_hl);

        /*
        //BroSet *ref_set = bro_set_new();
        //BroString ref_name_bs;
        //rn = sn->refs;
        //while(rn)
        //{
        //    bro_string_init(&ref_name_bs);
        //    bro_string_set(&ref_name_bs, rn->system->name);
        //    bro_set_insert(ref_set, BRO_TYPE_STRING, &ref_name_bs);
        //    bro_string_cleanup(&ref_name_bs);
        //    rn = rn->next;
        //}
        //bro_record_add_val(sad, "references", BRO_TYPE_SET, NULL, ref_set);
        //bro_set_free(ref_set);
        */
        
        /*bro_event_add_val(ev, BRO_TYPE_RECORD, "alert_data", sad);*/
        bro_event_add_val(ev, BRO_TYPE_RECORD, NULL, sad);
        bro_record_free(sad);

        /* Third value */
        BroString msg_bs;
        bro_string_init(&msg_bs);
        bro_string_set(&msg_bs, pa->s->msg);
        bro_event_add_val(ev, BRO_TYPE_STRING, NULL, &msg_bs);
        bro_string_cleanup(&msg_bs);
        
        /* Fourth value */
        BroString contents_bs;
        bro_string_init(&contents_bs);
        bro_string_set_data(&contents_bs, (uchar *) p->payload, p->payload_len);
        bro_event_add_val(ev, BRO_TYPE_STRING, NULL, &contents_bs);
        bro_string_cleanup(&contents_bs);
        
        SCMutexLock(&aft->ctx->mutex);

        /* send and free the event */
        bro_event_send(aft->ctx->bc, ev);

        aft->ctx->alerts++;

        SCMutexUnlock(&aft->ctx->mutex);

        bro_event_free(ev);
    }

    return TM_ECODE_OK;
}

TmEcode AlertBroccoliIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertBroccoliThread *aft = (AlertBroccoliThread *)data;
    BroEvent *ev;
    BroAddr src_ip;
    BroAddr dst_ip;
    BroPort src_p, dst_p;
    uint64 class, prio, gid, sid, rev;
    int i;
    double ts;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    for (i = 0; i < p->alerts.cnt; i++) {

        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        if (! (ev = bro_event_new("suricata_alert"))) {
      	    return TM_ECODE_FAILED;
        }

        /* First value */
        BroRecord *packet_id = bro_record_new();
        src_p.port_num = dst_p.port_num = 0;
        /* Broccoli's protocol handling is sort of broken at the moment
         * it segfaults when doing bro_record_add_val if not tcp, udp, or icmp
         * waiting on ticket: http://tracker.icir.org/bro/ticket/278
         */
        src_p.port_proto = dst_p.port_proto = IPPROTO_TCP;
        if(IPV6_GET_L4PROTO(p) != 255) {
            src_p.port_proto = dst_p.port_proto = IPV6_GET_L4PROTO(p);
            if(PKT_IS_ICMPV6(p)) {
                src_p.port_num = htons(ICMPV6_GET_TYPE(p));
                dst_p.port_num = htons(ICMPV6_GET_CODE(p));
            } else {
                src_p.port_num = p->sp;
                dst_p.port_num = p->dp;
            }
        }
        
        FillIPv6Addr(&src_ip, GET_IPV6_SRC_ADDR(p));
        FillIPv6Addr(&dst_ip, GET_IPV6_DST_ADDR(p));
        bro_record_add_val(packet_id, "src_ip", BRO_TYPE_IPADDR, NULL, &src_ip);
        bro_record_add_val(packet_id, "src_p",  BRO_TYPE_PORT,   NULL, &src_p);
        bro_record_add_val(packet_id, "dst_ip", BRO_TYPE_IPADDR, NULL, &dst_ip);
        bro_record_add_val(packet_id, "dst_p",  BRO_TYPE_PORT,   NULL, &dst_p);
        /*bro_event_add_val(ev, BRO_TYPE_RECORD, "PacketID", packet_id);*/
        bro_event_add_val(ev, BRO_TYPE_RECORD, NULL, packet_id);
        bro_record_free(packet_id);
       
        /* Second value */
        BroRecord *sad = bro_record_new();
        prio = pa->s->prio;
        gid = pa->s->gid;
        sid = pa->s->id;
        class = pa->s->class;
        rev = pa->s->rev;
        bro_record_add_val(sad, "sensor_id",          BRO_TYPE_COUNT, NULL, &sensor_id);
        ts = bro_util_timeval_to_double(&p->ts);
        bro_record_add_val(sad, "ts",                 BRO_TYPE_TIME,  NULL, &ts);
        bro_record_add_val(sad, "signature_id",       BRO_TYPE_COUNT, NULL, &sid);
        bro_record_add_val(sad, "generator_id",       BRO_TYPE_COUNT, NULL, &gid);
        bro_record_add_val(sad, "signature_revision", BRO_TYPE_COUNT, NULL, &rev);
        bro_record_add_val(sad, "classification_id",  BRO_TYPE_COUNT, NULL, &class);
        BroString class_bs;
        bro_string_init(&class_bs);
        bro_string_set(&class_bs, pa->s->class_msg);
        bro_record_add_val(sad, "classification",     BRO_TYPE_STRING, NULL, &class_bs);
        bro_string_cleanup(&class_bs);
        bro_record_add_val(sad, "priority_id",        BRO_TYPE_COUNT, NULL, &prio);
        uint64 event_id_hl = 0;
        bro_record_add_val(sad, "event_id",           BRO_TYPE_COUNT, NULL, &event_id_hl);

        /*
        //BroSet *ref_set = bro_set_new();
        //BroString ref_name_bs;
        //rn = sn->refs;
        //while(rn)
        //{
        //    bro_string_init(&ref_name_bs);
        //    bro_string_set(&ref_name_bs, rn->system->name);
        //    bro_set_insert(ref_set, BRO_TYPE_STRING, &ref_name_bs);
        //    bro_string_cleanup(&ref_name_bs);
        //    rn = rn->next;
        //}
        //bro_record_add_val(sad, "references", BRO_TYPE_SET, NULL, ref_set);
        //bro_set_free(ref_set);
        */
        
        //bro_event_add_val(ev, BRO_TYPE_RECORD, "alert_data", sad);
        bro_event_add_val(ev, BRO_TYPE_RECORD, NULL, sad);
        bro_record_free(sad);

        /* Third value */
        BroString msg_bs;
        bro_string_init(&msg_bs);
        bro_string_set(&msg_bs, pa->s->msg);
        bro_event_add_val(ev, BRO_TYPE_STRING, NULL, &msg_bs);
        bro_string_cleanup(&msg_bs);
        
        /* Fourth value */
        BroString contents_bs;
        bro_string_init(&contents_bs);
        bro_string_set_data(&contents_bs, (uchar *) p->payload, p->payload_len);
        bro_event_add_val(ev, BRO_TYPE_STRING, NULL, &contents_bs);
        bro_string_cleanup(&contents_bs);
        
        SCMutexLock(&aft->ctx->mutex);

        /* send and free the event */
        bro_event_send(aft->ctx->bc, ev);

        aft->ctx->alerts++;

        SCMutexUnlock(&aft->ctx->mutex);

        bro_event_free(ev);
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
        /* The barnyard2 broccoli format sends flow tuple fields.
         * We don't have any tuple information here.
         * As a result just count alerts.  Possibly implement
         * an alternate message format for this case.
         */
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
    const char *host = "localhost"; /* default host */
    const char *port = "47758";     /* default port */
    int flags = BRO_CFLAG_RECONNECT | BRO_CFLAG_ALWAYS_QUEUE;

    if (conf) {
        host = ConfNodeLookupChildValue(conf, "host");
        if (host == NULL) {
            SCLogError(SC_ERR_MISSING_CONFIG_PARAM,
                       "No Broccoli host in config,");
            exit(EXIT_FAILURE);
        }
        const char *port = ConfNodeLookupChildValue(conf, "port");
        if (port == NULL) {
            SCLogError(SC_ERR_MISSING_CONFIG_PARAM,
                       "No Broccoli port in config,");
            exit(EXIT_FAILURE);
        }

        const char *sensor_id_s = ConfNodeLookupChildValue(conf, "sensor-id");
        if (sensor_id_s != NULL) {
            if (ByteExtractStringUint64(&sensor_id, 10, 0, sensor_id_s) == -1) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                           "Failed to initialize broccoli output, "
                           "invalid sensor-is: %s", sensor_id_s);
                exit(EXIT_FAILURE);
            }
            sensor_id = htonl(sensor_id);
        }
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

    SCLogInfo("Connecting to Bro (%s)...", hostname);

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
