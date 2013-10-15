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
 * Implements dns logging portion of the engine.
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
#include "log-dnslog-ipfix.h"
#include "app-layer-dns-udp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-logipfix.h"
#include "util-time.h"

#define DEFAULT_LOG_FILENAME "dns-ipfix.log"

#define MODULE_NAME "LogDnsLogIPFIX"

#define OUTPUT_BUFFER_SIZE 65535

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */
#define QUERY 0

TmEcode LogDnsLogIPFIX (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogDnsLogIPFIXIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogDnsLogIPFIXIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogDnsLogIPFIXThreadInit(ThreadVars *, void *, void **);
TmEcode LogDnsLogIPFIXThreadDeinit(ThreadVars *, void *);
void LogDnsLogIPFIXExitPrintStats(ThreadVars *, void *);
static void LogDnsLogIPFIXDeInitCtx(OutputCtx *);

void TmModuleLogDnsLogIPFIXRegister (void) {
    tmm_modules[TMM_LOGDNSLOGIPFIX].name = MODULE_NAME;
    tmm_modules[TMM_LOGDNSLOGIPFIX].ThreadInit = LogDnsLogIPFIXThreadInit;
    tmm_modules[TMM_LOGDNSLOGIPFIX].Func = LogDnsLogIPFIX;
    tmm_modules[TMM_LOGDNSLOGIPFIX].ThreadExitPrintStats = LogDnsLogIPFIXExitPrintStats;
    tmm_modules[TMM_LOGDNSLOGIPFIX].ThreadDeinit = LogDnsLogIPFIXThreadDeinit;
    tmm_modules[TMM_LOGDNSLOGIPFIX].RegisterTests = NULL;
    tmm_modules[TMM_LOGDNSLOGIPFIX].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "dns-log-ipfix", LogDnsLogIPFIXInitCtx);

    /* enable the logger for the app layer */
    AppLayerRegisterLogger(ALPROTO_DNS_UDP);
    AppLayerRegisterLogger(ALPROTO_DNS_TCP);
    SCLogDebug("registered %s", MODULE_NAME);
}

typedef struct LogDnsFileCtx_ {
#if 1
    LogIPFIXCtx *ipfix_ctx;
#else
    LogFileCtx *file_ctx;
#endif
    uint32_t flags; /** Store mode */
} LogDnsFileCtx;

typedef struct LogDnsLogThread_ {
    LogDnsFileCtx *dnslog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t dns_cnt;

    MemBuffer *buffer;
} LogDnsLogThread;

/* TBD: move these to util-logipfix.h */
#define SURI_DNS_BASE_TID    0x3200

/* Special dimensions */
#define SURI_IP4		0x0001
#define SURI_IP6		0x0002

//#define NOMETADATA

/* IPFIX definition of the DNS log record */
static fbInfoElementSpec_t dns_log_int_spec[] = {
    /* Alert Millisecond (epoch) (native time) */
    { "alertMilliseconds",                  0, 0 },
#ifndef NOMETADATA
    { "dnsQName",                           0, 0 },
    { "dnsQRType",                          0, 0 },
    { "dnsID",                              0, 0 },
    { "dnsQueryResponse",                   0, 0 },
    { "paddingOctets",                      3, 0 },
    { "dnsIPv4Address",                     0, 0 },
#endif
    /* 5-tuple */
    { "sourceIPv6Address",                  0, 0 },
    { "destinationIPv6Address",             0, 0 },
    { "sourceIPv4Address",                  0, 0 },
    { "destinationIPv4Address",             0, 0 },
    { "sourceTransportPort",                0, 0 },
    { "destinationTransportPort",           0, 0 },
    { "protocolIdentifier",                 0, 0 },
    { "paddingOctets",                      7, 1 },
    /* dns info */
#ifndef NOMETADATA
    //{ "dnsID",                              0, 0 },
#endif
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t dns_log_ext_spec[] = {
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
    /* dns info */
#ifndef NOMETADATA
    { "dnsQName",                           0, 0 },
    { "dnsQRType",                          0, 0 },
    { "dnsQueryResponse",                   0, 0 }, /* Q(0) or R(1) - uint8 */
    { "dnsID",                              0, 0 },
    { "dnsIPv4Address",                     0, 0 },
#endif
    FB_IESPEC_NULL
};

/* DNS Metadata Record */
#pragma pack(push, 1)
typedef struct DnsLog_st {
    uint64_t	 AlertMilliseconds;
#ifndef NOMETADATA
    fbVarfield_t dnsQName;
    uint16_t     dnsQRType;
    uint16_t     dnsID;
    uint8_t      dnsQueryResponse;
    uint8_t      pad[3];
    uint32_t     dnsIPv4Address;
#endif
    uint8_t      sourceIPv6Address[16];
    uint8_t      destinationIPv6Address[16];

    uint32_t     sourceIPv4Address;
    uint32_t     destinationIPv4Address;

    uint16_t     sourceTransportPort;
    uint16_t     destinationTransportPort;
    uint8_t      protocolIdentifier;
#ifndef NOMETADATA
    //uint16_t     dnsQRType;
    //uint16_t     dnsID;
    //uint8_t      dnsQueryResponse;
#endif
} DnsLog_t;
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

    //SCLogInfo("tid: %x Appending tid: %x\n", tid, (tid & (~SURI_DNS_BASE_TID)));
    if (!fbTemplateAppendSpecArray(tmpl, dns_log_ext_spec,
                                   (tid & (~SURI_DNS_BASE_TID)), err))    {
        return FALSE;
    }

    if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, err)) {
        SCLogInfo("failed to add external template");
        return FALSE;
    }

    /* Template should be loaded. Try setting the template again. */
    return fBufSetExportTemplate(fbuf, tid, err);
}

static void CreateTypeString(uint16_t type, char *str, size_t str_size) {
    if (type == DNS_RECORD_TYPE_A) {
        snprintf(str, str_size, "A");
    } else if (type == DNS_RECORD_TYPE_NS) {
        snprintf(str, str_size, "NS");
    } else if (type == DNS_RECORD_TYPE_AAAA) {
        snprintf(str, str_size, "AAAA");
    } else if (type == DNS_RECORD_TYPE_TXT) {
        snprintf(str, str_size, "TXT");
    } else if (type == DNS_RECORD_TYPE_CNAME) {
        snprintf(str, str_size, "CNAME");
    } else if (type == DNS_RECORD_TYPE_SOA) {
        snprintf(str, str_size, "SOA");
    } else if (type == DNS_RECORD_TYPE_MX) {
        snprintf(str, str_size, "MX");
    } else if (type == DNS_RECORD_TYPE_PTR) {
        snprintf(str, str_size, "PTR");
    } else if (type == DNS_RECORD_TYPE_ANY) {
        snprintf(str, str_size, "ANY");
    } else if (type == DNS_RECORD_TYPE_TKEY) {
        snprintf(str, str_size, "TKEY");
    } else if (type == DNS_RECORD_TYPE_TSIG) {
        snprintf(str, str_size, "TSIG");
    } else {
        snprintf(str, str_size, "%04x/%u", type, type);
    }
}

static void ClearMetadata(DnsLog_t *rec)
{
    //SCLogInfo("ClearMetadata %d %d", offsetof(DnsLog_t, sourceIPv6Address),offsetof(DnsLog_t, dnsQName));
    memset(&rec->dnsQName, 0,
           offsetof(DnsLog_t, sourceIPv6Address)-offsetof(DnsLog_t, dnsQName));
}

//static void LogQuery(LogDnsLogThread *aft, DnsLog_t *rec, char *srcip, char *dstip, Port sp, Port dp, uint16_t tid, DNSTransaction *tx, DNSQueryEntry *entry) {
static void LogQuery(LogDnsLogThread *aft, DnsLog_t *rec, uint16_t tid, DNSTransaction *tx, DNSQueryEntry *entry) {
    LogDnsFileCtx *dlog = aft->dnslog_ctx;
    GError *err= NULL;

    SCLogDebug("got a DNS request and now logging !!");
    //SCLogInfo("got a DNS request and now logging !!");

#if 1
    ClearMetadata(rec);

    /* tx */
    rec->dnsID = tx->tx_id;
    rec->dnsQueryResponse = 0;
    rec->dnsQName.buf = (uint8_t *)((uint8_t *)entry + sizeof(DNSQueryEntry));
    rec->dnsQName.len = entry->len;
    SCMutexLock(&dlog->ipfix_ctx->mutex);

    /* Try to set export template */
    if (dlog->ipfix_ctx->fbuf) {
        if (!SetExportTemplate(dlog->ipfix_ctx->fb_model, dlog->ipfix_ctx->fbuf, tid, &err)) {
            SCMutexUnlock(&dlog->ipfix_ctx->mutex);
            SCLogInfo("fBufSetExportTemplate failed");
            return;
        }
    } else {
            SCMutexUnlock(&dlog->ipfix_ctx->mutex);
            SCLogInfo("no fbuf");
            return;
    }

    //SCLogInfo("Appending IPFIX record to log");
    /* Now append the record to the buffer */
    if (!fBufAppend(dlog->ipfix_ctx->fbuf, (uint8_t *)rec, sizeof(*rec), &err)) {
        //SCMutexUnlock(&aft->httplog_ctx->mutex);
        SCLogInfo("fBufAppend failed");
    }

    SCMutexUnlock(&dlog->ipfix_ctx->mutex);

    aft->dns_cnt++;
#else
    /* reset */
    MemBufferReset(aft->buffer);

    /* time & tx */
    MemBufferWriteString(aft->buffer,
            "%s [**] Query TX %04x [**] ", timebuf, tx->tx_id);

    /* query */
    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
            (uint8_t *)((uint8_t *)entry + sizeof(DNSQueryEntry)),
            entry->len);

    char record[16] = "";
    CreateTypeString(entry->type, record, sizeof(record));
    MemBufferWriteString(aft->buffer,
            " [**] %s [**] %s:%" PRIu16 " -> %s:%" PRIu16 "\n",
            record, srcip, sp, dstip, dp);

    aft->dns_cnt++;

    SCMutexLock(&hlog->ipfix_ctx->mutex);
    (void)MemBufferPrintToFPAsString(aft->buffer, hlog->file_ctx->fp);
    fflush(hlog->file_ctx->fp);
    SCMutexUnlock(&hlog->ipfix_ctx->mutex);
#endif
}

//static void LogAnswer(LogDnsLogThread *aft, DnsLog_t *rec, char *srcip, char *dstip, Port sp, Port dp, uint16_t tid, DNSTransaction *tx, DNSAnswerEntry *entry) {
static void LogAnswer(LogDnsLogThread *aft, DnsLog_t *rec, uint16_t tid, DNSTransaction *tx, DNSAnswerEntry *entry) {
    LogDnsFileCtx *dlog = aft->dnslog_ctx;
    GError *err= NULL;

    SCLogDebug("got a DNS response and now logging !!");
    //SCLogInfo("got a DNS response and now logging !!");

#if 1
    ClearMetadata(rec);

    /* tx */
    rec->dnsID = tx->tx_id;
    rec->dnsQueryResponse = 1;

    if (entry == NULL) {
        rec->dnsQName.buf = (uint8_t *)"No Such Name";
        rec->dnsQName.len = strlen("No Such Name");
    } else {
        /* query */
        if (entry->fqdn_len > 0) {
            rec->dnsQName.buf = (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry));
            rec->dnsQName.len = entry->fqdn_len;
        } else {
            rec->dnsQName.buf = (uint8_t *)"No Data";
            rec->dnsQName.len = strlen("No Data");
        }
        rec->dnsQRType = entry->type;
        if (entry->type == DNS_RECORD_TYPE_A) {
            rec->dnsIPv4Address = htonl(((uint8_t *)entry + sizeof(DNSAnswerEntry) + entry->fqdn_len));
        }
    }

    SCMutexLock(&dlog->ipfix_ctx->mutex);

    /* Try to set export template */
    if (dlog->ipfix_ctx->fbuf) {
        if (!SetExportTemplate(dlog->ipfix_ctx->fb_model, dlog->ipfix_ctx->fbuf, tid, &err)) {
            SCMutexUnlock(&dlog->ipfix_ctx->mutex);
            SCLogInfo("fBufSetExportTemplate failed");
            return;
        }
    } else {
            SCMutexUnlock(&dlog->ipfix_ctx->mutex);
            SCLogInfo("no fbuf");
            return;
    }

    //SCLogInfo("Appending IPFIX record to log");
    /* Now append the record to the buffer */
    if (!fBufAppend(dlog->ipfix_ctx->fbuf, (uint8_t *)rec, sizeof(*rec), &err)) {
        //SCMutexUnlock(&aft->httplog_ctx->mutex);
        SCLogInfo("fBufAppend failed");
    }

    SCMutexUnlock(&dlog->ipfix_ctx->mutex);

    aft->dns_cnt++;
#else
    /* reset */
    MemBufferReset(aft->buffer);

    /* time & tx*/
    MemBufferWriteString(aft->buffer,
            "%s [**] Response TX %04x [**] ", timebuf, tx->tx_id);

    if (entry == NULL) {
        MemBufferWriteString(aft->buffer,
                "No Such Name");
    } else {
        /* query */
        if (entry->fqdn_len > 0) {
            PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                    (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)),
                    entry->fqdn_len);
        } else {
            MemBufferWriteString(aft->buffer, "<no data>");
        }

        char record[16] = "";
        CreateTypeString(entry->type, record, sizeof(record));
        MemBufferWriteString(aft->buffer,
                " [**] %s [**] TTL %u [**] ", record, entry->ttl);

        uint8_t *ptr = (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry) + entry->fqdn_len);
        if (entry->type == DNS_RECORD_TYPE_A) {
            char a[16] = "";
            PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
            MemBufferWriteString(aft->buffer, "%s", a);
        } else if (entry->type == DNS_RECORD_TYPE_AAAA) {
            char a[46];
            PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
            MemBufferWriteString(aft->buffer, "%s", a);
        } else if (entry->data_len == 0) {
            MemBufferWriteString(aft->buffer, "<no data>");
        } else {
            PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                    aft->buffer->size, ptr, entry->data_len);
        }
    }

    /* ip/tcp header info */
    MemBufferWriteString(aft->buffer,
            " [**] %s:%" PRIu16 " -> %s:%" PRIu16 "\n",
            srcip, sp, dstip, dp);

    aft->dns_cnt++;

    SCMutexLock(&hlog->ipfix_ctx->mutex);
    (void)MemBufferPrintToFPAsString(aft->buffer, hlog->file_ctx->fp);
    fflush(hlog->file_ctx->fp);
    SCMutexUnlock(&hlog->ipfix_ctx->mutex);
#endif
}

static TmEcode LogDnsLogIPFIXIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
                            PacketQueue *postpq, int ipproto)
{
    SCEnter();

    DnsLog_t rec;
    GError *err= NULL;
    uint16_t tid;
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    LogDnsFileCtx *dlog = aft->dnslog_ctx;
    TmEcode rc = TM_ECODE_OK;
#if 1
    char timebuf[64];
#endif


    //SCLogInfo("got a DNS callback is client %d!!", PKT_IS_TOCLIENT(p));

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCLogDebug("no flow");
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have DNS state or not */
    FLOWLOCK_WRLOCK(p->flow); /* WRITE lock before we updated flow logged id */
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_DNS_UDP && proto != ALPROTO_DNS_TCP) {
        SCLogDebug("proto not ALPROTO_DNS_UDP: %u", proto);
        goto end;
    }

    DNSState *dns_state = (DNSState *)AppLayerGetProtoStateFromPacket(p);
    if (dns_state == NULL) {
        SCLogDebug("no dns state, so no request logging");
        goto end;
    }

    //SCLogInfo("rec: %p", &rec);
    uint64_t total_txs = AppLayerGetTxCnt(proto, dns_state);
    uint64_t tx_id = AppLayerTransactionGetLogId(p->flow);
    //int tx_progress_done_value_ts = AppLayerGetAlstateProgressCompletionStatus(proto, 0);
    //int tx_progress_done_value_tc = AppLayerGetAlstateProgressCompletionStatus(proto, 1);

    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);
#if 1
    rec.AlertMilliseconds = (p->ts.tv_sec * 1000) + (p->ts.tv_usec / 1000);
#else
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));
#endif

#if 0
    char srcip[46], dstip[46];
    Port sp, dp;
#endif
    if ((PKT_IS_TOCLIENT(p))) {
        switch (ipproto) {
            case AF_INET:
#if 1
                rec.sourceIPv4Address = ntohl(GET_IPV4_SRC_ADDR_U32(p));
                rec.destinationIPv4Address = ntohl(GET_IPV4_DST_ADDR_U32(p));
                tid = SURI_DNS_BASE_TID | SURI_IP4;
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
                tid = SURI_DNS_BASE_TID | SURI_IP6;
#else
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
#endif
                break;
            default:
                goto end;
        }
#if 1
        rec.sourceTransportPort = p->sp;
        rec.destinationTransportPort = p->dp;
#else
        sp = p->sp;
        dp = p->dp;
#endif
    } else {
        switch (ipproto) {
            case AF_INET:
#if 1
                rec.sourceIPv4Address = ntohl(GET_IPV4_DST_ADDR_U32(p));
                rec.destinationIPv4Address = ntohl(GET_IPV4_SRC_ADDR_U32(p));
                tid = SURI_DNS_BASE_TID | SURI_IP4;
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
                tid = SURI_DNS_BASE_TID | SURI_IP6;
#else
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), dstip, sizeof(dstip));
#endif
                break;
            default:
                goto end;
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

#if QUERY
    if (PKT_IS_TOSERVER(p)) {
        DNSTransaction *tx = NULL;
        TAILQ_FOREACH(tx, &dns_state->tx_list, next) {
            DNSQueryEntry *entry = NULL;
            TAILQ_FOREACH(entry, &tx->query_list, next) {
                LogQuery(aft, &rec, tid, tx, entry);
            }
        }
    } else
#endif
    if ((PKT_IS_TOCLIENT(p))) {
        DNSTransaction *tx = NULL;
        //SCLogInfo("looping %d to %d", tx_id, total_txs);
        for (; tx_id < total_txs; tx_id++)
        {
            tx = AppLayerGetTx(proto, dns_state, tx_id);
            if (tx == NULL)
                continue;
            //SCLogInfo("good AppLayerGetTx");
            DNSQueryEntry *query = NULL;
            TAILQ_FOREACH(query, &tx->query_list, next) {
                LogQuery(aft, &rec, tid, tx, query);
            }

            if (tx->no_such_name) {
                LogAnswer(aft, &rec, tid, tx, NULL);
            }

            DNSAnswerEntry *entry = NULL;
            TAILQ_FOREACH(entry, &tx->answer_list, next) {
                LogAnswer(aft, &rec, tid, tx, entry);
            }

            entry = NULL;
            TAILQ_FOREACH(entry, &tx->authority_list, next) {
                LogAnswer(aft, &rec, tid, tx, entry);
            }

            SCLogDebug("calling AppLayerTransactionUpdateLoggedId");
            /* TODO: finish below */
            AppLayerTransactionUpdateLogId(ALPROTO_DNS_UDP, p->flow);
        }
    }
end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogDnsLogIPFIXIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogDnsLogIPFIXIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

TmEcode LogDnsLogIPFIXIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogDnsLogIPFIXIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

TmEcode LogDnsLogIPFIX (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();

    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);
    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_UDP(p)) && !(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (PKT_IS_IPV4(p)) {
        int r  = LogDnsLogIPFIXIPv4(tv, p, data, pq, postpq);
        SCReturnInt(r);
    } else if (PKT_IS_IPV6(p)) {
        int r  = LogDnsLogIPFIXIPv6(tv, p, data, pq, postpq);
        SCReturnInt(r);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogDnsLogIPFIXThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogDnsLogThread *aft = SCMalloc(sizeof(LogDnsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogDnsLogThread));

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
    aft->dnslog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode LogDnsLogIPFIXThreadDeinit(ThreadVars *t, void *data)
{
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogDnsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void LogDnsLogIPFIXExitPrintStats(ThreadVars *tv, void *data) {
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("DNS IPFIX logger logged %" PRIu32 " requests", aft->dns_cnt);
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
    if (!fbTemplateAppendSpecArray(int_tmpl, dns_log_int_spec, SURI_DNS_BASE_TID, err)) {
        SCLogInfo("fbTemplateAppendSpecArray failed");
        return NULL;
    }
    /* Add the full record template to the session */
    if (!fbSessionAddTemplate(session, TRUE, SURI_DNS_BASE_TID, int_tmpl, err)) {
        SCLogInfo("fbSessionAddTemplate failed");
        return NULL;
    }

    /* Create the full record template */
    if ((ext_tmpl = fbTemplateAlloc(model)) == NULL) {
        SCLogInfo("fbTemplateAlloc failed");
        return NULL;
    }
    SCLogInfo("ext_tmpl: %p", ext_tmpl);
    if (!fbTemplateAppendSpecArray(ext_tmpl, dns_log_ext_spec, SURI_DNS_BASE_TID, err)) {
        SCLogInfo("fbTemplateAppendSpecArray failed");
        return NULL;
    }

    return session; 
}

/** \brief Create a new dns log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogDnsLogIPFIXInitCtx(ConfNode *conf)
{
    GError *err = NULL;

    SCLogInfo("DNS IPFIX logger initializing");

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
        SCLogError(SC_ERR_DNS_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

#endif
    LogDnsFileCtx *dnslog_ctx = SCMalloc(sizeof(LogDnsFileCtx));
    if (unlikely(dnslog_ctx == NULL)) {
#if 0
        LogFileFreeCtx(file_ctx);
#endif
        return NULL;
    }
    memset(dnslog_ctx, 0x00, sizeof(LogDnsFileCtx));

#if 1
    dnslog_ctx->ipfix_ctx = ipfix_ctx;
#else
    dnslog_ctx->file_ctx = file_ctx;
#endif

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
#if 0
        LogFileFreeCtx(file_ctx);
#endif
        SCFree(dnslog_ctx);
        return NULL;
    }

    /* Create a new session */
    uint32_t domain = 0xbeef; /* TBD??? */
    dnslog_ctx->ipfix_ctx->session = InitExporterSession(dnslog_ctx->ipfix_ctx->fb_model, domain,
                                               &err);
    SCLogInfo("session: %p", dnslog_ctx->ipfix_ctx->session);

    dnslog_ctx->ipfix_ctx->fbuf = fBufAllocForExport(dnslog_ctx->ipfix_ctx->session, dnslog_ctx->ipfix_ctx->exporter);
    SCLogInfo("fBufAllocForExport: %p", dnslog_ctx->ipfix_ctx->fbuf);

    if (dnslog_ctx->ipfix_ctx->session && dnslog_ctx->ipfix_ctx->fbuf) {

        /* write templates */
        fbSessionExportTemplates(dnslog_ctx->ipfix_ctx->session, &err);

        /* set internal template */
        if (!fBufSetInternalTemplate(dnslog_ctx->ipfix_ctx->fbuf, SURI_DNS_BASE_TID, &err)) {
            SCLogInfo("fBufSetInternalTemplate failed");
        }
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = LogDnsLogIPFIXDeInitCtx;

    SCLogDebug("DNS IPFIX log output initialized");

    return output_ctx;
}

static void LogDnsLogIPFIXDeInitCtx(OutputCtx *output_ctx)
{
    LogDnsFileCtx *dnslog_ctx = (LogDnsFileCtx *)output_ctx->data;
#if 0
    LogFileFreeCtx(dnslog_ctx->file_ctx);
#endif
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
}
