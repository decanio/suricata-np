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
 * Implements IPFIX DNS logging portion of the engine.
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
#include "util-mem.h"

#include "output.h"
#include "output-dnslog.h"
#include "app-layer-dns-udp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "util-ipfix.h"

#include "output-ipfix.h"

#ifdef HAVE_IPFIX

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */
#define QUERY 0

/* IPFIX definition of the DNS log record */
static fbInfoElementSpec_t dns_log_int_spec[] = {
    /* Alert Millisecond (epoch) (native time) */
    { "alertMilliseconds",                  0, 0 },
    { "dnsQName",                           0, 0 },
    { "dnsQRType",                          0, 0 },
    { "dnsID",                              0, 0 },
    { "dnsQueryResponse",                   0, 0 },
    { "paddingOctets",                      3, 0 },
    { "dnsIPv4Address",                     0, 0 },
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
    { "dnsQName",                           0, 0 },
    { "dnsQRType",                          0, 0 },
    { "dnsQueryResponse",                   0, 0 }, /* Q(0) or R(1) - uint8 */
    { "dnsID",                              0, 0 },
    { "dnsIPv4Address",                     0, 0 },
    FB_IESPEC_NULL
};

/* DNS Metadata Record */
#pragma pack(push, 1)
typedef struct DnsLog_st {
    uint64_t	 AlertMilliseconds;
    fbVarfield_t dnsQName;
    uint16_t     dnsQRType;
    uint16_t     dnsID;
    uint8_t      dnsQueryResponse;
    uint8_t      pad[3];
    uint32_t     dnsIPv4Address;
    uint8_t      sourceIPv6Address[16];
    uint8_t      destinationIPv6Address[16];

    uint32_t     sourceIPv4Address;
    uint32_t     destinationIPv4Address;

    uint16_t     sourceTransportPort;
    uint16_t     destinationTransportPort;
    uint8_t      protocolIdentifier;
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

static void ClearMetadata(DnsLog_t *rec)
{
    memset(&rec->dnsQName, 0,
           offsetof(DnsLog_t, sourceIPv6Address)-offsetof(DnsLog_t, dnsQName));
}

static void LogQuery(AlertIPFIXThread *aft, DnsLog_t *rec, uint16_t tid,
                     DNSTransaction *tx, DNSQueryEntry *entry)
{
    LogIPFIXCtx *ipfix_ctx = aft->ipfix_ctx;
    GError *err= NULL;

    SCLogDebug("got a DNS request and now logging !!");

    ClearMetadata(rec);

    /* tx */
    rec->dnsID = tx->tx_id;
    rec->dnsQueryResponse = 0;
    rec->dnsQName.buf = (uint8_t *)((uint8_t *)entry + sizeof(DNSQueryEntry));
    rec->dnsQName.len = entry->len;
    SCMutexLock(&ipfix_ctx->mutex);

    /* Try to set export template */
    if (ipfix_ctx->fbuf) {
        if (!SetExportTemplate(ipfix_ctx->fb_model, ipfix_ctx->fbuf, tid, &err)) {
            SCMutexUnlock(&ipfix_ctx->mutex);
            SCLogInfo("fBufSetExportTemplate failed");
            return;
        }
    } else {
            SCMutexUnlock(&ipfix_ctx->mutex);
            SCLogInfo("no fbuf");
            return;
    }

    /* Now append the record to the buffer */
    if (!fBufAppend(ipfix_ctx->fbuf, (uint8_t *)rec, sizeof(*rec), &err)) {
        SCLogInfo("fBufAppend failed");
    }

    SCMutexUnlock(&ipfix_ctx->mutex);

    aft->dns_cnt++;
}

static void LogAnswer(AlertIPFIXThread *aft, DnsLog_t *rec, uint16_t tid,
                      DNSTransaction *tx, DNSAnswerEntry *entry)
{
    LogIPFIXCtx *ipfix_ctx = aft->ipfix_ctx;
    GError *err= NULL;

    SCLogDebug("got a DNS response and now logging !!");

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

    SCMutexLock(&ipfix_ctx->mutex);

    /* Try to set export template */
    if (ipfix_ctx->fbuf) {
        if (!SetExportTemplate(ipfix_ctx->fb_model, ipfix_ctx->fbuf, tid, &err)) {
            SCMutexUnlock(&ipfix_ctx->mutex);
            SCLogInfo("fBufSetExportTemplate failed");
            return;
        }
    } else {
            SCMutexUnlock(&ipfix_ctx->mutex);
            SCLogInfo("no fbuf");
            return;
    }

    /* Now append the record to the buffer */
    if (!fBufAppend(ipfix_ctx->fbuf, (uint8_t *)rec, sizeof(*rec), &err)) {
        SCLogInfo("fBufAppend failed");
    }

    SCMutexUnlock(&ipfix_ctx->mutex);

    aft->dns_cnt++;
}

static TmEcode LogDnsLogIPFIXIPWrapper(ThreadVars *tv, Packet *p, void *data,
                                       int ipproto)
{
    SCEnter();

    DnsLog_t rec;
    GError *err= NULL;
    uint16_t tid;
    AlertIPFIXThread *aft = (AlertIPFIXThread *)data;
    LogIPFIXCtx *ipfix_ctx = aft->ipfix_ctx;
    TmEcode rc = TM_ECODE_OK;

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

    uint64_t total_txs = AppLayerGetTxCnt(proto, dns_state);
    uint64_t tx_id = AppLayerTransactionGetLogId(p->flow);
    //int tx_progress_done_value_ts = AppLayerGetAlstateProgressCompletionStatus(proto, 0);
    //int tx_progress_done_value_tc = AppLayerGetAlstateProgressCompletionStatus(proto, 1);

    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);
    rec.AlertMilliseconds = (p->ts.tv_sec * 1000) + (p->ts.tv_usec / 1000);

    if ((PKT_IS_TOCLIENT(p))) {
        switch (ipproto) {
            case AF_INET:
                rec.sourceIPv4Address = ntohl(GET_IPV4_SRC_ADDR_U32(p));
                rec.destinationIPv4Address = ntohl(GET_IPV4_DST_ADDR_U32(p));
                tid = SURI_DNS_BASE_TID | SURI_IP4;
                break;
            case AF_INET6:
                memcpy(rec.sourceIPv6Address, GET_IPV6_SRC_ADDR(p),
                       sizeof(rec.sourceIPv6Address));
                memcpy(rec.destinationIPv6Address, GET_IPV6_DST_ADDR(p),
                       sizeof(rec.destinationIPv6Address));
                tid = SURI_DNS_BASE_TID | SURI_IP6;
                break;
            default:
                goto end;
        }
        rec.sourceTransportPort = p->sp;
        rec.destinationTransportPort = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                rec.sourceIPv4Address = ntohl(GET_IPV4_DST_ADDR_U32(p));
                rec.destinationIPv4Address = ntohl(GET_IPV4_SRC_ADDR_U32(p));
                tid = SURI_DNS_BASE_TID | SURI_IP4;
                break;
            case AF_INET6:
                memcpy(rec.sourceIPv6Address, GET_IPV6_DST_ADDR(p),
                       sizeof(rec.sourceIPv6Address));
                memcpy(rec.destinationIPv6Address, GET_IPV6_SRC_ADDR(p),
                       sizeof(rec.destinationIPv6Address));
                tid = SURI_DNS_BASE_TID | SURI_IP6;
                break;
            default:
                goto end;
        }
        rec.sourceTransportPort = p->dp;
        rec.destinationTransportPort = p->sp;
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
        for (; tx_id < total_txs; tx_id++)
        {
            tx = AppLayerGetTx(proto, dns_state, tx_id);
            if (tx == NULL)
                continue;
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

TmEcode LogDnsLogIPFIXIPv4(ThreadVars *tv, Packet *p, void *data)
{
    return LogDnsLogIPFIXIPWrapper(tv, p, data, AF_INET);
}

TmEcode LogDnsLogIPFIXIPv6(ThreadVars *tv, Packet *p, void *data)
{
    return LogDnsLogIPFIXIPWrapper(tv, p, data, AF_INET6);
}

TmEcode OutputDnsIPFIXLog(ThreadVars *tv, Packet *p, void *data)
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
        int r  = LogDnsLogIPFIXIPv4(tv, p, data);
        SCReturnInt(r);
    } else if (PKT_IS_IPV6(p)) {
        int r  = LogDnsLogIPFIXIPv6(tv, p, data);
        SCReturnInt(r);
    }

    SCReturnInt(TM_ECODE_OK);
}

void OutputDnsSetTemplates(LogIPFIXCtx *ipfix_ctx)
{
    GError *err = NULL;

    if (ipfix_ctx->session && ipfix_ctx->fbuf) {

        if (!fbTemplateAppendSpecArray(ipfix_ctx->int_tmpl, dns_log_int_spec, SURI_DNS_BASE_TID, &err)) {
            SCLogInfo("fbTemplateAppendSpecArray failed");
            return;
        }
        /* Add the full record template to the session */
        if (!fbSessionAddTemplate(ipfix_ctx->session, TRUE, SURI_DNS_BASE_TID, ipfix_ctx->int_tmpl, &err)) {
            SCLogInfo("fbSessionAddTemplate failed");
            return;
        }
        if (!fbTemplateAppendSpecArray(ipfix_ctx->ext_tmpl, dns_log_ext_spec, SURI_DNS_BASE_TID, &err)) {
            SCLogInfo("fbTemplateAppendSpecArray failed");
            return;
        }

        /* write templates */
        fbSessionExportTemplates(ipfix_ctx->session, &err);

        /* set internal template */
        if (!fBufSetInternalTemplate(ipfix_ctx->fbuf, SURI_DNS_BASE_TID, &err)) {
            SCLogInfo("fBufSetInternalTemplate failed");
        }
    }
}

#endif
