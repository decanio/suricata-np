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
 * Logs in IPFIX format either to a file or to an IPFIX collector.
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
#include "app-layer-parser.h"
#include "util-classification-config.h"
#include "util-syslog.h"

#include "output.h"
#include "output-dns-ipfix.h"
#include "output-http-ipfix.h"
#include "output-smtp-ipfix.h"
#include "output-tls-ipfix.h"
#include "output-ipfix.h"

#include "util-error.h"
#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-logopenfile.h"
#include "util-ipfix.h"

#ifndef HAVE_IPFIX

/** Handle the case where no IPFIX support is compiled in.
 *
 */

TmEcode OutputIPFIX (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode OutputIPFIXThreadInit(ThreadVars *, void *, void **);
TmEcode OutputIPFIXThreadDeinit(ThreadVars *, void *);
int OutputIPFIXOpenFileCtx(LogFileCtx *, char *);
void OutputIPFIXRegisterTests(void);

void TmModuleOutputIPFIXRegister (void) {
    tmm_modules[TMM_OUTPUTIPFIX].name = "OutputIPFIX";
    tmm_modules[TMM_OUTPUTIPFIX].ThreadInit = OutputIPFIXThreadInit;
    tmm_modules[TMM_OUTPUTIPFIX].Func = OutputIPIX;
    tmm_modules[TMM_OUTPUTIPFIX].ThreadDeinit = OutputIPFIXThreadDeinit;
    tmm_modules[TMM_OUTPUTIPFIX].RegisterTests = OutputIPFIXRegisterTests;
}

OutputCtx *OutputIPFIXInitCtx(ConfNode *conf)
{
    SCLogDebug("Can't init IPFIX output - IPFIX support was disabled during build.");
    return NULL;
}

TmEcode OutputIPFIXThreadInit(ThreadVars *t, void *initdata, void **data)
{
    SCLogDebug("Can't init IPFIX output thread - IPFIX support was disabled during build.");
    return TM_ECODE_FAILED;
}

TmEcode OutputIPFIX (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return TM_ECODE_OK;
}

TmEcode OutputIPFIXThreadDeinit(ThreadVars *t, void *data)
{
    return TM_ECODE_FAILED;
}

void OutputIPFIXRegisterTests (void)
{
}

#else /* implied we do have IPFIX support */

#include <fixbuf/public.h>

#define DEFAULT_LOG_FILENAME "ipfix.json"
#define MODULE_NAME "OutputIPFIX"

extern uint8_t engine_mode;

TmEcode OutputIPFIX (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertIPFIX(ThreadVars *, Packet *, void *);
TmEcode OutputIPFIXThreadInit(ThreadVars *, void *, void **);
TmEcode OutputIPFIXThreadDeinit(ThreadVars *, void *);
void OutputIPFIXExitPrintStats(ThreadVars *, void *);
void OutputIPFIXRegisterTests(void);
static void OutputIPFIXDeInitCtx(OutputCtx *);

void TmModuleOutputIPFIXRegister (void) {
    tmm_modules[TMM_OUTPUTIPFIX].name = MODULE_NAME;
    tmm_modules[TMM_OUTPUTIPFIX].ThreadInit = OutputIPFIXThreadInit;
    tmm_modules[TMM_OUTPUTIPFIX].Func = OutputIPFIX;
    tmm_modules[TMM_OUTPUTIPFIX].ThreadExitPrintStats = OutputIPFIXExitPrintStats;
    tmm_modules[TMM_OUTPUTIPFIX].ThreadDeinit = OutputIPFIXThreadDeinit;
    tmm_modules[TMM_OUTPUTIPFIX].RegisterTests = OutputIPFIXRegisterTests;
    tmm_modules[TMM_OUTPUTIPFIX].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "ipfix-log", OutputIPFIXInitCtx);
}

/* Default Sensor ID value */
static int64_t sensor_id = -1; /* -1 = not defined */

enum IpfixOutput { ALERT_FILE,
                   ALERT_COLLECTOR,
                   ALERT_UNIX_DGRAM,
                   ALERT_UNIX_STREAM };
static enum IpfixOutput json_out = ALERT_FILE;

#define OUTPUT_ALERTS (1<<0)
#define OUTPUT_DNS    (1<<1)
#define OUTPUT_DROP   (1<<2)
#define OUTPUT_FILES  (1<<3)
#define OUTPUT_HTTP   (1<<4)
#define OUTPUT_SMTP   (1<<5)
#define OUTPUT_TLS    (1<<6)

static uint32_t output_flags = 0;

TmEcode OutputIPFIX (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
#ifdef NOTYET
    if (output_flags & OUTPUT_ALERTS) {

        if (PKT_IS_IPV4(p) || PKT_IS_IPV6(p)) {
            AlertJson(tv, p, data);
        } else if (p->events.cnt > 0) {
            AlertJsonDecoderEvent(tv, p, data);
        }
    }
#endif
    if (output_flags & OUTPUT_DNS) {
        OutputDnsIPFIXLog(tv, p, data);
    }

    if (output_flags & OUTPUT_DROP) {
#ifdef NOTYET
        OutputDropLog(tv, p, data);
#endif
    }

    if (output_flags & OUTPUT_FILES) {
#ifdef NOTYET
        OutputFileLog(tv, p, data);
#endif
    }

    if (output_flags & OUTPUT_HTTP) {
        OutputHttpIPFIXLog(tv, p, data);
    }

    if (output_flags & OUTPUT_SMTP) {
        OutputSmtpIPFIXLog(tv, p, data);
    }

    if (output_flags & OUTPUT_TLS) {
        OutputTlsIPFIXLog(tv, p, data);
    }

    return TM_ECODE_OK;
}

TmEcode OutputIPFIXThreadInit(ThreadVars *t, void *initdata, void **data)
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

    SCLogInfo("aft: %p", aft);
    /** Use the Ouptut Context (file pointer and mutex) */
    OutputIPFIXCtx *json_ctx = ((OutputCtx *)initdata)->data;
    SCLogInfo("json_ctx: %p", json_ctx);
    if (json_ctx != NULL) {
        aft->ipfix_ctx = json_ctx->ipfix_ctx;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode OutputIPFIXThreadDeinit(ThreadVars *t, void *data)
{
    AlertIPFIXThread *aft = (AlertIPFIXThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    SCFree(aft);
    return TM_ECODE_OK;
}

void OutputIPFIXExitPrintStats(ThreadVars *tv, void *data) {
    AlertIPFIXThread *aft = (AlertIPFIXThread *)data;
    if (aft == NULL) {
        return;
    }

#ifdef NOTYET
    SCLogInfo("IPFIX output wrote %" PRIu64 " alerts", aft->file_ctx->alerts);
#endif

}

static fbSession_t *
InitExporterSession(LogIPFIXCtx *ipfix_ctx, uint32_t domain, GError **err)
{
    fbInfoModel_t   *model = ipfix_ctx->fb_model;
    fbSession_t     *session = NULL;

    /* Allocate the session */
    session = fbSessionAlloc(model);

    /* set observation domain */
    fbSessionSetDomain(session, domain);

    /* Create the full record template */
    if ((ipfix_ctx->int_tmpl = fbTemplateAlloc(model)) == NULL) {
        SCLogInfo("fbTemplateAlloc failed");
        return NULL;
    }
    SCLogInfo("int_tmpl: %p", ipfix_ctx->int_tmpl);
    /* Create the full record template */
    if ((ipfix_ctx->ext_tmpl = fbTemplateAlloc(model)) == NULL) {
        SCLogInfo("fbTemplateAlloc failed");
        return NULL;
    }
    SCLogInfo("ext_tmpl: %p", ipfix_ctx->ext_tmpl);
    return session; 
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
OutputCtx *OutputIPFIXInitCtx(ConfNode *conf)
{
    OutputIPFIXCtx *ofix_ctx = SCCalloc(1, sizeof(OutputIPFIXCtx));;
    if (unlikely(ofix_ctx == NULL)) {
        SCLogDebug("AlertJsonInitCtx: Could not create new LogFileCtx");
        return NULL;
    }
    SCLogInfo("ofix_ctx: %p", ofix_ctx);

    LogIPFIXCtx *ipfix_ctx = LogIPFIXNewCtx();
    if (unlikely(ipfix_ctx == NULL)) {
        SCLogError(SC_ERR_IPFIX_LOG_GENERIC, "couldn't create new ipfix_ctx");
        SCFree(ofix_ctx);
        return NULL;
    }
    if (SCConfOpenIPFIX(conf, ipfix_ctx, DEFAULT_LOG_FILENAME) < 0) {
        //LogFileFreeCtx(ipfix_ctx);
        SCFree(ofix_ctx);
        return NULL;
    }

    SCLogInfo("ipfix_ctx: %p", ipfix_ctx);
    ofix_ctx->ipfix_ctx = ipfix_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(ofix_ctx);
        return NULL;
    }
    SCLogInfo("output_ctx: %p", output_ctx);

    output_ctx->data = ofix_ctx;
    output_ctx->DeInit = OutputIPFIXDeInitCtx;

    if (conf) {
        const char *output_s = ConfNodeLookupChildValue(conf, "type");
        if (output_s != NULL) {
            if (strcmp(output_s, "file") == 0) {
                json_out = ALERT_FILE;
            } else if (strcmp(output_s, "collector") == 0) {
                json_out = ALERT_COLLECTOR;
            } else if (strcmp(output_s, "unix_dgram") == 0) {
                json_out = ALERT_UNIX_DGRAM;
            } else if (strcmp(output_s, "unix_stream") == 0) {
                json_out = ALERT_UNIX_STREAM;
            } else {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                           "Invalid JSON output option: %s", output_s);
                exit(EXIT_FAILURE);
            }
        }

        const char *sensor_id_s = ConfNodeLookupChildValue(conf, "sensor-id");
        if (sensor_id_s != NULL) {
            if (ByteExtractStringUint64((uint64_t *)&sensor_id, 10, 0, sensor_id_s) == -1) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                           "Failed to initialize JSON output, "
                           "invalid sensor-is: %s", sensor_id_s);
                exit(EXIT_FAILURE);
            }
        }

        ConfNode *outputs, *output;
        outputs = ConfNodeLookupChild(conf, "types");
        if (outputs) {
            /*
             * TODO: make this more general with some sort of 
             * registration capability
             */
            TAILQ_FOREACH(output, &outputs->head, next) {
#ifdef NOTYET
                if (strcmp(output->val, "alert") == 0) {
                    SCLogDebug("Enabling alert output");
                    output_flags |= OUTPUT_ALERTS;
                    continue;
                }
#endif
                if (strcmp(output->val, "dns") == 0) {
                    SCLogDebug("Enabling DNS output");
                    AppLayerRegisterLogger(ALPROTO_DNS_UDP);
                    AppLayerRegisterLogger(ALPROTO_DNS_TCP);
                    output_flags |= OUTPUT_DNS;
                    continue;
                }
#ifdef NOTYET
                if (strcmp(output->val, "drop") == 0) {
                    SCLogDebug("Enabling drop output");
                    output_flags |= OUTPUT_DROP;
                    continue;
                }
                if (strcmp(output->val, "files") == 0) {
                    SCLogDebug("Enabling files output");
                    ConfNode *child = ConfNodeLookupChild(output, "files"); 
                    ofix_ctx->files_ctx = OutputFileLogInit(child);
                    output_flags |= OUTPUT_FILES;
                    continue;
                }
#endif
                if (strcmp(output->val, "http") == 0) {
                    SCLogDebug("Enabling HTTP output");
                    ConfNode *child = ConfNodeLookupChild(output, "http"); 
                    ofix_ctx->http_ctx = OutputHttpIPFIXLogInit(child);
                    AppLayerRegisterLogger(ALPROTO_HTTP);
                    output_flags |= OUTPUT_HTTP;
                    continue;
                }
                if (strcmp(output->val, "smtp") == 0) {
                    SCLogDebug("Enabling SMTP output");
                    AppLayerRegisterLogger(ALPROTO_SMTP);
                    output_flags |= OUTPUT_SMTP;
                    continue;
                }
                if (strcmp(output->val, "tls") == 0) {
                    SCLogDebug("Enabling TLS output");
                    AppLayerRegisterLogger(ALPROTO_TLS);
                    output_flags |= OUTPUT_TLS;
                    continue;
                }
            }
        }

        if (output_flags != 0) {
            GError *err = NULL;

            /* Create a new session */
            uint32_t domain = 0xbeef; /* TBD??? */
            ipfix_ctx->session = InitExporterSession(ipfix_ctx, domain, &err);
            SCLogInfo("session: %p", ipfix_ctx->session);

            ipfix_ctx->fbuf = fBufAllocForExport(ipfix_ctx->session, ipfix_ctx->exporter);
            SCLogInfo("fBufAllocForExport: %p", ipfix_ctx->fbuf);

#ifdef NOTYET
            if (output_flags & OUTPUT_ALERTS) {

                if (PKT_IS_IPV4(p) || PKT_IS_IPV6(p)) {
                    AlertJson(tv, p, data);
                } else if (p->events.cnt > 0) {
                    AlertJsonDecoderEvent(tv, p, data);
                }
            }
#endif
            if (output_flags & OUTPUT_DNS) {
                OutputDnsSetTemplates(ipfix_ctx);
            }

#ifdef NOTYET
            if (output_flags & OUTPUT_DROP) {
                OutputDropSetTemplates(ipfix_ctx);
            }
#endif

#ifdef NOTYET
            if (output_flags & OUTPUT_FILES) {
                //OutputFileSetTemplates(ipfix_ctx);
            }
#endif
            if (output_flags & OUTPUT_HTTP) {
                OutputHttpSetTemplates(ipfix_ctx);
            }

            if (output_flags & OUTPUT_SMTP) {
                OutputSmtpSetTemplates(ipfix_ctx);
            }

            if (output_flags & OUTPUT_TLS) {
                OutputTlsSetTemplates(ipfix_ctx);
            }
        }
    }

    return output_ctx;
}

static void OutputIPFIXDeInitCtx(OutputCtx *output_ctx)
{
    OutputIPFIXCtx *ofix_ctx = (OutputIPFIXCtx *)output_ctx->data;
#ifdef NOTYET
    LogFileCtx *logfile_ctx = json_ctx->file_ctx;
    LogFileFreeCtx(logfile_ctx);
#endif
    SCFree(ofix_ctx);
}

/*------------------------------Unittests-------------------------------------*/

#ifdef UNITTESTS

#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for AlertFastLog API.
 */
void OutputIPFIXRegisterTests(void)
{

#ifdef UNITTESTS

#endif /* UNITTESTS */

}
#endif
