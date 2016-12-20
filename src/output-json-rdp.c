/* Copyright (C) 2007-2015 Open Information Security Foundation
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
 * \author Tom DeCanio <decanio.tom@gmail.com>
 *
 * Implements JSON RDP logging portion of the engine.
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
#include "app-layer-parser.h"
#include "output.h"
#include "app-layer-rdp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#include "output-json.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

typedef struct LogRDPFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogRDPFileCtx;

typedef struct LogRDPLogThread_ {
    LogRDPFileCtx *rdplog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */

    MemBuffer *buffer;
} LogRDPLogThread;

/*
 * from https://technet.microsoft.com/en-us/library/cc722435(v=ws.10).aspx
 */
static const struct {
    uint16_t identifier;
    char *culture;
} LayoutMap[] = {
    { 1033, "en-US" },
    { 1043, "nl-NL" },
    { 1036, "fr-FR" },
    { 1031, "de-DE" },
    { 1040, "it-IT" },
    { 1041, "ja-JP" },
    { 3082, "es-ES" },
    { 1025, "ar-SA" },
    { 2052, "zh-CN" },
    { 3076, "zh-HK" },
    { 1028, "zh-TW" },
    { 1029, "cs-CZ" },
    { 1030, "da-DK" },
    { 1035, "fi-FI" },
    { 1032, "el-GR" },
    { 1037, "he-IL" },
    { 1038, "hu-HU" },
    { 1042, "ko-KR" },
    { 1044, "nb-NO" },
    { 1045, "pl-PL" },
    { 1046, "pt-BR" },
    { 2070, "pt-PT" },
    { 1049, "ru-RU" },
    { 1053, "sv-SE" },
    { 1055, "tr-TR" },
    { 1026, "bg-BG" },
    { 1050, "hr-HR" },
    { 1061, "et-EE" },
    { 1062, "lv-LV" },
    { 1063, "lt-LT" },
    { 1048, "ro-RO" },
    { 2074, "sr-Latn-CS" },
    { 1051, "sk-SK" },
    { 1060, "sl-SI" },
    { 1054, "th-TH" },
    { 1058, "uk-UA" },
    { 1078, "af-ZA" },
    { 1052, "sq-AL" },
    { 1118, "am-ET" },
    { 1067, "hy-AM" },
    { 1101, "as-IN" },
    { 1068, "az-Latn-AZ" },
    { 1069, "eu-ES" },
    { 1059, "be-BY" },
    { 2117, "bn-DB" },
    { 1093, "bn-IN" },
    { 8218, "bs-Cyrl-BA" },
    { 5146, "bs-Latn-BA" },
    { 1027, "ca-ES" },
    { 1124, "fil-PH" },
    { 1110, "gl-ES" },
    { 1079, "ka-GE" },
    { 1095, "gu-IN" },
    { 1128, "ha-Latn-NG" },
    { 1081, "hi-IN" },
    { 1039, "is-IS" },
    { 1136, "ig-NG" },
    { 1057, "id-ID" },
    { 2108, "ga-IE" },
    { 1076, "xh-ZA" },
    { 1077, "zu-ZA" },
    { 1099, "kn-IN" },
    { 1087, "kk-KZ" },
    { 1107, "km-KH" },
    { 1159, "rw-RW" },
    { 1089, "sw-KE" },
    { 1111, "kok-IN" },
    { 1088, "ky-KG" },
    { 1108, "lo-LA" },
    { 1134, "lb-LU" },
    { 1071, "mk-MK" },
    { 2110, "ms-BN" },
    { 1086, "ms-MY" },
    { 1100, "ml-IN" },
    { 1082, "mt-MT" },
    { 1153, "mi-NZ" },
    { 1102, "mr-IN" },
    { 1121, "ne-NP" },
    { 2068, "nn-NO" },
    { 1096, "or-IN" },
    { 1123, "ps-AF" },
    { 1065, "fa-IR" },
    { 1094, "pa-IN" },
    { 3179, "quz-PE" },
    { 3098, "sr-Cyrl-CS" },
    { 1132, "nso-ZA" },
    { 1074, "tn-ZA" },
    { 1115, "si-LK" },
    { 1097, "ta-IN" },
    { 1092, "tt-RU" },
    { 1098, "te-IN" },
    { 1056, "ur-PK" },
    { 1091, "uz-Latn-UZ" },
    { 1066, "vi-VN" },
    { 1106, "cy-GB" },
    { 1160, "wo-SN" },
    { 1130, "yo-NG" },
    { 0, NULL }
};

static char *RDPKeyboardLayout(uint16_t layout)
{
    int i;
    for (i = 0; LayoutMap[i].culture != NULL; i++) {
        if (LayoutMap[i].identifier == layout)
            return LayoutMap[i].culture;
    }
    return NULL;
}

/*
 * from https://technet.microsoft.com/en-us/library/cc722435(v=ws.10).aspx
 */
static const struct {
    uint32_t value;
    char *keyboard;
} KeyboardMap[] = {
    { 0x00000001, "IBM PC/XT or compatible (83-key)" },
    { 0x00000002, "Olivetti \"ICO\" (102-key)" },
    { 0x00000003, "IBM PC/AT (84-key)" },
    { 0x00000004, "IBM enhanced (101-key or 102-key)" },
    { 0x00000005, "Nokia 1050" },
    { 0x00000006, "Nokia 9140" },
    { 0x00000007, "japanese" },
    { 0, NULL }
};

static char *RDPKeyboardType(uint32_t keyboard)
{
    int i;
    for (i = 0; KeyboardMap[i].keyboard != NULL; i++) {
        if (KeyboardMap[i].value == keyboard)
            return KeyboardMap[i].keyboard;
    }
    return NULL;
}

static const struct {
    uint32_t value;
    char *string;
} ClientBuildMap[] = {
    { 2195, "RDP 5.0" },
    { 2600, "RDP 5.1" },
    { 2600, "RDP 5.2" },
    { 6000, "RDP 6.0" },
    { 6001, "RDP 6.1" },
    { 6002, "RDP 6.2" },
    { 7600, "RDP 7.0" },
    { 7601, "RDP 7.1" },
    { 0, NULL }
};

static char *RDPClientBuild(uint32_t build)
{
    int i;
    for (i = 0; ClientBuildMap[i].string != NULL; i++) {
        if (ClientBuildMap[i].value == build)
            return ClientBuildMap[i].string;
    }
    return NULL;
}

static const struct {
    uint32_t version;
    char *string;
} VersionMap[] = {
    { 0x00080001, "RDP 4.0 client" },
    { 0x00080004, "RDP 5.0, 5.1, 5.2, 6.0, 6.1, 7.0, 7.1, 8.0, or 8.1 client" },
    { 0x00080005, "RDP 10.0 client" },
    { 0x00080006, "RDP 10.1 client" },
    { 0x00080007, "RDP 10.2 client" },
    { 0, NULL }
};

static char *RDPVersion(uint32_t major, uint32_t minor)
{
    uint32_t version = minor << 16|major;
    int i;
    for (i = 0; VersionMap[i].string != NULL; i++) {
        if (VersionMap[i].version == version)
            return VersionMap[i].string;
    }
    return NULL;
}

static int JsonRDPLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();
    LogRDPLogThread *td = (LogRDPLogThread *)thread_data;
    MemBuffer *buffer = td->buffer;
    RDPTransaction *tx = txptr;
    json_t *js;
    
    MemBufferReset(buffer);

    js = CreateJSONHeader((Packet *)p, 0, "rdp");
    if (unlikely(js == NULL))
        SCReturnInt(TM_ECODE_OK);
        
    json_t *rjs = json_object();
    
    switch (tx->type) {
        case RDP_TYPE_X224_CONNECT: {
            json_object_set_new(rjs, "type", json_string("x224_connect"));
            json_t *cjs = json_object();
            json_object_set_new(cjs, "token", json_string((char *)tx->x224_connect.token));
            json_object_set_new(rjs, "x224_connect", cjs);
            }
            break;
        case RDP_TYPE_T125_MSCCONNECT: {
            char clientName[17];
            char clientDigProdId[33];
            size_t i;
            for (i = 0; i < sizeof(tx->t125_connect.clientName); i+=2) {
                clientName[i/2] = tx->t125_connect.clientName[i];
            }
            clientName[16] = '\0';
            for (i = 0; i < sizeof(tx->t125_connect.clientDigProductId); i+=2) {
                clientDigProdId[i/2] = tx->t125_connect.clientDigProductId[i];
            }
            clientDigProdId[32] = '\0';
            json_object_set_new(rjs, "type", json_string("t125_connect"));
            json_t *cjs = json_object();
            //json_object_set_new(cjs, "token", json_string(tx->connection.token));
            json_object_set_new(cjs, "version_major", json_integer(tx->t125_connect.versionMajor));
            json_object_set_new(cjs, "version_minor", json_integer(tx->t125_connect.versionMinor));
            char *version = RDPVersion(tx->t125_connect.versionMajor,
                                       tx->t125_connect.versionMinor);
            if (version != NULL) {
                json_object_set_new(cjs, "version", json_string(version));
            } else {
                json_object_set_new(cjs, "version", json_string("unknown"));
            }
            json_object_set_new(cjs, "desktop_width", json_integer(tx->t125_connect.desktopWidth));
            json_object_set_new(cjs, "desktop_height", json_integer(tx->t125_connect.desktopHeight));
            json_object_set_new(cjs, "color_depth", json_integer(tx->t125_connect.colorDepth));
            char *layout = RDPKeyboardLayout(tx->t125_connect.keyboardLayout);
            if (layout != NULL) {
                json_object_set_new(cjs, "keyboard_layout", json_string(layout));
            } else {
                char str[32];
                snprintf(str, sizeof(str)-1, "unknown %u", tx->t125_connect.keyboardLayout);
                json_object_set_new(cjs, "keyboard_layout", json_string(str));
            }
            char *build = RDPClientBuild(tx->t125_connect.clientBuild);
            if (build != NULL) {
                json_object_set_new(cjs, "client_build", json_string(build));
            } else {
                char str[32];
                snprintf(str, sizeof(str)-1, "unknown %u", tx->t125_connect.clientBuild);
                json_object_set_new(cjs, "client_build", json_string(str));
            }
		    json_object_set_new(cjs, "client_name", json_string(clientName));
            char *keyboard = RDPKeyboardType(tx->t125_connect.keyboardType);
            if (keyboard != NULL) {
                json_object_set_new(cjs, "keyboard_type", json_string(keyboard));
            } else {
                char str[32];
                snprintf(str, sizeof(str)-1, "unknown %u", tx->t125_connect.keyboardType);
                json_object_set_new(cjs, "keyboard_type", json_string(str));
            }
            json_object_set_new(cjs, "keyboard_subtype", json_integer(tx->t125_connect.keyboardSubtype));
            json_object_set_new(cjs, "client_dig_prod_id", json_string(clientDigProdId));
            json_object_set_new(rjs, "t125_connect", cjs);
            }
            break;
        case RDP_TYPE_T125_USER: {
            json_object_set_new(rjs, "type", json_string("t125_user"));
            json_t *cjs = json_object();
            //json_object_set_new(cjs, "token", json_string(tx->connection.token));
            json_object_set_new(rjs, "t125_user", cjs);
            }
            break;
        case RDP_TYPE_T125_JOIN: {
            json_object_set_new(rjs, "type", json_string("t125_join"));
            json_t *cjs = json_object();
            json_object_set_new(cjs, "channel_id", json_integer(tx->t125_join.channelId));
            json_object_set_new(rjs, "t125_join", cjs);
            }
            break;
        default:
            break;
    }
    
    json_object_set_new(js, "rdp", rjs);   
            
    OutputJSONBuffer(js, td->rdplog_ctx->file_ctx, &td->buffer);
      
    json_decref(js);

    SCReturnInt(TM_ECODE_OK);
}

#define OUTPUT_BUFFER_SIZE 65536
static TmEcode JsonRDPLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogRDPLogThread *aft = SCMalloc(sizeof(LogRDPLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogRDPLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for RDPLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->rdplog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonRDPLogThreadDeinit(ThreadVars *t, void *data)
{
    LogRDPLogThread *aft = (LogRDPLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogRDPLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogRDPLogDeInitCtx(OutputCtx *output_ctx)
{
    LogRDPFileCtx *rdplog_ctx = (LogRDPFileCtx *)output_ctx->data;
    LogFileFreeCtx(rdplog_ctx->file_ctx);
    SCFree(rdplog_ctx);
    SCFree(output_ctx);
}

static void LogRDPLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogRDPFileCtx *rdplog_ctx = (LogRDPFileCtx *)output_ctx->data;
    SCFree(rdplog_ctx);
    SCFree(output_ctx);
}

static OutputCtx *OutputRDPLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputJsonCtx *ojc = parent_ctx->data;

    LogRDPFileCtx *rdplog_ctx = SCMalloc(sizeof(LogRDPFileCtx));
    if (unlikely(rdplog_ctx == NULL)) {
        return NULL;
    }
    memset(rdplog_ctx, 0x00, sizeof(LogRDPFileCtx));

    rdplog_ctx->file_ctx = ojc->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(rdplog_ctx);
        return NULL;
    }

    output_ctx->data = rdplog_ctx;
    output_ctx->DeInit = LogRDPLogDeInitCtxSub;

    SCLogDebug("RDP log sub-module initialized");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_RDP);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_RDP);

    return output_ctx;
}

#define DEFAULT_LOG_FILENAME "rdp.json"
/** \brief Create a new RDP log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
static OutputCtx *OutputRDPLogInit(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();

    if(file_ctx == NULL) {
        SCLogDebug("couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogRDPFileCtx *rdplog_ctx = SCMalloc(sizeof(LogRDPFileCtx));
    if (unlikely(rdplog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
    memset(rdplog_ctx, 0x00, sizeof(LogRDPFileCtx));

    rdplog_ctx->file_ctx = file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(rdplog_ctx);
        return NULL;
    }

    output_ctx->data = rdplog_ctx;
    output_ctx->DeInit = LogRDPLogDeInitCtx;

    SCLogDebug("RDP log output initialized");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_RDP);

    return output_ctx;
}

void JsonRDPLogRegister (void)
{
    /* register as separate module */
    OutputRegisterTxModule(LOGGER_JSON_RDP, "JsonRDPLog", "rdp-json-log",
        OutputRDPLogInit, ALPROTO_RDP, JsonRDPLogger, JsonRDPLogThreadInit,
        JsonRDPLogThreadDeinit, NULL);

    /* also register as child of eve-log */
    OutputRegisterTxSubModule(LOGGER_JSON_RDP, "eve-log", "JsonRDPLog",
        "eve-log.rdp", OutputRDPLogInitSub, ALPROTO_RDP, JsonRDPLogger,
        JsonRDPLogThreadInit, JsonRDPLogThreadDeinit, NULL);
}

#else

void JsonRDPLogRegister (void)
{
}

#endif
