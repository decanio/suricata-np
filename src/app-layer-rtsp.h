/* Copyright (C) 2015 Open Information Security Foundation
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
 * \author FirstName LastName <yourname@domain>
 */

#ifndef __APP_LAYER_RTSP_H__
#define __APP_LAYER_RTSP_H__

#include "detect-engine-state.h"

#include "queue.h"


#ifdef HAVE_GSTREAMER

#include <gst/rtsp/gstrtspconnection.h>

typedef struct rtspTransaction_ {

    uint64_t tx_id;             /*<< Internal transaction ID. */

    AppLayerDecoderEvents *decoder_events; /*<< Application layer
                                            * events that occurred
                                            * while parsing this
                                            * transaction. */
    GstRTSPMessage request;
    GstRTSPMessage response;

    /* flags indicating which loggers that have logged */
    uint32_t logged;

    uint8_t response_done; /*<< Flag to be set when the response is
                            * seen. */

    DetectEngineState *de_state;

    TAILQ_ENTRY(rtspTransaction_) next;

} rtspTransaction;

/* a structure for constructing RTSPMessages */
typedef struct
{
  gint state;
  GstRTSPResult status;
  guint8 buffer[4096];
  guint offset;

  guint line;
  guint8 *body_data;
  glong body_len;
} GstRTSPBuilder;

typedef enum
{
  TUNNEL_STATE_NONE,
  TUNNEL_STATE_GET,
  TUNNEL_STATE_POST,
  TUNNEL_STATE_COMPLETE
} GstRTSPTunnelState;

#define TUNNELID_LEN    24

struct _GstRTSPConnection
{
  uint8_t *input;
  uint32_t input_len;
  uint32_t offset;
  /* connection state */
  gboolean manual_http;
  gboolean may_cancel;

  gchar tunnelid[TUNNELID_LEN];
  gboolean tunneled;
  GstRTSPTunnelState tstate;

  gint read_ahead;

  gboolean remember_session_id; /* remember the session id or not */

  /* Session state */
  gchar session_id[512];        /* session id */
  gint timeout;                 /* session timeout in seconds */
};

typedef struct rtspState_ {

    TAILQ_HEAD(, rtspTransaction_) tx_list; /**< List of rtsp transactions
                                       * associated with this
                                       * state. */

    GstRTSPBuilder request_builder;
    GstRTSPBuilder response_builder;

    GstRTSPConnection request_conn;
    GstRTSPConnection response_conn;

    uint64_t transaction_max; /**< A count of the number of
                               * transactions created.  The
                               * transaction ID for each transaction
                               * is allocted by incrementing this
                               * value. */


    uint16_t events; /**< Number of application layer events created
                      * for this state. */

} rtspState;

#endif /* HAVE_GSTREAMER */

void RegisterrtspParsers(void);
void rtspParserRegisterTests(void);

#endif /* __APP_LAYER_RTSP_H__ */
