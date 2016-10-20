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

/*
 * TODO: Implement your app-layer logic with unit tests.
 */

/**
 * \file
 *
 * \author Tom DeCanio <decanio.tom@gmail.com>
 *
 * RTSP application layer detector and parser.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-print.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-rtsp.h"

#ifndef HAVE_GSTREAMER

void RegisterrtspParsers(void)
{
}

#else

#include <gst/rtsp/gstrtspconnection.h>
#include <gst/rtsp/gstrtspmessage.h>
#include <gst/rtsp/gstrtsptransport.h>

//#define PRINT 1

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define RTSP_DEFAULT_PORT "554"

/* The minimum size for an echo message. For some protocols this might
 * be the size of a header. */
#define RTSP_MIN_FRAME_LEN 10

/* Enum of app-layer events for an echo protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For echo we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert rtsp any any -> any any (msg:"SURICATA rtsp empty message"; \
 *    app-layer-event:rtsp.empty_message; sid:X; rev:Y;)
 */
enum {
    RTSP_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap rtsp_decoder_event_table[] = {
    {"EMPTY_MESSAGE", RTSP_DECODER_EVENT_EMPTY_MESSAGE},
};

static rtspTransaction *rtspTxAlloc(rtspState *echo)
{
    rtspTransaction *tx = SCCalloc(1, sizeof(rtspTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = echo->transaction_max++;

    TAILQ_INSERT_TAIL(&echo->tx_list, tx, next);

    return tx;
}

static void rtspTxFree(void *tx)
{
    rtspTransaction *rtsptx = tx;

    AppLayerDecoderEventsFreeEvents(&rtsptx->decoder_events);

    SCFree(tx);
}

static void *rtspStateAlloc(void)
{
    SCLogDebug("Allocating rtsp state.");
    rtspState *state = SCCalloc(1, sizeof(rtspState));
    if (unlikely(state == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&state->tx_list);
    return state;
}

static void rtspStateFree(void *state)
{
    rtspState *rtsp_state = state;
    rtspTransaction *tx;
    SCLogDebug("Freeing rtsp state.");
    while ((tx = TAILQ_FIRST(&rtsp_state->tx_list)) != NULL) {
        TAILQ_REMOVE(&rtsp_state->tx_list, tx, next);
        rtspTxFree(tx);
    }
    if (rtsp_state->request_conn.input != NULL) {
        SCFree(rtsp_state->request_conn.input);
    }
    if (rtsp_state->response_conn.input != NULL) {
        SCFree(rtsp_state->response_conn.input);
    }
    SCFree(rtsp_state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the rtspState object.
 * \param tx_id the transaction ID to free.
 */
static void rtspStateTxFree(void *state, uint64_t tx_id)
{
    rtspState *echo = state;
    rtspTransaction *tx = NULL, *ttx;

    SCLogDebug("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &echo->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&echo->tx_list, tx, next);
        rtspTxFree(tx);
        return;
    }

    SCLogDebug("Transaction %"PRIu64" not found.", tx_id);
}

static int rtspStateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, rtsp_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "rtsp enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static AppLayerDecoderEvents *rtspGetEvents(void *state, uint64_t tx_id)
{
    rtspState *rtsp_state = state;
    rtspTransaction *tx;

    TAILQ_FOREACH(tx, &rtsp_state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            return tx->decoder_events;
        }
    }

    return NULL;
}

static int rtspHasEvents(void *state)
{
    rtspState *echo = state;
    return echo->events;
}
enum
{
  STATE_START = 0,
  STATE_DATA_HEADER,
  STATE_DATA_BODY,
  STATE_READ_LINES,
  STATE_END,
  STATE_LAST
};

enum
{
  READ_AHEAD_EOH = -1,          /* end of headers */
  READ_AHEAD_CRLF = -2,
  READ_AHEAD_CRLFCR = -3
};

static GstRTSPResult
parse_string (gchar * dest, gint size, gchar ** src)
{
  GstRTSPResult res = GST_RTSP_OK;
  gint idx;

  idx = 0;
  /* skip spaces */
  while (g_ascii_isspace (**src))
    (*src)++;

  while (!g_ascii_isspace (**src) && **src != '\0') {
    if (idx < size - 1)
      dest[idx++] = **src;
    else
      res = GST_RTSP_EPARSE;
    (*src)++;
  }
  if (size > 0)
    dest[idx] = '\0';

  return res;
}

static GstRTSPResult
parse_protocol_version (gchar * protocol, GstRTSPMsgType * type,
    GstRTSPVersion * version)
{
  GstRTSPResult res = GST_RTSP_OK;
  gchar *ver;

  if (G_LIKELY ((ver = strchr (protocol, '/')) != NULL)) {
    guint major;
    guint minor;
    gchar dummychar;

    *ver++ = '\0';

    /* the version number must be formatted as X.Y with nothing following */
    if (sscanf (ver, "%u.%u%c", &major, &minor, &dummychar) != 2)
      res = GST_RTSP_EPARSE;

    if (g_ascii_strcasecmp (protocol, "RTSP") == 0) {
      if (major != 1 || minor != 0) {
        *version = GST_RTSP_VERSION_INVALID;
        res = GST_RTSP_ERROR;
      }
    } else if (g_ascii_strcasecmp (protocol, "HTTP") == 0) {
      if (*type == GST_RTSP_MESSAGE_REQUEST)
        *type = GST_RTSP_MESSAGE_HTTP_REQUEST;
      else if (*type == GST_RTSP_MESSAGE_RESPONSE)
        *type = GST_RTSP_MESSAGE_HTTP_RESPONSE;

      if (major == 1 && minor == 1) {
        *version = GST_RTSP_VERSION_1_1;
      } else if (major != 1 || minor != 0) {
        *version = GST_RTSP_VERSION_INVALID;
        res = GST_RTSP_ERROR;
      }
    } else
      res = GST_RTSP_EPARSE;
  } else
    res = GST_RTSP_EPARSE;

  return res;
}

static GstRTSPResult
parse_response_status (guint8 * buffer, GstRTSPMessage * msg)
{
  GstRTSPResult res = GST_RTSP_OK;
  GstRTSPResult res2;
  gchar versionstr[20];
  gchar codestr[4];
  gint code;
  gchar *bptr;

  bptr = (gchar *) buffer;

  if (parse_string (versionstr, sizeof (versionstr), &bptr) != GST_RTSP_OK)
    res = GST_RTSP_EPARSE;

  if (parse_string (codestr, sizeof (codestr), &bptr) != GST_RTSP_OK)
    res = GST_RTSP_EPARSE;
  code = atoi (codestr);
  if (G_UNLIKELY (*codestr == '\0' || code < 0 || code >= 600))
    res = GST_RTSP_EPARSE;

  while (g_ascii_isspace (*bptr))
    bptr++;

  if (G_UNLIKELY (gst_rtsp_message_init_response (msg, code, bptr,
              NULL) != GST_RTSP_OK))
    res = GST_RTSP_EPARSE;

  res2 = parse_protocol_version (versionstr, &msg->type,
      &msg->type_data.response.version);
  if (G_LIKELY (res == GST_RTSP_OK))
    res = res2;

  return res;
}

static GstRTSPResult
parse_request_line (guint8 * buffer, GstRTSPMessage * msg)
{
  GstRTSPResult res = GST_RTSP_OK;
  GstRTSPResult res2;
  gchar versionstr[20];
  gchar methodstr[20];
  gchar urlstr[4096];
  gchar *bptr;
  GstRTSPMethod method;

  bptr = (gchar *) buffer;

  if (parse_string (methodstr, sizeof (methodstr), &bptr) != GST_RTSP_OK)
    res = GST_RTSP_EPARSE;
  method = gst_rtsp_find_method (methodstr);

  if (parse_string (urlstr, sizeof (urlstr), &bptr) != GST_RTSP_OK)
    res = GST_RTSP_EPARSE;
  if (G_UNLIKELY (*urlstr == '\0'))
    res = GST_RTSP_EPARSE;

  if (parse_string (versionstr, sizeof (versionstr), &bptr) != GST_RTSP_OK)
    res = GST_RTSP_EPARSE;

  if (G_UNLIKELY (*bptr != '\0'))
    res = GST_RTSP_EPARSE;

  if (G_UNLIKELY (gst_rtsp_message_init_request (msg, method,
              urlstr) != GST_RTSP_OK))
    res = GST_RTSP_EPARSE;

  res2 = parse_protocol_version (versionstr, &msg->type,
      &msg->type_data.request.version);
  if (G_LIKELY (res == GST_RTSP_OK))
    res = res2;

  if (G_LIKELY (msg->type == GST_RTSP_MESSAGE_REQUEST)) {
    /* GET and POST are not allowed as RTSP methods */
    if (msg->type_data.request.method == GST_RTSP_GET ||
        msg->type_data.request.method == GST_RTSP_POST) {
      msg->type_data.request.method = GST_RTSP_INVALID;
      if (res == GST_RTSP_OK)
        res = GST_RTSP_ERROR;
    }
  } else if (msg->type == GST_RTSP_MESSAGE_HTTP_REQUEST) {
    /* only GET and POST are allowed as HTTP methods */
    if (msg->type_data.request.method != GST_RTSP_GET &&
        msg->type_data.request.method != GST_RTSP_POST) {
      msg->type_data.request.method = GST_RTSP_INVALID;
      if (res == GST_RTSP_OK)
        res = GST_RTSP_ERROR;
    }
  }

  return res;
}

/* parsing lines means reading a Key: Value pair */
static GstRTSPResult
parse_line (guint8 * buffer, GstRTSPMessage * msg)
{
  GstRTSPHeaderField field;
  gchar *line = (gchar *) buffer;
  gchar *field_name = NULL;
  gchar *value;

  if ((value = strchr (line, ':')) == NULL || value == line)
    goto parse_error;

  /* trim space before the colon */
  if (value[-1] == ' ')
    value[-1] = '\0';

  /* replace the colon with a NUL */
  *value++ = '\0';

  /* find the header */
  field = gst_rtsp_find_header_field (line);
  /* custom header not present in the list of pre-defined headers */
  if (field == GST_RTSP_HDR_INVALID)
    field_name = line;

  /* split up the value in multiple key:value pairs if it contains comma(s) */
  while (*value != '\0') {
    gchar *next_value;
    gchar *comma = NULL;
    gboolean quoted = FALSE;
    guint comment = 0;

    /* trim leading space */
    if (*value == ' ')
      value++;

    /* for headers which may not appear multiple times, and thus may not
     * contain multiple values on the same line, we can short-circuit the loop
     * below and the entire value results in just one key:value pair*/
    if (!gst_rtsp_header_allow_multiple (field))
      next_value = value + strlen (value);
    else
      next_value = value;

    /* find the next value, taking special care of quotes and comments */
    while (*next_value != '\0') {
      if ((quoted || comment != 0) && *next_value == '\\' &&
          next_value[1] != '\0')
        next_value++;
      else if (comment == 0 && *next_value == '"')
        quoted = !quoted;
      else if (!quoted && *next_value == '(')
        comment++;
      else if (comment != 0 && *next_value == ')')
        comment--;
      else if (!quoted && comment == 0) {
        /* To quote RFC 2068: "User agents MUST take special care in parsing
         * the WWW-Authenticate field value if it contains more than one
         * challenge, or if more than one WWW-Authenticate header field is
         * provided, since the contents of a challenge may itself contain a
         * comma-separated list of authentication parameters."
         *
         * What this means is that we cannot just look for an unquoted comma
         * when looking for multiple values in Proxy-Authenticate and
         * WWW-Authenticate headers. Instead we need to look for the sequence
         * "comma [space] token space token" before we can split after the
         * comma...
         */
        if (field == GST_RTSP_HDR_PROXY_AUTHENTICATE ||
            field == GST_RTSP_HDR_SUPPORTED ||
            field == GST_RTSP_HDR_WWW_AUTHENTICATE) {
          if (*next_value == ',') {
            if (next_value[1] == ' ') {
              /* skip any space following the comma so we do not mistake it for
               * separating between two tokens */
              next_value++;
            }
            comma = next_value;
          } else if (*next_value == ' ' && next_value[1] != ',' &&
              next_value[1] != '=' && comma != NULL) {
            next_value = comma;
            comma = NULL;
            break;
          }
        } else if (*next_value == ',')
          break;
      }

      next_value++;
    }

    if (msg->type == GST_RTSP_MESSAGE_REQUEST && field == GST_RTSP_HDR_SESSION) {
      /* The timeout parameter is only allowed in a session response header
       * but some clients send it as part of the session request header.
       * Ignore everything from the semicolon to the end of the line. */
      next_value = value;
      while (*next_value != '\0') {
        if (*next_value == ';') {
          break;
        }
        next_value++;
      }
    }

    /* trim space */
    if (value != next_value && next_value[-1] == ' ')
      next_value[-1] = '\0';

    if (*next_value != '\0')
      *next_value++ = '\0';

    /* add the key:value pair */
    if (*value != '\0') {
      if (field != GST_RTSP_HDR_INVALID)
        gst_rtsp_message_add_header (msg, field, value);
      else
        gst_rtsp_message_add_header_by_name (msg, field_name, value);
    }

    value = next_value;
  }

  return GST_RTSP_OK;

  /* ERRORS */
parse_error:
  {
    return GST_RTSP_EPARSE;
  }
}

/* convert all consecutive whitespace to a single space */
static void
normalize_line (guint8 * buffer)
{
  while (*buffer) {
    if (g_ascii_isspace (*buffer)) {
      guint8 *tmp;

      *buffer++ = ' ';
      for (tmp = buffer; g_ascii_isspace (*tmp); tmp++) {
      }
      if (buffer != tmp)
        memmove (buffer, tmp, strlen ((gchar *) tmp) + 1);
    } else {
      buffer++;
    }
  }
}

static gint
fill_raw_bytes (GstRTSPConnection * conn, guint8 * buffer, guint size,
    gboolean block, GError ** err)
{
  gint out = 0;

  if (conn->offset + size <= conn->input_len) {
    memcpy(buffer, &conn->input[conn->offset], size);
    conn->offset += size;
    out = size;
  }
  return out;
}

static gint
fill_bytes (GstRTSPConnection * conn, guint8 * buffer, guint size,
    gboolean block, GError ** err)
{
  gint out = fill_raw_bytes (conn, buffer, size, block, err);

  return out;
}

static GstRTSPResult
read_bytes (GstRTSPConnection * conn, guint8 * buffer, guint * idx, guint size,
    gboolean block)
{
  guint left;
  gint r;
  GError *err = NULL;

  if (G_UNLIKELY (*idx > size))
    return GST_RTSP_ERROR;

  left = size - *idx;

  while (left) {
    r = fill_bytes (conn, &buffer[*idx], left, block, &err);
    if (G_UNLIKELY (r <= 0))
      goto error;

    left -= r;
    *idx += r;
  }
  return GST_RTSP_OK;

  /* ERRORS */
error:
    if (G_UNLIKELY (r == 0))
      return GST_RTSP_EEOF;

    return GST_RTSP_OK;
}

/* The code below tries to handle clients using \r, \n or \r\n to indicate the
 * end of a line. It even does its best to handle clients which mix them (even
 * though this is a really stupid idea (tm).) It also handles Line White Space
 * (LWS), where a line end followed by whitespace is considered LWS. This is
 * the method used in RTSP (and HTTP) to break long lines.
 */
static GstRTSPResult
read_line (GstRTSPConnection * conn, guint8 * buffer, guint * idx, guint size,
    gboolean block)
{
  GstRTSPResult res;

  while (TRUE) {
    guint8 c;
    guint i;

    if (conn->read_ahead == READ_AHEAD_EOH) {
      /* the last call to read_line() already determined that we have reached
       * the end of the headers, so convey that information now */
      conn->read_ahead = 0;
      break;
    } else if (conn->read_ahead == READ_AHEAD_CRLF) {
      /* the last call to read_line() left off after having read \r\n */
      c = '\n';
    } else if (conn->read_ahead == READ_AHEAD_CRLFCR) {
      /* the last call to read_line() left off after having read \r\n\r */
      c = '\r';
    } else if (conn->read_ahead != 0) {
      /* the last call to read_line() left us with a character to start with */
      c = (guint8) conn->read_ahead;
      conn->read_ahead = 0;
    } else {
      /* read the next character */
      i = 0;
      res = read_bytes (conn, &c, &i, 1, block);
      if (G_UNLIKELY (res != GST_RTSP_OK))
        return res;
    }

    /* special treatment of line endings */
    if (c == '\r' || c == '\n') {
      guint8 read_ahead;

    retry:
      /* need to read ahead one more character to know what to do... */
      i = 0;
      res = read_bytes (conn, &read_ahead, &i, 1, block);
      if (G_UNLIKELY (res != GST_RTSP_OK))
        return res;

      if (read_ahead == ' ' || read_ahead == '\t') {
        if (conn->read_ahead == READ_AHEAD_CRLFCR) {
          /* got \r\n\r followed by whitespace, treat it as a normal line
           * followed by one starting with LWS */
          conn->read_ahead = read_ahead;
          break;
        } else {
          /* got LWS, change the line ending to a space and continue */
          c = ' ';
          conn->read_ahead = read_ahead;
        }
      } else if (conn->read_ahead == READ_AHEAD_CRLFCR) {
        if (read_ahead == '\r' || read_ahead == '\n') {
          /* got \r\n\r\r or \r\n\r\n, treat it as the end of the headers */
          conn->read_ahead = READ_AHEAD_EOH;
          break;
        } else {
          /* got \r\n\r followed by something else, this is not really
           * supported since we have probably just eaten the first character
           * of the body or the next message, so just ignore the second \r
           * and live with it... */
          conn->read_ahead = read_ahead;
          break;
        }
      } else if (conn->read_ahead == READ_AHEAD_CRLF) {
        if (read_ahead == '\r') {
          /* got \r\n\r so far, need one more character... */
          conn->read_ahead = READ_AHEAD_CRLFCR;
          goto retry;
        } else if (read_ahead == '\n') {
          /* got \r\n\n, treat it as the end of the headers */
          conn->read_ahead = READ_AHEAD_EOH;
          break;
        } else {
          /* found the end of a line, keep read_ahead for the next line */
          conn->read_ahead = read_ahead;
          break;
        }
      } else if (c == read_ahead) {
        /* got double \r or \n, treat it as the end of the headers */
        conn->read_ahead = READ_AHEAD_EOH;
        break;
      } else if (c == '\r' && read_ahead == '\n') {
        /* got \r\n so far, still need more to know what to do... */
        conn->read_ahead = READ_AHEAD_CRLF;
        goto retry;
      } else {
        /* found the end of a line, keep read_ahead for the next line */
        conn->read_ahead = read_ahead;
        break;
      }
    }

    if (G_LIKELY (*idx < size - 1))
      buffer[(*idx)++] = c;
  }
  buffer[*idx] = '\0';

  return GST_RTSP_OK;
}

/* returns:
 *  GST_RTSP_OK when a complete message was read.
 *  GST_RTSP_EEOF: when the read socket is closed
 *  GST_RTSP_EINTR: when more data is needed.
 *  GST_RTSP_..: some other error occured.
 */
static GstRTSPResult
build_next (GstRTSPBuilder * builder, GstRTSPMessage * message,
    GstRTSPConnection * conn, gboolean block)
{
  GstRTSPResult res;

  while (TRUE) {
    switch (builder->state) {
      case STATE_START:
      {
        guint8 c;

        builder->offset = 0;
        res =
            read_bytes (conn, (guint8 *) builder->buffer, &builder->offset, 1,
            block);
        if (res != GST_RTSP_OK)
          goto done;

        c = builder->buffer[0];

        /* we have 1 bytes now and we can see if this is a data message or
         * not */
        if (c == '$') {
          /* data message, prepare for the header */
          builder->state = STATE_DATA_HEADER;
          conn->may_cancel = FALSE;
        } else if (c == '\n' || c == '\r') {
          /* skip \n and \r */
          builder->offset = 0;
        } else {
          builder->line = 0;
          builder->state = STATE_READ_LINES;
          conn->may_cancel = FALSE;
        }
        break;
      }
      case STATE_DATA_HEADER:
      {
        res =
            read_bytes (conn, (guint8 *) builder->buffer, &builder->offset, 4,
            block);
        if (res != GST_RTSP_OK)
          goto done;

        gst_rtsp_message_init_data (message, builder->buffer[1]);

        builder->body_len = (builder->buffer[2] << 8) | builder->buffer[3];
        builder->body_data = g_malloc (builder->body_len + 1);
        builder->body_data[builder->body_len] = '\0';
        builder->offset = 0;
        builder->state = STATE_DATA_BODY;
        break;
      }
      case STATE_DATA_BODY:
      {
        res =
            read_bytes (conn, builder->body_data, &builder->offset,
            builder->body_len, block);
        if (res != GST_RTSP_OK)
          goto done;

        /* we have the complete body now, store in the message adjusting the
         * length to include the trailing '\0' */
        gst_rtsp_message_take_body (message,
            (guint8 *) builder->body_data, builder->body_len + 1);
        builder->body_data = NULL;
        builder->body_len = 0;

        builder->state = STATE_END;
        break;
      }
      case STATE_READ_LINES:
      {
#ifdef PRINT
        printf("before readline offset: %d input_len %d\n", conn->offset, conn->input_len);
#endif
        res = read_line (conn, builder->buffer, &builder->offset,
            sizeof (builder->buffer), block);
        if (res != GST_RTSP_OK) {
#ifdef PRINT
          printf("bad line -----------------------\n");
          printf("\"%s\"\n", builder->buffer);
          printf("----------------------------\n");
#endif
          goto done;
        }
#ifdef PRINT
        printf("line -----------------------\n");
        printf("\"%s\"\n", builder->buffer);
        printf("----------------------------\n");
#endif
        /* we have a regular response */
        if (builder->buffer[0] == '\0') {
          gchar *hdrval;

          /* empty line, end of message header */
          /* see if there is a Content-Length header, but ignore it if this
           * is a POST request with an x-sessioncookie header */
          if (gst_rtsp_message_get_header (message,
                  GST_RTSP_HDR_CONTENT_LENGTH, &hdrval, 0) == GST_RTSP_OK &&
              (message->type != GST_RTSP_MESSAGE_HTTP_REQUEST ||
                  message->type_data.request.method != GST_RTSP_POST ||
                  gst_rtsp_message_get_header (message,
                      GST_RTSP_HDR_X_SESSIONCOOKIE, NULL, 0) != GST_RTSP_OK)) {
            /* there is, prepare to read the body */
            builder->body_len = atol (hdrval);
            builder->body_data = g_try_malloc (builder->body_len + 1);
            /* we can't do much here, we need the length to know how many bytes
             * we need to read next and when allocation fails, something is
             * probably wrong with the length. */
            if (builder->body_data == NULL)
              goto invalid_body_len;

            builder->body_data[builder->body_len] = '\0';
            builder->offset = 0;
            builder->state = STATE_DATA_BODY;
          } else {
            builder->state = STATE_END;
          }
          break;
        }

        /* we have a line */
        normalize_line (builder->buffer);
        if (builder->line == 0) {
          /* first line, check for response status */
          if (memcmp (builder->buffer, "RTSP", 4) == 0 ||
              memcmp (builder->buffer, "HTTP", 4) == 0) {
            builder->status = parse_response_status (builder->buffer, message);
          } else {
            builder->status = parse_request_line (builder->buffer, message);
          }
        } else {
          /* else just parse the line */
          res = parse_line (builder->buffer, message);
          if (res != GST_RTSP_OK)
            builder->status = res;
        }
        builder->line++;
        builder->offset = 0;
        break;
      }
      case STATE_END:
      {
        gchar *session_cookie;
        gchar *session_id;

        conn->may_cancel = TRUE;

        if (message->type == GST_RTSP_MESSAGE_DATA) {
          /* data messages don't have headers */
          builder->state = STATE_START; /* TD */
          res = GST_RTSP_OK;
          goto done;
        }

        /* save the tunnel session in the connection */
        if (message->type == GST_RTSP_MESSAGE_HTTP_REQUEST &&
            !conn->manual_http &&
            conn->tstate == TUNNEL_STATE_NONE &&
            gst_rtsp_message_get_header (message, GST_RTSP_HDR_X_SESSIONCOOKIE,
                &session_cookie, 0) == GST_RTSP_OK) {
          memcpy (conn->tunnelid, session_cookie, TUNNELID_LEN);
          conn->tunnelid[TUNNELID_LEN - 1] = '\0';
          conn->tunneled = TRUE;
        }

        /* save session id in the connection for further use */
        if (message->type == GST_RTSP_MESSAGE_RESPONSE &&
            gst_rtsp_message_get_header (message, GST_RTSP_HDR_SESSION,
                &session_id, 0) == GST_RTSP_OK) {
          gint maxlen, i;

          maxlen = sizeof (conn->session_id) - 1;
          /* the sessionid can have attributes marked with ;
           * Make sure we strip them */
          for (i = 0; session_id[i] != '\0'; i++) {
            if (session_id[i] == ';') {
              maxlen = i;
              /* parse timeout */
              do {
                i++;
              } while (g_ascii_isspace (session_id[i]));
              if (g_str_has_prefix (&session_id[i], "timeout=")) {
                gint to;

                /* if we parsed something valid, configure */
                if ((to = atoi (&session_id[i + 8])) > 0)
                  conn->timeout = to;
              }
              break;
            }
          }

          /* make sure to not overflow */
          if (conn->remember_session_id) {
            memcpy (conn->session_id, session_id, maxlen);
            conn->session_id[maxlen] = '\0';
          }
        }
        builder->state = STATE_START; /* TD */
        res = builder->status;
        goto done;
      }
      default:
        res = GST_RTSP_ERROR;
        break;
    }
  }
done:
  conn->may_cancel = TRUE;
  return res;

  /* ERRORS */
invalid_body_len:
  {
    conn->may_cancel = TRUE;
#if 0
    GST_DEBUG ("could not allocate body");
#endif
    return GST_RTSP_ERROR;
  }
}

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_RTSP if it looks like echo, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto rtspProbingParser(uint8_t *input, uint32_t input_len,
    uint32_t *offset)
{
    GstRTSPMessage message;
    GstRTSPConnection conn;
    GstRTSPBuilder builder;
    GstRTSPResult res;
    memset(&conn, 0, sizeof(conn));
    conn.input = input;
    conn.input_len = input_len;
    conn.offset = 0;
    memset(&message, 0, sizeof(message));
    memset(&builder, 0, sizeof(builder));
    res = build_next(&builder, &message, &conn, 0);
    if (res != GST_RTSP_ERROR) {
        if (message.type != GST_RTSP_MESSAGE_INVALID) {
            return ALPROTO_RTSP;
        }
    }
    SCLogDebug("Protocol not detected as ALPROTO_RTSP.");
    return ALPROTO_UNKNOWN;
}

static int rtspProcessMessage(rtspState *rtsp, GstRTSPMessage *message)
{
    rtspTransaction *tx = NULL, *ttx;
    switch (message->type) {
        case GST_RTSP_MESSAGE_REQUEST:
            tx = rtspTxAlloc(rtsp);
            if (unlikely(tx == NULL)) {
                SCLogDebug("Failed to allocate new rtsp tx.");
                goto end;
            }
            tx->request = *message;
            break;
        case GST_RTSP_MESSAGE_RESPONSE:
            TAILQ_FOREACH(ttx, &rtsp->tx_list, next) {
                tx = ttx;
            }
            if (tx == NULL) {
                SCLogDebug("Failed to find transaction for response on RTSP state %p.",
                            rtsp);
                goto end;
            }
            tx->response = *message;
            /* Set the response_done flag for transaction state checking in
             * rtspGetStateProgress(). */
            tx->response_done = 1;
            break;
        case GST_RTSP_MESSAGE_HTTP_REQUEST:
            break;
        case GST_RTSP_MESSAGE_HTTP_RESPONSE:
            break;
        case GST_RTSP_MESSAGE_DATA:
            SCLogDebug("RTSP message data received.");
            break;
        case GST_RTSP_MESSAGE_INVALID:
        default:
            break;
    }
end:
    return 0;
}

static int rtspParseRequest(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    rtspState *rtsp = state;
    GstRTSPMessage message;
    GstRTSPResult res;

    SCLogDebug("Parsing RTSP request: len=%"PRIu32, input_len);
#ifdef PRINT
    printf("RTSP Parse Request-------------------\n");
    PrintRawDataFp(stdout, input, input_len);
    printf("-------------------------------------\n");
#endif

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    /* Buffer the new input */
    if (rtsp->request_conn.input == NULL) {
        rtsp->request_conn.input = SCMalloc(input_len);
        if (rtsp->request_conn.input == NULL) {
            return 0;
        }
        memcpy(rtsp->request_conn.input, input, input_len);
        rtsp->request_conn.input_len = input_len;
        rtsp->request_conn.offset = 0;
    } else {
        memmove(rtsp->request_conn.input,
                &rtsp->request_conn.input[rtsp->request_conn.offset],
                rtsp->request_conn.input_len - rtsp->request_conn.offset);
        rtsp->request_conn.input_len -= rtsp->request_conn.offset;
        void *p = SCRealloc(rtsp->request_conn.input,
                            rtsp->request_conn.input_len + input_len);
        if (p == NULL) {
            SCFree(rtsp->request_conn.input);
            rtsp->request_conn.input_len = 0;
            rtsp->request_conn.offset = 0;
            return 0;
        }
        rtsp->request_conn.input = p;
        memcpy(&rtsp->request_conn.input[rtsp->request_conn.input_len],
               input, input_len);
        rtsp->request_conn.input_len += input_len;
        rtsp->request_conn.offset = 0;
    }

    memset(&message, 0, sizeof(message));
    
    res = build_next(&rtsp->request_builder, &message, &rtsp->request_conn, 0);
    if (res == GST_RTSP_ERROR) {
        goto end;
    }

#ifdef PRINT
    printf("consumed (%d bytes)-----------------\n", rtsp->request_conn.offset);
    PrintRawDataFp(stdout, rtsp->request_conn.input, rtsp->request_conn.offset);
    printf("-------------------------------------\n");
#endif

    rtspProcessMessage(rtsp, &message);

end:    
    return 0;
}

static int rtspParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    rtspState *rtsp = state;
    GstRTSPMessage message;
    GstRTSPResult res;

    SCLogDebug("Parsing RTSP response.");
#ifdef PRINT
    printf("RTSP Parse Response------------------\n");
    PrintRawDataFp(stdout, input, input_len);
    printf("-------------------------------------\n");
#endif

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    /* Buffer the new input */
    /* TBD: make this buffering stuff common to request/response */
    if (rtsp->response_conn.input == NULL) {
        rtsp->response_conn.input = SCMalloc(input_len);
        if (rtsp->response_conn.input == NULL) {
            return 0;
        }
        memcpy(rtsp->response_conn.input, input, input_len);
        rtsp->response_conn.input_len = input_len;
        rtsp->response_conn.offset = 0;
    } else {
        memmove(rtsp->response_conn.input,
                &rtsp->response_conn.input[rtsp->response_conn.offset],
                rtsp->response_conn.input_len - rtsp->response_conn.offset);
        rtsp->response_conn.input_len -= rtsp->response_conn.offset;
        void *p = SCRealloc(rtsp->response_conn.input,
                            rtsp->response_conn.input_len + input_len);
        if (p == NULL) {
            SCFree(rtsp->response_conn.input);
            rtsp->response_conn.input_len = 0;
            rtsp->response_conn.offset = 0;
            return 0;
        }
        rtsp->response_conn.input = p;
        memcpy(&rtsp->response_conn.input[rtsp->response_conn.input_len],
               input, input_len);
        rtsp->response_conn.input_len += input_len;
        rtsp->response_conn.offset = 0;
    }

    memset(&message, 0, sizeof(message));
    
    res = build_next(&rtsp->response_builder, &message, &rtsp->response_conn, 0);
    if (res == GST_RTSP_ERROR) {
        goto end;
    }

#ifdef PRINT
    printf("consumed (%d bytes)-----------------\n", rtsp->response_conn.offset);
    PrintRawDataFp(stdout, rtsp->response_conn.input, rtsp->response_conn.offset);
    printf("-------------------------------------\n");
#endif

    rtspProcessMessage(rtsp, &message);

end:
    return 0;
}

static uint64_t rtspGetTxCnt(void *state)
{
    rtspState *echo = state;
    SCLogDebug("Current tx count is %"PRIu64".", echo->transaction_max);
    return echo->transaction_max;
}

static void *rtspGetTx(void *state, uint64_t tx_id)
{
    rtspState *echo = state;
    rtspTransaction *tx;

    SCLogDebug("Requested tx ID %"PRIu64".", tx_id);

    TAILQ_FOREACH(tx, &echo->tx_list, next) {
        if (tx->tx_id == tx_id) {
            SCLogDebug("Transaction %"PRIu64" found, returning tx object %p.",
                tx_id, tx);
            return tx;
        }
    }

    SCLogDebug("Transaction ID %"PRIu64" not found.", tx_id);
    return NULL;
}

static void rtspSetTxLogged(void *state, void *vtx, uint32_t logger)
{
    rtspTransaction *tx = (rtspTransaction *)vtx;
    tx->logged |= logger;
}

static int rtspGetTxLogged(void *state, void *vtx, uint32_t logger)
{
    rtspTransaction *tx = (rtspTransaction *)vtx;
    if (tx->logged & logger)
        return 1;

    return 0;
}

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int rtspGetAlstateProgressCompletionStatus(uint8_t direction) {
    return 1;
}

/**
 * \brief Return the state of a transaction in a given direction.
 *
 * In the case of the echo protocol, the existence of a transaction
 * means that the request is done. However, some protocols that may
 * need multiple chunks of data to complete the request may need more
 * than just the existence of a transaction for the request to be
 * considered complete.
 *
 * For the response to be considered done, the response for a request
 * needs to be seen.  The response_done flag is set on response for
 * checking here.
 */
static int rtspGetStateProgress(void *tx, uint8_t direction)
{
    rtspTransaction *rtsptx = tx;

    SCLogDebug("Transaction progress requested for tx ID %"PRIu64
        ", direction=0x%02x", rtsptx->tx_id, direction);

    if (direction & STREAM_TOCLIENT && rtsptx->response_done) {
        return 1;
    }
    else if (direction & STREAM_TOSERVER) {
        /* For echo, just the existence of the transaction means the
         * request is done. */
        return 1;
    }

    return 0;
}

/**
 * \brief ???
 */
static DetectEngineState *rtspGetTxDetectState(void *vtx)
{
    rtspTransaction *tx = vtx;
    return tx->de_state;
}

/**
 * \brief ???
 */
static int rtspSetTxDetectState(void *state, void *vtx,
    DetectEngineState *s)
{
    rtspTransaction *tx = vtx;
    tx->de_state = s;
    return 0;
}

void RegisterrtspParsers(void)
{
    char *proto_name = "rtsp";

    /* Check if rtsp TCP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {

        SCLogDebug("RTSP TCP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_RTSP, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogDebug("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, RTSP_DEFAULT_PORT,
                ALPROTO_RTSP, 0, RTSP_MIN_FRAME_LEN, STREAM_TOSERVER,
                rtspProbingParser);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_RTSP, 0, RTSP_MIN_FRAME_LEN,
                    rtspProbingParser)) {
                SCLogDebug("No RTSP app-layer configuration, enabling RTSP"
                    " detection TCP detection on port %s.",
                    RTSP_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                    RTSP_DEFAULT_PORT, ALPROTO_RTSP, 0,
                    RTSP_MIN_FRAME_LEN, STREAM_TOSERVER,
                    rtspProbingParser);
            }

        }

    }

    else {
        SCLogDebug("Protocol detecter and parser disabled for rtsp.");
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {

        SCLogDebug("Registering RTSP protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new rtsp flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_RTSP,
            rtspStateAlloc, rtspStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_RTSP,
            STREAM_TOSERVER, rtspParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_RTSP,
            STREAM_TOCLIENT, rtspParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_RTSP,
            rtspStateTxFree);

        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_RTSP,
            rtspGetTxLogged, rtspSetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_RTSP,
            rtspGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_RTSP,
            rtspGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP,
            ALPROTO_RTSP, rtspGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_RTSP,
            rtspGetTx);

        /* Application layer event handling. */
        AppLayerParserRegisterHasEventsFunc(IPPROTO_TCP, ALPROTO_RTSP,
            rtspHasEvents);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_RTSP,
            NULL, rtspGetTxDetectState, rtspSetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_RTSP,
            rtspStateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_RTSP,
            rtspGetEvents);
    }
    else {
        SCLogDebug("rtsp protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_RTSP,
        rtspParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void rtspParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}

#endif
