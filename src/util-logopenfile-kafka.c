/* vi: set et ts=4: */
/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * \author Paulo Pacheco <fooinha@gmail.com>
 *
 * File-like output for logging: Apache Kafka
 */

#include "suricata-common.h" /* errno.h, string.h, etc. */
#include "util-print.h"      /* PrintBufferData */

#include "util-logopenfile-kafka.h"
#include "util-logopenfile.h"

#ifdef HAVE_LIBRDKAFKA

/**
 * \brief KafkaConfNew() - creates a new kafka configuration
 *
 * \retval pointer to allocated rd_kafka_conf_t created
 */
static rd_kafka_conf_t * KafkaConfNew(void) {

    /* Kafka configuration */
    rd_kafka_conf_t *conf = rd_kafka_conf_new();
    if (!conf) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating kafka conf");
        exit(EXIT_FAILURE);
    }

    return conf;
}

/**
 * \brief KafkaConfSetInt() sets a configuration key with integer value
 * \param conf the kafka configuration
 * \param key the configuration key
 * \param value the configuration integer value
 *
 * \retval rd_kafka_conf_res_t says if key was added to kafka configuration
 */
static rd_kafka_conf_res_t KafkaConfSetInt(rd_kafka_conf_t *conf, const char * key, intmax_t value)
{
    char buf[21] = {0};
    uint32_t sz  = sizeof(buf);

    char errstr[2048]  = {0};
    uint32_t errstr_sz = sizeof(errstr);

    uint32_t offset = 0;
    PrintBufferData(buf, &offset, sz, "%lu", value);

    rd_kafka_conf_res_t ret = rd_kafka_conf_set(conf, key, buf, errstr, errstr_sz);
    if (ret != RD_KAFKA_CONF_OK) {
        SCLogWarning(SC_ERR_MEM_ALLOC, "Failed to set kafka conf [%s] => [%s] : %s", key, buf, errstr);
    }

    return ret;
}

/**
 * \brief KafkaConfSetString() sets a configuration key with a string value
 * \param conf the kafka configuration
 * \param key the configuration key
 * \param value the configuration string value
 *
 * \retval rd_kafka_conf_res_t says if key was added to kafka configuration
 */
static rd_kafka_conf_res_t KafkaConfSetString(rd_kafka_conf_t *conf, const char * key, const char *value)
{
    char errstr[2048]  = {0};
    uint32_t errstr_sz = sizeof(errstr);

    rd_kafka_conf_res_t ret = rd_kafka_conf_set(conf, key, value, errstr, errstr_sz);
    if(ret != RD_KAFKA_CONF_OK) {
        SCLogWarning(SC_ERR_MEM_ALLOC, "Failed to set kafka conf [%s] => [%s] : %s", key, value, errstr);
    }

    return ret;
}

/**
 * \brief KafkaTopicConfSetString() sets a configuration key with a string value to a kafka topic
 * \param conf the kafka topic configuration
 * \param key the configuration key
 * \param value the configuration string value
 *
 * \retval rd_kafka_conf_res_t says if key was added to kafka topic's configuration
 */
static rd_kafka_conf_res_t KafkaTopicConfSetString(rd_kafka_topic_conf_t *conf, const char * key, const char *value)
{
    char errstr[2048]  = {0};
    uint32_t errstr_sz = sizeof(errstr);

    rd_kafka_conf_res_t ret = rd_kafka_topic_conf_set(conf, key, value, errstr, errstr_sz);
    if(ret != RD_KAFKA_CONF_OK) {
        SCLogWarning(SC_ERR_MEM_ALLOC, "Failed to set kafka topic conf [%s] => [%s] : %s", key, value, errstr);
    }

    return ret;
}

/**
 * \brief KafkaConfSetup() sets up kafka configuration for the most relevant settings from
 *                         suricata config file
 * \param conf the kafka configuration
 * \param sensor_name the client id to send to kafka brokers
 * \param compression with compression coded will be using when producing messages
 * \param buffer_max_messages max number of messages to keep in local producer queue
 * \param max_retries max number of retries when production messages to brokers
 * \param backoff_ms time to leave alone the kafka brokers
 * \param loglevel the level of logging for the rdkafka library . default=> 6 ; 7 => debug
 *
 * \retval rd_kafka_conf_t the built kafka configuration
 */
static rd_kafka_conf_t* KafkaConfSetup(rd_kafka_conf_t *conf, const char *sensor_name,
        const char *compression,
        intmax_t buffer_max_messages, intmax_t max_retries, intmax_t backoff_ms,
        intmax_t loglevel
        )
{

    /* Setting client id with sensor's name */
    if(!sensor_name) {
        KafkaConfSetString(conf, "client.id", sensor_name);
    } else {
        char hostname[1024] = {0};
        gethostname(hostname, 1023);
        KafkaConfSetString(conf, "client.id", hostname);
    }

    /* Compression */
    KafkaConfSetString(conf, "compression.codec", compression);

    /* Configure throughput */
    KafkaConfSetInt(conf, "queue.buffering.max.messages", buffer_max_messages);

    /* Configure retries */
    KafkaConfSetInt(conf, "message.send.max.retries", max_retries);

    /* Configure backoff in ms */
    KafkaConfSetInt(conf, "retry.backoff.ms", backoff_ms);

    /* Configure debug sections */
    KafkaConfSetInt(conf, "log_level", loglevel);

    /* Configure debug sections */
    KafkaConfSetString(conf, "debug", "all");

    return conf;
}

/**
 * \brief SCLogFileCloseKafka() Closes kafka logging
 * \param log_ctx the logging context
 */
void SCLogFileCloseKafka(LogFileCtx *log_ctx)
{
    if (log_ctx->kafka_setup.brokers) {
        /* Destroy brokers */
        SCFree(log_ctx->kafka_setup.brokers);
        log_ctx->kafka_setup.brokers = NULL;
    }

    if (log_ctx->kafka_setup.topic) {
        /* Destroy topic */
        rd_kafka_topic_destroy(log_ctx->kafka_setup.topic);
        log_ctx->kafka_setup.topic = NULL;
    }

    if (log_ctx->kafka) {
        /* Destroy the handle */
        rd_kafka_destroy(log_ctx->kafka);
        log_ctx->kafka = NULL;
    }

}

/**
 * \brief KafkaLogCb() callback for logging
 * \param rk the kafka producer handle
 * \param level the logging level
 * \param fac the facility name
 * \param buf the message to log
 */
static void KafkaLogCb(const rd_kafka_t *rk, int level, const char *fac, const char *buf)
{

    switch(level) {
        case SC_LOG_NOTSET:
        case SC_LOG_NONE:
            break;
        case SC_LOG_NOTICE:
            SCLogNotice("RDKAFKA-%i-%s: %s: %s\n", level, fac, rd_kafka_name(rk), buf);
            break;
        case SC_LOG_INFO:
            SCLogInfo("RDKAFKA-%i-%s: %s: %s\n", level, fac, rd_kafka_name(rk), buf);
            break;
        case SC_LOG_EMERGENCY:
            SCLogEmerg(SC_ERR_SOCKET,"RDKAFKA-%i-%s: %s: %s\n", level, fac, rd_kafka_name(rk), buf);
            break;
        case SC_LOG_CRITICAL:
            SCLogCritical(SC_ERR_SOCKET, "RDKAFKA-%i-%s: %s: %s\n", level, fac, rd_kafka_name(rk), buf);
            break;
        case SC_LOG_ALERT:
            SCLogAlert(SC_ERR_SOCKET, "RDKAFKA-%i-%s: %s: %s\n", level, fac, rd_kafka_name(rk), buf);
            break;
        case SC_LOG_ERROR:
            SCLogError(SC_ERR_SOCKET, "RDKAFKA-%i-%s: %s: %s\n", level, fac, rd_kafka_name(rk), buf);
            break;
        case SC_LOG_WARNING:
            SCLogWarning(SC_ERR_SOCKET, "RDKAFKA-%i-%s: %s: %s\n", level, fac, rd_kafka_name(rk), buf);
            break;
        case SC_LOG_DEBUG:
            SCLogDebug("RDKAFKA-%i-%s: %s: %s\n", level, fac, rd_kafka_name(rk), buf);
            break;
        default:
            /* OTHER LOG LEVELS */
            break;
    }
}

/**
 * \brief SCLogOpenKafka() creates a kafka handler based on config setup
 * \param kafka_setup the settings
 *
 * \return pointer rd_kafka_t * to created handler
 *                 NULL if failed
 */
rd_kafka_t *SCLogOpenKafka(KafkaSetup *kafka_setup)
{
    rd_kafka_t *rk                    = NULL;
    rd_kafka_topic_conf_t *topic_conf = NULL;
    rd_kafka_topic_t *rkt             = NULL;
    char errstr[2048]  = {0};

    /* Create Kafka handle */
    if (!(rk = rd_kafka_new(RD_KAFKA_PRODUCER, kafka_setup->conf, errstr, sizeof(errstr)))) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to create kafka handler: %s", errstr);
        return NULL;
    }
    /* Set the log level */
    rd_kafka_set_log_level(rk, kafka_setup->loglevel);
    /* Add brokers */
    if (rd_kafka_brokers_add(rk, kafka_setup->brokers) == 0) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to add kafka brokers: %s", kafka_setup->brokers);
        return NULL;
    } else {
        SCLogInfo("eve kafka output: afka brokers added: %s", kafka_setup->brokers);
    }
    /* Topic configuration - Not saved at setup */
    if ( !(topic_conf = rd_kafka_topic_conf_new())) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate kafka topic conf");
        return NULL;
    }
    /* Configure acks */
    KafkaTopicConfSetString(topic_conf, "request.required.acks", "0");

    /* Topic  */
    if ( !(rkt = rd_kafka_topic_new(rk, kafka_setup->topic_name, topic_conf))) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate kafka topic %s", kafka_setup->topic_name);
        return NULL;
    }
    kafka_setup->topic       = rkt;
    return rk;
}

/**
 * \brief SCConfLogOpenKafka() - Reads configuration settings and opens kafka logging output mode.
 * \param kafka_node the configuration node
 * \param sensor_name sensor's name to use as kafka's client.id
 *
 */
void SCConfLogOpenKafka(ConfNode *kafka_node, KafkaSetup *kafka_setup, char *sensor_name)
{
    /* Kafka default values */
    const char *    kafka_default_broker_list         = "127.0.0.1:9092";
    const char *    kafka_default_compression         = "snappy";
    const char *    kafka_default_topic               = "suricata";
    const intmax_t  kafka_default_max_retries         = 1;
    const intmax_t  kafka_default_backoff_ms          = 10;
    const intmax_t  kafka_default_buffer_max_messages = 100000;
    const intmax_t  kafka_default_loglevel            = 6;
    const intmax_t  kafka_default_partition           = RD_KAFKA_PARTITION_UA; /* Unassigned partition */
    const char *brokers          = kafka_default_broker_list;
    const char *compression      = kafka_default_compression;
    const char *topic_name       = kafka_default_topic;
    intmax_t max_retries         = kafka_default_max_retries;
    intmax_t backoff_ms          = kafka_default_backoff_ms;
    intmax_t buffer_max_messages = kafka_default_buffer_max_messages;
    intmax_t loglevel            = kafka_default_loglevel;
    intmax_t partition           = 0;

    /* Configures kafka things */
    if (! kafka_node )
        return;
    brokers = ConfNodeLookupChildValue(kafka_node, "broker-list");
    if (! brokers) {
        brokers = kafka_default_broker_list;
        SCLogWarning(SC_ERR_MISSING_CONFIG_PARAM, "eve kafka output: using default broker: %s", kafka_default_broker_list);
    }
    compression = ConfNodeLookupChildValue(kafka_node, "compression");
    if (! compression) {
        compression = kafka_default_compression;
        SCLogInfo("eve kafka output: using default compression: %s", kafka_default_compression);
    }
    topic_name = ConfNodeLookupChildValue(kafka_node, "topic");
    if (! topic_name) {
        topic_name = kafka_default_topic;
        SCLogWarning(SC_ERR_MISSING_CONFIG_PARAM, "eve kafka output: using default topic: %s", kafka_default_topic);
    } else {
        SCLogInfo("eve kafka output: topic: %s", topic_name);
    }
    if (! ConfGetChildValueInt(kafka_node, "max-retries", &max_retries) ) {
        SCLogInfo("eve kafka output: using default max-retries: %lu", kafka_default_max_retries);
    }
    if (! ConfGetChildValueInt(kafka_node, "backoff-ms", &backoff_ms) ) {
        SCLogInfo("eve kafka output: using default backoff-ms: %lu", kafka_default_backoff_ms);
    }
    if (! ConfGetChildValueInt(kafka_node, "buffer-max-messages", &buffer_max_messages) ) {
        SCLogInfo("eve kafka output: using default buffer-max-messages: %lu", kafka_default_buffer_max_messages);
    }
    if (! ConfGetChildValueInt(kafka_node, "partition", &partition) ) {
        SCLogInfo("eve kafka output: using default unassigned partition");
    }
    if (! ConfGetChildValueInt(kafka_node, "log-level", &loglevel) ) {
        SCLogInfo("eve kafka output: using default log-level: %lu", kafka_default_loglevel);
    } else {
        SCLogInfo("eve kafka output: log-level: %lu", loglevel);
    }
    kafka_setup->brokers   = SCStrdup(brokers);
    if (kafka_setup->brokers == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating kafka brokers");
        return;
    }
    if (partition < 0) {
        partition = kafka_default_partition;
        SCLogInfo("eve kafka output: using default unassigned partition");
    }
    /* Check librdkafka version and emit warning if outside of tested versions */
    if ( RD_KAFKA_VERSION > 0x000901ff || RD_KAFKA_VERSION < 0x00080100 ) {
        SCLogWarning(SC_ERR_SOCKET, "librdkafka version check fails : %x", RD_KAFKA_VERSION);
    }
    /* Kafka configuration */
    rd_kafka_conf_t *conf = KafkaConfNew();
    /* Set configurations */
    conf = KafkaConfSetup(conf,
            sensor_name,
            compression, buffer_max_messages, max_retries, backoff_ms, loglevel);

    /* Set log callback */
    rd_kafka_conf_set_log_cb(conf, KafkaLogCb);
    kafka_setup->conf        = conf;
    kafka_setup->topic_name  = topic_name;
    kafka_setup->loglevel    = loglevel;
    kafka_setup->partition   = partition;
    kafka_setup->tried       = 0;
    SCLogInfo("eve kafka ouput: config setup done!");
}

/**
 * \brief SCConfLogReopenKafka() Caller wants to re-open kafka output due to some error or
                                 disconnection
 * \param lf_ctx the logfile context to re-open
 *
 * \retval -1 if open failed or too soon
 *          0 if success
 */
static int SCConfLogReopenKafka(LogFileCtx *log_ctx)
{
    rd_kafka_t *rk     = NULL;
    char errstr[2048]  = {0};
    rd_kafka_conf_t *conf = log_ctx->kafka_setup.conf;
    
    /* only try to reconnect once per second */
    if (log_ctx->kafka_setup.tried >= time(NULL)) {
        return -1;
    }
    if (log_ctx->kafka != NULL) {
	conf = rd_kafka_conf_dup(log_ctx->kafka_setup.conf);
    }
    /* Create Kafka handle */
    if (!(rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr)))) {
        SCLogError(SC_ERR_SOCKET, "Failed to create kafka handler: %s", errstr);
	rd_kafka_conf_destroy(conf);
        log_ctx->kafka = NULL;
        return -1;
    }
    rd_kafka_set_log_level(rk, log_ctx->kafka_setup.loglevel);
    //TODO: for some rdkafka versions a double free happens 
    //rd_kafka_conf_destroy(log_ctx->kafka_setup.conf);
    rd_kafka_destroy(log_ctx->kafka);
    log_ctx->kafka_setup.conf  = conf;
    log_ctx->kafka             = rk;
    log_ctx->kafka_setup.tried = 0;
    return 0;
}

/**
 * \brief LogFileWriteKafka() - writes an event to the kafka ouput. Produces a message to broker.
 * \param lf_ctx the log file context
 * \param string the message to write
 * \param string_len the lenght of the message to write
 *
 * \retval -1 if open failed or too soon
 *          0 if success
 */
int LogFileWriteKafka(LogFileCtx *log_ctx, const char *string, size_t string_len)
{
    rd_kafka_t *rk = log_ctx->kafka;
    int err = 0;

    if (rk == NULL) {
        SCConfLogReopenKafka(log_ctx);
        if (rk == NULL) {
            SCLogInfo("Connection to kafka brokers not possible.");
            return -1;
        } else {
            SCLogInfo("Reconnected to Kafka brokers.");
        }
    }

    /* Send/Produce message. */
    if ((err =  rd_kafka_produce(
                    log_ctx->kafka_setup.topic,
                    log_ctx->kafka_setup.partition,
                    RD_KAFKA_MSG_F_COPY,
                    /* Payload and length */
                    (char *)string, string_len,
                    /* Optional key and its length */
                    NULL, 0,
                    /* Message opaque, provided in
                     * delivery report callback as
                     * msg_opaque. */
                    NULL)) == -1) {

        const char *errstr = rd_kafka_err2str(rd_kafka_errno2err(err));
        SCLogError(SC_ERR_SOCKET,
                "Error - %d  - %% Failed to produce to topic %s "
                "partition %i: %s\n",
                err,
                rd_kafka_topic_name(log_ctx->kafka_setup.topic),
                log_ctx->kafka_setup.partition,
                errstr);

        /* FIXME we may lose this message */
        //rd_kafka_destroy(log_ctx->kafka);
        //log_ctx->kafka = NULL;
        SCConfLogReopenKafka(log_ctx);


#ifdef DEBUG
    } else {
        SCLogDebug("KAFKA MSG:[%s] ERR:[%d] QUEUE:[%d]", string, err, rd_kafka_outq_len(rk));
#endif //DEBUG
    }

    return 0;
}

#endif //#ifdef HAVE_LIBRDKAFKA