/*
 * central_logger.c
 *
 * COMM_MODE 0 = ADV scanner, 1 = CONN subscriber  (default: CONN)
 * PHY_MODE  2 or 8                                 (default: 8)
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>

LOG_MODULE_REGISTER(central_logger, LOG_LEVEL_INF);

/* ── compile-time config ───────────────────────────────────── */
#define COMM_MODE_ADV  0
#define COMM_MODE_CONN 1

#ifndef COMM_MODE
#define COMM_MODE COMM_MODE_CONN
#endif

#ifndef PHY_MODE
#define PHY_MODE 8
#endif

#ifndef ADV_BURST_COUNT
#define ADV_BURST_COUNT 3
#endif

#define SCAN_INTERVAL 0x0060
#define SCAN_WINDOW   0x0030
#define EVT_SYNC      0
#define EVT_DATA      1

/* ── event packet ──────────────────────────────────────────── */
struct __packed event_packet {
    uint8_t  device_id;
    uint8_t  mode;
    uint8_t  phy_mode;
    uint8_t  event_type;
    uint8_t  adv_burst_idx;
    uint32_t event_id;
    uint32_t tx_ts_us;
    uint32_t inter_event_us;
    uint16_t batt_mv;
};

/* ── clock offset ──────────────────────────────────────────── */
static int32_t clock_offset_us    = 0;
static bool    clock_offset_valid = false;

/* ── timing helpers ────────────────────────────────────────── */
static uint32_t now_us_u32(void)
{
    return k_ticks_to_us_floor32(k_uptime_ticks());
}

static int64_t now_ms(void)
{
    return k_uptime_get();
}

/* ── duplicate tracker (ADV mode) ──────────────────────────── */
#define DUP_TRACK_SIZE 64
static struct { uint32_t event_id; uint8_t count; } dup_table[DUP_TRACK_SIZE];
static uint8_t dup_idx = 0;

static uint8_t dup_track_increment(uint32_t eid)
{
    for (int i = 0; i < DUP_TRACK_SIZE; i++) {
        if (dup_table[i].event_id == eid && dup_table[i].count > 0) {
            dup_table[i].count++;
            return dup_table[i].count;
        }
    }
    dup_table[dup_idx].event_id = eid;
    dup_table[dup_idx].count    = 1;
    dup_idx = (dup_idx + 1) % DUP_TRACK_SIZE;
    return 1;
}

/* ── connection timing ─────────────────────────────────────── */
static int64_t scan_start_ms   = 0;
static int64_t disconnected_ms = 0;
static int32_t conn_setup_ms   = -1;
static int32_t reconnect_ms    = -1;
static bool    first_conn      = true;

/* ── CSV row logger ────────────────────────────────────────── */
static void log_csv_row(const char *status, int8_t rssi,
                        const struct event_packet *pkt, uint8_t copy_count)
{
    uint32_t rx_ts_us    = now_us_u32();
    uint32_t tx_ts_us    = sys_le32_to_cpu(pkt->tx_ts_us);
    uint32_t event_id    = sys_le32_to_cpu(pkt->event_id);
    uint32_t inter_ev_us = sys_le32_to_cpu(pkt->inter_event_us);
    uint16_t batt_mv     = sys_le16_to_cpu(pkt->batt_mv);
    int32_t  naive       = (int32_t)(rx_ts_us - tx_ts_us);
    int32_t  corrected   = clock_offset_valid ? (naive - clock_offset_us) : -1;

    printk("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%d,%d,%d,%u,%u,%d,%s,%d,%d\n",
           pkt->mode, pkt->phy_mode, pkt->device_id,
           event_id, pkt->event_type,
           pkt->adv_burst_idx, copy_count, (uint32_t)ADV_BURST_COUNT,
           tx_ts_us, rx_ts_us, corrected, naive, clock_offset_us,
           inter_ev_us, batt_mv, rssi,
           status, conn_setup_ms, reconnect_ms);
}

/* ── sync packet handler ───────────────────────────────────── */
static void handle_sync_packet(const struct event_packet *pkt, int8_t rssi)
{
    uint32_t rx_ts_us = now_us_u32();
    uint32_t tx_ts_us = sys_le32_to_cpu(pkt->tx_ts_us);
    clock_offset_us    = (int32_t)(rx_ts_us - tx_ts_us);
    clock_offset_valid = true;
    LOG_INF("SYNC received: clock_offset=%d us", clock_offset_us);
    log_csv_row("sync", rssi, pkt, 1);
}

/* =========================================================
 * ADV MODE
 * ========================================================= */
#if COMM_MODE == COMM_MODE_ADV

struct adv_parse_ctx { int8_t rssi; };

static bool ad_parse_cb(struct bt_data *data, void *user_data)
{
    struct adv_parse_ctx *ctx = user_data;
    if (data->type != BT_DATA_MANUFACTURER_DATA) { return true; }
    if (data->data_len != sizeof(struct event_packet)) { return true; }
    const struct event_packet *pkt = (const struct event_packet *)data->data;
    if (pkt->event_type == EVT_SYNC) { handle_sync_packet(pkt, ctx->rssi); return false; }
    uint32_t eid = sys_le32_to_cpu(pkt->event_id);
    log_csv_row("rx_adv", ctx->rssi, pkt, dup_track_increment(eid));
    return false;
}

static void scan_recv_cb(const struct bt_le_scan_recv_info *info,
                         struct net_buf_simple *buf)
{
    struct adv_parse_ctx ctx = { .rssi = info->rssi };
    bt_data_parse(buf, ad_parse_cb, &ctx);
}

static struct bt_le_scan_cb scan_callbacks = { .recv = scan_recv_cb };

static int start_scan(void)
{
    struct bt_le_scan_param p = {
        .type = BT_LE_SCAN_TYPE_PASSIVE, .options = BT_LE_SCAN_OPT_CODED,
        .interval = SCAN_INTERVAL, .window = SCAN_WINDOW,
    };
    bt_le_scan_cb_register(&scan_callbacks);
    scan_start_ms = now_ms();
    int err = bt_le_scan_start(&p, NULL);
    if (err) { LOG_ERR("bt_le_scan_start failed (%d)", err); return err; }
    LOG_INF("Scanning ADV mode (PHY S=%d)", PHY_MODE);
    return 0;
}

#endif /* COMM_MODE_ADV */

/* =========================================================
 * CONN MODE
 * ========================================================= */
#if COMM_MODE == COMM_MODE_CONN

#define BT_UUID_PP_SERVICE_VAL \
    BT_UUID_128_ENCODE(0x12345678,0x1234,0x5678,0x9abc,0xdef012340000)
#define BT_UUID_PP_EVENT_VAL \
    BT_UUID_128_ENCODE(0x12345678,0x1234,0x5678,0x9abc,0xdef012340001)

static struct bt_uuid_128 pp_service_uuid = BT_UUID_INIT_128(BT_UUID_PP_SERVICE_VAL);
static struct bt_uuid_128 pp_event_uuid   = BT_UUID_INIT_128(BT_UUID_PP_EVENT_VAL);

static struct bt_conn *default_conn;
static bool connecting;

static struct bt_gatt_discover_params  discover_params;
static struct bt_gatt_subscribe_params subscribe_params;
static uint16_t event_value_handle;
static uint16_t service_end_handle;

static uint8_t notify_func(struct bt_conn *conn,
                           struct bt_gatt_subscribe_params *params,
                           const void *data, uint16_t length)
{
    ARG_UNUSED(conn);
    if (!data) {
        LOG_INF("Subscription ended");
        params->value_handle = 0U;
        return BT_GATT_ITER_STOP;
    }
    if (length < sizeof(struct event_packet)) {
        LOG_WRN("Packet too short: %u < %u", length, sizeof(struct event_packet));
        return BT_GATT_ITER_CONTINUE;
    }
    const struct event_packet *pkt = data;
    if (pkt->event_type == EVT_SYNC) {
        handle_sync_packet(pkt, 0);
        return BT_GATT_ITER_CONTINUE;
    }
    log_csv_row("rx_ntf", 0, pkt, 1);
    return BT_GATT_ITER_CONTINUE;
}

static uint8_t discover_func(struct bt_conn *conn,
                             const struct bt_gatt_attr *attr,
                             struct bt_gatt_discover_params *params)
{
    int err;
    if (!attr) {
        LOG_WRN("Discovery complete without result");
        memset(params, 0, sizeof(*params));
        return BT_GATT_ITER_STOP;
    }

    if (params->type == BT_GATT_DISCOVER_PRIMARY) {
        const struct bt_gatt_service_val *svc = attr->user_data;
        service_end_handle = svc->end_handle;
        LOG_INF("Service found: start=%u end=%u", attr->handle + 1, svc->end_handle);
        discover_params.uuid         = &pp_event_uuid.uuid;
        discover_params.start_handle = attr->handle + 1;
        discover_params.end_handle   = svc->end_handle;
        discover_params.type         = BT_GATT_DISCOVER_CHARACTERISTIC;
        err = bt_gatt_discover(conn, &discover_params);
        if (err) { LOG_ERR("Char discovery failed (%d)", err); }
        return BT_GATT_ITER_STOP;
    }

    if (params->type == BT_GATT_DISCOVER_CHARACTERISTIC) {
        const struct bt_gatt_chrc *chrc = attr->user_data;
        event_value_handle = chrc->value_handle;
        LOG_INF("Characteristic found: value_handle=%u", event_value_handle);
        discover_params.uuid         = BT_UUID_GATT_CCC;
        discover_params.start_handle = attr->handle + 2;
        discover_params.end_handle   = service_end_handle;
        discover_params.type         = BT_GATT_DISCOVER_DESCRIPTOR;
        err = bt_gatt_discover(conn, &discover_params);
        if (err) { LOG_ERR("CCC discovery failed (%d)", err); }
        return BT_GATT_ITER_STOP;
    }

    if (params->type == BT_GATT_DISCOVER_DESCRIPTOR) {
        LOG_INF("CCC descriptor found: handle=%u", attr->handle);
        subscribe_params.notify       = notify_func;
        subscribe_params.value        = BT_GATT_CCC_NOTIFY;
        subscribe_params.value_handle = event_value_handle;
        subscribe_params.ccc_handle   = attr->handle;
        err = bt_gatt_subscribe(conn, &subscribe_params);
        if (err) { LOG_ERR("Subscribe failed (%d)", err); }
        else     { LOG_INF("Subscribed — press button on peripheral"); }
        return BT_GATT_ITER_STOP;
    }

    return BT_GATT_ITER_STOP;
}

static void start_service_discovery(struct bt_conn *conn)
{
    memset(&discover_params, 0, sizeof(discover_params));
    discover_params.uuid         = &pp_service_uuid.uuid;
    discover_params.func         = discover_func;
    discover_params.start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
    discover_params.end_handle   = BT_ATT_LAST_ATTRIBUTE_HANDLE;
    discover_params.type         = BT_GATT_DISCOVER_PRIMARY;
    int err = bt_gatt_discover(conn, &discover_params);
    if (err) { LOG_ERR("Service discovery failed (%d)", err); }
    else      { LOG_INF("Service discovery started..."); }
}

static void connected_cb(struct bt_conn *conn, uint8_t err)
{
    if (err) { LOG_ERR("Connection failed (err 0x%02x)", err); connecting = false; return; }
    int64_t t = now_ms();
    if (first_conn) {
        conn_setup_ms = (int32_t)(t - scan_start_ms);
        first_conn    = false;
        LOG_INF("Connected! Setup: %d ms", conn_setup_ms);
    } else {
        reconnect_ms = (int32_t)(t - disconnected_ms);
        LOG_INF("Reconnected! Time: %d ms", reconnect_ms);
    }
    printk("CONN_SETUP,setup_ms=%d,reconnect_ms=%d\n", conn_setup_ms, reconnect_ms);
    default_conn = bt_conn_ref(conn);
    connecting   = false;
    k_msleep(1000);
    start_service_discovery(conn);
}

static void disconnected_cb(struct bt_conn *conn, uint8_t reason)
{
    ARG_UNUSED(conn);
    LOG_INF("Disconnected (reason 0x%02x)", reason);
    disconnected_ms = now_ms();
    if (default_conn) { bt_conn_unref(default_conn); default_conn = NULL; }
    connecting = false;
    struct bt_le_scan_param p = {
        .type = BT_LE_SCAN_TYPE_PASSIVE, .options = BT_LE_SCAN_OPT_CODED,
        .interval = SCAN_INTERVAL, .window = SCAN_WINDOW,
    };
    int e = bt_le_scan_start(&p, NULL);
    if (e) { LOG_ERR("Restart scan failed (%d)", e); }
    else   { LOG_INF("Scanning for reconnection..."); }
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
    .connected    = connected_cb,
    .disconnected = disconnected_cb,
};

static void scan_recv_connect_cb(const struct bt_le_scan_recv_info *info,
                                 struct net_buf_simple *buf)
{
    ARG_UNUSED(buf);
    int err;
    if (default_conn || connecting) { return; }
    if (!(info->adv_props & BT_GAP_ADV_PROP_CONNECTABLE)) { return; }
    if (info->primary_phy   != BT_GAP_LE_PHY_CODED &&
        info->secondary_phy != BT_GAP_LE_PHY_CODED) { return; }

    LOG_INF("Found coded PHY device (RSSI %d) — connecting...", info->rssi);
    connecting = true;

    err = bt_le_scan_stop();
    if (err) { LOG_ERR("Scan stop failed (%d)", err); connecting = false; return; }

    struct bt_conn_le_create_param create_param =
        BT_CONN_LE_CREATE_PARAM_INIT(
            BT_CONN_LE_OPT_CODED | BT_CONN_LE_OPT_NO_1M,
            BT_GAP_SCAN_FAST_INTERVAL,
            BT_GAP_SCAN_FAST_WINDOW);

    err = bt_conn_le_create(info->addr, &create_param,
                            BT_LE_CONN_PARAM_DEFAULT, &default_conn);
    if (err) {
        LOG_ERR("Create connection failed (%d)", err);
        connecting = false;
        struct bt_le_scan_param sp = {
            .type = BT_LE_SCAN_TYPE_PASSIVE, .options = BT_LE_SCAN_OPT_CODED,
            .interval = SCAN_INTERVAL, .window = SCAN_WINDOW,
        };
        bt_le_scan_start(&sp, NULL);
    }
}

static struct bt_le_scan_cb scan_callbacks = { .recv = scan_recv_connect_cb };

static int start_scan(void)
{
    struct bt_le_scan_param p = {
        .type = BT_LE_SCAN_TYPE_PASSIVE, .options = BT_LE_SCAN_OPT_CODED,
        .interval = SCAN_INTERVAL, .window = SCAN_WINDOW,
    };
    bt_le_scan_cb_register(&scan_callbacks);
    scan_start_ms = now_ms();
    int err = bt_le_scan_start(&p, NULL);
    if (err) { LOG_ERR("bt_le_scan_start failed (%d)", err); return err; }
    LOG_INF("Scanning for coded PHY device (CONN mode, PHY S=%d)", PHY_MODE);
    return 0;
}

#endif /* COMM_MODE_CONN */

/* =========================================================
 * MAIN
 * ========================================================= */
int main(void)
{
    int err;

    printk("mode,phy_mode,device_id,event_id,event_type,"
           "adv_burst_idx,adv_copies_rxd,adv_burst_expected,"
           "tx_ts_us,rx_ts_us,"
           "corrected_latency_us,naive_latency_us,clock_offset_us,"
           "inter_event_us,batt_mv,rssi,status,"
           "conn_setup_ms,reconnect_ms\n");

    err = bt_enable(NULL);
    if (err) { LOG_ERR("bt_enable failed (%d)", err); return err; }

    LOG_INF("Bluetooth initialized (central, PHY S=%d)", PHY_MODE);

    err = start_scan();
    if (err) { return err; }

    while (1) { k_sleep(K_SECONDS(1)); }

    return 0;
}