#include <esp_eth.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_netif.h>
#include <esp_netif_sntp.h>
#include <stdio.h>
#include <time.h>

#include "tox_main.h"

static const char *MAIN_TAG = "app_main";
static constexpr int NTP_TIMEOUT = 60;  // 1 minute

static esp_eth_handle_t eth_handle = nullptr;
static esp_netif_t *eth_netif = nullptr;

static void event_handler(
    void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (event_base == ETH_EVENT) {
        if (event_id == ETHERNET_EVENT_START) {
            return;
        }
        if (event_id == ETHERNET_EVENT_STOP) {
            return;
        }
    }
    if (event_base == IP_EVENT) {
        if (event_id == IP_EVENT_ETH_GOT_IP) {
            return;
        }
    }
}

static void register_ethernet(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_ETH();
    eth_netif = esp_netif_new(&cfg);

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    esp_eth_mac_t *mac = esp_eth_mac_new_openeth(&mac_config);

    esp_eth_phy_t *phy = esp_eth_phy_new_dp83848(&phy_config);

    esp_eth_config_t config = ETH_DEFAULT_CONFIG(mac, phy);
    ESP_ERROR_CHECK(esp_eth_driver_install(&config, &eth_handle));
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
    ESP_ERROR_CHECK(
        esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &event_handler, NULL));
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));
}

// Does all the esp32-specific init before running generic tox code.
extern "C" void app_main(void)
{
    register_ethernet();

    esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    ESP_ERROR_CHECK(esp_netif_sntp_init(&config));

    if (esp_netif_sntp_sync_wait(pdMS_TO_TICKS(NTP_TIMEOUT * 1000)) != ESP_OK) {
        ESP_LOGE(MAIN_TAG, "failed to update system time within %ds timeout", NTP_TIMEOUT);
        return;
    }

    ESP_LOGI(MAIN_TAG, "time is updated: %lld", time(nullptr));

    tox_main();
}
