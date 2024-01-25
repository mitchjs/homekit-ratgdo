// Copyright 2023 Brandon Matthews <thenewwazoo@optimaltour.us>
// Copyright (c) 2023-24 David Kerr, https://github.com/dkerr64
// All rights reserved. GPLv3 License

#define TAG ("WEB")

// Browser cache control, time in seconds after which browser cache invalid
// This is used for CSS, JS and IMAGE file types.  Set to 30 days !!
#define CACHE_CONTROL (60*60*24*30)

#include <string>
#include <tuple>
#include <unordered_map>

// define PROGMEM to blank, so it is a no-op in webcontent.h
#define PROGMEM
#include "www/build/webcontent.h"

#include "ratgdo.h"
#include "comms.h"

#include <esp_system.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <hap.h>

// Undocumented function to get HomeKit HAP server handle
extern "C" httpd_handle_t *hap_httpd_get_handle();

// tell httpd_resp_send to use strlen to calculate the response
// length, so I don't have to pass it myself.
#define HTTPD_RESP_USE_STRLEN -1

esp_err_t handle_reset(httpd_req_t *req);
esp_err_t handle_reboot(httpd_req_t *req);
esp_err_t handle_status(httpd_req_t *req);
esp_err_t handle_settings(httpd_req_t *req);
esp_err_t handle_everything(httpd_req_t *req);
esp_err_t handle_setgdo(httpd_req_t *req);
esp_err_t handle_logout(httpd_req_t *req);

static httpd_handle_t server = NULL;
httpd_config_t config = HTTPD_DEFAULT_CONFIG();

// Make device_name available
extern "C" char device_name[];
// Garage door status
extern struct GarageDoor garage_door;

// userid/password
const char www_username[] = "admin";
const char www_password[] = "password";
const char www_realm[] = "RATGDO Login Required";

// MD5 Hash of "user:realm:password"
char www_credentials[48] = "10d3c00fa1e09696601ef113b99f8a87";
const char credentials_file[] = "www_credentials";

esp_err_t
registerUri(const char *uri, const httpd_method_t method, esp_err_t (*handler)(httpd_req_t *))
{
    ESP_LOGI(TAG, "Register: %s", uri);
    const httpd_uri_t uriStruct = {
        .uri = uri,
        .method = method,
        .handler = handler,
        .user_ctx = NULL};
    return httpd_register_uri_handler(server, &uriStruct);
}

const std::unordered_multimap<std::string, std::pair<const httpd_method_t, esp_err_t (*)(httpd_req_t *)>> builtInUri = {
    {"/status.json", {HTTP_GET, handle_status}},
    {"/reset", {HTTP_POST, handle_reset}},
    {"/reboot", {HTTP_POST, handle_reboot}},
    {"/setgdo", {HTTP_POST, handle_setgdo}},
    {"/logout", {HTTP_GET, handle_logout}},
    {"/settings.html", {HTTP_GET, handle_settings}},
    {"/", {HTTP_GET, handle_everything}}};

void setup_web()
{
    ESP_LOGI(TAG, "Starting server");
    server = *hap_httpd_get_handle();
    if (!server)
    {
        ESP_LOGI(TAG, "Server handle = NULL");
        return;
    }

    ESP_LOGI(TAG, "Registering URI handlers");
    // Register URI handlers for URIs that have built-in handlers in this source file.
    esp_err_t err = 0;
    try
    {
        for (auto uri : builtInUri)
        {
            const httpd_method_t method = std::get<1>(uri).first;
            esp_err_t (*handler)(httpd_req_t *) = std::get<1>(uri).second;
            err = registerUri(uri.first.c_str(), method, handler);
            if (err)
                throw(err);
        }
        // Register URI handlers for URIs that are "external" files
        for (auto uri : webcontent)
        {
            // Only register those that are not duplicates of built-in handlers.
            if (builtInUri.find(uri.first) == builtInUri.end())
            {
                err = registerUri(uri.first.c_str(), HTTP_GET, handle_everything);
                if (err)
                    throw(err);
            }
        }
    }
    catch (int err)
    {
        ESP_LOGI(TAG, "Error starting HTTP server! %i : %s", err, esp_err_to_name(err));
    }

    return;
}

/********* handlers **********/
esp_err_t handle_reset(httpd_req_t *req)
{
    ESP_LOGI(TAG, "... reset requested");
    const char *resp = "<p>This device has been un-paired from HomeKit.</p><p><a href=\"/\">Back</a></p>";
    hap_reset_homekit_data();
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

esp_err_t handle_reboot(httpd_req_t *req)
{
    ESP_LOGI(TAG, "... reboot requested");
    const char *resp =
        "<head>"
        "<meta http-equiv=\"refresh\" content=\"15;url=/\" />"
        "</head>"
        "<body>"
        "<p>RATGDO restarting. Please wait. Reconnecting in 15 seconds...</p>"
        "<p><a href=\"/\">Back</a></p>"
        "</body>";
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    httpd_stop(server);
    hap_reboot_accessory();
    return ESP_OK;
}

esp_err_t load_page(httpd_req_t *req, const char *page)
{
    if (webcontent.count(page) > 0)
    {
        const unsigned char *data = std::get<0>(webcontent.at(page));
        const unsigned int length = std::get<1>(webcontent.at(page));
        const char *type = std::get<2>(webcontent.at(page));
        // Following for browser cache control...
        const char *crc32 = std::get<3>(webcontent.at(page)).c_str();
        bool cache = false;
        char cacheHdr[24] = "no-cache, no-store";
        char matchHdr[8] = "";

        if ((CACHE_CONTROL > 0) &&
            (!strcmp(type, "text/css") || !strcmp(type, "text/javascript") || strstr(type, "image")))
        {
            sprintf(cacheHdr, "max-age=%i", CACHE_CONTROL);
            cache = true;
        }

        httpd_resp_set_type(req, type);
        httpd_resp_set_hdr(req, "Cache-Control", cacheHdr);
        if (cache)
            httpd_resp_set_hdr(req, "ETag", crc32);

        httpd_req_get_hdr_value_str(req, "If-None-Match", matchHdr, 8);
        if (strcmp(crc32, matchHdr))
        {
            ESP_LOGI(TAG, "Sending gzip data for: %s (type %s, length %i)", page, type, length);
            httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
            httpd_resp_send(req, (const char *)data, length);
        }
        else
        {
            ESP_LOGI(TAG, "Sending 304 Not Modified for: %s (type %s)", page, type);
            httpd_resp_set_status(req, "304 Not Modified");
            httpd_resp_send(req, "", 0);
        }
    }
    else
    {
        ESP_LOGI(TAG, "Sending 404 not found for: %s", page);
        httpd_resp_send_404(req);
    }
    return ESP_OK;
}

esp_err_t handle_everything(httpd_req_t *req)
{

    if (!strcmp(req->uri, "/"))
        // convert / to /index.html
        return load_page(req, "/index.html");
    else
    {
        char url[20];
        strncpy(url,req->uri,20);
        if (char *p = strchr(url, (int)'?')) {
            *p = 0; //null terminate at the query string
        }
        return load_page(req, url);
    }
}

esp_err_t handle_status(httpd_req_t *req)
{
    bool all = true;
    char json[512] = ""; // Maximum length of JSON response

    // find query string and macro to test if arg is present
    char queryStr[100] = ""; // Maximum length of query string
    httpd_req_get_url_query_str(req, queryStr, 100);
    if (strlen(queryStr) > 0)
        all = false;
#define HAS_ARG(arg) strstr(queryStr, arg)
// Don't know how to retrieve these values yet...
#define upTime 0
#define paired false
#define accessoryID "unknown"
#define localIP "unknown"
#define subnetMask "unknown"
#define gatewayIP "unknown"
#define macAddress "unknown"
#define wifiSSID "unknown"

// Helper macros to add int, string or boolean to a json format string.
#define ADD_INT(s, k, v)                      \
    {                                         \
        strcat(s, "\"");                      \
        strcat(s, (k));                       \
        strcat(s, "\": ");                    \
        strcat(s, std::to_string(v).c_str()); \
        strcat(s, ",\n");                     \
    }
#define ADD_STR(s, k, v)     \
    {                        \
        strcat(s, "\"");     \
        strcat(s, (k));      \
        strcat(s, "\": \""); \
        strcat(s, (v));      \
        strcat(s, "\",\n");  \
    }
#define ADD_BOOL(s, k, v)                  \
    {                                      \
        strcat(s, "\"");                   \
        strcat(s, (k));                    \
        strcat(s, "\": ");                 \
        strcat(s, (v) ? "true" : "false"); \
        strcat(s, ",\n");                  \
    }

    // Build the JSON string
    strcat(json, "{\n");
    if (all || HAS_ARG("uptime"))
        ADD_INT(json, "upTime", upTime);
    if (all)
        ADD_STR(json, "deviceName", device_name);
    if (all)
        ADD_BOOL(json, "paired", paired);
    if (all)
        ADD_STR(json, "firmwareVersion", std::string(AUTO_VERSION).c_str());
    if (all)
        ADD_STR(json, "accessoryID", accessoryID);
    if (all)
        ADD_STR(json, "localIP", localIP);
    if (all)
        ADD_STR(json, "subnetMask", subnetMask);
    if (all)
        ADD_STR(json, "gatewayIP", gatewayIP);
    if (all)
        ADD_STR(json, "macAddress", macAddress);
    if (all)
        ADD_STR(json, "wifiSSID", wifiSSID);
    if (all || HAS_ARG("doorstate"))
    {
        switch (garage_door.current_state)
        {
        case 0:
            ADD_STR(json, "garageDoorState", "Open");
            break;
        case 1:
            ADD_STR(json, "garageDoorState", "Closed");
            break;
        case 2:
            ADD_STR(json, "garageDoorState", "Opening");
            break;
        case 3:
            ADD_STR(json, "garageDoorState", "Closing");
            break;
        case 4:
            ADD_STR(json, "garageDoorState", "Stopped");
            break;
        default:
            ADD_STR(json, "garageDoorState", "Unknown");
        }
    }
    if (all || HAS_ARG("lockstate"))
    {
        switch (garage_door.current_lock)
        {
        case 0:
            ADD_STR(json, "garageLockState", "Unsecured");
            break;
        case 1:
            ADD_STR(json, "garageLockState", "Secured");
            break;
        case 2:
            ADD_STR(json, "garageLockState", "Jammed");
            break;
        default:
            ADD_STR(json, "garageLockState", "Unknown");
        }
    }
    if (all || HAS_ARG("lighton"))
        ADD_BOOL(json, "garageLightOn", garage_door.light)
    if (all || HAS_ARG("motion"))
        ADD_BOOL(json, "garageMotion", garage_door.motion)
    if (all || HAS_ARG("obstruction"))
        ADD_BOOL(json, "garageObstructed", garage_door.obstructed)

    // remove the final comma/newline to ensure valid JSON syntax
    json[strlen(json) - 2] = 0;
    // Terminate json with close curly
    strcat(json, "\n}");
    // Only log if all requested (no arguments).
    // Avoids spaming console log if repeated requests for one value.
    if (all)
        ESP_LOGI(TAG, "Status requested:\n%s", json);
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

esp_err_t handle_settings(httpd_req_t *req)
{
    return load_page(req, "/settings.html");
}

esp_err_t handle_logout(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handle logout");
    return ESP_OK;
}

esp_err_t getPostedKeyValue(httpd_req_t *req, char *key, char *value)
{
    // Get the Content-Type to ensure that we have received multipart/form-data
    size_t len = httpd_req_get_hdr_value_len(req, "Content-Type");
    char *buf = (char *)malloc(len + 1);
    try
    {
        httpd_req_get_hdr_value_str(req, "Content-Type", buf, len + 1);
        if (strstr(buf, "multipart/form-data") == NULL)
            throw(404);
        free(buf); // release buffer allocated for content type

        // Read in the content of the multipart/form-data
        buf = (char *)malloc(req->content_len + 1);
        size_t off = 0;
        while (off < req->content_len)
        {
            /* Read data received in the request */
            int ret = httpd_req_recv(req, buf + off, req->content_len - off);
            if (ret <= 0)
            {
                if (ret == HTTPD_SOCK_ERR_TIMEOUT)
                {
                    ESP_LOGI(TAG, "Socket error: Timeout.");
                    httpd_resp_send_408(req);
                }
                free(buf);
                return ESP_FAIL;
            }
            off += ret;
        }
        buf[off] = '\0';
        // Find the content...
        // This code assumes only one value in the multipart/form-data
        char *p = strstr(buf, "Content-Disposition:");
        if (!p)
            throw(404);
        char *v = strstr(p, "\r\n\r\n") + 4; // find value at two newlines
        if (!v)
            throw(404);
        p = strstr(p, "name=\"") + 6; // find form name at name="
        if (!p)
            throw(404);
        *strstr(p, "\"") = 0;   // NULL terminate name string
        *strstr(v, "\r\n") = 0; // NULL terminate value string at newline
        strncpy(key, p, 20);
        strncpy(value, v, 48);
        free(buf);
        return ESP_OK;
    }
    catch (int err)
    {
        ESP_LOGI(TAG, "Error parsing data: [%s]", buf);
        free(buf);
        httpd_resp_send_404(req);
        return ESP_FAIL;
    }
}

esp_err_t handle_setgdo(httpd_req_t *req)
{
    char key[20] = "";
    char value[48] = "";
    ESP_LOGI(TAG, "In setGDO");
    getPostedKeyValue(req, key, value);
    ESP_LOGI(TAG, "Key: %s, Value: %s", key, value);
    if (strlen(key) == 0 || strlen(value) == 0)
    {
        httpd_resp_send_404(req);
        return ESP_FAIL;
    }

    if (!strcmp(key, "lighton"))
    {
        set_light(!strcmp(value, "1") ? true : false);
    }
    else if (!strcmp(key, "doorstate"))
    {
        if (!strcmp(value, "1"))
            open_door();
        else
            close_door();
    }
    else if (!strcmp(key, "lockstate"))
    {
        set_lock(!strcmp(value, "1") ? 1 : 0);
    }
    else if (!strcmp(key, "credentials"))
    {
    }
    else
    {
        httpd_resp_send_404(req);
    }
    ESP_LOGI(TAG, "SetGDO Complete");
    httpd_resp_send(req, "<p>Success.</p>", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}
