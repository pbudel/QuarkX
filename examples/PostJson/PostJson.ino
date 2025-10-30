#include <Arduino.h>
#include <LittleFS.h>
#include <WiFi.h>

#include <QuarkX.h>

#ifndef QUARKX_WIFI_SSID
#define QUARKX_WIFI_SSID "YOUR_WIFI_SSID"
#endif

#ifndef QUARKX_WIFI_PASSWORD
#define QUARKX_WIFI_PASSWORD "YOUR_WIFI_PASSWORD"
#endif

/*
 * curl -v -X POST http://<ip>/echo \
 *      -H "Content-Type: application/json" \
 *      -d '{"message":"Hello from QuarkX"}'
 */

static quarkx::Server server(80, false);

void setup() {
  Serial.begin(115200);
  Serial.println();

  WiFi.mode(WIFI_STA);
  WiFi.begin(QUARKX_WIFI_SSID, QUARKX_WIFI_PASSWORD);
  Serial.print(F("Connecting to Wi-Fi"));
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print('.');
  }
  Serial.printf("\nIP: %s\n", WiFi.localIP().toString().c_str());

  server.on("/echo", [](Stream &out, const String &method, const String &path) {
    Serial.printf("Handling %s %s\n", method.c_str(), path.c_str());

    uint8_t buffer[QUARKX_MAX_BODY + 1];
    const size_t n = quarkx::read_body(buffer, QUARKX_MAX_BODY);
    buffer[n] = '\0';

    quarkx::send_basic_response(out, 200, F("OK"),
                                n ? String((const char *)buffer)
                                  : String(F("{}")));
  });

  server.onNotFound([](Stream &out, const String &, const String &) {
    quarkx::send_basic_response(out, 404, F("Not Found"),
                                F("Endpoint not available"));
  });

  server.begin();
}

void loop() {
  server.poll();
  delay(1);
}
