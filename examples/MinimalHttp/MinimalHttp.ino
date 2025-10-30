#include <Arduino.h>
#include <WiFi.h>

#include <QuarkX.h>

#ifndef QUARKX_WIFI_SSID
#define QUARKX_WIFI_SSID "YOUR_WIFI_SSID"
#endif

#ifndef QUARKX_WIFI_PASSWORD
#define QUARKX_WIFI_PASSWORD "YOUR_WIFI_PASSWORD"
#endif

static quarkx::Server server(80, false);

void setup() {
  Serial.begin(115200);
  Serial.println();

  WiFi.mode(WIFI_STA);
  WiFi.begin(QUARKX_WIFI_SSID, QUARKX_WIFI_PASSWORD);
  Serial.print(F("Connecting"));
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print('.');
  }
  Serial.printf("\nReady: %s\n", WiFi.localIP().toString().c_str());

  server.on("/", [](Stream &out, const String &, const String &) {
    quarkx::send_basic_response(out, 200, F("OK"), F("Hello"));
  });

  server.begin();
}

void loop() {
  server.poll();
  delay(1);
}
