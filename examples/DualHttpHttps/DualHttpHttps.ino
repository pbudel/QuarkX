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

static quarkx::Server httpServer(80, false);
static quarkx::Server httpsServer(443, true);
static std::vector<uint8_t> cert_bin;
static std::vector<uint8_t> key_bin;

static bool loadFile(const char* path, std::vector<uint8_t>& out) {
  File f = LittleFS.open(path, "r");
  if (!f) {
    Serial.printf("Failed to open %s\n", path);
    return false;
  }
  out.resize(f.size());
  if (!out.empty()) {
    f.read(out.data(), out.size());
  }
  return true;
}

static void registerRoutes(quarkx::Server& srv) {
  srv.on("/", [](Stream& out, const String&, const String&) {
    quarkx::send_basic_response(out, 200, F("OK"), F("Hello from QuarkX"));
  });

  srv.on("/echo", [](Stream& out, const String& method, const String& path) {
    Serial.printf("Handling %s %s\n", method.c_str(), path.c_str());
    uint8_t buf[QUARKX_MAX_BODY + 1];
    const size_t n = quarkx::read_body(buf, QUARKX_MAX_BODY);
    buf[n] = '\0';
    quarkx::send_basic_response(out, 200, F("OK"),
                                n ? String((const char*)buf)
                                  : String(F("No body")));
  });
}

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

  if (!LittleFS.begin()) {
    Serial.println(F("LittleFS mount failed, formatting..."));
    if (!LittleFS.begin(true)) {
      Serial.println(F("LittleFS unavailable"));
    }
  }

  if (loadFile("/cert.der", cert_bin) && loadFile("/key.der", key_bin)) {
    const quarkx::TlsCreds creds{cert_bin.data(), cert_bin.size(), false,
                                 key_bin.data(), key_bin.size(), false};
    httpsServer.setTlsCredentials(creds);
    Serial.println(F("Loaded TLS credentials from LittleFS"));
  } else {
    Serial.println(F("Falling back to built-in test credentials"));
    const quarkx::TlsCreds default_creds{
        reinterpret_cast<const uint8_t*>(mbedtls_test_srv_crt),
        std::strlen(mbedtls_test_srv_crt) + 1, true,
        reinterpret_cast<const uint8_t*>(mbedtls_test_srv_key),
        std::strlen(mbedtls_test_srv_key) + 1, true};
    httpsServer.setTlsCredentials(default_creds);
  }

  registerRoutes(httpServer);
  registerRoutes(httpsServer);

  httpServer.begin();
  httpsServer.begin();

  Serial.println(F("HTTP ready on port 80"));
  Serial.println(F("HTTPS ready on port 443"));
}

void loop() {
  httpServer.poll();
  httpsServer.poll();
  delay(1);
}
