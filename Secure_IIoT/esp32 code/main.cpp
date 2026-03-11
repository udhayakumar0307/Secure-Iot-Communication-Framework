/*
 * ESP32 IoT Environmental Monitor - SECURE EDITION
 * BMP280 (Temp/Pressure/Altitude) + MQ-2 Gas Sensor
 * Display  : SSD1306 OLED 128x64
 * Security : AES-256-CBC + SHA-256 + HMAC-SHA256
 * Ledger   : Consortium Blockchain
 * Transport: AWS IoT Core MQTT/TLS (mTLS)
 *
 * platformio.ini lib_deps:
 *   adafruit/Adafruit BMP280 Library @ ^2.6.8
 *   adafruit/Adafruit GFX Library    @ ^1.11.9
 *   adafruit/Adafruit SSD1306        @ ^2.5.10
 *   knolleary/PubSubClient           @ ^2.8
 *   bblanchon/ArduinoJson            @ ^6.21.4
 *
 * Wiring:
 *   BMP280  -> SDA=GPIO21, SCL=GPIO22, VCC=3.3V  [I2C 0x76]
 *   SSD1306 -> SDA=GPIO21, SCL=GPIO22, VCC=3.3V  [I2C 0x3C]
 *   MQ-2    -> AOUT=GPIO34,            VCC=5V (use VIN pin)
 *
 * Tips:
 *   BMP280 not found at 0x76? Change MY_BMP280_ADDR to 0x77
 *   Allow 2-3 min MQ-2 warm-up for stable readings
 */

#include <Arduino.h>
#include <Wire.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <PubSubClient.h>
#include <Adafruit_BMP280.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"

//  WiFi
const char* WIFI_SSID     = "";
const char* WIFI_PASSWORD = "";
const char* DEVICE_ID     = "";
const char* LOCATION_ID   = "1";

//  AWS IoT Core
const char* AWS_IOT_ENDPOINT = ".amazonaws.com";
const int   AWS_IOT_PORT     = 8883;
const char* TOPIC_PUBLISH_DATA   = "esp32/env/data";
const char* TOPIC_PUBLISH_STATUS = "esp32/env/status";
const char* TOPIC_SUBSCRIBE_CMD  = "esp32/env/commands";

//  AWS Certificates - paste your 3 files below

// AmazonRootCA1.pem
// ================= CERTIFICATES =================
static const char AWS_ROOT_CA[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----

-----END CERTIFICATE-----
)EOF";

static const char DEVICE_CERT[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----

-----END CERTIFICATE-----

)EOF";

static const char PRIVATE_KEY[] PROGMEM = R"EOF(
-----BEGIN RSA PRIVATE KEY-----

-----END RSA PRIVATE KEY-----
)EOF";

// ============================================================
//  Security Keys - must match your backend app.py exactly
// ============================================================
const uint8_t AES_KEY[32] = {
  0x2B,0x7E,0x15,0x16, 0x28,0xAE,0xD2,0xA6,
  0xAB,0xF7,0x15,0x88, 0x09,0xCF,0x4F,0x3C,
  0x76,0x2E,0x71,0x60, 0xF3,0x8B,0x4D,0xA5,
  0x6A,0x78,0x4D,0x90, 0x45,0x19,0x0C,0xFE
};
const uint8_t HMAC_KEY[32] = {
  0x60,0x3D,0xEB,0x10, 0x15,0xCA,0x71,0xBE,
  0x2B,0x73,0xAE,0xF0, 0x85,0x7D,0x77,0x81,
  0x1F,0x35,0x2C,0x07, 0x3B,0x61,0x08,0xD7,
  0x2D,0x98,0x10,0xA3, 0x09,0x14,0xDF,0xF4
};

// ============================================================
//  Hardware Config
//  MY_BMP280_ADDR: SDO->GND = 0x76 | SDO->VCC = 0x77
// ============================================================
#define MQ2_PIN         34
#define I2C_SDA         21
#define I2C_SCL         22
#define MY_BMP280_ADDR  0x76
#define OLED_ADDRESS    0x3C
#define SCREEN_WIDTH    128
#define SCREEN_HEIGHT    64
#define OLED_RESET       -1
#define SEA_LEVEL_HPA   1013.25f

// MQ-2 calibration
// In clean air after 3-min warm-up, read raw ADC and set MQ2_CLEAN_AIR_VAL
#define MQ2_CLEAN_AIR_VAL   400
#define MQ2_ALERT_THRESHOLD 2000

// Timing
#define SEND_INTERVAL_MS   5000
#define STATUS_INTERVAL_MS 30000
#define OLED_INTERVAL_MS    500
#define REPORT_INTERVAL_MS 5000

// ============================================================
//  Blockchain
// ============================================================
#define MAX_CHAIN_LENGTH 20
struct Block {
  uint32_t index;
  uint64_t timestamp;
  float    temperature;
  float    pressure;
  float    altitude;
  int      mq2Raw;
  int      mq2Percent;
  bool     mq2Alert;
  char     previousHash[65];
  char     blockHash[65];
  char     signature[65];
  bool     valid;
};
Block    blockchain[MAX_CHAIN_LENGTH];
uint32_t chainLength = 0;
uint32_t blockIndex  = 0;
char     lastBlockHash[65] =
  "0000000000000000000000000000000000000000000000000000000000000000";

// ============================================================
//  Globals
// ============================================================
Adafruit_BMP280  bmp;
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
WiFiClientSecure wifiClientSecure;
PubSubClient     mqttClient(wifiClientSecure);

bool  bmpFound      = false;
bool  oledFound     = false;
bool  wifiConnected = false;
bool  awsConnected  = false;
float temperature   = 0.0f;
float pressure      = 0.0f;
float altitude      = 0.0f;
int   mq2Raw        = 0;
int   mq2Percent    = 0;
bool  mq2Alert      = false;
bool  alertBlink    = false;

unsigned long lastSendTime   = 0;
unsigned long lastStatusTime = 0;
unsigned long lastReportTime = 0;
unsigned long lastOledUpdate = 0;

// ============================================================
//  Prototypes
// ============================================================
void connectWiFi();
void connectAWS();
void mqttCallback(char* topic, byte* payload, unsigned int length);
void publishEnvData();
void publishStatusHeartbeat();
void initBMP280();
void initOLED();
void scanI2C();
void readSensors();
void updateOLED();
void oledSplash();
void oledWifiStatus(bool connecting);
void oledAwsStatus(bool connecting);
void printBanner();
void bytesToHex(const uint8_t* bytes, size_t len, char* hexOut);
void computeSHA256(const uint8_t* data, size_t len, char* hexOut);
void computeHMAC_SHA256(const uint8_t* data, size_t len, char* hexOut);
bool encryptAES256CBC(const char* plaintext, char* b64Out, size_t b64OutLen);
void   computeBlockHash(Block& b, char* hashOut);
void   signBlock(Block& b);
Block  createBlock(float temp, float pres, float alt, int mq2r, int mq2p, bool mq2a);
bool   addBlock(float temp, float pres, float alt, int mq2r, int mq2p, bool mq2a);
bool   verifyChain();
String blockToJson(const Block& b);

// ============================================================
//  SETUP
// ============================================================
void setup() {
  Serial.begin(115200);
  delay(1000);
  printBanner();

  Wire.begin(I2C_SDA, I2C_SCL);
  Wire.setClock(400000);
  delay(100);
  Serial.println("[I2C]    OK - 400kHz");

  scanI2C();
  initOLED();
  oledSplash();
  initBMP280();

  pinMode(MQ2_PIN, INPUT);
  Serial.println("[SENSOR] MQ-2 ready on GPIO34");
  Serial.println("[SENSOR] Allow 2-3 min warm-up for accurate readings");

  addBlock(0.0f, 0.0f, 0.0f, 0, 0, false);
  Serial.println("[CHAIN]  Genesis block created");

  oledWifiStatus(true);
  connectWiFi();
  oledWifiStatus(false);

  if (wifiConnected) {
    oledAwsStatus(true);
    connectAWS();
    oledAwsStatus(false);
  }

  Serial.println("[INIT]   All systems ready!");
}

// ============================================================
//  LOOP
// ============================================================
void loop() {
  unsigned long now = millis();

  if (awsConnected) {
    if (!mqttClient.connected()) {
      Serial.println("[MQTT]   Disconnected - reconnecting...");
      awsConnected = false;
      connectAWS();
    } else {
      mqttClient.loop();
    }
  }

  readSensors();
  alertBlink = (now % 1000) < 500;

  if (WiFi.status() != WL_CONNECTED) {
    if (wifiConnected) {
      wifiConnected = false;
      awsConnected  = false;
      Serial.println("[WIFI]   Lost - reconnecting...");
    }
    connectWiFi();
    if (wifiConnected && !awsConnected) connectAWS();
  }

  if (now - lastSendTime >= SEND_INTERVAL_MS) {
    lastSendTime = now;
    addBlock(temperature, pressure, altitude, mq2Raw, mq2Percent, mq2Alert);
    if (awsConnected) publishEnvData();
    else Serial.println("[ERROR]  AWS not connected, skipping publish");
  }

  if (awsConnected && (now - lastStatusTime >= STATUS_INTERVAL_MS)) {
    lastStatusTime = now;
    publishStatusHeartbeat();
  }

  if (oledFound && (now - lastOledUpdate >= OLED_INTERVAL_MS)) {
    lastOledUpdate = now;
    updateOLED();
  }

  if (now - lastReportTime >= REPORT_INTERVAL_MS) {
    lastReportTime = now;
    Serial.println("--------------------------------------------------");
    Serial.printf("[READING] Temp   : %.2f C\n",   temperature);
    Serial.printf("[READING] Pres   : %.2f hPa\n", pressure);
    Serial.printf("[READING] Alt    : %.2f m\n",   altitude);
    Serial.printf("[READING] MQ-2   : raw=%4d  %3d%%  %s\n",
                  mq2Raw, mq2Percent, mq2Alert ? "!! ALERT" : "OK");
    Serial.printf("[CHAIN]   Blocks : %u  Valid: %s\n",
                  blockIndex, verifyChain() ? "YES" : "TAMPERED");
    Serial.printf("[MQTT]    AWS    : %s\n", awsConnected ? "Connected" : "Offline");
    if (!bmpFound) Serial.println("[WARN]    BMP280 not found on I2C!");
    Serial.println("--------------------------------------------------");
  }

  delay(10);
}

// ============================================================
//  Read Sensors
// ============================================================
void readSensors() {
  if (bmpFound) {
    temperature = bmp.readTemperature();
    pressure    = bmp.readPressure() / 100.0f;
    altitude    = bmp.readAltitude(SEA_LEVEL_HPA);
  }
  mq2Raw     = analogRead(MQ2_PIN);
  mq2Percent = (int)map(mq2Raw, MQ2_CLEAN_AIR_VAL, 4095, 0, 100);
  mq2Percent = constrain(mq2Percent, 0, 100);
  mq2Alert   = (mq2Raw > MQ2_ALERT_THRESHOLD);
}

// ============================================================
//  Connect WiFi
// ============================================================
void connectWiFi() {
  Serial.printf("[WIFI]   Connecting to %s\n", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 40) {
    delay(500);
    Serial.print(".");
    if (++attempts % 20 == 0) Serial.println();
  }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    wifiConnected = true;
    Serial.printf("[WIFI]   Connected! IP:%s RSSI:%d dBm\n",
                  WiFi.localIP().toString().c_str(), WiFi.RSSI());
  } else {
    wifiConnected = false;
    Serial.println("[WIFI]   FAILED - will retry");
  }
}

// ============================================================
//  Connect AWS IoT Core
// ============================================================
void connectAWS() {
  Serial.printf("[AWS]    Connecting to %s:%d\n", AWS_IOT_ENDPOINT, AWS_IOT_PORT);
 wifiClientSecure.setCACert(AWS_ROOT_CA);
wifiClientSecure.setCertificate(DEVICE_CERT);
wifiClientSecure.setPrivateKey(PRIVATE_KEY);
  mqttClient.setServer(AWS_IOT_ENDPOINT, AWS_IOT_PORT);
  mqttClient.setCallback(mqttCallback);
  mqttClient.setBufferSize(2048);
  mqttClient.setKeepAlive(60);
  for (int i = 1; i <= 5; i++) {
    Serial.printf("[AWS]    Attempt %d/5 ClientID:%s\n", i, DEVICE_ID);
    if (mqttClient.connect(DEVICE_ID)) {
      awsConnected = true;
      mqttClient.subscribe(TOPIC_SUBSCRIBE_CMD);
      Serial.println("[AWS]    Connected!");
      Serial.printf("[AWS]    Sub: %s\n", TOPIC_SUBSCRIBE_CMD);
      Serial.printf("[AWS]    Pub: %s\n", TOPIC_PUBLISH_DATA);
      Serial.println("[AWS]    TLS mTLS | AES-256-CBC | HMAC-SHA256 | Blockchain");
      return;
    }
    Serial.printf("[AWS]    Failed state=%d, retry in 3s\n", mqttClient.state());
    delay(3000);
  }
  Serial.println("[AWS]    Could not connect. Check endpoint/certs/policy.");
}

// ============================================================
//  MQTT Callback
// ============================================================
void mqttCallback(char* topic, byte* payload, unsigned int length) {
  Serial.printf("[MQTT]   Msg [%s] %u bytes\n", topic, length);
  char msg[256] = {0};
  memcpy(msg, payload, min((unsigned int)255, length));
  Serial.printf("[MQTT]   %s\n", msg);
  StaticJsonDocument<256> doc;
  if (deserializeJson(doc, msg) == DeserializationError::Ok) {
    const char* cmd = doc["command"] | "";
    if (strcmp(cmd, "reset_chain") == 0) {
      chainLength = 0; blockIndex = 0;
      strcpy(lastBlockHash,
        "0000000000000000000000000000000000000000000000000000000000000000");
      addBlock(0.0f, 0.0f, 0.0f, 0, 0, false);
      Serial.println("[CMD]    Chain reset");
    } else if (strcmp(cmd, "status") == 0) {
      publishStatusHeartbeat();
    } else if (strcmp(cmd, "read_now") == 0) {
      readSensors(); publishEnvData();
      Serial.println("[CMD]    Immediate read published");
    }
  }
}

// ============================================================
//  Publish Environmental Data (encrypted + signed + blockchain)
// ============================================================
void publishEnvData() {
  Serial.printf("[MQTT]   Publishing -> %s\n", TOPIC_PUBLISH_DATA);

  StaticJsonDocument<300> rawDoc;
  rawDoc["device_id"]     = DEVICE_ID;
  rawDoc["location_id"]   = LOCATION_ID;
  rawDoc["temperature"]   = temperature;
  rawDoc["pressure"]      = pressure;
  rawDoc["altitude"]      = altitude;
  rawDoc["mq2_raw"]       = mq2Raw;
  rawDoc["mq2_percent"]   = mq2Percent;
  rawDoc["mq2_alert"]     = mq2Alert;
  rawDoc["device_status"] = "ONLINE";
  rawDoc["block_index"]   = blockIndex - 1;
  String rawPayload;
  serializeJson(rawDoc, rawPayload);

  char encB64[600] = {0};
  bool encOk = encryptAES256CBC(rawPayload.c_str(), encB64, sizeof(encB64));
  Serial.printf("[MQTT]   AES-256 : %s\n", encOk ? "OK" : "FAILED");

  char payloadHash[65];
  computeSHA256((uint8_t*)rawPayload.c_str(), rawPayload.length(), payloadHash);
  Serial.printf("[MQTT]   SHA-256 : %.24s...\n", payloadHash);

  char sig[65];
  computeHMAC_SHA256((uint8_t*)payloadHash, strlen(payloadHash), sig);
  Serial.printf("[MQTT]   HMAC    : %.24s...\n", sig);

  String blockJson = blockToJson(blockchain[(blockIndex - 1) % MAX_CHAIN_LENGTH]);
  StaticJsonDocument<512> blkDoc;
  deserializeJson(blkDoc, blockJson);

  StaticJsonDocument<1200> out;
  out["device_id"]      = DEVICE_ID;
  out["location_id"]    = LOCATION_ID;
  out["encrypted_data"] = encOk ? encB64 : rawPayload.c_str();
  out["payload_hash"]   = payloadHash;
  out["signature"]      = sig;
  out["encrypted"]      = encOk;
  out["algorithm"]      = "AES-256-CBC + HMAC-SHA256";
  out["chain_valid"]    = verifyChain();
  out["chain_length"]   = blockIndex;
  JsonObject blk      = out.createNestedObject("blockchain_block");
  blk["index"]        = blkDoc["index"];
  blk["blockHash"]    = blkDoc["blockHash"];
  blk["previousHash"] = blkDoc["previousHash"];
  blk["signature"]    = blkDoc["signature"];
  blk["timestamp"]    = blkDoc["timestamp"];
  blk["node_id"]      = DEVICE_ID;
  out["temperature"]   = temperature;
  out["pressure"]      = pressure;
  out["altitude"]      = altitude;
  out["mq2_raw"]       = mq2Raw;
  out["mq2_percent"]   = mq2Percent;
  out["mq2_alert"]     = mq2Alert;
  out["device_status"] = "ONLINE";
  out["transport"]     = "MQTT";
  out["timestamp"]     = (unsigned long)millis();

  String finalPayload;
  serializeJson(out, finalPayload);
  Serial.printf("[MQTT]   Block #%u | Chain:%s | %u bytes\n",
                blockIndex-1, verifyChain()?"Valid":"TAMPERED", finalPayload.length());

  bool ok = mqttClient.publish(
    TOPIC_PUBLISH_DATA, (const uint8_t*)finalPayload.c_str(),
    finalPayload.length(), false);
  Serial.println(ok ? "[MQTT]   Published OK" : "[MQTT]   Publish FAILED");
  if (!ok) awsConnected = false;
}

// ============================================================
//  Publish Heartbeat
// ============================================================
void publishStatusHeartbeat() {
  StaticJsonDocument<256> doc;
  doc["device_id"]    = DEVICE_ID;
  doc["location_id"]  = LOCATION_ID;
  doc["status"]       = "ONLINE";
  doc["uptime_ms"]    = (unsigned long)millis();
  doc["temperature"]  = temperature;
  doc["pressure"]     = pressure;
  doc["altitude"]     = altitude;
  doc["mq2_percent"]  = mq2Percent;
  doc["mq2_alert"]    = mq2Alert;
  doc["chain_length"] = blockIndex;
  doc["chain_valid"]  = verifyChain();
  doc["wifi_rssi"]    = WiFi.RSSI();
  doc["transport"]    = "MQTT";
  String payload;
  serializeJson(doc, payload);
  bool ok = mqttClient.publish(TOPIC_PUBLISH_STATUS, payload.c_str());
  Serial.printf("[MQTT]   Heartbeat: %s\n", ok ? "OK" : "FAILED");
}

// ============================================================
//  I2C Scanner
// ============================================================
void scanI2C() {
  Serial.println("[I2C]    Scanning...");
  int found = 0;
  for (byte addr = 1; addr < 127; addr++) {
    Wire.beginTransmission(addr);
    if (Wire.endTransmission() == 0) {
      Serial.printf("[I2C]    0x%02X", addr);
      if (addr==0x76||addr==0x77) Serial.print("  <- BMP280");
      if (addr==0x3C)             Serial.print("  <- SSD1306");
      Serial.println();
      found++;
    }
  }
  Serial.printf("[I2C]    %d device(s) found\n", found);
}

// ============================================================
//  Init BMP280
// ============================================================
void initBMP280() {
  Serial.println("[SENSOR] Init BMP280...");
  for (int i = 1; i <= 3; i++) {
    if (bmp.begin(MY_BMP280_ADDR)) {
      bmp.setSampling(Adafruit_BMP280::MODE_NORMAL,
                      Adafruit_BMP280::SAMPLING_X2,
                      Adafruit_BMP280::SAMPLING_X16,
                      Adafruit_BMP280::FILTER_X16,
                      Adafruit_BMP280::STANDBY_MS_500);
      bmpFound = true;
      Serial.printf("[SENSOR] BMP280 OK at 0x%02X\n", MY_BMP280_ADDR);
      return;
    }
    Serial.printf("[SENSOR] Attempt %d failed, retry...\n", i);
    delay(500);
  }
  bmpFound = false;
  Serial.println("[SENSOR] BMP280 FAILED! Try MY_BMP280_ADDR=0x77");
}

// ============================================================
//  Init OLED
// ============================================================
void initOLED() {
  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDRESS)) {
    Serial.println("[OLED]   SSD1306 not found!");
    oledFound = false; return;
  }
  oledFound = true;
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.display();
  Serial.println("[OLED]   SSD1306 OK");
}

// ============================================================
//  OLED Splash
// ============================================================
void oledSplash() {
  if (!oledFound) return;
  display.clearDisplay();
  display.drawRect(0, 0, 128, 26, SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(4,4);   display.print("ENVIRONMENTAL MONITOR");
  display.setCursor(36,15); display.print("SYSTEM v1.0");
  display.drawLine(0,27,128,27,SSD1306_WHITE);
  display.setCursor(8,33);  display.print("ESP32 Secure Node");
  display.setCursor(16,45); display.print("BMP280 + MQ-2");
  display.setCursor(22,56); display.print("Initializing...");
  display.display();
  delay(2500);
}

// ============================================================
//  OLED WiFi Status
// ============================================================
void oledWifiStatus(bool connecting) {
  if (!oledFound) return;
  display.clearDisplay();
  display.fillRect(0,0,128,14,SSD1306_WHITE);
  display.setTextColor(SSD1306_BLACK);
  display.setTextSize(1);
  display.setCursor(14,3); display.print("ENV MONITORING SYS");
  display.setTextColor(SSD1306_WHITE);
  display.drawLine(0,15,128,15,SSD1306_WHITE);
  display.setCursor(0,20);
  if (connecting) {
    display.print("WiFi Connecting...");
    display.setCursor(0,34); display.print("SSID:");
    display.setCursor(0,44); display.print(WIFI_SSID);
  } else {
    if (wifiConnected) {
      display.print("WiFi Connected!");
      display.setCursor(0,34); display.print("IP:");
      display.setCursor(0,44); display.print(WiFi.localIP().toString());
    } else {
      display.print("WiFi FAILED!");
      display.setCursor(0,34); display.print("Retrying later...");
    }
  }
  display.display();
  if (!connecting) delay(2000);
}

// ============================================================
//  OLED AWS Status
// ============================================================
void oledAwsStatus(bool connecting) {
  if (!oledFound) return;
  display.clearDisplay();
  display.fillRect(0,0,128,14,SSD1306_WHITE);
  display.setTextColor(SSD1306_BLACK);
  display.setTextSize(1);
  display.setCursor(22,3); display.print("AWS IoT Core");
  display.setTextColor(SSD1306_WHITE);
  display.drawLine(0,15,128,15,SSD1306_WHITE);
  display.setCursor(0,20);
  if (connecting) {
    display.print("Connecting MQTT...");
    display.setCursor(0,34); display.print("TLS mTLS Auth");
    display.setCursor(0,44); display.print(AWS_IOT_ENDPOINT);
  } else {
    if (awsConnected) {
      display.print("AWS Connected!");
      display.setCursor(0,34); display.print("MQTT TLS OK");
      display.setCursor(0,44); display.print("Publishing active");
    } else {
      display.print("AWS FAILED!");
      display.setCursor(0,34); display.print("Check certs/policy");
    }
  }
  display.display();
  if (!connecting) delay(2000);
}

// ============================================================
//  OLED Main Screen (every 500ms)
//  +------------------------+
//  | ENV MONITORING SYS     |  <- inverted header
//  +------------------------+
//  | T:28.3C   P:1012hPa   |  <- BMP280 temp & pressure
//  +------------------------+
//  | ALT:  124.5 m          |  <- altitude
//  +------------------------+
//  | MQ-2:  38%  [  OK   ] |  <- gas level + alert
//  +------------------------+
//  | W A  Blk:42  CHN:OK   |  <- status row
//  +------------------------+
// ============================================================
void updateOLED() {
  if (!oledFound) return;
  display.clearDisplay();
  display.fillRect(0,0,128,13,SSD1306_WHITE);
  display.setTextColor(SSD1306_BLACK);
  display.setTextSize(1);
  display.setCursor(2,3); display.print("ENV MONITORING SYS");
  display.setTextColor(SSD1306_WHITE);
  display.drawLine(0,14,128,14,SSD1306_WHITE);

  display.setCursor(0,17);
  display.print("T:");
  if (bmpFound) { display.printf("%.1f",temperature); display.print((char)247); display.print("C"); }
  else          display.print("---C");
  display.setCursor(66,17);
  display.print("P:");
  if (bmpFound) display.printf("%.0fhPa",pressure);
  else          display.print("----hPa");
  display.drawLine(0,27,128,27,SSD1306_WHITE);

  display.setCursor(0,30);
  display.print("ALT:");
  if (bmpFound) display.printf(" %.1f m",altitude);
  else          display.print("  ---.- m");
  display.drawLine(0,40,128,40,SSD1306_WHITE);

  display.setCursor(0,43);
  display.printf("MQ-2: %3d%%",mq2Percent);
  if (mq2Alert && alertBlink) { display.setCursor(72,43); display.print("[!!ALERT]"); }
  else if (!mq2Alert)         { display.setCursor(72,43); display.print("[  OK   ]"); }
  display.drawLine(0,54,128,54,SSD1306_WHITE);

  display.setCursor(0, 57); display.print(wifiConnected ? "W" : "w");
  display.setCursor(8, 57); display.print(awsConnected  ? "A" : "a");
  display.setCursor(18,57); display.printf("Blk:%u", blockIndex>0?blockIndex-1:0);
  display.setCursor(90,57); display.print(verifyChain() ? "CHN:OK" : "CHN:ER");
  display.display();
}

// ============================================================
//  Security - bytes to hex
// ============================================================
void bytesToHex(const uint8_t* bytes, size_t len, char* hexOut) {
  for (size_t i=0;i<len;i++) sprintf(hexOut+(i*2),"%02x",bytes[i]);
  hexOut[len*2]='\0';
}

// ============================================================
//  Security - SHA-256
// ============================================================
void computeSHA256(const uint8_t* data, size_t len, char* hexOut) {
  uint8_t hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx,0);
  mbedtls_sha256_update(&ctx,data,len);
  mbedtls_sha256_finish(&ctx,hash);
  mbedtls_sha256_free(&ctx);
  bytesToHex(hash,32,hexOut);
}

// ============================================================
//  Security - HMAC-SHA256
// ============================================================
void computeHMAC_SHA256(const uint8_t* data, size_t len, char* hexOut) {
  uint8_t hmac[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx,HMAC_KEY,32);
  mbedtls_md_hmac_update(&ctx,data,len);
  mbedtls_md_hmac_finish(&ctx,hmac);
  mbedtls_md_free(&ctx);
  bytesToHex(hmac,32,hexOut);
}

// ============================================================
//  Security - AES-256-CBC encrypt -> Base64
// ============================================================
bool encryptAES256CBC(const char* plaintext, char* b64Out, size_t b64OutLen) {
  uint8_t iv[16];
  esp_fill_random(iv,16);
  size_t ptLen=strlen(plaintext), padLen=16-(ptLen%16), totalLen=ptLen+padLen;
  uint8_t* padded=(uint8_t*)malloc(totalLen);
  if (!padded) return false;
  memcpy(padded,plaintext,ptLen);
  memset(padded+ptLen,(uint8_t)padLen,padLen);
  uint8_t* encrypted=(uint8_t*)malloc(totalLen);
  if (!encrypted){free(padded);return false;}
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes,AES_KEY,256);
  uint8_t iv_copy[16]; memcpy(iv_copy,iv,16);
  mbedtls_aes_crypt_cbc(&aes,MBEDTLS_AES_ENCRYPT,totalLen,iv_copy,padded,encrypted);
  mbedtls_aes_free(&aes);
  size_t combinedLen=16+totalLen;
  uint8_t* combined=(uint8_t*)malloc(combinedLen);
  if (!combined){free(padded);free(encrypted);return false;}
  memcpy(combined,iv,16); memcpy(combined+16,encrypted,totalLen);
  size_t b64Len=0;
  mbedtls_base64_encode((uint8_t*)b64Out,b64OutLen,&b64Len,combined,combinedLen);
  b64Out[b64Len]='\0';
  free(padded); free(encrypted); free(combined);
  return true;
}

// ============================================================
//  Blockchain - compute block hash
// ============================================================
void computeBlockHash(Block& b, char* hashOut) {
  char raw[512];
  snprintf(raw,sizeof(raw),"%u|%llu|%.4f|%.4f|%.4f|%d|%d|%d|%s",
    b.index,b.timestamp,b.temperature,b.pressure,b.altitude,
    b.mq2Raw,b.mq2Percent,(int)b.mq2Alert,b.previousHash);
  computeSHA256((uint8_t*)raw,strlen(raw),hashOut);
}

// ============================================================
//  Blockchain - sign block
// ============================================================
void signBlock(Block& b) {
  char sigInput[160];
  snprintf(sigInput,sizeof(sigInput),"%s|%s|%u",b.blockHash,DEVICE_ID,b.index);
  computeHMAC_SHA256((uint8_t*)sigInput,strlen(sigInput),b.signature);
}

// ============================================================
//  Blockchain - create block
// ============================================================
Block createBlock(float temp,float pres,float alt,int mq2r,int mq2p,bool mq2a) {
  Block b; memset(&b,0,sizeof(Block));
  b.index=blockIndex; b.timestamp=(uint64_t)millis();
  b.temperature=temp; b.pressure=pres; b.altitude=alt;
  b.mq2Raw=mq2r; b.mq2Percent=mq2p; b.mq2Alert=mq2a; b.valid=true;
  strncpy(b.previousHash,lastBlockHash,64); b.previousHash[64]='\0';
  computeBlockHash(b,b.blockHash); signBlock(b);
  return b;
}

// ============================================================
//  Blockchain - add block
// ============================================================
bool addBlock(float temp,float pres,float alt,int mq2r,int mq2p,bool mq2a) {
  Block nb=createBlock(temp,pres,alt,mq2r,mq2p,mq2a);
  uint32_t slot=blockIndex%MAX_CHAIN_LENGTH;
  blockchain[slot]=nb;
  strncpy(lastBlockHash,nb.blockHash,64); lastBlockHash[64]='\0';
  if (chainLength<MAX_CHAIN_LENGTH) chainLength++;
  blockIndex++;
  Serial.printf("[CHAIN]  #%u Hash:%.16s... Sig:%.16s...\n",
                nb.index,nb.blockHash,nb.signature);
  return true;
}

// ============================================================
//  Blockchain - verify chain
// ============================================================
bool verifyChain() {
  if (chainLength<2) return true;
  uint32_t count=min(chainLength,(uint32_t)MAX_CHAIN_LENGTH);
  for (uint32_t i=1;i<count;i++) {
    uint32_t cs=(blockIndex-count+i)%MAX_CHAIN_LENGTH;
    uint32_t ps=(blockIndex-count+i-1)%MAX_CHAIN_LENGTH;
    Block& cb=blockchain[cs]; Block& pb=blockchain[ps];
    char reHash[65];
    computeBlockHash(cb,reHash);
    if (strcmp(reHash,cb.blockHash)!=0){
      Serial.printf("[CHAIN]  Block %u hash tampered!\n",cb.index); return false;}
    if (strcmp(cb.previousHash,pb.blockHash)!=0){
      Serial.printf("[CHAIN]  Block %u chain broken!\n",cb.index); return false;}
    char expSig[65],sigIn[160];
    snprintf(sigIn,sizeof(sigIn),"%s|%s|%u",cb.blockHash,DEVICE_ID,cb.index);
    computeHMAC_SHA256((uint8_t*)sigIn,strlen(sigIn),expSig);
    if (strcmp(expSig,cb.signature)!=0){
      Serial.printf("[CHAIN]  Block %u signature invalid!\n",cb.index); return false;}
  }
  return true;
}

// ============================================================
//  Blockchain - block to JSON
// ============================================================
String blockToJson(const Block& b) {
  StaticJsonDocument<512> doc;
  doc["index"]=b.index; doc["timestamp"]=(unsigned long)b.timestamp;
  doc["temperature"]=b.temperature; doc["pressure"]=b.pressure;
  doc["altitude"]=b.altitude;
  doc["mq2_raw"]=b.mq2Raw; doc["mq2_percent"]=b.mq2Percent; doc["mq2_alert"]=b.mq2Alert;
  doc["previousHash"]=b.previousHash; doc["blockHash"]=b.blockHash;
  doc["signature"]=b.signature; doc["node_id"]=DEVICE_ID;
  String out; serializeJson(doc,out); return out;
}

// ============================================================
//  Startup Banner
// ============================================================
void printBanner() {
  Serial.println("\n===========================================");
  Serial.println("  ESP32 Secure Environmental Monitor");
  Serial.println("  Sensors  : BMP280 + MQ-2 (GPIO34)");
  Serial.println("  Display  : SSD1306 OLED 128x64");
  Serial.println("  Encrypt  : AES-256-CBC");
  Serial.println("  Sign     : HMAC-SHA256");
  Serial.println("  Ledger   : Consortium Blockchain");
  Serial.println("  Transport: AWS IoT Core MQTT/TLS");
  Serial.println("===========================================");
  Serial.printf("  Device   : %s\n",DEVICE_ID);
  Serial.printf("  Location : %s\n",LOCATION_ID);
  Serial.printf("  Endpoint : %s\n",AWS_IOT_ENDPOINT);
  Serial.println("  Wiring:");
  Serial.println("    BMP280  SDA=GPIO21 SCL=GPIO22 VCC=3.3V [0x76]");
  Serial.println("    SSD1306 SDA=GPIO21 SCL=GPIO22 VCC=3.3V [0x3C]");
  Serial.println("    MQ-2    AOUT=GPIO34            VCC=5V");
  Serial.println("===========================================\n");
}