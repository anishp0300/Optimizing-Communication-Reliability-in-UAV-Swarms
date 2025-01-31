#include "esp_wifi.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include <esp_now.h>
#include "AsyncUDP.h"
#include <FS.h>
#include <SPIFFS.h>
#include "esp_wifi_types.h"

const char* _ssid     = "ESP32-1";
const char* password = "123456789";
const int udpPort = 10000;
const char * udpAddress = "192.168.4.2";

uint8_t rssi=38;
uint8_t macIndex = 12;
uint8_t rssiIndex = 39;

int numMessages = 0;
int totalMessagesSent = 0;
int failedDeliveries = 0;

uint8_t destinationMac[] ={0xA4,0xE5,0x7C,0xDF,0xFD,0xE0}; // For manual messaging //This MAC is for module 6. For drone. 
//unit8_t destinationMac[] = {0xA4,0xE5,0x7C,0xE0,0xC5,0xCC}; // This is the MAC for module 2. for laptop

WiFiUDP udpSend;

//AsyncUDP udpSend;
AsyncUDP udpReceive;

void onReceiveUDP(AsyncUDPPacket packet) {
  Serial.print("UDP Packet Type: ");
  Serial.print(packet.isBroadcast() ? "Broadcast" : packet.isMulticast() ? "Multicast" : "Unicast");
  Serial.print(", From: ");
  Serial.print(packet.remoteIP());
  Serial.print(":");
  Serial.print(packet.remotePort());
  Serial.print(", To: ");
  Serial.print(packet.localIP());
  Serial.print(":");
  Serial.print(packet.localPort());
  Serial.print(", Length: ");
  Serial.print(packet.length());
  Serial.print(", Data: ");
  Serial.write(packet.data()+6, packet.length()-6);

//  uint8_t buffer[packet.length()]; 
//  memcpy(buffer,packet.data(),packet.length());
//  buffer[packet.length()] = 0;
////  memcpy(buffer+37,&rssi,1);
//  buffer[37] = rssi;
//  udpSend.print(buffer);
  
  uint8_t macAddr[6];
  memcpy(macAddr,packet.data()+macIndex,6);
  
  char macStr[18];
  formatMacAddress(macAddr, macStr, 18);

  Serial.print(", to MAC Addr: ");
  Serial.printf("%s",macStr);
  Serial.println();
  
  if (!esp_now_is_peer_exist(macAddr))
  {
    esp_now_peer_info_t peerInfo = {};
    memcpy(&peerInfo.peer_addr, macAddr, 6);
    esp_now_add_peer(&peerInfo);
  }
  esp_err_t result = esp_now_send(macAddr, packet.data(), packet.length());


  if (result == ESP_OK)
  {
    Serial.println("Broadcast message sent");
  }
  else if (result == ESP_ERR_ESPNOW_NOT_INIT)
  {
    Serial.println("ESPNOW not Init.");
  }
  else if (result == ESP_ERR_ESPNOW_ARG)
  {
    Serial.println("Invalid Argument");
  }
  else if (result == ESP_ERR_ESPNOW_INTERNAL)
  {
    Serial.println("Internal Error");
  }
  else if (result == ESP_ERR_ESPNOW_NO_MEM)
  {
    Serial.println("ESP_ERR_ESPNOW_NO_MEM");
  }
  else if (result == ESP_ERR_ESPNOW_NOT_FOUND)
  {
    Serial.println("Peer not found.");
  }
  else
  {
    Serial.println("Unknown error");
  }

}

void formatMacAddress(const uint8_t *macAddr, char *buffer, int maxLength)
{
  snprintf(buffer, maxLength, "%02x:%02x:%02x:%02x:%02x:%02x", macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
}

void onReceiveEspnow(const uint8_t *macAddr, const uint8_t *data, int dataLen)
{
  // only allow a maximum of 250 characters in the message + a null terminating byte
  int msgLen = min(ESP_NOW_MAX_DATA_LEN, dataLen);
  uint8_t buffer[msgLen];
  memcpy(buffer, data, msgLen);
  // make sure we are null terminated
  buffer[msgLen] = 0;
  // format the mac address
  char macStr[18];
  formatMacAddress(macAddr, macStr, 18);
  // debug log the message to the serial port
  Serial.printf("Received ESP-NOW message from: %s - %s - %d - %d\n", macStr, buffer,rssi, msgLen);

  buffer[rssiIndex] = rssi;

  udpSend.beginPacket(udpAddress, udpPort);
  udpSend.write(buffer, msgLen);
  udpSend.endPacket();

  //udpSend.print(buffer);

}

// callback when espnow data is sent
void onSentEspnow(const uint8_t *macAddr, esp_now_send_status_t status)
{
  char macStr[18];
  formatMacAddress(macAddr, macStr, 18);
  Serial.print("Last Packet Sent to: ");
  Serial.print(macStr);

  if (status == ESP_NOW_SEND_SUCCESS) {
    Serial.println(" Delivery Success ");
  }
  else {
    Serial.println(" Delivery Fail ");
    failedDeliveries++;
  }

  Serial.println(status == ESP_NOW_SEND_SUCCESS ? " Delivery Success" : " Delivery Fail");
}

typedef struct
{
  unsigned frame_ctrl : 16;  // 2 bytes / 16 bit fields
  unsigned duration_id : 16; // 2 bytes / 16 bit fields
  uint8_t addr1[6];          // receiver address
  uint8_t addr2[6];          //sender address
  uint8_t addr3[6];          // filtering address
  unsigned sequence_ctrl : 16; // 2 bytes / 16 bit fields
} wifi_ieee80211_mac_hdr_t;    // 24 bytes

typedef struct
{
  wifi_ieee80211_mac_hdr_t hdr;
  unsigned category_code : 8; // 1 byte / 8 bit fields
  uint8_t oui[3]; // 3 bytes / 24 bit fields
  uint8_t payload[0];
} wifi_ieee80211_packet_t;

void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type)
{
  // only filter mgmt frames
  if (type != WIFI_PKT_MGMT)
    return;

  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  static const uint8_t esp_oui[3] = {0x18, 0xfe, 0x34}; // esp32 oui

  // Filter vendor specific frame with the esp oui.
  if (((ipkt->category_code) == 127) && (memcmp(ipkt->oui, esp_oui,3) == 0))
  {
    rssi = -1 * ppkt->rx_ctrl.rssi;
    // PRINT RSSI
//    printf("Rssi = %d dbm\n"
//           "Category code = %d\n"
//           "OUI = %02x:%02x:%02x\n"
//           "Sender mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
//           ppkt->rx_ctrl.rssi,
//           ipkt->category_code,
//           ipkt->oui[0],ipkt->oui[1],ipkt->oui[2],
//           hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
//           hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
  }
}

void setup()
{
  Serial.begin(115200);
  delay(1000);

  // Initializing SPIFFS
  if (!SPIFFS.begin(true)) {
    Serial.println("An error occured while mounting of SPIFFS");
    return;
  }
  if (SPIFFS.mkdir("/mydir")) {
    Serial.println("Directory has been successfully created");
  }
  else {
    Serial.println("Error creating your directory");
  }

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(_ssid, password);

  Serial.println("Enter the number of messages to send:");

  unsigned long startTime = millis();  
  while (!Serial.available() && millis() - startTime < 5000) {    // Adjust delay here before the code selects te default number of messages
  }

  if (Serial.available()) {
    if (Serial.peek() == '\n') {
      // User did not input any value, set numMessages to default (30)
      numMessages = 30;
      Serial.println("Default number of messages (30) will be sent.");
    } else {
      numMessages = Serial.parseInt(); // Read the number of messages from user input
      Serial.print("Number of messages to send: ");
      Serial.println(numMessages);
    }
  } else {
    // Timeout occurred, set numMessages to default (30)
    numMessages = 30;
    Serial.println("Timeout. Default number of messages (30) will be sent.");
  }


  Serial.println("Starting.. ");
  // Output my MAC address - useful for later
  Serial.print("My MAC Address is: ");
  Serial.println(WiFi.macAddress());
  Serial.print("My AP IP Address is: ");
  Serial.println(WiFi.softAPIP());

  // set udp connection 
  //if (udpSend.connect(IPAddress(192,168,4,2), udpPort)) {
   // udpSend.onPacket(onReceiveUDP);
  //}

  // set udp listen
  if (udpReceive.listen(udpPort)) {
    Serial.print("UDP Listening on IP: ");
    Serial.print(WiFi.softAPIP());
    Serial.print("Port: ");
    Serial.println(udpPort);
    udpReceive.onPacket(onReceiveUDP);
  }

  // set promiscuous mode to get rssi
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  
  // set ESP Now
  if (esp_now_init() == ESP_OK)
  {
    Serial.println("ESPNow Init Success");
    esp_now_register_recv_cb(onReceiveEspnow);
    esp_now_register_send_cb(onSentEspnow);
  }
  else
  {
    Serial.println("ESPNow Init Failed");
    delay(3000);
    ESP.restart();
  }
}

void loop() {
  if (!esp_now_is_peer_exist(destinationMac)) {
    esp_now_peer_info_t peerInfo = {};
    memcpy(&peerInfo.peer_addr, destinationMac, 6);
    esp_now_add_peer(&peerInfo);
  }
  delay(7000);         // Delay here is for the wait time after the number of messages to be sent has been entered, and the code actually sending the messages.
  
  // Sending numbers 
  for (int i = 1; i <= numMessages; ++i) {
    totalMessagesSent++;
    
    char espmessage[4]; // Assuming numbers are up to 3 digits
    sprintf(espmessage, "%d", i);
    
    esp_err_t result = esp_now_send(destinationMac, (uint8_t*)espmessage, strlen(espmessage));
    
    if (result == ESP_OK) {
      Serial.println("Message sent: " + String(espmessage));
    } else if (result == ESP_ERR_ESPNOW_NOT_INIT) {
      Serial.println("ESPNOW not Init.");
    } else if (result == ESP_ERR_ESPNOW_ARG) {
      Serial.println("Invalid Argument");
    } else if (result == ESP_ERR_ESPNOW_INTERNAL) {
      Serial.println("Internal Error");
    } else if (result == ESP_ERR_ESPNOW_NO_MEM) {
      Serial.println("ESP_ERR_ESPNOW_NO_MEM");
    } else if (result == ESP_ERR_ESPNOW_NOT_FOUND) {
      Serial.println("Peer not found.");
    } else {
      Serial.println("Unknown error");
    }
    
    delay(100); // Adjust delay as needed
  }

  Serial.print("Total messages sent: ");
  Serial.println(totalMessagesSent - failedDeliveries);
  
  // Writing to the file
  File file = SPIFFS.open("/mydir/Success_Msgs.txt", FILE_APPEND);
  if (!file) {
    Serial.println("Error creating file");
    return;
  }
  Serial.println("File created");
  file.print("Expected messages: ");
  file.println(totalMessagesSent);
  file.print("Messages actually sent: ");
  file.println(totalMessagesSent - failedDeliveries);
  file.close();

  // Reading the file
  file = SPIFFS.open("/mydir/Success_Msgs.txt", FILE_READ);
  if (!file) {
    Serial.println("ERROR: Opening file");
    return;
  }
  while (file.available()) {
    Serial.write(file.read());
  }
  file.close();

  while (true) {
    delay(1000);
  }
}