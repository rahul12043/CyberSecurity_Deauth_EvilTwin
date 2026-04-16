# 📡 Wi-Fi Deauth & Evil Twin Demonstration

## 📌 Repository Overview

This project is a **proof-of-concept (PoC)** designed to demonstrate how attackers can exploit the **802.11 management frame vulnerability** and use **Evil Twin captive portals** to harvest credentials.

By combining an **ESP8266** with a laptop running the **Aircrack-ng suite**, this lab simulates a real-world **social engineering attack** in a controlled environment.

---

## 🛠 Tech Stack

**Hardware**

* ESP8266 (NodeMCU)

**Software**

* Aircrack-ng Suite

  * `airodump-ng`
  * `aireplay-ng`

**Firmware**

* Arduino IDE (C++)

**Web**

* HTML / CSS (Custom Captive Portal)

---

## 🏗 System Architecture

The attack lifecycle is divided into three distinct phases:

### 1️⃣ The Disruption (Deauthentication)

A wireless NIC in **Monitor Mode** is used to identify the target client and Access Point (AP), followed by broadcasting spoofed deauthentication frames.

* **Mechanism:**
  The target receives packets that appear to originate from the legitimate AP, forcing disconnection.

* **Goal:**
  Create a temporary service outage to push users toward reconnecting to available networks.

---

### 2️⃣ The Lure (Evil Twin Setup)

The ESP8266 is configured to broadcast an SSID identical to the target network.

* **Mechanism:**

  * ESP8266 runs a DNS server
  * Redirects all traffic to a local captive portal

* **Design:**
  The portal mimics:

  * Router login pages
  * Firmware update prompts

  (Because humans trust things that look official)

---

### 3️⃣ The Harvest (Credential Capture)

Once the user connects and submits credentials:
* Credentials are stored in:

  * Serial Monitor output
  * Internal SPIFFS (Flash Memory)
  * 
---

## 🚀 Implementation Steps

1. **Reconnaissance**

   ```bash
   airodump-ng <interface>
   ```

   * Identify:

     * Target SSID
     * Channel
     * MAC Address

2. **ESP8266 Setup**

   * Flash firmware via Arduino IDE
   * Configure:

     * Matching SSID
     * Captive portal HTML page

3. **Execution**

   ```bash
   aireplay-ng --deauth <count> -a <AP_MAC> -c <CLIENT_MAC> <interface>
   ```

4. **Observation**

   * Monitor Serial output
   * Watch for:

     * Client connections
     * Captured credentials

---
## Deauth in Action
<img width="1746" height="926" alt="image" src="https://github.com/user-attachments/assets/5c84fc78-3d6b-465f-b323-527e824b102c" />
<img width="1752" height="924" alt="image" src="https://github.com/user-attachments/assets/482add25-7fb2-44eb-bf43-2455998d41fc" />
<img width="1745" height="925" alt="image" src="https://github.com/user-attachments/assets/3a010544-149a-442d-bdef-a60e7f6df106" />
<img width="1749" height="921" alt="image" src="https://github.com/user-attachments/assets/3d4ead5d-c4ea-49a9-8b64-2069c8b12ba7" />

---

## 🛡 Mitigation & Defense

### 🔐 802.11w (Management Frame Protection)

* Prevents spoofed deauthentication packets
* Strongest technical defense

### 🌐 VPN Usage

* Encrypts traffic even on malicious networks
* Turns attacker into a confused spectator

### 🧠 User Awareness

* Never trust sudden login prompts
* Avoid entering credentials on **HTTP pages**
* Verify network authenticity before connecting

---

## ⚖ Ethical Disclosure

> ⚠️ **Disclaimer:**
> This project is strictly for **educational purposes only**.

* Unauthorized access to networks is **illegal**
* Capturing credentials without permission is **unethical**
* Always test in a **controlled lab environment**

The author is not responsible for misuse of this material.

---

