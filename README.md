# 🌐 Network Traffic Sentinel (V17.1)

**Advanced Network Monitoring System with Live Web Dashboard**

---

## 📖 About

**Network Traffic Sentinel** is a sophisticated network monitoring tool designed for **Home Labs** and **Personal Hotspots**. It captures, analyzes, and visualizes network traffic in real-time.

Unlike standard task managers, this tool distinguishes between:

- **Internet Traffic (WAN)**
- **Local File Transfer (LAN)** (e.g., Camo, Shareit, local gaming)

This provides an accurate calculation of actual bandwidth usage per device. The system features a modern **Dark Mode Web Dashboard** powered by **Flask**.

---

## ✨ Key Features

### 🕵️‍♂️ Deep Traffic Analysis

- **Smart Separation Logic**
  Automatically differentiates between data consuming your internet quota (**WAN**) and local network traffic (**LAN**).

- **App Identification**
  Identifies active applications (YouTube, WhatsApp, Netflix, Gaming, etc.) using **DNS**, **SNI**, and **Port Heuristics**.

- **Device Fingerprinting**
  Automatically detects the device vendor (Apple, Samsung, Intel, etc.) based on the **MAC Address OUI**.

---

### 💻 Live Web Dashboard

- **Modern UI**
  Sleek, responsive **Dark Mode** interface built with **Bootstrap**.

- **Real-Time Updates**
  Data refreshes every second using **AJAX** without page reloads.

- **Live Template Editing**
  Edit `dashboard.html` while the script is running — changes appear instantly on refresh.

- **Stable Sorting (Freeze Sort)**
  Keeps device order stable for **15 minutes** to prevent visual jumping while still updating live speeds.

---

## 🚀 Performance & Persistence

- **Live Speedometer**
  Displays real-time download/upload speeds for every connected device.

- **Data Persistence**
  Automatically saves traffic statistics to `traffic_data.json`. Monitoring resumes exactly where it left off — even after reboot.

- **Host Usage Calculation**
  Accurately calculates host machine usage:

  ```text
  Host Usage = Total WAN Traffic - Sum(Clients Internet Traffic)
  ```

---

## 📸 Screenshots

> Place your dashboard screenshot here:

```text
assets/dashboard.png
```

---

## 🛠️ Prerequisites & Installation

### 1️⃣ System Requirements

- **OS**: Windows 10 / 11 (Recommended) or Linux
- **Python**: 3.8 or higher
- **Driver (Windows Only)**: **Npcap**

⚠️ During installation, **enable**:

> ✔ Install Npcap in WinPcap API-compatible Mode

---

### 2️⃣ Install Dependencies

```bash
pip install scapy flask colorama
```

---

## 🚀 Usage

### 1️⃣ Run the Monitor

Run the script with **Administrator privileges** (required for packet sniffing):

```bash
python web_monitor.py
```

---

### 2️⃣ Select Network Interfaces

You will be prompted to choose two interfaces:

- **Hotspot Interface** → Virtual adapter broadcasting Wi-Fi
- **WAN Interface** → Physical adapter connected to the internet (Wi-Fi / Ethernet)

---

### 3️⃣ Access the Dashboard

Open your browser and navigate to:

```text
http://127.0.0.1:5000
```

---

## ⚙️ Configuration

Edit the `web_monitor.py` file to customize behavior.

### 🔖 Known Devices

Add static devices for friendly names:

```python
KNOWN_DEVICES = {
    "8a:af:98:xx:xx:xx": "My iPhone",
    "00:28:f8:xx:xx:xx": "Work Laptop",
}
```

---

### 🎯 App & Port Identification

Extend app detection by editing:

```python
APP_PORT_HINTS = {
    443: "HTTPS",
    3478: "WhatsApp",
}
```

---

## 🧠 Technical Details

- **Passive Network Monitor**
  No MITM, ARP spoofing, or packet injection.

- **Gateway-Based Analysis**
  Relies on the host machine acting as the **network gateway / hotspot**.

- **Packet Capture**
  Uses **Scapy** at Layer 2 / Layer 3.

### Traffic Classification Logic

- **Private IP Destination** → Local Traffic (LAN / Free)
- **Public IP Destination** → Internet Traffic (WAN / Quota)

### Host Usage Derivation

```text
Host Usage = Total WAN - Client WAN Usage
```

---

## ⚠️ Disclaimer

### 📚 Educational Use Only

This tool is intended for **monitoring your own network** (Home Lab / Personal Hotspot).

🚫 **Unauthorized monitoring of public networks or devices without explicit consent is illegal** and may violate privacy laws and terms of service.

The author assumes **no responsibility** for misuse.

---

## ❤️ Credits

Developed with passion by:

**Mohamed Abdelwahab**

---

> If you like this project, consider ⭐ starring it and sharing feedback!
