# import sys
# import time
# import os
# import threading
# import re
# import json
# import urllib.request
# from datetime import datetime
# from collections import defaultdict
# from scapy.all import sniff, get_if_list, get_if_addr, conf, DNS, IP, TCP, UDP, Ether
# from flask import Flask, jsonify, render_template_string, render_template
# import logging

# # ==========================================
# # 📝 إعدادات المستخدم
# # ==========================================
# KNOWN_DEVICES = {
#     "8a:af:98:60:2d:ee": "iPhone 11",
#     "00:28:f8:c6:ba:8d": "Laptop HP",
#     "9a:15:22:de:92:f9": "iPhone 13",
#     "70:1f:3c:3b:83:23": "Tablet",
#     "12:0f:06:c3:2b:e6": "Hawawi",
#     "fe:ef:d9:d0:8f:c8": "Relme omo haga",
# }

# HOTSPOT_SUBNET = "192.168.137."
# HOTSPOT_GATEWAY = "192.168.137.1"
# SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# DB_FILE = os.path.join(SCRIPT_DIR, "traffic_data.json")
# TEMPLATE_DIR = os.path.join(SCRIPT_DIR, "templates")
# TEMPLATE_FILE = os.path.join(TEMPLATE_DIR, "dashboard.html")
# WEB_PORT = 5000

# # ==========================================
# # 📄 HTML Template (Fixed Colors)
# # ==========================================
# DEFAULT_HTML = """
# <!DOCTYPE html>
# <html lang="en">
# <head>
#     <meta charset="UTF-8">
#     <meta name="viewport" content="width=device-width, initial-scale=1.0">
#     <title>Network Monitor V17.1</title>
#     <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
#     <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
#     <style>
#         body { background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; }
#         .card { background-color: #1e1e1e; border: 1px solid #333; margin-bottom: 15px; border-radius: 10px; }
#         .stat-box { background: #252526; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; }
#         .stat-val { font-size: 1.5rem; font-weight: bold; color: #4caf50; }
#         .stat-label { font-size: 0.9rem; color: #aaa; }
#         .device-name { color: #2196f3; font-weight: bold; font-size: 1.1rem; }
#         .vendor-badge { font-size: 0.75rem; background: #333; padding: 2px 6px; border-radius: 4px; color: #ff9800; margin-left: 5px; }
#         .speed-indicator { color: #f44336; font-weight: bold; }

#         .app-row { font-size: 0.85rem; padding: 4px 0; display: flex; justify-content: space-between; color: #ffffff; }
#         .usage-text { color: #aaa; }

#         /* 🔥 تعديل ألوان المعلومات الأساسية */
#         .device-meta { color: #bfbfbf; font-size: 0.85rem; margin-bottom: 10px; }
#         .device-meta i { color: #0dcaf0; width: 20px; text-align: center; }

#         .progress { height: 6px; background-color: #2c2c2c; border-radius: 3px; }
#         .progress-bar { background-color: #03a9f4; }

#         .ip-changed { color: #f44336; font-size: 0.8rem; animation: blink 2s infinite; }
#         .sort-timer { font-size: 0.8rem; color: #777; }
#         @keyframes blink { 50% { opacity: 0.5; } }
#     </style>
# </head>
# <body>
#     <div class="container py-4">
#         <div class="row mb-4">
#             <div class="col-md-3"><div class="stat-box"><div class="stat-val" id="wan-total">0 MB</div><div class="stat-label">🌐 WAN (Internet)</div></div></div>
#             <div class="col-md-3"><div class="stat-box"><div class="stat-val text-warning" id="clients-net">0 MB</div><div class="stat-label">🔥 Clients (Net)</div></div></div>
#             <div class="col-md-3"><div class="stat-box"><div class="stat-val text-info" id="clients-loc">0 MB</div><div class="stat-label">🏠 Local (LAN)</div></div></div>
#             <div class="col-md-3"><div class="stat-box"><div class="stat-val text-primary" id="host-total">0 MB</div><div class="stat-label">💻 Laptop (Host)</div></div></div>
#         </div>

#         <div class="d-flex justify-content-between mb-3 align-items-center">
#             <span class="text-muted"><i class="fas fa-clock"></i> Runtime: <span id="session-time">00:00:00</span></span>
#             <span class="sort-timer"><i class="fas fa-sort-amount-down"></i> Next Reorder in: <span id="sort-countdown" class="text-white">15:00</span></span>
#             <span class="text-success" id="connection-status">● Live</span>
#         </div>

#         <div class="row" id="devices-container"></div>
#     </div>

#     <script>
#         let cachedOrder = [];
#         let nextSortTime = 0;
#         const SORT_INTERVAL_MS = 15 * 60 * 1000;

#         function formatBytes(bytes) {
#             if (bytes === 0) return '0 B';
#             const k = 1024;
#             const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
#             const i = Math.floor(Math.log(bytes) / Math.log(k));
#             return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
#         }

#         function formatSpeed(bps) {
#             if (bps < 1024) return bps.toFixed(0) + ' B/s';
#             if (bps < 1024*1024) return (bps/1024).toFixed(1) + ' KB/s';
#             return (bps/(1024*1024)).toFixed(1) + ' MB/s';
#         }

#         function formatTimeLeft(ms) {
#             if (ms < 0) return "00:00";
#             const totalSeconds = Math.floor(ms / 1000);
#             const m = Math.floor(totalSeconds / 60);
#             const s = totalSeconds % 60;
#             return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
#         }

#         async function updateDashboard() {
#             try {
#                 const response = await fetch('/data');
#                 const data = await response.json();

#                 document.getElementById('wan-total').innerText = formatBytes(data.stats.wan);
#                 document.getElementById('clients-net').innerText = formatBytes(data.stats.clients_net);
#                 document.getElementById('clients-loc').innerText = formatBytes(data.stats.clients_loc);
#                 document.getElementById('host-total').innerText = formatBytes(data.stats.host_usage);
#                 document.getElementById('session-time').innerText = data.stats.runtime;

#                 const now = Date.now();
#                 if (now > nextSortTime || cachedOrder.length === 0) {
#                     data.devices.sort((a, b) => {
#                         if (a.is_host) return -1;
#                         if (b.is_host) return 1;
#                         return b.speed - a.speed;
#                     });
#                     cachedOrder = data.devices.map(d => d.mac);
#                     nextSortTime = now + SORT_INTERVAL_MS;
#                 } else {
#                     data.devices.sort((a, b) => {
#                         let idxA = cachedOrder.indexOf(a.mac);
#                         let idxB = cachedOrder.indexOf(b.mac);
#                         if (idxA === -1) idxA = 9999;
#                         if (idxB === -1) idxB = 9999;
#                         return idxA - idxB;
#                     });
#                 }

#                 document.getElementById('sort-countdown').innerText = formatTimeLeft(nextSortTime - now);

#                 const container = document.getElementById('devices-container');
#                 container.innerHTML = '';

#                 data.devices.forEach(dev => {
#                     const total = dev.total_net + dev.total_loc;
#                     let appsHtml = '';

#                     dev.apps.slice(0, 5).forEach(app => {
#                         const pct = total > 0 ? (app.usage / total * 100).toFixed(1) : 0;
#                         appsHtml += `
#                             <div class="app-row">
#                                 <span>${app.name}</span>
#                                 <span class="usage-text">${formatBytes(app.usage)} <span style="color:#666">(${pct}%)</span></span>
#                             </div>
#                             <div class="progress mb-2">
#                                 <div class="progress-bar" style="width: ${pct}%"></div>
#                             </div>
#                         `;
#                     });

#                     const speedClass = dev.speed > 1024*100 ? 'text-danger' : 'text-success';
#                     const ipAlert = dev.ip_log ? `<div class="ip-changed"><i class="fas fa-exclamation-triangle"></i> IP Changed: ${dev.ip_log}</div>` : '';

#                     const cardHtml = `
#                         <div class="col-md-6 col-lg-4">
#                             <div class="card h-100">
#                                 <div class="card-body">
#                                     <div class="d-flex justify-content-between align-items-center mb-2">
#                                         <div>
#                                             <span class="device-name">${dev.name}</span>
#                                             <span class="vendor-badge">${dev.vendor}</span>
#                                         </div>
#                                         <div class="${speedClass} fw-bold">
#                                             <i class="fas fa-tachometer-alt"></i> ${formatSpeed(dev.speed)}
#                                         </div>
#                                     </div>

#                                     <div class="device-meta">
#                                         <div><i class="fas fa-network-wired"></i> IP: ${dev.ip}</div>
#                                         <div><i class="fas fa-globe"></i> Net: ${formatBytes(dev.total_net)} | <i class="fas fa-home"></i> Loc: ${formatBytes(dev.total_loc)}</div>
#                                         ${ipAlert}
#                                     </div>
#                                     <hr class="border-secondary">
#                                     <div class="mt-2">
#                                         ${appsHtml}
#                                     </div>
#                                 </div>
#                             </div>
#                         </div>
#                     `;
#                     container.innerHTML += cardHtml;
#                 });

#             } catch (error) {
#                 document.getElementById('connection-status').innerText = '🔴 Disconnected';
#                 document.getElementById('connection-status').className = 'text-danger';
#             }
#         }
#         setInterval(updateDashboard, 1000);
#         updateDashboard();
#     </script>
# </body>
# </html>
# """

# # ==========================================
# # 💾 إدارة البيانات
# # ==========================================
# # إنشاء ملف القالب لو مش موجود
# if not os.path.exists(TEMPLATE_DIR):
#     os.makedirs(TEMPLATE_DIR)
# # 🔥 تحديث ملف HTML لو موجود عشان يطبق التعديلات الجديدة
# with open(TEMPLATE_FILE, "w", encoding="utf-8") as f:
#     f.write(DEFAULT_HTML)

# lock = threading.RLock()
# app = Flask(__name__, template_folder=TEMPLATE_DIR)
# app.config["TEMPLATES_AUTO_RELOAD"] = True
# log = logging.getLogger("werkzeug")
# log.setLevel(logging.ERROR)

# device_db = defaultdict(
#     lambda: {
#         "IP": "Unknown",
#         "Name": "Unknown",
#         "Vendor": "",
#         "Total_Internet": 0,
#         "Total_Local": 0,
#         "Prev_Total": 0,
#         "Current_Speed": 0,
#         "FirstSeen": time.time(),
#         "LastSeen": time.time(),
#         "Apps": defaultdict(int),
#         "IP_Log": None,
#     }
# )

# global_stats = {
#     "wan_total": 0,
#     "clients_internet": 0,
#     "clients_local": 0,
#     "wan_apps": defaultdict(int),
#     "host_mac": "HOST_PC",
#     "start_time": time.time(),
#     "last_save_date": str(datetime.now().date()),
# }

# ip_to_app_map = {}
# mac_vendor_cache = {}
# IP_MAPPING_TTL = 300
# host_ip = ""


# # ==========================================
# # 📥 دوال النظام
# # ==========================================
# def load_data():
#     global device_db, global_stats, mac_vendor_cache
#     if os.path.exists(DB_FILE):
#         try:
#             with open(DB_FILE, "r") as f:
#                 data = json.load(f)
#             if data["stats"].get("last_save_date") == str(datetime.now().date()):
#                 global_stats.update(data["stats"])
#                 global_stats["wan_apps"] = defaultdict(
#                     int, data["stats"].get("wan_apps", {})
#                 )
#                 for mac, info in data["devices"].items():
#                     device_db[mac].update(info)
#                     device_db[mac]["Apps"] = defaultdict(int, info["Apps"])
#                     device_db[mac]["Prev_Total"] = (
#                         info["Total_Internet"] + info["Total_Local"]
#                     )
#                     if "Vendor" in info:
#                         mac_vendor_cache[mac] = info["Vendor"]
#                 print(f"✅ Data Loaded. Resuming...")
#             else:
#                 print("📅 New Day Detected. Resetting.")
#         except Exception as e:
#             print(f"⚠️ Load Error: {e}")


# def save_data():
#     with lock:
#         s_devs = {}
#         for k, v in device_db.items():
#             s_devs[k] = dict(v)
#             s_devs[k]["Apps"] = dict(v["Apps"])
#             if "Prev_Total" in s_devs[k]:
#                 del s_devs[k]["Prev_Total"]
#             if "Current_Speed" in s_devs[k]:
#                 del s_devs[k]["Current_Speed"]
#         stats_copy = dict(global_stats)
#         stats_copy["wan_apps"] = dict(global_stats["wan_apps"])
#         data = {"stats": stats_copy, "devices": s_devs}
#         global_stats["last_save_date"] = str(datetime.now().date())
#         try:
#             with open(DB_FILE, "w") as f:
#                 json.dump(data, f, indent=4)
#         except:
#             pass


# # ==========================================
# # 🧠 الفلاتر والمعالجة
# # ==========================================
# APP_PATTERNS = {
#     "YouTube": re.compile(r"(youtube|googlevideo|ytimg|youtu\.be)", re.IGNORECASE),
#     "Facebook": re.compile(r"(facebook|fbcdn|fbsbx|messenger)", re.IGNORECASE),
#     "Instagram": re.compile(r"(instagram|cdninstagram)", re.IGNORECASE),
#     "WhatsApp": re.compile(r"(whatsapp|g\.whatsapp)", re.IGNORECASE),
#     "TikTok": re.compile(r"(tiktok|byteoversea|ibyteimg)", re.IGNORECASE),
#     "Google": re.compile(r"(google|gstatic|gmail)", re.IGNORECASE),
#     "Apple": re.compile(r"(apple|icloud|itunes)", re.IGNORECASE),
#     "Netflix": re.compile(r"(netflix|nflxvideo)", re.IGNORECASE),
#     "Twitter": re.compile(r"(twitter|twimg|x\.com)", re.IGNORECASE),
#     "Snapchat": re.compile(r"(snapchat|sc-cdn)", re.IGNORECASE),
#     "Telegram": re.compile(r"(telegram|t\.me)", re.IGNORECASE),
#     "Pubg": re.compile(r"(pubg|tencent)", re.IGNORECASE),
#     "Zoom": re.compile(r"(zoom\.us|zoom)", re.IGNORECASE),
#     "Microsoft": re.compile(
#         r"(microsoft|windowsupdate|live\.com|office)", re.IGNORECASE
#     ),
# }
# APP_PORT_HINTS = {
#     5228: "WhatsApp",
#     443: "HTTPS (Web)",
#     80: "HTTP (Web)",
#     53: "DNS",
#     1935: "Streaming",
#     22: "SSH",
# }


# def is_private_ip(ip):
#     return ip.startswith("192.168.") or ip.startswith("10.")


# def identify_app(domain):
#     if not domain:
#         return None
#     d = domain.lower()
#     for name, pat in APP_PATTERNS.items():
#         if pat.search(d):
#             return name
#     return "Other/Web"


# def parse_sni(payload):
#     try:
#         idx = payload.tobytes().find(b"\x00\x00")
#         if idx != -1:
#             m = re.search(
#                 b"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}",
#                 payload.tobytes(),
#             )
#             if m:
#                 return m.group(0).decode("utf-8", errors="ignore")
#     except:
#         pass
#     return None


# def format_duration(seconds):
#     m, s = divmod(int(seconds), 60)
#     h, m = divmod(m, 60)
#     return f"{h:02d}:{m:02d}:{s:02d}"


# # Helper Functions
# def get_vendor_online(mac):
#     try:
#         url = f"https://api.macvendors.com/{mac}"
#         req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
#         with urllib.request.urlopen(req, timeout=3) as r:
#             return r.read().decode("utf-8")
#     except:
#         return ""


# def resolve_vendor(mac):
#     if mac in mac_vendor_cache:
#         return
#     local = {"8A:AF:98": "Apple", "00:28:F8": "Intel", "9A:15:22": "Apple"}
#     p = mac[:8].upper()
#     if p in local:
#         mac_vendor_cache[mac] = local[p]
#         with lock:
#             device_db[mac]["Vendor"] = local[p]
#     else:
#         v = get_vendor_online(mac)
#         with lock:
#             mac_vendor_cache[mac] = v
#             device_db[mac]["Vendor"] = v


# def trigger_vendor(mac):
#     if mac != global_stats["host_mac"] and not device_db[mac]["Vendor"]:
#         threading.Thread(target=resolve_vendor, args=(mac,), daemon=True).start()


# def analyze_traffic_layer(packet):
#     global ip_to_app_map
#     app_detected = None
#     try:
#         if packet.haslayer(DNS) and packet[DNS].qr == 1:
#             for i in range(packet[DNS].ancount):
#                 if packet[DNS].an[i].type == 1:
#                     d = packet[DNS].an[i].rrname.decode("utf-8", "ignore").strip(".")
#                     app = identify_app(d)
#                     if app:
#                         with lock:
#                             ip_to_app_map[packet[DNS].an[i].rdata] = (
#                                 app,
#                                 time.time() + 300,
#                             )
#     except:
#         pass
#     try:
#         if packet.haslayer(TCP) and packet.haslayer("Raw"):
#             if packet[TCP].dport == 443 or packet[TCP].srcport == 443:
#                 d = parse_sni(packet["Raw"].load)
#                 if d:
#                     app_detected = identify_app(d)
#             if not app_detected:
#                 port = (
#                     packet[TCP].dport
#                     if packet.haslayer(IP) and packet[IP].src.startswith(HOTSPOT_SUBNET)
#                     else packet[TCP].sport
#                 )
#                 app_detected = APP_PORT_HINTS.get(port)
#             if app_detected:
#                 ip_target = (
#                     packet[IP].dst if packet[TCP].dport == 443 else packet[IP].src
#                 )
#                 with lock:
#                     ip_to_app_map[ip_target] = (app_detected, time.time() + 300)
#     except:
#         pass
#     return app_detected


# def process_client_packet(packet):
#     try:
#         if not packet.haslayer(IP) or not packet.haslayer(Ether):
#             return
#         src, dst, plen = packet[IP].src, packet[IP].dst, len(packet)
#         if src == "127.0.0.1":
#             return
#         detected = analyze_traffic_layer(packet)
#         t_mac, t_ip, is_local = None, None, False
#         if src.startswith(HOTSPOT_SUBNET):
#             t_mac, t_ip = packet[Ether].src, src
#             cached = ip_to_app_map.get(dst, (None,))[0]
#             if is_private_ip(dst):
#                 is_local = True
#         elif dst.startswith(HOTSPOT_SUBNET):
#             t_mac, t_ip = packet[Ether].dst, dst
#             cached = ip_to_app_map.get(src, (None,))[0]
#             if is_private_ip(src):
#                 is_local = True
#         if t_ip == HOTSPOT_GATEWAY:
#             return
#         if t_mac:
#             with lock:
#                 trigger_vendor(t_mac)
#                 d = device_db[t_mac]
#                 if d["IP"] != "Unknown" and d["IP"] != t_ip:
#                     d["IP_Log"] = f"{d['IP']} > {t_ip}"
#                 d["LastSeen"], d["IP"] = time.time(), t_ip
#                 if d["Name"] == "Unknown":
#                     d["Name"] = KNOWN_DEVICES.get(t_mac, f"Device")
#                 if is_local:
#                     d["Total_Local"] += plen
#                     d["Apps"]["LAN/Local"] += plen
#                     global_stats["clients_local"] += plen
#                 else:
#                     d["Total_Internet"] += plen
#                     app = detected if detected else (cached if cached else "Other/Web")
#                     d["Apps"][app] += plen
#                     global_stats["clients_internet"] += plen
#     except:
#         pass


# def process_wan_packet(packet):
#     try:
#         if packet.haslayer(IP):
#             plen = len(packet)
#             with lock:
#                 global_stats["wan_total"] += plen
#             app = analyze_traffic_layer(packet)
#             if app:
#                 with lock:
#                     global_stats["wan_apps"][app] += plen
#             else:
#                 src, dst = packet[IP].src, packet[IP].dst
#                 cached = (
#                     ip_to_app_map.get(src, (None,))[0]
#                     or ip_to_app_map.get(dst, (None,))[0]
#                 )
#                 final_app = cached if cached else "Other/Web"
#                 with lock:
#                     global_stats["wan_apps"][final_app] += plen
#     except:
#         pass


# def update_calculations():
#     with lock:
#         host_u = max(0, global_stats["wan_total"] - global_stats["clients_internet"])
#         hm = global_stats["host_mac"]
#         host_dev = device_db[hm]
#         host_dev["Name"], host_dev["Vendor"], host_dev["IP"] = (
#             "MY LAPTOP",
#             "Host",
#             host_ip,
#         )
#         host_dev["Total_Internet"], host_dev["LastSeen"] = host_u, time.time()
#         clients_apps_sum = defaultdict(int)
#         for mac, dev in device_db.items():
#             if mac == hm:
#                 continue
#             for app, usage in dev["Apps"].items():
#                 if app != "LAN/Local":
#                     clients_apps_sum[app] += usage
#         host_dev["Apps"] = defaultdict(int)
#         for app, total_usage in global_stats["wan_apps"].items():
#             client_usage = clients_apps_sum.get(app, 0)
#             host_specific_usage = max(0, total_usage - client_usage)
#             if host_specific_usage > 0:
#                 host_dev["Apps"][app] = host_specific_usage
#         for mac, dev in device_db.items():
#             curr = dev["Total_Internet"] + dev["Total_Local"]
#             dev["Current_Speed"] = max(0, (curr - dev["Prev_Total"]) / 1)
#             dev["Prev_Total"] = curr


# # ==========================================
# # 🚀 Flask & Main
# # ==========================================
# @app.route("/")
# def index():
#     return render_template("dashboard.html")


# @app.route("/data")
# def get_data():
#     update_calculations()
#     save_data()
#     with lock:
#         devices_list = []
#         for mac, dev in device_db.items():
#             sorted_apps = sorted(dev["Apps"].items(), key=lambda x: x[1], reverse=True)
#             apps_list = [{"name": k, "usage": v} for k, v in sorted_apps if v > 0]
#             devices_list.append(
#                 {
#                     "mac": mac,
#                     "name": dev["Name"],
#                     "vendor": dev["Vendor"][:15],
#                     "ip": dev["IP"],
#                     "speed": dev["Current_Speed"],
#                     "total_net": dev["Total_Internet"],
#                     "total_loc": dev["Total_Local"],
#                     "ip_log": dev["IP_Log"],
#                     "apps": apps_list,
#                     "is_host": mac == global_stats["host_mac"],
#                 }
#             )
#         return jsonify(
#             {
#                 "stats": {
#                     "wan": global_stats["wan_total"],
#                     "clients_net": global_stats["clients_internet"],
#                     "clients_loc": global_stats["clients_local"],
#                     "host_usage": device_db[global_stats["host_mac"]]["Total_Internet"],
#                     "runtime": format_duration(
#                         time.time() - global_stats["start_time"]
#                     ),
#                 },
#                 "devices": devices_list,
#             }
#         )


# def main():
#     global host_ip
#     os.system("cls" if os.name == "nt" else "clear")
#     load_data()
#     print(f"\n🌐 Starting Monitor V17.1 (Fixed Colors)...")
#     ifaces = get_if_list()
#     h_idx, w_idx = -1, -1
#     for i, iface in enumerate(ifaces):
#         try:
#             ip = get_if_addr(iface)
#         except:
#             ip = "N/A"
#         label = ""
#         if ip.startswith(HOTSPOT_SUBNET):
#             label = " ← HOTSPOT"
#             h_idx = i
#         elif ip.startswith("192.168.") and not ip.endswith(".1") and ip != "N/A":
#             label = " ← WAN"
#             w_idx = i
#         print(f"[{i}] {iface:<40} {ip:<15} {label}")
#     try:
#         h_sel = int(input(f"\n👉 Hotspot [{h_idx}]: ") or h_idx)
#         w_sel = int(input(f"👉 WAN [{w_idx}]: ") or w_idx)
#         host_ip = get_if_addr(ifaces[w_sel])

#         t1 = threading.Thread(
#             target=lambda: sniff(
#                 iface=ifaces[h_sel],
#                 prn=process_client_packet,
#                 store=0,
#                 filter="ip",
#                 promisc=False,
#             ),
#             daemon=True,
#         )
#         t2 = threading.Thread(
#             target=lambda: sniff(
#                 iface=ifaces[w_sel],
#                 prn=process_wan_packet,
#                 store=0,
#                 filter="ip",
#                 promisc=False,
#             ),
#             daemon=True,
#         )
#         t1.start()
#         t2.start()

#         print(f"\n🚀 Dashboard: http://127.0.0.1:{WEB_PORT}")
#         print("📝 Edit 'templates/dashboard.html' to customize UI.")
#         app.run(host="0.0.0.0", port=WEB_PORT, debug=False, use_reloader=False)
#     except Exception as e:
#         print(f"Error: {e}")


# if __name__ == "__main__":
#     main()
import sys
import time
import os
import threading
import re
import json
import urllib.request
from datetime import datetime
from collections import defaultdict
from scapy.all import (
    sniff,
    get_if_list,
    get_if_addr,
    conf,
    DNS,
    IP,
    TCP,
    UDP,
    Ether,
    ARP,
)
from flask import Flask, jsonify, render_template_string, render_template
import logging

# ==========================================
# 📝 إعدادات المستخدم
# ==========================================
KNOWN_DEVICES = {
    "8a:af:98:60:2d:ee": "iPhone 11",
    "00:28:f8:c6:ba:8d": "Laptop HP",
    "9a:15:22:de:92:f9": "iPhone 13",
    "70:1f:3c:3b:83:23": "Tablet",
    "12:0f:06:c3:2b:e6": "Hawawi",
    "fe:ef:d9:d0:8f:c8": "Relme omo haga",
}

HOTSPOT_SUBNET = "192.168.137."
HOTSPOT_GATEWAY = "192.168.137.1"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(SCRIPT_DIR, "traffic_data.json")
DAILY_REPORTS_DIR = os.path.join(SCRIPT_DIR, "daily_reports")
TEMPLATE_DIR = os.path.join(SCRIPT_DIR, "templates")
TEMPLATE_FILE = os.path.join(TEMPLATE_DIR, "dashboard.html")
WEB_PORT = 5000

# 🔥 إعدادات DNS History (في الذاكرة فقط)
MAX_DNS_HISTORY = 50  # احتفظ بآخر 50 domain فقط لكل جهاز
MAX_DOMAIN_COUNT = 100  # احتفظ بأول 100 domain الأكثر زيارة

# إنشاء مجلد التقارير اليومية
if not os.path.exists(DAILY_REPORTS_DIR):
    os.makedirs(DAILY_REPORTS_DIR)

# ==========================================
# 🌐 قاعدة بيانات المواقع الموسعة
# ==========================================
DETAILED_SITE_PATTERNS = {
    # Social Media
    "Facebook": [
        r"facebook\.com",
        r"fbcdn\.net",
        r"fbsbx\.com",
        r"messenger\.com",
        r"fb\.me",
        r"facebook-hardware\.com",
        r"m\.facebook\.com",
    ],
    "Instagram": [
        r"instagram\.com",
        r"cdninstagram\.com",
        r"instagramstatic\.com",
        r"instagramusercontent\.com",
        r"ig\.me",
    ],
    "TikTok": [
        r"tiktok\.com",
        r"tiktokcdn\.com",
        r"byteoversea\.com",
        r"ibyteimg\.com",
        r"musical\.ly",
        r"tiktokv\.com",
    ],
    "Twitter/X": [r"twitter\.com", r"twimg\.com", r"x\.com", r"t\.co"],
    "WhatsApp": [r"whatsapp\.com", r"whatsapp\.net", r"g\.whatsapp\.com", r"wa\.me"],
    "Snapchat": [r"snapchat\.com", r"sc-cdn\.net", r"snap-dev\.net", r"snapads\.com"],
    "Telegram": [r"telegram\.org", r"t\.me", r"telesco\.pe", r"telegram\.me"],
    "LinkedIn": [r"linkedin\.com", r"licdn\.com"],
    "Reddit": [r"reddit\.com", r"redd\.it", r"redditmedia\.com"],
    # Video Streaming
    "YouTube": [
        r"youtube\.com",
        r"googlevideo\.com",
        r"ytimg\.com",
        r"youtu\.be",
        r"youtube-nocookie\.com",
        r"yt3\.ggpht\.com",
    ],
    "Netflix": [
        r"netflix\.com",
        r"nflxvideo\.net",
        r"nflxso\.net",
        r"nflxext\.com",
        r"nflximg\.net",
    ],
    "Shahid": [r"shahid\.mbc\.net", r"shahid\.net", r"mbc\.net"],
    "Watch iT": [r"watchit\.com", r"watchit\.net"],
    "Disney+": [r"disneyplus\.com", r"disney\.com"],
    "Twitch": [r"twitch\.tv", r"ttvnw\.net"],
    "Vimeo": [r"vimeo\.com", r"vimeocdn\.com"],
    # Gaming
    "PUBG Mobile": [
        r"pubgmobile\.com",
        r"igamecj\.com",
        r"gameloop\.com",
        r"tencent\.com",
        r"pubg\.com",
    ],
    "Free Fire": [r"freefire\.com", r"ff\.garena\.com", r"garena\.com"],
    "Roblox": [r"roblox\.com", r"rbxcdn\.com"],
    "Fortnite": [r"fortnite\.com", r"epicgames\.com"],
    "Call of Duty": [r"callofduty\.com", r"activision\.com"],
    "Clash of Clans": [r"clashofclans\.com", r"supercell\.com"],
    "Minecraft": [r"minecraft\.net", r"mojang\.com"],
    # Google Services
    "Google Search": [r"google\.com", r"google\.com\.eg", r"www\.google\."],
    "Gmail": [r"mail\.google\.com", r"gmail\.com"],
    "Google Drive": [
        r"drive\.google\.com",
        r"docs\.google\.com",
        r"sheets\.google\.com",
    ],
    "Google Meet": [r"meet\.google\.com"],
    "YouTube Music": [r"music\.youtube\.com"],
    "Google Maps": [r"maps\.google\.com", r"maps\.gstatic\.com"],
    "Google Photos": [r"photos\.google\.com"],
    "Google Play": [r"play\.google\.com"],
    # Microsoft
    "Teams": [r"teams\.microsoft\.com", r"teams\.live\.com"],
    "OneDrive": [r"onedrive\.live\.com", r"1drv\.ms"],
    "Outlook": [r"outlook\.live\.com", r"outlook\.office365\.com"],
    "Office 365": [r"office\.com", r"office365\.com"],
    "Skype": [r"skype\.com", r"skypeassets\.com"],
    # E-commerce
    "Amazon": [r"amazon\.com", r"amazon\.eg", r"amazonpay\.com"],
    "Noon": [r"noon\.com"],
    "Jumia": [r"jumia\.com\.eg"],
    "AliExpress": [r"aliexpress\.com", r"alibaba\.com"],
    "eBay": [r"ebay\.com"],
    # News & Media
    "BBC": [r"bbc\.com", r"bbc\.co\.uk"],
    "CNN": [r"cnn\.com"],
    "AlJazeera": [r"aljazeera\.net", r"aljazeera\.com"],
    "Youm7": [r"youm7\.com"],
    "Masrawy": [r"masrawy\.com"],
    "Elwatan": [r"elwatannews\.com"],
    # Banking (البنوك المصرية)
    "Banking": [
        r"nbe\.com\.eg",
        r"banquemisr\.com",
        r"cibeg\.com",
        r"alexbank\.com",
        r"aaib\.com",
        r"qnb\.com",
    ],
    # Music & Audio
    "Spotify": [r"spotify\.com", r"scdn\.co"],
    "Anghami": [r"anghami\.com"],
    "Apple Music": [r"music\.apple\.com"],
    "SoundCloud": [r"soundcloud\.com"],
    # Education
    "Coursera": [r"coursera\.org"],
    "Udemy": [r"udemy\.com"],
    "Khan Academy": [r"khanacademy\.org"],
    "Zoom": [r"zoom\.us", r"zoom\.com"],
    # Apple Services
    "Apple": [
        r"apple\.com",
        r"icloud\.com",
        r"itunes\.com",
        r"cdn-apple\.com",
        r"mzstatic\.com",
    ],
    # Content Delivery / CDN
    "Cloudflare": [r"cloudflare\.com", r"cdnjs\.cloudflare\.com"],
    "Akamai": [r"akamai\.net", r"akamaihd\.net"],
    # Other Popular
    "Wikipedia": [r"wikipedia\.org", r"wikimedia\.org"],
    "WordPress": [r"wordpress\.com", r"wp\.com"],
    "GitHub": [r"github\.com", r"githubusercontent\.com"],
    "Stack Overflow": [r"stackoverflow\.com", r"stackexchange\.com"],
}

APP_PORT_HINTS = {
    5228: "WhatsApp",
    5222: "WhatsApp/Jabber",
    443: "HTTPS",
    80: "HTTP",
    53: "DNS",
    1935: "RTMP Streaming",
    22: "SSH",
    3478: "STUN (VoIP)",
    5060: "SIP (VoIP)",
}

# ==========================================
# 📄 HTML Template المحسّن
# ==========================================
ENHANCED_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Monitor V18.0 Enhanced</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body { background-color: #0d1117; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; }
        .card { background-color: #161b22; border: 1px solid #30363d; margin-bottom: 15px; border-radius: 10px; }
        .stat-box { background: #1c2128; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #30363d; }
        .stat-val { font-size: 1.5rem; font-weight: bold; color: #58a6ff; }
        .stat-label { font-size: 0.9rem; color: #8b949e; }
        .device-name { color: #58a6ff; font-weight: bold; font-size: 1.1rem; }
        .vendor-badge { font-size: 0.75rem; background: #21262d; padding: 2px 8px; border-radius: 4px; color: #f78166; margin-left: 5px; }
        .speed-indicator { font-weight: bold; }
        .speed-high { color: #f85149; }
        .speed-medium { color: #d29922; }
        .speed-low { color: #3fb950; }
        
        .app-row { font-size: 0.85rem; padding: 4px 0; display: flex; justify-content: space-between; color: #c9d1d9; }
        .usage-text { color: #8b949e; }
        .device-meta { color: #8b949e; font-size: 0.85rem; margin-bottom: 10px; }
        .device-meta i { color: #58a6ff; width: 20px; text-align: center; }
        .progress { height: 6px; background-color: #21262d; border-radius: 3px; }
        .progress-bar { background: linear-gradient(90deg, #58a6ff 0%, #1f6feb 100%); }
        .ip-changed { color: #f85149; font-size: 0.8rem; animation: blink 2s infinite; }
        .sort-timer { font-size: 0.8rem; color: #6e7681; }
        @keyframes blink { 50% { opacity: 0.5; } }
        
        .btn-details { 
            background: #238636; 
            border: none; 
            color: white; 
            padding: 4px 12px; 
            border-radius: 6px; 
            font-size: 0.85rem;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn-details:hover { background: #2ea043; }
        
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; 
                 overflow: auto; background-color: rgba(0,0,0,0.8); }
        .modal-content { 
            background-color: #161b22; 
            margin: 5% auto; 
            padding: 20px; 
            border: 1px solid #30363d; 
            border-radius: 10px;
            width: 90%; 
            max-width: 900px; 
            color: #c9d1d9;
        }
        .close { color: #8b949e; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
        .close:hover { color: #f85149; }
        
        .site-entry { 
            background: #21262d; 
            padding: 8px 12px; 
            margin: 5px 0; 
            border-radius: 6px; 
            display: flex; 
            justify-content: space-between;
            border-left: 3px solid #58a6ff;
        }
        .domain-name { color: #58a6ff; font-weight: 500; }
        .visit-count { color: #8b949e; font-size: 0.85rem; }
        .timestamp { color: #6e7681; font-size: 0.75rem; }
        
        .tabs { display: flex; border-bottom: 2px solid #21262d; margin-bottom: 20px; }
        .tab { 
            padding: 10px 20px; 
            cursor: pointer; 
            color: #8b949e; 
            border-bottom: 2px solid transparent;
            transition: all 0.3s;
        }
        .tab.active { color: #58a6ff; border-bottom-color: #58a6ff; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-bottom: 20px; }
        .mini-stat { background: #21262d; padding: 10px; border-radius: 6px; text-align: center; }
        .mini-stat-value { font-size: 1.2rem; color: #58a6ff; font-weight: bold; }
        .mini-stat-label { font-size: 0.8rem; color: #8b949e; }
        
        /* Content Type Icons & Colors */
        .content-type-box { 
            background: #21262d; 
            padding: 8px; 
            border-radius: 6px; 
            margin: 3px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-left: 3px solid;
        }
        .ct-images { border-left-color: #f85149; }
        .ct-videos { border-left-color: #d29922; }
        .ct-streaming { border-left-color: #a371f7; }
        .ct-audio { border-left-color: #3fb950; }
        .ct-text { border-left-color: #58a6ff; }
        .ct-documents { border-left-color: #f78166; }
        .ct-downloads { border-left-color: #79c0ff; }
        .ct-other { border-left-color: #6e7681; }
        
        .content-icon { font-size: 1.2rem; margin-right: 8px; }
    </style>
</head>
<body>
    <div class="container py-4">
        <div class="row mb-4">
            <div class="col-md-3"><div class="stat-box"><div class="stat-val" id="wan-total">0 MB</div><div class="stat-label">🌐 WAN (Internet)</div></div></div>
            <div class="col-md-3"><div class="stat-box"><div class="stat-val text-warning" id="clients-net">0 MB</div><div class="stat-label">🔥 Clients (Net)</div></div></div>
            <div class="col-md-3"><div class="stat-box"><div class="stat-val text-info" id="clients-loc">0 MB</div><div class="stat-label">🏠 Local (LAN)</div></div></div>
            <div class="col-md-3"><div class="stat-box"><div class="stat-val" id="host-total">0 MB</div><div class="stat-label">💻 Laptop (Host)</div></div></div>
        </div>
        
        <div class="d-flex justify-content-between mb-3 align-items-center">
            <span class="text-muted"><i class="fas fa-clock"></i> Runtime: <span id="session-time">00:00:00</span></span>
            <span class="sort-timer"><i class="fas fa-sort-amount-down"></i> Next Reorder: <span id="sort-countdown">15:00</span></span>
            <span class="text-success" id="connection-status">● Live</span>
        </div>

        <div class="row" id="devices-container"></div>
    </div>

    <!-- Modal للتفاصيل -->
    <div id="detailsModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <h3 id="modal-title" style="color: #58a6ff; margin-bottom: 20px;"></h3>
            
            <div class="tabs">
                <div class="tab active" onclick="switchTab('top-sites')">🔥 Most Visited</div>
                <div class="tab" onclick="switchTab('recent')">🕐 Recent Activity</div>
                <div class="tab" onclick="switchTab('stats')">📊 Statistics</div>
            </div>
            
            <div id="top-sites" class="tab-content active"></div>
            <div id="recent" class="tab-content"></div>
            <div id="stats" class="tab-content"></div>
        </div>
    </div>

    <script>
        let cachedOrder = [];
        let nextSortTime = 0;
        const SORT_INTERVAL_MS = 15 * 60 * 1000;

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function formatSpeed(bps) {
            if (bps < 1024) return bps.toFixed(0) + ' B/s';
            if (bps < 1024*1024) return (bps/1024).toFixed(1) + ' KB/s';
            return (bps/(1024*1024)).toFixed(2) + ' MB/s';
        }

        function getSpeedClass(bps) {
            if (bps > 1024*1024) return 'speed-high';
            if (bps > 100*1024) return 'speed-medium';
            return 'speed-low';
        }

        function formatTimeLeft(ms) {
            if (ms < 0) return "00:00";
            const totalSeconds = Math.floor(ms / 1000);
            const m = Math.floor(totalSeconds / 60);
            const s = totalSeconds % 60;
            return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
        }

        function formatTimestamp(ts) {
            const date = new Date(ts * 1000);
            return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
        }

        async function showDeviceDetails(mac) {
            try {
                const response = await fetch(`/device/${mac}/history`);
                const data = await response.json();
                
                document.getElementById('modal-title').innerText = `📱 ${data.device.name} (${data.device.ip})`;
                
                // Top Sites
                let topHtml = '<h5 style="color: #58a6ff; margin-bottom: 15px;">Most Visited Websites</h5>';
                data.top_sites.slice(0, 20).forEach(site => {
                    topHtml += `
                        <div class="site-entry">
                            <span class="domain-name">${site.domain}</span>
                            <span class="visit-count">${site.visits} visits • ${formatBytes(site.usage)}</span>
                        </div>
                    `;
                });
                document.getElementById('top-sites').innerHTML = topHtml || '<p style="color: #6e7681;">No data available</p>';
                
                // Recent
                let recentHtml = '<h5 style="color: #58a6ff; margin-bottom: 15px;">Recent Activity (Last 50)</h5>';
                data.recent_sites.slice().reverse().forEach(site => {
                    recentHtml += `
                        <div class="site-entry">
                            <div>
                                <span class="domain-name">${site.domain}</span>
                                <div class="timestamp">${formatTimestamp(site.timestamp)}</div>
                            </div>
                            <span class="visit-count">${site.category}</span>
                        </div>
                    `;
                });
                document.getElementById('recent').innerHTML = recentHtml || '<p style="color: #6e7681;">No recent activity</p>';
                
                // Stats
                let statsHtml = '<h5 style="color: #58a6ff; margin-bottom: 15px;">Device Statistics</h5>';
                statsHtml += '<div class="stats-grid">';
                statsHtml += `
                    <div class="mini-stat">
                        <div class="mini-stat-value">${data.stats.total_domains}</div>
                        <div class="mini-stat-label">Unique Domains</div>
                    </div>
                    <div class="mini-stat">
                        <div class="mini-stat-value">${data.stats.total_visits}</div>
                        <div class="mini-stat-label">Total Visits</div>
                    </div>
                    <div class="mini-stat">
                        <div class="mini-stat-value">${formatBytes(data.stats.total_usage)}</div>
                        <div class="mini-stat-label">Total Data</div>
                    </div>
                    <div class="mini-stat">
                        <div class="mini-stat-value">${data.stats.active_time}</div>
                        <div class="mini-stat-label">Active Time</div>
                    </div>
                `;
                statsHtml += '</div>';
                
                // Category breakdown
                statsHtml += '<h6 style="color: #58a6ff; margin: 20px 0 10px 0;">Usage by Category</h6>';
                Object.entries(data.stats.categories).forEach(([cat, usage]) => {
                    const pct = (usage / data.stats.total_usage * 100).toFixed(1);
                    statsHtml += `
                        <div class="site-entry">
                            <span class="domain-name">${cat}</span>
                            <span class="visit-count">${formatBytes(usage)} (${pct}%)</span>
                        </div>
                    `;
                });
                
                // Content Types breakdown
                statsHtml += '<h6 style="color: #58a6ff; margin: 20px 0 10px 0;">📊 Content Types</h6>';
                const contentIcons = {
                    'images': '🖼️ Images',
                    'videos': '🎬 Videos',
                    'streaming': '📺 Streaming',
                    'audio': '🎵 Audio',
                    'text': '📄 Web Pages',
                    'documents': '📁 Documents',
                    'downloads': '⬇️ Downloads',
                    'other': '📦 Other'
                };
                
                const contentEntries = Object.entries(data.stats.content_types || {})
                    .filter(([_, usage]) => usage > 0)
                    .sort((a, b) => b[1] - a[1]);
                
                if (contentEntries.length > 0) {
                    contentEntries.forEach(([type, usage]) => {
                        const pct = (usage / data.stats.total_usage * 100).toFixed(1);
                        statsHtml += `
                            <div class="site-entry">
                                <span class="domain-name">${contentIcons[type] || type}</span>
                                <span class="visit-count">${formatBytes(usage)} (${pct}%)</span>
                            </div>
                        `;
                    });
                } else {
                    statsHtml += '<p style="color: #6e7681;">No content type data available</p>';
                }
                
                document.getElementById('stats').innerHTML = statsHtml;
                
                document.getElementById('detailsModal').style.display = 'block';
            } catch (error) {
                console.error('Error loading details:', error);
            }
        }

        function closeModal() {
            document.getElementById('detailsModal').style.display = 'none';
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        }

        window.onclick = function(event) {
            if (event.target == document.getElementById('detailsModal')) {
                closeModal();
            }
        }

        async function updateDashboard() {
            try {
                const response = await fetch('/data');
                const data = await response.json();
                
                document.getElementById('wan-total').innerText = formatBytes(data.stats.wan);
                document.getElementById('clients-net').innerText = formatBytes(data.stats.clients_net);
                document.getElementById('clients-loc').innerText = formatBytes(data.stats.clients_loc);
                document.getElementById('host-total').innerText = formatBytes(data.stats.host_usage);
                document.getElementById('session-time').innerText = data.stats.runtime;

                const now = Date.now();
                if (now > nextSortTime || cachedOrder.length === 0) {
                    data.devices.sort((a, b) => {
                        if (a.is_host) return -1;
                        if (b.is_host) return 1;
                        return b.speed - a.speed;
                    });
                    cachedOrder = data.devices.map(d => d.mac);
                    nextSortTime = now + SORT_INTERVAL_MS;
                } else {
                    data.devices.sort((a, b) => {
                        let idxA = cachedOrder.indexOf(a.mac);
                        let idxB = cachedOrder.indexOf(b.mac);
                        if (idxA === -1) idxA = 9999;
                        if (idxB === -1) idxB = 9999;
                        return idxA - idxB;
                    });
                }

                document.getElementById('sort-countdown').innerText = formatTimeLeft(nextSortTime - now);

                const container = document.getElementById('devices-container');
                container.innerHTML = ''; 

                data.devices.forEach(dev => {
                    const total = dev.total_net + dev.total_loc;
                    let appsHtml = '';
                    
                    dev.apps.slice(0, 5).forEach(app => {
                        const pct = total > 0 ? (app.usage / total * 100).toFixed(1) : 0;
                        appsHtml += `
                            <div class="app-row">
                                <span>${app.name}</span>
                                <span class="usage-text">${formatBytes(app.usage)} <span style="color:#6e7681">(${pct}%)</span></span>
                            </div>
                            <div class="progress mb-2">
                                <div class="progress-bar" style="width: ${pct}%"></div>
                            </div>
                        `;
                    });
                    
                    // عرض نوع المحتوى
                    let contentHtml = '<div style="margin-top: 15px;"><strong style="color: #8b949e; font-size: 0.9rem;">📊 Content Types:</strong></div>';
                    
                    const contentIcons = {
                        'images': '🖼️',
                        'videos': '🎬',
                        'streaming': '📺',
                        'audio': '🎵',
                        'text': '📄',
                        'documents': '📁',
                        'downloads': '⬇️',
                        'other': '📦'
                    };
                    
                    const contentLabels = {
                        'images': 'Images',
                        'videos': 'Videos',
                        'streaming': 'Streaming',
                        'audio': 'Audio',
                        'text': 'Web Pages',
                        'documents': 'Documents',
                        'downloads': 'Downloads',
                        'other': 'Other'
                    };
                    
                    // ترتيب حسب الاستهلاك
                    const contentArray = Object.entries(dev.content_types || {})
                        .filter(([_, usage]) => usage > 0)
                        .sort((a, b) => b[1] - a[1])
                        .slice(0, 4);
                    
                    if (contentArray.length > 0) {
                        contentArray.forEach(([type, usage]) => {
                            const pct = total > 0 ? (usage / total * 100).toFixed(1) : 0;
                            contentHtml += `
                                <div class="content-type-box ct-${type}">
                                    <span>
                                        <span class="content-icon">${contentIcons[type] || '📦'}</span>
                                        ${contentLabels[type] || type}
                                    </span>
                                    <span style="color: #8b949e; font-size: 0.85rem;">
                                        ${formatBytes(usage)} (${pct}%)
                                    </span>
                                </div>
                            `;
                        });
                    } else {
                        contentHtml += '<p style="color: #6e7681; font-size: 0.85rem; margin: 5px 0;">No data yet...</p>';
                    }

                    const speedClass = getSpeedClass(dev.speed);
                    const ipAlert = dev.ip_log ? `<div class="ip-changed"><i class="fas fa-exclamation-triangle"></i> ${dev.ip_log}</div>` : '';

                    const cardHtml = `
                        <div class="col-md-6 col-lg-4">
                            <div class="card h-100">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between align-items-center mb-2">
                                        <div>
                                            <span class="device-name">${dev.name}</span>
                                            <span class="vendor-badge">${dev.vendor}</span>
                                        </div>
                                        <div class="${speedClass} speed-indicator">
                                            <i class="fas fa-tachometer-alt"></i> ${formatSpeed(dev.speed)}
                                        </div>
                                    </div>
                                    
                                    <div class="device-meta">
                                        <div><i class="fas fa-network-wired"></i> ${dev.ip} • <span style="color: #6e7681">${dev.mac}</span></div>
                                        <div><i class="fas fa-globe"></i> Net: ${formatBytes(dev.total_net)} | <i class="fas fa-home"></i> Loc: ${formatBytes(dev.total_loc)}</div>
                                        <div><i class="fas fa-chart-line"></i> Domains: ${dev.unique_domains} | Visits: ${dev.total_visits}</div>
                                        ${ipAlert}
                                    </div>
                                    
                                    <div class="d-flex justify-content-between align-items-center mb-2">
                                        <button class="btn-details" onclick="showDeviceDetails('${dev.mac}')">
                                            <i class="fas fa-info-circle"></i> View Details
                                        </button>
                                    </div>
                                    
                                    <hr class="border-secondary">
                                    <div class="mt-2">
                                        ${appsHtml}
                                        ${contentHtml}
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                    container.innerHTML += cardHtml;
                });

                document.getElementById('connection-status').innerText = '● Live';
                document.getElementById('connection-status').className = 'text-success';

            } catch (error) {
                document.getElementById('connection-status').innerText = '🔴 Disconnected';
                document.getElementById('connection-status').className = 'text-danger';
            }
        }
        
        setInterval(updateDashboard, 1000);
        updateDashboard();
    </script>
</body>
</html>
"""

# ==========================================
# 💾 المتغيرات العالمية المحسّنة
# ==========================================
if not os.path.exists(TEMPLATE_DIR):
    os.makedirs(TEMPLATE_DIR)
with open(TEMPLATE_FILE, "w", encoding="utf-8") as f:
    f.write(ENHANCED_HTML)

lock = threading.RLock()
app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.config["TEMPLATES_AUTO_RELOAD"] = True
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

# 🔥 ARP Cache للربط بين IP و MAC
arp_cache = {}
ip_to_mac_cache = {}

# 🔥 DNS History - في الذاكرة فقط (مش هنحفظها في ملف)
dns_history = defaultdict(
    lambda: {
        "domains": [],  # آخر 50 domain فقط
        "domain_count": defaultdict(int),  # أكثر 100 domain زيارة
        "domain_usage": defaultdict(int),  # استهلاك البيانات
        "categories": defaultdict(int),  # استهلاك حسب الفئة
        "first_seen": time.time(),
        "last_seen": time.time(),
    }
)

# 🔥 Content Type Tracking - تتبع نوع المحتوى
content_types = defaultdict(
    lambda: {
        "images": 0,  # الصور
        "videos": 0,  # الفيديوهات
        "audio": 0,  # الصوتيات
        "text": 0,  # النصوص والصفحات
        "documents": 0,  # المستندات
        "downloads": 0,  # التحميلات
        "streaming": 0,  # البث المباشر
        "other": 0,  # أخرى
    }
)

# 🔥 IP to Domain Mapping المحسّن
ip_to_domain_map = {}

device_db = defaultdict(
    lambda: {
        "IP": "Unknown",
        "Name": "Unknown",
        "Vendor": "",
        "Total_Internet": 0,
        "Total_Local": 0,
        "Prev_Total": 0,
        "Current_Speed": 0,
        "FirstSeen": time.time(),
        "LastSeen": time.time(),
        "Apps": defaultdict(int),
        "IP_Log": None,
    }
)

global_stats = {
    "wan_total": 0,
    "clients_internet": 0,
    "clients_local": 0,
    "wan_apps": defaultdict(int),
    "host_mac": "HOST_PC",
    "start_time": time.time(),
    "last_save_date": str(datetime.now().date()),
}

mac_vendor_cache = {}
host_ip = ""


# ==========================================
# 🧠 دوال التحليل المحسّنة
# ==========================================
def identify_app_advanced(domain):
    """تحديد التطبيق/الموقع بدقة عالية"""
    if not domain:
        return "Unknown"

    domain_lower = domain.lower().strip()

    for app_name, patterns in DETAILED_SITE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, domain_lower):
                return app_name

    return "Other/Web"


def categorize_domain(domain):
    """تصنيف الـ domain"""
    app = identify_app_advanced(domain)

    # Social Media
    if app in [
        "Facebook",
        "Instagram",
        "TikTok",
        "Twitter/X",
        "Snapchat",
        "LinkedIn",
        "Reddit",
    ]:
        return "Social Media"
    # Streaming
    elif app in ["YouTube", "Netflix", "Shahid", "Watch iT", "Disney+", "Twitch"]:
        return "Video Streaming"
    # Gaming
    elif app in [
        "PUBG Mobile",
        "Free Fire",
        "Roblox",
        "Fortnite",
        "Call of Duty",
        "Clash of Clans",
    ]:
        return "Gaming"
    # Messaging
    elif app in ["WhatsApp", "Telegram", "Teams", "Zoom"]:
        return "Messaging"
    # Google
    elif "Google" in app:
        return "Google Services"
    else:
        return "Other"


def get_mac_from_ip(ip):
    """الحصول على MAC من IP"""
    return ip_to_mac_cache.get(ip) or arp_cache.get(ip)


def update_arp_cache(packet):
    """تحديث ARP cache من الـ packets"""
    try:
        if packet.haslayer(Ether) and packet.haslayer(IP):
            mac = packet[Ether].src.lower()
            ip = packet[IP].src
            if ip.startswith(HOTSPOT_SUBNET) and ip != HOTSPOT_GATEWAY:
                with lock:
                    arp_cache[ip] = mac
                    ip_to_mac_cache[ip] = mac

        # معالجة ARP packets أيضاً
        if packet.haslayer(ARP):
            if packet[ARP].op == 2:  # ARP Reply
                mac = packet[ARP].hwsrc.lower()
                ip = packet[ARP].psrc
                if ip.startswith(HOTSPOT_SUBNET):
                    with lock:
                        arp_cache[ip] = mac
                        ip_to_mac_cache[ip] = mac
    except:
        pass


def enhanced_dns_analysis(packet):
    """تحليل DNS محسّن مع حفظ التاريخ"""
    try:
        if not packet.haslayer(DNS):
            return

        # DNS Query (Request)
        if packet[DNS].qr == 0 and packet.haslayer(IP):
            client_ip = packet[IP].src
            if packet[DNS].qd and client_ip.startswith(HOTSPOT_SUBNET):
                try:
                    domain = packet[DNS].qd.qname.decode("utf-8", "ignore").strip(".")
                    if domain and len(domain) > 3:
                        mac = get_mac_from_ip(client_ip)
                        if mac:
                            app = identify_app_advanced(domain)
                            category = categorize_domain(domain)

                            with lock:
                                # حفظ في تاريخ DNS (آخر 50 فقط)
                                dns_history[mac]["domains"].append(
                                    {
                                        "domain": domain,
                                        "timestamp": time.time(),
                                        "category": category,
                                        "app": app,
                                    }
                                )
                                dns_history[mac]["domain_count"][domain] += 1
                                dns_history[mac]["last_seen"] = time.time()

                                # احتفظ بآخر 50 domain فقط
                                if len(dns_history[mac]["domains"]) > MAX_DNS_HISTORY:
                                    dns_history[mac]["domains"].pop(0)

                                # احتفظ بأول 100 domain الأكثر زيارة فقط
                                if (
                                    len(dns_history[mac]["domain_count"])
                                    > MAX_DOMAIN_COUNT
                                ):
                                    # احذف الأقل زيارة
                                    least_visited = min(
                                        dns_history[mac]["domain_count"].items(),
                                        key=lambda x: x[1],
                                    )
                                    del dns_history[mac]["domain_count"][
                                        least_visited[0]
                                    ]
                                    if (
                                        least_visited[0]
                                        in dns_history[mac]["domain_usage"]
                                    ):
                                        del dns_history[mac]["domain_usage"][
                                            least_visited[0]
                                        ]
                except:
                    pass

        # DNS Response
        elif packet[DNS].qr == 1:
            for i in range(packet[DNS].ancount):
                try:
                    if packet[DNS].an[i].type == 1:  # A Record
                        domain = (
                            packet[DNS]
                            .an[i]
                            .rrname.decode("utf-8", "ignore")
                            .strip(".")
                        )
                        ip = packet[DNS].an[i].rdata

                        if domain and len(domain) > 3:
                            with lock:
                                ip_to_domain_map[ip] = {
                                    "domain": domain,
                                    "app": identify_app_advanced(domain),
                                    "expires": time.time() + 3600,  # ساعة كاملة
                                }
                except:
                    pass
    except:
        pass


def parse_sni_enhanced(payload):
    """استخراج SNI من TLS بشكل محسّن"""
    try:
        payload_bytes = bytes(payload)

        # البحث عن Server Name extension
        sni_start = payload_bytes.find(b"\x00\x00")
        if sni_start != -1:
            # البحث عن domain pattern
            match = re.search(
                b"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}",
                payload_bytes[sni_start:],
                re.IGNORECASE,
            )
            if match:
                domain = match.group(0).decode("utf-8", errors="ignore")
                if len(domain) > 3 and "." in domain:
                    return domain
    except:
        pass
    return None


def detect_content_type(packet, domain=None):
    """كشف نوع المحتوى من الـ Packet"""
    content_type = "other"

    try:
        # 1️⃣ من HTTP Headers
        if packet.haslayer("Raw"):
            payload = packet["Raw"].load

            # تحويل لـ string
            try:
                payload_str = payload.decode("utf-8", errors="ignore").lower()
            except:
                payload_str = str(payload).lower()

            # البحث عن Content-Type في HTTP Response
            if b"content-type:" in payload or "content-type:" in payload_str:
                # صور
                if any(
                    x in payload_str
                    for x in [
                        "image/jpeg",
                        "image/png",
                        "image/gif",
                        "image/webp",
                        "image/jpg",
                    ]
                ):
                    content_type = "images"
                # فيديوهات
                elif any(
                    x in payload_str
                    for x in [
                        "video/mp4",
                        "video/webm",
                        "video/mpeg",
                        "video/",
                        "application/x-mpegurl",
                        "m3u8",
                    ]
                ):
                    content_type = "videos"
                # صوتيات
                elif any(
                    x in payload_str
                    for x in ["audio/mpeg", "audio/mp3", "audio/wav", "audio/"]
                ):
                    content_type = "audio"
                # مستندات
                elif any(
                    x in payload_str
                    for x in [
                        "application/pdf",
                        "application/msword",
                        "application/vnd.",
                        "application/zip",
                        "application/x-rar",
                    ]
                ):
                    content_type = "documents"
                # نصوص
                elif any(
                    x in payload_str
                    for x in [
                        "text/html",
                        "text/plain",
                        "application/json",
                        "text/css",
                        "text/javascript",
                    ]
                ):
                    content_type = "text"

        # 2️⃣ من الـ Domain والـ URL patterns
        if domain:
            domain_lower = domain.lower()

            # YouTube, Netflix = فيديو/streaming
            if any(
                x in domain_lower
                for x in [
                    "youtube",
                    "googlevideo",
                    "netflix",
                    "nflx",
                    "twitch",
                    "vimeo",
                    "dailymotion",
                ]
            ):
                content_type = "streaming"

            # Instagram, Facebook = صور/فيديو
            elif any(
                x in domain_lower
                for x in ["cdninstagram", "fbcdn", "instagramusercontent"]
            ):
                # لو في 'video' في الـ URL = فيديو، غير كده = صور
                if packet.haslayer("Raw"):
                    payload_check = str(packet["Raw"].load).lower()
                    if "video" in payload_check or ".mp4" in payload_check:
                        content_type = "videos"
                    else:
                        content_type = "images"

            # Spotify, Anghami = صوتيات
            elif any(
                x in domain_lower
                for x in ["spotify", "scdn.co", "anghami", "soundcloud"]
            ):
                content_type = "audio"

            # Downloads
            elif any(x in domain_lower for x in ["download", "cdn", "dl."]):
                content_type = "downloads"

        # 3️⃣ من حجم الـ Packet (استنتاج)
        packet_size = len(packet)
        if content_type == "other":
            # Packets كبيرة جداً عادة فيديو أو تحميلات
            if packet_size > 1400:
                if packet.haslayer(TCP) and packet[TCP].flags == 0x18:  # PSH+ACK
                    content_type = "streaming"
            # Packets صغيرة نصوص أو API calls
            elif packet_size < 500:
                content_type = "text"

    except Exception as e:
        pass

    return content_type


def analyze_traffic_layer(packet, client_mac=None):
    """تحليل الـ packet للتعرف على التطبيق ونوع المحتوى"""
    app_detected = None
    domain_detected = None
    content_type = "other"

    try:
        # تحليل TLS/HTTPS
        if packet.haslayer(TCP) and packet.haslayer("Raw"):
            if packet[TCP].dport == 443 or packet[TCP].srcport == 443:
                domain = parse_sni_enhanced(packet["Raw"].load)
                if domain:
                    domain_detected = domain
                    app_detected = identify_app_advanced(domain)
                    content_type = detect_content_type(packet, domain)

                    # حفظ في الـ mapping
                    if packet.haslayer(IP):
                        ip_target = (
                            packet[IP].dst
                            if packet[TCP].dport == 443
                            else packet[IP].src
                        )
                        with lock:
                            ip_to_domain_map[ip_target] = {
                                "domain": domain,
                                "app": app_detected,
                                "content_type": content_type,
                                "expires": time.time() + 1800,
                            }
            else:
                # HTTP (port 80)
                content_type = detect_content_type(packet, None)

        # Port-based detection
        if not app_detected and packet.haslayer(TCP):
            port = (
                packet[TCP].dport
                if packet.haslayer(IP) and packet[IP].src.startswith(HOTSPOT_SUBNET)
                else packet[TCP].sport
            )
            app_detected = APP_PORT_HINTS.get(port)

    except:
        pass

    return app_detected, domain_detected, content_type


# ==========================================
# 📥 معالجة الـ Packets المحسّنة
# ==========================================
def process_client_packet_enhanced(packet):
    """معالجة محسّنة لـ packets الأجهزة"""
    try:
        # تحديث ARP أولاً
        update_arp_cache(packet)

        # تحليل DNS
        enhanced_dns_analysis(packet)

        if not packet.haslayer(IP) or not packet.haslayer(Ether):
            return

        src, dst, plen = packet[IP].src, packet[IP].dst, len(packet)

        if src == "127.0.0.1" or src == HOTSPOT_GATEWAY or dst == HOTSPOT_GATEWAY:
            return

        t_mac, t_ip, is_local = None, None, False
        target_remote_ip = None

        if src.startswith(HOTSPOT_SUBNET):
            t_mac = packet[Ether].src.lower()
            t_ip = src
            target_remote_ip = dst
            if is_private_ip(dst):
                is_local = True
        elif dst.startswith(HOTSPOT_SUBNET):
            t_mac = packet[Ether].dst.lower()
            t_ip = dst
            target_remote_ip = src
            if is_private_ip(src):
                is_local = True

        if not t_mac:
            return

        # تحليل التطبيق ونوع المحتوى
        app_detected, domain_detected, content_type_detected = analyze_traffic_layer(
            packet, t_mac
        )

        with lock:
            trigger_vendor(t_mac)
            d = device_db[t_mac]

            # تحديث معلومات الجهاز
            if d["IP"] != "Unknown" and d["IP"] != t_ip:
                d["IP_Log"] = f"{d['IP']} → {t_ip}"
            d["LastSeen"], d["IP"] = time.time(), t_ip

            if d["Name"] == "Unknown":
                d["Name"] = KNOWN_DEVICES.get(t_mac, f"Device-{t_mac[-5:]}")

            if is_local:
                d["Total_Local"] += plen
                d["Apps"]["LAN/Local"] += plen
                global_stats["clients_local"] += plen
            else:
                d["Total_Internet"] += plen
                global_stats["clients_internet"] += plen

                # تحديد التطبيق ونوع المحتوى
                final_app = "Other/Web"
                final_domain = None
                final_content_type = (
                    content_type_detected if content_type_detected else "other"
                )

                if app_detected:
                    final_app = app_detected
                    final_domain = domain_detected
                elif target_remote_ip in ip_to_domain_map:
                    info = ip_to_domain_map[target_remote_ip]
                    if info["expires"] > time.time():
                        final_app = info["app"]
                        final_domain = info["domain"]
                        final_content_type = info.get("content_type", "other")

                d["Apps"][final_app] += plen

                # تحديث نوع المحتوى
                content_types[t_mac][final_content_type] += plen

                # تحديث DNS history بالاستهلاك
                if final_domain:
                    dns_history[t_mac]["domain_usage"][final_domain] += plen
                    cat = categorize_domain(final_domain)
                    dns_history[t_mac]["categories"][cat] += plen

    except Exception as e:
        pass


def process_wan_packet(packet):
    """معالجة packets الـ WAN"""
    try:
        if packet.haslayer(IP):
            plen = len(packet)
            with lock:
                global_stats["wan_total"] += plen

            app_detected, _, content_type_detected = analyze_traffic_layer(packet)

            if app_detected:
                final_app = app_detected
            else:
                src, dst = packet[IP].src, packet[IP].dst
                info = ip_to_domain_map.get(src) or ip_to_domain_map.get(dst)
                if info and info["expires"] > time.time():
                    final_app = info["app"]
                else:
                    final_app = "Other/Web"

            with lock:
                global_stats["wan_apps"][final_app] += plen
    except:
        pass


def update_calculations():
    """حساب السرعات والإحصائيات"""
    with lock:
        host_u = max(0, global_stats["wan_total"] - global_stats["clients_internet"])
        hm = global_stats["host_mac"]
        host_dev = device_db[hm]
        host_dev["Name"], host_dev["Vendor"], host_dev["IP"] = (
            "MY LAPTOP",
            "Host",
            host_ip,
        )
        host_dev["Total_Internet"], host_dev["LastSeen"] = host_u, time.time()

        clients_apps_sum = defaultdict(int)
        for mac, dev in device_db.items():
            if mac == hm:
                continue
            for app, usage in dev["Apps"].items():
                if app != "LAN/Local":
                    clients_apps_sum[app] += usage

        host_dev["Apps"] = defaultdict(int)
        for app, total_usage in global_stats["wan_apps"].items():
            client_usage = clients_apps_sum.get(app, 0)
            host_specific_usage = max(0, total_usage - client_usage)
            if host_specific_usage > 0:
                host_dev["Apps"][app] = host_specific_usage

        for mac, dev in device_db.items():
            curr = dev["Total_Internet"] + dev["Total_Local"]
            dev["Current_Speed"] = max(0, (curr - dev["Prev_Total"]) / 1)
            dev["Prev_Total"] = curr


# ==========================================
# 💾 حفظ وتحميل البيانات
# ==========================================
def format_bytes_text(bytes_val):
    """تنسيق البايتات بشكل نصي"""
    if bytes_val == 0:
        return "0 B"
    k = 1024
    sizes = ["B", "KB", "MB", "GB", "TB"]
    i = int(abs(bytes_val).bit_length() / 10)
    if i >= len(sizes):
        i = len(sizes) - 1
    return f"{bytes_val / (k ** i):.2f} {sizes[i]}"


def create_daily_summary(date_str=None):
    """إنشاء ملخص يومي وحفظه في ملف JSON"""
    if date_str is None:
        date_str = str(datetime.now().date())

    with lock:
        # إعداد الملخص
        summary = {
            "date": date_str,
            "session_duration": format_duration(
                time.time() - global_stats["start_time"]
            ),
            "total_statistics": {
                "wan_total": global_stats["wan_total"],
                "wan_total_formatted": format_bytes_text(global_stats["wan_total"]),
                "clients_internet": global_stats["clients_internet"],
                "clients_internet_formatted": format_bytes_text(
                    global_stats["clients_internet"]
                ),
                "clients_local": global_stats["clients_local"],
                "clients_local_formatted": format_bytes_text(
                    global_stats["clients_local"]
                ),
                "host_usage": device_db[global_stats["host_mac"]]["Total_Internet"],
                "host_usage_formatted": format_bytes_text(
                    device_db[global_stats["host_mac"]]["Total_Internet"]
                ),
            },
            "wan_apps": {},
            "devices": {},
        }

        # إحصائيات التطبيقات على WAN
        for app, usage in sorted(
            global_stats["wan_apps"].items(), key=lambda x: x[1], reverse=True
        ):
            if usage > 0:
                summary["wan_apps"][app] = {
                    "usage": usage,
                    "usage_formatted": format_bytes_text(usage),
                    "percentage": round(
                        (
                            (usage / global_stats["wan_total"] * 100)
                            if global_stats["wan_total"] > 0
                            else 0
                        ),
                        2,
                    ),
                }

        # إحصائيات كل جهاز
        for mac, dev in device_db.items():
            total_usage = dev["Total_Internet"] + dev["Total_Local"]
            if total_usage > 0:
                device_summary = {
                    "name": dev["Name"],
                    "ip": dev["IP"],
                    "vendor": dev["Vendor"],
                    "mac": mac,
                    "total_internet": dev["Total_Internet"],
                    "total_internet_formatted": format_bytes_text(
                        dev["Total_Internet"]
                    ),
                    "total_local": dev["Total_Local"],
                    "total_local_formatted": format_bytes_text(dev["Total_Local"]),
                    "total_usage": total_usage,
                    "total_usage_formatted": format_bytes_text(total_usage),
                    "percentage_of_total": round(
                        (
                            (
                                total_usage
                                / (
                                    global_stats["wan_total"]
                                    + global_stats["clients_local"]
                                )
                                * 100
                            )
                            if (
                                global_stats["wan_total"]
                                + global_stats["clients_local"]
                            )
                            > 0
                            else 0
                        ),
                        2,
                    ),
                    "apps": {},
                }

                # أهم التطبيقات لهذا الجهاز
                for app, usage in sorted(
                    dev["Apps"].items(), key=lambda x: x[1], reverse=True
                ):
                    if usage > 0:
                        device_summary["apps"][app] = {
                            "usage": usage,
                            "usage_formatted": format_bytes_text(usage),
                            "percentage": round((usage / total_usage * 100), 2),
                        }

                summary["devices"][mac] = device_summary

        # حفظ الملف
        filename = f"daily_report_{date_str}.json"
        filepath = os.path.join(DAILY_REPORTS_DIR, filename)

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=4, ensure_ascii=False)
            print(f"📊 Daily Report Saved: {filename}")
            return True
        except Exception as e:
            print(f"⚠️ Error saving daily report: {e}")
            return False


def load_data():
    global device_db, global_stats, mac_vendor_cache

    # التحقق من وجود بيانات قديمة
    old_date = None
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r") as f:
                data = json.load(f)

            old_date = data["stats"].get("last_save_date")
            current_date = str(datetime.now().date())

            if old_date == current_date:
                # نفس اليوم - تحميل البيانات
                global_stats.update(data["stats"])
                global_stats["wan_apps"] = defaultdict(
                    int, data["stats"].get("wan_apps", {})
                )
                for mac, info in data["devices"].items():
                    device_db[mac].update(info)
                    device_db[mac]["Apps"] = defaultdict(int, info["Apps"])
                    device_db[mac]["Prev_Total"] = (
                        info["Total_Internet"] + info["Total_Local"]
                    )
                    if "Vendor" in info:
                        mac_vendor_cache[mac] = info["Vendor"]
                print(f"✅ Traffic Data Loaded (Today's Session)")
            else:
                # يوم جديد - حفظ تقرير اليوم السابق
                print(f"📅 New Day Detected ({current_date})")
                print(f"📊 Creating Daily Report for {old_date}...")

                # تحميل البيانات القديمة مؤقتاً
                temp_stats = data["stats"].copy()
                temp_stats["wan_apps"] = defaultdict(
                    int, data["stats"].get("wan_apps", {})
                )
                temp_devices = {}
                for mac, info in data["devices"].items():
                    temp_devices[mac] = info.copy()
                    temp_devices[mac]["Apps"] = defaultdict(int, info["Apps"])

                # حفظ التقرير اليومي للأمس
                with lock:
                    # حفظ البيانات الحالية مؤقتاً
                    current_stats_backup = global_stats.copy()
                    current_devices_backup = dict(device_db)

                    # استخدام البيانات القديمة لإنشاء التقرير
                    global_stats.update(temp_stats)
                    device_db.clear()
                    device_db.update(temp_devices)

                    # إنشاء التقرير
                    create_daily_summary(old_date)

                    # استرجاع البيانات الحالية (الفارغة للبدء من جديد)
                    global_stats.clear()
                    global_stats.update(current_stats_backup)
                    device_db.clear()
                    device_db.update(current_devices_backup)

                print(f"✅ Daily Report Created Successfully!")
                print(f"🆕 Starting Fresh Session for {current_date}")

        except Exception as e:
            print(f"⚠️ Load Error: {e}")

    # ملاحظة: DNS History مش هيتحفظ - بيبقى في الذاكرة فقط طول الجلسة


def save_data():
    """حفظ بيانات الاستهلاك فقط (بدون DNS History)"""
    with lock:
        # حفظ Traffic Data فقط
        s_devs = {}
        for k, v in device_db.items():
            s_devs[k] = dict(v)
            s_devs[k]["Apps"] = dict(v["Apps"])
            if "Prev_Total" in s_devs[k]:
                del s_devs[k]["Prev_Total"]
            if "Current_Speed" in s_devs[k]:
                del s_devs[k]["Current_Speed"]

        stats_copy = dict(global_stats)
        stats_copy["wan_apps"] = dict(global_stats["wan_apps"])
        data = {"stats": stats_copy, "devices": s_devs}
        global_stats["last_save_date"] = str(datetime.now().date())

        try:
            with open(DB_FILE, "w") as f:
                json.dump(data, f, indent=4)
        except:
            pass

        # ⚠️ DNS History مش هيتحفظ خالص - بيتمسح مع كل إعادة تشغيل


# ==========================================
# 🔧 Helper Functions
# ==========================================
def is_private_ip(ip):
    return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")


def format_duration(seconds):
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def get_vendor_online(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.read().decode("utf-8")
    except:
        return ""


def resolve_vendor(mac):
    if mac in mac_vendor_cache:
        return
    local = {"8A:AF:98": "Apple", "00:28:F8": "Intel", "9A:15:22": "Apple"}
    p = mac[:8].upper()
    if p in local:
        mac_vendor_cache[mac] = local[p]
        with lock:
            device_db[mac]["Vendor"] = local[p]
    else:
        v = get_vendor_online(mac)
        with lock:
            mac_vendor_cache[mac] = v
            device_db[mac]["Vendor"] = v


def trigger_vendor(mac):
    if mac != global_stats["host_mac"] and not device_db[mac]["Vendor"]:
        threading.Thread(target=resolve_vendor, args=(mac,), daemon=True).start()


# ==========================================
# 🚀 Flask Routes
# ==========================================
@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/data")
def get_data():
    update_calculations()
    save_data()

    with lock:
        devices_list = []
        for mac, dev in device_db.items():
            sorted_apps = sorted(dev["Apps"].items(), key=lambda x: x[1], reverse=True)
            apps_list = [{"name": k, "usage": v} for k, v in sorted_apps if v > 0]

            # إضافة إحصائيات DNS
            unique_domains = len(dns_history[mac]["domain_count"])
            total_visits = sum(dns_history[mac]["domain_count"].values())

            # إضافة إحصائيات نوع المحتوى
            content_stats = dict(content_types[mac])

            devices_list.append(
                {
                    "mac": mac,
                    "name": dev["Name"],
                    "vendor": dev["Vendor"][:15] if dev["Vendor"] else "Unknown",
                    "ip": dev["IP"],
                    "speed": dev["Current_Speed"],
                    "total_net": dev["Total_Internet"],
                    "total_loc": dev["Total_Local"],
                    "ip_log": dev["IP_Log"],
                    "apps": apps_list,
                    "is_host": mac == global_stats["host_mac"],
                    "unique_domains": unique_domains,
                    "total_visits": total_visits,
                    "content_types": content_stats,
                }
            )

        return jsonify(
            {
                "stats": {
                    "wan": global_stats["wan_total"],
                    "clients_net": global_stats["clients_internet"],
                    "clients_loc": global_stats["clients_local"],
                    "host_usage": device_db[global_stats["host_mac"]]["Total_Internet"],
                    "runtime": format_duration(
                        time.time() - global_stats["start_time"]
                    ),
                },
                "devices": devices_list,
            }
        )


@app.route("/device/<mac>/history")
def device_history(mac):
    """API للحصول على تاريخ الجهاز"""
    with lock:
        device = device_db.get(mac)
        history = dns_history.get(mac, {})
        content_data = content_types.get(mac, {})

        if not device:
            return jsonify({"error": "Device not found"}), 404

        # أكثر المواقع زيارة
        top_sites = []
        for domain, count in sorted(
            history.get("domain_count", {}).items(), key=lambda x: x[1], reverse=True
        )[:30]:
            usage = history.get("domain_usage", {}).get(domain, 0)
            top_sites.append({"domain": domain, "visits": count, "usage": usage})

        # آخر المواقع
        recent = history.get("domains", [])[-50:]

        # الإحصائيات
        total_domains = len(history.get("domain_count", {}))
        total_visits = sum(history.get("domain_count", {}).values())
        total_usage = device["Total_Internet"] + device["Total_Local"]
        active_time = format_duration(time.time() - device["FirstSeen"])
        categories = dict(history.get("categories", {}))

        # إحصائيات نوع المحتوى
        content_stats = dict(content_data)

        return jsonify(
            {
                "device": {
                    "name": device["Name"],
                    "ip": device["IP"],
                    "mac": mac,
                    "vendor": device["Vendor"],
                },
                "top_sites": top_sites,
                "recent_sites": recent,
                "stats": {
                    "total_domains": total_domains,
                    "total_visits": total_visits,
                    "total_usage": total_usage,
                    "active_time": active_time,
                    "categories": categories,
                    "content_types": content_stats,
                },
            }
        )


@app.route("/reports")
def list_reports():
    """عرض قائمة التقارير اليومية"""
    try:
        reports = []
        if os.path.exists(DAILY_REPORTS_DIR):
            files = [f for f in os.listdir(DAILY_REPORTS_DIR) if f.endswith(".json")]
            files.sort(reverse=True)  # الأحدث أولاً

            for filename in files:
                filepath = os.path.join(DAILY_REPORTS_DIR, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        report = json.load(f)
                        reports.append(
                            {
                                "filename": filename,
                                "date": report.get("date"),
                                "wan_total": report["total_statistics"][
                                    "wan_total_formatted"
                                ],
                                "devices_count": len(report.get("devices", {})),
                                "session_duration": report.get("session_duration"),
                            }
                        )
                except:
                    pass

        # عرض HTML بسيط
        html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Daily Reports</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0d1117; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; padding: 20px; }
        .card { background-color: #161b22; border: 1px solid #30363d; margin-bottom: 15px; }
        .report-link { color: #58a6ff; text-decoration: none; }
        .report-link:hover { color: #79c0ff; }
        h1 { color: #58a6ff; margin-bottom: 30px; }
        .btn-back { background: #238636; border: none; color: white; }
        .btn-back:hover { background: #2ea043; }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="btn btn-back mb-4">← Back to Dashboard</a>
        <h1>📊 Daily Reports</h1>
        <div class="row">
"""

        if reports:
            for report in reports:
                html += f"""
            <div class="col-md-6 col-lg-4 mb-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">📅 {report['date']}</h5>
                        <p class="card-text">
                            <strong>Total Data:</strong> {report['wan_total']}<br>
                            <strong>Devices:</strong> {report['devices_count']}<br>
                            <strong>Duration:</strong> {report['session_duration']}
                        </p>
                        <a href="/report/{report['date']}" class="report-link">View Details →</a>
                    </div>
                </div>
            </div>
"""
        else:
            html += '<div class="col-12"><p class="text-muted">No reports available yet.</p></div>'

        html += """
        </div>
    </div>
</body>
</html>
"""
        return html
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/report/<date>")
def get_report(date):
    """الحصول على تقرير يوم معين"""
    try:
        filename = f"daily_report_{date}.json"
        filepath = os.path.join(DAILY_REPORTS_DIR, filename)

        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                report = json.load(f)

            # عرض HTML منسق
            html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report - {date}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ background-color: #0d1117; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; padding: 20px; }}
        .card {{ background-color: #161b22; border: 1px solid #30363d; margin-bottom: 15px; }}
        .stat-box {{ background: #1c2128; padding: 15px; border-radius: 8px; text-align: center; }}
        .stat-val {{ font-size: 1.3rem; font-weight: bold; color: #58a6ff; }}
        .stat-label {{ font-size: 0.9rem; color: #8b949e; }}
        h1, h3 {{ color: #58a6ff; }}
        .device-card {{ background: #21262d; padding: 15px; border-radius: 8px; margin-bottom: 10px; }}
        .app-item {{ padding: 5px 0; border-bottom: 1px solid #30363d; }}
        .btn-back {{ background: #238636; border: none; color: white; }}
        .btn-back:hover {{ background: #2ea043; }}
    </style>
</head>
<body>
    <div class="container">
        <a href="/reports" class="btn btn-back mb-4">← Back to Reports</a>
        <h1>📊 Daily Report - {report['date']}</h1>
        <p class="text-muted">Session Duration: {report['session_duration']}</p>
        
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-val">{report['total_statistics']['wan_total_formatted']}</div>
                    <div class="stat-label">🌐 Total WAN</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-val">{report['total_statistics']['clients_internet_formatted']}</div>
                    <div class="stat-label">🔥 Clients Internet</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-val">{report['total_statistics']['clients_local_formatted']}</div>
                    <div class="stat-label">🏠 Clients Local</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-val">{report['total_statistics']['host_usage_formatted']}</div>
                    <div class="stat-label">💻 Host Usage</div>
                </div>
            </div>
        </div>
        
        <h3 class="mt-4 mb-3">🖥️ Devices Summary</h3>
        <div class="row">
"""

            for mac, device in sorted(
                report["devices"].items(),
                key=lambda x: x[1]["total_usage"],
                reverse=True,
            ):
                html += f"""
            <div class="col-md-6">
                <div class="device-card">
                    <h5 style="color: #58a6ff;">{device['name']}</h5>
                    <p style="color: #8b949e; font-size: 0.85rem;">
                        IP: {device['ip']} | {device['vendor']}<br>
                        MAC: {mac}
                    </p>
                    <p>
                        <strong>Internet:</strong> {device['total_internet_formatted']}<br>
                        <strong>Local:</strong> {device['total_local_formatted']}<br>
                        <strong>Total:</strong> {device['total_usage_formatted']} ({device['percentage_of_total']}%)
                    </p>
                    <hr style="border-color: #30363d;">
                    <p style="color: #8b949e; font-size: 0.9rem; margin-bottom: 5px;">Top Apps:</p>
"""
                for app, app_data in list(device["apps"].items())[:5]:
                    html += f"""
                    <div class="app-item">
                        <span>{app}</span>
                        <span style="float: right; color: #8b949e;">{app_data['usage_formatted']} ({app_data['percentage']}%)</span>
                    </div>
"""
                html += """
                </div>
            </div>
"""

            html += """
        </div>
    </div>
</body>
</html>
"""
            return html
        else:
            return "<h3>Report not found</h3>", 404
    except Exception as e:
        return f"<h3>Error: {str(e)}</h3>", 500


# ==========================================
# 🚀 Main Function
# ==========================================
def main():
    global host_ip
    os.system("cls" if os.name == "nt" else "clear")

    print("\n" + "=" * 60)
    print("🚀 Network Monitor V18.0 Enhanced")
    print("=" * 60)

    load_data()

    print(f"\n📡 Available Network Interfaces:")
    ifaces = get_if_list()
    h_idx, w_idx = -1, -1

    for i, iface in enumerate(ifaces):
        try:
            ip = get_if_addr(iface)
        except:
            ip = "N/A"

        label = ""
        if ip.startswith(HOTSPOT_SUBNET):
            label = " ← HOTSPOT (Clients)"
            h_idx = i
        elif ip.startswith("192.168.") and not ip.endswith(".1") and ip != "N/A":
            label = " ← WAN (Internet)"
            w_idx = i

        print(f"[{i}] {iface:<40} {ip:<15} {label}")

    try:
        print("\n" + "=" * 60)
        h_sel = int(input(f"👉 Select Hotspot Interface [{h_idx}]: ") or h_idx)
        w_sel = int(input(f"👉 Select WAN Interface [{w_idx}]: ") or w_idx)

        host_ip = get_if_addr(ifaces[w_sel])

        print("\n" + "=" * 60)
        print("🔍 Starting Traffic Monitoring...")
        print(f"📱 Hotspot: {ifaces[h_sel]} ({HOTSPOT_SUBNET}x)")
        print(f"🌐 WAN: {ifaces[w_sel]} ({host_ip})")
        print(
            f"💡 DNS History: In-Memory Only (Max {MAX_DNS_HISTORY} recent per device)"
        )
        print("=" * 60 + "\n")

        # Thread للـ Hotspot monitoring
        t1 = threading.Thread(
            target=lambda: sniff(
                iface=ifaces[h_sel],
                prn=process_client_packet_enhanced,
                store=0,
                filter="",
                promisc=True,
            ),
            daemon=True,
        )

        # Thread للـ WAN monitoring
        t2 = threading.Thread(
            target=lambda: sniff(
                iface=ifaces[w_sel],
                prn=process_wan_packet,
                store=0,
                filter="ip",
                promisc=True,
            ),
            daemon=True,
        )

        t1.start()
        t2.start()

        print(f"✅ Monitoring Started Successfully!")
        print(f"\n🌐 Dashboard URL: http://127.0.0.1:{WEB_PORT}")
        print(f"📊 View detailed stats for each device")
        print(f"📅 Daily Reports: http://127.0.0.1:{WEB_PORT}/reports")
        print(f"🔍 Track every website visit with timestamps")
        print(f"📱 Access from mobile: http://{host_ip}:{WEB_PORT}")
        print(f"\n💾 Daily reports saved in: {DAILY_REPORTS_DIR}")
        print("\n💡 Press Ctrl+C to stop\n")
        print("=" * 60 + "\n")

        app.run(host="0.0.0.0", port=WEB_PORT, debug=False, use_reloader=False)

    except KeyboardInterrupt:
        print("\n\n⏹️  Stopping monitor...")

        # حفظ تقرير اليوم الحالي قبل الإغلاق
        print("📊 Creating final daily report...")
        create_daily_summary()
        save_data()

        print("💾 Data saved successfully!")
        print(f"📁 Reports folder: {DAILY_REPORTS_DIR}")
        print("👋 Goodbye!\n")
    except Exception as e:
        print(f"\n❌ Error: {e}\n")


if __name__ == "__main__":
    main()
