# import sys
# import time
# import os
# import threading
# import re
# import pandas as pd
# from datetime import datetime, timedelta
# from collections import defaultdict
# from scapy.all import (
#     sniff,
#     get_if_list,
#     get_if_addr,
#     conf,
#     DNS,
#     IP,
#     TCP,
#     UDP,
#     Ether,
#     ARP,
# )
# import logging

# # ==========================================
# # 📝 إعدادات المستخدم
# # ==========================================
# KNOWN_DEVICES = {
#     "8a:af:98:60:2d:ee": "iPhone 11",
#     "00:28:f8:c6:ba:8d": "Laptop HP",
#     "9a:15:22:de:92:f9": "iPhone 13",
# }

# EXCEL_FILE_NAME = "traffic_report_v5.xlsx"

# # ==========================================
# # ⚙️ إعدادات التطبيقات
# # ==========================================
# APP_PATTERNS = {
#     "YouTube": [r"youtube", r"googlevideo", r"ytimg", r"youtu\.be"],
#     "Facebook": [r"facebook", r"fbcdn", r"fbsbx", r"messenger"],
#     "Instagram": [r"instagram", r"cdninstagram"],
#     "WhatsApp": [r"whatsapp", r"g\.whatsapp"],
#     "TikTok": [r"tiktok", r"byteoversea", r"ibyteimg"],
#     "Google": [r"google", r"gstatic", r"gmail"],
#     "Apple/iCloud": [r"apple", r"icloud", r"itunes"],
#     "Netflix": [r"netflix", r"nflxvideo"],
#     "Snapchat": [r"snapchat", r"sc-cdn"],
#     "Telegram": [r"telegram", r"t\.me"],
# }

# # ==========================================
# # ⚙️ قواعد البيانات
# # ==========================================
# device_db = defaultdict(
#     lambda: {
#         "IP": "Unknown",
#         "Name": "Unknown",
#         "Total": 0,
#         "FirstSeen": time.time(),
#         "LastSeen": time.time(),
#         "Apps": defaultdict(int),
#     }
# )

# global_stats = {"wan_total": 0, "clients_total": 0, "host_mac": "HOST_PC"}

# # IP-to-App mapping with TTL
# ip_to_app_map = {}  # ip -> (app_name, expire_time)
# IP_MAPPING_TTL = 300  # ثواني

# lock = threading.Lock()
# host_ip_wan = ""

# # ==========================================
# # 🛠️ Logging setup
# # ==========================================
# logging.basicConfig(
#     level=logging.INFO,
#     format="[%(asctime)s] %(levelname)s - %(message)s",
#     datefmt="%H:%M:%S",
# )


# # ==========================================
# # 🔍 Helper Functions
# # ==========================================
# def identify_app(domain):
#     if not domain:
#         return None
#     domain = domain.lower()
#     for app_name, patterns in APP_PATTERNS.items():
#         for pattern in patterns:
#             if re.search(pattern, domain):
#                 return app_name
#     return "Other/Web"


# def parse_sni(payload):
#     try:
#         content = payload.tobytes()
#         idx = content.find(b"\x00\x00")
#         if idx != -1 and idx + 5 < len(content):
#             match = re.search(
#                 b"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}", content
#             )
#             if match:
#                 return match.group(0).decode("utf-8", errors="ignore")
#     except Exception as e:
#         logging.debug(f"SNI parsing error: {e}")
#     return None


# def format_bytes(size):
#     if size < 1024:
#         return f"{size} B"
#     elif size < 1024**2:
#         return f"{size / 1024:.1f} KB"
#     elif size < 1024**3:
#         return f"{size / (1024 ** 2):.1f} MB"
#     else:
#         return f"{size / (1024 ** 3):.2f} GB"


# def format_duration(seconds):
#     m, s = divmod(int(seconds), 60)
#     h, m = divmod(m, 60)
#     return f"{h:02d}:{m:02d}:{s:02d}"


# def cleanup_ip_map():
#     """Remove expired IP-to-App mappings"""
#     current_time = time.time()
#     with lock:
#         expired_ips = [
#             ip for ip, (_, expire) in ip_to_app_map.items() if expire < current_time
#         ]
#         for ip in expired_ips:
#             del ip_to_app_map[ip]


# # ==========================================
# # 🖥️ Packet Processing
# # ==========================================
# def analyze_app_layer(packet):
#     global ip_to_app_map
#     try:
#         # DNS layer
#         if packet.haslayer(DNS) and packet.haslayer(UDP):
#             if packet[DNS].qr == 1 and packet[DNS].an:
#                 for i in range(packet[DNS].ancount):
#                     rr = packet[DNS].an[i]
#                     if rr.type == 1:
#                         domain = rr.rrname.decode("utf-8", "ignore").strip(".")
#                         detected = identify_app(domain)
#                         if detected != "Other/Web":
#                             with lock:
#                                 ip_to_app_map[rr.rdata] = (
#                                     detected,
#                                     time.time() + IP_MAPPING_TTL,
#                                 )
#         # TCP SNI
#         if packet.haslayer(TCP) and packet.haslayer("Raw"):
#             if packet[TCP].dport == 443 or packet[TCP].sport == 443:
#                 domain = parse_sni(packet["Raw"].load)
#                 if domain:
#                     detected = identify_app(domain)
#                     if detected != "Other/Web":
#                         with lock:
#                             ip_to_app_map[packet[IP].dst] = (
#                                 detected,
#                                 time.time() + IP_MAPPING_TTL,
#                             )
#     except Exception as e:
#         logging.debug(f"App layer analysis error: {e}")


# def process_client_packet(packet):
#     if not packet.haslayer(IP) or not packet.haslayer(Ether):
#         return
#     src_ip = packet[IP].src
#     dst_ip = packet[IP].dst
#     pkt_len = len(packet)
#     if src_ip == "127.0.0.1":
#         return

#     analyze_app_layer(packet)
#     cleanup_ip_map()

#     target_mac = None
#     app_name = None

#     if src_ip.startswith("192.168.137."):
#         target_mac = packet[Ether].src
#         app_name = ip_to_app_map.get(dst_ip, ("Unknown",))[0]
#     elif dst_ip.startswith("192.168.137."):
#         target_mac = packet[Ether].dst
#         app_name = ip_to_app_map.get(src_ip, ("Unknown",))[0]

#     if target_mac:
#         with lock:
#             device_db[target_mac]["Total"] += pkt_len
#             device_db[target_mac]["LastSeen"] = time.time()
#             device_db[target_mac]["IP"] = (
#                 src_ip if src_ip.startswith("192.168.137.") else dst_ip
#             )
#             if device_db[target_mac]["Name"] == "Unknown":
#                 device_db[target_mac]["Name"] = KNOWN_DEVICES.get(
#                     target_mac, f"Device ({target_mac[-5:]})"
#                 )
#             real_app = app_name if app_name else "Other/Web"
#             device_db[target_mac]["Apps"][real_app] += pkt_len
#             global_stats["clients_total"] += pkt_len


# def process_wan_packet(packet):
#     if not packet.haslayer(IP):
#         return
#     with lock:
#         global_stats["wan_total"] += len(packet)
#     analyze_app_layer(packet)
#     cleanup_ip_map()


# # ==========================================
# # 🖥️ Host Stats
# # ==========================================
# def update_host_stats():
#     host_usage = global_stats["wan_total"] - global_stats["clients_total"]
#     if host_usage < 0:
#         host_usage = 0

#     hmac = global_stats["host_mac"]
#     device_db[hmac]["Name"] = "💻 MY LAPTOP (Host)"
#     device_db[hmac]["IP"] = host_ip_wan
#     device_db[hmac]["Total"] = host_usage
#     device_db[hmac]["LastSeen"] = time.time()


# # ==========================================
# # 📊 Dashboard
# # ==========================================
# def print_bars(value, total, length=20):
#     percent = value / total if total else 0
#     bar_fill = int(percent * length)
#     return "█" * bar_fill + "░" * (length - bar_fill)


# def dashboard_loop():
#     while True:
#         time.sleep(2)
#         os.system("cls" if os.name == "nt" else "clear")
#         update_host_stats()

#         wan_mb = global_stats["wan_total"] / 1048576
#         clients_mb = global_stats["clients_total"] / 1048576
#         host_mb = device_db[global_stats["host_mac"]]["Total"] / 1048576

#         print(
#             f"""
# ╔════════════════════════════════════════════════════════════════════╗
# ║                   📊 NETWORK TRAFFIC OVERVIEW 📊                   ║
# ╠══════════════════════════╦══════════════════════════╦══════════════╣
# ║ 🌐 Total Router (WAN)    ║ 🔥 Hotspot Clients       ║ 💻 Laptop    ║
# ║ {wan_mb:8.2f} MB           ║ {clients_mb:8.2f} MB           ║ {host_mb:8.2f} MB  ║
# ╚══════════════════════════╩══════════════════════════╩══════════════╝
# """
#         )

#         current_time = time.time()
#         with lock:
#             sorted_devices = sorted(
#                 device_db.items(), key=lambda x: x[1]["Total"], reverse=True
#             )
#             active_cnt = 0
#             for mac, data in sorted_devices:
#                 if data["Total"] < 50 * 1024:
#                     continue
#                 active_cnt += 1
#                 duration = format_duration(current_time - data["FirstSeen"])
#                 print(f"📱 {data['Name']}")
#                 print(
#                     f"   Total: {format_bytes(data['Total']):<10} | Duration: {duration}"
#                 )
#                 print("-" * 70)

#                 sorted_apps = sorted(
#                     data["Apps"].items(), key=lambda x: x[1], reverse=True
#                 )
#                 if mac == global_stats["host_mac"] and not sorted_apps:
#                     print(
#                         f"   ├─ {'Mixed/Web':<12} {print_bars(1,1)} {format_bytes(data['Total']):<9} (100%)"
#                     )
#                 else:
#                     for app, usage in sorted_apps:
#                         if usage > 10 * 1024:
#                             percent = (usage / data["Total"]) * 100
#                             bar = print_bars(usage, data["Total"], 15)
#                             print(
#                                 f"   ├─ {app:<12} {bar} {format_bytes(usage):<9} ({percent:.1f}%)"
#                             )
#                 print("")
#             if active_cnt == 0:
#                 print("   ⏳ Waiting for traffic...")

#         print("=" * 70)
#         print("🔴 Press Ctrl+C to Stop & Save.")


# # ==========================================
# # 💾 Excel Export
# # ==========================================
# def save_to_excel():
#     print(f"\n💾 Saving data to {EXCEL_FILE_NAME}...")
#     data_rows = []
#     session_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     with lock:
#         update_host_stats()
#         data_rows.append(
#             {
#                 "Session Time": session_time,
#                 "Device Name": "--- SUMMARY ---",
#                 "Total Usage (MB)": "---",
#                 "App Name": "WAN (Router Total)",
#                 "App Usage (MB)": round(global_stats["wan_total"] / 1048576, 2),
#             }
#         )

#         for mac, info in device_db.items():
#             if info["Total"] < 1024:
#                 continue
#             duration = format_duration(info["LastSeen"] - info["FirstSeen"])
#             if mac == global_stats["host_mac"] and not info["Apps"]:
#                 info["Apps"]["Mixed/Web"] = info["Total"]

#             for app, size in info["Apps"].items():
#                 percent = (size / info["Total"]) * 100
#                 data_rows.append(
#                     {
#                         "Session Time": session_time,
#                         "Device Name": info["Name"],
#                         "IP Address": info["IP"],
#                         "MAC Address": mac,
#                         "Duration": duration,
#                         "Total Usage (MB)": round(info["Total"] / 1048576, 2),
#                         "App Name": app,
#                         "App Usage (MB)": round(size / 1048576, 2),
#                         "Percentage %": round(percent, 2),
#                     }
#                 )

#     if data_rows:
#         df = pd.DataFrame(data_rows)
#         session_sheet = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#         with pd.ExcelWriter(
#             EXCEL_FILE_NAME,
#             engine="openpyxl",
#             mode="a" if os.path.exists(EXCEL_FILE_NAME) else "w",
#         ) as writer:
#             df.to_excel(writer, sheet_name=session_sheet, index=False)
#         print("✅ Data saved successfully!")
#     else:
#         print("⚠️ No data to save.")


# # ==========================================
# # 🧵 Threads Starter
# # ==========================================
# def start_sniffers(hotspot_iface, wan_iface):
#     global host_ip_wan
#     try:
#         host_ip_wan = get_if_addr(wan_iface)
#     except Exception as e:
#         logging.warning(f"Cannot get WAN IP: {e}")

#     t_hotspot = threading.Thread(
#         target=lambda: sniff(
#             iface=hotspot_iface,
#             prn=process_client_packet,
#             store=0,
#             filter="ip",
#             promisc=False,
#         ),
#         daemon=True,
#     )
#     t_hotspot.start()

#     t_wan = threading.Thread(
#         target=lambda: sniff(
#             iface=wan_iface, prn=process_wan_packet, store=0, filter="ip", promisc=False
#         ),
#         daemon=True,
#     )
#     t_wan.start()

#     t_dashboard = threading.Thread(target=dashboard_loop, daemon=True)
#     t_dashboard.start()

#     t_dashboard.join()


# # ==========================================
# # 🏁 Main
# # ==========================================
# if __name__ == "__main__":
#     ifaces = get_if_list()
#     print("\n🔍 Network Interfaces:")
#     hotspot_idx = -1
#     wan_idx = -1

#     for i, iface in enumerate(ifaces):
#         try:
#             ip = get_if_addr(iface)
#         except:
#             ip = "N/A"

#         label = ""
#         if ip.startswith("192.168.137"):
#             label = "  <-- (🔥 HOTSPOT)"
#             hotspot_idx = i
#         elif ip.startswith("192.168.") and not ip.endswith(".1"):
#             label = "  <-- (🌐 INTERNET/WAN)"
#             wan_idx = i

#         print(f"[{i}] {iface} ({ip}){label}")

#     try:
#         print("\n👇 Select Interfaces (by ID):")
#         h_in = input(f"1. Hotspot Interface ID [Default {hotspot_idx}]: ")
#         h_sel = int(h_in) if h_in else hotspot_idx

#         w_in = input(f"2. Internet/WAN Interface ID [Default {wan_idx}]: ")
#         w_sel = int(w_in) if w_in else wan_idx

#         print(f"\n🚀 Starting Dual Monitor...")
#         start_sniffers(ifaces[h_sel], ifaces[w_sel])

#     except KeyboardInterrupt:
#         save_to_excel()
#     except Exception as e:
#         logging.error(f"Fatal error: {e}")
#         save_to_excel()

# import sys
# import time
# import os
# import threading
# import re
# import pandas as pd
# from datetime import datetime
# from collections import defaultdict
# from scapy.all import sniff, get_if_list, get_if_addr, conf, DNS, IP, TCP, UDP, Ether
# import logging

# # ==========================================
# # 📝 إعدادات المستخدم
# # ==========================================
# KNOWN_DEVICES = {
#     "8a:af:98:60:2d:ee": "iPhone 11",
#     "00:28:f8:c6:ba:8d": "Laptop HP",
#     "9a:15:22:de:92:f9": "iPhone 13",
# }

# EXCEL_FILE = "traffic_report_final.xlsx"
# HOTSPOT_SUBNET = "192.168.137."

# # ==========================================
# # 📱 فلاتر التطبيقات
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
# }

# # ==========================================
# # 💾 مخازن البيانات
# # ==========================================
# device_db = defaultdict(
#     lambda: {
#         "IP": "Unknown",
#         "Name": "Unknown",
#         "Total": 0,
#         "FirstSeen": time.time(),
#         "LastSeen": time.time(),
#         "Apps": defaultdict(int),
#     }
# )

# global_stats = {
#     "wan_total": 0,
#     "clients_total": 0,
#     "host_mac": "HOST_PC",
#     "start_time": time.time(),
# }

# ip_to_app_map = {}
# IP_MAPPING_TTL = 300
# lock = threading.RLock()
# host_ip = ""
# last_cleanup = time.time()

# logging.basicConfig(
#     level=logging.INFO, format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S"
# )


# # ==========================================
# # 🔍 دوال مساعدة
# # ==========================================
# def identify_app(domain):
#     if not domain:
#         return None
#     domain = domain.lower()
#     for app_name, pattern in APP_PATTERNS.items():
#         if pattern.search(domain):
#             return app_name
#     return "Other/Web"


# def parse_sni(payload):
#     try:
#         content = payload.tobytes()
#         idx = content.find(b"\x00\x00")
#         if idx != -1 and idx + 5 < len(content):
#             match = re.search(
#                 b"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}", content
#             )
#             if match:
#                 return match.group(0).decode("utf-8", errors="ignore")
#     except:
#         pass
#     return None


# def format_bytes(size):
#     for unit in ["B", "KB", "MB", "GB"]:
#         if size < 1024:
#             return f"{size:.1f} {unit}" if unit != "B" else f"{size} {unit}"
#         size /= 1024
#     return f"{size:.1f} TB"


# def format_duration(seconds):
#     h, rem = divmod(int(seconds), 3600)
#     m, s = divmod(rem, 60)
#     return f"{h:02d}:{m:02d}:{s:02d}"


# def print_bar(value, total, length=20):
#     if total == 0:
#         return "░" * length
#     percent = min(1.0, value / total)
#     filled = int(percent * length)
#     return "█" * filled + "░" * (length - filled)


# def clear_screen():
#     """مسح الشاشة بطريقة تدعم الويندوز بشكل كامل"""
#     if os.name == "nt":
#         _ = os.system("cls")
#     else:
#         _ = os.system("clear")


# def cleanup_expired_mappings():
#     global last_cleanup
#     current_time = time.time()
#     if current_time - last_cleanup < 60:
#         return
#     with lock:
#         expired = [ip for ip, (_, exp) in ip_to_app_map.items() if exp < current_time]
#         for ip in expired:
#             del ip_to_app_map[ip]
#     last_cleanup = current_time


# # ==========================================
# # 📦 معالجة الباكت
# # ==========================================
# def analyze_traffic_layer(packet):
#     global ip_to_app_map
#     try:
#         if packet.haslayer(DNS) and packet[DNS].qr == 1:
#             for i in range(packet[DNS].ancount):
#                 rr = packet[DNS].an[i]
#                 if rr.type == 1:
#                     domain = rr.rrname.decode("utf-8", "ignore").strip(".")
#                     app = identify_app(domain)
#                     if app and app != "Other/Web":
#                         with lock:
#                             ip_to_app_map[rr.rdata] = (
#                                 app,
#                                 time.time() + IP_MAPPING_TTL,
#                             )
#     except:
#         pass

#     try:
#         if packet.haslayer(TCP) and packet.haslayer("Raw"):
#             if packet[TCP].dport == 443 or packet[TCP].srcport == 443:
#                 domain = parse_sni(packet["Raw"].load)
#                 if domain:
#                     app = identify_app(domain)
#                     if app and app != "Other/Web":
#                         target_ip = (
#                             packet[IP].dst
#                             if packet[TCP].dport == 443
#                             else packet[IP].src
#                         )
#                         with lock:
#                             ip_to_app_map[target_ip] = (
#                                 app,
#                                 time.time() + IP_MAPPING_TTL,
#                             )
#     except:
#         pass


# def process_client_packet(packet):
#     try:
#         if not (packet.haslayer(IP) and packet.haslayer(Ether)):
#             return

#         src_ip = packet[IP].src
#         dst_ip = packet[IP].dst
#         pkt_len = len(packet)
#         if src_ip == "127.0.0.1":
#             return

#         analyze_traffic_layer(packet)
#         cleanup_expired_mappings()

#         target_mac = None
#         target_ip = None
#         app_name = None

#         if src_ip.startswith(HOTSPOT_SUBNET):
#             target_mac = packet[Ether].src
#             target_ip = src_ip
#             app_name = ip_to_app_map.get(dst_ip, ("Unknown",))[0]
#         elif dst_ip.startswith(HOTSPOT_SUBNET):
#             target_mac = packet[Ether].dst
#             target_ip = dst_ip
#             app_name = ip_to_app_map.get(src_ip, ("Unknown",))[0]

#         if target_mac:
#             with lock:
#                 device_db[target_mac]["Total"] += pkt_len
#                 device_db[target_mac]["LastSeen"] = time.time()
#                 device_db[target_mac]["IP"] = target_ip

#                 if device_db[target_mac]["Name"] == "Unknown":
#                     device_db[target_mac]["Name"] = KNOWN_DEVICES.get(
#                         target_mac, f"Device-{target_mac[-5:]}"
#                     )

#                 app = app_name if app_name else "Other/Web"
#                 device_db[target_mac]["Apps"][app] += pkt_len
#                 global_stats["clients_total"] += pkt_len
#     except Exception as e:
#         pass


# def process_wan_packet(packet):
#     try:
#         if packet.haslayer(IP):
#             with lock:
#                 global_stats["wan_total"] += len(packet)
#             analyze_traffic_layer(packet)
#     except:
#         pass


# def update_host_stats():
#     with lock:
#         host_usage = max(0, global_stats["wan_total"] - global_stats["clients_total"])
#         hmac = global_stats["host_mac"]
#         device_db[hmac]["Name"] = "💻 MY LAPTOP (Host)"
#         device_db[hmac]["IP"] = host_ip
#         device_db[hmac]["Total"] = host_usage
#         device_db[hmac]["LastSeen"] = time.time()


# # ==========================================
# # 📊 لوحة التحكم (معدلة للثبات)
# # ==========================================
# def dashboard_loop():
#     while True:
#         try:
#             # 1. تحديث البيانات
#             update_host_stats()

#             with lock:
#                 wan_mb = global_stats["wan_total"] / (1024**2)
#                 clients_mb = global_stats["clients_total"] / (1024**2)
#                 host_mb = device_db[global_stats["host_mac"]]["Total"] / (1024**2)
#                 runtime = time.time() - global_stats["start_time"]

#             # 2. مسح الشاشة بالكامل قبل الطباعة
#             clear_screen()

#             # 3. طباعة الشاشة الجديدة
#             print(
#                 f"""
# ╔═══════════════════════════════════════════════════════════════════╗
# ║             📊 NETWORK TRAFFIC MONITOR (STABLE) 📊                ║
# ╠══════════════════╦═══════════════════╦═══════════════════════════╣
# ║ 🌐 WAN Total     ║ 🔥 Clients        ║ 💻 Host                   ║
# ║ {wan_mb:7.2f} MB      ║ {clients_mb:7.2f} MB       ║ {host_mb:7.2f} MB                ║
# ╠══════════════════╩═══════════════════╩═══════════════════════════╣
# ║ ⏱️  Runtime: {format_duration(runtime):<45} ║
# ╚═══════════════════════════════════════════════════════════════════╝
# """
#             )

#             with lock:
#                 sorted_devices = sorted(
#                     [
#                         (mac, dev)
#                         for mac, dev in device_db.items()
#                         if dev["Total"] >= 50 * 1024
#                     ],
#                     key=lambda x: x[1]["Total"],
#                     reverse=True,
#                 )

#             if not sorted_devices:
#                 print("   ⏳ Waiting for traffic...\n")
#             else:
#                 for mac, dev in sorted_devices:
#                     duration = format_duration(time.time() - dev["FirstSeen"])
#                     print(f"📱 {dev['Name']}")
#                     print(
#                         f"   IP: {dev['IP']:<15} | Total: {format_bytes(dev['Total']):<12} | Time: {duration}"
#                     )
#                     print("-" * 70)

#                     sorted_apps = sorted(
#                         dev["Apps"].items(), key=lambda x: x[1], reverse=True
#                     )

#                     if not sorted_apps and mac == global_stats["host_mac"]:
#                         print(
#                             f"   ├─ {'Mixed/Web':<15} {print_bar(1,1)} {format_bytes(dev['Total']):<10} (100%)"
#                         )
#                     else:
#                         for app, usage in sorted_apps:
#                             if usage > 10 * 1024:
#                                 percent = (
#                                     (usage / dev["Total"] * 100)
#                                     if dev["Total"] > 0
#                                     else 0
#                                 )
#                                 bar = print_bar(usage, dev["Total"], 15)
#                                 print(
#                                     f"   ├─ {app:<15} {bar} {format_bytes(usage):<10} ({percent:5.1f}%)"
#                                 )
#                     print()

#             print("=" * 70)
#             print("🔴 Press Ctrl+C to Stop & Save")

#             # 4. الانتظار
#             time.sleep(2)

#         except Exception:
#             time.sleep(1)


# # ==========================================
# # 💾 الحفظ
# # ==========================================
# def save_excel():
#     print(f"\n💾 Saving to {EXCEL_FILE}...")
#     try:
#         update_host_stats()
#         session_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#         data_rows = []

#         with lock:
#             data_rows.append(
#                 {
#                     "Session Time": session_time,
#                     "Device Name": "=== SUMMARY ===",
#                     "Total Usage (MB)": round(global_stats["wan_total"] / (1024**2), 3),
#                     "App Name": "WAN Total",
#                     "App Usage (MB)": round(global_stats["wan_total"] / (1024**2), 3),
#                     "Percentage %": 100.0,
#                 }
#             )

#             for mac, dev in device_db.items():
#                 if dev["Total"] < 1024:
#                     continue
#                 duration = format_duration(dev["LastSeen"] - dev["FirstSeen"])

#                 if mac == global_stats["host_mac"] and not dev["Apps"]:
#                     dev["Apps"]["Mixed/Web"] = dev["Total"]

#                 for app, size in dev["Apps"].items():
#                     percent = (size / dev["Total"] * 100) if dev["Total"] > 0 else 0
#                     data_rows.append(
#                         {
#                             "Session Time": session_time,
#                             "Device Name": dev["Name"],
#                             "IP Address": dev["IP"],
#                             "MAC Address": mac,
#                             "Duration": duration,
#                             "Total Usage (MB)": round(dev["Total"] / (1024**2), 3),
#                             "App Name": app,
#                             "App Usage (MB)": round(size / (1024**2), 3),
#                             "Percentage %": round(percent, 2),
#                         }
#                     )

#         if not data_rows:
#             print("⚠️  No data to save")
#             return

#         df = pd.DataFrame(data_rows)
#         sheet_name = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#         mode = "a" if os.path.exists(EXCEL_FILE) else "w"
#         with pd.ExcelWriter(
#             EXCEL_FILE,
#             engine="openpyxl",
#             mode=mode,
#             if_sheet_exists="replace" if mode == "a" else None,
#         ) as writer:
#             df.to_excel(writer, sheet_name=sheet_name, index=False)

#         print(f"✅ Saved to sheet: {sheet_name}")
#     except Exception as e:
#         print(f"❌ Failed to save! {e}")


# # ==========================================
# # 🚀 MAIN
# # ==========================================
# def main():
#     global host_ip
#     clear_screen()
#     print("\n" + "=" * 70)
#     print(" 🌐 NETWORK TRAFFIC MONITOR (FINAL STABLE)")
#     print("=" * 70)

#     ifaces = get_if_list()
#     print("\n🔍 Network Interfaces:")
#     hotspot_idx = -1
#     wan_idx = -1

#     for i, iface in enumerate(ifaces):
#         try:
#             ip = get_if_addr(iface)
#         except:
#             ip = "N/A"

#         label = ""
#         if ip.startswith(HOTSPOT_SUBNET):
#             label = "  ← 🔥 HOTSPOT"
#             hotspot_idx = i
#         elif ip.startswith("192.168.") and not ip.endswith(".1") and ip != "N/A":
#             label = "  ← 🌐 WAN"
#             wan_idx = i
#         print(f"  [{i}] {iface:<40} {ip:<15} {label}")

#     print("-" * 70)
#     try:
#         print("\n👉 Select Interfaces (Enter for auto):")
#         h_input = input(f"   Hotspot [{hotspot_idx}]: ").strip()
#         h_sel = int(h_input) if h_input else hotspot_idx

#         w_input = input(f"   WAN [{wan_idx}]: ").strip()
#         w_sel = int(w_input) if w_input else wan_idx

#         if h_sel < 0 or w_sel < 0:
#             print("\n❌ Invalid selection!")
#             sys.exit(1)

#         host_ip = get_if_addr(ifaces[w_sel])
#         print(f"\n🚀 Starting...")

#         threading.Thread(
#             target=lambda: sniff(
#                 iface=ifaces[h_sel],
#                 prn=process_client_packet,
#                 store=0,
#                 filter="ip",
#                 promisc=False,
#             ),
#             daemon=True,
#         ).start()
#         threading.Thread(
#             target=lambda: sniff(
#                 iface=ifaces[w_sel],
#                 prn=process_wan_packet,
#                 store=0,
#                 filter="ip",
#                 promisc=False,
#             ),
#             daemon=True,
#         ).start()

#         dashboard_loop()

#     except KeyboardInterrupt:
#         save_excel()
#     except Exception as e:
#         print(f"Error: {e}")
#         save_excel()


# if __name__ == "__main__":
#     main()

# import sys
# import time
# import os
# import threading
# import re
# import json
# import urllib.request
# from datetime import datetime
# from collections import defaultdict
# from itertools import zip_longest
# from scapy.all import sniff, get_if_list, get_if_addr, conf, DNS, IP, TCP, UDP, Ether
# import logging
# from colorama import init, Fore, Style

# init(autoreset=True)

# # ==========================================
# # 📝 إعدادات المستخدم
# # ==========================================
# KNOWN_DEVICES = {
#     "8a:af:98:60:2d:ee": "iPhone 11",
#     "00:28:f8:c6:ba:8d": "Laptop HP",
#     "9a:15:22:de:92:f9": "iPhone 13",
# }

# HOTSPOT_SUBNET = "192.168.137."
# HOTSPOT_GATEWAY = "192.168.137.1"
# SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# DB_FILE = os.path.join(SCRIPT_DIR, "traffic_data.json")

# # ==========================================
# # 🧠 إعدادات الفلاتر
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

# # ==========================================
# # 💾 إدارة البيانات
# # ==========================================
# lock = threading.RLock()

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
#     "wan_apps": defaultdict(int),  # 🆕 لتجميع كل تطبيقات النت وحساب الهوست منها
#     "host_mac": "HOST_PC",
#     "start_time": time.time(),
#     "last_save_date": str(datetime.now().date()),
# }

# ip_to_app_map = {}
# mac_vendor_cache = {}
# IP_MAPPING_TTL = 300
# host_ip = ""

# # متغيرات للتحكم في الترتيب
# cached_sorted_order = []
# last_sort_time = 0
# SORT_INTERVAL = 900  # 15 دقيقة (900 ثانية)


# # ==========================================
# # 🕵️‍♂️ Helper Functions
# # ==========================================
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


# def load_data():
#     global device_db, global_stats, mac_vendor_cache
#     if os.path.exists(DB_FILE):
#         try:
#             with open(DB_FILE, "r") as f:
#                 data = json.load(f)
#             if data["stats"].get("last_save_date") == str(datetime.now().date()):
#                 global_stats.update(data["stats"])
#                 # استعادة defaultdict للتطبيقات العالمية
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
#         except:
#             pass


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

#         # تحويل wan_apps لدكت عادي للحفظ
#         stats_copy = dict(global_stats)
#         stats_copy["wan_apps"] = dict(global_stats["wan_apps"])

#         data = {"stats": stats_copy, "devices": s_devs}
#         try:
#             with open(DB_FILE, "w") as f:
#                 json.dump(data, f, indent=4)
#         except:
#             pass


# # ==========================================
# # 🖌️ دوال العرض والتنسيق
# # ==========================================
# def strip_ansi(text):
#     """إزالة أكواد الألوان لحساب الطول الحقيقي"""
#     return re.sub(r"\x1b\[[0-9;]*m", "", text)


# def pad_string(text, width):
#     """ضبط المسافات بدقة مع تجاهل الألوان"""
#     visible_len = len(strip_ansi(text))
#     padding = width - visible_len
#     if padding < 0:
#         padding = 0
#     return text + " " * padding


# def format_bytes(size):
#     for unit in ["B", "KB", "MB", "GB"]:
#         if size < 1024:
#             return f"{size:.1f} {unit}" if unit != "B" else f"{size} {unit}"
#         size /= 1024
#     return f"{size:.1f} TB"


# def format_speed(bps):
#     if bps < 1024:
#         return f"{bps} B/s"
#     elif bps < 1024**2:
#         return f"{bps/1024:.1f} KB/s"
#     return f"{bps/1024**2:.1f} MB/s"


# def format_duration(seconds):
#     m, s = divmod(int(seconds), 60)
#     h, m = divmod(m, 60)
#     return f"{h:02d}:{m:02d}:{s:02d}"


# def print_bar(value, total, length=10):
#     if total == 0:
#         return "░" * length
#     percent = min(1.0, value / total)
#     filled = int(percent * length)
#     return "█" * filled + "░" * (length - filled)


# def clear_screen():
#     os.system("cls" if os.name == "nt" else "clear")


# # ==========================================
# # 📦 تحليل الباكت
# # ==========================================
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


# def analyze_traffic_layer(packet):
#     global ip_to_app_map
#     app_detected = None

#     # DNS
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

#     # SNI & Ports
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
#             if dst.startswith("192.168.") or dst.startswith("10."):
#                 is_local = True
#         elif dst.startswith(HOTSPOT_SUBNET):
#             t_mac, t_ip = packet[Ether].dst, dst
#             cached = ip_to_app_map.get(src, (None,))[0]
#             if src.startswith("192.168.") or src.startswith("10."):
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
#             # تحديث الإجمالي
#             with lock:
#                 global_stats["wan_total"] += plen

#             # تحليل التطبيق وتحديث قائمة التطبيقات العامة للهوست
#             app = analyze_traffic_layer(packet)
#             if app:
#                 with lock:
#                     global_stats["wan_apps"][app] += plen
#             else:
#                 # محاولة جلب الاسم من الكاش لو مش ظاهر في الباكت ده
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
#         # حساب إجمالي الهوست
#         host_u = max(0, global_stats["wan_total"] - global_stats["clients_internet"])
#         hm = global_stats["host_mac"]

#         # إعداد بيانات الهوست
#         host_dev = device_db[hm]
#         host_dev["Name"] = "MY LAPTOP"
#         host_dev["Vendor"] = "Host Device"
#         host_dev["IP"] = host_ip
#         host_dev["Total_Internet"] = host_u
#         host_dev["LastSeen"] = time.time()

#         # --- حساب تطبيقات الهوست (المعادلة السحرية) ---
#         # Host_App = Total_WAN_App - Sum(Clients_App)

#         # 1. تجميع استهلاك العملاء لكل تطبيق
#         clients_apps_sum = defaultdict(int)
#         for mac, dev in device_db.items():
#             if mac == hm:
#                 continue
#             for app, usage in dev["Apps"].items():
#                 if app != "LAN/Local":  # تجاهل المحلي
#                     clients_apps_sum[app] += usage

#         # 2. طرح العملاء من الإجمالي العام (WAN)
#         host_dev["Apps"] = defaultdict(int)  # تصفير وإعادة حساب
#         for app, total_usage in global_stats["wan_apps"].items():
#             client_usage = clients_apps_sum.get(app, 0)
#             host_specific_usage = max(0, total_usage - client_usage)
#             if host_specific_usage > 0:
#                 host_dev["Apps"][app] = host_specific_usage

#         # 3. حساب السرعة
#         for mac, dev in device_db.items():
#             curr = dev["Total_Internet"] + dev["Total_Local"]
#             dev["Current_Speed"] = max(0, (curr - dev["Prev_Total"]) / 2)
#             dev["Prev_Total"] = curr


# # ==========================================
# # 📊 العرض النهائي (جدول متناسق)
# # ==========================================
# def get_device_block(mac, dev, width=60):
#     lines = []
#     total = dev["Total_Internet"] + dev["Total_Local"]
#     speed = dev["Current_Speed"]

#     # 1. Header Line
#     ven = f"[{dev['Vendor'][:8]}]" if dev["Vendor"] else ""
#     # استخدام pad_string لضمان الطول الثابت رغم الألوان
#     name_colored = f"{Fore.CYAN}📱 {dev['Name']} {Fore.YELLOW}{ven}{Style.RESET_ALL}"
#     lines.append(pad_string(name_colored, width))

#     # 2. Stats Line
#     spd_col = (
#         Fore.RED
#         if speed > 1024 * 1024
#         else (Fore.YELLOW if speed > 100 * 1024 else Fore.GREEN)
#     )
#     spd_txt = f"{spd_col}🚀 {format_speed(speed)}{Style.RESET_ALL}"

#     stats_txt = f"   IP: {dev['IP']:<15} | {spd_txt} | Net: {format_bytes(dev['Total_Internet'])}"
#     lines.append(pad_string(stats_txt, width))

#     # 3. Local / Warning
#     extra_info = f"   Loc: {format_bytes(dev['Total_Local'])}"
#     if dev["IP_Log"]:
#         extra_info += f" {Fore.RED}⚠ IP Changed{Style.RESET_ALL}"
#     lines.append(pad_string(extra_info, width))

#     # 4. Apps (Top 4)
#     lines.append(
#         pad_string(
#             f"{Fore.LIGHTBLACK_EX}" + "-" * (width - 4) + f"{Style.RESET_ALL}", width
#         )
#     )

#     sorted_apps = sorted(dev["Apps"].items(), key=lambda x: x[1], reverse=True)
#     count = 0
#     # للهوست اعرض 5، للعملاء 4
#     limit = 5 if mac == global_stats["host_mac"] else 4

#     for app, usage in sorted_apps:
#         if usage > 50 * 1024:
#             if count >= limit:
#                 break
#             pct = (usage / total * 100) if total > 0 else 0
#             bar = print_bar(usage, total, 10)
#             app_line = f"   ├─ {app:<12} {bar} {format_bytes(usage):<7} {pct:3.0f}%"
#             lines.append(pad_string(app_line, width))
#             count += 1

#     # Fill remaining lines to keep height consistent (optional but good for grid)
#     while len(lines) < 8:
#         lines.append(pad_string("", width))

#     return lines[:8]  # Force max height


# def dashboard_loop():
#     global cached_sorted_order, last_sort_time

#     while True:
#         try:
#             update_calculations()
#             save_data()

#             with lock:
#                 wan = global_stats["wan_total"]
#                 c_net = global_stats["clients_internet"]
#                 c_loc = global_stats["clients_local"]
#                 host = device_db[global_stats["host_mac"]]["Total_Internet"]
#                 rt = time.time() - global_stats["start_time"]

#                 # --- منطق الترتيب (كل 15 دقيقة) ---
#                 current_time = time.time()
#                 if not cached_sorted_order or (
#                     current_time - last_sort_time > SORT_INTERVAL
#                 ):
#                     # ترتيب حسب السرعة حالياً
#                     cached_sorted_order = sorted(
#                         [
#                             (k, v)
#                             for k, v in device_db.items()
#                             if (v["Total_Internet"] + v["Total_Local"]) > 1024
#                         ],
#                         key=lambda x: x[1]["Current_Speed"],
#                         reverse=True,
#                     )
#                     last_sort_time = current_time
#                     sort_status = f"{Fore.GREEN}Updated Now{Style.RESET_ALL}"
#                 else:
#                     # تحديث القيم فقط لنفس الترتيب
#                     # نحدث القيم داخل القائمة الم cached
#                     # (ملاحظة: بما أننا بنشاور على الأوبجكت في device_db، القيم هتتحدث تلقائياً، بس محتاجين نتأكد إن القائمة لسه صالحة)
#                     pass
#                     time_left = int(SORT_INTERVAL - (current_time - last_sort_time))
#                     m, s = divmod(time_left, 60)
#                     sort_status = f"Reorder in {m:02d}:{s:02d}"

#             clear_screen()
#             print(
#                 f"""
# {Fore.MAGENTA}╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
# ║                       🚀 NETWORK COMMAND CENTER (V14 - STABLE GRID) 🚀                               ║
# ╠════════════════════════╦════════════════════════╦════════════════════════╦═══════════════════════════╣{Style.RESET_ALL}
# ║ 🌐 WAN (Router)        ║ 🔥 Clients (Net)       ║ 🏠 Local (LAN)         ║ 💻 Laptop (Host)          ║
# ║ {Fore.WHITE}{format_bytes(wan):<22}{Style.RESET_ALL} ║ {Fore.YELLOW}{format_bytes(c_net):<22}{Style.RESET_ALL} ║ {Fore.BLUE}{format_bytes(c_loc):<22}{Style.RESET_ALL} ║ {Fore.CYAN}{format_bytes(host):<25}{Style.RESET_ALL} ║
# {Fore.MAGENTA}╚════════════════════════╩════════════════════════╩════════════════════════╩═══════════════════════════╝{Style.RESET_ALL}
#  ⏱️ Session: {format_duration(rt)} | 🔃 Sort: {sort_status}
# """
#             )

#             if not cached_sorted_order:
#                 print(
#                     f"\n   {Fore.LIGHTBLACK_EX}⏳ Analyzing Network Traffic...{Style.RESET_ALL}"
#                 )
#             else:
#                 # العرض بنظام الشبكة (Grid)
#                 col_width = 60
#                 # Split into rows of 2
#                 for i in range(0, len(cached_sorted_order), 2):
#                     d1 = cached_sorted_order[i]
#                     d2 = (
#                         cached_sorted_order[i + 1]
#                         if (i + 1) < len(cached_sorted_order)
#                         else None
#                     )

#                     lines1 = get_device_block(d1[0], d1[1], col_width)
#                     lines2 = (
#                         get_device_block(d2[0], d2[1], col_width)
#                         if d2
#                         else [" " * col_width] * 8
#                     )

#                     for l1, l2 in zip(lines1, lines2):
#                         print(f"{l1} {Fore.MAGENTA}║{Style.RESET_ALL} {l2}")

#                     print(
#                         f"{Fore.MAGENTA}"
#                         + "=" * (col_width * 2 + 3)
#                         + f"{Style.RESET_ALL}"
#                     )

#             print(f"\n{Fore.RED}🔴 Press Ctrl+C to Exit{Style.RESET_ALL}")
#             time.sleep(2)

#         except Exception as e:
#             # print(e) # Uncomment for debug
#             time.sleep(1)


# # ==========================================
# # 🚀 تشغيل
# # ==========================================
# def main():
#     global host_ip
#     clear_screen()
#     load_data()
#     print(f"{Fore.GREEN}Starting V14 Engine...{Style.RESET_ALL}")

#     ifaces = get_if_list()
#     h_idx, w_idx = -1, -1
#     for i, iface in enumerate(ifaces):
#         ip = "N/A"
#         try:
#             ip = get_if_addr(iface)
#         except:
#             pass
#         lbl = ""
#         if ip.startswith(HOTSPOT_SUBNET):
#             lbl = f"{Fore.RED}← HOTSPOT{Style.RESET_ALL}"
#             h_idx = i
#         elif ip.startswith("192.168.") and not ip.endswith(".1") and ip != "N/A":
#             lbl = f"{Fore.GREEN}← WAN{Style.RESET_ALL}"
#             w_idx = i
#         print(f"[{i}] {iface:<40} {ip:<15} {lbl}")

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

#         dashboard_loop()
#     except KeyboardInterrupt:
#         save_data()
#     except:
#         save_data()


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
from scapy.all import sniff, get_if_list, get_if_addr, conf, DNS, IP, TCP, UDP, Ether
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
TEMPLATE_DIR = os.path.join(SCRIPT_DIR, "templates")
TEMPLATE_FILE = os.path.join(TEMPLATE_DIR, "dashboard.html")
WEB_PORT = 5000

# ==========================================
# 📄 HTML Template (Fixed Colors)
# ==========================================
DEFAULT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Monitor V17.1</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body { background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; }
        .card { background-color: #1e1e1e; border: 1px solid #333; margin-bottom: 15px; border-radius: 10px; }
        .stat-box { background: #252526; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; }
        .stat-val { font-size: 1.5rem; font-weight: bold; color: #4caf50; }
        .stat-label { font-size: 0.9rem; color: #aaa; }
        .device-name { color: #2196f3; font-weight: bold; font-size: 1.1rem; }
        .vendor-badge { font-size: 0.75rem; background: #333; padding: 2px 6px; border-radius: 4px; color: #ff9800; margin-left: 5px; }
        .speed-indicator { color: #f44336; font-weight: bold; }
        
        .app-row { font-size: 0.85rem; padding: 4px 0; display: flex; justify-content: space-between; color: #ffffff; }
        .usage-text { color: #aaa; }
        
        /* 🔥 تعديل ألوان المعلومات الأساسية */
        .device-meta { color: #bfbfbf; font-size: 0.85rem; margin-bottom: 10px; }
        .device-meta i { color: #0dcaf0; width: 20px; text-align: center; }

        .progress { height: 6px; background-color: #2c2c2c; border-radius: 3px; }
        .progress-bar { background-color: #03a9f4; } 

        .ip-changed { color: #f44336; font-size: 0.8rem; animation: blink 2s infinite; }
        .sort-timer { font-size: 0.8rem; color: #777; }
        @keyframes blink { 50% { opacity: 0.5; } }
    </style>
</head>
<body>
    <div class="container py-4">
        <div class="row mb-4">
            <div class="col-md-3"><div class="stat-box"><div class="stat-val" id="wan-total">0 MB</div><div class="stat-label">🌐 WAN (Internet)</div></div></div>
            <div class="col-md-3"><div class="stat-box"><div class="stat-val text-warning" id="clients-net">0 MB</div><div class="stat-label">🔥 Clients (Net)</div></div></div>
            <div class="col-md-3"><div class="stat-box"><div class="stat-val text-info" id="clients-loc">0 MB</div><div class="stat-label">🏠 Local (LAN)</div></div></div>
            <div class="col-md-3"><div class="stat-box"><div class="stat-val text-primary" id="host-total">0 MB</div><div class="stat-label">💻 Laptop (Host)</div></div></div>
        </div>
        
        <div class="d-flex justify-content-between mb-3 align-items-center">
            <span class="text-muted"><i class="fas fa-clock"></i> Runtime: <span id="session-time">00:00:00</span></span>
            <span class="sort-timer"><i class="fas fa-sort-amount-down"></i> Next Reorder in: <span id="sort-countdown" class="text-white">15:00</span></span>
            <span class="text-success" id="connection-status">● Live</span>
        </div>

        <div class="row" id="devices-container"></div>
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
            return (bps/(1024*1024)).toFixed(1) + ' MB/s';
        }

        function formatTimeLeft(ms) {
            if (ms < 0) return "00:00";
            const totalSeconds = Math.floor(ms / 1000);
            const m = Math.floor(totalSeconds / 60);
            const s = totalSeconds % 60;
            return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
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
                                <span class="usage-text">${formatBytes(app.usage)} <span style="color:#666">(${pct}%)</span></span>
                            </div>
                            <div class="progress mb-2">
                                <div class="progress-bar" style="width: ${pct}%"></div>
                            </div>
                        `;
                    });

                    const speedClass = dev.speed > 1024*100 ? 'text-danger' : 'text-success';
                    const ipAlert = dev.ip_log ? `<div class="ip-changed"><i class="fas fa-exclamation-triangle"></i> IP Changed: ${dev.ip_log}</div>` : '';

                    const cardHtml = `
                        <div class="col-md-6 col-lg-4">
                            <div class="card h-100">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between align-items-center mb-2">
                                        <div>
                                            <span class="device-name">${dev.name}</span>
                                            <span class="vendor-badge">${dev.vendor}</span>
                                        </div>
                                        <div class="${speedClass} fw-bold">
                                            <i class="fas fa-tachometer-alt"></i> ${formatSpeed(dev.speed)}
                                        </div>
                                    </div>
                                    
                                    <div class="device-meta">
                                        <div><i class="fas fa-network-wired"></i> IP: ${dev.ip}</div>
                                        <div><i class="fas fa-globe"></i> Net: ${formatBytes(dev.total_net)} | <i class="fas fa-home"></i> Loc: ${formatBytes(dev.total_loc)}</div>
                                        ${ipAlert}
                                    </div>
                                    <hr class="border-secondary">
                                    <div class="mt-2">
                                        ${appsHtml}
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                    container.innerHTML += cardHtml;
                });

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
# 💾 إدارة البيانات
# ==========================================
# إنشاء ملف القالب لو مش موجود
if not os.path.exists(TEMPLATE_DIR):
    os.makedirs(TEMPLATE_DIR)
# 🔥 تحديث ملف HTML لو موجود عشان يطبق التعديلات الجديدة
with open(TEMPLATE_FILE, "w", encoding="utf-8") as f:
    f.write(DEFAULT_HTML)

lock = threading.RLock()
app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.config["TEMPLATES_AUTO_RELOAD"] = True
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

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

ip_to_app_map = {}
mac_vendor_cache = {}
IP_MAPPING_TTL = 300
host_ip = ""


# ==========================================
# 📥 دوال النظام
# ==========================================
def load_data():
    global device_db, global_stats, mac_vendor_cache
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r") as f:
                data = json.load(f)
            if data["stats"].get("last_save_date") == str(datetime.now().date()):
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
                print(f"✅ Data Loaded. Resuming...")
            else:
                print("📅 New Day Detected. Resetting.")
        except Exception as e:
            print(f"⚠️ Load Error: {e}")


def save_data():
    with lock:
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


# ==========================================
# 🧠 الفلاتر والمعالجة
# ==========================================
APP_PATTERNS = {
    "YouTube": re.compile(r"(youtube|googlevideo|ytimg|youtu\.be)", re.IGNORECASE),
    "Facebook": re.compile(r"(facebook|fbcdn|fbsbx|messenger)", re.IGNORECASE),
    "Instagram": re.compile(r"(instagram|cdninstagram)", re.IGNORECASE),
    "WhatsApp": re.compile(r"(whatsapp|g\.whatsapp)", re.IGNORECASE),
    "TikTok": re.compile(r"(tiktok|byteoversea|ibyteimg)", re.IGNORECASE),
    "Google": re.compile(r"(google|gstatic|gmail)", re.IGNORECASE),
    "Apple": re.compile(r"(apple|icloud|itunes)", re.IGNORECASE),
    "Netflix": re.compile(r"(netflix|nflxvideo)", re.IGNORECASE),
    "Twitter": re.compile(r"(twitter|twimg|x\.com)", re.IGNORECASE),
    "Snapchat": re.compile(r"(snapchat|sc-cdn)", re.IGNORECASE),
    "Telegram": re.compile(r"(telegram|t\.me)", re.IGNORECASE),
    "Pubg": re.compile(r"(pubg|tencent)", re.IGNORECASE),
    "Zoom": re.compile(r"(zoom\.us|zoom)", re.IGNORECASE),
    "Microsoft": re.compile(
        r"(microsoft|windowsupdate|live\.com|office)", re.IGNORECASE
    ),
}
APP_PORT_HINTS = {
    5228: "WhatsApp",
    443: "HTTPS (Web)",
    80: "HTTP (Web)",
    53: "DNS",
    1935: "Streaming",
    22: "SSH",
}


def is_private_ip(ip):
    return ip.startswith("192.168.") or ip.startswith("10.")


def identify_app(domain):
    if not domain:
        return None
    d = domain.lower()
    for name, pat in APP_PATTERNS.items():
        if pat.search(d):
            return name
    return "Other/Web"


def parse_sni(payload):
    try:
        idx = payload.tobytes().find(b"\x00\x00")
        if idx != -1:
            m = re.search(
                b"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}",
                payload.tobytes(),
            )
            if m:
                return m.group(0).decode("utf-8", errors="ignore")
    except:
        pass
    return None


def format_duration(seconds):
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


# Helper Functions
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


def analyze_traffic_layer(packet):
    global ip_to_app_map
    app_detected = None
    try:
        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            for i in range(packet[DNS].ancount):
                if packet[DNS].an[i].type == 1:
                    d = packet[DNS].an[i].rrname.decode("utf-8", "ignore").strip(".")
                    app = identify_app(d)
                    if app:
                        with lock:
                            ip_to_app_map[packet[DNS].an[i].rdata] = (
                                app,
                                time.time() + 300,
                            )
    except:
        pass
    try:
        if packet.haslayer(TCP) and packet.haslayer("Raw"):
            if packet[TCP].dport == 443 or packet[TCP].srcport == 443:
                d = parse_sni(packet["Raw"].load)
                if d:
                    app_detected = identify_app(d)
            if not app_detected:
                port = (
                    packet[TCP].dport
                    if packet.haslayer(IP) and packet[IP].src.startswith(HOTSPOT_SUBNET)
                    else packet[TCP].sport
                )
                app_detected = APP_PORT_HINTS.get(port)
            if app_detected:
                ip_target = (
                    packet[IP].dst if packet[TCP].dport == 443 else packet[IP].src
                )
                with lock:
                    ip_to_app_map[ip_target] = (app_detected, time.time() + 300)
    except:
        pass
    return app_detected


def process_client_packet(packet):
    try:
        if not packet.haslayer(IP) or not packet.haslayer(Ether):
            return
        src, dst, plen = packet[IP].src, packet[IP].dst, len(packet)
        if src == "127.0.0.1":
            return
        detected = analyze_traffic_layer(packet)
        t_mac, t_ip, is_local = None, None, False
        if src.startswith(HOTSPOT_SUBNET):
            t_mac, t_ip = packet[Ether].src, src
            cached = ip_to_app_map.get(dst, (None,))[0]
            if is_private_ip(dst):
                is_local = True
        elif dst.startswith(HOTSPOT_SUBNET):
            t_mac, t_ip = packet[Ether].dst, dst
            cached = ip_to_app_map.get(src, (None,))[0]
            if is_private_ip(src):
                is_local = True
        if t_ip == HOTSPOT_GATEWAY:
            return
        if t_mac:
            with lock:
                trigger_vendor(t_mac)
                d = device_db[t_mac]
                if d["IP"] != "Unknown" and d["IP"] != t_ip:
                    d["IP_Log"] = f"{d['IP']} > {t_ip}"
                d["LastSeen"], d["IP"] = time.time(), t_ip
                if d["Name"] == "Unknown":
                    d["Name"] = KNOWN_DEVICES.get(t_mac, f"Device")
                if is_local:
                    d["Total_Local"] += plen
                    d["Apps"]["LAN/Local"] += plen
                    global_stats["clients_local"] += plen
                else:
                    d["Total_Internet"] += plen
                    app = detected if detected else (cached if cached else "Other/Web")
                    d["Apps"][app] += plen
                    global_stats["clients_internet"] += plen
    except:
        pass


def process_wan_packet(packet):
    try:
        if packet.haslayer(IP):
            plen = len(packet)
            with lock:
                global_stats["wan_total"] += plen
            app = analyze_traffic_layer(packet)
            if app:
                with lock:
                    global_stats["wan_apps"][app] += plen
            else:
                src, dst = packet[IP].src, packet[IP].dst
                cached = (
                    ip_to_app_map.get(src, (None,))[0]
                    or ip_to_app_map.get(dst, (None,))[0]
                )
                final_app = cached if cached else "Other/Web"
                with lock:
                    global_stats["wan_apps"][final_app] += plen
    except:
        pass


def update_calculations():
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
# 🚀 Flask & Main
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
            devices_list.append(
                {
                    "mac": mac,
                    "name": dev["Name"],
                    "vendor": dev["Vendor"][:15],
                    "ip": dev["IP"],
                    "speed": dev["Current_Speed"],
                    "total_net": dev["Total_Internet"],
                    "total_loc": dev["Total_Local"],
                    "ip_log": dev["IP_Log"],
                    "apps": apps_list,
                    "is_host": mac == global_stats["host_mac"],
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


def main():
    global host_ip
    os.system("cls" if os.name == "nt" else "clear")
    load_data()
    print(f"\n🌐 Starting Monitor V17.1 (Fixed Colors)...")
    ifaces = get_if_list()
    h_idx, w_idx = -1, -1
    for i, iface in enumerate(ifaces):
        try:
            ip = get_if_addr(iface)
        except:
            ip = "N/A"
        label = ""
        if ip.startswith(HOTSPOT_SUBNET):
            label = " ← HOTSPOT"
            h_idx = i
        elif ip.startswith("192.168.") and not ip.endswith(".1") and ip != "N/A":
            label = " ← WAN"
            w_idx = i
        print(f"[{i}] {iface:<40} {ip:<15} {label}")
    try:
        h_sel = int(input(f"\n👉 Hotspot [{h_idx}]: ") or h_idx)
        w_sel = int(input(f"👉 WAN [{w_idx}]: ") or w_idx)
        host_ip = get_if_addr(ifaces[w_sel])

        t1 = threading.Thread(
            target=lambda: sniff(
                iface=ifaces[h_sel],
                prn=process_client_packet,
                store=0,
                filter="ip",
                promisc=False,
            ),
            daemon=True,
        )
        t2 = threading.Thread(
            target=lambda: sniff(
                iface=ifaces[w_sel],
                prn=process_wan_packet,
                store=0,
                filter="ip",
                promisc=False,
            ),
            daemon=True,
        )
        t1.start()
        t2.start()

        print(f"\n🚀 Dashboard: http://127.0.0.1:{WEB_PORT}")
        print("📝 Edit 'templates/dashboard.html' to customize UI.")
        app.run(host="0.0.0.0", port=WEB_PORT, debug=False, use_reloader=False)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
