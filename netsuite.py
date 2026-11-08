#!/usr/bin/env python3
"""
NetSuite — Combined Network Toolkit
-------------------------------------
A single tabbed desktop app combining:
  1. Network Device Monitor (nmap)      — new devices joining the LAN,
                                            plus deep nmap -A scans on demand
  2. WiFi Scanner (nmcli)               — nearby access points
  3. Brief Connection Watcher (scapy)   — devices connected only briefly

Requirements:
  sudo apt install nmap network-manager python3-tk
  scapy is required for tab 3 (already installed via apt on your system).

Root privileges:
  - Tab 1 (nmap) works without root, but loses MAC/vendor detection.
  - Tab 3 (scapy) REQUIRES root to sniff packets. If not running as root,
    that tab's Start button is disabled with an explanation instead of
    crashing — everything else still works normally.
  - Tab 2 never needs root.

  For full functionality (all three tabs), launch like this so root can
  still open the GUI window:

    sudo -E env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY python3 netsuite.py

  Or just run `python3 netsuite.py` normally and only tab 3 will be limited.
"""

import glob
import json
import os
import queue
import socket
import re
import shutil
import subprocess
import tempfile
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter import font as tkfont
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET


try:
    from scapy.all import sniff, ARP
except (ImportError, OSError):
    sniff = None
    ARP = None

IS_ROOT = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

STATE_FILE = Path.home() / ".netsuite_known_devices.json"
LOG_FILE = Path.home() / "netsuite.log"
TRUSTED_FILE = Path.home() / ".netsuite_trusted_devices.json"
NETSUITE_VERSION = "2.0"

# Shared palette for the personal workspace and tool windows.
BG_COLOR = "#101722"
PANEL_BG = "#172130"
TEXT_COLOR = "#e4eaf2"
FG_COLOR = "#b8d2f5"
ACCENT = "#83b5f4"
WARN = "#ee9297"
GOOD = "#87c8ab"
MEDIUM = "#dcc18b"
MUTED = "#94a4ba"
BORDER = "#2a3749"
SELECTED_BG = "#253b55"
UI_FONT = "DejaVu Sans"
MONO_FONT = "DejaVu Sans Mono"


def log_to_file(message: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")


def notify_desktop(title: str, message: str):
    try:
        subprocess.run(["notify-send", title, message], check=False, timeout=5)
    except Exception:
        pass


class TrustedDevicesManager:
    """Shared, persisted set of trusted MAC addresses. Used by both the
    Network Monitor tab (skip 'new device' alerts) and the Brief Connections
    tab (skip 'brief connection' alerts) so tagging a device trusted once
    quiets it everywhere in the app."""

    def __init__(self):
        self.trusted = self._load()
        self.listeners = []  # callables notified when the set changes

    def _load(self):
        if TRUSTED_FILE.exists():
            try:
                with open(TRUSTED_FILE, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save(self):
        try:
            with open(TRUSTED_FILE, "w") as f:
                json.dump(self.trusted, f, indent=2)
        except OSError:
            pass

    def is_trusted(self, mac):
        if not mac or mac == "-":
            return False
        return mac.upper() in self.trusted

    def add(self, mac, label=""):
        if not mac or mac == "-":
            return
        self.trusted[mac.upper()] = {"label": label, "added": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        self._save()
        self._notify()

    def remove(self, mac):
        self.trusted.pop(mac.upper(), None)
        self._save()
        self._notify()

    def toggle(self, mac, label=""):
        if self.is_trusted(mac):
            self.remove(mac)
        else:
            self.add(mac, label)

    def add_listener(self, callback):
        self.listeners.append(callback)

    def _notify(self):
        for cb in self.listeners:
            try:
                cb()
            except Exception:
                pass


def export_treeview_to_csv(parent_widget, tree, default_name="export.csv"):
    """Exports every row currently shown in a Treeview to a CSV file the user picks."""
    from tkinter import filedialog
    import csv as csv_module

    path = filedialog.asksaveasfilename(
        parent=parent_widget, defaultextension=".csv", initialfile=default_name,
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
    )
    if not path:
        return False

    columns = tree["columns"]
    headers = [tree.heading(col)["text"] for col in columns]

    try:
        with open(path, "w", newline="") as f:
            writer = csv_module.writer(f)
            writer.writerow(headers)
            for item_id in tree.get_children(""):
                writer.writerow(tree.item(item_id, "values"))
        return True
    except OSError as e:
        print(f"[NetSuite] Export failed: {e}")
        return False


def copy_to_clipboard(widget, text):
    widget.clipboard_clear()
    widget.clipboard_append(text)


def show_treeview_context_menu(event, tree, menu_items):
    """Selects the row under the cursor (if any) and pops up a context menu.
    menu_items: list of (label, callback) tuples, or None for a separator."""
    row_id = tree.identify_row(event.y)
    if row_id:
        tree.selection_set(row_id)

    menu = tk.Menu(tree, tearoff=0)
    for item in menu_items:
        if item is None:
            menu.add_separator()
        else:
            label, callback = item
            menu.add_command(label=label, command=callback)
    menu.tk_popup(event.x_root, event.y_root)


class Tooltip:
    """Small hover tooltip explaining what a widget does, in plain language."""

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, event=None):
        if self.tip_window or not self.text:
            return
        x = self.widget.winfo_rootx() + 10
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tip_window = tk.Toplevel(self.widget)
        self.tip_window.wm_overrideredirect(True)
        self.tip_window.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tip_window, text=self.text, justify="left", wraplength=280,
                          background=PANEL_BG, foreground=TEXT_COLOR, relief="solid", borderwidth=1,
                          font=(MONO_FONT, 9), padx=6, pady=4)
        label.pack()

    def hide(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None


def load_known_device_choices():
    """Returns ['ip — label', ...] for devices NetSuite has already discovered, for use in dropdowns."""
    if not STATE_FILE.exists():
        return []
    try:
        with open(STATE_FILE, "r") as f:
            devices = json.load(f)
    except Exception:
        return []
    return [f"{ip} — {info.get('hostname') or info.get('vendor') or 'unknown device'}"
            for ip, info in devices.items()]


def detect_default_gateway():
    """Best-effort parse of `ip route show default` to find the router's IP."""
    try:
        result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
        match = re.search(r"default via (\S+)", result.stdout)
        return match.group(1) if match else ""
    except Exception:
        return ""


# ===========================================================================
# TAB 1 — Network Device Monitor (nmap)
# ===========================================================================

class DeviceMonitorScanner(threading.Thread):
    def __init__(self, network, interval, event_queue, known_devices):
        super().__init__(daemon=True)
        self.network = network
        self.interval = interval
        self.event_queue = event_queue
        self.known_devices = known_devices
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()

    @staticmethod
    def parse_nmap_output(output):
        devices = {}
        current_ip = None
        ip_pattern = re.compile(r"Nmap scan report for (?:(\S+) \()?([\d\.]+)\)?")
        mac_pattern = re.compile(r"MAC Address: ([0-9A-Fa-f:]{17}) \(?([^)]*)\)?")
        for line in output.splitlines():
            ip_match = ip_pattern.search(line)
            if ip_match:
                current_ip = ip_match.group(2)
                devices[current_ip] = {"mac": None, "vendor": None, "hostname": ip_match.group(1)}
                continue
            mac_match = mac_pattern.search(line)
            if mac_match and current_ip:
                devices[current_ip]["mac"] = mac_match.group(1)
                devices[current_ip]["vendor"] = mac_match.group(2) or None
        return devices

    def run(self):
        while not self._stop_flag.is_set():
            self.event_queue.put(("status", f"Scanning {self.network} ..."))
            try:
                result = subprocess.run(["nmap", "-sn", self.network], capture_output=True, text=True, timeout=120)
                if result.returncode != 0:
                    self.event_queue.put(("error", result.stderr.strip() or "nmap error"))
                else:
                    devices = self.parse_nmap_output(result.stdout)
                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    new_ips = [ip for ip in devices if ip not in self.known_devices]
                    for ip in devices:
                        devices[ip]["first_seen"] = self.known_devices.get(ip, {}).get("first_seen", now_str)
                    self.known_devices.update(devices)
                    with open(STATE_FILE, "w") as f:
                        json.dump(self.known_devices, f, indent=2)
                    self.event_queue.put(("devices", dict(self.known_devices)))
                    if new_ips:
                        for ip in new_ips:
                            self.event_queue.put(("new_device", (ip, devices[ip])))
                    else:
                        self.event_queue.put(("status", f"No new devices. {len(devices)} online."))
            except FileNotFoundError:
                self.event_queue.put(("error", "nmap not installed (sudo apt install nmap)"))
                return
            except subprocess.TimeoutExpired:
                self.event_queue.put(("status", "Scan timed out, retrying next cycle."))

            slept = 0
            while slept < self.interval and not self._stop_flag.is_set():
                time.sleep(1)
                slept += 1


class DeepScanThread(threading.Thread):
    """Runs `nmap -A` (OS detection, version detection, scripts, traceroute) against a single host."""

    def __init__(self, target, event_queue):
        super().__init__(daemon=True)
        self.target = target
        self.event_queue = event_queue
        self.process = None
        self._cancelled = False

    def cancel(self):
        self._cancelled = True
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass

    def run(self):
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".xml")
        os.close(tmp_fd)

        cmd = ["nmap", "-A", "-oX", tmp_path, self.target]
        self.event_queue.put(("deep_scan_status", f"Running deep scan on {self.target} (nmap -A) — this can take a few minutes..."))

        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except FileNotFoundError:
            self.event_queue.put(("deep_scan_error", "nmap not installed."))
            return

        raw_lines = []
        for line in self.process.stdout:
            if self._cancelled:
                break
            raw_lines.append(line)

        self.process.wait()

        if self._cancelled:
            self.event_queue.put(("deep_scan_status", "Deep scan cancelled."))
            self._cleanup(tmp_path)
            return

        try:
            results = self._parse_xml(tmp_path)
            results["raw_output"] = "".join(raw_lines)
            self.event_queue.put(("deep_scan_results", results))
        except Exception as e:
            self.event_queue.put(("deep_scan_error", f"Failed to parse scan results: {e}"))
        finally:
            self._cleanup(tmp_path)

    def _parse_xml(self, path):
        tree = ET.parse(path)
        root = tree.getroot()
        host = root.find("host")
        if host is None:
            return {"ports": [], "os_matches": [], "traceroute": [], "state": "no response"}

        status = host.find("status")
        state = status.get("state") if status is not None else "unknown"

        ports_info = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                portid = port.get("portid")
                protocol = port.get("protocol")
                state_el = port.find("state")
                port_state = state_el.get("state") if state_el is not None else "?"
                if port_state != "open":
                    continue
                service_el = port.find("service")
                service_name = service_el.get("name", "?") if service_el is not None else "?"
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                extrainfo = service_el.get("extrainfo", "") if service_el is not None else ""
                ports_info.append({"port": portid, "protocol": protocol, "service": service_name,
                                    "product": product, "version": version, "extrainfo": extrainfo})

        os_matches = []
        os_el = host.find("os")
        if os_el is not None:
            for match in os_el.findall("osmatch"):
                os_matches.append({"name": match.get("name"), "accuracy": match.get("accuracy")})

        traceroute = []
        trace_el = host.find("trace")
        if trace_el is not None:
            for hop in trace_el.findall("hop"):
                traceroute.append({
                    "ttl": hop.get("ttl"), "ip": hop.get("ipaddr"),
                    "host": hop.get("host", ""), "rtt": hop.get("rtt", "?"),
                })

        return {"ports": ports_info, "os_matches": os_matches, "traceroute": traceroute, "state": state}

    def _cleanup(self, path):
        try:
            os.remove(path)
        except Exception:
            pass


class DeepScanWindow:
    """Popup window showing live progress and results of an nmap -A deep scan."""

    def __init__(self, parent, target):
        self.target = target
        self.event_queue = queue.Queue()
        self.scan_thread = None

        self.win = tk.Toplevel(parent)
        self.win.title(f"Deep Scan — {target}")
        self.win.geometry("820x600")
        self.win.configure(bg=BG_COLOR)

        style_frame = ttk.Frame(self.win, padding=10)
        style_frame.pack(fill="x")
        ttk.Label(style_frame, text=f"Target: {target}", font=(MONO_FONT, 13, "bold")).pack(anchor="w")
        self.status_label = ttk.Label(style_frame, text="Starting scan...")
        self.status_label.pack(anchor="w", pady=(5, 0))

        self.cancel_button = ttk.Button(style_frame, text="Cancel Scan", command=self.cancel)
        self.cancel_button.pack(anchor="e")

        notebook = ttk.Notebook(self.win)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        ports_tab = ttk.Frame(notebook, padding=8)
        notebook.add(ports_tab, text="Open Ports & Services")
        columns = ("port", "protocol", "service", "product", "version", "extrainfo")
        self.ports_tree = ttk.Treeview(ports_tab, columns=columns, show="headings", height=14)
        for col, label, width in [("port", "Port", 70), ("protocol", "Proto", 60), ("service", "Service", 110),
                                   ("product", "Product", 150), ("version", "Version", 100), ("extrainfo", "Extra Info", 150)]:
            self.ports_tree.heading(col, text=label)
            self.ports_tree.column(col, width=width, anchor="w")
        self.ports_tree.pack(fill="both", expand=True)

        os_tab = ttk.Frame(notebook, padding=8)
        notebook.add(os_tab, text="OS Detection")
        self.os_text = tk.Text(os_tab, wrap="word", bg="#111c2a", fg=TEXT_COLOR, font=(MONO_FONT, 10))
        self.os_text.pack(fill="both", expand=True)

        trace_tab = ttk.Frame(notebook, padding=8)
        notebook.add(trace_tab, text="Traceroute")
        trace_columns = ("ttl", "ip", "host", "rtt")
        self.trace_tree = ttk.Treeview(trace_tab, columns=trace_columns, show="headings", height=14)
        for col, label, width in [("ttl", "Hop", 60), ("ip", "IP", 150), ("host", "Hostname", 220), ("rtt", "RTT", 100)]:
            self.trace_tree.heading(col, text=label)
            self.trace_tree.column(col, width=width, anchor="w")
        self.trace_tree.pack(fill="both", expand=True)

        raw_tab = ttk.Frame(notebook, padding=8)
        notebook.add(raw_tab, text="Raw Output")
        self.raw_text = tk.Text(raw_tab, wrap="word", bg="#111c2a", fg=TEXT_COLOR, font=(MONO_FONT, 9))
        self.raw_text.pack(fill="both", expand=True)

        self.win.protocol("WM_DELETE_WINDOW", self.on_close)
        self.start_scan()
        self._poll_queue()

    def start_scan(self):
        self.scan_thread = DeepScanThread(self.target, self.event_queue)
        self.scan_thread.start()

    def cancel(self):
        if self.scan_thread:
            self.scan_thread.cancel()
        self.cancel_button.config(state="disabled")

    def on_close(self):
        if self.scan_thread:
            self.scan_thread.cancel()
        self.win.destroy()

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "deep_scan_status":
                    self.status_label.config(text=payload)
                elif kind == "deep_scan_error":
                    self.status_label.config(text=f"Error: {payload}", foreground=WARN)
                    self.cancel_button.config(state="disabled")
                elif kind == "deep_scan_results":
                    self._display_results(payload)
                    self.cancel_button.config(state="disabled")
        except queue.Empty:
            pass
        if self.win.winfo_exists():
            self.win.after(300, self._poll_queue)

    def _display_results(self, results):
        if results["state"] != "up" and not results["ports"]:
            self.status_label.config(text=f"Host did not respond (state: {results['state']}).")
        else:
            self.status_label.config(text="Scan complete.")

        for p in results["ports"]:
            self.ports_tree.insert("", "end", values=(p["port"], p["protocol"], p["service"],
                                                         p["product"], p["version"], p["extrainfo"]))

        self.os_text.insert("1.0", "OS Detection Guesses (best match first):\n\n")
        if results["os_matches"]:
            for m in results["os_matches"]:
                self.os_text.insert("end", f"  {m['accuracy']}% match — {m['name']}\n")
        else:
            self.os_text.insert("end", "  No confident OS match (host may be firewalled or filtering probes).\n")
        self.os_text.config(state="disabled")

        for hop in results["traceroute"]:
            self.trace_tree.insert("", "end", values=(hop["ttl"], hop["ip"] or "*", hop["host"], hop["rtt"]))

        self.raw_text.insert("1.0", results.get("raw_output", "(no raw output captured)"))
        self.raw_text.config(state="disabled")


class DeviceMonitorTab:
    def __init__(self, parent, trusted_manager):
        self.frame = ttk.Frame(parent, padding=10)
        self.event_queue = queue.Queue()
        self.known_devices = self._load_known_devices()
        self.scanner_thread = None
        self.row_ips = {}
        self.trusted_manager = trusted_manager
        self.trusted_manager.add_listener(lambda: self._refresh_table(self.known_devices))
        self._build_ui()
        self._poll_queue()
        if self.known_devices:
            self._refresh_table(self.known_devices)

    def _load_known_devices(self):
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _build_ui(self):
        controls = ttk.Frame(self.frame)
        controls.pack(fill="x")

        ttk.Label(controls, text="Network:").grid(row=0, column=0, sticky="w")
        self.network_entry = ttk.Entry(controls, width=20)
        self.network_entry.insert(0, "192.168.50.0/24")
        self.network_entry.grid(row=0, column=1, padx=(5, 15))

        ttk.Label(controls, text="Interval (sec):").grid(row=0, column=2, sticky="w")
        self.interval_entry = ttk.Entry(controls, width=8)
        self.interval_entry.insert(0, "600")
        self.interval_entry.grid(row=0, column=3, padx=(5, 15))

        self.start_button = ttk.Button(controls, text="Monitor", command=self.start)
        self.start_button.grid(row=0, column=4, padx=5)
        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop, state="disabled")
        self.stop_button.grid(row=0, column=5, padx=5)
        self.clear_button = ttk.Button(controls, text="Clear", command=self.clear_devices)
        self.clear_button.grid(row=0, column=6, padx=5)
        self.export_button = ttk.Button(controls, text="Export CSV", command=self.export_csv)
        self.export_button.grid(row=0, column=7, padx=5)

        self.status_label = ttk.Label(self.frame, text="Idle.")
        self.status_label.pack(fill="x", pady=(5, 5))

        search_row = ttk.Frame(self.frame)
        search_row.pack(fill="x", pady=(0, 5))
        ttk.Label(search_row, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self._refresh_table(self.known_devices))
        search_entry = ttk.Entry(search_row, textvariable=self.search_var, width=30)
        search_entry.pack(side="left", padx=(5, 0))

        columns = ("ip", "hostname", "mac", "vendor", "trusted", "first_seen")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings", height=12)
        for col, label, width in [("ip", "IP", 120), ("hostname", "Hostname", 140),
                                   ("mac", "MAC", 140), ("vendor", "Vendor", 140),
                                   ("trusted", "Trusted", 70), ("first_seen", "First Seen", 140)]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")
        self.tree.tag_configure("new", background=SELECTED_BG, foreground=ACCENT)
        self.tree.tag_configure("trusted", foreground=GOOD)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.pack(fill="both", expand=True)

        action_row = ttk.Frame(self.frame)
        action_row.pack(fill="x", pady=(8, 0))
        self.deep_scan_button = ttk.Button(action_row, text="Inspect selected device",
                                            command=self.deep_scan_selected, state="disabled")
        self.deep_scan_button.pack(anchor="e")

        ttk.Label(self.frame, text="Activity Log:").pack(anchor="w", pady=(10, 0))
        self.log_text = tk.Text(self.frame, height=6, state="disabled", wrap="word", bg="#111c2a", fg=TEXT_COLOR)
        self.log_text.pack(fill="both", expand=False)

    def _on_select(self, event):
        selection = self.tree.selection()
        self.deep_scan_button.config(state="normal" if selection else "disabled")

    def _on_right_click(self, event):
        values = self.tree.item(self.tree.identify_row(event.y), "values") if self.tree.identify_row(event.y) else None
        if not values:
            return
        ip, mac = values[0], values[2]
        is_trusted = self.trusted_manager.is_trusted(mac)
        trust_label = "Remove Trusted Tag" if is_trusted else "Mark as Trusted"

        show_treeview_context_menu(event, self.tree, [
            ("Copy IP", lambda: copy_to_clipboard(self.tree, ip)),
            ("Copy MAC", lambda: copy_to_clipboard(self.tree, mac)),
            None,
            ("Deep Scan (nmap -A)", lambda: self._deep_scan_ip(ip)),
            None,
            (trust_label, lambda: self._toggle_trusted(mac)),
        ])

    def _toggle_trusted(self, mac):
        self.trusted_manager.toggle(mac)
        self._refresh_table(self.known_devices)

    def _deep_scan_ip(self, ip):
        DeepScanWindow(self.frame.winfo_toplevel(), ip)
        self._log(f"Started deep scan (nmap -A) on {ip}.")

    def deep_scan_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        ip = self.tree.item(selection[0], "values")[0]
        self._deep_scan_ip(ip)

    def export_csv(self):
        if not self.tree.get_children():
            self._log("Nothing to export — no devices yet.")
            return
        if export_treeview_to_csv(self.frame, self.tree, "netsuite_devices.csv"):
            self._log("Exported device table to CSV.")

    def clear_devices(self):
        if not self.known_devices:
            self._log("Nothing to clear — no devices remembered yet.")
            return
        self.known_devices.clear()
        self.tree.delete(*self.tree.get_children())
        self.row_ips.clear()
        try:
            if STATE_FILE.exists():
                STATE_FILE.unlink()
        except OSError:
            pass
        self.deep_scan_button.config(state="disabled")
        self._log("Cleared all remembered devices.")

    def start(self):
        network = self.network_entry.get().strip()
        try:
            interval = int(self.interval_entry.get().strip())
        except ValueError:
            self.status_label.config(text="Interval must be a whole number of seconds.", foreground=WARN)
            return
        if not network:
            self.status_label.config(text="Enter a network range first, e.g. 192.168.1.0/24", foreground=WARN)
            return
        self.scanner_thread = DeviceMonitorScanner(network, interval, self.event_queue, self.known_devices)
        self.scanner_thread.start()
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self._log(f"Started monitoring {network} every {interval}s.")

    def stop(self):
        if self.scanner_thread:
            self.scanner_thread.stop()
            self.scanner_thread = None
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_label.config(text="Stopped.")
        self._log("Stopped monitoring.")

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "status":
                    self.status_label.config(text=payload)
                    self._log(payload)
                elif kind == "error":
                    self.status_label.config(text=f"Error: {payload}")
                    self._log(f"ERROR: {payload}")
                elif kind == "devices":
                    self._refresh_table(payload)
                elif kind == "new_device":
                    ip, info = payload
                    self._handle_new_device(ip, info)
        except queue.Empty:
            pass
        self.frame.after(200, self._poll_queue)

    def _refresh_table(self, devices):
        self.tree.delete(*self.tree.get_children())
        self.row_ips.clear()
        query = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""
        for ip, info in sorted(devices.items(), key=lambda kv: tuple(int(p) for p in kv[0].split("."))):
            haystack = " ".join([ip, info.get("hostname") or "", info.get("mac") or "", info.get("vendor") or ""]).lower()
            if query and query not in haystack:
                continue
            mac = info.get("mac") or "-"
            is_trusted = self.trusted_manager.is_trusted(mac)
            item_id = self.tree.insert("", "end", values=(
                ip, info.get("hostname") or "-", mac,
                info.get("vendor") or "-", "✓ Trusted" if is_trusted else "-",
                info.get("first_seen") or "-"),
                tags=("trusted",) if is_trusted else ())
            self.row_ips[item_id] = ip

    def _handle_new_device(self, ip, info):
        mac = info.get("mac") or "-"
        if self.trusted_manager.is_trusted(mac):
            self._log(f"New device seen but TRUSTED, no alert: {ip} ({mac})")
            return

        description = ip
        if info.get("hostname"):
            description += f" ({info['hostname']})"
        if info.get("vendor"):
            description += f" — {info['vendor']}"
        self._log(f"NEW DEVICE DETECTED: {description}")
        log_to_file(f"[NetworkMonitor] NEW DEVICE: {description}")
        for item_id, item_ip in self.row_ips.items():
            if item_ip == ip:
                self.tree.item(item_id, tags=("new",))
        notify_desktop("New device on your network!", description)

    def _log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")


# ===========================================================================
# TAB 2 — WiFi Scanner (nmcli)
# ===========================================================================

# ===========================================================================
# WiFi Security Test (aircrack-ng, invoked from the WiFi Scanner tab)
# ---------------------------------------------------------------------------
# ⚠ Only test networks you own or have explicit written authorization to
# test. Deauth packets disrupt real connected devices. This entire feature
# is gated behind an explicit acknowledgment checkbox before anything active
# (deauth) can run, and monitor mode is ALWAYS restored to managed mode
# afterward — even if the window is closed mid-process — so your normal
# WiFi Scanner tab keeps working once a test finishes.
# ===========================================================================

def run_shell(cmd, timeout=30):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"{cmd[0]} not found — is aircrack-ng installed? (sudo apt install aircrack-ng)"
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out."


def list_wifi_interfaces():
    code, out, err = run_shell(["iw", "dev"])
    interfaces = []
    if code == 0:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Interface"):
                interfaces.append(line.split()[1])
    return interfaces


class SecurityTestMonitorManager:
    """Puts ONE interface into monitor mode without disturbing NetworkManager's
    control of anything else, and always hands it back cleanly afterward."""

    def __init__(self, log_fn):
        self.log = log_fn
        self.monitor_iface = None
        self.original_iface = None

    def enable(self, iface):
        self.log(f"Pausing normal WiFi management on {iface} (other connections stay up)...")
        run_shell(["nmcli", "device", "set", iface, "managed", "no"], timeout=10)
        time.sleep(1)

        before = set(list_wifi_interfaces())
        self.log(f"Switching {iface} into monitor mode...")
        code, out, err = run_shell(["airmon-ng", "start", iface], timeout=15)
        if code != 0:
            run_shell(["nmcli", "device", "set", iface, "managed", "yes"], timeout=10)
            return None, err or "Failed to start monitor mode."

        time.sleep(1.5)
        after = set(list_wifi_interfaces())
        new_candidates = after - before
        new_iface = next((c for c in new_candidates if "mon" in c), None) \
            or (next(iter(new_candidates), None) if new_candidates else None) \
            or next((c for c in after if "mon" in c), None) \
            or iface

        self.original_iface = iface
        self.monitor_iface = new_iface
        self.log(f"Monitor mode active on '{new_iface}'.")
        return new_iface, None

    def disable(self):
        if not self.monitor_iface:
            return
        self.log(f"Restoring {self.monitor_iface} to normal WiFi mode...")
        run_shell(["airmon-ng", "stop", self.monitor_iface], timeout=15)
        if self.original_iface:
            run_shell(["nmcli", "device", "set", self.original_iface, "managed", "yes"], timeout=10)
        self.log("Done — normal WiFi scanning is available again.")
        self.monitor_iface = None
        self.original_iface = None


class HandshakeCaptureThread(threading.Thread):
    def __init__(self, iface, bssid, channel, event_queue, cap_prefix):
        super().__init__(daemon=True)
        self.iface = iface
        self.bssid = bssid
        self.channel = channel
        self.event_queue = event_queue
        self.cap_prefix = cap_prefix
        self.process = None
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass

    def run(self):
        cmd = ["airodump-ng", "--bssid", self.bssid, "--channel", str(self.channel),
               "--write", self.cap_prefix, "--output-format", "pcap", self.iface]
        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            self.event_queue.put(("sectest_error", "airodump-ng not found."))
            return

        self.event_queue.put(("sectest_status", f"Listening for a handshake on channel {self.channel}..."))

        while not self._stop_flag.is_set():
            time.sleep(3)
            cap_file = self._find_cap_file()
            if cap_file and self._check_handshake(cap_file):
                self.event_queue.put(("sectest_handshake_captured", cap_file))
                break

        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()

    def _find_cap_file(self):
        matches = sorted(glob.glob(self.cap_prefix + "-*.cap"))
        return matches[-1] if matches else None

    def _check_handshake(self, cap_file):
        code, out, err = run_shell(["aircrack-ng", cap_file], timeout=15)
        return "1 handshake" in out or ("handshake" in out.lower() and "0 handshake" not in out.lower())


def send_deauth_packets(iface, bssid, client_mac=None, count=5):
    cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
    if client_mac:
        cmd += ["-c", client_mac]
    cmd.append(iface)
    return run_shell(cmd, timeout=20)


class PasswordCrackThread(threading.Thread):
    def __init__(self, cap_file, wordlist, bssid, event_queue):
        super().__init__(daemon=True)
        self.cap_file = cap_file
        self.wordlist = wordlist
        self.bssid = bssid
        self.event_queue = event_queue
        self.process = None
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass

    def run(self):
        cmd = ["aircrack-ng", "-w", self.wordlist, "-b", self.bssid, self.cap_file]
        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except FileNotFoundError:
            self.event_queue.put(("sectest_error", "aircrack-ng not found."))
            return

        self.event_queue.put(("sectest_status", "Cracking — this can take a while depending on wordlist size..."))

        for line in self.process.stdout:
            if self._stop_flag.is_set():
                break
            line = line.strip()
            if not line:
                continue
            self.event_queue.put(("sectest_crack_line", line))
            key_match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", line)
            if key_match:
                self.event_queue.put(("sectest_crack_success", key_match.group(1)))

        self.process.wait()
        if not self._stop_flag.is_set():
            self.event_queue.put(("sectest_crack_done", None))


class SecurityTestWindow:
    """Guided popup: enable monitor mode -> capture handshake (+ optional
    deauth) -> crack with a wordlist -> always restore managed mode on close."""

    def __init__(self, parent, bssid, essid, channel, security):
        self.bssid = bssid
        self.essid = essid
        self.channel = channel
        self.security = security
        self.event_queue = queue.Queue()

        self.monitor_mgr = SecurityTestMonitorManager(self._log)
        self.capture_thread = None
        self.crack_thread = None
        self.current_cap_file = None
        self.authorized = tk.BooleanVar(value=False)

        self.win = tk.Toplevel(parent)
        self.win.title(f"Security Test — {essid}")
        self.win.geometry("760x640")
        self.win.configure(bg=BG_COLOR)
        self.win.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        header = ttk.Frame(self.win, padding=12)
        header.pack(fill="x")
        ttk.Label(header, text=f"{self.essid}  ({self.bssid})  •  ch {self.channel}  •  {self.security}",
                  font=(MONO_FONT, 13, "bold"), foreground=ACCENT).pack(anchor="w")

        if not self.security or self.security.upper() in ("", "--", "NONE", "OPEN"):
            ttk.Label(header, foreground=MEDIUM, wraplength=700, justify="left",
                      text="This network is open (no password) — nothing to crack. Worth knowing: anyone "
                           "nearby can join it and see unencrypted traffic.").pack(anchor="w", pady=(10, 0))
            return

        auth_check = ttk.Checkbutton(header, variable=self.authorized, command=self._on_auth_toggle,
                                      text="I own this network / have authorization to test it")
        auth_check.pack(anchor="w", pady=(8, 5))

        step_frame = ttk.Frame(self.win, padding=(12, 0))
        step_frame.pack(fill="x")

        ttk.Label(step_frame, text="Interface:").grid(row=0, column=0, sticky="w")
        self.iface_combo = ttk.Combobox(step_frame, width=15, values=list_wifi_interfaces(), state="readonly")
        if self.iface_combo["values"]:
            self.iface_combo.current(0)
        self.iface_combo.grid(row=0, column=1, padx=(5, 15))

        self.start_button = ttk.Button(step_frame, text="1. Start Capture (monitor mode)",
                                        command=self.start_capture, state="disabled")
        self.start_button.grid(row=0, column=2, padx=5)

        self.deauth_button = ttk.Button(step_frame, text="Send Deauth (speed up capture)",
                                         command=self.do_deauth, state="disabled")
        self.deauth_button.grid(row=0, column=3, padx=5)

        self.stop_button = ttk.Button(step_frame, text="Stop / Restore WiFi", command=self.stop_and_restore)
        self.stop_button.grid(row=1, column=0, columnspan=2, pady=(10, 0), sticky="w")

        self.handshake_status = ttk.Label(step_frame, text="Handshake captured: No", foreground=WARN)
        self.handshake_status.grid(row=1, column=2, columnspan=2, pady=(10, 0), sticky="w")

        crack_frame = ttk.Frame(self.win, padding=12)
        crack_frame.pack(fill="x")
        ttk.Label(crack_frame, text="2. Wordlists (tried in order):").pack(anchor="w")

        wordlist_row = ttk.Frame(crack_frame)
        wordlist_row.pack(fill="x", pady=(4, 0))
        self.wordlist_listbox = tk.Listbox(wordlist_row, height=4, bg=PANEL_BG, fg=TEXT_COLOR, selectbackground=SELECTED_BG, relief="flat", highlightthickness=1, highlightbackground=BORDER)
        self.wordlist_listbox.pack(side="left", fill="x", expand=True)
        self.wordlist_listbox.insert("end", "/usr/share/wordlists/rockyou.txt")

        list_buttons = ttk.Frame(wordlist_row)
        list_buttons.pack(side="left", padx=(8, 0))
        ttk.Button(list_buttons, text="Add...", command=self.add_wordlist).pack(fill="x", pady=(0, 4))
        ttk.Button(list_buttons, text="Remove Selected", command=self.remove_wordlist).pack(fill="x")

        self.crack_button = ttk.Button(crack_frame, text="Start Cracking", command=self.start_crack, state="disabled")
        self.crack_button.pack(anchor="e", pady=(8, 0))

        self.result_label = ttk.Label(self.win, text="", font=(MONO_FONT, 14, "bold"), padding=(12, 5))
        self.result_label.pack(fill="x")

        ttk.Label(self.win, text="Activity Log:", padding=(12, 0)).pack(anchor="w")
        self.log_text = tk.Text(self.win, height=14, state="disabled", wrap="word", bg="#111c2a", fg=TEXT_COLOR)
        self.log_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _on_auth_toggle(self):
        enabled = self.authorized.get()
        self.start_button.config(state="normal" if enabled else "disabled")
        self.deauth_button.config(state="normal" if (enabled and self.capture_thread) else "disabled")

    def add_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.wordlist_listbox.insert("end", path)

    def remove_wordlist(self):
        selection = self.wordlist_listbox.curselection()
        if selection:
            self.wordlist_listbox.delete(selection[0])

    # ---------------- Workflow actions ----------------

    def start_capture(self):
        iface = self.iface_combo.get()
        if not iface:
            self._log("Select a wireless interface first.")
            return

        self.start_button.config(state="disabled")

        def worker():
            new_iface, error = self.monitor_mgr.enable(iface)
            if error:
                self.event_queue.put(("sectest_error", error))
                return
            self.event_queue.put(("sectest_monitor_ready", new_iface))

        threading.Thread(target=worker, daemon=True).start()

    def _begin_capture_thread(self, monitor_iface):
        cap_prefix = os.path.join(tempfile.gettempdir(), f"netsuite_sectest_{self.bssid.replace(':', '')}")
        for f in glob.glob(cap_prefix + "*"):
            try:
                os.remove(f)
            except OSError:
                pass
        self.capture_thread = HandshakeCaptureThread(monitor_iface, self.bssid, self.channel, self.event_queue, cap_prefix)
        self.capture_thread.start()
        if self.authorized.get():
            self.deauth_button.config(state="normal")

    def do_deauth(self):
        if not self.authorized.get() or not self.monitor_mgr.monitor_iface:
            return
        confirm = messagebox.askyesno(
            "Confirm deauth",
            f"Send deauthentication packets to {self.bssid} ({self.essid})?\n\n"
            "This disconnects real devices from the network momentarily, forcing them to reconnect "
            "and (hopefully) letting us capture the handshake faster. Only proceed with authorization."
        )
        if not confirm:
            return

        iface = self.monitor_mgr.monitor_iface

        def worker():
            code, out, err = send_deauth_packets(iface, self.bssid)
            if code == 0:
                self.event_queue.put(("sectest_status", "Deauth packets sent."))
            else:
                self.event_queue.put(("sectest_status", f"Deauth may have failed: {err.strip() if err else 'unknown error'}"))

        threading.Thread(target=worker, daemon=True).start()
        self._log(f"Sent deauth to {self.bssid}.")

    def stop_and_restore(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread = None
        threading.Thread(target=self.monitor_mgr.disable, daemon=True).start()
        self.start_button.config(state="normal" if self.authorized.get() else "disabled")
        self.deauth_button.config(state="disabled")

    def start_crack(self):
        wordlists = list(self.wordlist_listbox.get(0, "end"))
        wordlists = [w for w in wordlists if os.path.exists(w)]
        if not self.current_cap_file or not os.path.exists(self.current_cap_file):
            self._log("Capture a handshake before cracking.")
            return
        if not wordlists:
            self._log("Add at least one valid wordlist file first.")
            return

        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")
        self.result_label.config(text="")

        # aircrack-ng accepts multiple wordlists as a comma-separated -w argument,
        # trying each one in order until the key is found or all are exhausted.
        combined_wordlist_arg = ",".join(wordlists)
        self._log(f"Trying {len(wordlists)} wordlist(s) in order: {', '.join(wordlists)}")
        self.crack_thread = PasswordCrackThread(self.current_cap_file, combined_wordlist_arg, self.bssid, self.event_queue)
        self.crack_thread.start()
        self.crack_button.config(state="disabled")

    def on_close(self):
        if self.capture_thread:
            self.capture_thread.stop()
        if self.crack_thread:
            self.crack_thread.stop()
        if self.monitor_mgr.monitor_iface:
            self._log("Window closing — restoring WiFi before exit...")
            self.monitor_mgr.disable()
        self.win.destroy()

    # ---------------- Queue polling ----------------

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "sectest_status":
                    self._log(payload)
                elif kind == "sectest_error":
                    self._log(f"ERROR: {payload}")
                    self.start_button.config(state="normal" if self.authorized.get() else "disabled")
                elif kind == "sectest_monitor_ready":
                    self._begin_capture_thread(payload)
                elif kind == "sectest_handshake_captured":
                    self.current_cap_file = payload
                    self.handshake_status.config(text=f"Handshake captured: YES", foreground=GOOD)
                    self._log(f"Handshake captured: {payload}")
                    self.crack_button.config(state="normal")
                    self.deauth_button.config(state="disabled")
                    try:
                        subprocess.run(["notify-send", "Handshake captured!", f"{self.essid} ({self.bssid})"],
                                        check=False, timeout=5)
                    except Exception:
                        pass
                elif kind == "sectest_crack_line":
                    self.log_text.config(state="normal")
                    self.log_text.insert("end", payload + "\n")
                    self.log_text.see("end")
                    self.log_text.config(state="disabled")
                elif kind == "sectest_crack_success":
                    self.result_label.config(text=f"Password found: {payload}", foreground=GOOD)
                    self.crack_button.config(state="normal")
                    try:
                        subprocess.run(["notify-send", "WiFi password cracked!", f"{self.essid}: {payload}"],
                                        check=False, timeout=5)
                    except Exception:
                        pass
                elif kind == "sectest_crack_done":
                    if not self.result_label.cget("text"):
                        self.result_label.config(text="No match in the selected wordlists.", foreground=WARN)
                    self.crack_button.config(state="normal")
        except queue.Empty:
            pass
        if self.win.winfo_exists():
            self.win.after(300, self._poll_queue)

    def _log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")


class WifiScannerThread(threading.Thread):
    def __init__(self, event_queue, interval, auto_refresh):
        super().__init__(daemon=True)
        self.event_queue = event_queue
        self.interval = interval
        self.auto_refresh = auto_refresh
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()

    @staticmethod
    def split_terse_line(line):
        parts = re.split(r"(?<!\\):", line)
        return [p.replace("\\:", ":") for p in parts]

    def scan(self):
        fields = ["SSID", "BSSID", "CHAN", "SIGNAL", "SECURITY", "RATE"]
        cmd = ["nmcli", "-t", "-f", ",".join(fields), "dev", "wifi", "list", "--rescan", "yes"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "nmcli error")
        networks = []
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            parts = self.split_terse_line(line)
            if len(parts) < 6:
                continue
            ssid, bssid, chan, signal, security, rate = parts[:6]
            networks.append({
                "ssid": ssid if ssid else "<Hidden Network>",
                "bssid": bssid, "channel": chan,
                "signal": int(signal) if signal.isdigit() else 0,
                "security": security if security else "Open", "rate": rate,
            })
        networks.sort(key=lambda n: n["signal"], reverse=True)
        return networks

    def run(self):
        while not self._stop_flag.is_set():
            try:
                self.event_queue.put(("networks", self.scan()))
            except FileNotFoundError:
                self.event_queue.put(("error", "nmcli not found (sudo apt install network-manager)"))
                return
            except Exception as e:
                self.event_queue.put(("error", str(e)))
            if not self.auto_refresh:
                break
            slept = 0
            while slept < self.interval and not self._stop_flag.is_set():
                time.sleep(1)
                slept += 1


def signal_bars(signal):
    if signal >= 80:
        return "▂▄▆█"
    elif signal >= 60:
        return "▂▄▆_"
    elif signal >= 40:
        return "▂▄__"
    elif signal >= 20:
        return "▂___"
    return "____"


class WifiScannerTab:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self.event_queue = queue.Queue()
        self.scanner_thread = None
        self.last_networks = []
        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        controls = ttk.Frame(self.frame)
        controls.pack(fill="x")

        self.scan_button = ttk.Button(controls, text="Scan Now", command=self.scan_once)
        self.scan_button.grid(row=0, column=0, padx=(0, 15))

        self.auto_refresh_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(controls, text="Auto-refresh every", variable=self.auto_refresh_var,
                         command=self._toggle_auto_refresh).grid(row=0, column=1)

        self.interval_entry = ttk.Entry(controls, width=6)
        self.interval_entry.insert(0, "30")
        self.interval_entry.grid(row=0, column=2, padx=5)
        ttk.Label(controls, text="sec").grid(row=0, column=3)

        self.status_label = ttk.Label(controls, text="Idle.")
        self.status_label.grid(row=0, column=4, padx=20)

        self.clear_button = ttk.Button(controls, text="Clear Results", command=self.clear_results)
        self.clear_button.grid(row=0, column=5, padx=5)
        self.export_button = ttk.Button(controls, text="Export CSV", command=self.export_csv)
        self.export_button.grid(row=0, column=6, padx=5)

        search_row = ttk.Frame(self.frame)
        search_row.pack(fill="x", pady=(8, 5))
        ttk.Label(search_row, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self._refresh_table(self.last_networks))
        search_entry = ttk.Entry(search_row, textvariable=self.search_var, width=30)
        search_entry.pack(side="left", padx=(5, 0))

        columns = ("ssid", "signal", "bars", "channel", "security", "bssid", "rate")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings", height=14)
        for col, label, width in [("ssid", "SSID", 200), ("signal", "Signal %", 70), ("bars", "Strength", 90),
                                   ("channel", "Channel", 70), ("security", "Security", 130),
                                   ("bssid", "BSSID", 150), ("rate", "Rate", 100)]:
            self.tree.heading(col, text=label, command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=width, anchor="w")
        self.tree.tag_configure("strong", foreground=GOOD)
        self.tree.tag_configure("weak", foreground=WARN)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.pack(fill="both", expand=True, pady=(10, 0))

        self.count_label = ttk.Label(self.frame, text="No scan yet.")
        self.count_label.pack(anchor="w", pady=(5, 0))

        action_row = ttk.Frame(self.frame)
        action_row.pack(fill="x", pady=(8, 0))
        ttk.Label(action_row, text="Wireless workspace", foreground=MUTED).pack(side="left")
        self.security_test_button = ttk.Button(action_row, text="Inspect wireless security",
                                                 command=self.test_security_selected, state="disabled")
        self.security_test_button.pack(side="right")

    def _on_select(self, event):
        self.security_test_button.config(state="normal" if self.tree.selection() else "disabled")

    def _selected_network_values(self):
        selection = self.tree.selection()
        if not selection:
            return None
        return self.tree.item(selection[0], "values")

    def test_security_selected(self):
        values = self._selected_network_values()
        if not values:
            return
        ssid, signal, bars, channel, security, bssid, rate = values
        SecurityTestWindow(self.frame.winfo_toplevel(), bssid, ssid, channel, security)

    def _on_right_click(self, event):
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return
        self.tree.selection_set(row_id)
        values = self.tree.item(row_id, "values")
        ssid, signal, bars, channel, security, bssid, rate = values
        show_treeview_context_menu(event, self.tree, [
            ("Copy SSID", lambda: copy_to_clipboard(self.tree, ssid)),
            ("Copy BSSID", lambda: copy_to_clipboard(self.tree, bssid)),
            None,
            ("Test Security (crack password)...", lambda: SecurityTestWindow(
                self.frame.winfo_toplevel(), bssid, ssid, channel, security)),
        ])

    def export_csv(self):
        if not self.tree.get_children():
            self.status_label.config(text="Nothing to export yet.")
            return
        if export_treeview_to_csv(self.frame, self.tree, "netsuite_wifi_scan.csv"):
            self.status_label.config(text="Exported to CSV.")

    def clear_results(self):
        self.last_networks = []
        self.tree.delete(*self.tree.get_children())
        self.count_label.config(text="No scan yet.")

    def scan_once(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            return
        self.status_label.config(text="Scanning...")
        self.scanner_thread = WifiScannerThread(self.event_queue, interval=0, auto_refresh=False)
        self.scanner_thread.start()

    def _toggle_auto_refresh(self):
        if self.auto_refresh_var.get():
            try:
                interval = int(self.interval_entry.get().strip())
                if interval < 5:
                    raise ValueError
            except ValueError:
                self.status_label.config(text="Enter 5 or more seconds.", foreground=WARN)
                self.auto_refresh_var.set(False)
                return
            if self.scanner_thread and self.scanner_thread.is_alive():
                self.scanner_thread.stop()
            self.scanner_thread = WifiScannerThread(self.event_queue, interval=interval, auto_refresh=True)
            self.scanner_thread.start()
            self.status_label.config(text=f"Auto-refreshing every {interval}s...")
        else:
            if self.scanner_thread:
                self.scanner_thread.stop()
            self.status_label.config(text="Auto-refresh stopped.")

    def _sort_by(self, col):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        if col in ("signal", "channel"):
            items.sort(key=lambda t: int(t[0]) if t[0].isdigit() else 0, reverse=True)
        else:
            items.sort(key=lambda t: t[0].lower())
        for index, (_, k) in enumerate(items):
            self.tree.move(k, "", index)

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "networks":
                    self._refresh_table(payload)
                    if not self.auto_refresh_var.get():
                        self.status_label.config(text="Idle.")
                elif kind == "error":
                    self.status_label.config(text=f"Error: {payload}")
                    self.count_label.config(text=payload)
        except queue.Empty:
            pass
        self.frame.after(300, self._poll_queue)

    def _refresh_table(self, networks):
        self.last_networks = networks
        self.tree.delete(*self.tree.get_children())
        query = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""
        shown = 0
        for net in networks:
            haystack = f"{net['ssid']} {net['bssid']} {net['security']}".lower()
            if query and query not in haystack:
                continue
            shown += 1
            tag = "strong" if net["signal"] >= 60 else ("weak" if net["signal"] < 30 else "")
            self.tree.insert("", "end", values=(net["ssid"], net["signal"], signal_bars(net["signal"]),
                                                 net["channel"], net["security"], net["bssid"], net["rate"]),
                              tags=(tag,) if tag else ())
        if query:
            self.count_label.config(text=f"{shown} of {len(networks)} network(s) match.")
        else:
            self.count_label.config(text=f"{len(networks)} network(s) found.")


# ===========================================================================
# TAB 3 — Brief Connection Watcher (scapy)
# ===========================================================================

STALE_TIMEOUT = 6
BRIEF_THRESHOLD = 10


class BriefWatcherThread(threading.Thread):
    def __init__(self, iface, event_queue):
        super().__init__(daemon=True)
        self.iface = iface
        self.event_queue = event_queue
        self._stop_flag = threading.Event()
        self.active_sessions = {}
        self.lock = threading.Lock()

    def stop(self):
        self._stop_flag.set()

    def _handle_packet(self, pkt):
        if not pkt.haslayer(ARP):
            return
        mac = pkt[ARP].hwsrc
        ip = pkt[ARP].psrc
        now = time.time()
        with self.lock:
            if mac not in self.active_sessions:
                self.active_sessions[mac] = {"ip": ip, "first_seen": now, "last_seen": now}
                self.event_queue.put(("device_appeared", {"mac": mac, "ip": ip}))
            else:
                self.active_sessions[mac]["last_seen"] = now
                self.active_sessions[mac]["ip"] = ip

    def _check_stale(self):
        now = time.time()
        with self.lock:
            stale = [m for m, s in self.active_sessions.items() if now - s["last_seen"] > STALE_TIMEOUT]
            for mac in stale:
                s = self.active_sessions.pop(mac)
                duration = s["last_seen"] - s["first_seen"]
                self.event_queue.put(("session_closed", {
                    "mac": mac, "ip": s["ip"], "duration": duration,
                    "first_seen": s["first_seen"], "last_seen": s["last_seen"]}))

    def run(self):
        last_check = time.time()
        try:
            while not self._stop_flag.is_set():
                try:
                    sniff(iface=self.iface, filter="arp", prn=self._handle_packet, store=False, timeout=1)
                except PermissionError:
                    self.event_queue.put(("error", "Permission denied — needs root."))
                    return
                except OSError as e:
                    self.event_queue.put(("error", f"Network error: {e}"))
                    return
                if time.time() - last_check >= 1:
                    self._check_stale()
                    last_check = time.time()
        finally:
            with self.lock:
                for mac, s in self.active_sessions.items():
                    duration = s["last_seen"] - s["first_seen"]
                    self.event_queue.put(("session_closed", {
                        "mac": mac, "ip": s["ip"], "duration": duration,
                        "first_seen": s["first_seen"], "last_seen": s["last_seen"]}))


class BriefWatcherTab:
    def __init__(self, parent, trusted_manager):
        self.frame = ttk.Frame(parent, padding=10)
        self.event_queue = queue.Queue()
        self.watcher_thread = None
        self.active_rows = {}
        self.history_records = []
        self.trusted_manager = trusted_manager
        self.trusted_manager.add_listener(self._refresh_history_display)
        self._build_ui()
        self._poll_queue()
        self._tick_active_table()

    def _list_interfaces(self):
        try:
            result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, timeout=5)
            names = []
            for line in result.stdout.splitlines():
                parts = line.split(":")
                if len(parts) > 1:
                    name = parts[1].strip().split("@")[0]
                    if name != "lo":
                        names.append(name)
            return names
        except Exception:
            return []

    def _build_ui(self):
        controls = ttk.Frame(self.frame)
        controls.pack(fill="x")

        ttk.Label(controls, text="Interface:").grid(row=0, column=0, sticky="w")
        self.iface_combo = ttk.Combobox(controls, width=15, state="readonly")
        self.iface_combo["values"] = self._list_interfaces()
        if self.iface_combo["values"]:
            self.iface_combo.current(0)
        self.iface_combo.grid(row=0, column=1, padx=(5, 15))

        can_run = sniff is not None and IS_ROOT
        self.start_button = ttk.Button(controls, text="Start Listening", command=self.start,
                                        state="normal" if can_run else "disabled")
        self.start_button.grid(row=0, column=2, padx=5)
        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop, state="disabled")
        self.stop_button.grid(row=0, column=3, padx=5)

        self.status_label = ttk.Label(controls, text="Idle.")
        self.status_label.grid(row=0, column=4, padx=20)

        self.clear_button = ttk.Button(controls, text="Clear History", command=self.clear_history)
        self.clear_button.grid(row=0, column=5, padx=5)
        self.export_button = ttk.Button(controls, text="Export CSV", command=self.export_csv)
        self.export_button.grid(row=0, column=6, padx=5)

        search_row = ttk.Frame(self.frame)
        search_row.pack(fill="x", pady=(8, 0))
        ttk.Label(search_row, text="Search (filters both tables by IP/MAC):").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self._refresh_history_display())
        search_entry = ttk.Entry(search_row, textvariable=self.search_var, width=30)
        search_entry.pack(side="left", padx=(5, 0))

        if not can_run:
            reason = "scapy is not installed." if sniff is None else "This tab requires root privileges."
            hint = ttk.Label(
                self.frame,
                text=f"⚠ {reason} Restart the whole app with:\n"
                     f"sudo -E env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY python3 netsuite.py",
                foreground=WARN
            )
            hint.pack(anchor="w", pady=(5, 5))

        paned = ttk.PanedWindow(self.frame, orient="vertical")
        paned.pack(fill="both", expand=True, pady=(10, 0))

        active_frame = ttk.Frame(paned)
        ttk.Label(active_frame, text="Currently Active Devices:").pack(anchor="w")
        self.active_tree = ttk.Treeview(active_frame, columns=("ip", "mac", "seen_for"), show="headings", height=6)
        for col, label, width in [("ip", "IP Address", 150), ("mac", "MAC Address", 180), ("seen_for", "Seen For", 100)]:
            self.active_tree.heading(col, text=label)
            self.active_tree.column(col, width=width, anchor="w")
        self.active_tree.bind("<Button-3>", lambda e: self._on_right_click(e, self.active_tree))
        self.active_tree.pack(fill="both", expand=True)
        paned.add(active_frame, weight=1)

        history_frame = ttk.Frame(paned)
        ttk.Label(history_frame, text="Connection History (most recent first):").pack(anchor="w")
        self.history_tree = ttk.Treeview(history_frame, columns=("time", "ip", "mac", "duration", "flag", "trusted"),
                                          show="headings", height=10)
        for col, label, width in [("time", "Ended At", 110), ("ip", "IP", 130), ("mac", "MAC", 160),
                                   ("duration", "Duration", 80), ("flag", "Note", 190), ("trusted", "Trusted", 70)]:
            self.history_tree.heading(col, text=label)
            self.history_tree.column(col, width=width, anchor="w")
        self.history_tree.tag_configure("brief", background="#392832", foreground=WARN)
        self.history_tree.tag_configure("trusted", foreground=GOOD)
        self.history_tree.bind("<Button-3>", lambda e: self._on_right_click(e, self.history_tree))
        self.history_tree.pack(fill="both", expand=True)
        paned.add(history_frame, weight=2)

        ttk.Label(self.frame, text="Activity Log:").pack(anchor="w", pady=(10, 0))
        self.log_text = tk.Text(self.frame, height=5, state="disabled", wrap="word", bg="#111c2a", fg=TEXT_COLOR)
        self.log_text.pack(fill="both", expand=False)

    def clear_history(self):
        self.history_records = []
        self.history_tree.delete(*self.history_tree.get_children())
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

    def export_csv(self):
        if not self.history_tree.get_children():
            self._log("Nothing to export — no history yet.")
            return
        if export_treeview_to_csv(self.frame, self.history_tree, "netsuite_brief_connections.csv"):
            self._log("Exported history to CSV.")

    def _on_right_click(self, event, tree):
        row_id = tree.identify_row(event.y)
        if not row_id:
            return
        values = tree.item(row_id, "values")
        ip, mac = values[0], values[1]
        is_trusted = self.trusted_manager.is_trusted(mac)
        trust_label = "Remove Trusted Tag" if is_trusted else "Mark as Trusted"

        show_treeview_context_menu(event, tree, [
            ("Copy IP", lambda: copy_to_clipboard(tree, ip)),
            ("Copy MAC", lambda: copy_to_clipboard(tree, mac)),
            None,
            (trust_label, lambda: self._toggle_trusted(mac)),
        ])

    def _toggle_trusted(self, mac):
        self.trusted_manager.toggle(mac)
        self._refresh_history_display()

    def start(self):
        iface = self.iface_combo.get()
        if not iface:
            self.status_label.config(text="Select a network interface first.", foreground=WARN)
            return
        self.watcher_thread = BriefWatcherThread(iface, self.event_queue)
        self.watcher_thread.start()
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.iface_combo.config(state="disabled")
        self.status_label.config(text=f"Listening on {iface}...")
        self._log(f"Started listening on {iface}.")

    def stop(self):
        if self.watcher_thread:
            self.watcher_thread.stop()
            self.watcher_thread = None
        self.start_button.config(state="normal" if (sniff is not None and IS_ROOT) else "disabled")
        self.stop_button.config(state="disabled")
        self.iface_combo.config(state="readonly")
        self.status_label.config(text="Stopped.")
        self._log("Stopped listening.")

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "device_appeared":
                    self._log(f"Device appeared: {payload['ip']} ({payload['mac']})")
                elif kind == "session_closed":
                    self._add_history_row(payload)
                    if payload["mac"] in self.active_rows:
                        self.active_tree.delete(self.active_rows.pop(payload["mac"]))
                elif kind == "error":
                    self.status_label.config(text=f"Error: {payload}")
                    self._log(f"ERROR: {payload}")
        except queue.Empty:
            pass
        self.frame.after(300, self._poll_queue)

    def _tick_active_table(self):
        if self.watcher_thread:
            with self.watcher_thread.lock:
                sessions = dict(self.watcher_thread.active_sessions)
            query = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""
            if query:
                sessions = {mac: s for mac, s in sessions.items() if query in mac.lower() or query in s["ip"].lower()}
            seen_macs = set(sessions.keys())
            for mac in list(self.active_rows.keys()):
                if mac not in seen_macs:
                    self.active_tree.delete(self.active_rows.pop(mac))
            now = time.time()
            for mac, session in sessions.items():
                seen_for = f"{now - session['first_seen']:.0f}s"
                if mac in self.active_rows:
                    self.active_tree.item(self.active_rows[mac], values=(session["ip"], mac, seen_for))
                else:
                    item_id = self.active_tree.insert("", "end", values=(session["ip"], mac, seen_for))
                    self.active_rows[mac] = item_id
        self.frame.after(1000, self._tick_active_table)

    def _add_history_row(self, payload):
        ended_at = datetime.fromtimestamp(payload["last_seen"]).strftime("%H:%M:%S")
        duration = payload["duration"]
        is_brief = duration < BRIEF_THRESHOLD
        is_trusted = self.trusted_manager.is_trusted(payload["mac"])
        note = f"⚠ Brief connection ({duration:.1f}s)" if is_brief else "Normal session"
        self.history_records.insert(0, {
            "ended_at": ended_at, "ip": payload["ip"], "mac": payload["mac"],
            "duration": f"{duration:.1f}s", "note": note, "is_brief": is_brief, "is_trusted": is_trusted,
        })
        self._refresh_history_display()

        if is_trusted:
            self._log(f"Session ended (TRUSTED, no alert): {payload['ip']} ({payload['mac']}) — {duration:.1f}s")
            return

        self._log(f"Session ended: {payload['ip']} ({payload['mac']}) — {duration:.1f}s — {note}")
        log_to_file(f"[BriefWatcher] {payload['ip']} ({payload['mac']}) — {duration:.1f}s — {note}")
        if is_brief:
            notify_desktop("Brief connection detected!",
                            f"{payload['ip']} ({payload['mac']}) was on the network for only {duration:.1f}s")

    def _refresh_history_display(self):
        self.history_tree.delete(*self.history_tree.get_children())
        query = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""
        for record in self.history_records:
            haystack = f"{record['ip']} {record['mac']}".lower()
            if query and query not in haystack:
                continue
            is_trusted = self.trusted_manager.is_trusted(record["mac"])
            tag = "trusted" if is_trusted else ("brief" if record["is_brief"] else "")
            self.history_tree.insert("", "end", values=(
                record["ended_at"], record["ip"], record["mac"], record["duration"], record["note"],
                "✓ Trusted" if is_trusted else "-"),
                tags=(tag,) if tag else ())

    def _log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")



# ===========================================================================
# Main App — Notebook combining all tabs
# ===========================================================================

class TrustedDevicesWindow:
    def __init__(self, parent, trusted_manager):
        self.trusted_manager = trusted_manager

        self.win = tk.Toplevel(parent)
        self.win.title("Trusted Devices")
        self.win.geometry("560x400")
        self.win.configure(bg=BG_COLOR)

        ttk.Label(self.win, text="These MAC addresses are muted — they won't trigger new-device or "
                                   "brief-connection alerts anywhere in NetSuite.",
                  wraplength=520, padding=10).pack(fill="x")

        columns = ("mac", "label", "added")
        self.tree = ttk.Treeview(self.win, columns=columns, show="headings", height=12)
        for col, label, width in [("mac", "MAC Address", 180), ("label", "Label", 180), ("added", "Added", 160)]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        button_row = ttk.Frame(self.win, padding=10)
        button_row.pack(fill="x")
        ttk.Button(button_row, text="Remove Selected", command=self.remove_selected).pack(side="left")
        ttk.Button(button_row, text="Close", command=self.win.destroy).pack(side="right")

        self._refresh()

    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        for mac, info in sorted(self.trusted_manager.trusted.items()):
            self.tree.insert("", "end", values=(mac, info.get("label", ""), info.get("added", "")))

    def remove_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        mac = self.tree.item(selection[0], "values")[0]
        self.trusted_manager.remove(mac)
        self._refresh()


class StreamThread(threading.Thread):
    """Runs a subprocess and streams its stdout line-by-line into a queue."""

    def __init__(self, cmd, event_queue, tag):
        super().__init__(daemon=True)
        self.cmd = cmd
        self.event_queue = event_queue
        self.tag = tag
        self.process = None
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass

    def run(self):
        try:
            self.process = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except FileNotFoundError:
            self.event_queue.put((self.tag, f"ERROR: {self.cmd[0]} not found — is it installed?\n"))
            return
        for line in self.process.stdout:
            if self._stop_flag.is_set():
                break
            self.event_queue.put((self.tag, line))
        self.process.wait()
        self.event_queue.put((f"{self.tag}_done", None))


# ===========================================================================
# TAB — Ping / Traceroute
# ===========================================================================

class PingTracerouteTab:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self.event_queue = queue.Queue()
        self.active_thread = None
        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        controls = ttk.Frame(self.frame)
        controls.pack(fill="x")
        ttk.Label(controls, text="Target host/IP:").pack(side="left")
        self.target_entry = ttk.Entry(controls, width=30)
        self.target_entry.insert(0, "8.8.8.8")
        self.target_entry.pack(side="left", padx=(5, 15))

        self.ping_button = ttk.Button(controls, text="Ping", command=self.start_ping)
        self.ping_button.pack(side="left", padx=5)
        self.trace_button = ttk.Button(controls, text="Traceroute", command=self.start_traceroute)
        self.trace_button.pack(side="left", padx=5)
        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop, state="disabled")
        self.stop_button.pack(side="left", padx=5)

        self.output_text = tk.Text(self.frame, wrap="word", bg="#111c2a", fg=TEXT_COLOR, font=(MONO_FONT, 10))
        self.output_text.pack(fill="both", expand=True, pady=(10, 0))

    def start_ping(self):
        target = self.target_entry.get().strip()
        if not target:
            return
        self._start(["ping", "-c", "10", target], "ping")

    def start_traceroute(self):
        target = self.target_entry.get().strip()
        if not target:
            return
        cmd = ["traceroute", target] if self._which("traceroute") else ["tracepath", target]
        self._start(cmd, "trace")

    def _which(self, prog):
        code, _, _ = 0, "", ""
        try:
            subprocess.run(["which", prog], capture_output=True, timeout=3)
            return subprocess.run(["which", prog], capture_output=True, timeout=3).returncode == 0
        except Exception:
            return False

    def _start(self, cmd, tag):
        if self.active_thread:
            self.active_thread.stop()
        self.output_text.delete("1.0", "end")
        self.output_text.insert("end", f"$ {' '.join(cmd)}\n\n")
        self.active_thread = StreamThread(cmd, self.event_queue, tag)
        self.active_thread.start()
        self.ping_button.config(state="disabled")
        self.trace_button.config(state="disabled")
        self.stop_button.config(state="normal")

    def stop(self):
        if self.active_thread:
            self.active_thread.stop()
            self.active_thread = None
        self._reset_buttons()

    def _reset_buttons(self):
        self.ping_button.config(state="normal")
        self.trace_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def _poll_queue(self):
        try:
            while True:
                tag, payload = self.event_queue.get_nowait()
                if tag in ("ping", "trace"):
                    self.output_text.insert("end", payload)
                    self.output_text.see("end")
                elif tag.endswith("_done"):
                    self._reset_buttons()
        except queue.Empty:
            pass
        self.frame.after(200, self._poll_queue)


# ===========================================================================
# TAB — DNS Lookup / Whois
# ===========================================================================

class DnsWhoisTab:
    DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self._build_ui()

    def _build_ui(self):
        controls = ttk.Frame(self.frame)
        controls.pack(fill="x")
        ttk.Label(controls, text="Domain or IP:").pack(side="left")
        self.target_entry = ttk.Entry(controls, width=30)
        self.target_entry.insert(0, "example.com")
        self.target_entry.pack(side="left", padx=(5, 15))
        ttk.Button(controls, text="DNS Lookup", command=self.do_dns_lookup).pack(side="left", padx=5)
        ttk.Button(controls, text="Whois", command=self.do_whois).pack(side="left", padx=5)

        notebook = ttk.Notebook(self.frame)
        notebook.pack(fill="both", expand=True, pady=(10, 0))

        dns_tab = ttk.Frame(notebook, padding=8)
        notebook.add(dns_tab, text="DNS Records")
        columns = ("type", "value")
        self.dns_tree = ttk.Treeview(dns_tab, columns=columns, show="headings", height=16)
        self.dns_tree.heading("type", text="Type")
        self.dns_tree.column("type", width=80, anchor="w")
        self.dns_tree.heading("value", text="Value")
        self.dns_tree.column("value", width=500, anchor="w")
        self.dns_tree.pack(fill="both", expand=True)

        whois_tab = ttk.Frame(notebook, padding=8)
        notebook.add(whois_tab, text="Whois")
        self.whois_text = tk.Text(whois_tab, wrap="word", bg="#111c2a", fg=TEXT_COLOR, font=(MONO_FONT, 9))
        self.whois_text.pack(fill="both", expand=True)

    def do_dns_lookup(self):
        target = self.target_entry.get().strip()
        if not target:
            return
        self.dns_tree.delete(*self.dns_tree.get_children())

        def worker():
            for rtype in self.DNS_RECORD_TYPES:
                try:
                    result = subprocess.run(["dig", "+short", target, rtype], capture_output=True, text=True, timeout=8)
                    for line in result.stdout.strip().splitlines():
                        if line:
                            self.frame.after(0, lambda t=rtype, v=line: self.dns_tree.insert("", "end", values=(t, v)))
                except Exception as e:
                    self.frame.after(0, lambda t=rtype, e=e: self.dns_tree.insert("", "end", values=(t, f"error: {e}")))

        threading.Thread(target=worker, daemon=True).start()

    def do_whois(self):
        target = self.target_entry.get().strip()
        if not target:
            return
        self.whois_text.delete("1.0", "end")
        self.whois_text.insert("end", "Looking up...\n")

        def worker():
            try:
                result = subprocess.run(["whois", target], capture_output=True, text=True, timeout=15)
                output = result.stdout or result.stderr or "(no output)"
            except FileNotFoundError:
                output = "whois not installed. Run: sudo apt install whois"
            except Exception as e:
                output = f"Error: {e}"
            self.frame.after(0, lambda: self._set_whois_text(output))

        threading.Thread(target=worker, daemon=True).start()

    def _set_whois_text(self, text):
        self.whois_text.delete("1.0", "end")
        self.whois_text.insert("1.0", text)


# ===========================================================================
# TAB — Wake-on-LAN
# ===========================================================================

class WakeOnLanTab:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self._build_ui()

    def _load_known_devices(self):
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _build_ui(self):
        info = ttk.Label(self.frame, wraplength=700, justify="left",
                          text="Sends a WoL 'magic packet' to wake a sleeping device. The target device's "
                               "network card must have Wake-on-LAN enabled in its BIOS/OS settings.")
        info.pack(fill="x", pady=(0, 10))

        picker_row = ttk.Frame(self.frame)
        picker_row.pack(fill="x", pady=(0, 10))
        ttk.Label(picker_row, text="Known device:").pack(side="left")
        devices = self._load_known_devices()
        choices = [f"{info.get('mac')} — {ip} ({info.get('hostname') or info.get('vendor') or 'unknown'})"
                   for ip, info in devices.items() if info.get("mac")]
        self.device_combo = ttk.Combobox(picker_row, width=50, values=choices, state="readonly")
        self.device_combo.pack(side="left", padx=(5, 10))
        self.device_combo.bind("<<ComboboxSelected>>", self._on_device_pick)
        ttk.Button(picker_row, text="Refresh List", command=self._refresh_choices).pack(side="left")

        entry_row = ttk.Frame(self.frame)
        entry_row.pack(fill="x", pady=(0, 10))
        ttk.Label(entry_row, text="MAC Address:").pack(side="left")
        self.mac_entry = ttk.Entry(entry_row, width=20)
        self.mac_entry.pack(side="left", padx=(5, 15))
        ttk.Label(entry_row, text="Broadcast IP:").pack(side="left")
        self.broadcast_entry = ttk.Entry(entry_row, width=18)
        self.broadcast_entry.insert(0, "255.255.255.255")
        self.broadcast_entry.pack(side="left", padx=(5, 15))
        ttk.Button(entry_row, text="Wake Device", command=self.wake_device).pack(side="left")

        ttk.Label(self.frame, text="Log:").pack(anchor="w", pady=(10, 0))
        self.log_text = tk.Text(self.frame, height=10, state="disabled", wrap="word", bg="#111c2a", fg=TEXT_COLOR)
        self.log_text.pack(fill="both", expand=True)

    def _refresh_choices(self):
        devices = self._load_known_devices()
        choices = [f"{info.get('mac')} — {ip} ({info.get('hostname') or info.get('vendor') or 'unknown'})"
                   for ip, info in devices.items() if info.get("mac")]
        self.device_combo["values"] = choices

    def _on_device_pick(self, event):
        selected = self.device_combo.get()
        mac = selected.split(" — ")[0]
        self.mac_entry.delete(0, "end")
        self.mac_entry.insert(0, mac)

    def wake_device(self):
        mac = self.mac_entry.get().strip()
        broadcast = self.broadcast_entry.get().strip() or "255.255.255.255"
        if not mac:
            self._log("Enter or select a MAC address first.")
            return

        try:
            mac_bytes = bytes.fromhex(mac.replace(":", "").replace("-", ""))
            if len(mac_bytes) != 6:
                raise ValueError
        except ValueError:
            self._log("Invalid MAC — needs 6 bytes, e.g. AA:BB:CC:DD:EE:FF")
            return

        magic_packet = b"\xff" * 6 + mac_bytes * 16

        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(magic_packet, (broadcast, 9))
            sock.close()
            self._log(f"Sent magic packet to {mac} via {broadcast}.")
        except Exception as e:
            self._log(f"Failed to send magic packet: {e}")

    def _log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")


# ===========================================================================
# TAB — Bandwidth Monitor (this machine's traffic only — see note in UI)
# ===========================================================================

class BandwidthThread(threading.Thread):
    def __init__(self, iface, event_queue):
        super().__init__(daemon=True)
        self.iface = iface
        self.event_queue = event_queue
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()

    def run(self):
        while not self._stop_flag.is_set():
            cmd = ["iftop", "-t", "-s", "5", "-L", "15", "-N", "-n", "-i", self.iface]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                hosts = self._parse(result.stdout)
                self.event_queue.put(("bandwidth_data", hosts))
            except FileNotFoundError:
                self.event_queue.put(("bandwidth_error", "iftop not installed (sudo apt install iftop)."))
                return
            except subprocess.TimeoutExpired:
                pass

    def _parse(self, output):
        hosts = []
        pattern = re.compile(r"^\s*\d+\s+(\S+)\s*=>\s*(\S+)\s+([\d.]+\S*)\s+([\d.]+\S*)\s+([\d.]+\S*)")
        for line in output.splitlines():
            m = pattern.match(line)
            if m:
                hosts.append({"local": m.group(1), "remote": m.group(2),
                               "rate2s": m.group(3), "rate10s": m.group(4), "rate40s": m.group(5)})
        return hosts


class BandwidthMonitorTab:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self.event_queue = queue.Queue()
        self.thread = None
        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        note = ttk.Label(self.frame, wraplength=750, justify="left", foreground=MEDIUM,
                          text="⚠ This shows traffic to/from THIS machine only. Seeing other devices' bandwidth "
                               "requires being the network's router/gateway — not possible from a regular host "
                               "on a switched network.")
        note.pack(fill="x", pady=(0, 10))

        controls = ttk.Frame(self.frame)
        controls.pack(fill="x")
        ttk.Label(controls, text="Interface:").pack(side="left")
        self.iface_entry = ttk.Entry(controls, width=12)
        self.iface_entry.insert(0, "wlan0")
        self.iface_entry.pack(side="left", padx=(5, 15))
        self.start_button = ttk.Button(controls, text="Monitor", command=self.start)
        self.start_button.pack(side="left", padx=5)
        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop, state="disabled")
        self.stop_button.pack(side="left", padx=5)

        self.status_label = ttk.Label(self.frame, text="Idle.")
        self.status_label.pack(fill="x", pady=(5, 5))

        columns = ("local", "remote", "rate2s", "rate10s", "rate40s")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings", height=14)
        for col, label, width in [("local", "Local", 180), ("remote", "Remote Host", 220),
                                   ("rate2s", "2s Avg", 100), ("rate10s", "10s Avg", 100), ("rate40s", "40s Avg", 100)]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=(10, 0))

    def start(self):
        iface = self.iface_entry.get().strip()
        if not iface:
            return
        self.thread = BandwidthThread(iface, self.event_queue)
        self.thread.start()
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.status_label.config(text=f"Monitoring {iface}...")

    def stop(self):
        if self.thread:
            self.thread.stop()
            self.thread = None
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_label.config(text="Stopped.")

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "bandwidth_data":
                    self.tree.delete(*self.tree.get_children())
                    for h in payload:
                        self.tree.insert("", "end", values=(h["local"], h["remote"], h["rate2s"], h["rate10s"], h["rate40s"]))
                elif kind == "bandwidth_error":
                    self.status_label.config(text=f"Error: {payload}")
                    self.stop()
        except queue.Empty:
            pass
        self.frame.after(500, self._poll_queue)


# ===========================================================================
# TAB — Firewall Rules Manager (iptables)
# ===========================================================================

class FirewallRulesTab:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self._build_ui()
        self.refresh_rules()

    def _build_ui(self):
        if not IS_ROOT:
            ttk.Label(self.frame, foreground=MEDIUM,
                      text="Root required to view or modify firewall rules — restart NetSuite with sudo.").pack(
                anchor="w", pady=(0, 10))

        controls = ttk.Frame(self.frame)
        controls.pack(fill="x")
        ttk.Button(controls, text="Refresh Rules", command=self.refresh_rules).pack(side="left", padx=(0, 10))
        ttk.Button(controls, text="Add Rule...", command=self.open_add_rule_dialog).pack(side="left", padx=(0, 10))
        ttk.Button(controls, text="Delete Selected Rule", command=self.delete_selected).pack(side="left")

        self.status_label = ttk.Label(self.frame, text="")
        self.status_label.pack(fill="x", pady=(8, 0))

        columns = ("line", "target", "protocol", "source", "destination", "extra")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings", height=16)
        for col, label, width in [("line", "#", 40), ("target", "Target", 90), ("protocol", "Proto", 70),
                                   ("source", "Source", 150), ("destination", "Destination", 150), ("extra", "Extra", 200)]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")
        self.tree.tag_configure("drop", foreground=WARN)
        self.tree.tag_configure("accept", foreground=GOOD)
        self.tree.pack(fill="both", expand=True, pady=(10, 0))

    def refresh_rules(self):
        self.tree.delete(*self.tree.get_children())
        try:
            result = subprocess.run(["iptables", "-L", "INPUT", "-n", "-v", "--line-numbers"],
                                     capture_output=True, text=True, timeout=10)
        except FileNotFoundError:
            self.status_label.config(text="iptables not found — is it installed?", foreground=WARN)
            return
        except Exception as e:
            self.status_label.config(text=f"Error: {e}", foreground=WARN)
            return

        lines = result.stdout.splitlines()
        for line in lines[2:]:  # skip the two header lines
            parts = line.split(None, 8)
            if len(parts) < 8:
                continue
            line_num, pkts, bytes_, target, prot, opt, in_if, out_if = parts[:8]
            rest = parts[8] if len(parts) > 8 else ""
            src_dst = rest.split()
            source = src_dst[0] if len(src_dst) > 0 else "anywhere"
            dest = src_dst[1] if len(src_dst) > 1 else "anywhere"
            extra = " ".join(src_dst[2:]) if len(src_dst) > 2 else ""
            tag = "drop" if target in ("DROP", "REJECT") else ("accept" if target == "ACCEPT" else "")
            self.tree.insert("", "end", values=(line_num, target, prot, source, dest, extra),
                              tags=(tag,) if tag else ())
        self.status_label.config(text=f"{len(self.tree.get_children())} rule(s) loaded.", foreground=FG_COLOR)

    def delete_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        line_num = self.tree.item(selection[0], "values")[0]
        result = subprocess.run(["iptables", "-D", "INPUT", str(line_num)], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            self.status_label.config(text=result.stderr.strip() or "Failed to delete rule.", foreground=WARN)
        else:
            self.status_label.config(text=f"Deleted rule #{line_num}.", foreground=GOOD)
        self.refresh_rules()

    def open_add_rule_dialog(self):
        dialog = tk.Toplevel(self.frame)
        dialog.title("Add Firewall Rule")
        dialog.geometry("380x280")
        dialog.configure(bg=BG_COLOR)

        ttk.Label(dialog, text="Action:").pack(anchor="w", padx=10, pady=(10, 0))
        action_var = tk.StringVar(value="DROP")
        ttk.Combobox(dialog, textvariable=action_var, values=["ACCEPT", "DROP", "REJECT"], state="readonly").pack(
            fill="x", padx=10)

        ttk.Label(dialog, text="Protocol:").pack(anchor="w", padx=10, pady=(10, 0))
        proto_var = tk.StringVar(value="tcp")
        ttk.Combobox(dialog, textvariable=proto_var, values=["tcp", "udp", "any"], state="readonly").pack(
            fill="x", padx=10)

        ttk.Label(dialog, text="Source IP (blank = any):").pack(anchor="w", padx=10, pady=(10, 0))
        source_entry = ttk.Entry(dialog)
        source_entry.pack(fill="x", padx=10)

        ttk.Label(dialog, text="Destination port (blank = any):").pack(anchor="w", padx=10, pady=(10, 0))
        port_entry = ttk.Entry(dialog)
        port_entry.pack(fill="x", padx=10)

        dialog_status = ttk.Label(dialog, text="")
        dialog_status.pack(fill="x", padx=10, pady=(10, 0))

        def apply_rule():
            cmd = ["iptables", "-A", "INPUT"]
            if source_entry.get().strip():
                cmd += ["-s", source_entry.get().strip()]
            if proto_var.get() != "any":
                cmd += ["-p", proto_var.get()]
            if port_entry.get().strip():
                cmd += ["--dport", port_entry.get().strip()]
            cmd += ["-j", action_var.get()]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                dialog_status.config(text=result.stderr.strip() or "Failed to add rule.", foreground=WARN)
            else:
                dialog.destroy()
                self.refresh_rules()

        ttk.Button(dialog, text="Add Rule", command=apply_rule).pack(pady=15)


# ===========================================================================
# TAB — Service Brute-Forcer (Hydra)
# ===========================================================================

class HydraThread(threading.Thread):
    def __init__(self, cmd, event_queue):
        super().__init__(daemon=True)
        self.cmd = cmd
        self.event_queue = event_queue
        self.process = None
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass

    def run(self):
        try:
            self.process = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except FileNotFoundError:
            self.event_queue.put(("hydra_line", "ERROR: hydra not found (sudo apt install hydra)\n"))
            return
        for line in self.process.stdout:
            if self._stop_flag.is_set():
                break
            self.event_queue.put(("hydra_line", line))
            if "login:" in line and "password:" in line:
                self.event_queue.put(("hydra_success", line.strip()))
        self.process.wait()
        self.event_queue.put(("hydra_done", None))


class HydraTab:
    SERVICES = ["ssh", "ftp", "telnet", "mysql", "postgres", "smb", "rdp", "http-get"]

    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self.event_queue = queue.Queue()
        self.thread = None
        self.authorized = tk.BooleanVar(value=False)
        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        ttk.Label(self.frame, foreground=MUTED,
                  text="Tests login strength against a service. Only for accounts/systems you're authorized to test.").pack(
            anchor="w", pady=(0, 8))
        auth_cb = ttk.Checkbutton(self.frame, variable=self.authorized, text="I'm authorized to test this target")
        auth_cb.pack(anchor="w", pady=(0, 10))
        Tooltip(auth_cb, "Attempting logins on a system without permission may be illegal. "
                          "Only test accounts/servers you own or have written authorization for.")

        picker_row = ttk.Frame(self.frame)
        picker_row.pack(fill="x", pady=(0, 8))
        ttk.Label(picker_row, text="Known device:").pack(side="left")
        self.device_combo = ttk.Combobox(picker_row, width=40, values=load_known_device_choices(), state="readonly")
        self.device_combo.pack(side="left", padx=(5, 10))
        self.device_combo.bind("<<ComboboxSelected>>", self._on_device_pick)
        ttk.Button(picker_row, text="Refresh List", command=self._refresh_devices).pack(side="left")

        row1 = ttk.Frame(self.frame)
        row1.pack(fill="x", pady=2)
        ttk.Label(row1, text="Target:").pack(side="left")
        self.target_entry = ttk.Entry(row1, width=25)
        self.target_entry.pack(side="left", padx=(5, 15))
        ttk.Label(row1, text="Service:").pack(side="left")
        self.service_combo = ttk.Combobox(row1, values=self.SERVICES, width=12, state="readonly")
        self.service_combo.current(0)
        self.service_combo.pack(side="left", padx=(5, 15))
        ttk.Label(row1, text="Port (blank = default):").pack(side="left")
        self.port_entry = ttk.Entry(row1, width=8)
        self.port_entry.pack(side="left", padx=(5, 0))

        row2 = ttk.Frame(self.frame)
        row2.pack(fill="x", pady=2)
        ttk.Label(row2, text="Username:").pack(side="left")
        self.user_entry = ttk.Entry(row2, width=20)
        self.user_entry.pack(side="left", padx=(5, 15))
        ttk.Label(row2, text="Password wordlist:").pack(side="left")
        self.wordlist_entry = ttk.Entry(row2, width=35)
        self.wordlist_entry.insert(0, "/usr/share/wordlists/rockyou.txt")
        self.wordlist_entry.pack(side="left", padx=(5, 5))
        ttk.Button(row2, text="Browse", command=self.browse_wordlist).pack(side="left")

        row3 = ttk.Frame(self.frame)
        row3.pack(fill="x", pady=(8, 0))
        self.start_button = ttk.Button(row3, text="Start Attack", command=self.start, state="disabled")
        self.start_button.pack(side="left", padx=(0, 10))
        self.stop_button = ttk.Button(row3, text="Stop", command=self.stop, state="disabled")
        self.stop_button.pack(side="left")

        self.authorized.trace_add("write", lambda *a: self.start_button.config(
            state="normal" if self.authorized.get() else "disabled"))

        self.result_label = ttk.Label(self.frame, text="", font=(MONO_FONT, 13, "bold"), padding=(0, 10))
        self.result_label.pack(fill="x")

        self.output_text = tk.Text(self.frame, wrap="word", bg="#111c2a", fg=TEXT_COLOR, font=(MONO_FONT, 10))
        self.output_text.pack(fill="both", expand=True)

    def _on_device_pick(self, event):
        ip = self.device_combo.get().split(" — ")[0]
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, ip)

    def _refresh_devices(self):
        self.device_combo["values"] = load_known_device_choices()

    def browse_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.wordlist_entry.delete(0, "end")
            self.wordlist_entry.insert(0, path)

    def start(self):
        target = self.target_entry.get().strip()
        user = self.user_entry.get().strip()
        wordlist = self.wordlist_entry.get().strip()
        service = self.service_combo.get()
        port = self.port_entry.get().strip()

        if not target or not user or not os.path.exists(wordlist):
            self.result_label.config(text="Fill in target, username, and a valid wordlist.", foreground=WARN)
            return

        cmd = ["hydra", "-l", user, "-P", wordlist]
        if port:
            cmd += ["-s", port]
        cmd += [target, service]

        self.output_text.delete("1.0", "end")
        self.result_label.config(text="")
        self.thread = HydraThread(cmd, self.event_queue)
        self.thread.start()
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

    def stop(self):
        if self.thread:
            self.thread.stop()
            self.thread = None
        self.start_button.config(state="normal" if self.authorized.get() else "disabled")
        self.stop_button.config(state="disabled")

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "hydra_line":
                    self.output_text.insert("end", payload)
                    self.output_text.see("end")
                elif kind == "hydra_success":
                    self.result_label.config(text=payload, foreground=GOOD)
                    try:
                        subprocess.run(["notify-send", "Hydra: credentials found!", payload], check=False, timeout=5)
                    except Exception:
                        pass
                elif kind == "hydra_done":
                    self.start_button.config(state="normal" if self.authorized.get() else "disabled")
                    self.stop_button.config(state="disabled")
        except queue.Empty:
            pass
        self.frame.after(200, self._poll_queue)


# ===========================================================================
# TAB — Exploit Search (searchsploit)
# ===========================================================================

class ExploitSearchTab:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self._build_ui()

    def _build_ui(self):
        controls = ttk.Frame(self.frame)
        controls.pack(fill="x")
        ttk.Label(controls, text="Search (service/software + version):").pack(side="left")
        self.query_entry = ttk.Entry(controls, width=40)
        self.query_entry.pack(side="left", padx=(5, 15))
        ttk.Button(controls, text="Search", command=self.search).pack(side="left")

        self.status_label = ttk.Label(self.frame, text="")
        self.status_label.pack(fill="x", pady=(8, 5))

        columns = ("title", "path", "type")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings", height=16)
        for col, label, width in [("title", "Title", 480), ("path", "Path", 300), ("type", "Type", 100)]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")
        self.tree.bind("<Double-1>", self.view_selected)
        self.tree.pack(fill="both", expand=True)

    def search(self):
        query = self.query_entry.get().strip()
        if not query:
            return
        self.tree.delete(*self.tree.get_children())
        self.status_label.config(text="Searching...")

        def worker():
            try:
                result = subprocess.run(["searchsploit", "-j", query], capture_output=True, text=True, timeout=20)
                data = json.loads(result.stdout)
                results = data.get("RESULTS_EXPLOIT", [])
                self.frame.after(0, lambda: self._show_results(results))
            except FileNotFoundError:
                self.frame.after(0, lambda: self.status_label.config(
                    text="searchsploit not found (sudo apt install exploitdb)", foreground=WARN))
            except Exception as e:
                self.frame.after(0, lambda error=str(e): self.status_label.config(text=f"Error: {error}", foreground=WARN))

        threading.Thread(target=worker, daemon=True).start()

    def _show_results(self, results):
        for r in results:
            self.tree.insert("", "end", values=(r.get("Title", ""), r.get("Path", ""), r.get("Type", "")))
        self.status_label.config(text=f"{len(results)} result(s).", foreground=FG_COLOR)

    def view_selected(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        path = self.tree.item(selection[0], "values")[1]
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            content = f"Could not read file: {e}"

        popup = tk.Toplevel(self.frame)
        popup.title(os.path.basename(path))
        popup.geometry("700x500")
        popup.configure(bg=BG_COLOR)
        text = tk.Text(popup, wrap="word", bg="#111c2a", fg=TEXT_COLOR, font=(MONO_FONT, 9))
        text.pack(fill="both", expand=True, padx=10, pady=10)
        text.insert("1.0", content)
        text.config(state="disabled")


# ===========================================================================
# TAB — ARP Spoof / MITM  (same authorization-gate treatment as deauth)
# ===========================================================================

class ArpSpoofTab:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self.spoof_processes = []
        self.forwarding_enabled = False
        self.capture_process = None
        self.authorized = tk.BooleanVar(value=False)
        self._build_ui()

    def _build_ui(self):
        ttk.Label(self.frame, foreground=MEDIUM, wraplength=850, justify="left",
                  text="This intercepts a real device's traffic by poisoning ARP tables — it affects that "
                       "device's connectivity while active. Only use on devices you own or have explicit "
                       "authorization to test.").pack(anchor="w", pady=(0, 8))

        auth_check = ttk.Checkbutton(self.frame, variable=self.authorized,
                                      text="I own this device/network or have explicit authorization to test it")
        auth_check.pack(anchor="w", pady=(0, 10))
        Tooltip(auth_check, "This actively redirects another device's traffic through your machine — "
                             "it's not passive listening. Requires real authorization.")

        picker_row = ttk.Frame(self.frame)
        picker_row.pack(fill="x", pady=(0, 8))
        ttk.Label(picker_row, text="Known device:").pack(side="left")
        self.device_combo = ttk.Combobox(picker_row, width=40, values=load_known_device_choices(), state="readonly")
        self.device_combo.pack(side="left", padx=(5, 10))
        self.device_combo.bind("<<ComboboxSelected>>", self._on_device_pick)
        ttk.Button(picker_row, text="Refresh List", command=self._refresh_devices).pack(side="left")

        row1 = ttk.Frame(self.frame)
        row1.pack(fill="x", pady=2)
        ttk.Label(row1, text="Interface:").pack(side="left")
        self.iface_combo = ttk.Combobox(row1, values=list_wifi_interfaces(), width=12, state="readonly")
        if self.iface_combo["values"]:
            self.iface_combo.current(0)
        self.iface_combo.pack(side="left", padx=(5, 15))
        ttk.Label(row1, text="Target IP:").pack(side="left")
        self.target_entry = ttk.Entry(row1, width=16)
        self.target_entry.pack(side="left", padx=(5, 15))
        ttk.Label(row1, text="Gateway IP:").pack(side="left")
        self.gateway_entry = ttk.Entry(row1, width=16)
        self.gateway_entry.pack(side="left", padx=(5, 5))
        gw_button = ttk.Button(row1, text="Auto-detect", command=self.autofill_gateway)
        gw_button.pack(side="left")
        Tooltip(gw_button, "Fills in your router's IP address automatically.")

        self.capture_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.frame, variable=self.capture_var,
                         text="Also capture intercepted traffic to a .pcap file (for Wireshark)").pack(anchor="w", pady=(8, 0))

        row2 = ttk.Frame(self.frame)
        row2.pack(fill="x", pady=(10, 0))
        self.start_button = ttk.Button(row2, text="Start MITM", command=self.start_mitm, state="disabled")
        self.start_button.pack(side="left", padx=(0, 10))
        self.stop_button = ttk.Button(row2, text="Stop / Restore Network", command=self.stop_mitm, state="disabled")
        self.stop_button.pack(side="left")

        self.authorized.trace_add("write", lambda *a: self.start_button.config(
            state="normal" if self.authorized.get() else "disabled"))

        self.status_label = ttk.Label(self.frame, text="Idle.", padding=(0, 10))
        self.status_label.pack(fill="x")

        ttk.Label(self.frame, text="Activity Log:").pack(anchor="w")
        self.log_text = tk.Text(self.frame, height=14, state="disabled", wrap="word", bg="#111c2a", fg=TEXT_COLOR)
        self.log_text.pack(fill="both", expand=True)

    def _on_device_pick(self, event):
        ip = self.device_combo.get().split(" — ")[0]
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, ip)

    def _refresh_devices(self):
        self.device_combo["values"] = load_known_device_choices()

    def autofill_gateway(self):
        gateway = detect_default_gateway()
        if gateway:
            self.gateway_entry.delete(0, "end")
            self.gateway_entry.insert(0, gateway)
            self._log(f"Detected gateway: {gateway}")
        else:
            self._log("Couldn't auto-detect gateway — enter it manually.")

    def start_mitm(self):
        target = self.target_entry.get().strip()
        gateway = self.gateway_entry.get().strip()
        iface = self.iface_combo.get()
        if not target or not gateway or not iface:
            self.status_label.config(text="Fill in interface, target IP, and gateway IP.", foreground=WARN)
            return

        confirm = messagebox.askyesno(
            "Confirm MITM",
            f"Start intercepting traffic between {target} and gateway {gateway}?\n\n"
            "This will disrupt that device's connection momentarily while ARP tables update, then route "
            "its traffic through this machine. Only proceed with authorization."
        )
        if not confirm:
            return

        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
            self.forwarding_enabled = True
            self._log("Enabled IP forwarding.")
        except Exception as e:
            self._log(f"Could not enable IP forwarding: {e}")

        try:
            p1 = subprocess.Popen(["arpspoof", "-i", iface, "-t", target, gateway],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            p2 = subprocess.Popen(["arpspoof", "-i", iface, "-t", gateway, target],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.spoof_processes = [p1, p2]
            self._log(f"ARP spoofing started between {target} and {gateway} on {iface}.")
        except FileNotFoundError:
            self._log("arpspoof not found (sudo apt install dsniff).")
            return

        if self.capture_var.get():
            cap_path = os.path.join(tempfile.gettempdir(), f"netsuite_mitm_{target.replace('.', '_')}.pcap")
            try:
                self.capture_process = subprocess.Popen(
                    ["tcpdump", "-i", iface, "-w", cap_path, "host", target],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self._log(f"Capturing traffic to {cap_path}")
            except FileNotFoundError:
                self._log("tcpdump not found — skipping capture.")

        self.status_label.config(text=f"MITM active: {target} <-> {gateway}", foreground=WARN)
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

    def stop_mitm(self):
        for p in self.spoof_processes:
            try:
                p.terminate()
            except Exception:
                pass
        self.spoof_processes = []

        if self.capture_process:
            try:
                self.capture_process.terminate()
            except Exception:
                pass
            self.capture_process = None

        if self.forwarding_enabled:
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("0\n")
            except Exception:
                pass
            self.forwarding_enabled = False

        self._log("Stopped ARP spoofing and disabled IP forwarding. ARP caches will self-correct shortly.")
        self.status_label.config(text="Idle.", foreground=TEXT_COLOR)
        self.start_button.config(state="normal" if self.authorized.get() else "disabled")
        self.stop_button.config(state="disabled")

    def _log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")


# ===========================================================================
# TAB — Web Vulnerability Scanner (Nikto)
# ===========================================================================

class NiktoTab:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self.event_queue = queue.Queue()
        self.thread = None
        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        ttk.Label(self.frame, foreground=MUTED,
                  text="Scans a website for common vulnerabilities/misconfigurations. Only for sites you own or manage.").pack(
            anchor="w", pady=(0, 8))

        controls = ttk.Frame(self.frame)
        controls.pack(fill="x")
        ttk.Label(controls, text="Target URL:").pack(side="left")
        self.url_entry = ttk.Entry(controls, width=40)
        self.url_entry.insert(0, "http://127.0.0.1")
        self.url_entry.pack(side="left", padx=(5, 15))
        self.start_button = ttk.Button(controls, text="Start Scan", command=self.start)
        self.start_button.pack(side="left", padx=5)
        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop, state="disabled")
        self.stop_button.pack(side="left")

        self.findings_tree = ttk.Treeview(self.frame, columns=("finding",), show="headings", height=8)
        self.findings_tree.heading("finding", text="Findings")
        self.findings_tree.column("finding", width=900, anchor="w")
        self.findings_tree.pack(fill="both", expand=False, pady=(10, 10))

        ttk.Label(self.frame, text="Raw Output:").pack(anchor="w")
        self.output_text = tk.Text(self.frame, wrap="word", bg="#111c2a", fg=TEXT_COLOR, font=(MONO_FONT, 9))
        self.output_text.pack(fill="both", expand=True)

    def start(self):
        url = self.url_entry.get().strip()
        if not url:
            return
        self.output_text.delete("1.0", "end")
        self.findings_tree.delete(*self.findings_tree.get_children())
        self.thread = StreamThread(["nikto", "-h", url], self.event_queue, "nikto")
        self.thread.start()
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

    def stop(self):
        if self.thread:
            self.thread.stop()
            self.thread = None
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def _poll_queue(self):
        try:
            while True:
                tag, payload = self.event_queue.get_nowait()
                if tag == "nikto":
                    self.output_text.insert("end", payload)
                    self.output_text.see("end")
                    if payload.strip().startswith("+"):
                        self.findings_tree.insert("", "end", values=(payload.strip(),))
                elif tag == "nikto_done":
                    self.start_button.config(state="normal")
                    self.stop_button.config(state="disabled")
        except queue.Empty:
            pass
        self.frame.after(200, self._poll_queue)


# ===========================================================================
# TAB — Home (guide + requirements checker)
# ===========================================================================

REQUIRED_TOOLS = [
    ("nmap", "Device discovery", "nmap", "nmap"),
    ("nmcli", "WiFi", "nmcli", "network-manager"),
    ("scapy", "ARP activity", None, "python3-scapy"),  # checked separately (already imported or not)
    ("dig", "DNS/Whois", "dig", "dnsutils"),
    ("whois", "DNS/Whois", "whois", "whois"),
    ("traceroute", "Ping/Traceroute", "traceroute", "traceroute"),
    ("iftop", "Bandwidth", "iftop", "iftop"),
    ("iptables", "Firewall", "iptables", "iptables"),
    ("airmon-ng", "Wireless testing", "airmon-ng", "aircrack-ng"),
    ("hydra", "Login testing", "hydra", "hydra"),
    ("searchsploit", "Vulnerability lookup", "searchsploit", "exploitdb"),
    ("arpspoof", "ARP/MITM", "arpspoof", "dsniff"),
    ("tcpdump", "ARP/MITM (capture)", "tcpdump", "tcpdump"),
    ("nikto", "Web Scanner", "nikto", "nikto"),
]

class HomeTab:
    def __init__(self, parent, app):
        self.app = app
        self.frame = ttk.Frame(parent, padding=24)
        self._build_ui()
        self.check_requirements()

    def _build_ui(self):
        metrics = ttk.Frame(self.frame)
        metrics.pack(fill="x", pady=(0, 24))
        self.metric_values = {}
        for index, (key, label, detail) in enumerate([
            ("devices", "KNOWN DEVICES", "Saved from your network"),
            ("trusted", "TRUSTED DEVICES", "Your recognized hardware"),
            ("tools", "LOCAL TOOLS", "Available on this machine"),
        ]):
            metrics.columnconfigure(index, weight=1, uniform="metric")
            card = ttk.Frame(metrics, style="Card.TFrame", padding=18)
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 8, 0))
            ttk.Label(card, text=label, style="Eyebrow.TLabel").pack(anchor="w")
            value = ttk.Label(card, text="—", style="Metric.TLabel")
            value.pack(anchor="w", pady=(8, 4))
            self.metric_values[key] = value
            ttk.Label(card, text=detail, style="CardMuted.TLabel").pack(anchor="w")

        columns = ttk.Frame(self.frame)
        columns.pack(fill="both", expand=True)
        columns.columnconfigure(0, weight=1)
        columns.columnconfigure(1, weight=1)
        columns.rowconfigure(0, weight=1)
        shortcuts = ttk.Frame(columns)
        shortcuts.grid(row=0, column=0, sticky="nsew", padx=(0, 24))
        ttk.Label(shortcuts, text="Your workspace", style="Section.TLabel").pack(anchor="w")
        ttk.Label(shortcuts, text="Pick up where you need to.", style="Muted.TLabel").pack(anchor="w", pady=(4, 16))
        for key, title, detail in [
            ("devices", "My devices", "Monitor the LAN and inspect saved hosts."),
            ("wifi", "Nearby WiFi", "Signal, channels and access points."),
            ("ping", "Connection check", "Reachability and the route to a host."),
            ("bandwidth", "Traffic", "Connections and bandwidth on this machine."),
        ]:
            card = ttk.Frame(shortcuts, padding=14, style="Card.TFrame")
            card.pack(fill="x", pady=(0, 8))
            ttk.Button(card, text=title, style="Quick.TButton",
                       command=lambda target=key: self.app.navigate(target)).pack(anchor="w")
            ttk.Label(card, text=detail, style="CardMuted.TLabel", wraplength=330).pack(anchor="w", pady=(5, 0))
        ttk.Button(shortcuts, text="Manage trusted devices", command=self.app.open_trusted_devices).pack(anchor="w", pady=(8, 0))

        local = ttk.Frame(columns)
        local.grid(row=0, column=1, sticky="nsew")
        ttk.Label(local, text="Machine readiness", style="Section.TLabel").pack(anchor="w")
        ttk.Label(local, text="Tools available to your workspace.", style="Muted.TLabel").pack(anchor="w", pady=(4, 16))
        tool_list = ttk.Frame(local)
        tool_list.pack(fill="both", expand=True)
        self.req_tree = ttk.Treeview(tool_list, columns=("tool", "used_by", "status"), show="headings", height=11)
        for column, title, width in [("tool", "Tool", 100), ("used_by", "Used for", 150), ("status", "Status", 90)]:
            self.req_tree.heading(column, text=title)
            self.req_tree.column(column, width=width, minwidth=60, stretch=True)
        self.req_tree.tag_configure("missing", foreground=MEDIUM)
        self.req_tree.tag_configure("ok", foreground=GOOD)
        self.req_tree.pack(side="left", fill="both", expand=True)
        tool_scroll = ttk.Scrollbar(tool_list, orient="vertical", command=self.req_tree.yview)
        tool_scroll.pack(side="right", fill="y")
        self.req_tree.configure(yscrollcommand=tool_scroll.set)
        controls = ttk.Frame(local)
        controls.pack(fill="x", pady=(12, 0))
        ttk.Button(controls, text="Refresh", command=self.check_requirements).pack(side="left", padx=(0, 8))
        self.install_button = ttk.Button(controls, text="Install missing tools", command=self.install_missing)
        self.install_button.pack(side="left")
        self.install_status = ttk.Label(local, style="Muted.TLabel", wraplength=360)
        self.install_status.pack(anchor="w", pady=(10, 0))

    def check_requirements(self):
        self.req_tree.delete(*self.req_tree.get_children())
        self.missing_packages = set()
        ready = 0
        for tool, used_by, binary, package in REQUIRED_TOOLS:
            installed = sniff is not None if binary is None else shutil.which(binary) is not None
            ready += int(installed)
            if not installed:
                self.missing_packages.add(package)
            self.req_tree.insert("", "end", values=(tool, used_by, "Ready" if installed else "Not installed"),
                                 tags=("ok" if installed else "missing",))
        self.metric_values["devices"].config(text=str(len(self.app.device_tab.known_devices)))
        self.metric_values["trusted"].config(text=str(len(self.app.trusted_manager.trusted)))
        self.metric_values["tools"].config(text=f"{ready} / {len(REQUIRED_TOOLS)}")
        self.install_status.config(text=(f"{len(self.missing_packages)} optional packages not installed."
                                        if self.missing_packages else "All local tools are ready."), foreground=MUTED)

    def install_missing(self):
        if not self.missing_packages:
            self.install_status.config(text="Nothing to install.", foreground=GOOD)
            return

        packages = sorted(self.missing_packages)
        self.install_status.config(text=f"Installing: {', '.join(packages)} ...", foreground=MEDIUM)
        self.install_button.config(state="disabled")

        def worker():
            cmd = ["sudo", "apt", "install", "-y"] + packages
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                ok = result.returncode == 0
            except Exception as e:
                ok = False
            self.frame.after(0, lambda: self._install_done(ok))

        threading.Thread(target=worker, daemon=True).start()

    def _install_done(self, ok):
        self.install_button.config(state="normal")
        if ok:
            self.install_status.config(text="Install finished — re-checking...", foreground=GOOD)
        else:
            self.install_status.config(text="Install may have failed — try running it manually in a terminal.", foreground=WARN)
        self.check_requirements()


class NetSuiteApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NetSuite · Personal workspace")
        self.root.geometry("1440x940")
        self.root.minsize(1260, 850)
        self.hostname = socket.gethostname().split(".")[0]
        self._configure_theme()
        self.trusted_manager = TrustedDevicesManager()
        self._build_menu_bar()
        self._build_header()

        shell = ttk.Frame(root)
        shell.pack(fill="both", expand=True)
        self.sidebar = tk.Frame(shell, bg=PANEL_BG, width=210)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        main = ttk.Frame(shell)
        main.pack(side="left", fill="both", expand=True)
        heading = ttk.Frame(main, padding=(24, 22, 24, 16))
        heading.pack(fill="x")
        self.page_title = ttk.Label(heading, style="Title.TLabel")
        self.page_title.pack(anchor="w")
        self.page_description = ttk.Label(heading, style="Muted.TLabel")
        self.page_description.pack(anchor="w", pady=(6, 0))
        ttk.Separator(main).pack(fill="x", padx=24)
        self.notebook = ttk.Notebook(main, style="Workspace.TNotebook", takefocus=False)
        self.notebook.pack(fill="both", expand=True)
        notebook = self.notebook
        self.device_tab = DeviceMonitorTab(notebook, self.trusted_manager)
        self.wifi_tab = WifiScannerTab(notebook)
        self.brief_tab = BriefWatcherTab(notebook, self.trusted_manager)
        self.ping_tab = PingTracerouteTab(notebook)
        self.dns_tab = DnsWhoisTab(notebook)
        self.wol_tab = WakeOnLanTab(notebook)
        self.bandwidth_tab = BandwidthMonitorTab(notebook)
        self.firewall_tab = FirewallRulesTab(notebook)
        self.hydra_tab = HydraTab(notebook)
        self.exploit_tab = ExploitSearchTab(notebook)
        self.arpspoof_tab = ArpSpoofTab(notebook)
        self.nikto_tab = NiktoTab(notebook)
        self.home_tab = HomeTab(notebook, self)
        self.pages = [
            ("overview", "Overview", "Your network, devices and local tools at a glance.", self.home_tab, "WORKSPACE"),
            ("devices", "My devices", "Saved hosts, trusted hardware and network discovery.", self.device_tab, None),
            ("wifi", "WiFi", "Nearby access points, channel usage and signal strength.", self.wifi_tab, None),
            ("connections", "Brief activity", "Short bursts of ARP activity observed on your interface.", self.brief_tab, None),
            ("bandwidth", "Traffic", "Bandwidth and connections on this machine.", self.bandwidth_tab, None),
            ("ping", "Connectivity", "Check a host and trace the path to it.", self.ping_tab, "DIAGNOSTICS"),
            ("dns", "DNS & ownership", "Resolve records and inspect domain ownership.", self.dns_tab, None),
            ("wake", "Wake a device", "Send a wake packet to your hardware.", self.wol_tab, None),
            ("firewall", "Firewall", "Inspect and manage local input rules.", self.firewall_tab, None),
            ("logins", "Login testing", "Check credentials against services in your lab.", self.hydra_tab, "SECURITY LAB"),
            ("research", "Vulnerability lookup", "Search the local exploit database by service or version.", self.exploit_tab, None),
            ("arp", "ARP workspace", "Interface controls and packet capture for your lab.", self.arpspoof_tab, None),
            ("web", "Web checks", "Inspect your web services for common configuration issues.", self.nikto_tab, None),
        ]
        self.nav_buttons = {}
        for key, title, description, tab, section in self.pages:
            if section:
                tk.Label(self.sidebar, text=section, bg=PANEL_BG, fg=MUTED,
                         font=(UI_FONT, 8, "bold"), anchor="w").pack(fill="x", padx=20, pady=(22, 7))
            notebook.add(tab.frame, text=title)
            button = tk.Button(self.sidebar, text=title, anchor="w", relief="flat", bd=0,
                               bg=PANEL_BG, fg=MUTED, activebackground=SELECTED_BG,
                               activeforeground=TEXT_COLOR, font=(UI_FONT, 10), padx=14, pady=9,
                               cursor="hand2", command=lambda target=key: self.navigate(target))
            button.pack(fill="x", padx=9, pady=1)
            self.nav_buttons[key] = button
        footer = ttk.Frame(root, style="Card.TFrame", padding=(20, 9))
        footer.pack(fill="x")
        ttk.Label(footer, text="LOCAL WORKSPACE", style="Eyebrow.TLabel").pack(side="left")
        ttk.Label(footer, text=("Elevated session" if IS_ROOT else "Standard session · capture and firewall need elevation"),
                  style="CardMuted.TLabel").pack(side="right")
        self.navigate("overview")
        self.root.bind("<Control-1>", lambda event: self.navigate("overview"))
        self.root.bind("<Control-2>", lambda event: self.navigate("devices"))

    def _configure_theme(self):
        global UI_FONT, MONO_FONT
        families = set(tkfont.families(self.root))
        UI_FONT = next((font for font in ("Inter", "Segoe UI", "DejaVu Sans") if font in families), "TkDefaultFont")
        MONO_FONT = next((font for font in ("JetBrains Mono", "DejaVu Sans Mono", "Consolas") if font in families), "TkFixedFont")
        tkfont.nametofont("TkDefaultFont").configure(family=UI_FONT, size=10)
        tkfont.nametofont("TkTextFont").configure(family=UI_FONT, size=10)
        tkfont.nametofont("TkFixedFont").configure(family=MONO_FONT, size=10)
        self.root.configure(bg=BG_COLOR)
        self.root.option_add("*Text.font", (MONO_FONT, 10))
        self.root.option_add("*Text.background", "#111c2a")
        self.root.option_add("*Text.foreground", TEXT_COLOR)
        self.root.option_add("*Text.insertBackground", ACCENT)
        self.root.option_add("*Text.selectBackground", SELECTED_BG)
        self.root.option_add("*Text.relief", "flat")
        self.root.option_add("*Text.borderWidth", 0)
        self.root.option_add("*Text.padX", 12)
        self.root.option_add("*Text.padY", 10)
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", background=BG_COLOR, foreground=TEXT_COLOR, font=(UI_FONT, 10), bordercolor=BORDER)
        style.configure("TFrame", background=BG_COLOR)
        style.configure("Card.TFrame", background=PANEL_BG)
        style.configure("TLabel", background=BG_COLOR, foreground=TEXT_COLOR)
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("CardMuted.TLabel", background=PANEL_BG, foreground=MUTED, font=(UI_FONT, 9))
        style.configure("Eyebrow.TLabel", background=PANEL_BG, foreground=MUTED, font=(UI_FONT, 8, "bold"))
        style.configure("Metric.TLabel", background=PANEL_BG, foreground=TEXT_COLOR, font=(UI_FONT, 28, "bold"))
        style.configure("Title.TLabel", font=(UI_FONT, 22, "bold"))
        style.configure("Section.TLabel", font=(UI_FONT, 12, "bold"))
        style.configure("TButton", background=PANEL_BG, foreground=TEXT_COLOR, padding=(12, 8), borderwidth=1, relief="flat")
        style.map("TButton", background=[("active", SELECTED_BG), ("disabled", BG_COLOR)],
                  foreground=[("disabled", "#65758b")], bordercolor=[("focus", ACCENT)])
        style.configure("Quick.TButton", font=(UI_FONT, 11, "bold"), foreground=ACCENT, padding=0, borderwidth=0)
        style.configure("TEntry", fieldbackground=PANEL_BG, foreground=TEXT_COLOR, insertcolor=ACCENT, padding=7)
        style.configure("TCombobox", fieldbackground=PANEL_BG, background=PANEL_BG, foreground=TEXT_COLOR, padding=6, arrowcolor=MUTED)
        style.map("TCombobox", fieldbackground=[("readonly", PANEL_BG)], foreground=[("readonly", TEXT_COLOR)])
        style.configure("TCheckbutton", background=BG_COLOR, foreground=TEXT_COLOR, padding=4)
        style.map("TCheckbutton", background=[("active", BG_COLOR)])
        style.configure("TNotebook", background=BG_COLOR, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(14, 9), background=PANEL_BG)
        style.map("TNotebook.Tab", background=[("selected", SELECTED_BG)], foreground=[("selected", ACCENT)])
        style.layout("Workspace.TNotebook.Tab", [])
        style.configure("Treeview", background=PANEL_BG, fieldbackground=PANEL_BG, foreground=TEXT_COLOR,
                        rowheight=32, borderwidth=0, font=(UI_FONT, 10))
        style.configure("Treeview.Heading", background="#1f2d3f", foreground=MUTED,
                        padding=(10, 10), relief="flat", font=(UI_FONT, 9, "bold"))
        style.map("Treeview", background=[("selected", SELECTED_BG)], foreground=[("selected", TEXT_COLOR)])
        style.configure("TSeparator", background=BORDER)
        style.configure("Vertical.TScrollbar", background=BORDER, troughcolor=BG_COLOR, borderwidth=0, arrowcolor=MUTED)

    def _build_header(self):
        header = tk.Frame(self.root, bg=PANEL_BG, height=72)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="N", bg=SELECTED_BG, fg=ACCENT, font=(UI_FONT, 17, "bold"),
                 padx=12, pady=4).pack(side="left", padx=(20, 12), pady=16)
        tk.Label(header, text="NetSuite", bg=PANEL_BG, fg=TEXT_COLOR,
                 font=(UI_FONT, 17, "bold")).pack(side="left")
        tk.Label(header, text="PERSONAL NETWORK", bg=PANEL_BG, fg=MUTED,
                 font=(UI_FONT, 9)).pack(side="left", padx=18)
        tk.Label(header, text=self.hostname, bg=PANEL_BG, fg=MUTED,
                 font=(MONO_FONT, 10)).pack(side="right", padx=24)

    def navigate(self, key):
        for page_key, title, description, tab, section in self.pages:
            selected = page_key == key
            self.nav_buttons[page_key].config(bg=SELECTED_BG if selected else PANEL_BG,
                                              fg=TEXT_COLOR if selected else MUTED)
            if selected:
                self.notebook.select(tab.frame)
                self.page_title.config(text=title)
                self.page_description.config(text=description)
        if key == "overview":
            self.home_tab.check_requirements()

    def _build_menu_bar(self):
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)

        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Export Current Tab to CSV...", command=self.export_current_tab, accelerator="Ctrl+E")
        file_menu.add_separator()
        file_menu.add_command(label="Manage Trusted Devices...", command=self.open_trusted_devices)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=lambda: self.root.event_generate("<<CloseApp>>"))
        menu_bar.add_cascade(label="Workspace", menu=file_menu)
        self.root.bind_all("<Control-e>", lambda e: self.export_current_tab())

        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About NetSuite", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

    def export_current_tab(self):
        current = self.notebook.nametowidget(self.notebook.select())
        if current is self.device_tab.frame:
            self.device_tab.export_csv()
        elif current is self.wifi_tab.frame:
            self.wifi_tab.export_csv()
        elif current is self.brief_tab.frame:
            self.brief_tab.export_csv()

    def open_trusted_devices(self):
        TrustedDevicesWindow(self.root, self.trusted_manager)

    def show_about(self):
        messagebox.showinfo(
            "NetSuite",
            f"NetSuite {NETSUITE_VERSION}\nPersonal network workspace\n\n"
            f"Machine: {self.hostname}\n"
            "Device history and trusted hardware stay on this machine.\n\n"
            "Ctrl+1  Overview\nCtrl+2  My devices\nCtrl+E  Export current device or WiFi table"
        )

    def shutdown(self):
        if self.device_tab.scanner_thread:
            self.device_tab.scanner_thread.stop()
        if self.wifi_tab.scanner_thread:
            self.wifi_tab.scanner_thread.stop()
        if self.brief_tab.watcher_thread:
            self.brief_tab.watcher_thread.stop()
        if self.ping_tab.active_thread:
            self.ping_tab.active_thread.stop()
        if self.bandwidth_tab.thread:
            self.bandwidth_tab.thread.stop()
        if self.hydra_tab.thread:
            self.hydra_tab.thread.stop()
        if self.arpspoof_tab.spoof_processes:
            self.arpspoof_tab.stop_mitm()
        if self.nikto_tab.thread:
            self.nikto_tab.thread.stop()


def main():
    root = tk.Tk()
    app = NetSuiteApp(root)

    def on_close():
        app.shutdown()
        root.destroy()

    root.bind("<<CloseApp>>", lambda event: on_close())
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
