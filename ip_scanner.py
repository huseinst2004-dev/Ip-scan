"""
IP Scanner - network scanner with a GUI (Python + tkinter, no extra packages).

Features:
  * Auto-detects your local network (e.g. 192.168.1.0/24)
  * Accepts CIDR (192.168.1.0/24), ranges (192.168.1.10-192.168.1.50) or a single IP
  * Fast parallel ping sweep
  * Shows hostname, MAC address, response time and open ports
  * Export results to CSV

Run:  py ip_scanner.py
CLI:  py ip_scanner.py --cli 192.168.1.0/24
"""

import csv
import ipaddress
import platform
import queue
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

IS_WINDOWS = platform.system() == "Windows"
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                3306, 3389, 5900, 8080, 8443]
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW


# ---------------------------------------------------------------- core logic
def get_local_network():
    """Return the local /24 network of this machine, e.g. '192.168.1.0/24'."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # no packets are sent for UDP connect
        ip = s.getsockname()[0]
        s.close()
    except OSError:
        ip = socket.gethostbyname(socket.gethostname())
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def parse_targets(text):
    """Parse CIDR, range 'a-b', range 'a.b.c.d-e' or single IP into a list."""
    text = text.strip()
    if "-" in text:
        start, end = [p.strip() for p in text.split("-", 1)]
        start_ip = ipaddress.IPv4Address(start)
        if "." not in end:  # short form: 192.168.1.10-50
            end = start.rsplit(".", 1)[0] + "." + end
        end_ip = ipaddress.IPv4Address(end)
        if end_ip < start_ip:
            start_ip, end_ip = end_ip, start_ip
        return [str(ipaddress.IPv4Address(i))
                for i in range(int(start_ip), int(end_ip) + 1)]
    if "/" in text:
        net = ipaddress.ip_network(text, strict=False)
        hosts = list(net.hosts())
        return [str(h) for h in (hosts or [net.network_address])]
    return [str(ipaddress.IPv4Address(text))]


def ping(ip, timeout_ms=800):
    """Ping once. Returns response time in ms, or None if no reply."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    start = time.perf_counter()
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout_ms / 1000 + 2,
                             creationflags=NO_WINDOW).stdout
    except (subprocess.TimeoutExpired, OSError):
        return None
    elapsed = (time.perf_counter() - start) * 1000
    # On Windows, "Destination host unreachable" still returns code 0,
    # so check for a real TTL in the reply.
    if "TTL=" not in out.upper():
        return None
    m = re.search(r"(?:time|zeit|temps)[=<]\s*([\d.]+)\s*ms", out, re.I)
    return float(m.group(1)) if m else round(elapsed, 1)


def tcp_alive(ip, ports=(80, 443, 445, 22, 3389), timeout=0.4):
    """Fallback for hosts that block ping: try a few TCP ports."""
    for p in ports:
        if check_port(ip, p, timeout):
            return True
    return False


def check_port(ip, port, timeout=0.4):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def get_arp_table():
    """Read the OS ARP cache -> {ip: mac}."""
    table = {}
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             creationflags=NO_WINDOW).stdout
    except OSError:
        return table
    for m in re.finditer(
            r"(\d+\.\d+\.\d+\.\d+)\D+?([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})",
            out):
        table[m.group(1)] = m.group(2).replace("-", ":").upper()
    return table


def scan_host(ip, scan_ports, stop_event):
    if stop_event.is_set():
        return None
    rtt = ping(ip)
    alive = rtt is not None
    if not alive and scan_ports:
        alive = tcp_alive(ip)
    if not alive:
        return None
    result = {"ip": ip, "rtt": rtt, "hostname": get_hostname(ip),
              "mac": "", "ports": []}
    if scan_ports and not stop_event.is_set():
        result["ports"] = [p for p in COMMON_PORTS if check_port(ip, p)]
    return result


def run_scan(targets, scan_ports, workers, stop_event, on_result, on_progress):
    done = 0
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_host, ip, scan_ports, stop_event)
                   for ip in targets]
        for fut in as_completed(futures):
            done += 1
            r = fut.result()
            if r:
                results.append(r)
                on_result(r)
            on_progress(done, len(targets))
    # Fill MAC addresses from the ARP cache (populated by the pings)
    arp = get_arp_table()
    for r in results:
        r["mac"] = arp.get(r["ip"], "")
    return results


def ip_key(ip):
    return tuple(int(x) for x in ip.split("."))


# ---------------------------------------------------------------- GUI
def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    root = tk.Tk()
    root.title("IP Scanner")
    root.geometry("900x560")
    root.minsize(700, 400)

    events = queue.Queue()
    state = {"stop": threading.Event(), "running": False, "results": {}}

    # --- top bar
    top = ttk.Frame(root, padding=10)
    top.pack(fill="x")
    ttk.Label(top, text="Target:").pack(side="left")
    target_var = tk.StringVar(value=get_local_network())
    entry = ttk.Entry(top, textvariable=target_var, width=32)
    entry.pack(side="left", padx=6)
    ports_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(top, text="Scan common ports",
                    variable=ports_var).pack(side="left", padx=6)
    ttk.Label(top, text="Threads:").pack(side="left")
    workers_var = tk.IntVar(value=100)
    ttk.Spinbox(top, from_=1, to=500, textvariable=workers_var,
                width=5).pack(side="left", padx=4)
    scan_btn = ttk.Button(top, text="Start scan")
    scan_btn.pack(side="left", padx=6)
    export_btn = ttk.Button(top, text="Export CSV")
    export_btn.pack(side="left")

    ttk.Label(root, padding=(10, 0),
              text="Examples: 192.168.1.0/24   |   192.168.1.1-192.168.1.100"
                   "   |   192.168.1.1-50   |   10.0.0.5",
              foreground="gray").pack(anchor="w")

    # --- table
    cols = ("ip", "hostname", "mac", "rtt", "ports")
    heads = {"ip": "IP Address", "hostname": "Hostname", "mac": "MAC Address",
             "rtt": "Ping (ms)", "ports": "Open ports"}
    widths = {"ip": 130, "hostname": 220, "mac": 150, "rtt": 80, "ports": 280}
    frame = ttk.Frame(root, padding=10)
    frame.pack(fill="both", expand=True)
    tree = ttk.Treeview(frame, columns=cols, show="headings")
    for c in cols:
        tree.heading(c, text=heads[c], command=lambda c=c: sort_by(c))
        tree.column(c, width=widths[c], anchor="w")
    sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")

    # --- status bar
    bottom = ttk.Frame(root, padding=(10, 0, 10, 10))
    bottom.pack(fill="x")
    progress = ttk.Progressbar(bottom, mode="determinate")
    progress.pack(fill="x")
    status_var = tk.StringVar(value="Ready.")
    ttk.Label(bottom, textvariable=status_var).pack(anchor="w", pady=(4, 0))

    sort_state = {"col": "ip", "rev": False}

    def sort_by(col):
        rev = not sort_state["rev"] if sort_state["col"] == col else False
        sort_state.update(col=col, rev=rev)
        items = list(tree.get_children())

        def key(iid):
            v = tree.set(iid, col)
            if col == "ip":
                return ip_key(v)
            if col == "rtt":
                try:
                    return float(v)
                except ValueError:
                    return float("inf")
            return v.lower()
        for i, iid in enumerate(sorted(items, key=key, reverse=rev)):
            tree.move(iid, "", i)

    def row_values(r):
        rtt = "" if r["rtt"] is None else f"{r['rtt']:.0f}"
        return (r["ip"], r["hostname"] or "-", r["mac"] or "-", rtt,
                ", ".join(map(str, r["ports"])) or "-")

    def insert_sorted(r):
        idx = 0
        for i, iid in enumerate(tree.get_children()):
            if ip_key(iid) > ip_key(r["ip"]):
                idx = i
                break
        else:
            idx = "end"
        tree.insert("", idx, iid=r["ip"], values=row_values(r))

    def start_scan():
        if state["running"]:
            state["stop"].set()
            status_var.set("Stopping...")
            return
        try:
            targets = parse_targets(target_var.get())
        except ValueError as e:
            messagebox.showerror("Invalid target", str(e))
            return
        if len(targets) > 65536:
            messagebox.showerror("Too many", "Maximum is 65,536 addresses.")
            return
        tree.delete(*tree.get_children())
        state["results"].clear()
        state["stop"] = threading.Event()
        state["running"] = True
        state["t0"] = time.time()
        progress.configure(maximum=len(targets), value=0)
        scan_btn.configure(text="Stop")
        status_var.set(f"Scanning {len(targets)} addresses...")

        def worker():
            res = run_scan(
                targets, ports_var.get(), max(1, workers_var.get()),
                state["stop"],
                on_result=lambda r: events.put(("result", r)),
                on_progress=lambda d, t: events.put(("progress", (d, t))))
            events.put(("done", res))
        threading.Thread(target=worker, daemon=True).start()

    def poll():
        try:
            while True:
                kind, data = events.get_nowait()
                if kind == "result":
                    state["results"][data["ip"]] = data
                    insert_sorted(data)
                elif kind == "progress":
                    d, t = data
                    progress.configure(value=d)
                    status_var.set(f"Scanned {d}/{t}  -  "
                                   f"{len(state['results'])} hosts up")
                elif kind == "done":
                    for r in data:  # update MACs
                        state["results"][r["ip"]] = r
                        if tree.exists(r["ip"]):
                            tree.item(r["ip"], values=row_values(r))
                    state["running"] = False
                    scan_btn.configure(text="Start scan")
                    secs = time.time() - state["t0"]
                    word = "stopped" if state["stop"].is_set() else "finished"
                    status_var.set(f"Scan {word}: {len(data)} hosts up "
                                   f"in {secs:.1f}s.")
        except queue.Empty:
            pass
        root.after(100, poll)

    def export_csv():
        if not state["results"]:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile="scan_results.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["IP", "Hostname", "MAC", "Ping (ms)", "Open ports"])
            for ip in sorted(state["results"], key=ip_key):
                w.writerow(row_values(state["results"][ip]))
        status_var.set(f"Saved: {path}")

    def copy_ip(_event=None):
        sel = tree.selection()
        if sel:
            root.clipboard_clear()
            root.clipboard_append("\n".join(sel))
            status_var.set(f"Copied: {', '.join(sel)}")

    scan_btn.configure(command=start_scan)
    export_btn.configure(command=export_csv)
    entry.bind("<Return>", lambda e: start_scan())
    tree.bind("<Control-c>", copy_ip)
    tree.bind("<Double-1>", copy_ip)

    poll()
    root.mainloop()


# ---------------------------------------------------------------- CLI
def run_cli(target, scan_ports=True):
    targets = parse_targets(target)
    print(f"Scanning {len(targets)} addresses in {target} ...")
    t0 = time.time()
    results = run_scan(targets, scan_ports, 100, threading.Event(),
                       on_result=lambda r: print(f"  [+] {r['ip']} is up"),
                       on_progress=lambda d, t: None)
    print(f"\n{'IP':<16}{'Hostname':<30}{'MAC':<19}{'Ping':<7}Ports")
    print("-" * 90)
    for r in sorted(results, key=lambda r: ip_key(r["ip"])):
        rtt = "" if r["rtt"] is None else f"{r['rtt']:.0f}ms"
        print(f"{r['ip']:<16}{(r['hostname'] or '-')[:29]:<30}"
              f"{r['mac'] or '-':<19}{rtt:<7}"
              f"{', '.join(map(str, r['ports'])) or '-'}")
    print(f"\n{len(results)} hosts up, {time.time() - t0:.1f}s")


if __name__ == "__main__":
    if "--cli" in sys.argv:
        args = [a for a in sys.argv[1:] if a != "--cli"]
        no_ports = "--no-ports" in args
        args = [a for a in args if a != "--no-ports"]
        run_cli(args[0] if args else get_local_network(), not no_ports)
    else:
        run_gui()
