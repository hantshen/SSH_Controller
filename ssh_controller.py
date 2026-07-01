import tkinter as tk
from tkinter import scrolledtext, messagebox
import tkinter.font as tkfont
import configparser
import threading
import queue
import time
import os
import sys

import paramiko

# When frozen by PyInstaller --onefile, use the EXE's directory.
# When running as script, use the script's directory.
if getattr(sys, 'frozen', False):
    _BASE_DIR = os.path.dirname(sys.executable)
else:
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE      = os.path.join(_BASE_DIR, "settings.ini")
KNOWN_HOSTS_FILE = os.path.join(_BASE_DIR, "ssh_known_hosts.txt")
RECV_BUFFER   = 4096
MAX_LOG_LINES = 500
CONNECT_TIMEOUT = 15

# Single source of truth for outgoing device commands — edit here only.
CMDS = {
    "fan_start":    "FAN start",
    "fan_stop":     "FAN stop",
    "power_switch": "PWR switch",
    "key_a":        "KEY A",
    "key_b":        "KEY B",
    "key_c":        "KEY C",
    "key_d":        "KEY D",
    "key_back":     "KEY back",
    "enc_left":     "ENC left",
    "enc_enter":    "ENC enter",
    "enc_right":    "ENC right",
    "get_lcm":      "GET LCM",
    "get_pwr":      "PWR status",
}

# Echoes of button commands from the device — suppress to keep log clean.
# Derived from CMDS so button strings and echo filter can never drift apart.
_CMD_ECHOES  = frozenset(v.lower() for k, v in CMDS.items() if not k.startswith("get_"))
_POLL_ECHOES = tuple(v.upper() for k, v in CMDS.items() if k.startswith("get_"))


class _TrustFirstUsePolicy(paramiko.MissingHostKeyPolicy):
    """TOFU: trust the server's host key on first connection.
    If a previously-saved key for the host changes, reject — GUI has no
    console to prompt for accept/reject, so a mismatch fails closed."""

    def __init__(self, log_cb):
        self._log = log_cb

    def missing_host_key(self, client, hostname, key):
        key_type = key.get_name()
        host_key_str = f"{key_type} {key.get_base64()}"

        known = {}
        if os.path.exists(KNOWN_HOSTS_FILE):
            with open(KNOWN_HOSTS_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        known[parts[0]] = " ".join(parts[1:])

        if hostname in known:
            if known[hostname] != host_key_str:
                fingerprint = key.get_fingerprint().hex(":")
                raise paramiko.SSHException(
                    f"Host key for {hostname} has CHANGED (fingerprint {fingerprint}) — "
                    f"refusing to connect. Delete {KNOWN_HOSTS_FILE} entry if this is expected.")
            return

        fingerprint = key.get_fingerprint().hex(":")
        self._log(f"First connection to {hostname} — key {key_type} {fingerprint}, trusting and saving")

        known[hostname] = host_key_str
        with open(KNOWN_HOSTS_FILE, "w") as f:
            f.write("# SSH Controller Known Hosts (auto-generated)\n")
            for h, k in known.items():
                f.write(f"{h} {k}\n")


class SSHApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Controller")
        self.root.resizable(True, True)

        self.ssh_client = None
        self.channel = None
        self.connected = False
        self.recv_thread = None
        self.send_thread = None
        self.stop_recv = threading.Event()

        self._cmd_queue     = queue.Queue()
        self._cmd_event     = threading.Event()  # wakes sender immediately on enqueue
        self._led_dim_id    = None
        self._lcm_refresh_id = None
        self._pwr_refresh_id = None
        self._recv_linebuf  = ""   # accumulates partial recv data until newline
        self._response_rules = self._build_response_rules()

        self._build_ui()
        self._load_settings()

    # ------------------------------------------------------------------ UI --

    def _build_ui(self):
        # Settings
        frm_settings = tk.LabelFrame(self.root, text="Connection Settings", padx=6, pady=6)
        frm_settings.grid(row=0, column=0, columnspan=2, padx=10, pady=8, sticky="ew")

        labels = ["IP Address", "Port", "Username", "Password"]
        self.vars = {}
        for i, lbl in enumerate(labels):
            tk.Label(frm_settings, text=lbl + ":").grid(row=i, column=0, sticky="e", padx=4, pady=2)
            key = lbl.lower().replace(" ", "_")
            var = tk.StringVar()
            show = "*" if lbl == "Password" else ""
            entry = tk.Entry(frm_settings, textvariable=var, width=24, show=show)
            entry.grid(row=i, column=1, sticky="w", padx=4, pady=2)
            self.vars[key] = var

        # Connect / Disconnect — right column of settings frame
        frm_conn = tk.Frame(frm_settings)
        frm_conn.grid(row=0, column=2, rowspan=4, padx=16, pady=4, sticky="ns")

        self.btn_connect = tk.Button(frm_conn, text="Connect", width=14, bg="#d0d0d0", fg="black",
                                     command=self._connect)
        self.btn_connect.pack(pady=4)

        self.btn_disconnect = tk.Button(frm_conn, text="Disconnect", width=14, bg="#d0d0d0", fg="black",
                                        state=tk.DISABLED, command=self._disconnect)
        self.btn_disconnect.pack(pady=4)

        self.lbl_status = tk.Label(frm_conn, text="Disconnected", fg="red")
        self.lbl_status.pack(pady=2)

        # Fan / Power commands
        frm_cmd = tk.LabelFrame(self.root, text="Commands", padx=6, pady=6)
        frm_cmd.grid(row=1, column=0, columnspan=2, padx=10, pady=4, sticky="ew")

        self.btn_fan_start = tk.Button(frm_cmd, text="FAN START", width=14, bg="#d0d0d0", fg="black",
                                       state=tk.DISABLED, command=lambda: self._send_cmd(CMDS["fan_start"]))
        self.btn_fan_start.pack(side=tk.LEFT, padx=4)

        self.btn_fan_stop = tk.Button(frm_cmd, text="FAN STOP", width=14, bg="#d0d0d0", fg="black",
                                      state=tk.DISABLED, command=lambda: self._send_cmd(CMDS["fan_stop"]))
        self.btn_fan_stop.pack(side=tk.LEFT, padx=4)

        # Remote control
        frm_remote = tk.LabelFrame(self.root, text="Remote Control", padx=8, pady=8)
        frm_remote.grid(row=2, column=0, columnspan=2, padx=10, pady=4, sticky="ew")

        BTN_W = 8
        BTN_BG = "#d0d0d0"

        # LED indicator — top-right of Remote Control frame
        frm_led_bar = tk.Frame(frm_remote)
        frm_led_bar.pack(fill=tk.X)
        self._led_canvas = tk.Canvas(frm_led_bar, width=16, height=16,
                                     bg=frm_remote.cget("bg"), highlightthickness=0)
        self._led_canvas.pack(side=tk.RIGHT, padx=4, pady=2)
        self._led_oval = self._led_canvas.create_oval(2, 2, 14, 14,
                                                      fill="#606060", outline="#404040")

        # Row 0: POWER | A | B | C | D | BACK
        frm_r0 = tk.Frame(frm_remote)
        frm_r0.pack(fill=tk.X, pady=2)
        self.btn_rmt_power = tk.Button(frm_r0, text="POWER", width=BTN_W, bg=BTN_BG, fg="black",
                                       state=tk.DISABLED, command=lambda: self._send_cmd(CMDS["power_switch"]))
        self.btn_rmt_power.pack(side=tk.LEFT, padx=4)

        self._remote_btns = []
        for lbl, key in [("A", "key_a"), ("B", "key_b"), ("C", "key_c"), ("D", "key_d")]:
            b = tk.Button(frm_r0, text=lbl, width=BTN_W, bg=BTN_BG, fg="black",
                          state=tk.DISABLED, command=lambda k=key: self._send_cmd(CMDS[k]))
            b.pack(side=tk.LEFT, padx=4)
            self._remote_btns.append(b)

        self.btn_back = tk.Button(frm_r0, text="BACK", width=BTN_W, bg=BTN_BG, fg="black",
                                  state=tk.DISABLED, command=lambda: self._send_cmd(CMDS["key_back"]))
        self.btn_back.pack(side=tk.LEFT, padx=4)

        # Row 1: Encoder
        frm_r2 = tk.Frame(frm_remote)
        frm_r2.pack(fill=tk.X, pady=2)
        tk.Label(frm_r2, text="Encoder:").pack(side=tk.LEFT, padx=4)
        self.btn_enc_left = tk.Button(frm_r2, text="◄ Left", width=BTN_W, bg=BTN_BG, fg="black",
                                      state=tk.DISABLED, command=lambda: self._send_cmd(CMDS["enc_left"]))
        self.btn_enc_left.pack(side=tk.LEFT, padx=4)
        self.btn_enc_enter = tk.Button(frm_r2, text="Enter", width=BTN_W, bg=BTN_BG, fg="black",
                                       state=tk.DISABLED, command=lambda: self._send_cmd(CMDS["enc_enter"]))
        self.btn_enc_enter.pack(side=tk.LEFT, padx=4)
        self.btn_enc_right = tk.Button(frm_r2, text="Right ►", width=BTN_W, bg=BTN_BG, fg="black",
                                       state=tk.DISABLED, command=lambda: self._send_cmd(CMDS["enc_right"]))
        self.btn_enc_right.pack(side=tk.LEFT, padx=4)

        # LCD screen
        self._build_lcd_frame(row=3)

        # Log
        frm_log = tk.LabelFrame(self.root, text="Log", padx=6, pady=6)
        frm_log.grid(row=4, column=0, columnspan=2, padx=10, pady=8, sticky="nsew")

        self.log = scrolledtext.ScrolledText(frm_log, width=70, height=14, state=tk.DISABLED,
                                             bg="#1e1e1e", fg="#d4d4d4", font=("Consolas", 9),
                                             insertbackground="white")
        self.log.pack(fill=tk.BOTH, expand=True)

        btn_clear = tk.Button(frm_log, text="Clear Log", command=self._clear_log)
        btn_clear.pack(anchor="e", pady=2)

        # Custom send
        frm_custom = tk.Frame(self.root)
        frm_custom.grid(row=5, column=0, columnspan=2, padx=10, pady=4, sticky="ew")

        tk.Label(frm_custom, text="Send:").pack(side=tk.LEFT)
        self.custom_cmd = tk.StringVar()
        self.entry_cmd = tk.Entry(frm_custom, textvariable=self.custom_cmd, width=50)
        self.entry_cmd.pack(side=tk.LEFT, padx=4)
        self.entry_cmd.bind("<Return>", lambda e: self._send_custom())

        self.btn_send = tk.Button(frm_custom, text="Send", width=8, bg="#d0d0d0", fg="black",
                                  state=tk.DISABLED, command=self._send_custom)
        self.btn_send.pack(side=tk.LEFT, padx=4)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(4, weight=1)

    def _build_lcd_frame(self, row: int):
        COLS = 16
        ROWS = 2
        PAD_X = 8
        PAD_Y = 6
        LCD_BG = "#1a2d1a"
        LCD_BORDER = "#3a6a3a"
        CHAR_COLOR = "#33ff66"
        FONT = ("Courier", 12, "bold")

        # Measure exact character dimensions from font
        f = tkfont.Font(family="Courier", size=12, weight="bold")
        CHAR_W = f.measure("W")          # monospace: all chars same width
        CHAR_H = f.metrics("linespace")

        canvas_w = COLS * CHAR_W + 2 * PAD_X
        canvas_h = ROWS * CHAR_H + 2 * PAD_Y

        frm_lcd = tk.LabelFrame(self.root, text="LCM Display (16×2)", padx=8, pady=6)
        # No sticky — frame wraps tightly around the canvas
        frm_lcd.grid(row=row, column=0, columnspan=2, padx=10, pady=4)

        self._lcd = tk.Canvas(frm_lcd, width=canvas_w, height=canvas_h,
                              bg=LCD_BG, highlightthickness=2,
                              highlightbackground=LCD_BORDER)
        self._lcd.pack(pady=4, expand=False, fill=tk.NONE)

        self._lcd_text = []
        for r in range(ROWS):
            y = PAD_Y + r * CHAR_H + CHAR_H // 2
            tid = self._lcd.create_text(PAD_X, y, anchor="w",
                                        text=" " * COLS,
                                        font=FONT,
                                        fill=CHAR_COLOR)
            self._lcd_text.append(tid)

    def _update_lcd(self, row1: str, row2: str):
        self._lcd.itemconfig(self._lcd_text[0], text=row1[:16].ljust(16))
        self._lcd.itemconfig(self._lcd_text[1], text=row2[:16].ljust(16))

    # ------------------------------------------------------------ Settings --

    def _load_settings(self):
        cfg = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE):
            cfg.read(CONFIG_FILE)
            sec = cfg["connection"] if "connection" in cfg else {}
            self.vars["ip_address"].set(sec.get("ip", ""))
            self.vars["port"].set(sec.get("port", "22"))
            self.vars["username"].set(sec.get("username", ""))
            self.vars["password"].set(sec.get("password", ""))
        else:
            self.vars["port"].set("22")

    # --------------------------------------------------------------- Log --

    def _log(self, msg, tag="info"):
        colors = {"send": "#9CDCFE", "recv": "#CE9178", "info": "#DCDCAA", "error": "#F44747"}
        self.log.config(state=tk.NORMAL)
        timestamp = time.strftime("%H:%M:%S")
        self.log.insert(tk.END, f"[{timestamp}] {msg}\n", tag)
        self.log.tag_config(tag, foreground=colors.get(tag, "#d4d4d4"))
        # Trim oldest lines so widget stays O(1) — unbounded growth makes see(END) slow
        line_count = int(self.log.index("end-1c").split(".")[0])
        if line_count > MAX_LOG_LINES:
            self.log.delete("1.0", f"{line_count - MAX_LOG_LINES + 1}.0")
        self.log.see(tk.END)
        self.log.config(state=tk.DISABLED)

    def _clear_log(self):
        self.log.config(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.config(state=tk.DISABLED)

    # --------------------------------------------------------- Connection --

    def _set_connected(self, state: bool):
        self.connected = state
        on_conn = tk.NORMAL if state else tk.DISABLED
        off_conn = tk.DISABLED if state else tk.NORMAL
        self.btn_connect.config(state=off_conn, text="Connect")
        self.btn_disconnect.config(state=on_conn)
        self.btn_fan_start.config(state=on_conn)
        self.btn_fan_stop.config(state=on_conn)
        self.btn_rmt_power.config(state=on_conn)
        for b in self._remote_btns:
            b.config(state=on_conn)
        self.btn_back.config(state=on_conn)
        self.btn_enc_left.config(state=on_conn)
        self.btn_enc_enter.config(state=on_conn)
        self.btn_enc_right.config(state=on_conn)
        self.btn_send.config(state=on_conn)
        self.lbl_status.config(text="Connected" if state else "Disconnected",
                               fg="green" if state else "red")
        if state:
            # Fetch initial state immediately after connect
            self._poll_lcm()
            self._poll_pwr()
        else:
            # Cancel any pending post-button refresh timers
            if self._lcm_refresh_id:
                self.root.after_cancel(self._lcm_refresh_id)
                self._lcm_refresh_id = None
            if self._pwr_refresh_id:
                self.root.after_cancel(self._pwr_refresh_id)
                self._pwr_refresh_id = None
            self._update_lcd(" " * 16, " " * 16)
            self.btn_rmt_power.config(fg="black")

    def _connect(self):
        self.btn_connect.config(state=tk.DISABLED, text="Connecting...")
        self.lbl_status.config(text="Connecting...", fg="orange")
        threading.Thread(target=self._do_connect, daemon=True).start()

    def _reset_connect_button(self):
        self.btn_connect.config(state=tk.NORMAL, text="Connect")
        self.lbl_status.config(text="Disconnected", fg="red")

    def _do_connect(self):
        ip = self.vars["ip_address"].get().strip()
        port_str = self.vars["port"].get().strip()
        username = self.vars["username"].get().strip()
        password = self.vars["password"].get().strip()

        if not ip:
            self.root.after(0, lambda: messagebox.showerror("Error", "IP address required"))
            self.root.after(0, self._reset_connect_button)
            return
        try:
            port = int(port_str)
        except ValueError:
            self.root.after(0, lambda: messagebox.showerror("Error", "Invalid port number"))
            self.root.after(0, self._reset_connect_button)
            return

        self.root.after(0, lambda: self._log(f"Connecting to {ip}:{port}...", "info"))

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(
                _TrustFirstUsePolicy(lambda m: self.root.after(0, lambda: self._log(m, "info"))))
            client.connect(
                hostname=ip, port=port, username=username or None, password=password or None,
                timeout=CONNECT_TIMEOUT, allow_agent=False, look_for_keys=False,
                banner_timeout=CONNECT_TIMEOUT)

            channel = client.invoke_shell(term="vt100", width=200, height=50)
            channel.settimeout(0.2)

            time.sleep(0.5)
            try:
                banner = channel.recv(RECV_BUFFER)
                if banner:
                    text = banner.decode("latin-1").strip()
                    if text:
                        self.root.after(0, lambda t=text: self._log(t, "recv"))
            except Exception:
                pass

            self.ssh_client = client
            self.channel = channel
            self.stop_recv.clear()
            self._recv_linebuf = ""   # reset here (single-threaded) not in _set_connected
            self._cmd_event.clear()   # reset wakeup state for new session
            # drain stale items from previous session
            while not self._cmd_queue.empty():
                try:
                    self._cmd_queue.get_nowait()
                except queue.Empty:
                    break
            self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self.recv_thread.start()
            self.send_thread = threading.Thread(target=self._sender_loop, daemon=True)
            self.send_thread.start()

            self.root.after(0, lambda: self._set_connected(True))
            self.root.after(0, lambda: self._log(f"Connected to {ip}:{port}", "info"))

        except paramiko.AuthenticationException:
            self.root.after(0, lambda: self._log("Authentication failed: wrong username or password", "error"))
            self.root.after(0, self._reset_connect_button)
        except paramiko.SSHException as e:
            self.root.after(0, lambda err=e: self._log(f"SSH error: {err}", "error"))
            self.root.after(0, self._reset_connect_button)
        except Exception as e:
            self.root.after(0, lambda err=e: self._log(f"Connection failed: {err}", "error"))
            self.root.after(0, self._reset_connect_button)

    def _disconnect(self):
        self.stop_recv.set()
        self._cmd_queue.put(None)   # poison pill — stops sender thread
        self._cmd_event.set()       # wake sender so it reads the poison pill immediately
        if self.channel:
            try:
                self.channel.close()
            except Exception:
                pass
            self.channel = None
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:
                pass
            self.ssh_client = None
        self.root.after(0, lambda: self._set_connected(False))
        self.root.after(0, lambda: self._log("Disconnected", "info"))

    # --------------------------------------------------------- Recv loop --

    def _recv_loop(self):
        # Capture channel once — it only becomes None after disconnect sets stop_recv.
        chan = self.channel
        if not chan:
            return
        try:
            while not self.stop_recv.is_set():
                if not chan.recv_ready():
                    time.sleep(0.01)
                    continue
                data = chan.recv(RECV_BUFFER)
                if not data:
                    self.root.after(0, lambda: self._log("Connection closed by server", "error"))
                    self.root.after(0, lambda: self._set_connected(False))
                    break
                text = data.decode("latin-1")
                self._handle_recv(text)
        except Exception as e:
            if not self.stop_recv.is_set():
                self.root.after(0, lambda err=e: self._log(f"Recv error: {err}", "error"))
                self.root.after(0, lambda: self._set_connected(False))

    # HD44780 → Unicode mapping for characters that need translation
    _LCD_CHARMAP = str.maketrans({
        # Custom bar-graph chars (CGRAM 0x00–0x07) → Unicode vertical blocks
        "\x00": " ",   # empty / unused custom char
        "\x01": "▁",
        "\x02": "▂",
        "\x03": "▃",
        "\x04": "▄",
        "\x05": "▅",
        "\x06": "▆",
        "\x07": "▇",
        # Standard HD44780 specials
        "\xdf": "°",   # degree symbol
        "\xff": "█",   # full block
        "\xe4": "ä",
        "\xf6": "ö",
        "\xfc": "ü",
    })

    def _enqueue_cmd(self, data: bytes):
        """High-priority queue: button / user commands. Sets _cmd_event to wake sender immediately."""
        self._cmd_queue.put(data)
        self._cmd_event.set()       # break sender out of its poll-wait instantly

    def _sender_loop(self):
        """Dedicated send thread. Event-driven — wakes immediately on _enqueue_cmd."""
        while True:
            try:
                item = self._cmd_queue.get_nowait()
            except queue.Empty:
                self._cmd_event.wait(timeout=0.05)
                self._cmd_event.clear()
                continue

            if item is None:        # poison pill → exit
                break
            chan = self.channel
            if chan:
                try:
                    chan.sendall(item)
                except Exception as e:
                    self.root.after(0, lambda err=e: self._log(f"Send error: {err}", "error"))

    def _handle_lcm_line(self, stripped: str):
        payload = stripped[4:].translate(self._LCD_CHARMAP)
        row1 = payload[:16].ljust(16)
        row2 = payload[16:32].ljust(16)
        self.root.after(0, lambda r1=row1, r2=row2: (
            self._update_lcd(r1, r2), self._flash_led()))

    def _build_response_rules(self):
        """Ordered (match, action) table for one stripped recv line.
        match(stripped, upper) -> bool; first match wins.
        action(stripped) -> None, or None to suppress the line silently.
        Add new device-reply handling here instead of growing an if/elif chain."""
        return (
            (lambda s, u: u.startswith("LCM:"),                self._handle_lcm_line),
            (lambda s, u: any(p in u for p in _POLL_ECHOES),   None),  # poll command echoes
            (lambda s, u: u == ">",                            None),  # bare prompt
            (lambda s, u: s.lower() in _CMD_ECHOES,            None),  # button command echoes
            (lambda s, u: "POWER ON" in u,                     lambda s: self.root.after(0, self._on_power_on)),
            (lambda s, u: "POWER OFF" in u,                    lambda s: self.root.after(0, self._on_power_off)),
        )

    def _handle_recv(self, text: str):
        # Accumulate into line buffer; process only complete lines.
        # Fragmented echoes ("GET LCM" arriving as "GET ", "LCM\r\n") are
        # reassembled before filtering, so no response chars are accidentally stripped.
        self._recv_linebuf += text
        parts = self._recv_linebuf.split('\n')
        self._recv_linebuf = parts[-1]          # keep incomplete tail
        log_lines = []
        for raw in parts[:-1]:
            line = raw.strip('\r')
            stripped = line.strip()
            if not stripped:
                continue
            upper = stripped.upper()
            for match, action in self._response_rules:
                if match(stripped, upper):
                    if action:
                        action(stripped)
                    break
            else:
                log_lines.append(stripped)
        if log_lines:
            out = "\n".join(log_lines)
            self.root.after(0, lambda t=out: self._log(t, "recv"))

    # ------------------------------------------------------------ LED --

    def _flash_led(self):
        # Cancel any pending dim so rapid LCM updates don't stack orphaned timers.
        if self._led_dim_id:
            self.root.after_cancel(self._led_dim_id)
        self._led_canvas.itemconfig(self._led_oval, fill="#00e040", outline="#00ff60")
        self._led_dim_id = self.root.after(120, self._dim_led)

    def _dim_led(self):
        self._led_canvas.itemconfig(self._led_oval, fill="#606060", outline="#404040")
        self._led_dim_id = None

    # --------------------------------------------------- Power state --

    def _on_power_on(self):
        self.btn_rmt_power.config(fg="blue")

    def _on_power_off(self):
        self.btn_rmt_power.config(fg="red")
        self._update_lcd(" " * 16, " " * 16)

    # --------------------------------------------------------- Send --

    def _send_cmd(self, cmd: str):
        if not self.connected:
            return
        self._enqueue_cmd(cmd.encode() + b"\r\n")
        # Cancel any pending refresh from a previous press, then reschedule
        if self._lcm_refresh_id:
            self.root.after_cancel(self._lcm_refresh_id)
        if self._pwr_refresh_id:
            self.root.after_cancel(self._pwr_refresh_id)
        self._lcm_refresh_id = self.root.after(100, self._trigger_lcm_refresh)
        self._pwr_refresh_id = self.root.after(200, self._trigger_pwr_refresh)

    def _trigger_lcm_refresh(self):
        self._lcm_refresh_id = None
        if self.connected:
            self._poll_lcm()

    def _trigger_pwr_refresh(self):
        self._pwr_refresh_id = None
        if self.connected:
            self._poll_pwr()

    def _poll_lcm(self):
        self._enqueue_cmd(CMDS["get_lcm"].encode() + b"\r\n")

    def _poll_pwr(self):
        self._enqueue_cmd(CMDS["get_pwr"].encode() + b"\r\n")

    def _send_custom(self):
        cmd = self.custom_cmd.get().strip()
        if cmd:
            self._send_cmd(cmd)
            self.custom_cmd.set("")


def main():
    root = tk.Tk()
    SSHApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
