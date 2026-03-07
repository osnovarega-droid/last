import json
import os
import queue
import re
import subprocess
import uuid
import hashlib
import sys
import base64
import time
import rsa
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import customtkinter
import requests
from Managers.AccountsManager import AccountManager
from Managers.LogManager import LogManager
from Managers.SettingsManager import SettingsManager


customtkinter.set_appearance_mode("Dark")
customtkinter.set_default_color_theme("blue")

BG_MAIN = "#0b1020"
BG_PANEL = "#121a30"
BG_CARD = "#151d34"
BG_CARD_ALT = "#10182d"
BG_BORDER = "#242d48"
TXT_MAIN = "#e9edf7"
TXT_MUTED = "#8f9bb8"
TXT_SOFT = "#b8c2df"
ACCENT_BLUE = "#2f6dff"
ACCENT_BLUE_DARK = "#214ebe"
ACCENT_GREEN = "#1f9d55"
ACCENT_RED = "#c83a4a"
ACCENT_PURPLE = "#252b4f"
ACCENT_ORANGE = "#ff9500"

LICENSE_SERVER_URL = "http://77.91.96.154"
LICENSE_PUBLIC_KEY_PATH = Path("settings/license_public_key.pem")
LICENSE_EMBEDDED_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvNaTMWsTGK8T0Vt0T5ea
YOHBJmLjIIArrd2RMeQ4Cdx+RWOJxR/o5VWjLB1SPhH13r0UONb1m9KgHozQjYWj
TwM28lDr7lTWBKP1+N74Fdneb4E43WTifRiSnIjR2MbSJLDrWgkbOcqFHvk6nUlV
TLR+LM/AF2z5/S1CkDCcAg45ixIYXrBJB1sMjP2nv6OqSr3DLugSFREMAWG6n2lC
CIH7SOA4o8D88FHEVANm5rcseeMq9LND9z7aOJ+CEdxyjN8lb+CZ9xGKGl/8+UG+
1uUIB2UqX1RuowIL3xLi7T5hTh0rGNP58tQhv5Y/6DjiZM11CAnhxWa1BRiCXMlK
rwIDAQAB
-----END PUBLIC KEY-----"""
LICENSE_CACHE_PATH = Path("settings/license_cache.json")
LICENSE_TOKEN_TTL_GRACE_SECONDS = 300
LICENSE_RECHECK_INTERVAL_MS = 60000
LICENSE_REQUEST_TIMEOUT = (3, 8)
LICENSE_WATCHDOG_TIMEOUT_MS = 25000
MAX_TOKEN_TTL_SECONDS = 3600
LICENSE_CHALLENGE_TTL_SECONDS = 30

REGION_PING_TARGETS = {}
WEEKLY_RESET_WEEKDAY = 2  # Wednesday
WEEKLY_RESET_HOUR = 3


class SteamRouteManager:
    """Manages Windows Firewall rules for Steam SDR regional routing."""

    PREFIX = "FSN_Route_"

    def __init__(self):
        pass

    def _run_netsh(self, cmd_args):
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall"] + cmd_args,
                capture_output=True,
                check=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return True
        except Exception:
            return False

    def add_block_rule(self, region_name, ips):
        if ips:
            packed_ips = ",".join(ips)
            return self._run_netsh(
                ["add", "rule", f"name={self.PREFIX}{region_name}", "dir=out", "action=block", f"remoteip={packed_ips}"]
            )
        return False

    def remove_rule(self, region_name):
        return self._run_netsh(["delete", "rule", f"name={self.PREFIX}{region_name}"])

    def full_cleanup(self):
        try:
            cmd = f'Remove-NetFirewallRule -Name "{self.PREFIX}*" -ErrorAction SilentlyContinue'
            subprocess.run(["powershell", "-Command", cmd], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except Exception:
            pass

    def get_blocked_regions(self):
        try:
            cmd = (
                f'Get-NetFirewallRule -DisplayName "{self.PREFIX}*" -ErrorAction SilentlyContinue '
                "| Select-Object -ExpandProperty DisplayName"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
                capture_output=True,
                text=True,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

            if result.returncode != 0:
                cmd = (
                    f'Get-NetFirewallRule -Name "{self.PREFIX}*" -ErrorAction SilentlyContinue '
                    "| Select-Object -ExpandProperty Name"
                )
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
                    capture_output=True,
                    text=True,
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )

            if result.returncode != 0:
                return set()

            blocked_regions = set()
            for line in (result.stdout or "").splitlines():
                rule_name = line.strip()
                if not rule_name.startswith(self.PREFIX):
                    continue
                blocked_regions.add(rule_name[len(self.PREFIX) :])
            return blocked_regions
        except Exception:
            return set()


class App(customtkinter.CTk):
    def __init__(self, gsi_manager=None, startup_gpu_info=None):
        super().__init__()
        self.title("Goose Panel | v.4.0.3")
        self.gsi_manager = gsi_manager
        self.window_position_file = Path("window_position.txt")
        self.executor = ThreadPoolExecutor(max_workers=8)
        self.runtime_poll_in_flight = False
        self.ping_refresh_in_flight = False
        self._ui_actions_queue = queue.SimpleQueue()
        self._pending_section = None
        self._section_switch_job = None

        self.is_unlocked = False
        self.license_token = None
        self.license_exp = 0
        self.license_nonce = None
        self.license_challenge_id = None
        self.license_challenge_exp = 0
        self._license_check_in_flight = False
        self._background_license_check_in_flight = False
        self.http_session = requests.Session()
        self.http_session.trust_env = False  # игнорировать системные прокси/ENV (очень часто именно они ломают)
        self.http_session.verify = True  # для http:// не влияет, но не мешает

        self.geometry("1100x600")
        self.minsize(1100, 600)
        self.maxsize(1100, 600)
        self.configure(fg_color=BG_MAIN)
        self._load_window_position()

        base_path = Path(sys._MEIPASS) if hasattr(sys, "_MEIPASS") else Path(__file__).parent.parent
        icon_path = Path(base_path) / "Icon1.ico"
        if icon_path.exists():
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass

        self.account_manager = AccountManager()
        self.log_manager = LogManager()
        self.settings_manager = SettingsManager()
        self.account_row_items = []
        self.account_badges = {}
        self.sdr_regions = {}
        self._level_file_mtime = None
        self.lobby_buttons = {}

        self._build_srt_state()
        self._load_region_json_if_exists()

        # ВАЖНО: сначала создаём legacy контроллеры (accounts_list нужен для functional UI)
        self._create_hidden_legacy_controllers()
        self._build_layout()

        self._connect_gsi_to_ui()
        self._log_startup_gpu_info(startup_gpu_info)

        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.show_section("license")
        self._start_ui_actions_pump()
        self._start_runtime_status_tracking()
        self.after(LICENSE_RECHECK_INTERVAL_MS, self._start_background_check)

    # ---------------- UI queue / async ----------------
    def _start_ui_actions_pump(self):
        def pump():
            try:
                while True:
                    action = self._ui_actions_queue.get_nowait()
                    action()
            except queue.Empty:
                pass
            except Exception:
                pass
            finally:
                if self.winfo_exists():
                    self.after(50, pump)

        self.after(50, pump)

    def _queue_ui_action(self, action):
        try:
            self._ui_actions_queue.put(action)
        except Exception:
            pass

    def _run_action_async(self, fn, done_callback=None):
        try:
            future = self.executor.submit(fn)
        except Exception as exc:
            if self.winfo_exists():
                self.after(0, lambda: self.log_manager.add_log(f"❌ executor.submit failed: {exc}"))
            raise

        def on_done(done_future):
            if not done_callback:
                return
            try:
                self._queue_ui_action(lambda: done_callback(done_future))
            except Exception as exc:
                try:
                    self._queue_ui_action(lambda: self.log_manager.add_log(f"❌ done_callback scheduling failed: {exc}"))
                except Exception:
                    pass

        future.add_done_callback(on_done)
        return future

    def _safe_ui_refresh(self):
        if not self.winfo_exists():
            return
        self._sync_switches_with_selection()
        self._update_accounts_info()

    # ---------------- Legacy controllers ----------------
    def _create_hidden_legacy_controllers(self):
        self.legacy_host = customtkinter.CTkFrame(self, fg_color="transparent")

        self.accounts_list = AccountsListFrame(self.legacy_host)
        self.accounts_control = AccountsControl(self.legacy_host, self.update_label, self.accounts_list)
        self.control_frame = ControlFrame(self.legacy_host)
        self.main_menu = MainMenu(self.legacy_host)
        self.config_tab = ConfigTab(self.legacy_host)

        for widget in [self.accounts_list, self.accounts_control, self.control_frame, self.main_menu, self.config_tab]:
            widget.grid_remove()

        self.control_frame.set_accounts_list_frame(self.accounts_list)
        self.accounts_list.set_control_frame(self.control_frame)

    # ---------------- Layout ----------------
    def _build_layout(self):
        # страховка, чтобы functional секция не упала
        if not hasattr(self, "accounts_list"):
            self._create_hidden_legacy_controllers()

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = customtkinter.CTkFrame(
            self,
            width=200,
            corner_radius=1,
            fg_color=BG_PANEL,
            border_width=1,
            border_color=BG_BORDER,
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew", padx=(1, 1), pady=1)
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_rowconfigure(7, weight=1)

        customtkinter.CTkLabel(
            self.sidebar,
            text="    Goose Panel  ",
            font=customtkinter.CTkFont(size=20, weight="bold"),
            text_color=TXT_MAIN,
        ).grid(row=0, column=0, padx=10, pady=(10, 4), sticky="w")

        self.nav_buttons = {}
        nav_items = [("functional", "Functionals"), ("config", "Configurations"), ("license", "License"), ("stats", "Accs Statistic")]
        for idx, (key, text) in enumerate(nav_items, start=1):
            btn = customtkinter.CTkButton(
                self.sidebar,
                text=text,
                width=150,
                height=34,
                corner_radius=9,
                font=customtkinter.CTkFont(size=12, weight="bold"),
                fg_color=BG_CARD_ALT,
                hover_color=BG_CARD,
                text_color=TXT_MAIN,
                border_width=1,
                border_color=ACCENT_RED,
                command=lambda k=key: self.show_section(k),
            )
            btn.grid(row=idx, column=0, padx=24, pady=4)
            self.nav_buttons[key] = btn

        logs_wrap = customtkinter.CTkFrame(
            self.sidebar,
            width=197,
            fg_color=BG_CARD_ALT,
            corner_radius=1,
            border_width=1,
            border_color=BG_BORDER,
        )
        logs_wrap.grid(row=7, column=0, padx=2, pady=(2, 2), sticky="nsew")
        logs_wrap.grid_propagate(False)
        logs_wrap.grid_columnconfigure(0, weight=1)
        logs_wrap.grid_rowconfigure(1, weight=1)

        customtkinter.CTkLabel(
            logs_wrap,
            text="• Logs",
            text_color=TXT_MAIN,
            font=customtkinter.CTkFont(size=15, weight="bold"),
        ).grid(row=0, column=0, padx=8, pady=(6, 2), sticky="w")

        self.logs_box = customtkinter.CTkTextbox(
            logs_wrap,
            width=250,
            fg_color="#0e1428",
            text_color="#98a7cf",
            border_width=0,
            corner_radius=8,
            wrap="word",
            font=customtkinter.CTkFont(size=11),
        )
        self.logs_box.grid(row=1, column=0, padx=2, pady=(0, 2), sticky="nsew")
        self.log_manager.textbox = self.logs_box

        self.content = customtkinter.CTkFrame(
            self,
            fg_color=BG_PANEL,
            corner_radius=12,
            border_width=1,
            border_color=BG_BORDER,
        )
        self.content.grid(row=0, column=1, padx=(6, 10), pady=10, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self.sections = {
            "functional": self._build_functional_section(self.content),
            "config": self._build_config_section(self.content),
            "license": self._build_license_section(self.content),
            "stats": self._build_stats_section(self.content),
        }

    def _run_hidden_cmd(self, cmd, check=False):
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

    # ---------------- Reset proxy/firewall ----------------
    def _reset_windows_proxy(self):
        if not sys.platform.startswith("win"):
            self.log_manager.add_log("⚠️ Reset доступен только на Windows")
            return

        self.log_manager.add_log("🔄 Reset: сброс proxy...")

        commands = [
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                'Remove-NetFirewallRule -Name "FSN_Route_*" -ErrorAction SilentlyContinue; '
                'Get-NetFirewallRule -DisplayName "FSN_Route_*" -ErrorAction SilentlyContinue | '
                "Remove-NetFirewallRule -ErrorAction SilentlyContinue",
            ],
            ["netsh", "advfirewall", "firewall", "delete", "rule", "name=FSN_Route_*"],
            ["netsh", "winhttp", "reset", "proxy"],
            ["reg", "add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"],
            ["reg", "add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "/v", "ProxyServer", "/t", "REG_SZ", "/d", "", "/f"],
            ["reg", "delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "/v", "AutoConfigURL", "/f"],
            ["reg", "add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "/v", "AutoDetect", "/t", "REG_DWORD", "/d", "1", "/f"],
            ["reg", "add", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"],
            ["reg", "add", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "/v", "ProxyServer", "/t", "REG_SZ", "/d", "", "/f"],
            ["reg", "delete", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "/v", "AutoConfigURL", "/f"],
            ["rundll32.exe", "inetcpl.cpl,ClearMyTracksByProcess", "8"],
            ["ipconfig", "/flushdns"],
        ]

        command_errors = []
        for cmd in commands:
            try:
                result = self._run_hidden_cmd(cmd, check=False)
                if result.returncode != 0:
                    command_errors.append(" ".join(cmd[:3]))
            except Exception:
                command_errors.append(" ".join(cmd[:3]))

        try:
            verify = self._run_hidden_cmd(["netsh", "winhttp", "show", "proxy"], check=False)
            verify_text = ((verify.stdout or "") + "\n" + (verify.stderr or "")).lower()
        except Exception:
            verify_text = ""

        direct_markers = ("direct access", "прямой доступ", "without proxy", "без прокси", "no proxy server", "нет прокси")
        has_proxy_markers = ("proxy server", "прокси-сервер", "proxy-server")

        is_direct = any(marker in verify_text for marker in direct_markers)
        if not is_direct and verify_text:
            is_direct = not any(marker in verify_text for marker in has_proxy_markers)

        if is_direct:
            self.log_manager.add_log("✅ Reset завершен: proxy очищен")
        elif command_errors:
            self.log_manager.add_log("⚠️ Reset частично выполнен: запустите от администратора для полного сброса")
        else:
            self.log_manager.add_log("⚠️ Reset выполнен, но WinHTTP не подтвердил direct mode")

    # ---------------- Functional section ----------------
    def _build_functional_section(self, parent):
        frame = customtkinter.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        top = customtkinter.CTkFrame(frame, fg_color="transparent")
        top.grid(row=0, column=0, padx=10, pady=(8, 6), sticky="ew")

        title_frame = customtkinter.CTkFrame(top, fg_color="transparent")
        title_frame.grid(row=0, column=0, sticky="w")

        customtkinter.CTkLabel(
            title_frame,
            text="Accounts",
            text_color=TXT_MAIN,
            font=customtkinter.CTkFont(size=24, weight="bold"),
        ).grid(row=0, column=0, padx=(0, 10))

        self.accounts_info = customtkinter.CTkLabel(
            title_frame,
            text="0 accounts • 0 selected • 0 launched",
            text_color=TXT_MUTED,
            font=customtkinter.CTkFont(size=12),
        )
        self.accounts_info.grid(row=0, column=1)

        search_wrap = customtkinter.CTkFrame(title_frame, fg_color="transparent")
        search_wrap.grid(row=0, column=2, padx=(14, 0), sticky="w")
        self.search_var = customtkinter.StringVar()
        self.search_var.trace_add("write", lambda *_: self._apply_account_filter())

        customtkinter.CTkEntry(
            search_wrap,
            textvariable=self.search_var,
            placeholder_text="Search",
            width=220,
            height=32,
            fg_color=BG_CARD,
            border_color=BG_BORDER,
            text_color=TXT_MAIN,
        ).grid(row=0, column=0)

        actions = customtkinter.CTkFrame(frame, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BG_BORDER)
        actions.grid(row=1, column=0, padx=10, pady=(0, 8), sticky="ew")
        for i in range(4):
            actions.grid_columnconfigure(i, weight=1)

        common_btn = {"height": 34, "font": customtkinter.CTkFont(size=12, weight="bold")}
        customtkinter.CTkButton(actions, text="Launch Selected", command=self._action_start_selected, fg_color=ACCENT_BLUE, hover_color=ACCENT_BLUE_DARK, **common_btn).grid(row=0, column=0, padx=6, pady=8, sticky="ew")
        customtkinter.CTkButton(actions, text="Select 4 accs", command=self._action_select_first_4, fg_color=ACCENT_PURPLE, hover_color="#313866", **common_btn).grid(row=0, column=1, padx=6, pady=8, sticky="ew")
        customtkinter.CTkButton(actions, text="Select all accs", command=self._action_select_all_toggle, fg_color=BG_CARD_ALT, hover_color=BG_BORDER, **common_btn).grid(row=0, column=2, padx=6, pady=8, sticky="ew")
        customtkinter.CTkButton(actions, text="Kill selected", command=self._action_kill_selected, fg_color=BG_CARD_ALT, hover_color=BG_BORDER, **common_btn).grid(row=0, column=3, padx=6, pady=8, sticky="ew")

        main = customtkinter.CTkFrame(frame, fg_color="transparent")
        main.grid(row=2, column=0, padx=10, pady=(0, 8), sticky="nsew")
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=1)
        main.grid_columnconfigure(2, weight=1)
        main.grid_rowconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=0)

        accounts_block = customtkinter.CTkFrame(main, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BG_BORDER)
        accounts_block.grid(row=0, column=0, rowspan=2, padx=(0, 6), pady=0, sticky="nsew")
        accounts_block.grid_rowconfigure(1, weight=1)
        accounts_block.grid_columnconfigure(0, weight=1)
        customtkinter.CTkLabel(accounts_block, text="Accounts", font=customtkinter.CTkFont(size=20, weight="bold"), text_color=TXT_MAIN).grid(row=0, column=0, padx=10, pady=8, sticky="w")

        self.accounts_scroll = customtkinter.CTkScrollableFrame(accounts_block, fg_color=BG_CARD_ALT)
        self.accounts_scroll.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="nsew")
        self.accounts_scroll.grid_columnconfigure(0, weight=1)
        self._create_account_rows()

        self.srt_placeholder = customtkinter.CTkFrame(main, width=260, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BG_BORDER)
        self.srt_placeholder.grid(row=0, column=1, padx=6, pady=0, sticky="nsew")
        self.srt_placeholder.grid_propagate(False)
        self.srt_placeholder.grid_rowconfigure(2, weight=1)
        self.srt_placeholder.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(self.srt_placeholder, text="Steam Route Tool", text_color="#2ee66f", font=customtkinter.CTkFont(size=14, weight="bold")).grid(row=0, column=0, padx=8, pady=(8, 3), sticky="w")

        actions_bar = customtkinter.CTkFrame(self.srt_placeholder, fg_color="transparent")
        actions_bar.grid(row=1, column=0, padx=8, pady=(0, 4), sticky="ew")
        actions_bar.grid_columnconfigure((0, 1), weight=1)

        customtkinter.CTkButton(actions_bar, text="Block all", fg_color=ACCENT_RED, hover_color="#962c38", height=28, command=self._srt_block_all, font=customtkinter.CTkFont(size=11, weight="bold")).grid(row=0, column=0, padx=(0, 4), sticky="ew")
        customtkinter.CTkButton(actions_bar, text="Reset", fg_color=BG_CARD_ALT, hover_color=BG_BORDER, height=28, command=self._srt_reset, font=customtkinter.CTkFont(size=11, weight="bold")).grid(row=0, column=1, padx=(4, 0), sticky="ew")

        self.srt_scroll = customtkinter.CTkScrollableFrame(self.srt_placeholder, fg_color=BG_CARD_ALT, corner_radius=8)
        self.srt_scroll.grid(row=2, column=0, padx=8, pady=(0, 8), sticky="nsew")
        self.srt_scroll.grid_columnconfigure(0, weight=1)
        self._build_srt_rows()

        tools = customtkinter.CTkFrame(main, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BG_BORDER)
        tools.grid(row=0, column=2, padx=(6, 0), pady=0, sticky="nsew")
        tools.grid_columnconfigure(0, weight=1)
        customtkinter.CTkLabel(tools, text="Extra Tools", text_color=TXT_MAIN, font=customtkinter.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=8, pady=(8, 6), sticky="w")
        extra_buttons = [
            ("Move all CS windows", self._action_move_all_cs_windows, BG_CARD_ALT),
            ("Kill ALL CS & Steam", self._action_kill_all_cs_and_steam, ACCENT_PURPLE),
            ("Send trade", self._action_send_trade_selected, ACCENT_GREEN),
            ("Settings trade", self._action_open_looter_settings, ACCENT_RED),
            ("Marked farmed", self._action_marked_farmer, ACCENT_ORANGE),
            ("Launch BES", self._action_launch_bes, BG_CARD_ALT),
        ]
        for idx, (text, cmd, color) in enumerate(extra_buttons, start=1):
            customtkinter.CTkButton(tools, text=text, command=cmd, fg_color=color, hover_color=BG_BORDER, height=34, font=customtkinter.CTkFont(size=11, weight="bold")).grid(row=idx, column=0, padx=8, pady=4, sticky="ew")

        lobby = customtkinter.CTkFrame(main, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BG_BORDER)
        lobby.grid(row=1, column=1, columnspan=2, padx=(6, 0), pady=(0, 0), sticky="ew")
        customtkinter.CTkLabel(lobby, text="Lobby Management", text_color=TXT_MAIN, font=customtkinter.CTkFont(size=13, weight="bold")).grid(row=0, column=0, columnspan=2, padx=8, pady=(8, 4), sticky="w")
        for i in range(2):
            lobby.grid_columnconfigure(i, weight=1)

        lobby_buttons = [
            ("Make Lobbies", self._action_make_lobbies, BG_CARD_ALT),
            ("Make Lobbies & Search Game", self._action_make_lobbies_and_search, ACCENT_BLUE),
            ("Disband lobbies", self._action_disband_lobbies, BG_CARD_ALT),
            ("Get level", self._action_try_get_level, BG_CARD_ALT),
            ("Shuffle Lobbies", self._action_shuffle_lobbies, BG_CARD_ALT),
            ("Get wingman rank", self._action_try_get_wingman_rank, BG_CARD_ALT),
        ]
        for idx, (text, cmd, color) in enumerate(lobby_buttons):
            r, c = divmod(idx, 2)
            btn = customtkinter.CTkButton(
                lobby,
                text=text,
                command=cmd,
                fg_color=color,
                hover_color=BG_BORDER,
                height=32,
                font=customtkinter.CTkFont(size=11, weight="bold"),
            )
            btn.grid(row=r + 1, column=c, padx=6, pady=4, sticky="ew")
            self.lobby_buttons[text] = btn

        self._update_accounts_info()
        return frame

    def _create_account_rows(self):
        self.account_row_items.clear()
        levels_cache = getattr(self.accounts_list, "levels_cache", {})

        for idx, account in enumerate(self.account_manager.accounts):
            row = customtkinter.CTkFrame(self.accounts_scroll, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BG_BORDER)
            row.grid(row=idx, column=0, padx=4, pady=3, sticky="ew")
            row.grid_columnconfigure(1, weight=1)

            sw = customtkinter.CTkSwitch(
                row,
                text="",
                width=24,
                command=lambda a=account: self._toggle_account(a),
                fg_color="#2d3b60",
                progress_color=ACCENT_BLUE,
            )
            sw.grid(row=0, column=0, rowspan=2, padx=(6, 5), pady=6, sticky="w")
            if account in self.account_manager.selected_accounts:
                sw.select()

            lvl_data = levels_cache.get(account.login, {})
            level_text = lvl_data.get("level", "-")
            xp_text = lvl_data.get("xp", "-")

            level_label = customtkinter.CTkLabel(row, text=f"lvl: {level_text} | xp: {xp_text}", anchor="w", text_color=TXT_MUTED, font=customtkinter.CTkFont(size=11))
            level_label.grid(row=1, column=1, padx=3, pady=(0, 5), sticky="w")

            badge = customtkinter.CTkLabel(
                row,
                text="Idle week",
                text_color="#dbe8ff",
                font=customtkinter.CTkFont(size=10),
                fg_color=ACCENT_BLUE,
                corner_radius=8,
                width=78,
                height=20,
            )
            badge.grid(row=0, column=2, rowspan=2, padx=6, pady=6)

            login_label = customtkinter.CTkLabel(row, text=account.login, anchor="w", text_color=TXT_MAIN, font=customtkinter.CTkFont(size=12, weight="bold"))
            login_label.grid(row=0, column=1, padx=3, pady=(5, 0), sticky="w")

            account.setColorCallback(lambda color, a=account: self._handle_account_color_change(a, color))
            self.account_badges[account.login] = badge

            self.account_row_items.append(
                {
                    "row": row,
                    "account": account,
                    "login_lower": account.login.lower(),
                    "switch": sw,
                    "login_label": login_label,
                    "level_label": level_label,
                    "badge": badge,
                }
            )
            self._refresh_account_badge(account)

    def _refresh_level_labels(self):
        try:
            if hasattr(self.accounts_list, "_load_levels_from_json"):
                self.accounts_list.levels_cache = self.accounts_list._load_levels_from_json()
            levels_cache = getattr(self.accounts_list, "levels_cache", {}) or {}
            levels_cache_lower = {str(k).lower(): v for k, v in levels_cache.items()}
            for item in self.account_row_items:
                login = item["account"].login
                lvl_data = levels_cache.get(login, levels_cache_lower.get(str(login).lower(), {}))
                level_text = lvl_data.get("level", "-")
                xp_text = lvl_data.get("xp", "-")
                item["level_label"].configure(text=f"lvl: {level_text} | xp: {xp_text}")
        except Exception:
            pass

    def _refresh_level_labels_if_changed(self):
        try:
            level_path = Path("level.json")
            mtime = level_path.stat().st_mtime if level_path.exists() else None
            if mtime != self._level_file_mtime:
                self._level_file_mtime = mtime
                self._refresh_level_labels()
        except Exception:
            pass

    def _normalize_account_color(self, color):
        color_map = {"green": ACCENT_GREEN, "yellow": "#f5c542", "white": "#DCE4EE"}
        return color_map.get(str(color).lower(), color)

    def _handle_account_color_change(self, account, color):
        normalized = self._normalize_account_color(color)

        def apply_change():
            for item in self.account_row_items:
                if item["account"] is account:
                    item["login_label"].configure(text_color=normalized)
                    break
            self._refresh_account_badge(account)
            self._update_accounts_info()

        self._queue_ui_action(apply_change)

    def _refresh_account_badge(self, account, is_running=None):
        for item in self.account_row_items:
            if item["account"] is not account:
                continue
            badge_text, badge_color = self._get_weekly_badge_status(account)
            item["badge"].configure(text=badge_text, fg_color=badge_color)
            return

    def _get_weekly_window_start(self, now=None):
        current_time = now or datetime.now()
        reset_anchor = current_time.replace(hour=WEEKLY_RESET_HOUR, minute=0, second=0, microsecond=0)
        days_since_reset = (current_time.weekday() - WEEKLY_RESET_WEEKDAY) % 7
        week_start = reset_anchor - timedelta(days=days_since_reset)
        if current_time < week_start:
            week_start -= timedelta(days=7)
        return week_start

    def _get_weekly_badge_status(self, account):
        levels_cache = getattr(self.accounts_list, "levels_cache", {}) or {}
        account_data = levels_cache.get(account.login, {})
        if not isinstance(account_data, dict):
            account_data = {}

        now = datetime.now()
        week_start = self._get_weekly_window_start(now)
        week_start_iso = week_start.isoformat()
        should_persist = False

        if account_data.get("weekly_baseline_start") != week_start_iso:
            account_data["weekly_baseline_start"] = week_start_iso
            level_value = account_data.get("level")
            account_data["weekly_baseline_level"] = level_value if isinstance(level_value, int) else None
            account_data.pop("trade_sent_week_start", None)
            should_persist = True

        if should_persist:
            levels_cache[account.login] = account_data
            self.accounts_list.levels_cache = levels_cache
            if hasattr(self.accounts_list, "_save_levels_to_json"):
                self.accounts_list._save_levels_to_json()

        if account_data.get("trade_sent_week_start") == week_start_iso:
            return "Sent trade", ACCENT_ORANGE

        current_level = account_data.get("level")
        baseline_level = account_data.get("weekly_baseline_level")
        if isinstance(current_level, int) and isinstance(baseline_level, int) and current_level >= baseline_level + 1:
            return "Take drop", ACCENT_GREEN

        return "Idle week", ACCENT_BLUE

    def _refresh_all_runtime_states(self):
        for item in self.account_row_items:
            account = item["account"]
            current_color = self._normalize_account_color(getattr(account, "_color", TXT_MAIN))
            item["login_label"].configure(text_color=current_color)
        self._sync_switches_with_selection()
        self._update_accounts_info()

    def _start_runtime_status_tracking(self):
        def poll():
            try:
                self._refresh_all_runtime_states()
                self._refresh_level_labels_if_changed()
                for item in self.account_row_items:
                    self._refresh_account_badge(item["account"])
            except Exception:
                self.runtime_poll_in_flight = False
            finally:
                if self.winfo_exists():
                    self.after(1500, poll)

        self.after(500, poll)

    def _apply_account_filter(self):
        filter_text = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""
        render_idx = 0
        for item in self.account_row_items:
            show = not filter_text or filter_text in item["login_lower"]
            if show:
                item["row"].grid(row=render_idx, column=0, padx=4, pady=3, sticky="ew")
                render_idx += 1
            else:
                item["row"].grid_remove()

    def _toggle_account(self, account):
        if account in self.account_manager.selected_accounts:
            self.account_manager.selected_accounts.remove(account)
        else:
            self.account_manager.selected_accounts.append(account)
        self._safe_ui_refresh()

    def _sync_switches_with_selection(self):
        selected = set(self.account_manager.selected_accounts)
        for item in self.account_row_items:
            if item["account"] in selected:
                item["switch"].select()
            else:
                item["switch"].deselect()

    def _update_accounts_info(self):
        total = len(self.account_manager.accounts)
        selected = len(self.account_manager.selected_accounts)
        launched = self.account_manager.count_launched_accounts()
        if hasattr(self, "accounts_info"):
            self.accounts_info.configure(text=f"{total} accounts • {selected} selected • {launched} launched")

    # ---------------- Config section ----------------
    def _build_config_section(self, parent):
        frame = customtkinter.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)

        header = customtkinter.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, padx=12, pady=(10, 4), sticky="ew")
        customtkinter.CTkLabel(header, text="Configurations", font=customtkinter.CTkFont(size=24, weight="bold"), text_color=TXT_MAIN).grid(row=0, column=0, sticky="w")
        customtkinter.CTkLabel(header, text="Настройте автологику и пути Steam/CS2 в одном месте", font=customtkinter.CTkFont(size=11), text_color=TXT_MUTED).grid(row=1, column=0, pady=(4, 0), sticky="w")

        card = customtkinter.CTkFrame(frame, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BG_BORDER)
        card.grid(row=1, column=0, padx=12, pady=(0, 8), sticky="nsew")
        card.grid_columnconfigure(0, weight=1, minsize=150)
        card.grid_columnconfigure(1, weight=2, minsize=150)

        switches_card = customtkinter.CTkFrame(card, fg_color=BG_CARD_ALT, corner_radius=10, border_width=1, border_color=BG_BORDER)
        switches_card.grid(row=0, column=0, padx=(8, 4), pady=8, sticky="nsew")
        switches_card.grid_columnconfigure(0, weight=1)
        customtkinter.CTkLabel(switches_card, text="Automation", text_color=TXT_MAIN, font=customtkinter.CTkFont(size=15, weight="bold")).grid(row=0, column=0, padx=10, pady=(8, 2), sticky="w")

        self.config_toggle_auto_accept = self._create_labeled_switch(
            switches_card,
            row=1,
            title="Auto accept game",
            description="Автоматически принимает матч.",
            setting_key="AutoAcceptEnabled",
            on_toggle=self._on_auto_accept_toggle,
            default=True,
        )
        self.config_toggle_auto_match = self._create_labeled_switch(
            switches_card,
            row=2,
            title="Auto match in start",
            description="После 4 окон CS2 ждёт 25с и начинает игру.",
            setting_key="AutoMatchInStartEnabled",
            default=True,
        )
        self.config_toggle_auto_account_switching = self._create_labeled_switch(
            switches_card,
            row=3,
            title="Automatic account switching",
            description="Автоматическая смена аккаунтов после отфарма",
            setting_key="AutomaticAccountSwitchingEnabled",
            default=True,
        )

        paths_card = customtkinter.CTkFrame(card, fg_color=BG_CARD_ALT, corner_radius=10, border_width=1, border_color=BG_BORDER)
        paths_card.grid(row=0, column=1, padx=(4, 8), pady=8, sticky="nsew")
        paths_card.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(paths_card, text="Steam / CS2 paths", text_color=TXT_MAIN, font=customtkinter.CTkFont(size=15, weight="bold")).grid(row=0, column=0, padx=10, pady=(8, 2), sticky="w")

        self.path_status = {}
        self.path_entries = {}
        self._create_path_input(
            paths_card,
            row=1,
            label="Steam path",
            key="SteamPath",
            placeholder="C:/Program Files (x86)/Steam/steam.exe",
            validator=lambda value: Path(value).is_file() and value.lower().endswith(".exe"),
        )
        self._create_path_input(
            paths_card,
            row=2,
            label="CS2 path",
            key="CS2Path",
            placeholder="C:/Program Files (x86)/Steam/steamapps/common/Counter-Strike Global Offensive",
            validator=lambda value: (Path(value) / "game" / "bin" / "win64" / "cs2.exe").is_file(),
        )

        self.config_status_label = customtkinter.CTkLabel(frame, text="", text_color=TXT_MUTED, font=customtkinter.CTkFont(size=11, weight="bold"))
        self.config_status_label.grid(row=2, column=0, padx=14, pady=(0, 2), sticky="e")

        frame.grid_rowconfigure(1, weight=1)
        return frame

    def _create_labeled_switch(self, parent, row, title, description, setting_key, default=False, on_toggle=None):
        row_wrap = customtkinter.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BG_BORDER)
        row_wrap.grid(row=row, column=0, padx=8, pady=5, sticky="ew")
        row_wrap.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(row_wrap, text=title, text_color=TXT_MAIN, font=customtkinter.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=10, pady=(7, 0), sticky="w")
        customtkinter.CTkLabel(row_wrap, text=description, text_color=TXT_SOFT, font=customtkinter.CTkFont(size=10)).grid(row=1, column=0, padx=10, pady=(2, 6), sticky="w")

        switch_wrap = customtkinter.CTkFrame(row_wrap, fg_color="transparent")
        switch_wrap.grid(row=2, column=0, padx=10, pady=(0, 6), sticky="w")
        customtkinter.CTkLabel(switch_wrap, text="OFF", text_color=TXT_MUTED, font=customtkinter.CTkFont(size=10, weight="bold")).grid(row=0, column=0, padx=(0, 4))

        switch = customtkinter.CTkSwitch(switch_wrap, text="", width=44)
        switch.grid(row=0, column=1)
        customtkinter.CTkLabel(switch_wrap, text="ON", text_color=TXT_MAIN, font=customtkinter.CTkFont(size=10, weight="bold")).grid(row=0, column=2, padx=(4, 0))

        current_value = bool(self.settings_manager.get(setting_key, default))
        if current_value:
            switch.select()
        else:
            switch.deselect()

        def handle_toggle():
            value = bool(switch.get())
            self.settings_manager.set(setting_key, value)
            if on_toggle:
                on_toggle(value)

        switch.configure(command=handle_toggle)
        return switch

    def _create_path_input(self, parent, row, label, key, placeholder, validator):
        wrap = customtkinter.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BG_BORDER)
        wrap.grid(row=row, column=0, padx=8, pady=5, sticky="ew")
        wrap.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(wrap, text=label, text_color=TXT_MAIN, font=customtkinter.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=10, pady=(7, 2), sticky="w")
        entry = customtkinter.CTkEntry(wrap, placeholder_text=placeholder, fg_color=BG_CARD_ALT, border_color=BG_BORDER, text_color=TXT_MAIN)
        entry.grid(row=1, column=0, padx=10, pady=(0, 6), sticky="ew")

        saved_path = self.settings_manager.get(key, "") or ""
        entry.insert(0, saved_path)

        status = customtkinter.CTkLabel(wrap, text="", font=customtkinter.CTkFont(size=20, weight="bold"), text_color=ACCENT_GREEN)
        status.grid(row=1, column=1, padx=(0, 8), pady=(0, 6), sticky="e")

        def save_path():
            value = entry.get().strip()
            if not value:
                status.configure(text="✖", text_color=ACCENT_RED)
                self.config_status_label.configure(text=f"{label}: путь пустой", text_color=ACCENT_RED)
                return

            self.settings_manager.set(key, value)
            if validator(value):
                status.configure(text="✔", text_color=ACCENT_GREEN)
                self.config_status_label.configure(text=f"{label}: сохранено", text_color=ACCENT_GREEN)
            else:
                status.configure(text="✖", text_color=ACCENT_RED)
                self.config_status_label.configure(text=f"{label}: путь невалидный", text_color=ACCENT_RED)

        customtkinter.CTkButton(wrap, text="Save", width=60, height=24, fg_color=ACCENT_BLUE, hover_color=ACCENT_BLUE_DARK, command=save_path).grid(row=2, column=0, padx=10, pady=(0, 7), sticky="w")

        self.path_status[key] = status
        self.path_entries[key] = entry
        if saved_path and validator(saved_path):
            status.configure(text="✔", text_color=ACCENT_GREEN)

    def _on_auto_accept_toggle(self, enabled):
        try:
            self.main_menu._lobbyManager.auto_accept = enabled
        except Exception:
            pass

        try:
            module = self.main_menu.auto_accept_module
            if enabled and not module._running:
                module.start()
            elif (not enabled) and module._running:
                module.stop()
        except Exception:
            pass

    # ---------------- License logic ----------------
    def get_hwid(self):
        mac = uuid.getnode()
        return hashlib.sha256(str(mac).encode("utf-8")).hexdigest()[:20].upper()

    def _urlsafe_b64decode(self, value: str) -> bytes:
        padding = "=" * ((4 - len(value) % 4) % 4)
        return base64.urlsafe_b64decode((value + padding).encode("utf-8"))

    def _load_public_key(self):
        try:
            if LICENSE_EMBEDDED_PUBLIC_KEY_PEM.strip():
                return rsa.PublicKey.load_pkcs1_openssl_pem(LICENSE_EMBEDDED_PUBLIC_KEY_PEM.encode("utf-8"))
            if LICENSE_PUBLIC_KEY_PATH.exists():
                return rsa.PublicKey.load_pkcs1_openssl_pem(LICENSE_PUBLIC_KEY_PATH.read_bytes())
            return None
        except Exception:
            return None

    def _save_license_cache(self, signed_token, hwid, exp):
        try:
            LICENSE_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            LICENSE_CACHE_PATH.write_text(
                json.dumps({"signed_token": signed_token, "hwid": hwid, "exp": int(exp), "saved_at": int(time.time())}, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _clear_license_cache(self):
        try:
            if LICENSE_CACHE_PATH.exists():
                LICENSE_CACHE_PATH.unlink()
        except Exception:
            pass

    def _restore_cached_license(self, hwid):
        try:
            if not LICENSE_CACHE_PATH.exists():
                return False
            cached = json.loads(LICENSE_CACHE_PATH.read_text(encoding="utf-8"))
            token = cached.get("signed_token")
            cached_hwid = cached.get("hwid")
            cached_exp = int(cached.get("exp", 0) or 0)
            if not token:
                return False
            if cached_hwid and cached_hwid != hwid:
                self.log_manager.add_log("⚠️ Кэш лицензии отклонён: HWID не совпадает.")
                self._clear_license_cache()
                return False
            if cached_exp and cached_exp <= int(time.time()):
                self.log_manager.add_log("⚠️ Кэш лицензии просрочен.")
                self._clear_license_cache()
                return False
            payload = self._verify_signed_token(token, hwid, expected_nonce=None)
            self._apply_license_result(True, f"Офлайн кэш до {payload.get('expires_at', 'n/a')}")
            self.log_manager.add_log("ℹ️ Использован локальный кэш лицензии.")
            return True
        except Exception:
            self._clear_license_cache()
            return False

    def _request_license_challenge(self, hwid):
        # ВАЖНО: на сервере роут без trailing slash: /api/challenge
        url = f"{LICENSE_SERVER_URL}/api/challenge"

        response = self.http_session.get(
            url,
            params={"hwid": hwid},
            timeout=LICENSE_REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Некорректный challenge от сервера")

        nonce = data.get("nonce")
        challenge_id = data.get("challenge_id")
        expires_in = int(data.get("expires_in", LICENSE_CHALLENGE_TTL_SECONDS))

        if not nonce or not challenge_id:
            raise ValueError(f"Сервер не вернул nonce/challenge_id. Ответ: {data}")

        self.license_nonce = nonce
        self.license_challenge_id = challenge_id
        self.license_challenge_exp = int(time.time()) + min(expires_in, LICENSE_CHALLENGE_TTL_SECONDS)

        return {"nonce": nonce, "challenge_id": challenge_id}


    def _request_license_state(self, hwid):
        # 1) получить challenge
        challenge = self._request_license_challenge(hwid)

        # 2) POST /api/check с JSON body (как в серверном CheckRequest)
        url = f"{LICENSE_SERVER_URL}/api/check"
        body = {
            "hwid": hwid,
            "challenge_id": challenge["challenge_id"],
            "nonce": challenge["nonce"],
            "ts": int(time.time()),
        }

        response = self.http_session.post(url, json=body, timeout=LICENSE_REQUEST_TIMEOUT)
        response.raise_for_status()

        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Некорректный ответ сервера лицензий")

        signed_token = data.get("signed_token")
        if not signed_token:
            raise ValueError(data.get("detail") or data.get("message") or f"Сервер не вернул signed_token. Ответ: {data}")

        # Сервер всегда возвращает подписанный токен (signed_token) в этом коде:
        return self._verify_signed_token(signed_token, hwid, expected_nonce=challenge["nonce"])

    def _verify_signed_token(self, signed_token, expected_hwid, expected_nonce=None):
        if not signed_token or "." not in signed_token:
            raise ValueError("Подпись лицензии отсутствует")

        payload_b64, signature_b64 = signed_token.split(".", 1)
        payload_raw = self._urlsafe_b64decode(payload_b64)
        signature = self._urlsafe_b64decode(signature_b64)

        public_key = self._load_public_key()
        if public_key is None:
            raise ValueError("Отсутствует settings/license_public_key.pem для проверки подписи")

        try:
            rsa.verify(payload_raw, signature, public_key)
        except Exception as exc:
            raise ValueError(f"Подпись сервера не прошла проверку: {exc}") from exc

        payload = json.loads(payload_raw.decode("utf-8"))
        now_ts = int(time.time())
        iat = int(payload.get("iat", 0))
        exp = int(payload.get("exp", 0))

        # Некоторые серверы лицензий возвращают unix-время в миллисекундах.
        # Нормализуем к секундам, чтобы не отклонять валидные токены.
        if iat > 10**12:
            iat //= 1000
        if exp > 10**12:
            exp //= 1000

        if payload.get("hwid") != expected_hwid:
            raise ValueError("HWID в токене не совпадает с устройством")
        if expected_nonce and payload.get("nonce") != expected_nonce:
            raise ValueError("Nonce в токене не совпадает с запросом")
        if iat > now_ts + LICENSE_TOKEN_TTL_GRACE_SECONDS:
            raise ValueError("Токен имеет некорректный iat")
        if exp <= now_ts:
            raise ValueError("Токен лицензии истёк")
        if exp - iat > MAX_TOKEN_TTL_SECONDS:
            raise ValueError("TTL токена превышает допустимый лимит")
        if payload.get("status") != "active":
            raise ValueError(payload.get("message") or "Лицензия не активна")

        self.license_token = signed_token
        self.license_exp = exp
        self.license_nonce = payload.get("nonce")
        self._save_license_cache(signed_token, expected_hwid, exp)
        return payload

    def _validate_current_token(self):
        return int(time.time()) < int(self.license_exp) - LICENSE_TOKEN_TTL_GRACE_SECONDS

    def check_license_async(self, hwid):
        # если уже идёт проверка — НЕ молчим
        if self._license_check_in_flight:
            self.log_manager.add_log("⏳ Проверка лицензии уже выполняется...")
            try:
                self.license_status.configure(text="Статус: Проверка уже идёт...", text_color=ACCENT_ORANGE)
            except Exception:
                pass
            return

        self._license_check_in_flight = True
        request_id = getattr(self, "_license_check_request_id", 0) + 1
        self._license_check_request_id = request_id
        self.log_manager.add_log(f"🔄 Проверка лицензии: {hwid}...")
        try:
            self.license_status.configure(text="Статус: Проверка...", text_color=ACCENT_ORANGE)
        except Exception:
            pass

        # watchdog: если что-то пошло не так и future не вернулось — сбросим флаг
        watchdog_id = None

        def watchdog():
            # если спустя 15с всё ещё "in flight" — сбрасываем и логируем
            if (
                self._license_check_in_flight
                and getattr(self, "_license_check_request_id", 0) == request_id
                and self.winfo_exists()
            ):
                self._license_check_in_flight = False
                if not self.is_unlocked:
                    self.log_manager.add_log("⚠️ Проверка лицензии зависла/не вернулась. Флаг сброшен, попробуйте ещё раз.")
                    try:
                        self.license_status.configure(text="Статус: Таймаут проверки", text_color=ACCENT_RED)
                    except Exception:
                        pass

        if self.winfo_exists():
            watchdog_id = self.after(LICENSE_WATCHDOG_TIMEOUT_MS, watchdog)

        def task():
            return self._request_license_state(hwid)

        def done(fut):
            nonlocal watchdog_id
            try:
                # блокируем watchdog до изменения UI, чтобы не перетёр корректный статус
                self._license_check_in_flight = False
                if watchdog_id is not None and self.winfo_exists():
                    try:
                        self.after_cancel(watchdog_id)
                    except Exception:
                        pass

                payload = fut.result()
                msg = f"Активна до {payload.get('expires_at', 'n/a')}"
                self._apply_license_result(True, msg)

            except Exception as exc:
                self._apply_license_result(False, f"Проверка не пройдена: {exc}")

       

        # важно: если executor.submit упал — тоже сбросить флаг
        try:
            self._run_action_async(task, done)
        except Exception as exc:
            if watchdog_id is not None and self.winfo_exists():
                try:
                    self.after_cancel(watchdog_id)
                except Exception:
                    pass
            self._license_check_in_flight = False
            self.log_manager.add_log(f"❌ Не удалось запустить проверку в фоне: {exc}")
            try:
                self.license_status.configure(text="Статус: Ошибка запуска проверки", text_color=ACCENT_RED)
            except Exception:
                pass

    def _start_background_check(self):
        my_hwid = self.get_hwid()

        if self._license_check_in_flight or self._background_license_check_in_flight:
            if self.winfo_exists():
                self.after(LICENSE_RECHECK_INTERVAL_MS, self._start_background_check)
            return

        self._background_license_check_in_flight = True
        self._run_action_async(lambda: self._request_license_state(my_hwid), self._on_silent_check_done)

        if self.winfo_exists():
            self.after(LICENSE_RECHECK_INTERVAL_MS, self._start_background_check)

    def _on_silent_check_done(self, future):
        self._background_license_check_in_flight = False

        if future.exception():
            self.log_manager.add_log(f"⚠️ Автопроверка: ошибка проверки лицензии: {future.exception()}")
            self._apply_license_result(False, "Проверьте лицензию: запись не найдена или недоступна в БД")
            self.log_manager.add_log("⚠️ Автопроверка: лицензия не подтверждена в БД. Доступ ограничен до раздела License.")
            return
        payload = future.result()
        expires_at = payload.get("expires_at", "n/a")
        if self.is_unlocked:

            return

        self._apply_license_result(True, f"Активна до {expires_at}")
            
    def _ensure_license(self):
        if not self.is_unlocked:
            try:
                self.license_status.configure(text="Статус: Обновление лицензии...", text_color=ACCENT_ORANGE)
            except Exception:
                pass
            self.log_manager.add_log("❌ Действие заблокировано: лицензия не активна")
            return False

        if self._validate_current_token():
            return True

        self.log_manager.add_log("⚠️ Токен устарел, обновляю лицензию...")
        self.check_license_async(self.get_hwid())
        self.show_section("license")
        return False

    def _apply_license_result(self, is_valid, message):
        self.is_unlocked = is_valid

        if is_valid:
            status_text = "Статус: Лицензия подтверждена"
            if message:
                status_text = f"{status_text} ({message})"
            try:
                self.license_status.configure(text=status_text, text_color=ACCENT_GREEN)
            except Exception:
                pass
            self.log_manager.add_log(f"✅ Лицензия подтверждена сервером! {message}")
            self.show_section(self._pending_section or "license")
        else:
            try:
                self.license_status.configure(text="Статус: Лицензия не подтверждена. Нажмите «Проверить»", text_color=ACCENT_RED)
            except Exception:
                pass
            self.log_manager.add_log(f"❌ Лицензия отклонена: {message}")
            self.show_section("license")

    # ---------------- License section UI ----------------
    def _build_license_section(self, parent):
        frame = customtkinter.CTkFrame(parent, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BG_BORDER)
        frame.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(frame, text="License", font=customtkinter.CTkFont(size=30, weight="bold"), text_color=TXT_MAIN).grid(row=0, column=0, padx=16, pady=(20, 8), sticky="w")

        self.license_status = customtkinter.CTkLabel(frame, text="Статус: Ожидание...", text_color=ACCENT_ORANGE, font=customtkinter.CTkFont(size=14, weight="bold"))
        self.license_status.grid(row=1, column=0, padx=16, pady=(0, 14), sticky="w")

        block = customtkinter.CTkFrame(frame, fg_color=BG_CARD_ALT, corner_radius=8, border_width=1, border_color=BG_BORDER)
        block.grid(row=2, column=0, padx=16, pady=8, sticky="ew")
        block.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(block, text="Ваш HWID:", text_color=TXT_SOFT).grid(row=0, column=0, padx=10, pady=(8, 2), sticky="w")

        hwid_entry = customtkinter.CTkEntry(block, height=34)
        hwid_entry.grid(row=1, column=0, padx=10, pady=(0, 8), sticky="ew")

        my_hwid = self.get_hwid()
        hwid_entry.insert(0, my_hwid)
        hwid_entry.configure(state="readonly")

        customtkinter.CTkButton(
            block,
            text="Копировать",
            width=100,
            height=34,
            fg_color=ACCENT_BLUE,
            hover_color=ACCENT_BLUE_DARK,
            command=lambda: [self.clipboard_clear(), self.clipboard_append(my_hwid), self.log_manager.add_log("📋 HWID скопирован")],
        ).grid(row=1, column=1, padx=(0, 10), pady=(0, 8))

        customtkinter.CTkButton(
            block,
            text="Проверить",
            width=100,
            height=34,
            fg_color=ACCENT_GREEN,
            hover_color="#177a42",
            command=lambda: self.check_license_async(my_hwid),
        ).grid(row=1, column=2, padx=(0, 10), pady=(0, 8))

        self._restore_cached_license(my_hwid)
        self.check_license_async(my_hwid)
        return frame

    # ---------------- Stats section ----------------
    def _build_stats_section(self, parent):
        frame = customtkinter.CTkFrame(parent, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BG_BORDER)
        frame.grid_columnconfigure(0, weight=1)
        customtkinter.CTkLabel(frame, text="Accs Stats", font=customtkinter.CTkFont(size=30, weight="bold"), text_color=TXT_MAIN).grid(row=0, column=0, padx=16, pady=(20, 8), sticky="w")
        return frame

    # ---------------- Actions (locked) ----------------
    def _action_start_selected(self):
        if not self._ensure_license():
            return
        self._run_action_async(self.accounts_control.start_selected)

    def _action_select_first_4(self):
        if not self._ensure_license():
            return
        non_farmed = [acc for acc in self.account_manager.accounts if not self.accounts_list.is_reserved_from_rotation(acc)]
        target = non_farmed[:4]
        current = self.account_manager.selected_accounts
        if len(current) == len(target) and all(a in current for a in target):
            self.account_manager.selected_accounts.clear()
        else:
            self.account_manager.selected_accounts.clear()
            self.account_manager.selected_accounts.extend(target)
        self._safe_ui_refresh()

    def _action_select_all_toggle(self):
        if not self._ensure_license():
            return
        if len(self.account_manager.selected_accounts) == len(self.account_manager.accounts):
            self.account_manager.selected_accounts.clear()
        else:
            self.account_manager.selected_accounts.clear()
            self.account_manager.selected_accounts.extend(self.account_manager.accounts)
        self._safe_ui_refresh()

    def _action_kill_selected(self):
        if not self._ensure_license():
            return
        self._run_action_async(self.accounts_control.kill_selected)

    def _action_try_get_level(self):
        if not self._ensure_license():
            return
        self._run_action_async(self.accounts_control.try_get_level, lambda _: self.after(300, self._refresh_level_labels))

    def _action_kill_all_cs_and_steam(self):
        if not self._ensure_license():
            return
        self._run_action_async(self.control_frame.kill_all_cs_and_steam)

    def _action_move_all_cs_windows(self):
        if not self._ensure_license():
            return
        self._run_action_async(self.control_frame.move_all_cs_windows)

    def _action_launch_bes(self):
        if not self._ensure_license():
            return
        self._run_action_async(self.control_frame.launch_bes)

    def _action_try_get_wingman_rank(self):
        if not self._ensure_license():
            return
        self._run_action_async(self.accounts_control.try_get_wingmanRank)

    def _action_send_trade_selected(self):
        if not self._ensure_license():
            return
        self.config_tab.send_trade_selected(on_trade_sent=self._on_trade_sent_success)

    def _on_trade_sent_success(self, login):
        def mark_sent():
            levels_cache = getattr(self.accounts_list, "levels_cache", {}) or {}
            account_data = levels_cache.get(login, {})
            if not isinstance(account_data, dict):
                account_data = {}

            week_start_iso = self._get_weekly_window_start().isoformat()
            account_data["trade_sent_week_start"] = week_start_iso
            levels_cache[login] = account_data
            self.accounts_list.levels_cache = levels_cache

            if hasattr(self.accounts_list, "_save_levels_to_json"):
                self.accounts_list._save_levels_to_json()

            for item in self.account_row_items:
                if item["account"].login == login:
                    self._refresh_account_badge(item["account"])
                    break

        self._queue_ui_action(mark_sent)

    def _action_open_looter_settings(self):
        if not self._ensure_license():
            return
        self._run_action_async(self.config_tab.open_looter_settings)

    def _action_marked_farmer(self):
        if not self._ensure_license():
            return
        self._run_action_async(self.accounts_control.mark_farmed, lambda _: self._safe_ui_refresh())

    def _action_make_lobbies_and_search(self):
        if not self._ensure_license():
            return
        self._run_action_async(self.main_menu.make_lobbies_and_search_game)

    def trigger_make_lobbies_and_search_button(self):
        button = self.lobby_buttons.get("Make lobbies & search game")
        if button is None:
            for text, candidate in self.lobby_buttons.items():
                if text.strip().lower() == "make lobbies & search game":
                    button = candidate
                    break
        if button is None:
            self.log_manager.add_log("❌ UI button 'Make lobbies & search game' not found in app.py")
            return False

        try:
            button.invoke()
            self.log_manager.add_log("✅ AUTO: invoke() on app.py button 'Make lobbies & search game'")
            return True
        except Exception as error:
            self.log_manager.add_log(f"❌ Failed to invoke app.py button: {error}")
            return False

    def _action_make_lobbies(self):
        if not self._ensure_license():
            return
        self._run_action_async(self.main_menu.make_lobbies)

    def _action_shuffle_lobbies(self):
        if not self._ensure_license():
            return
        self._run_action_async(self.main_menu.shuffle_lobbies)

    def _action_disband_lobbies(self):
        if not self._ensure_license():
            return
        self._run_action_async(self.main_menu.disband_lobbies)

    # ---------------- Regions / SRT ----------------
    def _load_region_json_if_exists(self):
        region_path = Path("region.json")
        if not region_path.exists():
            return
        try:
            data = json.loads(region_path.read_text(encoding="utf-8"))
            pops = data.get("pops", {})
            parsed_regions = {}
            parsed_ping_targets = {}

            for pop_key, pop_data in pops.items():
                relays = pop_data.get("relays", [])
                if not relays:
                    continue

                desc = pop_data.get("desc") or pop_key
                relay_ips = []
                ping_targets = []
                for relay in relays:
                    ip = relay.get("ipv4")
                    if not ip:
                        continue
                    relay_ips.append(ip)

                    port_range = relay.get("port_range") or []
                    if isinstance(port_range, (list, tuple)) and len(port_range) >= 2:
                        try:
                            start_port = int(port_range[0])
                            end_port = int(port_range[1])
                        except Exception:
                            start_port, end_port = 27015, 27060
                    else:
                        start_port, end_port = 27015, 27060

                    ping_targets.append((ip, start_port, end_port))

                if not relay_ips:
                    continue

                parsed_regions[desc] = sorted(set(relay_ips))
                parsed_ping_targets[desc] = sorted(set(ping_targets))

            if parsed_regions:
                self.sdr_regions = parsed_regions
                REGION_PING_TARGETS.clear()
                REGION_PING_TARGETS.update(parsed_ping_targets)
        except Exception:
            pass

    def _build_srt_state(self):
        self.route_manager = SteamRouteManager() if sys.platform.startswith("win") else None
        self.blocked_regions = set()
        self.srt_rows = {}
        self.region_ping_cache = {}

    def _build_srt_rows(self):
        if not self.sdr_regions:
            customtkinter.CTkLabel(self.srt_scroll, text="region.json не найден или пуст", text_color=TXT_MUTED, font=customtkinter.CTkFont(size=11)).grid(row=0, column=0, padx=6, pady=8, sticky="w")
            return

        for idx, region in enumerate(self.sdr_regions.keys()):
            row = customtkinter.CTkFrame(self.srt_scroll, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BG_BORDER)
            row.grid(row=idx, column=0, padx=2, pady=2, sticky="ew")
            row.grid_columnconfigure(0, weight=1)

            customtkinter.CTkLabel(row, text=region, text_color=TXT_MAIN, font=customtkinter.CTkFont(size=11, weight="bold")).grid(row=0, column=0, padx=(6, 2), pady=4, sticky="w")

            ping_label = customtkinter.CTkLabel(row, text="-- ms", text_color=TXT_MUTED, font=customtkinter.CTkFont(size=10))
            ping_label.grid(row=0, column=1, padx=2, pady=4)

            block_btn = customtkinter.CTkButton(
                row,
                text="✕",
                width=26,
                height=24,
                fg_color=BG_CARD_ALT,
                hover_color=ACCENT_RED,
                font=customtkinter.CTkFont(size=12, weight="bold"),
                command=lambda r=region: self._toggle_region_block(r),
            )
            block_btn.grid(row=0, column=2, padx=(2, 6), pady=3)
            self.srt_rows[region] = {"ping": ping_label, "button": block_btn}

        self._restore_blocked_regions_state()
        self._schedule_ping_refresh()

    def _restore_blocked_regions_state(self):
        if self.route_manager is None:
            return
        blocked_regions = self.route_manager.get_blocked_regions()
        if not blocked_regions:
            return
        self.blocked_regions = {region for region in blocked_regions if region in self.sdr_regions}
        for region in self.blocked_regions:
            self._set_region_visual(region)

    def _set_region_visual(self, region):
        row = self.srt_rows.get(region)
        if not row:
            return
        is_blocked = region in self.blocked_regions
        row["button"].configure(
            fg_color=ACCENT_RED if is_blocked else BG_CARD_ALT,
            text="✓" if is_blocked else "✕",
            hover_color="#962c38" if is_blocked else ACCENT_RED,
        )

    def _toggle_region_block(self, region):
        def op():
            if region in self.blocked_regions:
                ok = True if self.route_manager is None else self.route_manager.remove_rule(region)
                if ok:
                    self.blocked_regions.discard(region)
            else:
                region_ips = self.sdr_regions.get(region, [])
                ok = True if self.route_manager is None else self.route_manager.add_block_rule(region, region_ips)
                if ok:
                    self.blocked_regions.add(region)
            return True

        self._run_action_async(op, lambda _: self._set_region_visual(region))

    def _srt_block_all(self):
        def op():
            for region, region_ips in self.sdr_regions.items():
                ok = True if self.route_manager is None else self.route_manager.add_block_rule(region, region_ips)
                if ok:
                    self.blocked_regions.add(region)

        def done(_):
            for region in self.sdr_regions.keys():
                self._set_region_visual(region)

        self._run_action_async(op, done)

    def _srt_reset(self):
        def op():
            self._reset_windows_proxy()
            self.blocked_regions.clear()

        def done(_):
            for region in self.sdr_regions.keys():
                self._set_region_visual(region)

        self._run_action_async(op, done)

    def _measure_host_latency_ms(self, host, tcp_ports=None):
        try:
            if sys.platform.startswith("win"):
                cmd = ["cmd", "/c", "ping", "-n", "1", "-w", "1000", host]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", host]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=False,
                timeout=4,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

            raw_output = (result.stdout or b"") + b"\n" + (result.stderr or b"")
            decoded_parts = []
            for enc in ("utf-8", "cp866", "cp1251", "latin-1"):
                try:
                    decoded_parts.append(raw_output.decode(enc, errors="ignore"))
                except Exception:
                    pass
            out = "\n".join(decoded_parts).lower()

            samples = []
            for m in re.finditer(r"(?:time|время)\s*[=<]?\s*([0-9]+(?:[\.,][0-9]+)?)\s*(?:ms|мс|мсек)?", out):
                try:
                    samples.append(float(m.group(1).replace(",", ".")))
                except Exception:
                    pass

            for m in re.finditer(r"(?<!\d)([0-9]+(?:[\.,][0-9]+)?)\s*(?:ms|мс|мсек)", out):
                try:
                    samples.append(float(m.group(1).replace(",", ".")))
                except Exception:
                    pass

            avg_match = re.search(r"(?:average|avg|среднее)\s*[=:]\s*([0-9]+(?:[\.,][0-9]+)?)", out)
            if avg_match:
                try:
                    samples.append(float(avg_match.group(1).replace(",", ".")))
                except Exception:
                    pass

            rtt_match = re.search(r"(?:rtt|round-trip)[^=]*=\s*[0-9]+(?:[\.,][0-9]+)?/([0-9]+(?:[\.,][0-9]+)?)/", out)
            if rtt_match:
                try:
                    samples.append(float(rtt_match.group(1).replace(",", ".")))
                except Exception:
                    pass

            if samples:
                return samples[0]

            if sys.platform.startswith("win"):
                ps_cmd = (
                    f'$r=Test-Connection -Count 1 -TimeoutSeconds 1 -TargetName "{host}" -ErrorAction SilentlyContinue; '
                    "if ($r) { [double]$r.Latency }"
                )
                ps_result = subprocess.run(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                ps_text = (ps_result.stdout or "").strip().replace(",", ".")
                if ps_text:
                    try:
                        return float(ps_text)
                    except Exception:
                        pass

            return None
        except Exception:
            return None

    def _get_ping_ms(self, target_hosts):
        try:
            if not target_hosts:
                return "-- ms"

            hosts = target_hosts if isinstance(target_hosts, (list, tuple, set)) else [target_hosts]
            best_latency = None
            for target in hosts:
                if isinstance(target, (list, tuple)) and len(target) >= 3:
                    host = target[0]
                    try:
                        start_port = int(target[1])
                        end_port = int(target[2])
                    except Exception:
                        start_port, end_port = 27015, 27060

                    if end_port < start_port:
                        start_port, end_port = end_port, start_port

                    span = max(0, end_port - start_port)
                    step = max(1, span // 3) if span else 1
                    _ = sorted({start_port, start_port + step, start_port + step * 2, end_port})
                else:
                    host = target

                latency = self._measure_host_latency_ms(host)
                if latency is None:
                    continue

                if best_latency is None or latency < best_latency:
                    best_latency = latency

            if best_latency is None:
                return "-- ms"

            return f"{int(round(best_latency))} ms"
        except Exception:
            return "-- ms"

    def _collect_region_pings(self):
        ping_map = {}
        for region in self.srt_rows.keys():
            targets = REGION_PING_TARGETS.get(region) or self.sdr_regions.get(region, [])
            current_ping = self._get_ping_ms(targets)
            if current_ping != "-- ms":
                self.region_ping_cache[region] = current_ping
            ping_map[region] = self.region_ping_cache.get(region, current_ping)
        return ping_map

    def _schedule_ping_refresh(self):
        def refresh_once():
            try:
                if self.ping_refresh_in_flight:
                    return
                self.ping_refresh_in_flight = True

                def done_callback(future):
                    self.ping_refresh_in_flight = False
                    try:
                        ping_map = future.result()
                        for region, row in self.srt_rows.items():
                            row["ping"].configure(text=ping_map.get(region, "-- ms"))
                    except Exception:
                        pass

                self._run_action_async(self._collect_region_pings, done_callback)
            except Exception:
                self.ping_refresh_in_flight = False

        self.after(500, refresh_once)

    # ---------------- Navigation ----------------
    def _apply_section_switch(self, section_key):
        for key, frame in self.sections.items():
            if key == section_key:
                frame.grid(row=0, column=0, sticky="nsew")
            else:
                frame.grid_remove()

        for key, button in self.nav_buttons.items():
            button.configure(
                fg_color=BG_CARD if key == section_key else BG_CARD_ALT,
                border_color=ACCENT_GREEN if key == section_key else ACCENT_RED,
            )
        self._pending_section = None
        self._section_switch_job = None

    def show_section(self, section_key):
        self._pending_section = section_key

        for k, button in self.nav_buttons.items():
            is_selected = (k == section_key)
            if (not getattr(self, "is_unlocked", False)) and k != "license":
                btn_state = "disabled"
            else:
                btn_state = "normal"

            button.configure(
                state=btn_state,
                fg_color=BG_CARD if is_selected else BG_CARD_ALT,
                border_color=ACCENT_GREEN if is_selected else ACCENT_RED,
            )

        if self._section_switch_job is not None:
            try:
                self.after_cancel(self._section_switch_job)
            except Exception:
                pass

        self._section_switch_job = self.after(85, lambda: self._apply_section_switch(self._pending_section))

    # ---------------- Misc ----------------
    def _log_startup_gpu_info(self, startup_gpu_info):
        if not startup_gpu_info:
            return
        vendor_id, device_id, source = startup_gpu_info
        source_label = "detected" if source == "detected" else "settings fallback"
        try:
            self.log_manager.add_log(f"🎮 GPU ({source_label}): VendorID={vendor_id}, DeviceID={device_id}")
        except Exception:
            pass

    def _connect_gsi_to_ui(self):
        try:
            if self.gsi_manager and self.accounts_list:
                self.gsi_manager.set_accounts_list_frame(self.accounts_list)
                print("✅ 🎮 GSIManager подключен к AccountsListFrame!")
            else:
                print("⚠️ GSIManager или AccountsListFrame недоступны")
        except Exception as exc:
            print(f"❌ Ошибка подключения GSIManager: {exc}")

    def _load_window_position(self):
        try:
            if not self.window_position_file.exists():
                return
            raw = self.window_position_file.read_text(encoding="utf-8").strip()
            if not raw:
                return
            parts = raw.split(",")
            if len(parts) != 2:
                return
            x = int(parts[0].strip())
            y = int(parts[1].strip())
            self.geometry(f"1100x600+{x}+{y}")
        except Exception:
            pass

    def _save_window_position(self):
        try:
            x = self.winfo_x()
            y = self.winfo_y()
            self.window_position_file.write_text(f"{x},{y}", encoding="utf-8")
        except Exception:
            pass

    def on_closing(self):
        if self._section_switch_job is not None:
            try:
                self.after_cancel(self._section_switch_job)
            except Exception:
                pass
        try:
            self._save_window_position()
        except Exception:
            pass
        try:
            self.executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        try:
            self.quit()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass
        os._exit(0)

    def update_label(self):
        self._update_accounts_info()
        self._sync_switches_with_selection()
        self._apply_account_filter()


if __name__ == "__main__":
    app = App()
    app.mainloop()
    
# ===== Inlined from ui/accounts_list_frame.py =====
import customtkinter
import json
from pathlib import Path
import os
import queue
from datetime import datetime, timedelta

from Managers.AccountsManager import AccountManager

class AccountsListFrame(customtkinter.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)

        self.accountsManager = AccountManager()
        self.control_frame = None

        # ✅ Очередь UI задач (важно: создаём СРАЗУ)
        self._ui_queue = queue.Queue()
        self.after(50, self._process_ui_queue)

        # 🆕 ПУТЬ К ФАЙЛУ ОТФАРМЛЕННЫХ
        self.farmed_file = Path("settings/accs_list.txt")
        self.farmed_file.parent.mkdir(exist_ok=True)

        self.levels_cache = self._load_levels_from_json()
        self.farmed_accounts = self._load_farmed_accounts()

        print(f"✅ Загружено {len(self.levels_cache)} уровней из level.json")
        print(f"🟠 Загружено {len(self.farmed_accounts)} отфармленных аккаунтов")

        # Фрейм для метки
        self.top_frame = customtkinter.CTkFrame(self, fg_color="transparent")
        self.top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        self.top_frame.grid_columnconfigure(0, weight=1)

        self.label_text = customtkinter.CTkLabel(
            self.top_frame,
            text=self._get_label_text(),
            font=customtkinter.CTkFont(size=14),
            fg_color="#3c3f41",
            corner_radius=8,
            height=30
        )
        self.label_text.grid(row=0, column=0, sticky="ew")

        # Scrollable content
        self.scrollable_content = customtkinter.CTkScrollableFrame(self, fg_color="transparent")
        self.scrollable_content.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.scrollable_content.grid_columnconfigure(0, weight=1)
        self.scrollable_content.grid_rowconfigure(0, weight=1)

        self.switches = []
        self.level_labels = []
        self.account_switches = []

        self._create_switches()

        # ✅ чтобы не дергать UI слишком рано — применяем цвета после старта mainloop
        self.after(0, self._apply_farmed_colors)

    def _get_weekly_window_start(self, now=None):
        current_time = now or datetime.now()
        reset_anchor = current_time.replace(hour=3, minute=0, second=0, microsecond=0)
        days_since_reset = (current_time.weekday() - 2) % 7
        week_start = reset_anchor - timedelta(days=days_since_reset)
        if current_time < week_start:
            week_start -= timedelta(days=7)
        return week_start.isoformat()

    def is_drop_ready_login(self, login):
        account_data = self.levels_cache.get(login, self.levels_cache.get(login.lower(), {}))
        if not isinstance(account_data, dict):
            return False
        return account_data.get("drop_ready_week_start") == self._get_weekly_window_start()

    def is_drop_ready_account(self, account):
        return self.is_drop_ready_login(account.login)

    def set_drop_ready(self, login, value=True):
        account_data = self.levels_cache.get(login, self.levels_cache.get(login.lower(), {}))
        if not isinstance(account_data, dict):
            account_data = {}

        if value:
            account_data["drop_ready_week_start"] = self._get_weekly_window_start()
        else:
            account_data.pop("drop_ready_week_start", None)

        self.levels_cache[login] = account_data
        self._save_levels_to_json()

    def is_reserved_from_rotation(self, account):
        return self.is_farmed_account(account) or self.is_drop_ready_account(account)
    def set_control_frame(self, control_frame):
        """Установка ссылки на ControlFrame"""
        self.control_frame = control_frame

    def _load_levels_from_json(self):
        levels_cache = {}
        level_file = Path("level.json")
        if level_file.exists():
            try:
                with open(level_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                levels_cache = data
            except Exception as e:
                print(f"⚠️ Ошибка level.json: {e}")
        return levels_cache

    def _save_levels_to_json(self):
        try:
            with open("level.json", "w", encoding="utf-8") as f:
                json.dump(self.levels_cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"⚠️ Сохранение level.json: {e}")

    # 🆕 Загрузка отфармленных аккаунтов
    def _load_farmed_accounts(self):
        """Загружает список отфармленных аккаунтов из settings/accs_list.txt"""
        if not self.farmed_file.exists():
            return set()
        
        try:
            with open(self.farmed_file, "r", encoding="utf-8") as f:
                logins = [line.strip() for line in f.readlines() if line.strip()]
            print(f"✅ Загружены отфармленные: {logins[:5]}{'...' if len(logins)>5 else ''}")
            return set(logins)
        except Exception as e:
            print(f"⚠️ Ошибка загрузки farmed_accounts: {e}")
            return set()

    # 🆕 Сохранение отфармленных аккаунтов
    def _save_farmed_accounts(self):
        """Сохраняет список отфармленных аккаунтов в settings/accs_list.txt"""
        try:
            with open(self.farmed_file, "w", encoding="utf-8") as f:
                for login in sorted(self.farmed_accounts):
                    f.write(f"{login}\n")
            print(f"💾 Сохранено {len(self.farmed_accounts)} отфармленных аккаунтов")
        except Exception as e:
            print(f"⚠️ Ошибка сохранения farmed_accounts: {e}")

    def _create_switches(self):
        for i, account in enumerate(self.accountsManager.accounts):
            row_frame = customtkinter.CTkFrame(self.scrollable_content, fg_color="transparent")
            row_frame.grid(row=i, column=0, pady=2, sticky="ew", padx=0)
            row_frame.grid_columnconfigure(0, weight=1)

            # Switch
            sw = customtkinter.CTkSwitch(
                row_frame,
                text=f"{account.login}",
                command=lambda acc=account: self._toggle_account(acc),
                width=250,
                height=28
            )
            sw.grid(row=0, column=0, padx=(0, 8), sticky="w")

            # Level + XP
            login = account.login
            if login in self.levels_cache and "level" in self.levels_cache[login]:
                level = self.levels_cache[login]["level"]
                xp = self.levels_cache[login]["xp"]
                stats_text = f"[lvl: {level} | xp: {xp}]"
                text_color = "#00ff88"
            else:
                stats_text = "[lvl:-- | xp:--]"
                text_color = "#888"

            stats_label = customtkinter.CTkLabel(
                row_frame, 
                text=stats_text, 
                font=customtkinter.CTkFont(size=11, weight="bold"),
                text_color=text_color, 
                width=85,
                height=28,
                anchor="e"
            )
            stats_label.grid(row=0, column=1, sticky="e")

            self.switches.append(sw)
            self.level_labels.append((account, stats_label))
            self.account_switches.append((account, sw))
            account.setColorCallback(lambda color, acc=account, s=sw: self._handle_color_change(acc, color, s))

    def _process_ui_queue(self):
        try:
            while True:
                func = self._ui_queue.get_nowait()
                func()
        except queue.Empty:
            pass

        # повторяем каждые 50мс
        self.after(50, self._process_ui_queue)


    def _handle_color_change(self, account, color, switch):
        # ⚠️ Тут НЕЛЬЗЯ трогать Tk вообще. Только кладём задачу в очередь.
        def ui_update():
            try:
                if self.is_farmed_account(account) and color == "#DCE4EE":
                    switch.configure(text_color="#ff9500")
                    account._color = "#ff9500"
                elif self.is_drop_ready_account(account) and color == "#DCE4EE":
                    switch.configure(text_color="#a855f7")
                    account._color = "#a855f7"
                else:
                    switch.configure(text_color=color)

                self.update_label()
            except Exception:
                # если виджет уничтожен/окно закрыто — молча игнорируем
                pass

        self._ui_queue.put(ui_update)



    def _mark_ui_ready(self):
        self.ui_ready = True

    # 🆕 Применение цветов отфармленных при запуске
    def _apply_farmed_colors(self):
        """Применяет сохраненные цвета: оранжевый/фиолетовый."""
        for i, account in enumerate(self.accountsManager.accounts):
            if account.login in self.farmed_accounts:
                account.setColor("#ff9500")  # 🟠 Оранжевый для отфармленных
                print(f"🟠 [{account.login}] Восстановлен цвет отфармленного")
            elif self.is_drop_ready_account(account):
                account.setColor("#a855f7")
                print(f"🟣 [{account.login}] Восстановлен цвет Take drop")
    def update_account_level(self, login, level, xp):
        print(f"📊 [{login}]lvl: {level} xp: {xp}")
        matched_account = None
        for acc, stats_label in self.level_labels:
            if acc.login == login:
                matched_account = acc
                stats_label.configure(text=f"[lvl: {level} | xp: {xp}]", text_color="#00ff88")
                break

        existing = self.levels_cache.get(login, self.levels_cache.get(login.lower(), {}))
        current_data = existing if isinstance(existing, dict) else {}
        current_data.update({"level": level, "xp": xp})

        week_start_iso = self._get_weekly_window_start()
        baseline_level = current_data.get("weekly_baseline_level")
        baseline_start = current_data.get("weekly_baseline_start")
        has_take_drop = (
            baseline_start == week_start_iso
            and isinstance(level, int)
            and isinstance(baseline_level, int)
            and level >= baseline_level + 1
        )

        if has_take_drop:
            current_data["drop_ready_week_start"] = week_start_iso
        self.levels_cache[login] = current_data
        self._save_levels_to_json()
        if has_take_drop and matched_account and login not in self.farmed_accounts:
            matched_account.setColor("#a855f7")
        self.update_label()

    def _toggle_account(self, account):
        if account in self.accountsManager.selected_accounts:
            self.accountsManager.selected_accounts.remove(account)
        else:
            self.accountsManager.selected_accounts.append(account)
        self.update_label()

    def update_label(self):
        self.label_text.configure(text=self._get_label_text())
        for sw, account in zip(self.switches, self.accountsManager.accounts):
            if account in self.accountsManager.selected_accounts:
                sw.select()
            else:
                sw.deselect()

    def _get_label_text(self):
        return f"Accs: {len(self.accountsManager.accounts)} | Selected: {len(self.accountsManager.selected_accounts)} | Launched: {self.accountsManager.count_launched_accounts()}"

    # 🆕 ОБНОВЛЕННЫЙ метод отметки отфармленных
    def mark_farmed_accounts(self):
        """🟠 Отмечает ВСЕ выделенные аккаунты как отфармленные (оранжевый)"""
        print("🟠 Отмечаем отфармленные аккаунты...")
        selected_accounts = self.accountsManager.selected_accounts.copy()
        
        for account in selected_accounts:
            login = account.login
            # Устанавливаем оранжевый цвет
            account.setColor("#ff9500")  # 🟠 Оранжевый
            # Добавляем в отфармленные
            self.farmed_accounts.add(login)
            self.set_drop_ready(login, value=False)
            print(f"🟠 [{login}] Отмечен как отфармленный")
        
        # ✅ Сохраняем в файл
        self._save_farmed_accounts()
        
        # ✅ Очищаем выделение
        self.accountsManager.selected_accounts.clear()
        self.update_label()
        print(f"✅ Отфармлено {len(selected_accounts)} аккаунтов")

    def is_farmed_account(self, account):
        """Проверяет, является ли аккаунт отфармленным"""
        return account.login in self.farmed_accounts

    def select_first_non_farmed(self, n=4):
        """Выбирает первые N НЕ отфармленных аккаунтов"""
        available_accounts = [acc for acc in self.accountsManager.accounts 
                            if not self.is_reserved_from_rotation(acc)]
        count = min(n, len(available_accounts))
        
        self.accountsManager.selected_accounts.clear()
        for acc in available_accounts[:count]:
            self.accountsManager.selected_accounts.append(acc)
        
        print(f"✅ Выбрано {count} НЕ отфармленных аккаунтов")
        self.update_label()

    # 🆕 Метод для сброса отфармленных (если понадобится)
    def clear_farmed_accounts(self):
        """🔄 Сбрасывает все отфармленные аккаунты"""
        self.farmed_accounts.clear()
        self._save_farmed_accounts()
        self.reset_all_colors()
        print("🔄 Все отфармленные аккаунты сброшены!")

    def set_green_for_launched_cs2(self, launched_pids):
        """🟢 Зелёный ТОЛЬКО для НИКОВ - lvl/xp НЕ ТРОГАЕМ!"""
        print(f"🟢 Обновляем НИКИ для PID: {launched_pids}")
        
        processed_accounts = set()
        
        for i, (account, stats_label) in enumerate(self.level_labels):
            login = account.login
            
            if login in processed_accounts:
                continue
            
            cs2_pid = self._get_account_cs2_pid(login)
            
            if cs2_pid and cs2_pid in launched_pids:
                # ✅ 🟢 ЗЕЛЁНЫЙ ТОЛЬКО НИК (switch)!
                account.setColor("green")
                print(f"✅ 🟢 НИК: {login} (PID {cs2_pid})")
            else:
                # ✅ ⚪ Белый ТОЛЬКО НИК (switch)! (кроме оранжевых отфармленных)
                if login not in self.farmed_accounts:
                    if self.is_drop_ready_account(account):
                        account.setColor("#a855f7")
                    else:
                        account.setColor("#DCE4EE")
                else:
                    account.setColor("#ff9500")
                # 🟠 Оранжевые остаются оранжевыми
                
            processed_accounts.add(login)
        
        self.update_label()

    def _get_account_cs2_pid(self, login):
        """Находит CS2Pid аккаунта из runtime.json"""
        try:
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            runtime_path = os.path.join(project_root, "runtime.json")
            
            if os.path.exists(runtime_path):
                with open(runtime_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for item in data:
                        if item.get('login') == login:
                            return int(item.get('CS2Pid', 0))
        except Exception as e:
            print(f"⚠️ Ошибка поиска CS2Pid {login}: {e}")
        return None

    def reset_all_colors(self):
        def ui_update():
            print("🔄 Сброс НИКОВ в белый...")
            for i, sw in enumerate(self.switches):
                login = self.accountsManager.accounts[i].login
                if login not in self.farmed_accounts:
                    if self.is_drop_ready_login(login):
                        sw.configure(text_color="#a855f7")
                    else:
                        sw.configure(text_color="#DCE4EE")
            print("✅ НИКИ сброшены!")

        self.after(0, ui_update)


# ===== Inlined from ui/accounts_tab.py =====
import os
import re
import shutil
import threading
import customtkinter
import time
import keyboard

from Helpers.LoginExecutor import SteamLoginSession
from Managers.AccountsManager import AccountManager
from Managers.LogManager import LogManager
from Managers.SettingsManager import SettingsManager


class AccountsControl(customtkinter.CTkTabview):
    def __init__(self, parent, update_label, accounts_list):
        super().__init__(parent, width=250)
        self._active_stat_threads = 0
        self._stat_lock = threading.Lock()
        self._start_sequence_lock = threading.Lock()
        self._start_sequence_active = False
        self._ctrlq_hotkey_handle = None
        self._settingsManager = SettingsManager()
        self._logManager = LogManager()
        self.accountsManager = AccountManager()
        self.update_label = update_label
        self.accounts_list = accounts_list
        self.stat_buttons = []
        self.grid(row=1, column=2, padx=(20, 0), pady=(0, 0), sticky="nsew")

        # Вкладки
        self.add("Accounts Control")
        self.tab("Accounts Control").grid_columnconfigure(0, weight=1)

        self.add("Account Stats")
        self.tab("Account Stats").grid_columnconfigure(0, weight=1)

        self.create_control_buttons()
        self.create_stat_buttons()
        
        self.accounts_list.set_control_frame(self)

    # ----------------- Вкладка Accounts Control -----------------
    def create_control_buttons(self):
        buttons = [
            ("Start selected accounts", "darkgreen", self.start_selected),
            ("Kill selected accounts", "red", self.kill_selected),
            ("Select first 4 accounts", None, self.select_first_4),
            ("Select all accounts", None, self.select_unselect_all_accounts),
            ("Select dedicated farmed", "orange", self.mark_farmed),  # Toggle кнопка
        ]
        for i, (text, color, cmd) in enumerate(buttons):
            b = customtkinter.CTkButton(self.tab("Accounts Control"), text=text, fg_color=color, command=cmd)
            b.grid(row=i, column=0, padx=20, pady=10)

    def mark_farmed(self):
        """🟠 Toggle: отмечает/снимает отфармленные аккаунты"""
        if self.accounts_list:
            selected_accounts = self.accountsManager.selected_accounts.copy()
            if not selected_accounts:
                print("⚠️ Нет выделенных аккаунтов!")
                return
            


            for account in selected_accounts:
                login = account.login
                if self.accounts_list.is_farmed_account(account):
                    account.setColor("#DCE4EE")
                    self.accounts_list.farmed_accounts.discard(login)
                    self.accounts_list.set_drop_ready(login, value=False)
                    print(f"⚪ [{login}] Оранжевый -> белый")
                elif self.accounts_list.is_drop_ready_account(account):
                    account.setColor("#ff9500")
                    self.accounts_list.farmed_accounts.add(login)
                    self.accounts_list.set_drop_ready(login, value=False)
                    print(f"🟠 [{login}] Фиолетовый -> оранжевый")
                else:
                    account.setColor("#ff9500")
                    self.accounts_list.farmed_accounts.add(login)
                    print(f"🟠 [{login}] Белый -> оранжевый")

            self.accounts_list._save_farmed_accounts()
            self.accountsManager.selected_accounts.clear()
            self.update_label()
        else:
            print("⚠️ Нет ссылки на accounts_list")

    def _unmark_farmed_accounts(self, accounts):
        """🔄 Снимает отметку отфармленных аккаунтов"""
        print("🔄 Снимаем отметку отфармленных аккаунтов...")
        unmarked_count = 0
        
        for account in accounts:
            login = account.login
            if self.accounts_list.is_farmed_account(account):
                # 🟠 → ⚪ Оранжвый → белый
                account.setColor("#DCE4EE")
                # Удаляем из списка отфармленных
                self.accounts_list.farmed_accounts.discard(login)
                self.accounts_list._save_farmed_accounts()
                print(f" [{login}] Снято отфармлено (оранжевый → белый)")
                unmarked_count += 1
            else:
                print(f"⚪ [{login}] Уже не отфармленный")
        
        print(f" Снято отфармлено с {unmarked_count} аккаунтов")
        
        # Очищаем выделение
        self.accountsManager.selected_accounts.clear()
        self.update_label()

    def create_stat_buttons(self):
        buttons = [
            ("Get level", None, self.try_get_level),
            ("Get wingman Rank", None, self.try_get_wingmanRank),
            ("Get MM Ranks", None, self.try_get_mapStats),
            ("Get premier Rank", None, self.try_get_premierRank),
            ("Get all in html", None, self.save_stats_to_html),
        ]
        for i, (text, color, cmd) in enumerate(buttons):
            b = customtkinter.CTkButton(self.tab("Account Stats"), text=text, fg_color=color,
                                        command=lambda c=cmd: self._run_stat_with_lock(c))
            b.grid(row=i, column=0, padx=20, pady=10)
            self.stat_buttons.append(b)

    def _disable_stat_buttons(self):
        for b in self.stat_buttons:
            b.configure(state="disabled")

    def _enable_stat_buttons(self):
        for b in self.stat_buttons:
            b.configure(state="normal")

    def _run_stat_with_lock(self, func):
        def wrapper():
            with self._stat_lock:
                self._active_stat_threads += 1
                if self._active_stat_threads == 1:
                    self._disable_stat_buttons()
            try:
                func()
            finally:
                with self._stat_lock:
                    self._active_stat_threads -= 1
                    if self._active_stat_threads == 0:
                        self._enable_stat_buttons()

        self._run_in_thread(wrapper)

    def start_selected(self): 
        with self._start_sequence_lock:
            if self._start_sequence_active:
                self._logManager.add_log("⚠️ Процесс запуска уже выполняется. Дождитесь завершения")
                return
            self._start_sequence_active = True

        steam_path = self._settingsManager.get(
            "SteamPath", r"C:\Program Files (x86)\Steam\steam.exe"
        )
        cs2_path = self._settingsManager.get(
            "CS2Path", r"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive"
        )
        cs2_exe_path = os.path.join(cs2_path, r"game\bin\win64\cs2.exe")

        if not os.path.isfile(steam_path) or not steam_path.lower().endswith(".exe"):
            self._logManager.add_log("Steam path incorrect")
            self._finish_start_sequence()
            return

        if not os.path.isfile(cs2_exe_path):
            self._logManager.add_log("CS2 path incorrect")
            self._finish_start_sequence()
            return

        if not self._sync_required_cfg_files_to_cs2(cs2_path):
            self._finish_start_sequence()
            return

        accounts_to_start = self.accountsManager.selected_accounts.copy()
        if not accounts_to_start:
            self._logManager.add_log("No accounts selected")
            self._finish_start_sequence()
            return

        self.auto_cancelled = False
        self.auto_cancelled_by_user = False

        self.accountsManager.begin_start_selected_batch(len(accounts_to_start))
        for acc in accounts_to_start:
            self.accountsManager.add_to_start_queue(acc)
            print("Starting:", acc.login)

        self.accountsManager.selected_accounts.clear()
        self.update_label()

        threading.Thread(target=lambda: self._auto_get_level(accounts_to_start), daemon=True).start()

        self._register_ctrlq_hotkey()

        def check_cancellation_loop():
            timeout = 120
            start_time = time.time()
            while time.time() - start_time < timeout:
                if self.auto_cancelled:
                    self._logManager.add_log("Start game canceled")
                    break
                time.sleep(0.5)

            self._unregister_ctrlq_hotkey()
            self._finish_start_sequence()

        threading.Thread(target=check_cancellation_loop, daemon=True).start()

        if self.auto_cancelled:
            self._logManager.add_log("Start game canceled")
            self._finish_start_sequence()
            return

        try:
            app = self.winfo_toplevel()
            if hasattr(app, "control_frame"):
                def on_move_complete():
                    if self.auto_cancelled:
                        self._logManager.add_log("🛑 Lobbies отменены")
                        self._finish_start_sequence()
                        return

                    auto_match_enabled = bool(self._settingsManager.get("AutoMatchInStartEnabled", True))
                    if not auto_match_enabled:
                        self._logManager.add_log("ℹ️ Auto match in start: OFF")
                        self._finish_start_sequence()
                        return

                    def schedule_lobbies():
                        try:
                            current_app = self.winfo_toplevel()
                            if hasattr(current_app, "main_menu"):
                                current_app.main_menu.make_lobbies_and_search_game()
                            else:
                                self._logManager.add_log("❌ Main Menu not found: cannot trigger Make lobbies & Search game")
                        except Exception as e:
                            self._logManager.add_log(f"❌ Lobbies error: {e}")
                        finally:
                            self._finish_start_sequence()

                    def delay_and_schedule():
                        delay_seconds = 10
                        step = 0.5
                        waited = 0.0
                        while waited < delay_seconds:
                            if self.auto_cancelled:
                                self._logManager.add_log("🛑 Lobbies/Search отменены")
                                self._finish_start_sequence()
                                return
                            time.sleep(step)
                            waited += step
                        self.after(0, schedule_lobbies)

                    threading.Thread(target=delay_and_schedule, daemon=True).start()

                if not self.auto_cancelled:
                    app.control_frame.auto_move_after_4_cs2(
                        delay=25,
                        callback=on_move_complete,
                        cancel_check=lambda: self.auto_cancelled
                    )
                else:
                    self._logManager.add_log("Start game canceled")
                    self._finish_start_sequence()
            else:
                self._logManager.add_log("⚠️ control_frame not found in App")
                self._finish_start_sequence()
        except Exception as e:
            self._logManager.add_log(f"❌ Auto sequence error: {e}")
            self._finish_start_sequence()

    def _finish_start_sequence(self):
        with self._start_sequence_lock:
            self._start_sequence_active = False

    def _global_ctrlq_callback(self):
        """🔥 Глобальный Ctrl+Q обработчик"""
        self.auto_cancelled = True
        self.auto_cancelled_by_user = True

    def _register_ctrlq_hotkey(self):
        self._unregister_ctrlq_hotkey()
        self._ctrlq_hotkey_handle = keyboard.add_hotkey('ctrl+q', self._global_ctrlq_callback)

    def _unregister_ctrlq_hotkey(self):
        if self._ctrlq_hotkey_handle is None:
            return
        try:
            keyboard.remove_hotkey(self._ctrlq_hotkey_handle)
        except KeyError:
            pass
        finally:
            self._ctrlq_hotkey_handle = None

    def _auto_get_level(self, accounts):
        time.sleep(2)
        self._logManager.add_log("🔄 Авто Get Level для запущенных аккаунтов...")
        self.try_get_level_for_accounts(accounts)
    def _refresh_modern_levels_ui(self):
        """Обновляет уровни в новом UI (ui/app.py), если он доступен."""
        try:
            app = self.winfo_toplevel()
            if hasattr(app, "_refresh_level_labels"):
                app.after(0, app._refresh_level_labels)
        except Exception:
            pass
    def try_get_level_for_accounts(self, accounts):
        def worker():
            for acc in accounts:
                try:
                    steam = SteamLoginSession(acc.login, acc.password, acc.shared_secret)
                    html = self._fetch_html_with_retry(steam, url_suffix="gcpd/730")
                    if not html:
                        continue
                    rank_match = re.search(r'CS:GO Profile Rank:\s*([^\n<]+)', html)
                    xp_match = re.search(r'Experience points earned towards next rank:\s*([^\n<]+)', html)
                    if rank_match and xp_match:
                        rank = rank_match.group(1).strip().replace(',', '')
                        exp = xp_match.group(1).strip().replace(',', '').split()[0]
                        
                        try:
                            level = int(rank)
                            xp = int(exp)
                            self._logManager.add_log(f"[{acc.login}]  lvl: {level} | xp: {xp}")
                            if self.accounts_list:
                                self.accounts_list.update_account_level(acc.login, level, xp)
                            self._refresh_modern_levels_ui()
                        except ValueError:
                            self._logManager.add_log(f"[{acc.login}] ❌ Parse error")
                except Exception as e:
                    self._logManager.add_log(f"[{acc.login}] ❌ Auto level error: {e}")
        
        threading.Thread(target=worker, daemon=True).start()

    def try_get_level(self):
        def worker():
            for acc in self.accountsManager.selected_accounts:
                try:
                    steam = SteamLoginSession(acc.login, acc.password, acc.shared_secret)
                    html = self._fetch_html(steam, url_suffix="gcpd/730")
                    if not html:
                        self._logManager.add_log(f"[{acc.login}] Ошибка парснига")
                        continue

                    print(f"⏳ [{acc.login}] Wait for JS...")
                    time.sleep(1)

                    level, xp = 0, 0
                    rank_match = re.search(r'CS:GO Profile Rank:\s*([\d,]+)', html, re.IGNORECASE)
                    if rank_match:
                        level = int(rank_match.group(1).replace(',', ''))
                        xp_match = re.search(r'Experience points earned towards next rank:\s*([\d,]+)', html, re.IGNORECASE)
                        xp = int(xp_match.group(1).replace(',', '')) if xp_match else 0
                    else:
                        if re.search(r'"profile_rank"[:\s]*(\d+)', html):
                            rank_match = re.search(r'"profile_rank"[:\s]*(\d+)', html)
                            level = int(rank_match.group(1)) if rank_match else 0

                    if level > 0:
                        self._logManager.add_log(f"[{acc.login}] lvl: {level} | xp: {xp}")
                        acc.update_level_xp(level, xp)
                        self.accounts_list.update_account_level(acc.login, level, xp)
                        self._refresh_modern_levels_ui()
                    else:
                        with open(f"debug_{acc.login}.html", "w", encoding="utf-8") as f:
                            f.write(html)
                        self._logManager.add_log(f"[{acc.login}] ❌ No level (debug_{acc.login}.html)")

                except Exception as e:
                    self._logManager.add_log(f"[{acc.login}] ❌ Error: {e}")

        self._run_stat_with_lock(worker)

    def kill_selected(self):
        print("💀 УБИВАЮ ВЫБРАННЫЕ аккаунты!")
        
        killed = 0
        for acc in self.accountsManager.selected_accounts[:]:
            try:
                if hasattr(acc, 'steamProcess') and acc.steamProcess:
                    try:
                        acc.steamProcess.kill()
                        print(f"💀 Steam [{acc.login}]: {acc.steamProcess.pid}")
                        killed += 1
                    except:
                        pass
                    acc.steamProcess = None
                    
                if hasattr(acc, 'CS2Process') and acc.CS2Process:
                    try:
                        acc.CS2Process.kill()
                        print(f"💀 CS2 [{acc.login}]: {acc.CS2Process.pid}")
                        killed += 1
                    except:
                        pass
                    acc.CS2Process = None
                
                if self.accounts_list and self.accounts_list.is_farmed_account(acc):
                    acc.setColor("#ff9500")
                    print(f" [{acc.login}] Сброс - оранжевый цвет")
                elif self.accounts_list and self.accounts_list.is_drop_ready_account(acc):
                    acc.setColor("#a855f7")
                    print(f" [{acc.login}] Сброс - фиолетовый цвет")
                else:
                    acc.setColor("#DCE4EE")
                    print(f" [{acc.login}] Сброс - белый цвет")
                
            except Exception as e:
                print(f"⚠️ [{acc.login}] Ошибка: {e}")
        
        self.accountsManager.selected_accounts.clear()
        self.update_label()
        print(f" УБИТО {killed} процессов выбранных аккаунтов!")

    def select_first_4(self):
        if len(self.accountsManager.selected_accounts) < 4:
            if self.accounts_list:
                self.accounts_list.select_first_non_farmed(4)
            else:
                self._select_first_n(4)
        else:
            self.accountsManager.selected_accounts = []
            self.update_label()

    def select_unselect_all_accounts(self):
        all_accounts = self.accountsManager.accounts
        if not all_accounts:
            return

        if len(self.accountsManager.selected_accounts) == len(all_accounts):
            self.accountsManager.selected_accounts.clear()
        else:
            self.accountsManager.selected_accounts = list(all_accounts)

        self.update_label()
    def _select_first_n(self, n):
        for acc in self.accountsManager.accounts[:n]:
            if acc not in self.accountsManager.selected_accounts:
                self.accountsManager.selected_accounts.append(acc)
        self.update_label()

    def _resolve_cs2_cfg_folder(self, cs2_path):
        candidates = [
            os.path.join(cs2_path, "game", "csgo", "cfg"),
            os.path.join(cs2_path, "cfg"),
        ]
        for folder in candidates:
            if os.path.isdir(folder):
                return folder
        return None

    def _sync_required_cfg_files_to_cs2(self, cs2_path):
        cfg_folder = self._resolve_cs2_cfg_folder(cs2_path)
        if not cfg_folder:
            self._logManager.add_log("CS2 cfg folder not found")
            return False

        files_to_sync = [
            "cs2_machine_convars.vcfg",
            "cs2_video.txt",
            "cs2_video.txt.bak",
            "gamestate_integration_fsn.cfg",
            "fsn.cfg",
        ]

        for file_name in files_to_sync:
            source = os.path.join("settings", file_name)
            target = os.path.join(cfg_folder, file_name)

            if not os.path.isfile(source):
                self._logManager.add_log(f"Missing source file: {source}")
                return False

            try:
                shutil.copy2(source, target)
            except Exception as e:
                self._logManager.add_log(f"Failed to copy {file_name}: {e}")
                return False

        return True
        
    # ----------------- Helper Methods -----------------
    def _fetch_html_with_retry(self, steam, url_suffix="gcpd/730/?tab=matchmaking", retries=3):
        for _ in range(retries):
            html = self._fetch_html(steam, url_suffix=url_suffix)
            if html:
                return html
        return None
    def _fetch_html(self, steam, url_suffix="gcpd/730/?tab=matchmaking"):
        try:
            steam.login()

        except Exception:
            return None
        try:
            resp = steam.session.get(f'https://steamcommunity.com/profiles/{steam.steamid}/{url_suffix}', timeout=10)

        except Exception:
            return None
        if resp.status_code != 200:

            return None
        return resp.text

    def _run_in_thread(self, func):
        thread = threading.Thread(target=func, daemon=True)
        thread.start()

    # ----------------- Stats Methods -----------------
    def try_get_premierRank(self):
        def worker():
            for acc in self.accountsManager.selected_accounts:
                steam = SteamLoginSession(acc.login, acc.password, acc.shared_secret)
                parsed = False
                for _ in range(3):
                    html = self._fetch_html(steam)
                    if not html:
                        continue
                    match = re.search(
                        r'<td>Wingman</td><td>(\d+)</td><td>(\d+)</td><td>(\d+)</td><td>([^<]*)</td>',
                        html
                    )
                    if not match:
                        continue
                    wins, ties, losses = int(match.group(1)), int(match.group(2)), int(match.group(3))
                    skill = match.group(4).strip()
                    skill = int(skill) if skill.isdigit() else -1
                    self._logManager.add_log(f"[{acc.login}] Premier: W:{wins} T:{ties} L:{losses} R:{skill}")
                else:
                    self._logManager.add_log(f"[{acc.login}] ⚠ Premier stats not found")
        self._run_stat_with_lock(worker)

    def try_get_wingmanRank(self):
        def worker():
            for acc in self.accountsManager.selected_accounts:
                steam = SteamLoginSession(acc.login, acc.password, acc.shared_secret)
                html = self._fetch_html(steam)
                if not html:
                    continue
                match = re.search(
                    r'<td>Wingman</td><td>(\d+)</td><td>(\d+)</td><td>(\d+)</td><td>([^<]*)</td>',
                    html
                )
                if match:
                    wins, ties, losses = int(match.group(1)), int(match.group(2)), int(match.group(3))
                    skill = match.group(4).strip()
                    skill = int(skill) if skill.isdigit() else -1
                    self._logManager.add_log(f"[{acc.login}] Wingman: W:{wins} T:{ties} L:{losses} R:{skill}")

                else:
                    self._logManager.add_log(f"[{acc.login}] ⚠ Wingman статистика не найдена")
        self._run_stat_with_lock(worker)

    def try_get_mapStats(self):
        def worker():
            for acc in self.accountsManager.selected_accounts:
                steam = SteamLoginSession(acc.login, acc.password, acc.shared_secret)
                html = self._fetch_html(steam)
                if not html:
                    continue
                table_match = re.search(
                    r'<table class="generic_kv_table"><tr>\s*<th>Matchmaking Mode</th>\s*<th>Map</th>.*?</table>',
                    html, re.DOTALL
                )
                if not table_match:
                    self._logManager.add_log(f"[{acc.login}] ⚠ No map stats table found")
                    continue
                table_html = table_match.group(0)
                rows = re.findall(
                    r'<tr>\s*<td>([^<]+)</td><td>([^<]+)</td><td>(\d+)</td><td>(\d+)</td><td>(\d+)</td><td>([^<]*)</td>',
                    table_html
                )
                if rows:
                    for mode, map_name, wins, ties, losses, skill in rows:
                        wins, ties, losses = int(wins), int(ties), int(losses)
                        skill = skill.strip()
                        skill = int(skill) if skill.isdigit() else -1
                        self._logManager.add_log(
                            f"[{acc.login}] Map '{map_name}': W:{wins} T:{ties} L:{losses} R:{skill}"
                        )
        self._run_stat_with_lock(worker)

    def save_stats_to_html(self, filename="cs2_stats.html"):
        def worker():
            html_parts = [
                "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>CS2 Stats</title>",
                "<style>body { background-color: #121212; color: #eee; font-family: 'Segoe UI', Tahoma, sans-serif; display: flex; flex-direction: column; align-items: center; padding: 20px; }",
                "h1 { color: #00bfff; margin-bottom: 30px; }.account-card { background: #1e1e1e; border-radius: 8px; padding: 15px; margin-bottom: 20px; width: 100%; max-width: 600px; box-shadow: 0 3px 8px rgba(0,0,0,0.5); }",
                ".account-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }.account-title { font-size: 1.3em; color: #ffcc00; }.account-level { font-size: 0.95em; color: #00ff90; }",
                "table { border-collapse: collapse; width: 100%; margin-bottom: 10px; font-size: 13px; } th, td { border: 1px solid #333; padding: 5px; text-align: center; } th { background-color: #222; color: #fff; }",
                "tr:nth-child(even) { background-color: #2a2a2a; } tr:hover { background-color: #333; }.wins { color: #00ff00; font-weight: bold; }.ties { color: #ffff66; font-weight: bold; }.losses { color: #ff5555; font-weight: bold; }",
                ".skill { color: #00bfff; font-weight: bold; }.missing { color: #ff5555; font-style: italic; font-size: 12px; }</style></head><body><h1>CS2 Account Stats</h1>"
            ]
            i = 1
            accounts = self.accountsManager.selected_accounts
            for acc in accounts:
                self._logManager.add_log(f"Collecting stats ({i}/{len(accounts)})")
                steam = SteamLoginSession(acc.login, acc.password, acc.shared_secret)
                level_html = self._fetch_html(steam, "gcpd/730")
                rank_match = re.search(r'CS:GO Profile Rank:\s*([^\n<]+)', level_html) if level_html else None
                xp_match = re.search(r'Experience points earned towards next rank:\s*([^\n<]+)', level_html) if level_html else None
                level = rank_match.group(1).strip() if rank_match else "N/A"
                xp = xp_match.group(1).strip() if xp_match else "N/A"
                stats_html = self._fetch_html(steam)
                html_parts.extend([
                    "<div class='account-card'>",
                    f"<div class='account-header'><div class='account-title'>{acc.login}</div><div class='account-level'>Level: {level} | XP: {xp}</div></div>"
                ])
                # Premier, Wingman, Map Stats (сокращено для компактности)
                html_parts.append("</div>")
                i += 1
            html_parts.extend(["</body></html>"])
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(html_parts))
            self._logManager.add_log(f" Stats saved to {filename}")
        self._run_stat_with_lock(worker)

    def update_label(self):
        if hasattr(self.parent, 'update_label'):
            self.parent.update_label()


# ===== Inlined from ui/config_tab.py =====
import os
import shutil
import subprocess
import threading

import customtkinter

from Managers.AccountsManager import AccountManager
from Managers.LogManager import LogManager
from Managers.SettingsManager import SettingsManager


class ConfigTab(customtkinter.CTkTabview):
    def __init__(self, parent):
        super().__init__(parent, width=250)
        self._settingsManager = SettingsManager()
        self._logManager = LogManager()
        self.accountsManager = AccountManager()

        self.grid(row=0, column=3, padx=(20, 20), pady=(0, 0), sticky="nsew")
        self.add("Config")
        self.tab("Config").grid_columnconfigure(0, weight=1)

        # --- Buttons for path selection ---
        b1 = customtkinter.CTkButton(
            self.tab("Config"),
            text="Select Steam path",
            command=lambda: self.set_path("SteamPath", "Steam", "C:/Program Files (x86)/Steam/steam.exe"),
        )
        b2 = customtkinter.CTkButton(
            self.tab("Config"),
            text="Select CS2 path",
            command=lambda: self.set_path(
                "CS2Path",
                "CS2",
                "C:/Program Files (x86)/Steam/steamapps/common/Counter-Strike Global Offensive",
            ),
        )
        b1.grid(row=0, column=0, padx=20, pady=10)
        b2.grid(row=1, column=0, padx=20, pady=10)

        # --- Switches ---
        self.bg_switch = customtkinter.CTkSwitch(
            self.tab("Config"),
            text="Remove background",
            command=lambda: self._settingsManager.set("RemoveBackground", self.bg_switch.get()),
        )
        self.bg_switch.grid(row=2, column=0, padx=10, pady=5)

        self.overlay_switch = customtkinter.CTkSwitch(
            self.tab("Config"),
            text="Disable Steam Overlay",
            command=lambda: self._settingsManager.set("DisableOverlay", self.overlay_switch.get()),
        )
        self.overlay_switch.grid(row=3, column=0, padx=10, pady=5)

        self.send_trade_button = customtkinter.CTkButton(
            self.tab("Config"),
            text="Send trade",
            fg_color="#ff1a1a",
            command=self.send_trade_selected,
        )
        self.send_trade_button.grid(row=4, column=0, padx=20, pady=(10, 5))

        self.settings_looter_button = customtkinter.CTkButton(
            self.tab("Config"),
            text="Settings looter",
            fg_color="#1b5e20",
            command=self.open_looter_settings,
        )
        self.settings_looter_button.grid(row=5, column=0, padx=20, pady=(5, 10))

        # --- Load saved values ---
        self.load_settings()

    def set_path(self, key, name, placeholder):
        """Opens a path input window and saves result in settingsManager."""
        value = self.open_path_window(name, placeholder)
        if value:
            self._settingsManager.set(key, value)

    def open_path_window(self, name, placeholder):
        """Opens a separate window for entering a path and returns the result."""
        result = {"value": None}

        win = customtkinter.CTkToplevel(self)
        win.title(f"Select {name} path")
        win.geometry("500x150")
        win.grab_set()

        label = customtkinter.CTkLabel(win, text=f"Enter {name} path:")
        label.pack(pady=(20, 5))

        entry = customtkinter.CTkEntry(win, placeholder_text=f"Example: {placeholder}", width=400)
        entry.pack(pady=5)

        def save_and_close():
            result["value"] = entry.get()
            win.destroy()

        btn = customtkinter.CTkButton(win, text="OK", command=save_and_close)
        btn.pack(pady=10)

        win.wait_window()
        return result["value"]

    def load_settings(self):
        """Load saved values from settingsManager and apply them."""
        bg_value = self._settingsManager.get("RemoveBackground", False)
        if bg_value is not None:
            self.bg_switch.select() if bg_value else self.bg_switch.deselect()

        overlay_value = self._settingsManager.get("DisableOverlay", False)
        if overlay_value is not None:
            self.overlay_switch.select() if overlay_value else self.overlay_switch.deselect()

        steam_path = self._settingsManager.get("SteamPath", "C:/Program Files (x86)/Steam/steam.exe")
        if steam_path:
            print(f"Loaded SteamPath: {steam_path}")

        cs2_path = self._settingsManager.get(
            "CS2Path", "C:/Program Files (x86)/Steam/steamapps/common/Counter-Strike Global Offensive"
        )
        if cs2_path:
            print(f"Loaded CS2Path: {cs2_path}")

    def _get_looter_script_path(self):
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(project_root, "looter_core.js")

    def open_looter_settings(self):
        current_inventory = self._settingsManager.get("LooterInventory", "730/2")

        dialog = customtkinter.CTkInputDialog(
            text=(
                "Введите ссылку обмена Steam (trade offer link).\n"
                "Она будет использована кнопкой Send trade."
            ),
            title="Settings looter",
        )
        new_trade_link = dialog.get_input()

        if new_trade_link is None:
            self._logManager.add_log("⚠️ Настройки лутера не изменены")
            return

        new_trade_link = new_trade_link.strip()
        if not new_trade_link:
            self._logManager.add_log("❌ Пустая трейд ссылка. Настройки не сохранены")
            return

        inv_dialog = customtkinter.CTkInputDialog(
            text=(
                "Инвентари для отправки (например: 730/2 440/2 753/6).\n"
                "Разделители: пробел, запятая или ;\n"
                f"Текущее значение: {current_inventory}"
            ),
            title="Settings looter",
        )
        new_inventory = inv_dialog.get_input()

        if new_inventory is None:
            new_inventory = current_inventory
        else:
            new_inventory = new_inventory.strip() or "730/2"

        new_inventory = self._normalize_inventory_string(new_inventory)
        if not new_inventory:
            self._logManager.add_log("❌ Инвентари указаны некорректно. Использую значение по умолчанию 730/2")
            new_inventory = "730/2"

        self._settingsManager.set("LooterTradeLink", new_trade_link)
        self._settingsManager.set("LooterInventory", new_inventory)
        self._logManager.add_log("✅ Settings looter сохранены")

    def send_trade_selected(self, on_trade_sent=None):
        selected_accounts = self.accountsManager.selected_accounts.copy()
        if not selected_accounts:
            self._logManager.add_log("⚠️ Выберите аккаунты для отправки трейда")
            return

        trade_link = (self._settingsManager.get("LooterTradeLink", "") or "").strip()
        if not trade_link:
            self._logManager.add_log("❌ Сначала заполните trade link в Settings looter")
            return

        script_path = self._get_looter_script_path()
        if not os.path.isfile(script_path):
            self._logManager.add_log(f"❌ Файл looter_core.js не найден: {script_path}")
            return

        inventory_string = (self._settingsManager.get("LooterInventory", "730/2") or "730/2").strip() or "730/2"
        inventory_string = self._normalize_inventory_string(inventory_string)
        if not inventory_string:
            self._logManager.add_log("❌ В настройках looter нет валидных inventory pair")
            return

        self._logManager.add_log(f"🚚 Запускаю Send trade для {len(selected_accounts)} аккаунтов")
        threading.Thread(
            target=self._send_trade_worker,
            args=(selected_accounts, trade_link, inventory_string, script_path, on_trade_sent),
            daemon=True,
        ).start()

    def _extract_looter_error(self, stdout, stderr):
        lines = [line.strip() for line in (stdout or "").splitlines() if line.strip()]
        for line in reversed(lines):
            if "HandleError" in line:
                return line

        err_lines = [line.strip() for line in (stderr or "").splitlines() if line.strip()]
        if err_lines:
            return err_lines[-1]
        return ""

    def _is_authorization_error(self, error_line):
        lowered = (error_line or "").lower()
        return (
            "steam login error" in lowered
            or "ratelimitexceeded" in lowered
            or "accountlogindeniedthrottle" in lowered
            or "toomanylogonfailures" in lowered
            or "invalidpassword" in lowered
            or "twofactor" in lowered
            or "invalidauthcode" in lowered
        )

    def _send_trade_worker(self, selected_accounts, trade_link, inventory_string, script_path, on_trade_sent=None):
        script_dir = os.path.dirname(script_path)

        if not self._ensure_looter_dependencies(script_dir):
            return

        for acc in selected_accounts:
            if not acc.shared_secret:
                self._logManager.add_log(f"⚠️ [{acc.login}] Нет shared_secret (mafile), пропускаю")
                continue

            if not getattr(acc, "identity_secret", None):
                self._logManager.add_log(f"⚠️ [{acc.login}] Нет identity_secret (mafile), пропускаю")
                continue

            cmd = [
                "node",
                script_path,
                acc.login,
                acc.password,
                acc.shared_secret,
                acc.identity_secret,
                trade_link,
                inventory_string,
            ]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=180,
                    cwd=script_dir,
                    env={**os.environ, "NODE_NO_WARNINGS": "1"},
                )
            except FileNotFoundError:
                self._logManager.add_log("❌ Не найден Node.js (команда node)")
                return
            except subprocess.TimeoutExpired:
                self._logManager.add_log(f"⏰ [{acc.login}] Таймаут отправки трейда (180с)")
                continue
            except Exception as exc:
                self._logManager.add_log(f"❌ [{acc.login}] Ошибка отправки трейда: {exc}")
                continue

            stdout = (result.stdout or "").strip()
            stderr = (result.stderr or "").strip()

            if result.returncode == 0:
                sent_count = 0
                for line in stdout.splitlines():
                    if line.startswith("SENT_ITEMS_COUNT:"):
                        try:
                            sent_count = int(line.split(":", 1)[1].strip())
                        except ValueError:
                            sent_count = 0
                        break

                self._logManager.add_log(f"{acc.login} succesfull send trade: {sent_count}")
                if callable(on_trade_sent):
                    try:
                        on_trade_sent(acc.login)
                    except Exception:
                        pass
            elif result.returncode == 10:
                self._logManager.add_log(f"{acc.login} inventory is empty")
            else:
                error_line = self._extract_looter_error(stdout, stderr)
                if self._is_authorization_error(error_line):
                    self._logManager.add_log(f"❌ [{acc.login}] Ошибка авторизации")
                elif error_line:
                    self._logManager.add_log(f"❌ [{acc.login}] Ошибка при отправке трейда: (проверьте на наличие блокировок)")
                else:
                    self._logManager.add_log(f"❌ [{acc.login}] Ошибка при отправке трейда (проверьте на наличие блокировок)")

    def _run_install_command(self, cmd, cwd, timeout=300):
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            self._logManager.add_log("❌ Установка зависимостей не успела завершиться (таймаут 300с)")
            return False
        except Exception as exc:
            self._logManager.add_log(f"❌ Ошибка запуска установщика зависимостей: {exc}")
            return False

    def _install_looter_dependencies(self, script_dir):
        attempted = []

        install_commands = [
            ["npm", "install", "--no-audit", "--no-fund"],
            ["npm.cmd", "install", "--no-audit", "--no-fund"],
            ["corepack", "npm", "install", "--no-audit", "--no-fund"],
        ]

        for cmd in install_commands:
            attempted.append(" ".join(cmd))
            result = self._run_install_command(cmd, script_dir)
            if result is None:
                continue
            if result is False:
                return False
            return result

        node_path = shutil.which("node")
        if node_path:
            node_dir = os.path.dirname(node_path)
            npm_cli_candidates = [
                os.path.join(node_dir, "node_modules", "npm", "bin", "npm-cli.js"),
                os.path.join(node_dir, "..", "node_modules", "npm", "bin", "npm-cli.js"),
                os.path.join(
                    os.environ.get("ProgramFiles", "C:/Program Files"),
                    "nodejs",
                    "node_modules",
                    "npm",
                    "bin",
                    "npm-cli.js",
                ),
            ]

            for cli_path in npm_cli_candidates:
                cli_path = os.path.abspath(cli_path)
                if not os.path.isfile(cli_path):
                    continue

                cmd = ["node", cli_path, "install", "--no-audit", "--no-fund"]
                attempted.append(" ".join(cmd))
                result = self._run_install_command(cmd, script_dir)
                if result is None:
                    continue
                if result is False:
                    return False
                return result

        self._logManager.add_log("❌ Не удалось найти рабочий npm installer автоматически")
        if attempted:
            self._logManager.add_log("⚠️ Пробовал: " + " || ".join(attempted))
        self._logManager.add_log("⚠️ Установите Node.js LTS (включая npm) и перезапустите приложение")
        return None

    def _ensure_looter_dependencies(self, script_dir):
        package_json_path = os.path.join(script_dir, "package.json")
        if not os.path.isfile(package_json_path):
            self._logManager.add_log("❌ package.json для looter не найден. Переустановите сборку")
            return False

        steam_user_module = os.path.join(script_dir, "node_modules", "steam-user")
        if os.path.isdir(steam_user_module):
            return True

        self._logManager.add_log("📦 Не найдены Node.js зависимости looter. Выполняю авто-установку...")

        install_result = self._install_looter_dependencies(script_dir)
        if install_result is None:
            return False
        if install_result is False:
            return False

        if install_result.returncode != 0:
            stdout_tail = " | ".join((install_result.stdout or "").splitlines()[-8:])
            stderr_tail = " | ".join((install_result.stderr or "").splitlines()[-8:])
            self._logManager.add_log(f"❌ npm install завершился с code={install_result.returncode}")
            if stdout_tail:
                self._logManager.add_log(f"📄 npm stdout: {stdout_tail}")
            if stderr_tail:
                self._logManager.add_log(f"⚠️ npm stderr: {stderr_tail}")
            return False

        if not os.path.isdir(steam_user_module):
            self._logManager.add_log("❌ После npm install модуль steam-user всё ещё отсутствует")
            return False

        self._logManager.add_log("✅ Node.js зависимости looter установлены")
        return True

    def _normalize_inventory_string(self, inventory_string):
        pairs = []
        normalized_raw = (
            (inventory_string or "")
            .replace(';', ',')
            .replace('\n', ',')
            .replace('\t', ',')
            .replace(' ', ',')
        )
        for raw_pair in normalized_raw.split(','):
            pair = raw_pair.strip()
            if not pair:
                continue

            if pair == "400/2":
                self._logManager.add_log("⚠️ Исправил appid 400/2 -> 440/2 (TF2)")
                pair = "440/2"

            if '/' not in pair:
                self._logManager.add_log(f"⚠️ Пропущен некорректный inventory pair: {pair}")
                continue

            app_id, context_id = [v.strip() for v in pair.split('/', 1)]
            if not app_id.isdigit() or not context_id.isdigit():
                self._logManager.add_log(f"⚠️ Пропущен некорректный inventory pair: {pair}")
                continue

            normalized_pair = f"{app_id}/{context_id}"
            if normalized_pair not in pairs:
                pairs.append(normalized_pair)

        return ','.join(pairs)


# ===== Inlined from ui/control_frame.py =====
import sys
import customtkinter
import os
import psutil
import ctypes
import json
import shutil
import win32gui
import win32process
import win32con
import time
import threading
import keyboard
from Managers.AccountsManager import AccountManager
from Managers.LogManager import LogManager
from Managers.SettingsManager import SettingsManager


class ControlFrame(customtkinter.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, width=250)
        self.logManager = LogManager()
        self.accounts_list_frame = None

        self.grid(row=1, column=3, padx=(20, 20), pady=(20, 0), sticky="nsew")

        data = [
            ("Move all CS windows", None, self.move_all_cs_windows),
            ("Kill ALL CS & Steam processes", "red", self.kill_all_cs_and_steam),
            ("Launch BES", "darkgreen", self.launch_bes),
            ("Launch SRT", "darkgreen", self.launch_srt),
            ("Support Developer", "darkgreen", self.sendCasesMe),
        ]

        for text, color, func in data:
            b = customtkinter.CTkButton(self, text=text, fg_color=color, command=func)
            b.pack(pady=10)

    def _load_runtime_maps(self):
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        runtime_path = os.path.join(project_root, "runtime.json")

        login_to_pid = {}
        pid_to_login = {}

        with open(runtime_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for item in data:
            login = item.get("login")
            cs2_pid = item.get("CS2Pid")
            if not login or cs2_pid is None:
                continue
            try:
                pid = int(cs2_pid)
            except (TypeError, ValueError):
                continue
            login_to_pid[login] = pid
            pid_to_login[pid] = login

        return login_to_pid, pid_to_login

    @staticmethod
    def _get_active_cs2_pids():
        pids = set()
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if (proc.info.get("name") or "").lower() == "cs2.exe":
                    pids.add(proc.info["pid"])
            except Exception:
                pass
        return pids

    def move_all_cs_windows(self):
        print("🔀 Расстановка окон CS2 по порядку аккаунтов...")

        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

        window_width = 383
        window_height = 280
        spacing = 0

        # 1) Порядок строго из аккаунтов в UI
        accounts_order = [acc.login for acc in AccountManager().accounts]
        if not accounts_order:
            print("❌ Список аккаунтов пуст")
            return

        # 2) runtime.json -> карты login<->pid
        try:
            login_to_pid, pid_to_login = self._load_runtime_maps()
        except Exception as e:
            print(f"❌ Ошибка чтения runtime.json: {e}")
            return

        print(f"✅ КАРТА runtime.json: {len(login_to_pid)} login→pid")

        active_cs2_pids = self._get_active_cs2_pids()
        if not active_cs2_pids:
            print("❌ Активные cs2.exe процессы не найдены")
            return

        # 3) Ищем окна только для активных cs2 pid
        hwnd_by_pid = {}

        def enum_cb(hwnd, _):
            try:
                if not win32gui.IsWindowVisible(hwnd) or not win32gui.IsWindowEnabled(hwnd):
                    return True
                if win32gui.GetParent(hwnd) != 0:
                    return True

                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if pid not in active_cs2_pids:
                    return True
                if pid in hwnd_by_pid:
                    return True

                title = win32gui.GetWindowText(hwnd)
                if not title:
                    return True

                hwnd_by_pid[pid] = hwnd

                # по возможности нормализуем заголовок
                login = pid_to_login.get(pid)
                if login:
                    try:
                        win32gui.SetWindowText(hwnd, f"[FSN] {login}")
                    except Exception:
                        pass
            except Exception:
                pass
            return True

        win32gui.EnumWindows(enum_cb, None)

        # 4) Строим упорядоченный список окон строго по accounts_order
        ordered_windows = []
        for login in accounts_order:
            pid = login_to_pid.get(login)
            hwnd = hwnd_by_pid.get(pid)
            if hwnd and win32gui.IsWindow(hwnd):
                ordered_windows.append((login, pid, hwnd))

        if not ordered_windows:
            print("❌ Не найдено подходящих окон CS2 для расстановки")
            return

        # 5) Ставим в линию 1-2-3-4... по списку аккаунтов
        placed = 0
        for idx, (login, pid, hwnd) in enumerate(ordered_windows):
            x = idx * (window_width + spacing)
            y = 0
            try:
                win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                win32gui.MoveWindow(hwnd, x, y, window_width, window_height, True)
                print(f"📍 {idx + 1}. {login} (PID {pid}) -> ({x},{y})")
                placed += 1
            except Exception as e:
                print(f"⚠️ Не удалось переместить {login}: {e}")

        print(f"✅ Размещено окон: {placed}")

        if self.accounts_list_frame:
            self.accounts_list_frame.set_green_for_launched_cs2(active_cs2_pids)

    def check_cs2_and_update_colors(self):
        launched_pids = self._get_active_cs2_pids()
        if self.accounts_list_frame:
            self.accounts_list_frame.set_green_for_launched_cs2(launched_pids)

    def set_accounts_list_frame(self, frame):
        self.accounts_list_frame = frame

    def sendCasesMe(self):
        os.system("start https://steamcommunity.com/tradeoffer/new/?partner=1820312068&token=IfT_ec3_")

    def kill_all_cs_and_steam(self):
        """💀 УБИВАЕТ ВСЕ CS2 & Steam процессы + ПРАВИЛЬНЫЕ ЦВЕТА (оранжевые НЕ трогаем!)"""
        print("💀 УБИВАЮ ВСЕ CS2 & Steam процессы!")
        killed = 0
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = (proc.info.get("name") or "").lower()
                if "cs2" in name or "steam" in name or "csgo" in name:
                    proc.kill()
                    print(f"💀 [{proc.info['pid']}] {proc.info.get('name')}")
                    killed += 1
            except Exception:
                pass
        print(f"✅ УБИТО {killed} процессов!")

        try:
            account_manager = AccountManager()
            for acc in account_manager.accounts:
                if hasattr(acc, "steamProcess"):
                    acc.steamProcess = None
                if hasattr(acc, "CS2Process"):
                    acc.CS2Process = None
                if self.accounts_list_frame and self.accounts_list_frame.is_farmed_account(acc):
                    acc.setColor("#ff9500")
                elif self.accounts_list_frame and self.accounts_list_frame.is_drop_ready_account(acc):
                    acc.setColor("#a855f7")
                else:
                    acc.setColor("#DCE4EE")
        except Exception as e:
            print(f"⚠️ Ошибка UI: {e}")

        if self.accounts_list_frame:
            self.accounts_list_frame.update_label()

        self._clear_steam_userdata()

    def _clear_steam_userdata(self):
        settings_manager = SettingsManager()
        steam_path = settings_manager.get("SteamPath", r"C:\\Program Files (x86)\\Steam\\steam.exe")
        steam_dir = os.path.dirname(steam_path)
        userdata_path = os.path.join(steam_dir, "userdata")
        if not os.path.isdir(userdata_path):
            print(f"⚠️ userdata папка не найдена: {userdata_path}")
            return

        removed = 0
        for entry in os.listdir(userdata_path):
            entry_path = os.path.join(userdata_path, entry)
            try:
                if os.path.isdir(entry_path):
                    shutil.rmtree(entry_path, ignore_errors=True)
                else:
                    os.remove(entry_path)
                removed += 1
            except Exception as exc:
                print(f"⚠️ Не удалось удалить {entry_path}: {exc}")

        print(f"🧹 userdata очищена, удалено элементов: {removed}")

    def launch_bes(self):
        base_path = (
            os.path.dirname(sys.executable)
            if getattr(sys, "frozen", False)
            else os.path.dirname(os.path.abspath(sys.argv[0]))
        )
        bes_path = os.path.join(base_path, "BES", "BES.exe")
        if os.path.exists(bes_path):
            try:
                os.startfile(bes_path)
                print("✅ BES запущен!")
            except Exception as e:
                print(f"❌ Ошибка BES: {e}")
        else:
            print(f"❌ BES.exe не найден: {bes_path}")

    def launch_srt(self):
        base_path = (
            os.path.dirname(sys.executable)
            if getattr(sys, "frozen", False)
            else os.path.dirname(os.path.abspath(sys.argv[0]))
        )
        srt_path = os.path.join(base_path, "SteamRouteTool", "SteamRouteTool.exe")
        if os.path.exists(srt_path):
            try:
                os.startfile(srt_path)
                print("✅ SRT запущен!")
            except Exception as e:
                print(f"❌ Ошибка SRT: {e}")
        else:
            print(f"❌ SRT.exe не найден: {srt_path}")

    def auto_move_after_4_cs2(self, delay=1, callback=None, cancel_check=None):
        """Ждёт 4 окна CS2, двигает их, вызывает callback"""
        threading.Thread(
            target=self._wait_4_cs2_and_move,
            args=(delay, callback, cancel_check),
            daemon=True,
        ).start()
    def _press_ctrl_q(self):
        try:
            keyboard.press_and_release("ctrl+q")

            return True
        except Exception as e:
            self.logManager.add_log(f"⚠️ AUTO: failed to press Ctrl+Q: {e}")
            return False
    def _wait_4_cs2_and_move(self, delay, callback, cancel_check):
        """Внутренний метод ожидания + перемещения"""
        print("👀 Ожидаю запуск 4 CS2...")

        start_detect_time = None

        while True:
            if cancel_check and cancel_check():
                self.logManager.add_log("🛑 Auto move отменён")
                return

            cs2_pids = list(self._get_active_cs2_pids())

            if len(cs2_pids) >= 4:
                if start_detect_time is None:
                    start_detect_time = time.time()
                    self.logManager.add_log(f"⏳ Найдено 4 CS2 → жду {delay} сек")
                elif time.time() - start_detect_time >= delay:
                    if cancel_check and cancel_check():
                        self.logManager.add_log("🛑 Auto move отменён")
                        return

                    self.logManager.add_log("🚀 Таймер истёк → Make lobbies + Start Game")
                    self.move_all_cs_windows()



                    self._press_ctrl_q()
                    if callback:
                        try:
                            if cancel_check and cancel_check():
                                self.logManager.add_log("🛑 Callback отменён")
                                return
                            callback()
                        except Exception as e:
                            self.logManager.add_log(f"❌ Callback error: {e}")
                    return
            else:
                start_detect_time = None

            time.sleep(2)


# ===== Inlined from ui/main_menu.py =====
import customtkinter
import threading
import time
import keyboard

from Managers.AccountsManager import AccountManager
from Managers.LobbyManager import LobbyManager
from Managers.LogManager import LogManager
from Managers.SettingsManager import SettingsManager
from Modules.AutoAcceptModule import AutoAcceptModule


class MainMenu(customtkinter.CTkTabview):
    def __init__(self, parent):
        super().__init__(parent, width=250)
        self.grid(row=0, column=2, padx=(20, 0), pady=(0, 0), sticky="nsew")

        self._create_main_tab()

        self._logManager = LogManager()
        self._accountManager = AccountManager()
        self._lobbyManager = LobbyManager()
        self._settingsManager = SettingsManager()
        self.auto_accept_module = AutoAcceptModule()

        auto_accept_enabled = bool(self._settingsManager.get("AutoAcceptEnabled", True))
        if auto_accept_enabled:
            self.auto_accept_module.start()
            print("🚀 AutoAcceptModule: АВТОЗАПУСК ✓")

        self._create_buttons([
            ("Make lobbies", "darkgreen", self.make_lobbies),
            ("Disband lobbies", "darkblue", self.disband_lobbies),
            ("Shuffle lobbies", "darkblue", self.shuffle_lobbies),
            ("Make lobbies & Search game", "purple", self.make_lobbies_and_search_game),
        ])

        self._create_toggle("Auto Accept Game", self.toggle_auto_accept, default_value=auto_accept_enabled)

        self._cancel_requested = False
        self._hotkey_registered = False
        self._active_action_name = None
        self._cancel_notified_for_action = None
        self._last_hotkey_ts = 0.0
        self._register_global_cancel_hotkey()

    def _create_main_tab(self):
        self.add("Main Menu")
        self.tab("Main Menu").grid_columnconfigure(0, weight=1)

    def _create_buttons(self, buttons_data):
        self.buttons = {}
        for i, (text, color, command) in enumerate(buttons_data):
            button = customtkinter.CTkButton(
                self.tab("Main Menu"),
                text=text,
                fg_color=color,
                command=command
            )
            button.grid(row=i, column=0, padx=20, pady=10, sticky="ew")
            self.buttons[text] = button

    def _create_toggle(self, text, command, default_value=False):
        self.toggles = getattr(self, "toggles", {})
        toggle = customtkinter.CTkSwitch(
            self.tab("Main Menu"),
            text=text,
            command=command
        )
        toggle.grid(row=len(self.buttons) + len(self.toggles), column=0, padx=20, pady=10)
        if default_value:
            toggle.select()
        else:
            toggle.deselect()
        self.toggles[text] = toggle

    def _register_global_cancel_hotkey(self):
        if self._hotkey_registered:
            return
        try:
            keyboard.add_hotkey('ctrl+q', self._on_global_cancel_hotkey)
            self._hotkey_registered = True
            print("✅ Global Ctrl+Q hotkey registered")
        except Exception as e:
            print(f"⚠️ Cannot register global Ctrl+Q hotkey: {e}")

    def _on_global_cancel_hotkey(self):
        # анти-флуд: suppress key-repeat storms
        now = time.time()
        if now - self._last_hotkey_ts < 0.25:
            return
        self._last_hotkey_ts = now
        self._cancel_requested = True

    def _is_cancelled(self):
        if self._cancel_requested:
            return True
        try:
            return keyboard.is_pressed('ctrl+q')
        except Exception:
            return False

    def _format_cancel_message(self, action_name):
        mapping = {
            "Make lobbies": "Make lobbies",
            "Disband lobbies": "Disband lobbies",
            "Shuffle lobbies": "Shuffle lobbies",
            "Make lobbies & Search game": "Make lobbies & Search game",
        }
        return mapping.get(action_name or "", "Canceled action")

    def _notify_cancel_once(self, action_name):
        if self._cancel_notified_for_action == action_name:
            return
        self._cancel_notified_for_action = action_name
        msg = self._format_cancel_message(action_name)
        try:
            self._logManager.add_log(msg)
        except Exception:
            pass
        print(f"🛑 {msg}")

    def toggle_auto_accept(self):
        self.auto_accept_module.toggle()
        status = 'ON' if self.auto_accept_module._running else 'OFF'
        print(f"🔄 Auto Accept Game: {status}")
        self._lobbyManager.auto_accept = self.auto_accept_module._running
        self._settingsManager.set("AutoAcceptEnabled", self.auto_accept_module._running)
    def _set_all_buttons_state(self, state):
        for button in self.buttons.values():
            try:
                button.configure(state=state)
            except Exception:
                pass
    # -----------------------------
    # Universal countdown runner on button
    # -----------------------------
    def run_with_countdown_on_button(
        self,
        button_text,
        action,
        message="Completed",
        message_in_run="Running...",
        countdown=3,
        message_time=1
    ):
        button = self.buttons.get(button_text)
        if not button:
            return

        original_text = button.cget("text")
        self._active_action_name = button_text
        self._cancel_notified_for_action = None
        self._cancel_requested = False
        self._set_all_buttons_state("disabled")
        self._countdown_step(button, action, original_text, countdown, message, message_in_run, message_time)

    def _countdown_step(self, button, action, original_text, seconds, message, message_in_run, message_time):
        if self._is_cancelled():
            self._notify_cancel_once(self._active_action_name)
            button.configure(text=self._format_cancel_message(self._active_action_name), state="disabled")
            self.after(message_time * 1000, lambda: self._reset_button_text(button, original_text))
            return

        if seconds > 0:
            button.configure(text=f"{seconds}...")
            self.after(1000, lambda: self._countdown_step(
                button, action, original_text, seconds - 1, message, message_in_run, message_time
            ))
        else:
            button.configure(text=message_in_run)
            self.after(100, lambda: self._run_action_on_button(
                button, action, original_text, message, message_time
            ))

    def _run_action_on_button(self, button, action, original_text, message, message_time):
        def worker():
            ok = False
            cancelled = False
            try:

                if self._is_cancelled():
                    cancelled = True
                else:
                    res = action()
                    ok = bool(res) if res is not None else True
                    if not ok and self._is_cancelled():
                        cancelled = True
            except Exception as e:
                print(f"❌ Action error: {e}")
                ok = False

            def ui_done():

                if cancelled:
                    self._notify_cancel_once(self._active_action_name)
                    button.configure(text=self._format_cancel_message(self._active_action_name), state="disabled")
                else:
                    button.configure(text=message if ok else "Failed", state="disabled")
                self.after(message_time * 1000, lambda: self._reset_button_text(button, original_text))

            self.after(0, ui_done)

        threading.Thread(target=worker, daemon=True).start()

    def _reset_button_text(self, button, original_text):
        button.configure(text=original_text)
        self._set_all_buttons_state("normal")
        self._active_action_name = None

    # -----------------------------
    # Button actions
    # -----------------------------
    def make_lobbies(self):
        self.run_with_countdown_on_button(
            button_text="Make lobbies",
            action=self._lobbyManager.CollectLobby,
            message="Completed",
            message_in_run="Collecting lobbies...",
            countdown=3,
            message_time=1
        )

    def disband_lobbies(self):
        self.run_with_countdown_on_button(
            button_text="Disband lobbies",
            action=self._lobbyManager.DisbandLobbies,
            message="Completed",
            message_in_run="Disbanding lobbies...",
            countdown=1,
            message_time=1
        )

    def shuffle_lobbies(self):

        self.run_with_countdown_on_button(
            button_text="Shuffle lobbies",
            action=self._lobbyManager.Shuffle,
            message="Completed",
            message_in_run="Shuffling lobbies...",
            countdown=1,
            message_time=1
        )

    def make_lobbies_and_search_game(self):
        self.run_with_countdown_on_button(
            button_text="Make lobbies & Search game",
            action=self._lobbyManager.MakeLobbiesAndSearchGame,
            message="Completed",
            message_in_run="Making lobbies & Search",
            countdown=3,
            message_time=1
        )

    def trigger_make_lobbies_and_search_game_auto(self):
        """Надёжно имитирует клик по кнопке Main Menu для авто-сценария."""
        button_text = "Make lobbies & Search game"
        button = self.buttons.get(button_text)
        if not button:
            self._logManager.add_log("❌ Main Menu button not found: Make lobbies & Search game")
            return False

        try:
            if str(button.cget("state")) == "disabled":
                self._logManager.add_log("⚠️ Main Menu button is disabled: Make lobbies & Search game")
                return False
        except Exception:
            pass

        try:
            button.invoke()
            return True
        except Exception as e:
            self._logManager.add_log(f"❌ Button invoke error: {e}")
            return False


# ===== Inlined from ui/sidebar.py =====
import customtkinter

class Sidebar(customtkinter.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, width=140, corner_radius=0)
        self.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.grid_rowconfigure(4, weight=1)

        self.logo_label = customtkinter.CTkLabel(self, text="Actuality 23.02", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.version_label = customtkinter.CTkLabel(self, text="Beta Replic Panel", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.version_label.grid(row=1, column=0, padx=20, pady=(20, 10))

        self.appearance_mode_label = customtkinter.CTkLabel(self, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=5, column=0, padx=20, pady=(10, 0))

        self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self, values=["Light","Dark","System"], command=self.change_appearance_mode)
        self.appearance_mode_optionemenu.grid(row=6, column=0, padx=20, pady=(10, 10))

        self.scaling_label = customtkinter.CTkLabel(self, text="UI Scaling:", anchor="w")
        self.scaling_label.grid(row=7, column=0, padx=20, pady=(10, 0))

        self.scaling_optionemenu = customtkinter.CTkOptionMenu(self, values=["80%","90%","100%","110%","120%"], command=self.change_scaling)
        self.scaling_optionemenu.grid(row=8, column=0, padx=20, pady=(10, 20))

    def set_defaults(self):
        self.appearance_mode_optionemenu.set("Dark")
        self.scaling_optionemenu.set("100%")

    def change_appearance_mode(self, mode):
        customtkinter.set_appearance_mode(mode)

    def change_scaling(self, value):
        customtkinter.set_widget_scaling(int(value.replace("%",""))/100)
