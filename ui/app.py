import json
import os
import queue
import re
import subprocess
import uuid
import hashlib
import sys
import base64
import secrets
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
from .accounts_list_frame import AccountsListFrame
from .accounts_tab import AccountsControl
from .config_tab import ConfigTab
from .control_frame import ControlFrame
from .main_menu import MainMenu

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
LICENSE_TOKEN_TTL_GRACE_SECONDS = 5

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
                creationflags=subprocess.CREATE_NO_WINDOW,
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
            subprocess.run(["powershell", "-Command", cmd], creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

    def get_blocked_regions(self):
        try:
            cmd = (
                f'Get-NetFirewallRule -DisplayName "{self.PREFIX}*" -ErrorAction SilentlyContinue '
                '| Select-Object -ExpandProperty DisplayName'
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
                    '| Select-Object -ExpandProperty Name'
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
                blocked_regions.add(rule_name[len(self.PREFIX):])
            return blocked_regions
        except Exception:
            return set()

class App(customtkinter.CTk):
    def __init__(self, gsi_manager=None, startup_gpu_info=None):
        super().__init__()
        self.title("Goose Panel | v.4.0.2")
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
        self.http_session = requests.Session()
        self.http_session.verify = True
        
        self.geometry("1100x600")
        self.minsize(1100, 600)
        self.maxsize(1100, 600)
        self.configure(fg_color=BG_MAIN)
        self._load_window_position()

        base_path = Path(sys._MEIPASS) if hasattr(sys, "_MEIPASS") else Path(__file__).parent.parent
        icon_path = Path(base_path) / "Icon1.ico"
        if icon_path.exists():
            self.iconbitmap(icon_path)

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
        self._create_hidden_legacy_controllers()
        self._build_layout()

        self._connect_gsi_to_ui()
        self._log_startup_gpu_info(startup_gpu_info)

        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.show_section("license")
        self._start_ui_actions_pump()
        self._start_runtime_status_tracking()
        self._start_background_check()
        
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
        future = self.executor.submit(fn)

        def on_done(done_future):
            if not self.winfo_exists():
                return
            if done_callback:
                self.after(0, lambda: done_callback(done_future))

        future.add_done_callback(on_done)

    def _safe_ui_refresh(self):
        if not self.winfo_exists():
            return
        self._sync_switches_with_selection()
        self._update_accounts_info()

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

    def _build_layout(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = customtkinter.CTkFrame(self, width=200, corner_radius=1, fg_color=BG_PANEL, border_width=1, border_color=BG_BORDER)
        self.sidebar.grid(row=0, column=0, sticky="nsew", padx=(1, 1), pady=1)
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_rowconfigure(7, weight=1)

        customtkinter.CTkLabel(self.sidebar, text="Goose Panel", font=customtkinter.CTkFont(size=20, weight="bold"), text_color=TXT_MAIN).grid(row=0, column=0, padx=10, pady=(10, 4), sticky="w")

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

        logs_wrap = customtkinter.CTkFrame(self.sidebar, width=197, fg_color=BG_CARD_ALT, corner_radius=1, border_width=1, border_color=BG_BORDER)
        logs_wrap.grid(row=7, column=0, padx=2, pady=(2, 2), sticky="nsew")
        logs_wrap.grid_propagate(False)
        logs_wrap.grid_columnconfigure(0, weight=1)
        logs_wrap.grid_rowconfigure(1, weight=1)

        customtkinter.CTkLabel(logs_wrap, text="• Logs", text_color=TXT_MAIN, font=customtkinter.CTkFont(size=15, weight="bold")).grid(row=0, column=0, padx=8, pady=(6, 2), sticky="w")

        self.logs_box = customtkinter.CTkTextbox(logs_wrap, width=250, fg_color="#0e1428", text_color="#98a7cf", border_width=0, corner_radius=8, wrap="word", font=customtkinter.CTkFont(size=11))
        self.logs_box.grid(row=1, column=0, padx=2, pady=(0, 2), sticky="nsew")
        self.log_manager.textbox = self.logs_box

        self.content = customtkinter.CTkFrame(self, fg_color=BG_PANEL, corner_radius=12, border_width=1, border_color=BG_BORDER)
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

    def _reset_windows_proxy(self):
        if not sys.platform.startswith("win"):
            self.log_manager.add_log("⚠️ Reset доступен только на Windows")
            return

        self.log_manager.add_log("🔄 Reset: сброс proxy...")

        commands = [
            # Удаляем SRT firewall-правила (по Name и DisplayName)
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", 'Remove-NetFirewallRule -Name "FSN_Route_*" -ErrorAction SilentlyContinue; Get-NetFirewallRule -DisplayName "FSN_Route_*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue'],
            ["netsh", "advfirewall", "firewall", "delete", "rule", "name=FSN_Route_*"],

            # WinHTTP proxy -> direct
            ["netsh", "winhttp", "reset", "proxy"],

            # WinINET proxy (текущий пользователь)
            ["reg", "add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"],
            ["reg", "add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "/v", "ProxyServer", "/t", "REG_SZ", "/d", "", "/f"],
            ["reg", "delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "/v", "AutoConfigURL", "/f"],
            ["reg", "add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "/v", "AutoDetect", "/t", "REG_DWORD", "/d", "1", "/f"],

            # Машинные ключи (best effort, могут требовать admin)
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

        direct_markers = (
            "direct access",
            "прямой доступ",
            "without proxy",
            "без прокси",
            "no proxy server",
            "нет прокси",
        )
        has_proxy_markers = (
            "proxy server",
            "прокси-сервер",
            "proxy-server",
        )

        is_direct = any(marker in verify_text for marker in direct_markers)
        if not is_direct and verify_text:
            is_direct = not any(marker in verify_text for marker in has_proxy_markers)

        if is_direct:
            self.log_manager.add_log("✅ Reset завершен: proxy очищен")
        elif command_errors:
            self.log_manager.add_log("⚠️ Reset частично выполнен: запустите от администратора для полного сброса")
        else:
            self.log_manager.add_log("⚠️ Reset выполнен, но WinHTTP не подтвердил direct mode")

    def _build_functional_section(self, parent):
        frame = customtkinter.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        top = customtkinter.CTkFrame(frame, fg_color="transparent")
        top.grid(row=0, column=0, padx=10, pady=(8, 6), sticky="ew")
        title_frame = customtkinter.CTkFrame(top, fg_color="transparent")
        title_frame.grid(row=0, column=0, sticky="w")
        customtkinter.CTkLabel(title_frame, text="Accounts", text_color=TXT_MAIN, font=customtkinter.CTkFont(size=24, weight="bold")).grid(row=0, column=0, padx=(0, 10))

        self.accounts_info = customtkinter.CTkLabel(title_frame, text="0 accounts • 0 selected • 0 launched", text_color=TXT_MUTED, font=customtkinter.CTkFont(size=12))
        self.accounts_info.grid(row=0, column=1)

        search_wrap = customtkinter.CTkFrame(title_frame, fg_color="transparent")
        search_wrap.grid(row=0, column=2, padx=(14, 0), sticky="w")
        self.search_var = customtkinter.StringVar()
        self.search_var.trace_add("write", lambda *_: self._apply_account_filter())

        customtkinter.CTkEntry(search_wrap, textvariable=self.search_var, placeholder_text="Search", width=220, height=32, fg_color=BG_CARD, border_color=BG_BORDER, text_color=TXT_MAIN).grid(row=0, column=0)

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
            ("Support Developer", self._action_support_developer, BG_CARD_ALT),
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

            sw = customtkinter.CTkSwitch(row, text="", width=24, command=lambda a=account: self._toggle_account(a), fg_color="#2d3b60", progress_color=ACCENT_BLUE)
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

            self.account_row_items.append({
                "row": row,
                "account": account,
                "login_lower": account.login.lower(),
                "switch": sw,
                "login_label": login_label,
                "level_label": level_label,
                "badge": badge,
            })
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
        """Обновляет level/xp в UI, если level.json изменился."""
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

    def _poll_runtime_states(self):
        running_map = {}
        for item in self.account_row_items:
            account = item["account"]
            try:
                running_map[account] = account.isCSValid()
            except Exception:
                running_map[account] = False
        return running_map

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

    def _build_config_section(self, parent):
        frame = customtkinter.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)

        header = customtkinter.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, padx=12, pady=(10, 4), sticky="ew")
        customtkinter.CTkLabel(
            header,
            text="Configurations",
            font=customtkinter.CTkFont(size=24, weight="bold"),
            text_color=TXT_MAIN,
        ).grid(row=0, column=0, sticky="w")
        customtkinter.CTkLabel(
            header,
            text="Настройте автологику и пути Steam/CS2 в одном месте",
            font=customtkinter.CTkFont(size=11),
            text_color=TXT_MUTED,
        ).grid(row=1, column=0, pady=(4, 0), sticky="w")

        card = customtkinter.CTkFrame(
            frame,
            fg_color=BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=BG_BORDER,
        )
        card.grid(row=1, column=0, padx=12, pady=(0, 8), sticky="nsew")
        card.grid_columnconfigure(0, weight=1, minsize=150)
        card.grid_columnconfigure(1, weight=2, minsize=150)

        switches_card = customtkinter.CTkFrame(card, fg_color=BG_CARD_ALT, corner_radius=10, border_width=1, border_color=BG_BORDER)
        switches_card.grid(row=0, column=0, padx=(8, 4), pady=8, sticky="nsew")
        switches_card.grid_columnconfigure(0, weight=1)
        customtkinter.CTkLabel(
            switches_card,
            text="Automation",
            text_color=TXT_MAIN,
            font=customtkinter.CTkFont(size=15, weight="bold"),
        ).grid(row=0, column=0, padx=10, pady=(8, 2), sticky="w")

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

        customtkinter.CTkLabel(
            paths_card,
            text="Steam / CS2 paths",
            text_color=TXT_MAIN,
            font=customtkinter.CTkFont(size=15, weight="bold"),
        ).grid(row=0, column=0, padx=10, pady=(8, 2), sticky="w")

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

        self.config_status_label = customtkinter.CTkLabel(
            frame,
            text="",
            text_color=TXT_MUTED,
            font=customtkinter.CTkFont(size=11, weight="bold"),
        )
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
            elif not enabled and module._running:
                module.stop()
        except Exception:
            pass

    def get_hwid(self):
        mac = uuid.getnode()
        return hashlib.sha256(str(mac).encode("utf-8")).hexdigest()[:20].upper()

    def _urlsafe_b64decode(self, value):
        padding = '=' * ((4 - len(value) % 4) % 4)
        return base64.urlsafe_b64decode((value + padding).encode('utf-8'))

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

    def _request_license_state(self, hwid):
        if LICENSE_SERVER_URL.lower().startswith("http://"):
            self.log_manager.add_log("⚠️ LICENSE_SERVER_URL использует HTTP (без TLS). Используется защита подписью RSA.")

        challenge = self._request_license_challenge(hwid)
        url = f"{LICENSE_SERVER_URL}/api/check"
        response = self.http_session.post(
            url,
            json={
                "hwid": hwid,
                "challenge_id": challenge["challenge_id"],
                "nonce": challenge["nonce"],
                "ts": int(time.time()),
            },
            timeout=8,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Некорректный ответ сервера лицензий")

        signed_token = data.get("signed_token") or data.get("token")
        if signed_token:
            return self._verify_signed_token(signed_token, hwid, challenge["nonce"])

        raise ValueError(data.get("message") or "Сервер не вернул signed_token")
        
    def _verify_signed_token(self, signed_token, expected_hwid, expected_nonce=None):
        if not signed_token or '.' not in signed_token:
            raise ValueError('Подпись лицензии отсутствует')

        payload_b64, signature_b64 = signed_token.split('.', 1)
        payload_raw = self._urlsafe_b64decode(payload_b64)
        signature = self._urlsafe_b64decode(signature_b64)

        public_key = self._load_public_key()
        if public_key is None:
            raise ValueError('Отсутствует settings/license_public_key.pem для проверки подписи')

        try:
            rsa.verify(payload_raw, signature, public_key)
        except Exception as exc:
            raise ValueError(f'Подпись сервера не прошла проверку: {exc}') from exc

        payload = json.loads(payload_raw.decode('utf-8'))
        now_ts = int(time.time())
        iat = int(payload.get('iat', 0))
        exp = int(payload.get('exp', 0))

        if payload.get('hwid') != expected_hwid:
            raise ValueError('HWID в токене не совпадает с устройством')
        if expected_nonce and payload.get('nonce') != expected_nonce:
            raise ValueError('Nonce в токене не совпадает с запросом')
        if iat > now_ts + LICENSE_TOKEN_TTL_GRACE_SECONDS:
            raise ValueError('Токен имеет некорректный iat')
        if exp <= now_ts:
            raise ValueError('Токен лицензии истёк')
        if exp - iat > MAX_TOKEN_TTL_SECONDS:
            raise ValueError('TTL токена превышает допустимый лимит')
        if payload.get('status') != 'active':
            raise ValueError(payload.get('message') or 'Лицензия не активна')

        self.license_token = signed_token
        self.license_exp = exp
        self.license_nonce = payload.get('nonce')
        self._save_license_cache(signed_token, expected_hwid, exp)
        return payload



    def _validate_current_token(self):
        return int(time.time()) < int(self.license_exp) - LICENSE_TOKEN_TTL_GRACE_SECONDS

    def check_license_async(self, hwid):
        if self._license_check_in_flight:
            return
        self._license_check_in_flight = True
        self.log_manager.add_log(f"🔄 Проверка лицензии: {hwid}...")
        self.license_status.configure(text="Статус: Проверка...", text_color=ACCENT_ORANGE)
        self.executor.submit(self._do_check_request, hwid)


    def _do_check_request(self, hwid):


        try:
            payload = self._request_license_state(hwid)
            msg = f"Активна до {payload.get('expires_at', 'n/a')}"
            self._queue_ui_action(lambda: self._apply_license_result(True, msg))
        except Exception as exc:
            self._queue_ui_action(lambda: self._apply_license_result(False, f"Проверка не пройдена: {exc}"))
        finally:
            self._queue_ui_action(lambda: setattr(self, "_license_check_in_flight", False))

    def _start_background_check(self):
        if getattr(self, "is_unlocked", False):
            my_hwid = self.get_hwid()
            self.executor.submit(self._do_silent_check, my_hwid)

        if self.winfo_exists():
            self.after(15000, self._start_background_check)

    def _do_silent_check(self, hwid):


        try:
            if self._validate_current_token():
                return

            self._request_license_state(hwid)
        except Exception:
            if self.is_unlocked:
                self._queue_ui_action(lambda: self._apply_license_result(False, "Сеанс лицензии истёк/отозван"))
                self._queue_ui_action(
                    lambda: self.log_manager.add_log("⚠️ Сеанс прерван: нужна повторная серверная валидация лицензии.")
                )
    def _ensure_license(self):
        if not self.is_unlocked:
            self.license_status.configure(text="Статус: Обновление лицензии...", text_color=ACCENT_ORANGE)
            self.log_manager.add_log('❌ Действие заблокировано: лицензия не активна')
            return False

        if self._validate_current_token():
            return True

        self.log_manager.add_log('⚠️ Токен устарел, обновляю лицензию...')
        self.check_license_async(self.get_hwid())
        self.show_section('license')
        return False

    def _apply_license_result(self, is_valid, message):
        self.is_unlocked = is_valid

        if is_valid:
            self.license_status.configure(text=f"Статус: {message}", text_color=ACCENT_GREEN)
            self.log_manager.add_log("✅ Лицензия подтверждена сервером!")
            self.show_section(self._pending_section or "license")
        else:
            self.license_status.configure(text=f"Статус: {message}", text_color=ACCENT_RED)
            self.log_manager.add_log(f"❌ Лицензия отклонена: {message}")
            self.show_section("license")
            
    def _build_license_section(self, parent):
        frame = customtkinter.CTkFrame(parent, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BG_BORDER)
        frame.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(
            frame,
            text="License",
            font=customtkinter.CTkFont(size=30, weight="bold"),
            text_color=TXT_MAIN,
        ).grid(row=0, column=0, padx=16, pady=(20, 8), sticky="w")

        self.license_status = customtkinter.CTkLabel(
            frame,
            text="Статус: Ожидание...",
            text_color=ACCENT_ORANGE,
            font=customtkinter.CTkFont(size=14, weight="bold"),
        )
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

    def _build_stats_section(self, parent):
        frame = customtkinter.CTkFrame(parent, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BG_BORDER)
        frame.grid_columnconfigure(0, weight=1)
        customtkinter.CTkLabel(frame, text="Accs Stats", font=customtkinter.CTkFont(size=30, weight="bold"), text_color=TXT_MAIN).grid(row=0, column=0, padx=16, pady=(20, 8), sticky="w")
        return frame

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

    def _action_support_developer(self):
        if not self._ensure_license():
            return
        self._run_action_async(self.control_frame.sendCasesMe)

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

                # Используем только точные IP-адреса релэев, без расширения до /24,
                # чтобы блокировка одной-двух зон не "задевала" соседние регионы.
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
            customtkinter.CTkLabel(
                self.srt_scroll,
                text="region.json не найден или пуст",
                text_color=TXT_MUTED,
                font=customtkinter.CTkFont(size=11),
            ).grid(row=0, column=0, padx=6, pady=8, sticky="w")
            return

        for idx, region in enumerate(self.sdr_regions.keys()):
            row = customtkinter.CTkFrame(self.srt_scroll, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BG_BORDER)
            row.grid(row=idx, column=0, padx=2, pady=2, sticky="ew")
            row.grid_columnconfigure(0, weight=1)

            name_label = customtkinter.CTkLabel(row, text=region, text_color=TXT_MAIN, font=customtkinter.CTkFont(size=11, weight="bold"))
            name_label.grid(row=0, column=0, padx=(6, 2), pady=4, sticky="w")

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
            # Запускаем ping через cmd в фоне на Windows,
            # чтобы поведение совпадало с ручной командой `ping <ip>`.
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

            # Универсальный парсинг строк вида `time=24.4 ms`, `время<1мс`,
            # а также локализованных форматов, где после числа сразу идёт ms/мс/мсек.
            for m in re.finditer(r"(?:time|время)\s*[=<]?\s*([0-9]+(?:[\.,][0-9]+)?)\s*(?:ms|мс|мсек)?", out):
                try:
                    samples.append(float(m.group(1).replace(",", ".")))
                except Exception:
                    pass

            # Фолбэк: любое число рядом с суффиксом миллисекунд, если в выводе нет
            # явных time/время маркеров (встречается в некоторых локализациях/утилитах).
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
            # Linux/macOS summary: rtt min/avg/max/mdev = 11.3/22.6/...
            rtt_match = re.search(
                r"(?:rtt|round-trip)[^=]*=\s*[0-9]+(?:[\.,][0-9]+)?/([0-9]+(?:[\.,][0-9]+)?)/",
                out,
            )
            if rtt_match:
                try:
                    samples.append(float(rtt_match.group(1).replace(",", ".")))
                except Exception:
                    pass
            if samples:
                return samples[0]

            # 2) PowerShell fallback для Windows (часто устойчивее к локализации).
            if sys.platform.startswith("win"):
                ps_cmd = (
                    f'$r=Test-Connection -Count 1 -TimeoutSeconds 1 -TargetName "{host}" -ErrorAction SilentlyContinue; '
                    'if ($r) { [double]$r.Latency }'
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
                    tcp_ports = sorted({start_port, start_port + step, start_port + step * 2, end_port})
                else:
                    host = target
                    tcp_ports = None

                latency = self._measure_host_latency_ms(host, tcp_ports=tcp_ports)
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

    def _apply_section_switch(self, section_key):
        for key, frame in self.sections.items():
            if key == section_key:
                frame.grid(row=0, column=0, sticky="nsew")
            else:
                frame.grid_remove()

        for key, button in self.nav_buttons.items():
            button.configure(fg_color=BG_CARD if key == section_key else BG_CARD_ALT, border_color=ACCENT_GREEN if key == section_key else ACCENT_RED)
        self._pending_section = None
        self._section_switch_job = None

    def show_section(self, section_key):
        self._pending_section = section_key

        # Обновляем состояние и стиль кнопок в сайдбаре
        for k, button in self.nav_buttons.items():
            is_selected = (k == section_key)

            # Если лицензия не активна — разрешаем только вкладку License
            if (not getattr(self, "is_unlocked", False)) and k != "license":
                btn_state = "disabled"
            else:
                btn_state = "normal"

            button.configure(
                state=btn_state,
                fg_color=BG_CARD if is_selected else BG_CARD_ALT,
                border_color=ACCENT_GREEN if is_selected else ACCENT_RED,
            )

        # Отложенное переключение секции (анти-дребезг)
        if self._section_switch_job is not None:
            try:
                self.after_cancel(self._section_switch_job)
            except Exception:
                pass

        self._section_switch_job = self.after(
            85,
            lambda: self._apply_section_switch(self._pending_section)
    )
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
        self.executor.shutdown(wait=False, cancel_futures=True)
        try:
            self.quit()
        except Exception:
            pass
        self.destroy()
        os._exit(0)

    def update_label(self):
        self._update_accounts_info()
        self._sync_switches_with_selection()
        self._apply_account_filter()


if __name__ == "__main__":
    app = App()
    app.mainloop()
