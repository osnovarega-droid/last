import time

import pyautogui
import pyperclip
import win32gui
import win32con
import win32process
import keyboard
import psutil

from Helpers.MouseController import MouseHelper


class LobbyInstance:
    def __init__(self, leader, bots):
        self.leader = leader
        self.bots = bots

    @staticmethod
    def _is_cancelled():
        try:
            return keyboard.is_pressed("ctrl+q")
        except Exception:
            return False

    @staticmethod
    def _focus_window(hwnd):
        try:
            if not hwnd or not win32gui.IsWindow(hwnd):
                return False

            try:
                win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
            except Exception:
                pass

            if not win32gui.IsWindow(hwnd):
                return False

            try:
                win32gui.BringWindowToTop(hwnd)
            except Exception:
                pass

            if not win32gui.IsWindow(hwnd):
                return False

            try:
                win32gui.SetForegroundWindow(hwnd)
            except Exception:
                return False

            return True
        except Exception:
            return False


    @staticmethod
    def _is_cs2_process(pid):
        if not pid:
            return False
        try:
            proc = psutil.Process(pid)
            return (proc.name() or "").lower() == "cs2.exe"
        except Exception:
            return False

    def _resolve_member_cs2_hwnd(self, member):
        hwnd = 0
        try:
            hwnd = member.FindCSWindow()
        except Exception:
            hwnd = 0

        if hwnd and win32gui.IsWindow(hwnd):
            try:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
            except Exception:
                pid = 0
            if self._is_cs2_process(pid):
                return hwnd

        pid = 0
        try:
            if getattr(member, 'CS2Process', None):
                pid = member.CS2Process.pid
        except Exception:
            pid = 0

        if not self._is_cs2_process(pid):
            return 0

        candidates = []

        def enum_cb(enum_hwnd, _):
            try:
                if not win32gui.IsWindow(enum_hwnd):
                    return True
                if not win32gui.IsWindowVisible(enum_hwnd):
                    return True
                if win32gui.GetParent(enum_hwnd) != 0:
                    return True

                _, hwnd_pid = win32process.GetWindowThreadProcessId(enum_hwnd)
                if hwnd_pid != pid:
                    return True

                rect = win32gui.GetWindowRect(enum_hwnd)
                area = max(0, rect[2] - rect[0]) * max(0, rect[3] - rect[1])
                if area <= 0:
                    return True

                candidates.append((area, rect[0], rect[1], enum_hwnd))
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(enum_cb, None)
        except Exception:
            return 0

        if not candidates:
            return 0

        candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
        return candidates[0][3]

    def _resolve_member_hwnd(self, member):
        """CS2-aware HWND with safe fallback to raw FindCSWindow when needed."""
        hwnd = self._resolve_member_cs2_hwnd(member)
        if hwnd and win32gui.IsWindow(hwnd):
            return hwnd

        try:
            fallback = member.FindCSWindow()
        except Exception:
            fallback = 0

        if fallback and win32gui.IsWindow(fallback):
            return fallback

        return 0

    def _focus_member(self, member, retries=3, delay=0.12):
        for _ in range(max(1, retries)):
            hwnd = self._resolve_member_hwnd(member)
            if hwnd and self._focus_window(hwnd):
                return hwnd
            time.sleep(delay)
        return 0

    def Collect(self):
        leader_hwnd = self._focus_member(self.leader)
        if not leader_hwnd:
            return False

        for bot in self.bots:
            if self._is_cancelled():
                return False

            bot_hwnd = self._focus_member(bot)
            if not bot_hwnd:
                return False

            time.sleep(0.1)
            bot.MoveMouse(380, 100)
            time.sleep(0.5)
            bot.ClickMouse(375, 8)
            time.sleep(0.5)
            bot.ClickMouse(375, 8)
            time.sleep(0.5)
            bot.ClickMouse(204, 157)
            time.sleep(0.5)
            bot.ClickMouse(237, 157)

            if self._is_cancelled():
                return False

            leader_hwnd = self._focus_member(self.leader)
            if not leader_hwnd:
                return False

            self.leader.MoveMouse(380, 100)
            time.sleep(0.6)
            self.leader.ClickMouse(375, 8)
            time.sleep(1)
            MouseHelper.PasteText()
            time.sleep(1)
            self.leader.ClickMouse(195, 140)
            time.sleep(1.5)
            for i in range(142, 221, 5):
                self.leader.ClickMouse(235, i)
                time.sleep(0.001)
            self.leader.ClickMouse(235, 165)

        time.sleep(1.5)

        for bot in self.bots:
            if self._is_cancelled():
                return False
            bot_hwnd = self._focus_member(bot)
            if not bot_hwnd:
                return False
            bot.MoveMouse(380, 100)
            time.sleep(0.6)
            bot.ClickMouse(306, 37)

        return True

    def Disband(self):
        # По ТЗ disband должен работать строго с bot1/bot2.
        primary_bots = self.bots[:1]

        for bot in primary_bots:
            if self._is_cancelled():
                return False
            bot_hwnd = self._focus_member(bot)
            if not bot_hwnd:
                return False
            time.sleep(0.1)
            bot.MoveMouse(380, 100)
            time.sleep(0.5)
            bot.ClickMouse(375, 8)

        return True