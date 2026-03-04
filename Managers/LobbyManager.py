import ctypes
import time
import random
import psutil
import win32gui
import win32api
import win32con
import win32process
import keyboard

from Instances.LobbyInstance import LobbyInstance
from Managers.AccountsManager import AccountManager
from Managers.LogManager import LogManager
from Managers.SettingsManager import SettingsManager


class LobbyManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(LobbyManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._accountManager = AccountManager()
        self._logManager = LogManager()
        self._settingManager = SettingsManager()

        self.team1 = None
        self.team2 = None
        self._last_window_order_logins = []

        self._maps_scrolled_once = False
        self._screen_grab_warning_logged = False
        self._initialized = True

    # -----------------------------
    # Validation / lifecycle
    # -----------------------------
    def isValid(self):
        if self.team1 is None or self.team2 is None:
            return False

        if not self.team1.leader.isCSValid():
            return False
        if any(not bot.isCSValid() for bot in self.team1.bots):
            return False

        if not self.team2.leader.isCSValid():
            return False
        if any(not bot.isCSValid() for bot in self.team2.bots):
            return False

        return True

    def CollectLobby(self):
        if self._is_cancelled():
            return False

        # Жесткий анализ: фиксируем ровно 4 слота окон 1..4 и собираем лобби строго из них.
        top4 = self._get_strict_4_accounts_by_window_order()
        if not top4:
            return False
        self._build_strict_lobbies_from_4(top4)

        # Перед действиями всегда выравниваем окна в линию 1-2-3-4
        if not self.MoveWindows(ordered_logins=self._last_window_order_logins):
            return False

        if not self._has_strict_pair_windows():
            self._logManager.add_log("❌ Strict collect failed: нужны полные пары окон 1/2 и 3/4")
            return False

        if self._is_cancelled():
            return False

        if self.team1 and self.team1.Collect() is False:
            return False
        if self.team2 and self.team2.Collect() is False:
            return False

        return True

    def DisbandLobbies(self):
        if self._is_cancelled():
            return False

        # Для disband используем именно текущих bot1/bot2 из активных команд.
        # Если команды ещё не собраны — тогда делаем анализ по окнам.
        if not self._ensure_lobbies_for_disband():
            return False

        # ВАЖНО: не переставляем окна перед disband, чтобы кликать по реальным bot1/bot2,
        # а не по "2-му/4-му" окну после принудительного MoveWindows.
        if self.team1 is not None:
            if self.team1.Disband() is False:
                return False
            self.team1 = None
        if self.team2 is not None:
            if self.team2.Disband() is False:
                return False
            self.team2 = None

        return True

    def _ensure_lobbies_for_disband(self):
        if self.team1 and self.team2 and self._has_primary_bots(self.team1, self.team2):
            return True
        return self._auto_create_lobbies()

    @staticmethod
    def _has_primary_bots(team1, team2):
        return bool(getattr(team1, 'bots', None)) and bool(getattr(team2, 'bots', None))

    @staticmethod
    def _is_cs2_process(pid):
        if not pid:
            return False
        try:
            proc = psutil.Process(pid)
            return (proc.name() or "").lower() == "cs2.exe"
        except Exception:
            return False

    def _resolve_account_cs2_hwnd(self, account):
        hwnd = 0
        try:
            hwnd = account.FindCSWindow()
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
            if getattr(account, 'CS2Process', None):
                pid = account.CS2Process.pid
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
                width = max(0, rect[2] - rect[0])
                height = max(0, rect[3] - rect[1])
                area = width * height
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

    def _has_strict_pair_windows(self):
        if not self.team1 or not self.team2:
            return False
        if not self._has_primary_bots(self.team1, self.team2):
            return False

        members = [self.team1.leader, self.team1.bots[0], self.team2.leader, self.team2.bots[0]]
        positions = []
        seen_hwnds = set()

        for member in members:
            hwnd = self._resolve_account_cs2_hwnd(member)
            if not hwnd or not win32gui.IsWindow(hwnd) or hwnd in seen_hwnds:
                return False
            try:
                rect = win32gui.GetWindowRect(hwnd)
            except Exception:
                return False

            seen_hwnds.add(hwnd)
            positions.append((rect[0], rect[1], member.login))

        expected_order = [member.login for member in members]
        actual_order = [item[2] for item in sorted(positions, key=lambda item: (item[0], item[1]))]
        return actual_order == expected_order

    def MoveWindows(self, ordered_logins=None):
        if not self.team1 or not self.team2:
            return False

        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

        ordered_members = []
        all_members = [self.team1.leader] + self.team1.bots + [self.team2.leader] + self.team2.bots
        member_by_login = {m.login: m for m in all_members if hasattr(m, 'login')}

        # По умолчанию: строго по списку аккаунтов.
        # Для Shuffle можно передать random ordered_logins.
        if ordered_logins:
            order_source = ordered_logins
        elif self._last_window_order_logins:
            order_source = self._last_window_order_logins
        else:
            order_source = [acc.login for acc in self._accountManager.accounts]

        for login in order_source:
            member = member_by_login.get(login)
            if member:
                ordered_members.append(member)

        if not ordered_members:
            ordered_members = all_members

        target_width = 383
        target_height = 280
        y = 0
        placed = 0

        for member in ordered_members:
            if self._is_cancelled():
                return False


            try:
                hwnd = self._resolve_account_cs2_hwnd(member)
                if not hwnd or not win32gui.IsWindow(hwnd):
                    continue

                x = placed * target_width
                win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                win32gui.MoveWindow(hwnd, x, y, target_width, target_height, True)
                win32gui.SetWindowText(hwnd, f"[FSN FREE] {member.login}")
                placed += 1
            except Exception:
                continue

        return placed > 0

    def Shuffle(self):
        if self._is_cancelled():
            return False

        valid_accounts = [acc for acc in self._accountManager.accounts if acc.isCSValid()]
        if len(valid_accounts) < 4:
            self._logManager.add_log("❌ Недостаточно активных CS аккаунтов для Shuffle")
            return False

        random.shuffle(valid_accounts)
        random_order_logins = [acc.login for acc in valid_accounts]
        mid = len(valid_accounts) // 2

        self.team1 = LobbyInstance(valid_accounts[0], valid_accounts[1:mid])
        self.team2 = LobbyInstance(valid_accounts[mid], valid_accounts[mid + 1:])
        self._last_window_order_logins = random_order_logins

        moved = self.MoveWindows(ordered_logins=random_order_logins)
        if moved:
            self._logManager.add_log(
                f"🔀 Shuffle выполнен"
            )
        return moved

    def _auto_create_lobbies(self):
        ordered_accounts = self._get_accounts_sorted_by_window_position()
        total = len(ordered_accounts)
        if total < 4:
            self._logManager.add_log("❌ Нужно минимум 4 валидных CS2 окна для сборки лобби")
            return False

        leader1 = ordered_accounts[0]
        bot1 = ordered_accounts[1]
        leader2 = ordered_accounts[2]
        bot2 = ordered_accounts[3]

        bots1 = [bot1]
        bots2 = [bot2]

        # Если аккаунтов больше 4 — дальше строго чередуем ботов между командами
        for index, account in enumerate(ordered_accounts[4:], start=4):
            if index % 2 == 0:
                bots1.append(account)
            else:
                bots2.append(account)

        self.team1 = LobbyInstance(leader1, bots1)
        self.team2 = LobbyInstance(leader2, bots2)
        self._last_window_order_logins = [acc.login for acc in ordered_accounts]

        return True

    def _get_strict_4_accounts_by_window_order(self):
        """Возвращает строго 4 аккаунта в порядке окон слева-направо (слоты 1..4)."""
        ordered_accounts = self._get_accounts_sorted_by_window_position()
        if len(ordered_accounts) < 4:
            self._logManager.add_log("❌ Нужно минимум 4 валидных CS2 окна")
            return None

        top4 = ordered_accounts[:4]
        seen_hwnds = set()

        for acc in top4:
            hwnd = self._resolve_account_cs2_hwnd(acc)
            if not hwnd or not win32gui.IsWindow(hwnd):
                self._logManager.add_log(f"❌ Не найдено окно CS2 для {getattr(acc, 'login', 'unknown')}")
                return None
            if hwnd in seen_hwnds:
                self._logManager.add_log("❌ Дубли hwnd среди 4 слотов — порядок окон нестабилен")
                return None
            seen_hwnds.add(hwnd)

        return top4

    def _build_strict_lobbies_from_4(self, top4_accounts):
        """Жёсткая сборка: slot1=leader1, slot2=bot1, slot3=leader2, slot4=bot2."""
        leader1, bot1, leader2, bot2 = top4_accounts
        self.team1 = LobbyInstance(leader1, [bot1])
        self.team2 = LobbyInstance(leader2, [bot2])
        self._last_window_order_logins = [acc.login for acc in top4_accounts]

    def _prepare_strict_4_windows_flow(self):
        """Подготовка без дополнительных пауз: move all -> align -> strict check."""
        moved_count = self.lift_all_cs2_windows()


        top4 = self._get_strict_4_accounts_by_window_order()
        if not top4:
            return False
        self._build_strict_lobbies_from_4(top4)

        if not self.MoveWindows(ordered_logins=self._last_window_order_logins):
            self._logManager.add_log("❌ MoveWindows failed during strict pre-start")
            return False

        if not self._has_strict_pair_windows():
            self._logManager.add_log("❌ Strict check failed after MoveWindows: нужны пары 1/2 и 3/4")
            return False

        return True

    def _get_accounts_sorted_by_window_position(self):
        valid_accounts = [acc for acc in self._accountManager.accounts if acc.isCSValid()]
        if not valid_accounts:
            return []

        ordered = []
        missing_windows = []

        for order_index, account in enumerate(valid_accounts):
            hwnd = self._resolve_account_cs2_hwnd(account)
            if not hwnd:
                missing_windows.append(account.login)
                continue

            try:
                rect = win32gui.GetWindowRect(hwnd)
            except Exception:
                missing_windows.append(account.login)
                continue

            ordered.append((rect[0], rect[1], order_index, account, hwnd))

        if missing_windows:
            self._logManager.add_log(f"⚠️ Пропущены аккаунты без окна CS2: {', '.join(missing_windows)}")

        # Строго: только слева направо. При равном X сохраняем исходный порядок аккаунтов.
        ordered.sort(key=lambda item: (item[0], item[1], item[2]))

        return [item[3] for item in ordered]

    def _get_rect_for_account_window(self, account):
        pid = 0
        try:
            if account.CS2Process:
                pid = account.CS2Process.pid
        except Exception:
            pid = 0

        if not pid:
            return None

        best = None

        def enum_cb(hwnd, _):
            nonlocal best
            try:
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                if win32gui.GetParent(hwnd) != 0:
                    return True

                _, hwnd_pid = win32process.GetWindowThreadProcessId(hwnd)
                if hwnd_pid != pid:
                    return True

                title = win32gui.GetWindowText(hwnd)
                if not title:
                    return True

                rect = win32gui.GetWindowRect(hwnd)
                if not best:
                    best = rect
                    return True

                # Берем самое левое окно процесса; если X равен — самое верхнее.
                if rect[0] < best[0] or (rect[0] == best[0] and rect[1] < best[1]):
                    best = rect
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(enum_cb, None)
        except Exception:
            return None

        return best

    # -----------------------------
    # Win32 helpers (shared)
    # -----------------------------
    @staticmethod
    def _is_cancelled():
        try:
            return keyboard.is_pressed("ctrl+q")
        except Exception:
            return False

    @staticmethod
    def _sleep_with_cancel(duration, step=0.05):
        if duration <= 0:
            return False

        end_time = time.time() + duration
        while True:
            if LobbyManager._is_cancelled():
                return True

            remaining = end_time - time.time()
            if remaining <= 0:
                return False

            time.sleep(max(0.0, min(step, remaining)))

    def _grab_avg_color_2x2(self, x, y, rect, image_grab):
        left = rect[0] + x
        top = rect[1] + y
        right = left + 2
        bottom = top + 2

        if right <= left or bottom <= top:
            return None

        try:
            img = image_grab.grab(bbox=(left, top, right, bottom))
        except Exception as e:
            if not self._screen_grab_warning_logged:
                self._logManager.add_log(f"⚠️ Pixel sampling unavailable for some windows: {e}")
                self._screen_grab_warning_logged = True
            return None

        r_sum = g_sum = b_sum = 0
        count = 0
        for px in range(img.size[0]):
            for py in range(img.size[1]):
                r, g, b = img.getpixel((px, py))[:3]
                r_sum += r
                g_sum += g
                b_sum += b
                count += 1

        if count == 0:
            return None

        return (r_sum // count, g_sum // count, b_sum // count)

    @staticmethod
    def _safe_set_foreground(hwnd):
        if not hwnd:
            return False

        attached = False
        fg_tid = 0
        hwnd_tid = 0

        try:
            if not win32gui.IsWindow(hwnd):
                return False

            try:
                win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
            except Exception:
                pass

            fg = 0
            try:
                fg = win32gui.GetForegroundWindow()
            except Exception:
                fg = 0

            try:
                fg_tid, _ = win32process.GetWindowThreadProcessId(fg)
            except Exception:
                fg_tid = 0

            try:
                hwnd_tid, _ = win32process.GetWindowThreadProcessId(hwnd)
            except Exception:
                hwnd_tid = 0

            if fg_tid and hwnd_tid and fg_tid != hwnd_tid:
                try:
                    win32process.AttachThreadInput(fg_tid, hwnd_tid, True)
                    attached = True
                except Exception:
                    attached = False

            # Окно могло исчезнуть между вызовами — проверяем повторно.
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
        finally:
            if attached and fg_tid and hwnd_tid and fg_tid != hwnd_tid:
                try:
                    win32process.AttachThreadInput(fg_tid, hwnd_tid, False)
                except Exception:
                    pass

    def lift_all_cs2_windows(self):
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

        cs2_pids = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = (proc.info.get('name') or "").lower()
                if name == "cs2.exe":
                    cs2_pids.append(proc.info['pid'])
            except Exception:
                continue

        if not cs2_pids:
            return 0

        processed = set()
        lifted = 0

        def enum_cb(hwnd, _):
            nonlocal lifted
            try:
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                if win32gui.GetParent(hwnd) != 0:
                    return True

                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if pid not in cs2_pids or pid in processed:
                    return True

                title = win32gui.GetWindowText(hwnd)
                if not title:
                    return True

                processed.add(pid)
                self._safe_set_foreground(hwnd)
                lifted += 1
                time.sleep(0.05)
            except Exception:
                pass
            return True

        win32gui.EnumWindows(enum_cb, None)
        return lifted

    def press_esc_all_cs2_windows(self):
        """Нажимает ESC два раза в КАЖДОМ найденном окне cs2.exe перед запуском лобби-потока."""
        cs2_pids = [
            p.info['pid'] for p in psutil.process_iter(['pid', 'name'])
            if (p.info.get('name') or "").lower() == "cs2.exe"
        ]
        if not cs2_pids:
            return 0

        seen = set()
        count = 0

        def enum_cb(hwnd, _):
            nonlocal count
            if self._is_cancelled():
                return False
            try:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if pid not in cs2_pids:
                    return True
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                if hwnd in seen:
                    return True

                seen.add(hwnd)
                self._safe_set_foreground(hwnd)
                if self._sleep_with_cancel(0.1):
                    return False

                for _ in range(2):
                    win32api.PostMessage(hwnd, win32con.WM_KEYDOWN, win32con.VK_ESCAPE, 0)
                    if self._sleep_with_cancel(0.05):
                        return False
                    win32api.PostMessage(hwnd, win32con.WM_KEYUP, win32con.VK_ESCAPE, 0)
                    if self._sleep_with_cancel(0.1):
                        return False

                count += 1
            except Exception:
                pass
            return True

        win32gui.EnumWindows(enum_cb, None)
        return count

    def _press_red_buttons_everywhere(self, final_click_pos, enforce_green=False, max_wait=12.0, leaders_only=False):
        from PIL import ImageGrab

        def get_avg_color_2x2(x, y, rect):
            return self._grab_avg_color_2x2(x, y, rect, ImageGrab)

        def button_state(x, y, rect):
            avg = get_avg_color_2x2(x, y, rect)
            if avg is None:
                return None
            r, g, b = avg
            if r > g + 20 and r > b + 20:
                return "red"
            if g > r + 20 and g > b + 20:
                return "green"
            return "red"

        def click_rel(x, y, rect, hwnd):
            if self._is_cancelled():
                return False
            self._safe_set_foreground(hwnd)
            abs_x = rect[0] + x
            abs_y = rect[1] + y
            win32api.SetCursorPos((abs_x, abs_y))
            if self._sleep_with_cancel(0.03):
                return False
            win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
            if self._sleep_with_cancel(0.03):
                return False
            win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
            return True

        members = []
        if leaders_only:
            if self.team1 and getattr(self.team1, 'leader', None):
                members.append(self.team1.leader)
            if self.team2 and getattr(self.team2, 'leader', None):
                members.append(self.team2.leader)

            if not members:
                ordered = self._get_accounts_sorted_by_window_position()
                if len(ordered) >= 3:
                    members = [ordered[0], ordered[2]]
        else:
            if self.team1:
                members.extend([self.team1.leader] + self.team1.bots)
            if self.team2:
                members.extend([self.team2.leader] + self.team2.bots)

        if not members:
            members = [acc for acc in self._accountManager.accounts if acc.isCSValid()]

        if not members:
            return True

        deadline = time.time() + max_wait
        warned_unknown = False

        while True:
            any_red = False
            all_green = True

            for acc in members:
                hwnd = self._resolve_account_cs2_hwnd(acc)
                if not hwnd:
                    continue
                try:
                    rect = win32gui.GetWindowRect(hwnd)
                except Exception:
                    continue

                state = button_state(final_click_pos[0], final_click_pos[1], rect)
                if state is None:
                    all_green = False
                    if not warned_unknown:
                        self._logManager.add_log("⚠️ Не удалось определить цвет кнопки в одном из окон CS2")
                        warned_unknown = True
                    continue

                if state == "red":
                    any_red = True
                    all_green = False
                    if not click_rel(final_click_pos[0], final_click_pos[1], rect, hwnd):
                        return False
                    if self._sleep_with_cancel(0.1):
                        return False

            if not enforce_green:
                return True

            if all_green:
                return True

            if time.time() >= deadline:
                self._logManager.add_log("⚠️ Не удалось перевести все кнопки в зеленый за отведенное время")
                return False

            if not any_red and self._sleep_with_cancel(0.15):
                return False

    def _recover_after_match_timeout(self, final_click_pos):
        self._logManager.add_log("⏱ 600s timeout without accepted match. Running recovery flow.")
        self._logManager.add_log("🔴→🟢 Timeout reached: forcing red buttons to green on leader windows (1 & 3)")

        if not self._press_red_buttons_everywhere(final_click_pos, enforce_green=True, max_wait=20.0, leaders_only=True):
            return False

        esc_count = self.press_esc_all_cs2_windows()
        self._logManager.add_log(f"⌨️ Recovery: ESC x2 sent to {esc_count} CS2 windows")
        if self._is_cancelled():
            return False

        if not self.DisbandLobbies():
            self._logManager.add_log("⚠️ DisbandLobbies failed")
        if self._is_cancelled():
            return False

        if not self.Shuffle():
            self._logManager.add_log("⚠️ Shuffle failed")
            return False
        if self._is_cancelled():
            return False

        return True

    # -----------------------------
    # Main flow (по ТЗ)
    # -----------------------------
    def MakeLobbiesAndSearchGame(self):

        from PIL import ImageGrab
        from Modules.AutoAcceptModule import AutoAcceptModule

        AutoAcceptModule.reset_final_clicks_state()

        # Жёсткая подготовка 4 окон по ТЗ: 40с -> move all -> align -> strict check -> 10с
        if not self._prepare_strict_4_windows_flow():
            return False

        if self._is_cancelled():
            return False

        FINAL_CLICK = (289, 271)
        OPEN_SEQ = [(206, 8), (154, 23), (142, 33)]
        max_cycles = 3

        def click_rel(x, y, rect, hwnd):
            if self._is_cancelled():
                return False
            self._safe_set_foreground(hwnd)
            abs_x = rect[0] + x
            abs_y = rect[1] + y
            win32api.SetCursorPos((abs_x, abs_y))
            if self._sleep_with_cancel(0.03):
                return False
            win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
            if self._sleep_with_cancel(0.03):
                return False
            win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
            return True

        def get_team_info(team):
            if not team or not team.leader:
                return None
            hwnd = self._resolve_account_cs2_hwnd(team.leader)
            if not hwnd:
                return None
            try:
                rect = win32gui.GetWindowRect(hwnd)
            except Exception:
                return None
            return {"hwnd": hwnd, "rect": rect}

        def get_button_state(info):
            if not info:
                return None
            avg = self._grab_avg_color_2x2(FINAL_CLICK[0], FINAL_CLICK[1], info["rect"], ImageGrab)
            if avg is None:
                return None
            r, g, b = avg
            if r > g + 20 and r > b + 20:
                return "red"
            if g > r + 20 and g > b + 20:
                return "green"
            return "red"

        def click_final(info):
            return click_rel(FINAL_CLICK[0], FINAL_CLICK[1], info["rect"], info["hwnd"])

        def rebuild_strict_slots_or_fail():
            top4_accounts = self._get_strict_4_accounts_by_window_order()
            if not top4_accounts:
                return False
            self._build_strict_lobbies_from_4(top4_accounts)
            return self._has_strict_pair_windows()

        for cycle in range(1, max_cycles + 1):
            if AutoAcceptModule.final_clicks_disabled():
                self._logManager.add_log("✅ Match already detected. Stopping lobby/search cycle immediately.")
                return True

            self._logManager.add_log(f"🚀 Start cycle {cycle}/{max_cycles}")

            self.press_esc_all_cs2_windows()
            if self._is_cancelled():
                return False

            self._maps_scrolled_once = False

            # На каждом цикле заново фиксируем 1..4 строго по реальным CS2 окнам.
            if not rebuild_strict_slots_or_fail():
                self._logManager.add_log("❌ Abort search: не удалось строго зафиксировать окна 1/2/3/4")
                return False

            if self.CollectLobby() is False:
                return False

            if not self._has_strict_pair_windows():
                self._logManager.add_log("❌ Abort search: собраны нестрого. Нужны пары 1/2 и 3/4")
                return False

            if AutoAcceptModule.final_clicks_disabled():
                self._logManager.add_log("✅ Match detected during lobby collect. Stopping search flow.")
                return True

            if not self.MoveWindows(ordered_logins=self._last_window_order_logins):
                self._logManager.add_log("❌ Abort search: MoveWindows failed before start clicks")
                return False

            if self._sleep_with_cancel(1.5):
                return False

            if not self._has_strict_pair_windows():
                self._logManager.add_log("❌ Abort start clicks: окна 1/2/3/4 потеряли строгий порядок")
                return False

            # Открывающие клики только по лидерам (слоты 1 и 3)
            for team in (self.team1, self.team2):
                if self._is_cancelled():
                    return False
                if AutoAcceptModule.final_clicks_disabled():
                    self._logManager.add_log("✅ Match detected. Skipping remaining start-search actions.")
                    return True

                info = get_team_info(team)
                if not info:
                    self._logManager.add_log("❌ Не удалось получить окно лидера для стартовых кликов")
                    return False

                self._safe_set_foreground(info["hwnd"])
                if self._sleep_with_cancel(0.25):
                    return False

                for x, y in OPEN_SEQ:
                    if not click_rel(x, y, info["rect"], info["hwnd"]):
                        return False
                    if self._sleep_with_cancel(0.25):
                        return False

            if self._sleep_with_cancel(0.6):
                return False

            info1 = get_team_info(self.team1)
            info2 = get_team_info(self.team2)
            if not info1 or not info2:
                self._logManager.add_log("❌ Не удалось получить окна лидеров перед финальными кликами")
                return False

            s1_start = get_button_state(info1)
            s2_start = get_button_state(info2)

            # Старт: жмём только зелёные кнопки.
            if s1_start == "green":
                if not click_final(info1):
                    return False
            if s2_start == "green":
                if not click_final(info2):
                    return False

            timed_out = True
            start_time = time.time()
            while time.time() - start_time < 600:
                if self._is_cancelled():
                    return False

                if AutoAcceptModule.final_clicks_disabled():
                    timed_out = False
                    break

                info1 = get_team_info(self.team1)
                info2 = get_team_info(self.team2)
                if not info1 or not info2:
                    self._logManager.add_log("⚠️ Лидерское окно потеряно во время поиска")
                    timed_out = False
                    break

                s1 = get_button_state(info1)
                s2 = get_button_state(info2)

                if s1 is None or s2 is None:
                    if self._sleep_with_cancel(0.25):
                        return False
                    continue

                if s1 == "red" and s2 == "green":
                    if not click_final(info1):
                        return False

                    if self._sleep_with_cancel(0.15):
                        return False

                    info1_new = get_team_info(self.team1)
                    info2_new = get_team_info(self.team2)
                    if info1_new and info2_new:
                        s1_new = get_button_state(info1_new)
                        s2_new = get_button_state(info2_new)
                        if s1_new == "green" and s2_new == "green":
                            if not click_final(info1_new):
                                return False
                            if not click_final(info2_new):
                                return False

                elif s1 == "green" and s2 == "red":
                    if not click_final(info2):
                        return False

                    if self._sleep_with_cancel(0.15):
                        return False

                    info1_new = get_team_info(self.team1)
                    info2_new = get_team_info(self.team2)
                    if info1_new and info2_new:
                        s1_new = get_button_state(info1_new)
                        s2_new = get_button_state(info2_new)
                        if s1_new == "green" and s2_new == "green":
                            if not click_final(info1_new):
                                return False
                            if not click_final(info2_new):
                                return False

                elif s1 == "green" and s2 == "green":
                    if not click_final(info1):
                        return False
                    if not click_final(info2):
                        return False

                # Если обе красные — ничего не делаем по ТЗ.
                elif s1 == "red" and s2 == "red":
                    pass

                if self._sleep_with_cancel(1.0):
                    return False

            if not timed_out or AutoAcceptModule.final_clicks_disabled():
                return True

            if not self._recover_after_match_timeout(FINAL_CLICK):
                return False

        self._logManager.add_log("❌ Match was not found after 3 recovery cycles")
        return False