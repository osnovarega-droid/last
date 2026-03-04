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

