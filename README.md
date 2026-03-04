@@ -45,25 +45,42 @@ python main.py
## ⚙ Account Setup

1. To add accounts, place your `maFiles` (optional) in the `mafiles` folder.
2. Add logins and passwords in the `logpass.txt` file in the format:

```
login:password
```

---

## 🖼 Example Screenshot

<img width="1642" height="909" alt="image" src="https://github.com/user-attachments/assets/48aadeae-7365-44fb-9824-a69dc730a6da" />


---

## 🚀 Usage

* The panel allows launching multiple CS2 accounts simultaneously.
* Automatically arranges windows and collects lobbies.
* Works with accounts listed in `logpass.txt` and `maFiles`.

pip install opencv-python pillow pyautogui numpy psutil pywin32 requests


## 📦 Looter (Send trade)

Добавлены кнопки `Send trade` и `Settings looter` в блоке **Config** (под `Disable Steam Overlay`).

1. Нажмите `Settings looter` и укажите вашу Steam trade-ссылку.
2. Выделите аккаунты в списке.
3. Нажмите `Send trade` — для каждого выбранного аккаунта будет запущен `looter_core.js`.

### Требования для looter

```bash
npm install
```

Секреты `shared_secret` и `identity_secret` берутся из ваших `.mafile` файлов в папке `mafiles`.