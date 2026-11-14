# By LainProject — deep static scanner for Java/Python cheat indicators
# Target: Windows 7 SP1+; Python 3.8.10; PyInstaller 5.13.2
# No third-party runtime dependencies. Files are inspected, never executed.
#
# IMPORTANT: Heuristic scanner, not a definitive anti-cheat/antivirus.
# Static inspection cannot reliably prove behavior or detect obfuscated/packed cheats.

import os
import re
import sys
import zipfile
import shutil
import ctypes
import threading
import queue
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

APP_NAME = "BY LAINPROJECT"
MAX_FILE_SIZE = 256 * 1024 * 1024
MAX_TEXT_READ = 8 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 2500
MAX_ARCHIVE_TOTAL = 32 * 1024 * 1024
MAX_NESTED_DEPTH = 2
QUARANTINE_NAME = "ByLainProject_Quarantine"

# Behavior-oriented terms. A single generic term is deliberately not enough
# to label a file as a cheat; combinations and context increase confidence.
BEHAVIOR_GROUPS = {
    "Combat / KillAura": [
        "killaura", "kill_aura", "aura", "autoclicker", "auto_clicker",
        "triggerbot", "trigger_bot", "aimassist", "aim_assist",
        "autocombat", "auto_attack", "attackdelay", "cps"
    ],
    "ESP / Wallhack": [
        "playeresp", "player_esp", "entityesp", "entity_esp", "chestesp",
        "chest_esp", "itemesp", "item_esp", "esp", "wallhack", "wall_hack",
        "tracers", "nametags", "name_tags", "entityrenderer"
    ],
    "Rotation / Aim": [
        "silentrotation", "silent_rotation", "rotationbypass", "rotation_bypass",
        "rotationmanager", "rotation_manager", "rotationspoof", "spoofrotation",
        "aimbot", "aim_angle", "smoothaim", "smooth_aim", "rotations"
    ],
    "Movement": [
        "speedhack", "speed_hack", "flyhack", "fly_hack", "nofall",
        "no_fall", "jesus", "spider", "longjump", "long_jump",
        "strafe", "timerhack", "timer_hack", "stepheight"
    ],
    "Player advantage / Exploits": [
        "reach", "velocity", "antiknockback", "anti_knockback",
        "scaffold", "safewalk", "inventorymove", "inventory_move",
        "fastplace", "fast_place", "nuker", "cheststealer", "chest_stealer",
        "autototem", "auto_totem", "fastbreak", "fast_break"
    ],
    "Anti-cheat bypass": [
        "anticheatbypass", "anti_cheat_bypass", "grimbypass", "grim_bypass",
        "matrixbypass", "matrix_bypass", "watchdogbypass", "watchdog_bypass",
        "verusbypass", "verus_bypass", "bypassmode", "bypass_mode",
        "packetspoof", "packet_spoof", "spoofpacket", "spoof_packet"
    ],
}

# Common client/module framework terms. These are supporting context only,
# never a cheat verdict on their own.
FRAMEWORK_TERMS = [
    "meteordevelopment", "liquidbounce", "wurstclient", "baritone",
    "org.spongepowered.asm.mixin", "mixinextras", "modmenu",
    "net.fabricmc", "net.minecraftforge", "clickgui", "modulemanager",
    "togglemodule", "keybindmanager", "eventbus"
]

KNOWN_CHEAT_NAMES = [
    "wurst", "liquidbounce", "meteor client", "raven b+", "raven b",
    "vape", "rise client", "sigma client", "impact client", "aristois",
    "bleachhack", "inertia client", "future client", "konas", "astolfo",
    "novoline", "zeroday", "jigsaw", "gamesense", "exhibition",
    "tenacity", "moon client", "horion", "lb++", "liquidbounce plus"
]

# Only Minecraft Java artifacts and metadata are candidates. Python scripts,
# generic text files, executables and unrelated archives are intentionally ignored.
SCAN_EXTENSIONS = {
    ".jar", ".zip", ".class", ".json", ".toml", ".cfg", ".conf",
    ".ini", ".yml", ".yaml", ".properties", ".accesswidener"
}
MINECRAFT_CONTEXT_TERMS = (
    "net/minecraft", "net.minecraft", "com/mojang", "com.mojang",
    "net/fabricmc", "net.fabricmc", "net/minecraftforge",
    "net.minecraftforge", "org/spongepowered/asm/mixin",
    "org.spongepowered.asm.mixin", "fabric.mod.json", "mods.toml",
    "mcmod.info", "minecraftforge", "yarn", "intermediary",
    "net.fabricmc", "net.minecraftforge", "modmenu", "mixins.json"
)
MINECRAFT_PATH_MARKERS = (
    ".minecraft", "minecraft\\mods", "minecraft/mods",
    "curseforge", "prismlauncher", "multimc", "modrinth", "technic"
)
SKIP_DIRS = {
    "$recycle.bin", "system volume information", "windows", "winsxs",
    "installer", "driverstore", "node_modules", ".git", "__pycache__",
    ".gradle", ".m2", "venv", ".venv"
}

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def request_admin_restart():
    if os.name != "nt" or is_admin():
        return True
    try:
        params = " ".join('"' + x.replace('"', '') + '"' for x in sys.argv)
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1)
        return result > 32
    except Exception:
        return False

def scan_roots():
    # Search the drive for Minecraft-related artifacts, but inspect only the
    # allowlisted Java/archive/metadata extensions and require MC context.
    roots = []
    c_drive = Path("C:/")
    if c_drive.exists():
        roots.append(c_drive)
    return roots

def is_minecraft_candidate(path, text=""):
    """Require Minecraft-specific path or package/loader metadata context."""
    p = str(path).lower().replace("\\", "/")
    if any(marker in p for marker in MINECRAFT_PATH_MARKERS):
        return True
    haystack = (text or "").lower()
    return any(term in haystack for term in MINECRAFT_CONTEXT_TERMS)

def printable_strings(data, min_len=4):
    # Extract readable ASCII/UTF-8-ish fragments from Java bytecode and binaries.
    found = re.findall(rb"[ -~]{%d,}" % min_len, data)
    return "\n".join(x.decode("latin-1", "ignore") for x in found).lower()

def analyze_text(text, filename):
    hits = {}
    lower_name = filename.lower()
    for family, terms in BEHAVIOR_GROUPS.items():
        matches = []
        for term in terms:
            # Match common class/method naming styles and separator variations.
            pattern = re.escape(term).replace(r"\_", r"[_.$/ -]?")
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(term)
        if matches:
            hits[family] = sorted(set(matches))[:8]

    known = [n for n in KNOWN_CHEAT_NAMES if n in lower_name or n in text]
    framework = [x for x in FRAMEWORK_TERMS if x in text]

    # Score by distinct behavior families, not by raw number of word matches.
    score = len(hits) * 3
    if known:
        score += 5
    if framework and hits:
        score += 2
    # Strong combinations: combat+rotation, ESP+render, bypass+packet/rotation.
    families = set(hits)
    if "Combat / KillAura" in families and "Rotation / Aim" in families:
        score += 3
    if "ESP / Wallhack" in families and framework:
        score += 2
    if "Anti-cheat bypass" in families and (
        "Rotation / Aim" in families or "Player advantage / Exploits" in families
    ):
        score += 3

    return score, hits, known, framework

def inspect_archive_bytes(blob, depth=0):
    combined = []
    try:
        import io
        with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
            infos = zf.infolist()[:MAX_ARCHIVE_ENTRIES]
            total = 0
            for info in infos:
                if info.is_dir():
                    continue
                total += info.file_size
                if total > MAX_ARCHIVE_TOTAL:
                    break
                name = info.filename.lower()
                combined.append(name)
                # Read source/config/class files only, with strict limits.
                if info.file_size <= 2 * 1024 * 1024 and (
                    name.endswith((".class", ".py", ".pyw", ".json", ".txt",
                                   ".cfg", ".yml", ".yaml", ".properties"))
                ):
                    try:
                        raw = zf.read(info)[:2 * 1024 * 1024]
                        if name.endswith(".class"):
                            combined.append(printable_strings(raw))
                        else:
                            combined.append(raw.decode("utf-8", "ignore").lower())
                    except Exception:
                        pass
                # Inspect nested zip/jar payloads, bounded to two levels.
                elif depth < MAX_NESTED_DEPTH and name.endswith((".jar", ".zip")) and info.file_size <= 8 * 1024 * 1024:
                    try:
                        nested = zf.read(info)
                        combined.extend(inspect_archive_bytes(nested, depth + 1))
                    except Exception:
                        pass
    except Exception:
        pass
    return combined

def inspect_file(path):
    try:
        size = path.stat().st_size
        if size > MAX_FILE_SIZE:
            return None
        with path.open("rb") as f:
            # ZIP/JAR central directories are at the end of the archive.
            # Read the complete bounded archive so its entries can be inspected.
            raw = f.read() if path.suffix.lower() in (".jar", ".zip") else f.read(MAX_TEXT_READ)
    except (OSError, PermissionError):
        return None

    ext = path.suffix.lower()
    name = path.name.lower()
    if ext in (".jar", ".zip"):
        fragments = inspect_archive_bytes(raw)
        text = "\n".join(fragments)
    elif ext == ".class" or ext == ".pyc":
        text = printable_strings(raw)
    else:
        text = raw.decode("utf-8", "ignore").lower()

    # Ignore generic files even if they happen to contain words such as
    # "aura", "reach" or "velocity": Minecraft context is mandatory.
    if not is_minecraft_candidate(path, text):
        return None

    score, hits, known, framework = analyze_text(text, name)

    # Known cheat name in filename is a meaningful signal, but still displayed
    # as "high suspicion" rather than claiming proof.
    if any(n in name for n in KNOWN_CHEAT_NAMES):
        score += 5
        known = sorted(set(known + [n for n in KNOWN_CHEAT_NAMES if n in name]))

    if not hits and not known:
        return None

    if score >= 12:
        level = "ВЫСОКАЯ"
    elif score >= 6:
        level = "СРЕДНЯЯ"
    else:
        level = "НИЗКАЯ"

    reasons = []
    for family, terms in hits.items():
        reasons.append(f"{family}: {', '.join(terms)}")
    if known:
        reasons.append("Известное имя чита/клиента: " + ", ".join(known[:4]))
    if framework and hits:
        reasons.append("Контекст модульного клиента: " + ", ".join(framework[:4]))
    return {"path": path, "score": score, "level": level, "reasons": reasons}

class App:
    BG = "#f4f4f4"
    FG = "#111111"
    MUTED = "#666666"
    LINE = "#d8d8d8"
    WHITE = "#ffffff"

    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)
        self.root.configure(bg=self.BG)
        self.events = queue.Queue()
        self.items = {}
        self.scanning = False
        self.build_ui()
        self.root.after(100, self.poll)

    def build_ui(self):
        header = tk.Frame(self.root, bg=self.WHITE, highlightbackground=self.LINE, highlightthickness=1)
        header.pack(fill="x", padx=22, pady=(20, 12))
        tk.Label(header, text="BY LAINPROJECT", bg=self.WHITE, fg=self.FG,
                 font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=20, pady=(16, 0))
        tk.Label(header, text="MINECRAFT JAVA / MOD / CLASS SCANNER",
                 bg=self.WHITE, fg=self.MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=21, pady=(2, 15))

        bar = tk.Frame(self.root, bg=self.BG)
        bar.pack(fill="x", padx=22, pady=5)
        self.status = tk.Label(bar, text="ГОТОВ К ПРОВЕРКЕ", bg=self.BG, fg=self.FG,
                               font=("Segoe UI", 10, "bold"))
        self.status.pack(side="left")
        self.count = tk.Label(bar, text="ПРОВЕРЕНО: 0    НАХОДОК: 0",
                              bg=self.BG, fg=self.MUTED, font=("Segoe UI", 9))
        self.count.pack(side="right")

        self.progress = ttk.Progressbar(self.root, mode="determinate")
        self.progress.pack(fill="x", padx=22, pady=(5, 14))

        actions = tk.Frame(self.root, bg=self.BG)
        actions.pack(fill="x", padx=22, pady=(0, 12))
        self.scan_btn = tk.Button(actions, text="НАЧАТЬ ПОЛНУЮ ПРОВЕРКУ",
            command=self.start_scan, bg=self.FG, fg=self.WHITE, activebackground="#333333",
            activeforeground=self.WHITE, relief="flat", bd=0, padx=18, pady=12,
            font=("Segoe UI", 9, "bold"), cursor="hand2")
        self.scan_btn.pack(side="left")
        tk.Button(actions, text="ВЫБРАТЬ ВСЁ", command=self.select_all,
            bg=self.WHITE, fg=self.FG, relief="flat", bd=0, padx=14, pady=12,
            font=("Segoe UI", 9), cursor="hand2").pack(side="left", padx=8)
        tk.Button(actions, text="СНЯТЬ ВЫБОР", command=self.clear_selection,
            bg=self.WHITE, fg=self.FG, relief="flat", bd=0, padx=14, pady=12,
            font=("Segoe UI", 9), cursor="hand2").pack(side="left")
        tk.Button(actions, text="В КАРАНТИН", command=self.quarantine_selected,
            bg="#e5e5e5", fg=self.FG, relief="flat", bd=0, padx=16, pady=12,
            font=("Segoe UI", 9, "bold"), cursor="hand2").pack(side="right")

        wrap = tk.Frame(self.root, bg=self.WHITE, highlightbackground=self.LINE, highlightthickness=1)
        wrap.pack(fill="both", expand=True, padx=22, pady=(0, 10))
        cols = ("pick", "risk", "name", "type", "reason", "path")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="browse")
        headers = {"pick": "□", "risk": "РИСК", "name": "ФАЙЛ",
                   "type": "ТИП", "reason": "НАЙДЕННЫЕ ПРИЗНАКИ", "path": "ПУТЬ"}
        widths = {"pick": 42, "risk": 80, "name": 150, "type": 55, "reason": 300, "path": 360}
        for c in cols:
            self.tree.heading(c, text=headers[c])
            self.tree.column(c, width=widths[c], minwidth=40, stretch=c in ("reason", "path"))
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)
        self.tree.bind("<Double-1>", self.toggle)
        self.tree.tag_configure("high", foreground="#111111")
        self.tree.tag_configure("medium", foreground="#444444")
        self.tree.tag_configure("low", foreground="#777777")

        tk.Label(self.root,
            text="Ищутся только Minecraft-файлы: JAR, CLASS, архивы модов и метаданные Fabric/Forge. "
                 "Обычные EXE, Python-файлы и посторонние документы пропускаются. "
                 "Анализ статический: файлы не запускаются; возможны ложные совпадения.",
            bg=self.BG, fg=self.MUTED, font=("Segoe UI", 8), wraplength=1050,
            justify="left").pack(anchor="w", padx=22, pady=(0, 12))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=self.WHITE, foreground=self.FG,
                        fieldbackground=self.WHITE, rowheight=29, borderwidth=0,
                        font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background="#eeeeee", foreground=self.FG,
                        relief="flat", font=("Segoe UI", 8, "bold"))
        style.map("Treeview", background=[("selected", "#dddddd")],
                  foreground=[("selected", self.FG)])
        style.configure("TProgressbar", troughcolor="#e5e5e5",
                        background="#111111", thickness=7)

    def start_scan(self):
        if self.scanning:
            return
        if os.name == "nt" and not is_admin():
            if messagebox.askyesno(APP_NAME, "Запросить права администратора Windows для более полного доступа?"):
                if request_admin_restart():
                    self.root.destroy()
                    return
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.items.clear()
        self.progress["value"] = 0
        self.count.config(text="ПРОВЕРЕНО: 0    НАХОДОК: 0")
        self.status.config(text="ПОИСК MINECRAFT-ФАЙЛОВ...")
        self.scanning = True
        self.scan_btn.config(state="disabled")
        threading.Thread(target=self.worker, daemon=True).start()

    def worker(self):
        roots = scan_roots()
        total = 0
        # First count candidate files, then scan. System and bulky dependency dirs skipped.
        for root in roots:
            for current, dirs, files in os.walk(str(root)):
                dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
                for fn in files:
                    if Path(fn).suffix.lower() in SCAN_EXTENSIONS:
                        total += 1
        self.events.put(("total", total))
        checked = 0
        for root in roots:
            for current, dirs, files in os.walk(str(root)):
                dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
                for fn in files:
                    p = Path(current) / fn
                    if p.suffix.lower() not in SCAN_EXTENSIONS:
                        continue
                    result = inspect_file(p)
                    checked += 1
                    if result:
                        self.events.put(("hit", result))
                    if checked % 25 == 0 or checked == total:
                        self.events.put(("progress", checked, total))
        self.events.put(("done", checked, total))

    def poll(self):
        try:
            while True:
                e = self.events.get_nowait()
                if e[0] == "total":
                    self.progress["maximum"] = max(1, e[1])
                elif e[0] == "hit":
                    r = e[1]
                    p = r["path"]
                    iid = self.tree.insert("", "end", values=(
                        "□", r["level"], p.name, p.suffix.lower(),
                        " | ".join(r["reasons"][:3]), str(p)),
                        tags=(r["level"].lower(),))
                    self.items[iid] = {"result": r, "selected": False}
                elif e[0] == "progress":
                    _, n, total = e
                    self.progress["maximum"] = max(1, total)
                    self.progress["value"] = n
                    self.count.config(text=f"ПРОВЕРЕНО: {n}    НАХОДОК: {len(self.items)}")
                elif e[0] == "done":
                    _, n, total = e
                    self.scanning = False
                    self.scan_btn.config(state="normal")
                    self.status.config(text="ПРОВЕРКА ЗАВЕРШЕНА")
                    self.count.config(text=f"ПРОВЕРЕНО: {n}    НАХОДОК: {len(self.items)}")
                    messagebox.showinfo(APP_NAME,
                        f"Проверка завершена.\nПроверено файлов: {n}\nНайдено подозрительных файлов: {len(self.items)}\n\n"
                        "Проверьте причины каждого совпадения перед карантином.")
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def toggle(self, event):
        iid = self.tree.identify_row(event.y)
        if iid not in self.items:
            return
        item = self.items[iid]
        item["selected"] = not item["selected"]
        vals = list(self.tree.item(iid, "values"))
        vals[0] = "☑" if item["selected"] else "□"
        self.tree.item(iid, values=vals)

    def select_all(self):
        for iid, item in self.items.items():
            item["selected"] = True
            vals = list(self.tree.item(iid, "values"))
            vals[0] = "☑"
            self.tree.item(iid, values=vals)

    def clear_selection(self):
        for iid, item in self.items.items():
            item["selected"] = False
            vals = list(self.tree.item(iid, "values"))
            vals[0] = "□"
            self.tree.item(iid, values=vals)

    def quarantine_selected(self):
        chosen = [(iid, x) for iid, x in self.items.items() if x["selected"]]
        if not chosen:
            messagebox.showwarning(APP_NAME, "Отметьте файлы двойным щелчком по строке.")
            return
        if not messagebox.askyesno(APP_NAME,
            f"Переместить {len(chosen)} файлов в карантин?\nФайлы не будут удалены навсегда."):
            return
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / QUARANTINE_NAME
        try:
            base.mkdir(parents=True, exist_ok=True)
        except Exception as ex:
            messagebox.showerror(APP_NAME, "Не удалось создать карантин: " + str(ex))
            return
        moved, errors = 0, []
        for iid, item in chosen:
            src = item["result"]["path"]
            try:
                digest = hashlib.sha256(str(src).encode("utf-8", "ignore")).hexdigest()[:10]
                dest = base / (src.stem + "_" + digest + src.suffix)
                i = 1
                while dest.exists():
                    dest = base / (src.stem + "_" + digest + "_" + str(i) + src.suffix)
                    i += 1
                shutil.move(str(src), str(dest))
                (base / (dest.name + ".original_path.txt")).write_text(str(src), encoding="utf-8")
                self.tree.delete(iid)
                del self.items[iid]
                moved += 1
            except Exception as ex:
                errors.append(src.name + ": " + str(ex))
        self.count.config(text=f"НАХОДОК: {len(self.items)}")
        message = f"Перемещено в карантин: {moved}\n{base}"
        if errors:
            message += "\n\nОшибки:\n" + "\n".join(errors[:6])
        messagebox.showinfo(APP_NAME, message)

if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
