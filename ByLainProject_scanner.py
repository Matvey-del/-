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
import json
import html
import datetime
import string
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path

APP_NAME = "BY LAINPROJECT"
MAX_FILE_SIZE = 256 * 1024 * 1024
MAX_TEXT_READ = 8 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 2500
MAX_ARCHIVE_TOTAL = 32 * 1024 * 1024
MAX_NESTED_DEPTH = 2
QUARANTINE_NAME = "ByLainProject_Quarantine"
APP_DATA = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "ByLainProject"
HISTORY_FILE = APP_DATA / "scan_history.json"

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
    ".ini", ".yml", ".yaml", ".properties", ".accesswidener",
    ".java", ".kt", ".kts", ".scala", ".groovy"
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
    if os.name == "nt":
        for letter in string.ascii_uppercase:
            drive = Path(letter + ":\\\\")
            if drive.exists():
                roots.append(drive)
    else:
        roots.append(Path.home())
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



def extract_class_symbols(data):
    """Parse JVM constant pool and actual invoke instructions; never load the class."""
    import struct
    symbols = []
    try:
        if len(data) < 12 or data[:4] != b'\xca\xfe\xba\xbe':
            return symbols
        pos = 8
        count = struct.unpack_from('>H', data, pos)[0]; pos += 2
        pool = [None] * count
        i = 1
        while i < count:
            tag = data[pos]; pos += 1
            if tag == 1:
                n = struct.unpack_from('>H', data, pos)[0]; pos += 2
                pool[i] = data[pos:pos+n].decode('utf-8', 'replace'); pos += n
            elif tag in (3, 4): pos += 4
            elif tag in (5, 6): pos += 8; i += 1
            elif tag == 7: pool[i] = ('class', struct.unpack_from('>H', data, pos)[0]); pos += 2
            elif tag == 8: pool[i] = ('string', struct.unpack_from('>H', data, pos)[0]); pos += 2
            elif tag in (9, 10, 11):
                x, y = struct.unpack_from('>HH', data, pos); pos += 4
                pool[i] = ('ref', tag, x, y)
            elif tag == 12:
                x, y = struct.unpack_from('>HH', data, pos); pos += 4
                pool[i] = ('nat', x, y)
            elif tag == 15: pos += 3
            elif tag in (16, 19, 20): pos += 2
            elif tag in (17, 18): pos += 4
            else: return symbols
            i += 1
        def utf(index):
            v = pool[index] if 0 < index < len(pool) else None
            return v if isinstance(v, str) else ''
        def class_name(index):
            v = pool[index] if 0 < index < len(pool) else None
            return utf(v[1]) if isinstance(v, tuple) and v[0] == 'class' else ''
        def method_ref(index):
            v = pool[index] if 0 < index < len(pool) else None
            if not isinstance(v, tuple) or v[0] != 'ref': return ''
            owner = class_name(v[2]); nat = pool[v[3]] if v[3] < len(pool) else None
            if isinstance(nat, tuple) and nat[0] == 'nat':
                name, desc = utf(nat[1]), utf(nat[2])
                return owner.replace('/', '.') + '.' + name + desc if owner and name else ''
            return ''
        # Skip class header and interfaces.
        pos += 6
        interfaces = struct.unpack_from('>H', data, pos)[0]; pos += 2 + interfaces * 2
        def skip_attributes(offset):
            n = struct.unpack_from('>H', data, offset)[0]; offset += 2
            for _ in range(n):
                name_idx = struct.unpack_from('>H', data, offset)[0]
                length = struct.unpack_from('>I', data, offset + 2)[0]
                offset += 6 + length
            return offset
        fields = struct.unpack_from('>H', data, pos)[0]; pos += 2
        for _ in range(fields):
            pos += 6
            pos = skip_attributes(pos)
        methods = struct.unpack_from('>H', data, pos)[0]; pos += 2
        # JVM bytecode instruction lengths; unspecified opcodes are one byte.
        two = set([0x10,0x12,0x15,0x16,0x17,0x18,0x19,0x36,0x37,0x38,0x39,0x3a,0xa9,0xbc])
        three = set([0x11,0x13,0x14,0x84,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xc6,0xc7,0xbb,0xbd,0xc0,0xc1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8])
        four = set([0xc5])
        five = set([0xb9,0xba,0xc8,0xc9])
        for _ in range(methods):
            pos += 6
            attr_count = struct.unpack_from('>H', data, pos)[0]; pos += 2
            for _ in range(attr_count):
                attr_name = utf(struct.unpack_from('>H', data, pos)[0])
                attr_len = struct.unpack_from('>I', data, pos + 2)[0]
                start = pos + 6
                if attr_name == 'Code' and attr_len >= 12:
                    code_len = struct.unpack_from('>I', data, start + 4)[0]
                    code_start = start + 8
                    code = data[code_start:code_start + code_len]
                    pc = 0
                    while pc < len(code):
                        op = code[pc]
                        if op in (0xb6, 0xb7, 0xb8, 0xb9, 0xba) and pc + 2 < len(code):
                            idx = (code[pc+1] << 8) | code[pc+2]
                            ref = method_ref(idx)
                            if ref: symbols.append('INVOKE ' + ref)
                        if op == 0xaa:  # tableswitch
                            pad = (4 - ((pc + 1) % 4)) % 4
                            base = pc + 1 + pad
                            if base + 12 > len(code): break
                            low, high = struct.unpack_from('>ii', code, base + 4)
                            step = 12 + max(0, high - low + 1) * 4
                        elif op == 0xab:  # lookupswitch
                            pad = (4 - ((pc + 1) % 4)) % 4
                            base = pc + 1 + pad
                            if base + 8 > len(code): break
                            pairs = struct.unpack_from('>i', code, base + 4)[0]
                            step = 8 + max(0, pairs) * 8
                        elif op == 0xc4:  # wide
                            step = 6 if pc + 1 < len(code) and code[pc+1] == 0x84 else 4
                        elif op in two: step = 2
                        elif op in three: step = 3
                        elif op in four: step = 4
                        elif op in five: step = 5
                        else: step = 1
                        if step <= 0: break
                        pc += step
                pos = start + attr_len
        # Class names aid Minecraft-context validation; method names above are actual calls.
        for v in pool:
            if isinstance(v, tuple) and v[0] == 'class':
                value = utf(v[1])
                if value: symbols.append(value.replace('/', '.'))
        return sorted(set(symbols))
    except Exception:
        return symbols


# API-level evidence is stronger than isolated words: these are Minecraft
# client/server symbols commonly needed to implement particular mechanics.
API_RULES = {
    'Combat automation': [
        'ClientPlayerInteractionManager.attackEntity', 'PlayerInteractEntityC2SPacket',
        'attackEntity(', 'doAttack(', 'swingHand(', 'getEntitiesByClass('
    ],
    'Entity ESP / through-wall rendering': [
        'World.getEntities(', 'getEntitiesByClass(', 'EntityRenderer',
        'LivingEntityRenderer', 'isInvisibleTo(', 'Frustum', 'getBoundingBox('
    ],
    'Rotation manipulation': [
        'PlayerMoveC2SPacket', 'LookAndOnGround', 'getYaw(', 'getPitch(',
        'setYaw(', 'setPitch(', 'changeLookDirection(', 'sendMovementPackets('
    ],
    'Movement modification': [
        'setVelocity(', 'getAbilities(', 'flying', 'PlayerMoveC2SPacket',
        'setSprinting(', 'jump(', 'setOnGround('
    ],
    'Packet manipulation / bypass': [
        'ClientConnection.send(', 'sendPacket(', 'NetworkManager.sendPacket(',
        'ChannelPipeline', 'PacketEncoder', 'PacketDecoder', 'channelRead('
    ],
    'Automated inventory / interaction': [
        'clickSlot(', 'interactBlock(', 'interactItem(', 'updateSlotStacks(',
        'ClickSlotC2SPacket', 'PlayerActionC2SPacket'
    ],
}


def analyze_api_behavior(text):
    lower = text.lower()
    found = {}
    for family, needles in API_RULES.items():
        matches = [n for n in needles if n.lower() in lower]
        if matches:
            found[family] = sorted(set(matches))[:10]
    # A behavior family is meaningful only when its API evidence co-occurs
    # with another relevant API or an implementation-level indicator.
    score = 0
    if 'Combat automation' in found and ('Rotation manipulation' in found or 'Packet manipulation / bypass' in found):
        score += 7
    if 'Entity ESP / through-wall rendering' in found and ('world.getentities(' in lower or 'isinvisibleto(' in lower or 'frustum' in lower):
        score += 6
    if 'Rotation manipulation' in found and 'Packet manipulation / bypass' in found:
        score += 6
    if 'Movement modification' in found and 'Packet manipulation / bypass' in found:
        score += 5
    if 'Automated inventory / interaction' in found and 'Packet manipulation / bypass' in found:
        score += 4
    return score, found


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


MOJANG_POLICY_INDICATORS = {
    "Внешняя оплата / play-to-earn": ["play-to-earn", "cashout", "cash out", "withdraw crypto", "real-world currency", "real money payout"],
    "Проверка владения внешним контентом для игровых функций": ["owns_nft", "has_nft", "verifyownership", "ownershipcheck", "entitlementcheck", "purchasecheck", "paidaccess", "nft gate", "token gate"],
}


def analyze_mojang_policy_indicators(text):
    """Find technical indicators related to explicit Mojang mod/distribution rules.

    This is not a legal opinion: commercial context, permissions and distribution
    cannot be established from a JAR's code alone.
    """
    lower = text.lower()
    found = {}
    for rule, markers in MOJANG_POLICY_INDICATORS.items():
        matches = [m for m in markers if m in lower]
        if matches:
            found[rule] = matches[:8]
    # Bundling Minecraft implementation classes inside a mod archive can indicate
    # redistribution of game software; package references alone are not enough.
    bundled = re.findall(r"(?:^|\n)(?:net/minecraft/(?:client|server)/[^\n]+\.class|com/mojang/blaze3d/[^\n]+\.class)", lower)
    if bundled:
        found["Возможное включение классов самой игры в архив"] = bundled[:8]
    return found


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
                    name.endswith((".class", ".java", ".kt", ".kts", ".scala", ".groovy",
                                   ".json", ".txt", ".cfg", ".toml", ".yml", ".yaml", ".properties"))
                ):
                    try:
                        raw = zf.read(info)[:2 * 1024 * 1024]
                        if name.endswith(".class"):
                            combined.append(printable_strings(raw))
                            combined.extend(extract_class_symbols(raw))
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


# Stronger semantic indicators for the user's requested ESP / bypass checks.
# These are evaluated as combinations, not as isolated keywords.
ESP_ENTITY_MARKERS = (
    "playeresp", "entityesp", "itemesp", "chestesp", "wallhack", "tracers",
    "nametag", "getentities", "getentitiesbyclass", "livingentityrenderer",
    "entityrenderer", "renderentity", "renderentities", "rendername",
    "itemrenderer", "renderitem", "entityoutline", "outlineprovider",
)
ESP_THROUGH_WALL_MARKERS = (
    "disabledepthtest", "depthtest", "depth_test", "depthfunc", "gl_always",
    "glalways", "always", "no_depth", "nodepth", "throughwall", "through_wall",
    "see_through", "seethrough", "depthmask", "depth_mask", "renderlayer",
    "rendertype", "linestrip", "linewidth", "outline", "glow", "shader",
)
ANTICHEAT_BYPASS_MARKERS = (
    "anticheatbypass", "anti_cheat_bypass", "bypassanticheat",
    "grimac", "grim_bypass", "matrix_bypass", "watchdog_bypass",
    "verus_bypass", "ncp_bypass", "vulcan_bypass", "intave_bypass",
    "spoofpacket", "packetspoof", "spoof_rotation", "silentrotation",
    "rotationspoof", "blink", "desync", "badpackets", "transaction",
    "keepalive", "brandspoof", "clientbrand", "protocolhack",
)

def detect_strong_behavior(text):
    """Return strong behavior evidence when implementation clues co-occur."""
    low = text.lower()
    entity = sorted({m for m in ESP_ENTITY_MARKERS if m in low})
    wall = sorted({m for m in ESP_THROUGH_WALL_MARKERS if m in low})
    bypass = sorted({m for m in ANTICHEAT_BYPASS_MARKERS if m in low})

    # Require both entity/player/item rendering context and a depth/overlay
    # technique. A normal renderer or outline effect alone is not sufficient.
    esp_confirmed = bool(entity and wall and (
        any(x in low for x in ("disabledepthtest", "depthfunc", "gl_always",
                               "glalways", "throughwall", "through_wall",
                               "no_depth", "nodepth", "depthmask"))
        or ("outline" in low and any(x in low for x in
                                     ("player", "entity", "item", "livingentity")))
    ))
    # A bypass verdict requires anti-cheat-specific language or a combination
    # of spoofing/desync and network packet manipulation indicators.
    packet_context = any(x in low for x in (
        "sendpacket", "clientconnection", "networkmanager", "packet",
        "channelpipeline", "packetencoder", "packetdecoder"
    ))
    bypass_confirmed = bool(
        any(x in low for x in ("anticheatbypass", "anti_cheat_bypass",
                               "bypassanticheat", "grim_bypass", "matrix_bypass",
                               "watchdog_bypass", "verus_bypass", "ncp_bypass",
                               "vulcan_bypass", "intave_bypass"))
        or (packet_context and len(bypass) >= 2 and any(
            x in low for x in ("spoof", "desync", "blink", "silentrotation")))
    )
    return {
        "esp_confirmed": esp_confirmed,
        "esp_entity_evidence": entity[:12],
        "esp_render_evidence": wall[:12],
        "bypass_confirmed": bypass_confirmed,
        "bypass_evidence": bypass[:12],
    }


OBFUSCATION_MARKERS = {
    "Reflection": ("java/lang/reflect", "java.lang.reflect", "getdeclaredmethod",
                   "getdeclaredfield", "method.invoke", "class.forname"),
    "Динамическая загрузка классов": ("classloader", "defineclass", "loadclass",
                                      "secureclassloader", "urlclassloader"),
    "Шифрование/декодирование строк": ("javax/crypto", "cipher.getinstance",
        "secretkey", "stringdecrypt", "decryptstring", "base64.getdecoder",
        "base64.getdecoder", "xor", "aes/gcm", "aes/cbc"),
    "Генерация/изменение байткода": ("org/objectweb/asm", "javassist",
        "bytebuddy", "definehiddenclass", "methodhandles.lookup",
        "invokedynamic", "classwriter", "classvisitor"),
}
def detect_obfuscation(text):
    low = (text or "").lower()
    return {label: [m for m in markers if m in low][:10]
            for label, markers in OBFUSCATION_MARKERS.items()
            if any(m in low for m in markers)}

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
    elif ext == ".class":
        text = printable_strings(raw) + "\n" + "\n".join(extract_class_symbols(raw))
    elif ext == ".pyc":
        text = printable_strings(raw)
    else:
        text = raw.decode("utf-8", "ignore").lower()

    # Ignore generic files even if they happen to contain words such as
    # "aura", "reach" or "velocity": Minecraft context is mandatory.
    if not is_minecraft_candidate(path, text):
        return None

    score, hits, known, framework = analyze_text(text, name)
    api_score, api_hits = analyze_api_behavior(text)
    policy_hits = analyze_mojang_policy_indicators(text)
    strong = detect_strong_behavior(text)
    obfuscation = detect_obfuscation(text)
    score += api_score
    if len(obfuscation) >= 2:
        score += 3
    if strong['esp_confirmed']:
        score += 12
    if strong['bypass_confirmed']:
        score += 12

    # A client name is a weak indicator only; code/API combinations carry more weight.
    if any(n in name for n in KNOWN_CHEAT_NAMES):
        score += 2
        known = sorted(set(known + [n for n in KNOWN_CHEAT_NAMES if n in name]))

    if not hits and not known and not api_hits and not policy_hits and not strong['esp_confirmed'] and not strong['bypass_confirmed'] and not obfuscation:
        return None

    if strong['esp_confirmed'] or strong['bypass_confirmed'] or api_score >= 10 or score >= 16:
        level = "ВЫСОКАЯ"
    elif api_score >= 5 or score >= 8:
        level = "СРЕДНЯЯ"
    else:
        level = "НИЗКАЯ"

    reasons = []
    for family, terms in api_hits.items():
        reasons.append("API/ссылки в байткоде — " + family + ": " + ", ".join(terms))
    for family, terms in hits.items():
        reasons.append(f"Текстовые признаки — {family}: {', '.join(terms)}")
    if strong['esp_confirmed']:
        reasons.append("ПОДТВЕРЖДЁННЫЙ ПРИЗНАК ESP ЧЕРЕЗ СТЕНЫ: найдены сущности/игроки/предметы и техники обхода глубины/обводки: " +
                       ", ".join(strong['esp_entity_evidence'] + strong['esp_render_evidence']))
    if strong['bypass_confirmed']:
        reasons.append("ПРИЗНАК ОБХОДА АНТИЧИТА: найдены bypass/spoof/desync и сетевой контекст: " +
                       ", ".join(strong['bypass_evidence']))
    for label, markers in obfuscation.items():
        reasons.append("Индикаторы обфускации — " + label + ": " + ", ".join(markers))
    for rule, markers in policy_hits.items():
        reasons.append("Риск по критериям Mojang — " + rule + ": " + ", ".join(markers))
    if known:
        reasons.append("Имя известного клиента/чита (не доказательство): " + ", ".join(known[:4]))
    if framework and hits:
        reasons.append("Контекст клиентского фреймворка: " + ", ".join(framework[:4]))
    return {"path": path, "score": score, "level": level, "reasons": reasons,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "api_evidence": api_hits, "policy_evidence": policy_hits,
            "obfuscation_evidence": obfuscation, "strong_evidence": strong,
            "classification": ("ВЫСОКАЯ ВЕРОЯТНОСТЬ ЧИТА" if strong["esp_confirmed"] or strong["bypass_confirmed"] else "ТРЕБУЕТ ПРОВЕРКИ — статические признаки не доказывают нарушение")}

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
        self.cancel_event = threading.Event()
        self.scan_errors = 0
        self.history = self.load_history()
        self.all_results = {}
        self.scan_root_override = None
        self.build_ui()
        self.root.after(100, self.poll)

    def build_ui(self):
        # Full-width application title bar.
        header = tk.Frame(self.root, bg=self.WHITE, highlightbackground="#000000", highlightthickness=1)
        header.pack(fill="x", padx=0, pady=(0, 12))
        tk.Label(header, text="LainScaner", bg=self.WHITE, fg=self.FG,
                 font=("Segoe UI", 28, "bold")).pack(fill="x", padx=0, pady=(16, 4))
        tk.Label(header, text="MINECRAFT JAVA / MOD / CLASS SCANNER",
                 bg=self.WHITE, fg=self.MUTED, font=("Segoe UI", 9)).pack(fill="x", pady=(0, 14))

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
            command=self.start_full_scan, bg=self.FG, fg=self.WHITE, activebackground="#333333",
            activeforeground=self.WHITE, relief="solid", bd=1, highlightthickness=1,
            highlightbackground="#000000", highlightcolor="#000000", padx=18, pady=12,
            font=("Segoe UI", 9, "bold"), cursor="hand2")
        self.scan_btn.pack(side="left")
        tk.Button(actions, text="ПАПКА...", command=self.choose_folder,
            bg=self.WHITE, fg=self.FG, relief="solid", bd=1, padx=12, pady=12,
            font=("Segoe UI", 9), cursor="hand2").pack(side="left", padx=6)
        self.stop_btn = tk.Button(actions, text="ОСТАНОВИТЬ", command=self.stop_scan,
            bg="#eeeeee", fg=self.FG, relief="solid", bd=1, padx=12, pady=12,
            font=("Segoe UI", 9), state="disabled", cursor="hand2")
        self.stop_btn.pack(side="left", padx=4)
        tk.Button(actions, text="HTML", command=lambda: self.export_report("html"),
            bg=self.WHITE, fg=self.FG, relief="solid", bd=1, padx=10, pady=12).pack(side="right", padx=4)
        tk.Button(actions, text="TXT", command=lambda: self.export_report("txt"),
            bg=self.WHITE, fg=self.FG, relief="solid", bd=1, padx=10, pady=12).pack(side="right", padx=4)
        tk.Button(actions, text="ПОДРОБНОСТИ", command=self.show_details,
            bg=self.WHITE, fg=self.FG, relief="solid", bd=1, padx=10, pady=12).pack(side="right", padx=4)
        tk.Button(actions, text="ВЫБРАТЬ ВСЁ", command=self.select_all,
            bg=self.WHITE, fg=self.FG, relief="solid", bd=1, highlightthickness=1,
            highlightbackground="#000000", highlightcolor="#000000", padx=14, pady=12,
            font=("Segoe UI", 9), cursor="hand2").pack(side="left", padx=8)
        tk.Button(actions, text="СНЯТЬ ВЫБОР", command=self.clear_selection,
            bg=self.WHITE, fg=self.FG, relief="solid", bd=1, highlightthickness=1,
            highlightbackground="#000000", highlightcolor="#000000", padx=14, pady=12,
            font=("Segoe UI", 9), cursor="hand2").pack(side="left")
        tk.Button(actions, text="В КАРАНТИН", command=self.quarantine_selected,
            bg="#e5e5e5", fg=self.FG, relief="solid", bd=1, highlightthickness=1,
            highlightbackground="#000000", highlightcolor="#000000", padx=16, pady=12,
            font=("Segoe UI", 9, "bold"), cursor="hand2").pack(side="right")

        filters = tk.Frame(self.root, bg=self.BG)
        filters.pack(fill="x", padx=22, pady=(0, 8))
        tk.Label(filters, text="ПОИСК:", bg=self.BG, fg=self.FG).pack(side="left")
        self.search_var = tk.StringVar()
        search = tk.Entry(filters, textvariable=self.search_var, width=34)
        search.pack(side="left", padx=6)
        self.search_var.trace_add("write", lambda *_: self.apply_filters())
        tk.Label(filters, text="РИСК:", bg=self.BG, fg=self.FG).pack(side="left", padx=(12, 4))
        self.risk_var = tk.StringVar(value="Все")
        riskbox = ttk.Combobox(filters, textvariable=self.risk_var, values=("Все", "ВЫСОКАЯ", "СРЕДНЯЯ", "НИЗКАЯ"), state="readonly", width=12)
        riskbox.pack(side="left")
        riskbox.bind("<<ComboboxSelected>>", lambda e: self.apply_filters())

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
        self.tree.bind("<Double-Button-3>", self.open_containing_folder)
        # Risk level colors: green -> yellow/orange -> red.
        self.tree.tag_configure("high", foreground="#e53935")
        self.tree.tag_configure("medium", foreground="#f39c12")
        self.tree.tag_configure("low", foreground="#2eaa57")

        tk.Label(self.root,
            text="Ищутся только Minecraft-файлы: JAR, CLASS, архивы модов и метаданные Fabric/Forge. "
                 "Обычные EXE, Python-файлы и посторонние документы пропускаются. "
                 "Проверяются байткод Java, ссылки на методы Minecraft, метаданные и комбинации игровых API. "
                 "Статический анализ: файлы не запускаются; эвристики не доказывают нарушение.",
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

    def start_full_scan(self):
        self.scan_root_override = None
        self.start_scan()

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
        self.cancel_event.clear()
        self.scan_errors = 0
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        threading.Thread(target=self.worker, daemon=True).start()

    def worker(self):
        roots = [self.scan_root_override] if self.scan_root_override else scan_roots()
        total = 0
        for root in roots:
            for current, dirs, files in os.walk(str(root), onerror=lambda e: self.events.put(("error", str(e)))):
                if self.cancel_event.is_set(): break
                dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
                total += sum(1 for fn in files if Path(fn).suffix.lower() in SCAN_EXTENSIONS)
        self.events.put(("total", total))
        checked = 0
        for root in roots:
            for current, dirs, files in os.walk(str(root), onerror=lambda e: self.events.put(("error", str(e)))):
                if self.cancel_event.is_set(): break
                dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
                for fn in files:
                    if self.cancel_event.is_set(): break
                    p = Path(current) / fn
                    if p.suffix.lower() not in SCAN_EXTENSIONS:
                        continue
                    try:
                        result = inspect_file(p)
                        checked += 1
                        if result:
                            result["history_status"] = self.record_history(result)
                            self.events.put(("hit", result))
                    except Exception as exc:
                        self.events.put(("error", str(p) + ": " + str(exc)))
                    if checked % 10 == 0 or checked == total:
                        self.events.put(("progress", checked, total))
        self.events.put(("done", checked, total, self.cancel_event.is_set()))

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
                        " | ".join([r.get("history_status", "")] + r["reasons"][:3]), str(p)),
                        tags=(r["level"].lower(),))
                    self.items[iid] = {"result": r, "selected": False}
                    self.all_results[iid] = self.items[iid]
                    self.sort_results_english()
                elif e[0] == "error":
                    self.scan_errors += 1
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

    def load_history(self):
        try:
            APP_DATA.mkdir(parents=True, exist_ok=True)
            return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def save_history(self):
        try:
            APP_DATA.mkdir(parents=True, exist_ok=True)
            HISTORY_FILE.write_text(json.dumps(self.history, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    def record_history(self, result):
        key = str(result["path"]).casefold()
        old = self.history.get(key)
        status = "НОВЫЙ ФАЙЛ" if not old else ("БЕЗ ИЗМЕНЕНИЙ" if old.get("sha256") == result["sha256"] else "ВЕРСИЯ ИЗМЕНЕНА")
        result["previous_sha256"] = old.get("sha256") if old else None
        result["history_status"] = status
        self.history[key] = {"sha256": result["sha256"], "last_seen": datetime.datetime.now().isoformat(timespec="seconds")}
        self.save_history()
        return status

    def choose_folder(self):
        chosen = filedialog.askdirectory(title="Выберите папку для проверки")
        if chosen:
            self.scan_root_override = Path(chosen)
            self.status.config(text="ВЫБРАНА ПАПКА: " + chosen)
            self.start_scan()

    def stop_scan(self):
        if self.scanning:
            self.cancel_event.set()
            self.status.config(text="ОСТАНОВКА ПО ЗАПРОСУ...")

    def apply_filters(self):
        if not hasattr(self, "tree"):
            return
        query = self.search_var.get().casefold()
        risk = self.risk_var.get()
        for iid, item in self.items.items():
            r = item["result"]
            hay = (str(r["path"]) + " " + " ".join(r["reasons"])).casefold()
            visible = (not query or query in hay) and (risk == "Все" or r["level"] == risk)
            if visible:
                if not self.tree.exists(iid):
                    p = r["path"]
                    self.tree.insert("", "end", iid=iid, values=("☑" if item["selected"] else "□",
                        r["level"], p.name, p.suffix.lower(), " | ".join([r.get("history_status", "")] + r["reasons"][:3]), str(p)),
                        tags=(r["level"].lower(),))
            elif self.tree.exists(iid):
                self.tree.detach(iid)
        self.sort_results_english()

    def show_details(self):
        selection = self.tree.selection()
        iid = selection[0] if selection else None
        if iid not in self.items:
            messagebox.showinfo(APP_NAME, "Выберите строку результата.")
            return
        r = self.items[iid]["result"]
        detail = ("Файл: " + str(r["path"]) + "\\nРиск: " + r["level"] +
                  "\\nОценка: " + str(r["score"]) + "\\nSHA-256: " + r["sha256"] +
                  "\\nИстория: " + r.get("history_status", "—") +
                  "\\nПредыдущий SHA-256: " + str(r.get("previous_sha256") or "—") +
                  "\\nКлассификация: " + r["classification"] +
                  "\\n\\nПричины:\\n- " + "\\n- ".join(r["reasons"]))
        win = tk.Toplevel(self.root); win.title("Подробности обнаружения"); win.geometry("760x520")
        box = tk.Text(win, wrap="word"); box.pack(fill="both", expand=True, padx=10, pady=10)
        box.insert("1.0", detail); box.config(state="disabled")

    def export_report(self, kind):
        results = [x["result"] for x in self.items.values()]
        if not results:
            messagebox.showinfo(APP_NAME, "Нет результатов для экспорта.")
            return
        ext = ".html" if kind == "html" else ".txt"
        target = filedialog.asksaveasfilename(defaultextension=ext,
            filetypes=[("HTML", "*.html")] if kind == "html" else [("Text", "*.txt")])
        if not target: return
        if kind == "txt":
            body = "\\n\\n".join(
                f"{r['level']} | {r['path']}\\nSHA-256: {r['sha256']}\\nИстория: {r.get('history_status','—')}\\n" +
                "\\n".join("- " + x for x in r["reasons"]) for r in results)
        else:
            rows = []
            for r in results:
                rows.append("<article><h2>" + html.escape(r["level"] + " — " + r["path"].name) +
                    "</h2><p><b>Путь:</b> " + html.escape(str(r["path"])) +
                    "<br><b>SHA-256:</b> " + r["sha256"] +
                    "<br><b>История:</b> " + html.escape(r.get("history_status", "—")) +
                    "</p><ul>" + "".join("<li>" + html.escape(x) + "</li>" for x in r["reasons"]) + "</ul></article>")
            body = "<!doctype html><meta charset='utf-8'><title>LainScaner report</title><h1>LainScaner — отчёт</h1>" + "".join(rows)
        try:
            Path(target).write_text(body, encoding="utf-8")
            messagebox.showinfo(APP_NAME, "Отчёт сохранён: " + target)
        except Exception as exc:
            messagebox.showerror(APP_NAME, "Не удалось сохранить отчёт: " + str(exc))

    def sort_results_english(self):
        # Priority first: HIGH -> MEDIUM -> LOW. Within each priority,
        # keep the English filename order A-Z (case-insensitive).
        priority_order = {"ВЫСОКАЯ": 0, "СРЕДНЯЯ": 1, "НИЗКАЯ": 2}
        rows = []
        for iid in self.tree.get_children(""):
            values = self.tree.item(iid, "values")
            risk = str(values[1]).strip().upper()
            filename = str(values[2]).casefold()
            fullpath = str(values[5]).casefold()
            priority = priority_order.get(risk, 3)
            rows.append((priority, filename, fullpath, iid))
        rows.sort(key=lambda row: (row[0], row[1], row[2]))
        for index, (_, _, _, iid) in enumerate(rows):
            self.tree.move(iid, "", index)

    def open_containing_folder(self, event):
        # Two consecutive right-clicks on a result open the folder containing the mod.
        iid = self.tree.identify_row(event.y)
        if iid not in self.items:
            return
        path = self.items[iid]["result"]["path"]
        try:
            folder = str(path.parent.resolve())
            if os.name == "nt":
                os.startfile(folder)
            elif sys.platform == "darwin":
                import subprocess
                subprocess.Popen(["open", folder])
            else:
                import subprocess
                subprocess.Popen(["xdg-open", folder])
        except Exception as exc:
            messagebox.showerror(APP_NAME, "Не удалось открыть папку:\\n" + str(exc))

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
