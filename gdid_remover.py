#!/usr/bin/env python3
"""
GDID Removal Tool
"""

import sys
import os
import ctypes
import subprocess
import winreg
import time
import re
import logging
import tempfile
import shutil
import hashlib
import json
from typing import List, Optional, Tuple, Literal

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QProgressBar, QTabWidget,
    QMessageBox, QSystemTrayIcon, QMenu, QFileDialog,
    QGroupBox, QFormLayout, QSpinBox, QCheckBox, QStyle,
    QLineEdit, QSizePolicy
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QObject
from PySide6.QtGui import QAction, QFont, QColor, QKeySequence, QTextCursor

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger("GDIDRemover")
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(_handler)
logger.setLevel(logging.INFO)

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
SERVICE_START_DISABLED = 4
SERVICE_START_MANUAL = 3
SERVICE_START_AUTO = 2
SC_TIMEOUT_S = 10
SCHTASKS_CREATE_TIMEOUT_S = 15
DEFAULT_MONITOR_MINUTES = 5
VERIFY_STARTUP_DELAY_MS = 800
POST_ACTION_REVERIFY_MS = 400
HOSTNAME_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})*\.[a-z]{2,}$")
MAX_ENDPOINTS = 500
MAX_ENDPOINT_FILE_BYTES = 1_000_000
SERVICES_TO_DISABLE = [
    "CDPSvc",
    "DoSvc",
    "DiagTrack",
    "wlidsvc",
]

REGISTRY_PATHS = {
    "CDPSvc": r"SYSTEM\CurrentControlSet\Services\CDPSvc",
    "DoSvc": r"SYSTEM\CurrentControlSet\Services\DoSvc",
    "DiagTrack": r"SYSTEM\CurrentControlSet\Services\DiagTrack",
    "wlidsvc": r"SYSTEM\CurrentControlSet\Services\wlidsvc",
}

GDID_REG_PATH = r"SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties"
GDID_VALUE_NAME = "LID"
HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_MARKER = "# GDIDRemover"
HOSTS_BACKUP = HOSTS_FILE + ".gdid.bak"

APP_SETTINGS_REG_PATH = r"Software\GDIDRemover"
BACKUP_REG_PATH = r"Software\GDIDRemover\Backup"
BACKUP_VALUE_PREFIX = "Backup_Start_"
MONITOR_ENABLED_VALUE = "MonitorEnabled"
MONITOR_INTERVAL_VALUE = "MonitorInterval"

TASK_NAME = "GDIDRemover"

# Audit log: %ProgramData%\GDIDRemover\audit.log with %TEMP% fallback.
def _audit_log_path() -> str:
    try:
        base = os.environ.get("ProgramData") or os.environ.get("ALLUSERSPROFILE")
        if base:
            return os.path.join(base, "GDIDRemover", "audit.log")
    except Exception:
        pass
    return os.path.join(tempfile.gettempdir(), "GDIDRemover_audit.log")

AUDIT_LOG = _audit_log_path()

# Windows Update / delivery endpoints that can break patching if blocked.
# Kept separate so the safe default list never includes them.
UPDATE_RELATED = {
    "update.googleapis.com",
    "download.windowsupdate.com",
    "download.microsoft.com",
    "fe2.update.microsoft.com.akadns.net",
    "sls.update.microsoft.com.akadns.net",
    "fe3.delivery.dsp.mp.microsoft.com.nsatc.net",
    "tlu.dl.delivery.mp.microsoft.com",
    "test.stats.update.microsoft.com",
    "statsfe1.ws.microsoft.com",
    "statsfe2.update.microsoft.com.akadns.net",
    "ntservicepack.microsoft.com",
}

AGGRESSIVE_ENDPOINTS = sorted(UPDATE_RELATED)

# Safe-only built-in list: deduped, sorted, no ports, no update-related hosts.
# NOTE: blocking AGGRESSIVE_ENDPOINTS may break Windows Update; enable only
# via explicit opt-in (UI checkbox planned).
DEFAULT_ENDPOINTS = [
    "a-0001.a-msedge.net",
    "account.live.com",
    "choice.microsoft.com",
    "choice.microsoft.com.nsatc.net",
    "client.wns.windows.com",
    "compatexchange.cloudapp.net",
    "corpext.msitadfs.glbdns2.microsoft.com",
    "cs.dds.microsoft.com",
    "cs1.wpc.v0cdn.net",
    "devicemetadata.microsoft.com",
    "df.telemetry.microsoft.com",
    "diagnostics.support.microsoft.com",
    "go.microsoft.com",
    "login.live.com",
    "oca.telemetry.microsoft.com",
    "oca.telemetry.microsoft.com.nsatc.net",
    "redir.metaservices.microsoft.com",
    "reports.wes.df.telemetry.microsoft.com",
    "sdx.microsoft.com",
    "services.wes.df.telemetry.microsoft.com",
    "settings-sandbox.data.microsoft.com",
    "settings-win.data.microsoft.com",
    "settings.data.microsoft.com",
    "sqm.telemetry.microsoft.com",
    "sqm.telemetry.microsoft.com.nsatc.net",
    "statsfe2.ws.microsoft.com",
    "survey.watson.microsoft.com",
    "telecommand.telemetry.microsoft.com",
    "telecommand.telemetry.microsoft.com.nsatc.net",
    "telemetry.appex.bing.net",
    "telemetry.microsoft.com",
    "telemetry.urs.microsoft.com",
    "vortex-sandbox.data.microsoft.com",
    "vortex-win.data.microsoft.com",
    "vortex.data.microsoft.com",
    "watson.live.com",
    "watson.microsoft.com",
    "watson.ppe.telemetry.microsoft.com",
    "watson.telemetry.microsoft.com",
    "watson.telemetry.microsoft.com.nsatc.net",
    "wdcp.microsoft.com",
    "wdcpalt.microsoft.com",
    "wes.df.telemetry.microsoft.com",
]

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (OSError, AttributeError):
        return False

def elevate():
    # Elevate to admin; raises on failure, honors --elevated sentinel.
    if "--elevated" in sys.argv and not is_admin():
        raise PermissionError("Elevation failed (already tried --elevated).")
    params = subprocess.list2cmdline([*sys.argv, "--elevated"] if "--elevated" not in sys.argv else sys.argv)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    if rc <= 32:
        raise OSError(f"ShellExecuteW failed with code {rc}")

def _service_hive():
    return winreg.HKEY_LOCAL_MACHINE

def _app_hive():
    return winreg.HKEY_CURRENT_USER

def reg_path_for(svc: str) -> str:
    return REGISTRY_PATHS.get(svc) or f"SYSTEM\\CurrentControlSet\\Services\\{svc}"

def read_registry_value(hive, key_path: str, value_name: str) -> Optional[str]:
    try:
        with winreg.OpenKey(hive, key_path) as key:
            value, _ = winreg.QueryValueEx(key, value_name)
            return str(value)
    except FileNotFoundError:
        return None
    except OSError as e:
        logger.warning("Registry read failed for %s\\%s: %s", key_path, value_name, e)
        return None

def write_registry_dword(hive, key_path: str, value_name: str, data: int) -> bool:
    try:
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, data)
        return True
    except FileNotFoundError:
        try:
            with winreg.CreateKeyEx(hive, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, data)
            return True
        except OSError as e:
            logger.error("Registry write failed for %s\\%s: %s", key_path, value_name, e)
            return False
    except OSError as e:
        logger.error("Registry write failed for %s\\%s: %s", key_path, value_name, e)
        return False

def delete_registry_value(hive, key_path: str, value_name: str) -> bool:
    try:
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, value_name)
        return True
    except FileNotFoundError:
        return False
    except OSError as e:
        logger.warning("Registry delete failed for %s\\%s: %s", key_path, value_name, e)
        return False

def read_gdid_values() -> dict:
    # Check GDID value in both HKLM and HKCU; report both.
    result = {}
    for hive_name, hive in (("HKLM", winreg.HKEY_LOCAL_MACHINE), ("HKCU", winreg.HKEY_CURRENT_USER)):
        val = read_registry_value(hive, GDID_REG_PATH, GDID_VALUE_NAME)
        if val is not None:
            result[hive_name] = val
    return result

def snapshot_service_start(svc: str) -> None:
    # Save current Start value to HKCU backup before first disable.
    try:
        cur = read_registry_value(_service_hive(), reg_path_for(svc), "Start")
        if cur is not None:
            try:
                start_int = int(cur)
            except ValueError:
                return
            write_registry_dword(_app_hive(), BACKUP_REG_PATH, f"{BACKUP_VALUE_PREFIX}{svc}", start_int)
            logger.info("Backup Start=%s for %s (pre=%s)", start_int, svc, cur)
    except OSError as e:
        logger.warning("Snapshot failed for %s: %s", svc, e)

def get_backup_start(svc: str) -> Optional[int]:
    val = read_registry_value(_app_hive(), BACKUP_REG_PATH, f"{BACKUP_VALUE_PREFIX}{svc}")
    if val is None:
        return None
    try:
        return int(val)
    except ValueError:
        return None

def _hidden_run(args: List[str], timeout: int, check: bool = False):
    # Run console tools (sc/schtasks) without flashing a console window.
    # CREATE_NO_WINDOW + STARTF_USESHOWWINDOW keeps windowed (pythonw/exe)
    # builds from popping conhost on every Check/Verify/startup.
    kwargs: dict = {"capture_output": True, "text": True, "timeout": timeout, "check": check}
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        kwargs["startupinfo"] = si
    except Exception:
        pass
    try:
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    except AttributeError:
        pass  # non-Windows (dev) — flags simply don't exist
    return subprocess.run(args, **kwargs)

def stop_service(service_name: str) -> bool:
    try:
        result = _hidden_run(["sc", "stop", service_name], SC_TIMEOUT_S, check=False)
        if result.returncode == 0:
            return True
        # sc stop returns non-zero if already stopped / not running — treat STOP_PENDING/STOPPED output as ok, else False
        out = ((result.stdout or "") + "\n" + (result.stderr or "")).upper()
        if "STOP_PENDING" in out or "STOPPED" in out:
            return True
        logger.warning("sc stop %s returned %s: %s", service_name, result.returncode, (result.stdout or result.stderr or "").strip()[:300])
        return False
    except subprocess.TimeoutExpired:
        logger.warning("Timeout stopping %s", service_name)
        return False
    except (OSError, FileNotFoundError) as e:
        logger.warning("Failed to stop %s: %s", service_name, e)
        return False

def disable_service(service_name: str) -> tuple[bool, str]:
    try:
        result = _hidden_run(
            ["sc", "config", service_name, "start=", "disabled"],
            SC_TIMEOUT_S, check=False
        )
    except subprocess.TimeoutExpired:
        logger.warning("Timeout disabling %s", service_name)
        return False, "sc config timed out"
    except (OSError, FileNotFoundError) as e:
        logger.warning("Failed to disable %s: %s", service_name, e)
        return False, str(e)
    success = (result.returncode == 0) or ("SUCCESS" in result.stdout.upper() or "CHANGE_START_TYPE" in result.stdout.upper())
    message = result.stdout.strip() if result.stdout else result.stderr.strip()
    return success, message

def service_exists(service_name: str) -> bool:
    try:
        result = _hidden_run(["sc", "query", service_name], SC_TIMEOUT_S)
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return False
    if result.returncode == 0:
        return True
    # Fallback for localized sc output: FAILED + DOES NOT EXIST means missing
    out = ((result.stdout or "") + "\n" + (result.stderr or "")).upper()
    return "FAILED" not in out and "DOES NOT EXIST" not in out and result.returncode != 1060

def get_cdp_user_services() -> List[str]:
    services = []
    base = r"SYSTEM\CurrentControlSet\Services"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(key, index)
                    if name.startswith("CDPUserSvc_"):
                        services.append(name)
                    index += 1
                except OSError:
                    break
    except OSError as e:
        logger.warning("Failed to enumerate CDPUserSvc: %s", e)
    return services

def normalize_endpoint(ep: str) -> Optional[str]:
    if not ep or not isinstance(ep, str):
        return None
    s = ep.strip().lower()
    if not s or s.startswith("#"):
        return None
    if " " in s or "\t" in s or "\n" in s or "\r" in s:
        return None
    if "://" in s or "*" in s or "/" in s:
        return None
    # Split port only if :digits suffix.
    if ":" in s:
        host, _, port = s.partition(":")
        if not port.isdigit():
            return None
        s = host
    s = s.rstrip(".")
    if not s or "." not in s:
        return None
    if not HOSTNAME_RE.match(s):
        return None
    return s

def _parse_hosts_line(line: str) -> Tuple[Optional[str], List[str], str, str]:
    raw = line
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None, [], "", raw
    comment = ""
    body = line.rstrip("\n")
    if "#" in body:
        body, _, comment = body.partition("#")
        comment = "#" + comment
    parts = body.split()
    if not parts:
        return None, [], comment, raw
    ip = parts[0]
    hostnames = [p.lower().rstrip(".") for p in parts[1:] if p]
    return ip, hostnames, comment, raw

def is_endpoint_blocked(hosts_content: str, domain: str) -> bool:
    target = (domain or "").strip().lower().rstrip(".")
    if not target:
        return False
    for line in hosts_content.splitlines():
        ip, hostnames, _, _ = _parse_hosts_line(line)
        if ip is None:
            continue
        if target in hostnames:
            return True
    return False

def modify_hosts_file(endpoints: List[str], action: Literal["add", "remove"] = "add") -> bool:
    # Normalize, dedupe, sort; warn on aggressive list.
    normalized: List[str] = []
    for ep in endpoints or []:
        n = normalize_endpoint(ep)
        if n:
            normalized.append(n)
        elif isinstance(ep, str) and ep.strip() and not ep.strip().startswith("#"):
            logger.warning("Skipping invalid endpoint: %r", ep)
    blockset = sorted(set(normalized))
    aggressive_hit = sorted(set(blockset) & UPDATE_RELATED)
    if aggressive_hit:
        logger.warning("Aggressive update-related endpoints included (may break Windows Update): %s", aggressive_hit)
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8", errors="strict") as f:
            lines = f.readlines()
    except FileNotFoundError:
        logger.error("Hosts file not found: %s", HOSTS_FILE)
        return False
    except OSError as e:
        logger.error("Cannot read hosts file: %s", e)
        return False

    if action == "add":
        present: set = set()
        for line in lines:
            _, hostnames, _, _ = _parse_hosts_line(line)
            present.update(hostnames)
        new_lines = []
        for domain in blockset:
            if domain not in present:
                new_lines.append(f"0.0.0.0 {domain} {HOSTS_MARKER}\n")
        lines.extend(new_lines)
    elif action == "remove":
        block = set(blockset)
        kept = []
        for line in lines:
            ip, hostnames, comment, raw = _parse_hosts_line(line)
            if ip is None:
                kept.append(line)
                continue
            intersect = block.intersection(set(hostnames))
            if not intersect:
                kept.append(line)
                continue
            # Only remove our own marker lines or standard block IPs with exact match.
            has_marker = HOSTS_MARKER in line
            is_block_ip = ip in ("0.0.0.0", "127.0.0.1")
            if not (has_marker or is_block_ip):
                kept.append(line)
                continue
            remaining = [h for h in hostnames if h not in block]
            if not remaining:
                continue  # drop line - all hostnames blocked
            # Preserve other hostnames on same line instead of deleting them
            suffix = f" {comment}" if comment else ""
            kept.append(f"{ip} {' '.join(remaining)}{suffix}\n")
        lines = kept
    else:
        logger.error("Unknown hosts action: %r", action)
        return False

    # Atomic write: rotating backup, then temp + fsync + replace.
    try:
        try:
            # Rotate: keep .gdid.bak.1 as previous, .gdid.bak as latest
            if os.path.exists(HOSTS_BACKUP):
                try:
                    shutil.copy2(HOSTS_BACKUP, HOSTS_BACKUP + ".1")
                except OSError:
                    pass
            shutil.copy2(HOSTS_FILE, HOSTS_BACKUP)
            logger.info("Hosts backup created: %s", HOSTS_BACKUP)
        except OSError as e:
            logger.warning("Hosts backup failed (continuing): %s", e)
        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(HOSTS_FILE) or ".", prefix="hosts.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as tf:
                tf.writelines(lines)
                tf.flush()
                os.fsync(tf.fileno())
            os.replace(tmp_path, HOSTS_FILE)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        return True
    except OSError as e:
        logger.error("Failed to write hosts file: %s", e)
        return False

# ----------------------------------------------------------------------
# Startup task management
# ----------------------------------------------------------------------
def get_pythonw_path() -> str:
    exe_dir = os.path.dirname(sys.executable)
    pythonw = os.path.join(exe_dir, "pythonw.exe")
    if os.path.exists(pythonw):
        return pythonw
    return sys.executable

def get_script_path() -> str:
    return os.path.abspath(sys.argv[0])

def _run_schtasks(args: List[str], timeout: int) -> Tuple[bool, str]:
    try:
        result = _hidden_run(args, timeout)
    except subprocess.TimeoutExpired:
        return False, "schtasks timed out."
    except FileNotFoundError:
        return False, "schtasks.exe not found."
    except OSError as e:
        return False, str(e)
    if result.returncode == 0:
        return True, ""
    error = result.stderr.strip() if result.stderr else result.stdout.strip()
    if not error:
        error = f"Unknown error (return code {result.returncode})"
    return False, error

def _validate_script_path(script: str) -> Tuple[bool, str]:
    if not script or not os.path.exists(script):
        return False, f"Script path does not exist: {script}"
    low = script.lower()
    if not (low.endswith(".py") or low.endswith(".exe")):
        return False, f"Refusing to schedule unexpected file type: {script}"
    if any(c in script for c in ("&", "|", "<", ">", "^", "%", '"', "\n", "\r")):
        return False, "Script path contains unsafe characters."
    return True, ""

def create_elevated_startup_task() -> tuple[bool, str]:
    pythonw = get_pythonw_path()
    script = get_script_path()
    ok, err = _validate_script_path(script)
    if not ok:
        logger.error("Startup task validation failed: %s", err)
        return False, err
    if any(c in pythonw for c in ("&", "|", "<", ">", "^", "%", '"', "\n", "\r")):
        return False, "Python interpreter path contains unsafe characters."
    tr_value = subprocess.list2cmdline([pythonw, script, "--background"])
    args = ["schtasks", "/Create", "/TN", TASK_NAME, "/TR", tr_value, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"]
    ok, err = _run_schtasks(args, SCHTASKS_CREATE_TIMEOUT_S)
    if not ok:
        logger.error("Failed to create startup task: %s", err)
    return ok, err

def delete_elevated_startup_task() -> tuple[bool, str]:
    ok, error = _run_schtasks(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"], SC_TIMEOUT_S)
    if ok:
        return True, ""
    if "cannot find" in error.lower():
        return True, ""
    return False, error

def is_elevated_startup_task_exists() -> bool:
    ok, _ = _run_schtasks(["schtasks", "/Query", "/TN", TASK_NAME], SC_TIMEOUT_S)
    return ok

# ----------------------------------------------------------------------
# Monitoring settings persistence
# ----------------------------------------------------------------------
def save_monitor_settings(enabled: bool, interval_minutes: int):
    try:
        ok1 = write_registry_dword(_app_hive(), APP_SETTINGS_REG_PATH, MONITOR_ENABLED_VALUE, 1 if enabled else 0)
        ok2 = write_registry_dword(_app_hive(), APP_SETTINGS_REG_PATH, MONITOR_INTERVAL_VALUE, int(interval_minutes))
        return bool(ok1 and ok2)
    except OSError as e:
        logger.error("Failed to save monitor settings: %s", e)
        return False

def load_monitor_settings() -> tuple[bool, int]:
    enabled_val = read_registry_value(_app_hive(), APP_SETTINGS_REG_PATH, MONITOR_ENABLED_VALUE)
    interval_val = read_registry_value(_app_hive(), APP_SETTINGS_REG_PATH, MONITOR_INTERVAL_VALUE)
    enabled = enabled_val == "1"
    try:
        interval = int(interval_val) if interval_val is not None else DEFAULT_MONITOR_MINUTES
    except (ValueError, TypeError, AttributeError):
        interval = DEFAULT_MONITOR_MINUTES
    try:
        interval = max(1, min(60, int(interval)))
    except (ValueError, TypeError):
        interval = DEFAULT_MONITOR_MINUTES
    return bool(enabled), int(interval)

def _append_audit_file(line: str) -> None:
    # Append one line to audit log, best-effort.
    try:
        parent = os.path.dirname(AUDIT_LOG)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(AUDIT_LOG, "a", encoding="utf-8", errors="replace") as f:
            f.write(f"[{ts}] {line}\n")
    except Exception:
        pass

def _hosts_sha256() -> str:
    # SHA-256 of current hosts file bytes (or "unreadable").
    try:
        with open(HOSTS_FILE, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return "unreadable"

def _service_snapshot_json(services: List[str]) -> str:
    # JSON snapshot of Start values for given services.
    snap = {}
    for svc in services:
        try:
            snap[svc] = read_registry_value(_service_hive(), reg_path_for(svc), "Start")
        except Exception:
            snap[svc] = "error"
    try:
        return json.dumps(snap, sort_keys=True)
    except Exception:
        return str(snap)

# ----------------------------------------------------------------------
# Worker Thread
# ----------------------------------------------------------------------
class WorkerSignals(QObject):
    log = Signal(str)
    progress = Signal(int)
    finished = Signal(dict)

class WorkerThread(QThread):
    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    def run(self):
        try:
            result = self.func(*self.args, **self.kwargs, log_callback=self.signals.log.emit, progress_callback=self.signals.progress.emit)
            self.signals.finished.emit({"success": True, "result": result})
        except Exception as e:
            self.signals.log.emit(f"ERROR: {e}")
            self.signals.finished.emit({"success": False, "error": str(e)})

# ----------------------------------------------------------------------
# Main Window
# ----------------------------------------------------------------------
class GDIDRemoverApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GDID Removal Tool")
        self.resize(860, 620)
        self.setMinimumSize(640, 480)

        # System tray
        self.tray_icon = QSystemTrayIcon(self)
        # Use a valid standard icon
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        self.tray_icon.setToolTip("GDID Remover — monitoring every 5 min")
        tray_menu = QMenu()
        show_action = QAction("Show", self)
        show_action.setShortcut(QKeySequence("Ctrl+Shift+G"))
        show_action.triggered.connect(self.show_normal)
        check_action = QAction("Check now", self)
        check_action.triggered.connect(self.check_gdid_silent)
        open_log_action = QAction("Open log", self)
        open_log_action.triggered.connect(self.open_log_tab)
        quit_action = QAction("Exit", self)
        quit_action.setShortcut(QKeySequence("Ctrl+Q"))
        quit_action.triggered.connect(self.quit_app)
        tray_menu.addAction(show_action)
        tray_menu.addAction(check_action)
        tray_menu.addAction(open_log_action)
        tray_menu.addSeparator()
        tray_menu.addAction(quit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.tray_activated)

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Tabs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Status tab
        self.status_tab = QWidget()
        self.tabs.addTab(self.status_tab, "Status")
        status_layout = QVBoxLayout(self.status_tab)
        self.gdid_label = QLabel("GDID status: Unknown")
        status_layout.addWidget(self.gdid_label)
        self.check_gdid_btn = QPushButton("Check GDID")
        self.check_gdid_btn.setAccessibleName("check_gdid_btn")
        self.check_gdid_btn.setAccessibleDescription("Check whether GDID registry value is present")
        self.check_gdid_btn.clicked.connect(self.check_gdid)
        status_layout.addWidget(self.check_gdid_btn)
        self.refresh_status_btn = QPushButton("Refresh status (Verify all)")
        self.refresh_status_btn.setAccessibleName("refresh_status_btn")
        self.refresh_status_btn.setAccessibleDescription("Run full verification and update status dashboard")
        self.refresh_status_btn.setToolTip("Checks GDID, services Start values, hosts coverage and startup task.")
        self.refresh_status_btn.clicked.connect(self.verify_all)
        status_layout.addWidget(self.refresh_status_btn)
        # Status dashboard (updated by verify_all)
        self.lbl_services = QLabel("Services: Unknown")
        self.lbl_hosts = QLabel("Hosts: Unknown")
        self.lbl_task = QLabel("Startup task: Unknown")
        self.lbl_last_checked = QLabel("Last checked: never")
        for lbl in (self.lbl_services, self.lbl_hosts, self.lbl_task, self.lbl_last_checked):
            status_layout.addWidget(lbl)

        # Actions tab
        self.actions_tab = QWidget()
        self.tabs.addTab(self.actions_tab, "Actions")
        actions_layout = QVBoxLayout(self.actions_tab)

        actions_layout.setSpacing(8)
        actions_layout.setContentsMargins(12, 12, 12, 12)

        actions_group = QGroupBox("Removal Steps — run 1→4 in order, reboot after step 1")
        actions_group_layout = QVBoxLayout(actions_group)
        self.btn_disable_services = QPushButton("&1. Disable GDID Services")
        self.btn_disable_services.setShortcut("Alt+1")
        self.btn_disable_services.setAccessibleName("btn_disable_services")
        self.btn_disable_services.setAccessibleDescription("Disable CDPSvc, DoSvc, DiagTrack, wlidsvc and CDPUserSvc instances")
        self.btn_disable_services.setToolTip("Disables CDPSvc,DoSvc,DiagTrack,wlidsvc+CDPUserSvc_* (Start=4). May affect Update/Hello.")
        self.btn_disable_services.clicked.connect(self.disable_services)
        self.btn_block_endpoints = QPushButton("&2. Block GDID Endpoints")
        self.btn_block_endpoints.setShortcut("Alt+2")
        self.btn_block_endpoints.setShortcut("Alt+2")
        self.btn_block_endpoints.setAccessibleName("btn_block_endpoints")
        self.btn_block_endpoints.setAccessibleDescription("Append endpoint domains to hosts file")
        self.btn_block_endpoints.clicked.connect(self.block_endpoints)
        self.btn_delete_gdid = QPushButton("&3. Delete GDID Registry Value")
        self.btn_delete_gdid.setShortcut("Alt+3")
        self.btn_delete_gdid.setShortcut("Alt+3")
        self.btn_delete_gdid.setAccessibleName("btn_delete_gdid")
        self.btn_delete_gdid.setAccessibleDescription("Delete LID value from IdentityCRL registry keys")
        self.btn_delete_gdid.setToolTip("Deletes LID in HKLM+HKCU IdentityCRL. Reversible via re-login.")
        self.btn_delete_gdid.clicked.connect(self.delete_gdid)
        self.btn_verify = QPushButton("&4. Verify All Changes")
        self.btn_verify.setShortcut("Alt+4")
        self.btn_verify.setAccessibleName("btn_verify")
        self.btn_verify.setAccessibleDescription("Verify GDID, services and hosts coverage")
        self.btn_verify.setToolTip("Checks GDID, services Start, hosts coverage.")
        self.btn_verify.clicked.connect(self.verify_all)

        actions_group_layout.addWidget(self.btn_disable_services)
        actions_group_layout.addWidget(self.btn_block_endpoints)
        actions_group_layout.addWidget(self.btn_delete_gdid)
        actions_group_layout.addWidget(self.btn_verify)
        actions_layout.addWidget(actions_group)

        # Danger zone for rollback
        danger_group = QGroupBox("Danger zone")
        danger_group.setStyleSheet("QGroupBox { color: darkred; font-weight: bold; }")
        danger_layout = QVBoxLayout(danger_group)
        self.btn_rollback = QPushButton("Rollback (Restore Services & Hosts)")
        self.btn_rollback.setAccessibleName("btn_rollback")
        self.btn_rollback.setAccessibleDescription("Restore backed-up service Start values and remove hosts entries")
        self.btn_rollback.setToolTip("Restores backed-up Start values and removes GDID hosts entries.")
        self.btn_rollback.clicked.connect(self.rollback)
        danger_layout.addWidget(self.btn_rollback)
        actions_layout.addWidget(danger_group)
        self.setTabOrder(self.check_gdid_btn, self.btn_disable_services)
        self.setTabOrder(self.btn_disable_services, self.btn_block_endpoints)
        self.setTabOrder(self.btn_block_endpoints, self.btn_delete_gdid)
        self.setTabOrder(self.btn_delete_gdid, self.btn_verify)
        self.setTabOrder(self.btn_verify, self.btn_rollback)

        # Endpoint list management
        endpoint_group = QGroupBox("Endpoint List")
        endpoint_layout = QHBoxLayout(endpoint_group)
        self.endpoint_file_label = QLabel("Using built-in endpoint list")
        self.endpoint_file_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.endpoint_file_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.btn_load_endpoints = QPushButton("Load from File")
        self.btn_load_endpoints.clicked.connect(self.load_endpoints_file)
        self.btn_fetch_github = QPushButton("Update from GitHub")
        self.btn_fetch_github.clicked.connect(self.fetch_endpoints_from_github)
        if not HAS_REQUESTS:
            self.btn_fetch_github.setEnabled(False)
            self.btn_fetch_github.setToolTip("requests module not installed")
        endpoint_layout.addWidget(self.endpoint_file_label, 1)
        endpoint_layout.addWidget(self.btn_load_endpoints)
        endpoint_layout.addWidget(self.btn_fetch_github)
        actions_layout.addWidget(endpoint_group)
        # Aggressive opt-in checkbox
        self.aggressive_checkbox = QCheckBox("Include Windows Update endpoints (aggressive, breaks patching)")
        self.aggressive_checkbox.setChecked(False)
        self.aggressive_checkbox.setToolTip("WARNING: adds Windows Update / delivery endpoints. May break patching. Off by default.")
        self.aggressive_checkbox.setAccessibleName("aggressive_checkbox")
        self.aggressive_checkbox.setAccessibleDescription("Include Windows Update endpoints in block list")
        self.aggressive_checkbox.toggled.connect(self.on_aggressive_toggled)
        actions_layout.addWidget(self.aggressive_checkbox)

        # Tray monitoring tab
        self.tray_tab = QWidget()
        self.tabs.addTab(self.tray_tab, "Tray Monitor")
        tray_layout = QVBoxLayout(self.tray_tab)
        tray_info = QLabel(
            "Enable background monitoring. The app will minimize to the system tray "
            "and periodically check if GDID reappears. A notification will be shown."
        )
        tray_info.setWordWrap(True)
        tray_layout.addWidget(tray_info)
        self.monitor_checkbox = QCheckBox("Monitor in background")
        self.monitor_checkbox.setAccessibleName("monitor_checkbox")
        self.monitor_checkbox.setAccessibleDescription("Enable background GDID monitoring")
        tray_layout.addWidget(self.monitor_checkbox)
        self.monitor_interval = QSpinBox()
        self.monitor_interval.setRange(1, 60)
        self.monitor_interval.setValue(5)
        self.monitor_interval.setSuffix(" minutes")
        self.monitor_interval.setAccessibleName("monitor_interval")
        self.monitor_interval.setAccessibleDescription("Check interval in minutes")
        form = QFormLayout()
        form.addRow("Check interval:", self.monitor_interval)
        tray_layout.addLayout(form)
        self.btn_start_monitor = QPushButton("Start Monitoring")
        self.btn_start_monitor.setAccessibleName("btn_start_monitor")
        self.btn_start_monitor.setAccessibleDescription("Start background tray monitoring")
        self.btn_start_monitor.clicked.connect(self.start_tray_monitor)
        tray_layout.addWidget(self.btn_start_monitor)

        # Startup checkbox (default unchecked — real state arrives via
        # background verify, so __init__ never flashes a console).
        self.startup_checkbox = QCheckBox("Start with Windows (elevated, background)")
        self.startup_checkbox.setAccessibleName("startup_checkbox")
        self.startup_checkbox.setAccessibleDescription("Create elevated logon task")
        self.startup_checkbox.setToolTip("Creates elevated ONLOGON schtask. Requires UAC.")
        self.startup_checkbox.setChecked(False)
        self.startup_checkbox.stateChanged.connect(self.on_startup_checkbox_changed)
        tray_layout.addWidget(self.startup_checkbox)

        # Log tab
        self.log_tab = QWidget()
        self.tabs.addTab(self.log_tab, "Log")
        log_layout = QVBoxLayout(self.log_tab)
        log_toolbar = QHBoxLayout()
        self.btn_clear_log = QPushButton("Clear")
        self.btn_clear_log.setAccessibleName("btn_clear_log")
        self.btn_clear_log.setAccessibleDescription("Clear the visible log view")
        self.btn_clear_log.setToolTip("Clear the visible log view")
        self.btn_clear_log.clicked.connect(self.clear_log)
        self.btn_save_log = QPushButton("Save")
        self.btn_save_log.setAccessibleName("btn_save_log")
        self.btn_save_log.setAccessibleDescription("Save log to a file")
        self.btn_save_log.setToolTip("Save log to a file")
        self.btn_save_log.clicked.connect(self.save_log)
        self.log_filter = QLineEdit()
        self.log_filter.setPlaceholderText("Filter…")
        self.log_filter.setAccessibleName("log_filter")
        self.log_filter.textChanged.connect(self.on_log_filter_changed)
        self.autoscroll_checkbox = QCheckBox("Autoscroll")
        self.autoscroll_checkbox.setChecked(True)
        log_toolbar.addWidget(self.btn_clear_log)
        log_toolbar.addWidget(self.btn_save_log)
        log_toolbar.addWidget(self.log_filter)
        log_toolbar.addWidget(self.autoscroll_checkbox)
        log_layout.addLayout(log_toolbar)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        self.log_text.setPlaceholderText("Operations appear here…")
        self.log_text.setAccessibleName("log_text")
        self.log_text.setAccessibleDescription("Operation log")
        log_layout.addWidget(self.log_text)

        # Progress bar
        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        # Initialize endpoints
        self.endpoints: List[str] = []
        self.load_endpoints_from_default()

        # Worker threads
        self.worker: Optional[WorkerThread] = None
        self.monitor_timer: Optional[QTimer] = None

        # Load saved monitoring settings
        monitor_enabled, interval = load_monitor_settings()
        self.monitor_checkbox.setChecked(monitor_enabled)
        self.monitor_interval.setValue(interval)

        self.log("Application started.")
        # Auto-populate the Status dashboard on launch (non-blocking worker).
        try:
            QTimer.singleShot(VERIFY_STARTUP_DELAY_MS, self.verify_all)
        except Exception:
            pass

    # ------------------------------------------------------------------
    def log(self, message: str):
        #Timestamped, color-coded log + audit file append.
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        upper = message.upper()
        if "FAIL" in upper or "ERROR" in upper:
            self.log_text.setTextColor(QColor("red"))
        elif "WARN" in upper:
            self.log_text.setTextColor(QColor("orange"))
        elif message.startswith("OK") or " OK" in message or "SUCCESS" in upper or "OK:" in message:
            self.log_text.setTextColor(QColor("darkgreen"))
        else:
            self.log_text.setTextColor(QColor("black"))
        self.log_text.append(f"[{timestamp}] {message}")
        self.log_text.setTextColor(QColor("black"))
        if getattr(self, "autoscroll_checkbox", None) is not None:
            try:
                if self.autoscroll_checkbox.isChecked():
                    self.log_text.moveCursor(QTextCursor.End)
                    self.log_text.ensureCursorVisible()
            except RuntimeError:
                pass
        _append_audit_file(message)

    def clear_log(self):
        #Clear the visible log view.
        self.log_text.clear()

    def save_log(self):
        #Save log_text contents to a user-chosen file.
        path, _ = QFileDialog.getSaveFileName(self, "Save Log", "gdid_remover.log", "Log Files (*.log *.txt);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.log_text.toPlainText())
            self.log(f"Log saved to {path}.")
        except OSError as e:
            QMessageBox.critical(self, "Error", f"Failed to save log: {e}")

    def on_log_filter_changed(self, text: str):
        #Jump to next occurrence of filter text.
        if not text:
            return
        try:
            self.log_text.find(text)
        except Exception:
            pass

    def open_log_tab(self):
        #Restore window and show the Log tab.
        self.show_normal()
        try:
            self.tabs.setCurrentWidget(self.log_tab)
        except RuntimeError:
            pass

    def _active_endpoints(self) -> List[str]:
        #DEFAULT list, plus AGGRESSIVE when checkbox is on. Fetched/file-loaded
        #lists are filtered here so UPDATE_RELATED never applies without opt-in.
        base = list(self.endpoints) if self.endpoints else DEFAULT_ENDPOINTS.copy()
        if getattr(self, "aggressive_checkbox", None) is not None and self.aggressive_checkbox.isChecked():
            return sorted(set(base) | set(AGGRESSIVE_ENDPOINTS))
        return sorted(e for e in set(base) if e not in UPDATE_RELATED)

    def on_aggressive_toggled(self, checked: bool):
        #Rebuild endpoint list when aggressive opt-in changes.
        if checked:
            ans = QMessageBox.question(
                self, "Confirm Aggressive",
                f"Include {len(AGGRESSIVE_ENDPOINTS)} Windows Update endpoints? This may break patching. Continue?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if ans != QMessageBox.Yes:
                self.aggressive_checkbox.blockSignals(True)
                self.aggressive_checkbox.setChecked(False)
                self.aggressive_checkbox.blockSignals(False)
                return
            self.endpoints = sorted(set(DEFAULT_ENDPOINTS) | set(AGGRESSIVE_ENDPOINTS))
            self.log(f"Aggressive ON: {len(self.endpoints)} endpoints (includes {len(AGGRESSIVE_ENDPOINTS)} update-related). Patching may break.")
        else:
            # Drop aggressive entries, keep any custom-loaded ones that are safe.
            self.endpoints = [e for e in self.endpoints if e not in UPDATE_RELATED] or DEFAULT_ENDPOINTS.copy()
            self.log(f"Aggressive OFF: {len(self.endpoints)} endpoints.")
        self._refresh_block_tooltip()
        self.endpoint_file_label.setText(f"Using {'aggressive' if checked else 'built-in'} list ({len(self.endpoints)} endpoints)")

    def _refresh_block_tooltip(self):
        #Dynamic tooltip for Block button with N + backup path.
        try:
            n = len(self.endpoints)
            self.btn_block_endpoints.setToolTip(f"Appends {n} domains as 0.0.0.0 to hosts. Backup at {HOSTS_BACKUP}")
        except RuntimeError:
            pass

    def _mark_step_done(self, btn: QPushButton, step_prefix: str):
        #Prefix button text with checkmark, preserving mnemonic.
        #step_prefix ("1"/"2") identifies the workflow step for logs.
        try:
            t = btn.text()
            if not t.startswith("✓"):
                # Keep & mnemonic: insert check before it.
                if t.startswith("&"):
                    btn.setText("✓ &" + t[1:])
                else:
                    btn.setText("✓ " + t)
            logger.info("Step %s marked done: %s", step_prefix, btn.text())
        except RuntimeError:
            pass

    def _update_dashboard(self, gdid_ok=None, services_ok=None, hosts_ok=None, task_ok=None, last_checked=None):
        #Update status dashboard labels green/red + timestamp. Only paints rows with non-None values.
        #NOTE: never runs schtasks/sc here — task_ok must be supplied by the
        #verify worker. Calling subprocess on the GUI thread flashes consoles.
        def paint(lbl: QLabel, text: str, ok: Optional[bool]):
            lbl.setText(text)
            if ok is True:
                lbl.setStyleSheet("color:darkgreen")
            elif ok is False:
                lbl.setStyleSheet("color:darkred")
            else:
                lbl.setStyleSheet("")
        try:
            if gdid_ok is not None:
                if gdid_ok is True:
                    paint(self.gdid_label, "GDID status: Not present (OK)", True)
                else:
                    paint(self.gdid_label, "GDID status: Present — action needed", False)
            if services_ok is not None:
                if services_ok is True:
                    paint(self.lbl_services, "Services: Disabled", True)
                else:
                    paint(self.lbl_services, "Services: Attention needed", False)
            if hosts_ok is not None:
                if hosts_ok is True:
                    paint(self.lbl_hosts, "Hosts: Blocked", True)
                else:
                    paint(self.lbl_hosts, "Hosts: Missing entries", False)
            if task_ok is not None:
                if task_ok is True:
                    paint(self.lbl_task, "Startup task: Present", True)
                else:
                    paint(self.lbl_task, "Startup task: Absent", False)
            ts = last_checked if isinstance(last_checked, str) and last_checked else time.strftime("%Y-%m-%d %H:%M:%S")
            self.lbl_last_checked.setText(f"Last checked: {ts}")
        except RuntimeError:
            pass

    # ------------------------------------------------------------------
    def check_gdid(self):
        self.log("Checking GDID (HKLM + HKCU)...")
        values = read_gdid_values()
        if values:
            for hive_name, value in values.items():
                self.log(f"GDID present in {hive_name}: {value}")
            first = next(iter(values.values()))
            self.gdid_label.setText(f"GDID found: {first} (in {', '.join(values.keys())})")
            self.gdid_label.setStyleSheet("color:darkred")
            self.log(f"GDID present: {values}")
            try:
                self._update_dashboard(gdid_ok=False, last_checked=time.strftime("%Y-%m-%d %H:%M:%S"))
            except Exception:
                pass
        else:
            self.gdid_label.setText("GDID not found.")
            self.gdid_label.setStyleSheet("color:darkgreen")
            self.log("GDID is not present in HKLM nor HKCU.")
            try:
                self._update_dashboard(gdid_ok=True, last_checked=time.strftime("%Y-%m-%d %H:%M:%S"))
            except Exception:
                pass

    # ------------------------------------------------------------------
    def disable_services(self):
        services_preview = SERVICES_TO_DISABLE.copy()
        try:
            services_preview.extend(get_cdp_user_services())
        except Exception:
            pass
        n = len(services_preview)
        ans = QMessageBox.question(
            self, "Confirm Disable",
            f"Disable {n}+ services? Sets Start=4, requires reboot. Backup will be saved. Continue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if ans != QMessageBox.Yes:
            return
        self.log("Disabling services...")
        _append_audit_file(f"disable_services start snapshot={_service_snapshot_json(services_preview)}")

        def task(log_callback, progress_callback):
            services = SERVICES_TO_DISABLE.copy()
            cdp_user = get_cdp_user_services()
            services.extend(cdp_user)
            log_callback(f"Services to disable: {', '.join(services)}")
            results = {}
            total = max(1, len(services))
            for i, svc in enumerate(services):
                log_callback(f"Processing {svc}...")
                reg_path = reg_path_for(svc)
                # Snapshot original Start once before first disable.
                if get_backup_start(svc) is None:
                    snapshot_service_start(svc)
                pre = read_registry_value(_service_hive(), reg_path, "Start")

                reg_success = write_registry_dword(_service_hive(), reg_path, "Start", SERVICE_START_DISABLED)
                if reg_success:
                    post = read_registry_value(_service_hive(), reg_path, "Start")
                    log_callback(f"  Registry Start {pre}->{post} for {svc}")
                else:
                    log_callback(f"  FAILED to set registry Start for {svc}")
                    results[svc] = False
                    continue

                if svc.startswith("CDPUserSvc_"):
                    if service_exists(svc):
                        stop_service(svc)
                        log_callback(f"  Stopped {svc} (per-user service, registry disabled)")
                    else:
                        log_callback(f"  {svc} not running or does not exist")
                    results[svc] = True
                    continue

                if not service_exists(svc):
                    log_callback(f"  Service {svc} does not exist; registry change is sufficient")
                    results[svc] = True
                    continue

                if stop_service(svc):
                    log_callback(f"  Stopped {svc}")
                else:
                    log_callback(f"  Could not stop {svc} (may already be stopped)")

                success, msg = disable_service(svc)
                if success:
                    log_callback(f"  Disabled {svc} via sc config")
                else:
                    log_callback(f"  sc config failed for {svc}: {msg}")
                    log_callback(f"  Registry Start=4 should still disable it on next reboot")
                results[svc] = True
                try:
                    progress_callback(int((i + 1) * 100 / total))
                except Exception:
                    pass

            return results

        def _on_disable_finished(res):
            self.log("Service disabling completed.")
            try:
                ok_flag = bool(res.get("success"))
                results = res.get("result") if ok_flag else {}
                if isinstance(results, dict) and results:
                    ok_n = sum(1 for v in results.values() if v)
                    fail_n = len(results) - ok_n
                    self.log(f"Disable summary: {ok_n} succeeded, {fail_n} failed — see Log.")
                    QMessageBox.information(self, "Disable Result", f"{ok_n} succeeded, {fail_n} failed — see Log.")
                    if fail_n == 0:
                        self._mark_step_done(self.btn_disable_services, "1")
                else:
                    self.log(f"Disable finished success={ok_flag}.")
            except Exception:
                pass
            QMessageBox.information(self, "Reboot Required", "Reboot required for Start=4 to fully apply.")
            # Refresh Status dashboard so Services row leaves "Unknown".
            try:
                QTimer.singleShot(POST_ACTION_REVERIFY_MS, self.verify_all)
            except Exception:
                pass

        self.run_worker(task, on_finished=_on_disable_finished)

    # ------------------------------------------------------------------
    def block_endpoints(self):
        active = list(self._active_endpoints())
        if not active:
            QMessageBox.warning(self, "No Endpoints", "No endpoints loaded. Load a file or update from GitHub.")
            return
        n = len(active)
        ans = QMessageBox.question(
            self, "Confirm Block",
            f"Append {n} domains as 0.0.0.0 to hosts? Backup at {HOSTS_BACKUP}. Continue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if ans != QMessageBox.Yes:
            return
        endpoints_snapshot = list(active)
        before_hash = _hosts_sha256()
        self.log(f"Blocking {len(endpoints_snapshot)} endpoints via hosts file... (sha256 before={before_hash})")

        def task(log_callback, progress_callback):
            success = modify_hosts_file(endpoints_snapshot, "add")
            after_hash = _hosts_sha256()
            log_callback(f"Hosts sha256 before={before_hash} after={after_hash}.")
            if success:
                log_callback("Endpoints added to hosts file successfully.")
            else:
                log_callback("Failed to modify hosts file (permission denied?).")
            return success

        def _on_block_finished(res):
            self.log("Endpoint blocking done.")
            try:
                ok_flag = bool(res.get("success") and res.get("result"))
                self.log(f"Block summary: {'1 succeeded, 0 failed' if ok_flag else '0 succeeded, 1 failed'} — see Log.")
                QMessageBox.information(self, "Block Result", f"{'1 succeeded, 0 failed' if ok_flag else '0 succeeded, 1 failed'} — see Log.")
                if ok_flag:
                    self._mark_step_done(self.btn_block_endpoints, "2")
            except Exception:
                pass
            # Refresh Status dashboard so Hosts row leaves "Unknown".
            try:
                QTimer.singleShot(POST_ACTION_REVERIFY_MS, self.verify_all)
            except Exception:
                pass

        self.run_worker(task, on_finished=_on_block_finished)

    # ------------------------------------------------------------------
    def delete_gdid(self):
        # Intentionally synchronous: 2 registry deletes (<100ms), no subprocess/hosts I/O.
        try:
            if self.worker is not None and self.worker.isRunning():
                QMessageBox.warning(self, "Busy", "Another operation is still running.")
                return False
        except RuntimeError:
            self.worker = None
        ans = QMessageBox.question(
            self, "Confirm Delete",
            "Delete GDID (LID in HKLM+HKCU IdentityCRL)? Reversible via re-login. Continue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if ans != QMessageBox.Yes:
            return
        self.log("Deleting GDID registry value (HKLM + HKCU)...")
        try:
            ok_hklm = delete_registry_value(winreg.HKEY_LOCAL_MACHINE, GDID_REG_PATH, GDID_VALUE_NAME)
            ok_hkcu = delete_registry_value(winreg.HKEY_CURRENT_USER, GDID_REG_PATH, GDID_VALUE_NAME)
            remaining = read_gdid_values()
        except OSError as e:
            logger.warning("GDID delete failed: %s", e)
            self.log(f"FAIL: GDID Delete failed (admin?): {e}")
            QMessageBox.critical(self, "Delete Failed", f"Delete failed (admin?): {e}")
            return False
        if not remaining:
            if ok_hklm or ok_hkcu:
                self.log(f"OK: GDID deleted (HKLM:{ok_hklm} HKCU:{ok_hkcu}).")
            else:
                self.log("OK: GDID Not present (OK) — nothing to delete.")
            self.gdid_label.setText("GDID deleted.")
            self.gdid_label.setStyleSheet("color:darkgreen")
            try:
                self._update_dashboard(gdid_ok=True, last_checked=time.strftime("%Y-%m-%d %H:%M:%S"))
                QTimer.singleShot(POST_ACTION_REVERIFY_MS, self.verify_all)
            except Exception:
                pass
            return True
        else:
            self.log(f"FAIL: GDID Delete failed (admin?) — still present: {remaining}")
            self.gdid_label.setText(f"GDID still present: {remaining}")
            self.gdid_label.setStyleSheet("color:darkred")
            QMessageBox.warning(self, "Delete Incomplete", f"Delete failed (admin?) — still present: {remaining}")
            try:
                self._update_dashboard(gdid_ok=False, last_checked=time.strftime("%Y-%m-%d %H:%M:%S"))
            except Exception:
                pass
            return False

    # ------------------------------------------------------------------
    def verify_all(self):
        self.log("Verifying all changes (background)...")
        try:
            self.lbl_services.setText("Services: Checking…")
            self.lbl_hosts.setText("Hosts: Checking…")
            self.lbl_task.setText("Startup task: Checking…")
        except RuntimeError:
            pass
        endpoints_snapshot = list(self._active_endpoints())

        def task(log_callback, progress_callback):
            gdid = read_gdid_values()
            gdid_ok: bool = not bool(gdid)
            if gdid:
                log_callback(f"FAIL: GDID still present: {gdid}")
            else:
                log_callback("OK: GDID not present in HKLM nor HKCU.")
            try:
                progress_callback(10)
            except Exception:
                pass

            services = SERVICES_TO_DISABLE.copy()
            services.extend(get_cdp_user_services())
            services_ok: bool = True
            total = max(1, len(services))
            for i, svc in enumerate(services):
                reg_path = reg_path_for(svc)
                try:
                    start_value = read_registry_value(_service_hive(), reg_path, "Start")
                except OSError as e:
                    log_callback(f"WARN: {svc} read failed: {e}")
                    services_ok = False
                    continue
                if start_value is not None and start_value == str(SERVICE_START_DISABLED):
                    log_callback(f"OK: {svc} is disabled (Start={SERVICE_START_DISABLED}).")
                else:
                    log_callback(f"WARN: {svc} may not be disabled (Start={start_value}).")
                    services_ok = False
                try:
                    progress_callback(int(10 + (i + 1) * 70 / total))
                except Exception:
                    pass

            try:
                with open(HOSTS_FILE, "r", encoding="utf-8", errors="strict") as f:
                    hosts_content = f.read()
            except OSError as e:
                log_callback(f"ERROR: cannot read hosts file: {e}")
                hosts_content = ""

            missing = [ep for ep in endpoints_snapshot if (normalize_endpoint(ep) or "") and not is_endpoint_blocked(hosts_content, normalize_endpoint(ep))]
            hosts_ok: bool = not bool(missing)
            if missing:
                log_callback(f"WARN: Missing {len(missing)} endpoints in hosts file: {missing}")
            else:
                log_callback("OK: All endpoints are present in hosts file (exact match).")
            try:
                task_ok: Optional[bool] = is_elevated_startup_task_exists()
            except Exception as e:
                log_callback(f"WARN: startup task query failed: {e}")
                task_ok = None
            try:
                progress_callback(100)
            except Exception:
                pass
            return {"gdid_ok": gdid_ok, "services_ok": services_ok, "hosts_ok": hosts_ok, "task_ok": task_ok}

        def _on_verify_finished(res):
            try:
                if not res.get("success"):
                    self.log(f"FAIL: Verify worker failed: {res.get('error', 'Unknown error')}")
                    return
                d = res.get("result") or {}
                gdid_ok = d.get("gdid_ok")
                services_ok = d.get("services_ok")
                hosts_ok = d.get("hosts_ok")
                task_ok = d.get("task_ok")
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                self._update_dashboard(gdid_ok, services_ok, hosts_ok, task_ok=task_ok, last_checked=ts)
                self.log(f"Verify completed: gdid_ok={gdid_ok} services_ok={services_ok} hosts_ok={hosts_ok} task_ok={task_ok} last_checked={ts}.")
                # Keep startup checkbox in sync without flashing (no subprocess here — value from worker).
                try:
                    if task_ok is not None:
                        self.startup_checkbox.blockSignals(True)
                        self.startup_checkbox.setChecked(bool(task_ok))
                        self.startup_checkbox.blockSignals(False)
                except RuntimeError:
                    pass
            except Exception as e:
                self.log(f"FAIL: Verify summary failed: {e}")

        self.run_worker(task, on_finished=_on_verify_finished)

    # ------------------------------------------------------------------
    def rollback(self):
        endpoints_snapshot = list(self._active_endpoints())
        n = len(endpoints_snapshot)
        ans = QMessageBox.question(
            self, "Confirm Rollback",
            f"Restore services to backed-up values + remove {n} hosts entries? Continue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if ans != QMessageBox.Yes:
            return
        before_hash = _hosts_sha256()
        self.log(f"Rolling back changes (background)... (hosts sha256 before={before_hash})")
        _append_audit_file(f"rollback start endpoints={n} hosts_before={before_hash}")

        def task(log_callback, progress_callback):
            services = SERVICES_TO_DISABLE.copy()
            services.extend(get_cdp_user_services())
            start_to_sc = {SERVICE_START_AUTO: "auto", SERVICE_START_MANUAL: "demand", SERVICE_START_DISABLED: "disabled"}
            total = max(1, len(services))
            for i, svc in enumerate(services):
                reg_path = reg_path_for(svc)
                pre = read_registry_value(_service_hive(), reg_path, "Start")
                backup = get_backup_start(svc)
                target = backup if backup is not None else SERVICE_START_MANUAL
                ok = write_registry_dword(_service_hive(), reg_path, "Start", target)
                post = read_registry_value(_service_hive(), reg_path, "Start")
                if not svc.startswith("CDPUserSvc_"):
                    sc_arg = start_to_sc.get(target, "demand")
                    try:
                        _hidden_run(["sc", "config", svc, "start=", sc_arg], SC_TIMEOUT_S)
                    except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as e:
                        log_callback(f"sc config failed for {svc}: {e}")
                        logger.warning("Rollback sc config failed for %s: %s", svc, e)
                log_callback(f"Restored {svc}: Start {pre}->{post} (target={target}, backup={backup}, ok={ok}).")
                try:
                    progress_callback(int((i + 1) * 80 / total))
                except Exception:
                    pass
            ok_hosts = modify_hosts_file(endpoints_snapshot, "remove")
            after_hash = _hosts_sha256()
            log_callback(f"Hosts entries removed: {ok_hosts} (sha256 before={before_hash} after={after_hash}).")
            try:
                progress_callback(100)
            except Exception:
                pass
            return {"hosts_ok": bool(ok_hosts), "after_hash": after_hash}

        def _on_rollback_finished(res):
            after_hash = _hosts_sha256()
            try:
                result = res.get("result")
                if isinstance(result, dict):
                    ok_flag = bool(res.get("success") and result.get("hosts_ok", True))
                else:
                    ok_flag = bool(res.get("success"))
            except Exception:
                ok_flag = bool(res.get("success"))
            self.log(f"Rollback completed: hosts sha256 before={before_hash} after={after_hash} success={ok_flag}.")
            _append_audit_file(f"rollback done before={before_hash} after={after_hash} success={ok_flag}")
            QMessageBox.information(self, "Rollback Result", f"Services restored + {len(endpoints_snapshot)} hosts entries removed.\nhosts sha256 before={before_hash}\nafter={after_hash}")
            # Refresh Status dashboard so rows leave "Unknown" after restore.
            try:
                QTimer.singleShot(POST_ACTION_REVERIFY_MS, self.verify_all)
            except Exception:
                pass

        self.run_worker(task, on_finished=_on_rollback_finished)

    # ------------------------------------------------------------------
    def start_tray_monitor(self):
        if not self.monitor_checkbox.isChecked():
            QMessageBox.information(self, "Not Enabled", "Please check 'Monitor in background' first.")
            return
        if not QSystemTrayIcon.isSystemTrayAvailable():
            QMessageBox.warning(self, "No System Tray", "System tray is not available on this system. Monitoring will not work.")
            return
        interval_min = self.monitor_interval.value()
        save_monitor_settings(True, interval_min)
        self.log(f"Starting tray monitor (every {interval_min} minutes).")
        ans = QMessageBox.information(
            self, "Minimize to Tray",
            "Minimized to tray — double-click (or single-click) to restore, Exit via tray menu",
            QMessageBox.Ok | QMessageBox.Cancel, QMessageBox.Ok)
        if ans != QMessageBox.Ok:
            return
        self.hide()
        self.tray_icon.show()
        if self.monitor_timer is None:
            self.monitor_timer = QTimer()
            self.monitor_timer.timeout.connect(self.check_gdid_silent)
        else:
            self.monitor_timer.stop()
        self.monitor_timer.start(interval_min * 60 * 1000)
        self.check_gdid_silent()
        try:
            last_check = time.strftime("%Y-%m-%d %H:%M:%S")
            self.tray_icon.setToolTip(f"GDID Remover — monitoring every {interval_min} min, last check {last_check}")
        except Exception:
            pass

    def check_gdid_silent(self):
        vals = read_gdid_values()
        gdid = next(iter(vals.values()), None)
        if gdid:
            self.tray_icon.showMessage(
                "GDID Restored!",
                "The GDID value has reappeared. Consider re-running removal steps.",
                QSystemTrayIcon.Warning,
                10000
            )
            self.log("Tray monitor: GDID detected again!")

    def tray_activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.show_normal()
        # Tray menu already wires: Show -> show_normal, Check now -> check_gdid_silent, Open log -> open_log_tab, Exit -> quit_app.

    def show_normal(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def quit_app(self):
        self.tray_icon.hide()
        QApplication.quit()

    # ------------------------------------------------------------------
    def closeEvent(self, event):
        if self.monitor_timer and self.monitor_timer.isActive():
            ans = QMessageBox.question(
                self, "Minimize or Quit?",
                "Monitoring is active.\n[Yes] = Minimize to tray (keep monitoring)\n[No] = Quit (stop monitoring)",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            if ans == QMessageBox.Yes:
                # Yes = minimize to tray.
                event.ignore()
                self.hide()
                self.tray_icon.show()
                self.tray_icon.showMessage(
                    "GDID Remover",
                    "Continuing to monitor in background.",
                    QSystemTrayIcon.Information,
                    5000
                )
            else:
                # No = quit.
                event.accept()
                try:
                    self.tray_icon.hide()
                except Exception:
                    pass
                QApplication.quit()
        else:
            event.accept()
            QApplication.quit()

    # ------------------------------------------------------------------
    def set_actions_enabled(self, enabled: bool):
        widgets = [self.btn_disable_services, self.btn_block_endpoints, self.btn_delete_gdid,
                    self.btn_verify, self.btn_rollback, self.btn_fetch_github,
                    self.btn_load_endpoints, self.btn_start_monitor]
        try:
            widgets.append(self.refresh_status_btn)
        except AttributeError:
            pass
        try:
            widgets.append(self.check_gdid_btn)
        except AttributeError:
            pass
        # Misc members: aggressive opt-in + log toolbar controls.
        for extra in ("aggressive_checkbox", "btn_clear_log", "btn_save_log", "log_filter", "autoscroll_checkbox", "monitor_checkbox", "monitor_interval", "startup_checkbox"):
            w = getattr(self, extra, None)
            if w is not None:
                widgets.append(w)
            else:
                try:
                    found = self.findChildren(QWidget, extra)
                    widgets.extend(found)
                except Exception:
                    pass
        for btn in widgets:
            try:
                btn.setEnabled(enabled)
            except RuntimeError:
                pass

    def run_worker(self, func, on_finished=None):
        try:
            worker_running = bool(self.worker is not None and self.worker.isRunning())
        except RuntimeError:
            # Previously deleteLater'd worker — treat as not running.
            self.worker = None
            worker_running = False
        if worker_running:
            QMessageBox.warning(self, "Busy", "Another operation is still running.")
            self.progress.setRange(0, 100)
            return False
        self.progress.setRange(0, 0)
        self.set_actions_enabled(False)
        self.worker = WorkerThread(func)
        self.worker.signals.log.connect(self.log)
        self.worker.signals.progress.connect(self.progress.setValue)
        self.worker.signals.finished.connect(lambda res: self.worker_finished(res, on_finished))
        self.worker.start()
        return True

    def worker_finished(self, result, callback):
        if not isinstance(result, dict):
            result = {"success": False, "error": f"Bad worker payload: {type(result).__name__}"}
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.set_actions_enabled(True)
        try:
            w, self.worker = self.worker, None
            if w is not None:
                w.deleteLater()
        except RuntimeError:
            self.worker = None
        if callback:
            try:
                callback(result)
            except Exception as e:
                logger.warning("on_finished callback failed: %s", e)
                self.log(f"Callback error: {e}")
        if not result.get("success"):
            QMessageBox.critical(self, "Error", f"Operation failed: {result.get('error', 'Unknown error')}")

    # ------------------------------------------------------------------
    def load_endpoints_from_default(self):
        self.endpoints = DEFAULT_ENDPOINTS.copy()
        self.endpoint_file_label.setText(f"Using built-in list ({len(self.endpoints)} endpoints)")
        self.log("Loaded built-in endpoint list.")
        try:
            self._refresh_block_tooltip()
        except Exception:
            pass

    def load_endpoints_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Endpoints File", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                size = os.path.getsize(file_path)
                if size > MAX_ENDPOINT_FILE_BYTES:
                    QMessageBox.critical(self, "Error", f"File too large ({size} bytes, max {MAX_ENDPOINT_FILE_BYTES}).")
                    return
                with open(file_path, "r", encoding="utf-8", errors="strict") as f:
                    raw = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
            except (OSError, UnicodeDecodeError) as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {e}")
                return
            cleaned = []
            skipped = 0
            for ep in raw:
                n = normalize_endpoint(ep)
                if n:
                    cleaned.append(n)
                else:
                    skipped += 1
            deduped = sorted(set(cleaned))
            if len(deduped) > MAX_ENDPOINTS:
                self.log(f"Endpoint list truncated to {MAX_ENDPOINTS} (was {len(deduped)}).")
                deduped = deduped[:MAX_ENDPOINTS]
            self.endpoints = deduped
            self.endpoint_file_label.setText(f"Loaded {len(self.endpoints)} endpoints from {file_path} (skipped {skipped} invalid)")
            self.log(f"Loaded endpoints from {file_path}: {len(self.endpoints)} valid, {skipped} skipped.")
            try:
                self._refresh_block_tooltip()
            except Exception:
                pass

    def fetch_endpoints_from_github(self):
        if not HAS_REQUESTS:
            QMessageBox.critical(self, "Error", "The 'requests' module is not installed. Cannot fetch.")
            return
        self.log("Fetching endpoints from GitHub...")

        def task(log_callback, progress_callback):
            try:
                url = "https://raw.githubusercontent.com/Korben00/no-gdid/main/mitigate/Block-GDID-Endpoints.ps1"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    text = response.text
                    endpoints = re.findall(r"'([^']*\.[^']*)'", text)
                    cleaned = []
                    skipped = 0
                    for ep in endpoints:
                        n = normalize_endpoint(ep)
                        if n:
                            cleaned.append(n)
                        else:
                            skipped += 1
                    deduped = sorted(set(cleaned))
                    if len(deduped) > MAX_ENDPOINTS:
                        log_callback(f"Fetched list truncated to {MAX_ENDPOINTS} (was {len(deduped)}).")
                        deduped = deduped[:MAX_ENDPOINTS]
                    aggressive = sorted(set(deduped) & UPDATE_RELATED)
                    if aggressive:
                        log_callback(f"WARNING: aggressive update-related endpoints fetched (may break Windows Update): {aggressive}")
                    if deduped:
                        log_callback(f"Fetched {len(deduped)} endpoints from GitHub (skipped {skipped} invalid).")
                        return deduped
                    else:
                        log_callback("No endpoints found in the fetched content.")
                        return []
                else:
                    log_callback(f"Failed to fetch (HTTP {response.status_code}).")
                    return []
            except Exception as e:
                logger.warning("GitHub fetch failed: %s", e)
                log_callback(f"Error during fetch: {e}")
                return []

        def on_finished(result):
            # GUI-thread only: mutate self.endpoints here, never in worker.
            if result.get("success") and result.get("result"):
                self.endpoints = sorted(set(result.get("result")))
                self.endpoint_file_label.setText(f"Fetched {len(self.endpoints)} endpoints from GitHub")
                self.log(f"Endpoint list updated: {len(self.endpoints)} endpoints.")
            else:
                err = result.get("error", "") if isinstance(result, dict) else ""
                detail = f" ({err})" if err else ""
                self.endpoint_file_label.setText(f"Fetch failed{detail} — using built-in list")
                self.log(f"Fetch failed{detail} — using built-in list. See Log for TLS/HTTP detail.")
            try:
                self._refresh_block_tooltip()
            except Exception:
                pass

        self.run_worker(task, on_finished=on_finished)

    # ------------------------------------------------------------------
    def on_startup_checkbox_changed(self, state):
        # state: 0 = unchecked, 2 = checked (also possible 1 = partially checked)
        enabled = state != 0
        # Guard: if worker busy, revert checkbox and return (run_worker restores progress)
        try:
            busy = bool(self.worker is not None and self.worker.isRunning())
        except RuntimeError:
            self.worker = None
            busy = False
        if busy:
            self.startup_checkbox.blockSignals(True)
            self.startup_checkbox.setChecked(not enabled)
            self.startup_checkbox.blockSignals(False)
            QMessageBox.warning(self, "Busy", "Another operation is still running.")
            return
        if enabled:
            ans = QMessageBox.question(
                self, "Confirm Startup Task",
                "Create an elevated ONLOGON scheduled task (runs at logon with admin rights)? Continue?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if ans != QMessageBox.Yes:
                self.startup_checkbox.blockSignals(True)
                self.startup_checkbox.setChecked(False)
                self.startup_checkbox.blockSignals(False)
                return
        self.startup_checkbox.setEnabled(False)

        def task(log_callback, progress_callback):
            if enabled:
                return ("create",) + create_elevated_startup_task()
            return ("delete",) + delete_elevated_startup_task()

        def on_finished(result):
            # GUI-thread only.
            self.startup_checkbox.setEnabled(True)
            if not result.get("success"):
                self.startup_checkbox.blockSignals(True)
                self.startup_checkbox.setChecked(not enabled)
                self.startup_checkbox.blockSignals(False)
                return
            action, success, error = result.get("result")
            if action == "create":
                if success:
                    self.log("Elevated startup task created. The app will run at logon with admin rights.")
                    QMessageBox.information(self, "Success", "Startup task created successfully.")
                    if self.monitor_checkbox.isChecked() and (self.monitor_timer is None or not self.monitor_timer.isActive()):
                        self.start_tray_monitor()
                else:
                    self.log(f"Failed to create startup task: {error}")
                    logger.warning("Create startup task failed: %s", error)
                    QMessageBox.critical(self, "Error", f"Failed to create startup task:\n{error}")
                    self.startup_checkbox.blockSignals(True)
                    self.startup_checkbox.setChecked(False)
                    self.startup_checkbox.blockSignals(False)
            else:
                if success:
                    self.log("Elevated startup task removed.")
                    QMessageBox.information(self, "Success", "Startup task removed.")
                else:
                    self.log(f"Failed to remove startup task: {error}")
                    logger.warning("Delete startup task failed: %s", error)
                    QMessageBox.critical(self, "Error", f"Failed to remove startup task:\n{error}")
                    self.startup_checkbox.blockSignals(True)
                    self.startup_checkbox.setChecked(True)
                    self.startup_checkbox.blockSignals(False)

        self.run_worker(task, on_finished=on_finished)

    # ------------------------------------------------------------------
    def auto_start_monitoring(self):
        enabled, interval = load_monitor_settings()
        if enabled:
            self.monitor_checkbox.setChecked(True)
            self.monitor_interval.setValue(interval)
            self.tray_icon.show()
            self.monitor_timer = QTimer()
            self.monitor_timer.timeout.connect(self.check_gdid_silent)
            self.monitor_timer.start(interval * 60 * 1000)
            self.check_gdid_silent()
            self.log("Background monitoring started automatically.")
            return True
        return False

# ----------------------------------------------------------------------
def main():
    background_mode = "--background" in sys.argv

    if not is_admin():
        if "--elevated" in sys.argv:
            logger.error("Elevation failed (already tried --elevated).")
            sys.exit(1223)
        try:
            elevate()
        except (OSError, PermissionError) as e:
            logger.error("Failed to elevate: %s", e)
            sys.exit(1)
        sys.exit(0)

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    window = GDIDRemoverApp()

    if background_mode:
        if not window.auto_start_monitoring():
            window.tray_icon.show()
    else:
        window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()