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
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QProgressBar, QTabWidget,
    QMessageBox, QSystemTrayIcon, QMenu, QLineEdit, QFileDialog,
    QGroupBox, QFormLayout, QSpinBox, QCheckBox, QStyle
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QObject
from PySide6.QtGui import QIcon, QAction

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
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

APP_SETTINGS_REG_PATH = r"Software\GDIDRemover"
MONITOR_ENABLED_VALUE = "MonitorEnabled"
MONITOR_INTERVAL_VALUE = "MonitorInterval"

TASK_NAME = "GDIDRemover"

DEFAULT_ENDPOINTS = [
    "login.live.com",
    "account.live.com",
    "settings-win.data.microsoft.com",
    "go.microsoft.com",
    "devicemetadata.microsoft.com",
    "cs.dds.microsoft.com",
    "vortex-win.data.microsoft.com",
    "telemetry.microsoft.com",
    "watson.telemetry.microsoft.com",
    "df.telemetry.microsoft.com",
    "diagnostics.support.microsoft.com",
    "statsfe2.ws.microsoft.com",
    "corpext.msitadfs.glbdns2.microsoft.com",
    "compatexchange.cloudapp.net",
    "cs1.wpc.v0cdn.net",
    "a-0001.a-msedge.net",
    "fe2.update.microsoft.com.akadns.net",
    "sdx.microsoft.com",
    "sls.update.microsoft.com.akadns.net",
    "fe3.delivery.dsp.mp.microsoft.com.nsatc.net",
    "tlu.dl.delivery.mp.microsoft.com",
    "client.wns.windows.com",
    "wdcp.microsoft.com",
    "wdcpalt.microsoft.com",
    "update.googleapis.com",
    "download.windowsupdate.com",
    "download.microsoft.com",
    "test.stats.update.microsoft.com",
    "ntservicepack.microsoft.com",
    "statsfe1.ws.microsoft.com",
    "statsfe2.update.microsoft.com.akadns.net",
    "survey.watson.microsoft.com",
    "watson.live.com",
    "watson.microsoft.com",
    "watson.ppe.telemetry.microsoft.com",
    "telecommand.telemetry.microsoft.com",
    "telecommand.telemetry.microsoft.com.nsatc.net",
    "oca.telemetry.microsoft.com",
    "oca.telemetry.microsoft.com.nsatc.net",
    "sqm.telemetry.microsoft.com",
    "sqm.telemetry.microsoft.com.nsatc.net",
    "watson.telemetry.microsoft.com.nsatc.net",
    "redir.metaservices.microsoft.com",
    "choice.microsoft.com",
    "choice.microsoft.com.nsatc.net",
    "df.telemetry.microsoft.com",
    "reports.wes.df.telemetry.microsoft.com",
    "services.wes.df.telemetry.microsoft.com",
    "wes.df.telemetry.microsoft.com",
    "watson.ppe.telemetry.microsoft.com",
    "telemetry.appex.bing.net",
    "telemetry.urs.microsoft.com",
    "vortex-sandbox.data.microsoft.com",
    "vortex-win.data.microsoft.com",
    "telemetry.appex.bing.net:443",
    "settings-sandbox.data.microsoft.com",
    "vortex.data.microsoft.com",
    "settings.data.microsoft.com",
    "watson.telemetry.microsoft.com",
    "oca.telemetry.microsoft.com",
    "sqm.telemetry.microsoft.com",
    "telemetry.microsoft.com",
    "watson.telemetry.microsoft.com",
    "telemetry.appex.bing.net",
    "telemetry.urs.microsoft.com",
    "settings-win.data.microsoft.com",
    "vortex-win.data.microsoft.com",
    "watson.telemetry.microsoft.com",
    "df.telemetry.microsoft.com",
]

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def elevate():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )

def read_registry_value(key_path: str, value_name: str) -> Optional[str]:
    hive = winreg.HKEY_LOCAL_MACHINE if key_path.startswith("SYSTEM") else winreg.HKEY_CURRENT_USER
    try:
        with winreg.OpenKey(hive, key_path) as key:
            value, _ = winreg.QueryValueEx(key, value_name)
            return str(value)
    except FileNotFoundError:
        return None
    except Exception:
        return None

def write_registry_dword(key_path: str, value_name: str, data: int) -> bool:
    hive = winreg.HKEY_LOCAL_MACHINE if key_path.startswith("SYSTEM") else winreg.HKEY_CURRENT_USER
    try:
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, data)
        return True
    except Exception as e:
        print(f"Registry write failed for {key_path}\\{value_name}: {e}")
        return False

def delete_registry_value(key_path: str, value_name: str) -> bool:
    hive = winreg.HKEY_LOCAL_MACHINE if key_path.startswith("SYSTEM") else winreg.HKEY_CURRENT_USER
    try:
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, value_name)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return False

def stop_service(service_name: str) -> bool:
    try:
        subprocess.run(["sc", "stop", service_name], check=False, capture_output=True, text=True, timeout=10)
        return True
    except subprocess.TimeoutExpired:
        return False

def disable_service(service_name: str) -> tuple[bool, str]:
    result = subprocess.run(
        ["sc", "config", service_name, "start=", "disabled"],
        check=False, capture_output=True, text=True, timeout=10
    )
    success = "SUCCESS" in result.stdout.upper() or "CHANGE_START_TYPE" in result.stdout.upper()
    message = result.stdout.strip() if result.stdout else result.stderr.strip()
    return success, message

def service_exists(service_name: str) -> bool:
    result = subprocess.run(["sc", "query", service_name], capture_output=True, text=True)
    return "FAILED" not in result.stdout.upper() and "DOES NOT EXIST" not in result.stdout.upper()

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
    except Exception:
        pass
    return services

def modify_hosts_file(endpoints: List[str], action: str = "add") -> bool:
    try:
        with open(HOSTS_FILE, "r") as f:
            lines = f.readlines()
    except PermissionError:
        return False

    if action == "add":
        new_lines = []
        for ep in endpoints:
            domain = ep.split(":")[0]
            entry = f"0.0.0.0 {domain}\n"
            if entry not in lines:
                new_lines.append(entry)
        lines.extend(new_lines)
    elif action == "remove":
        lines = [line for line in lines if not any(ep.split(":")[0] in line for ep in endpoints)]

    try:
        with open(HOSTS_FILE, "w") as f:
            f.writelines(lines)
        return True
    except PermissionError:
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

def create_elevated_startup_task() -> tuple[bool, str]:
    pythonw = get_pythonw_path()
    script = get_script_path()
    command = f'"{pythonw}" "{script}" --background'
    schtasks_cmd = (
        f'schtasks /Create /TN "{TASK_NAME}" '
        f'/TR "{command}" '
        f'/SC ONLOGON '
        f'/RL HIGHEST '
        f'/F'
    )
    try:
        result = subprocess.run(
            schtasks_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15
        )
        if result.returncode == 0:
            return True, ""
        else:
            error = result.stderr.strip() if result.stderr else result.stdout.strip()
            if not error:
                error = f"Unknown error (return code {result.returncode})"
            return False, error
    except subprocess.TimeoutExpired:
        return False, "Command timed out."
    except Exception as e:
        return False, str(e)

def delete_elevated_startup_task() -> tuple[bool, str]:
    try:
        result = subprocess.run(
            f'schtasks /Delete /TN "{TASK_NAME}" /F',
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return True, ""
        else:
            error = result.stderr.strip() if result.stderr else result.stdout.strip()
            if "cannot find" in error.lower():
                return True, ""
            return False, error
    except Exception as e:
        return False, str(e)

def is_elevated_startup_task_exists() -> bool:
    result = subprocess.run(
        ["schtasks", "/Query", "/TN", TASK_NAME],
        capture_output=True, text=True, timeout=10
    )
    return result.returncode == 0

# ----------------------------------------------------------------------
# Monitoring settings persistence
# ----------------------------------------------------------------------
def save_monitor_settings(enabled: bool, interval_minutes: int):
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, APP_SETTINGS_REG_PATH) as key:
            pass
        write_registry_dword(APP_SETTINGS_REG_PATH, MONITOR_ENABLED_VALUE, 1 if enabled else 0)
        write_registry_dword(APP_SETTINGS_REG_PATH, MONITOR_INTERVAL_VALUE, interval_minutes)
        return True
    except Exception as e:
        print(f"Failed to save monitor settings: {e}")
        return False

def load_monitor_settings() -> tuple[bool, int]:
    enabled_val = read_registry_value(APP_SETTINGS_REG_PATH, MONITOR_ENABLED_VALUE)
    interval_val = read_registry_value(APP_SETTINGS_REG_PATH, MONITOR_INTERVAL_VALUE)
    enabled = enabled_val == "1"
    interval = int(interval_val) if interval_val else 5
    return enabled, interval

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
        self.setMinimumSize(800, 600)

        # System tray
        self.tray_icon = QSystemTrayIcon(self)
        # Use a valid standard icon
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        tray_menu = QMenu()
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show_normal)
        quit_action = QAction("Exit", self)
        quit_action.triggered.connect(self.quit_app)
        tray_menu.addAction(show_action)
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
        self.check_gdid_btn.clicked.connect(self.check_gdid)
        status_layout.addWidget(self.check_gdid_btn)

        # Actions tab
        self.actions_tab = QWidget()
        self.tabs.addTab(self.actions_tab, "Actions")
        actions_layout = QVBoxLayout(self.actions_tab)

        actions_group = QGroupBox("Removal Steps")
        actions_group_layout = QVBoxLayout(actions_group)
        self.btn_disable_services = QPushButton("1. Disable GDID Services")
        self.btn_disable_services.clicked.connect(self.disable_services)
        self.btn_block_endpoints = QPushButton("2. Block GDID Endpoints")
        self.btn_block_endpoints.clicked.connect(self.block_endpoints)
        self.btn_delete_gdid = QPushButton("3. Delete GDID Registry Value")
        self.btn_delete_gdid.clicked.connect(self.delete_gdid)
        self.btn_verify = QPushButton("4. Verify All Changes")
        self.btn_verify.clicked.connect(self.verify_all)
        self.btn_rollback = QPushButton("Rollback (Restore Services & Hosts)")
        self.btn_rollback.clicked.connect(self.rollback)

        actions_group_layout.addWidget(self.btn_disable_services)
        actions_group_layout.addWidget(self.btn_block_endpoints)
        actions_group_layout.addWidget(self.btn_delete_gdid)
        actions_group_layout.addWidget(self.btn_verify)
        actions_group_layout.addWidget(self.btn_rollback)
        actions_layout.addWidget(actions_group)

        # Endpoint list management
        endpoint_group = QGroupBox("Endpoint List")
        endpoint_layout = QHBoxLayout(endpoint_group)
        self.endpoint_file_label = QLabel("Using built-in endpoint list")
        self.btn_load_endpoints = QPushButton("Load from File")
        self.btn_load_endpoints.clicked.connect(self.load_endpoints_file)
        self.btn_fetch_github = QPushButton("Update from GitHub")
        self.btn_fetch_github.clicked.connect(self.fetch_endpoints_from_github)
        if not HAS_REQUESTS:
            self.btn_fetch_github.setEnabled(False)
            self.btn_fetch_github.setToolTip("requests module not installed")
        endpoint_layout.addWidget(self.endpoint_file_label)
        endpoint_layout.addWidget(self.btn_load_endpoints)
        endpoint_layout.addWidget(self.btn_fetch_github)
        actions_layout.addWidget(endpoint_group)

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
        tray_layout.addWidget(self.monitor_checkbox)
        self.monitor_interval = QSpinBox()
        self.monitor_interval.setRange(1, 60)
        self.monitor_interval.setValue(5)
        self.monitor_interval.setSuffix(" minutes")
        form = QFormLayout()
        form.addRow("Check interval:", self.monitor_interval)
        tray_layout.addLayout(form)
        self.btn_start_monitor = QPushButton("Start Monitoring")
        self.btn_start_monitor.clicked.connect(self.start_tray_monitor)
        tray_layout.addWidget(self.btn_start_monitor)

        # Startup checkbox
        self.startup_checkbox = QCheckBox("Start with Windows (elevated, background)")
        self.startup_checkbox.setChecked(is_elevated_startup_task_exists())
        self.startup_checkbox.stateChanged.connect(self.on_startup_checkbox_changed)
        tray_layout.addWidget(self.startup_checkbox)

        # Log tab
        self.log_tab = QWidget()
        self.tabs.addTab(self.log_tab, "Log")
        log_layout = QVBoxLayout(self.log_tab)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
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

    # ------------------------------------------------------------------
    def log(self, message: str):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")

    # ------------------------------------------------------------------
    def check_gdid(self):
        self.log("Checking GDID...")
        value = read_registry_value(GDID_REG_PATH, GDID_VALUE_NAME)
        if value:
            self.gdid_label.setText(f"GDID found: {value}")
            self.log(f"GDID present: {value}")
        else:
            self.gdid_label.setText("GDID not found.")
            self.log("GDID is not present.")

    # ------------------------------------------------------------------
    def disable_services(self):
        self.log("Disabling services...")
        self.progress.setRange(0, 0)
        self.btn_disable_services.setEnabled(False)

        def task(log_callback, progress_callback):
            services = SERVICES_TO_DISABLE.copy()
            cdp_user = get_cdp_user_services()
            services.extend(cdp_user)
            log_callback(f"Services to disable: {', '.join(services)}")
            results = {}
            for svc in services:
                log_callback(f"Processing {svc}...")

                if svc in REGISTRY_PATHS:
                    reg_path = REGISTRY_PATHS[svc]
                else:
                    reg_path = f"SYSTEM\\CurrentControlSet\\Services\\{svc}"

                reg_success = write_registry_dword(reg_path, "Start", 4)
                if reg_success:
                    log_callback(f"  Registry Start set to 4 for {svc}")
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

            return results

        self.run_worker(task, on_finished=lambda res: self.log("Service disabling completed."))

    # ------------------------------------------------------------------
    def block_endpoints(self):
        if not self.endpoints:
            QMessageBox.warning(self, "No Endpoints", "No endpoints loaded. Load a file or update from GitHub.")
            return
        self.log(f"Blocking {len(self.endpoints)} endpoints via hosts file...")
        self.progress.setRange(0, 0)
        self.btn_block_endpoints.setEnabled(False)

        def task(log_callback, progress_callback):
            success = modify_hosts_file(self.endpoints, "add")
            if success:
                log_callback("Endpoints added to hosts file successfully.")
            else:
                log_callback("Failed to modify hosts file (permission denied?).")
            return success

        self.run_worker(task, on_finished=lambda res: self.log("Endpoint blocking done."))

    # ------------------------------------------------------------------
    def delete_gdid(self):
        self.log("Deleting GDID registry value...")
        if delete_registry_value(GDID_REG_PATH, GDID_VALUE_NAME):
            self.log("GDID deleted successfully.")
            self.gdid_label.setText("GDID deleted.")
        else:
            self.log("GDID not found or could not be deleted.")
            self.gdid_label.setText("GDID not found.")

    # ------------------------------------------------------------------
    def verify_all(self):
        self.log("Verifying all changes...")

        gdid = read_registry_value(GDID_REG_PATH, GDID_VALUE_NAME)
        if gdid:
            self.log("FAIL: GDID still present!")
        else:
            self.log("OK: GDID not present.")

        services = SERVICES_TO_DISABLE.copy()
        services.extend(get_cdp_user_services())
        for svc in services:
            reg_path = REGISTRY_PATHS.get(svc) or f"SYSTEM\\CurrentControlSet\\Services\\{svc}"
            start_value = read_registry_value(reg_path, "Start")
            if start_value is not None and start_value == "4":
                self.log(f"OK: {svc} is disabled (Start=4).")
            else:
                self.log(f"WARN: {svc} may not be disabled (Start={start_value}).")

        try:
            with open(HOSTS_FILE, "r") as f:
                hosts_content = f.read()
        except Exception as e:
            self.log(f"ERROR: cannot read hosts file: {e}")
            hosts_content = ""

        missing = [ep for ep in self.endpoints if ep.split(":")[0] not in hosts_content]
        if missing:
            self.log(f"WARN: Missing endpoints in hosts file: {missing}")
        else:
            self.log("OK: All endpoints are present in hosts file.")

    # ------------------------------------------------------------------
    def rollback(self):
        self.log("Rolling back changes...")
        services = SERVICES_TO_DISABLE.copy()
        services.extend(get_cdp_user_services())
        for svc in services:
            reg_path = REGISTRY_PATHS.get(svc) or f"SYSTEM\\CurrentControlSet\\Services\\{svc}"
            write_registry_dword(reg_path, "Start", 3)  # 3 = Manual
            if not svc.startswith("CDPUserSvc_"):
                subprocess.run(["sc", "config", svc, "start=", "demand"], capture_output=True, text=True)
            self.log(f"Restored {svc} to manual start.")
        modify_hosts_file(self.endpoints, "remove")
        self.log("Rollback completed.")

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
        self.hide()
        self.tray_icon.show()
        if self.monitor_timer is None:
            self.monitor_timer = QTimer()
            self.monitor_timer.timeout.connect(self.check_gdid_silent)
        else:
            self.monitor_timer.stop()
        self.monitor_timer.start(interval_min * 60 * 1000)
        self.check_gdid_silent()

    def check_gdid_silent(self):
        gdid = read_registry_value(GDID_REG_PATH, GDID_VALUE_NAME)
        if gdid:
            self.tray_icon.showMessage(
                "GDID Restored!",
                "The GDID value has reappeared. Consider re-running removal steps.",
                QSystemTrayIcon.Warning,
                10000
            )
            self.log("Tray monitor: GDID detected again!")

    def tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show_normal()

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
            event.ignore()
            self.hide()
            self.tray_icon.showMessage(
                "GDID Remover",
                "Continuing to monitor in background.",
                QSystemTrayIcon.Information,
                2000
            )
        else:
            event.accept()
            QApplication.quit()

    # ------------------------------------------------------------------
    def run_worker(self, func, on_finished=None):
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Busy", "Another operation is still running.")
            return
        self.worker = WorkerThread(func)
        self.worker.signals.log.connect(self.log)
        self.worker.signals.progress.connect(self.progress.setValue)
        self.worker.signals.finished.connect(lambda res: self.worker_finished(res, on_finished))
        self.worker.start()

    def worker_finished(self, result, callback):
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.btn_disable_services.setEnabled(True)
        self.btn_block_endpoints.setEnabled(True)
        if callback:
            callback(result)
        if not result.get("success"):
            QMessageBox.critical(self, "Error", f"Operation failed: {result.get('error', 'Unknown error')}")

    # ------------------------------------------------------------------
    def load_endpoints_from_default(self):
        self.endpoints = DEFAULT_ENDPOINTS.copy()
        self.endpoint_file_label.setText(f"Using built-in list ({len(self.endpoints)} endpoints)")
        self.log("Loaded built-in endpoint list.")

    def load_endpoints_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Endpoints File", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                with open(file_path, "r") as f:
                    self.endpoints = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                self.endpoint_file_label.setText(f"Loaded {len(self.endpoints)} endpoints from {file_path}")
                self.log(f"Loaded endpoints from {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {e}")

    def fetch_endpoints_from_github(self):
        if not HAS_REQUESTS:
            QMessageBox.critical(self, "Error", "The 'requests' module is not installed. Cannot fetch.")
            return
        self.log("Fetching endpoints from GitHub...")
        self.btn_fetch_github.setEnabled(False)
        self.progress.setRange(0, 0)

        def task(log_callback, progress_callback):
            try:
                url = "https://raw.githubusercontent.com/Korben00/no-gdid/main/mitigate/Block-GDID-Endpoints.ps1"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    text = response.text
                    endpoints = re.findall(r"'([^']*\.[^']*)'", text)
                    cleaned = []
                    for ep in endpoints:
                        domain = ep.split(":")[0].strip()
                        if domain and "." in domain:
                            cleaned.append(domain)
                    if cleaned:
                        self.endpoints = list(set(cleaned))
                        log_callback(f"Fetched {len(self.endpoints)} endpoints from GitHub.")
                        return True
                    else:
                        log_callback("No endpoints found in the fetched content.")
                        return False
                else:
                    log_callback(f"Failed to fetch (HTTP {response.status_code}).")
                    return False
            except Exception as e:
                log_callback(f"Error during fetch: {e}")
                return False

        def on_finished(result):
            self.btn_fetch_github.setEnabled(True)
            self.progress.setRange(0, 100)
            self.progress.setValue(100)
            if result.get("success") and result.get("result"):
                self.endpoint_file_label.setText(f"Fetched {len(self.endpoints)} endpoints from GitHub")
            else:
                self.endpoint_file_label.setText("Using built-in endpoint list")

        self.run_worker(task, on_finished=on_finished)

    # ------------------------------------------------------------------
    def on_startup_checkbox_changed(self, state):
        # state: 0 = unchecked, 2 = checked (also possible 1 = partially checked)
        enabled = state != 0
        if enabled:
            success, error = create_elevated_startup_task()
            if success:
                self.log("Elevated startup task created. The app will run at logon with admin rights.")
                QMessageBox.information(self, "Success", "Startup task created successfully.")
                # If monitoring is enabled and not already running, start it now
                if self.monitor_checkbox.isChecked() and (self.monitor_timer is None or not self.monitor_timer.isActive()):
                    self.start_tray_monitor()
            else:
                self.log(f"Failed to create startup task: {error}")
                QMessageBox.critical(self, "Error", f"Failed to create startup task:\n{error}")
                self.startup_checkbox.blockSignals(True)
                self.startup_checkbox.setChecked(False)
                self.startup_checkbox.blockSignals(False)
        else:
            success, error = delete_elevated_startup_task()
            if success:
                self.log("Elevated startup task removed.")
                QMessageBox.information(self, "Success", "Startup task removed.")
            else:
                self.log(f"Failed to remove startup task: {error}")
                QMessageBox.critical(self, "Error", f"Failed to remove startup task:\n{error}")
                self.startup_checkbox.blockSignals(True)
                self.startup_checkbox.setChecked(True)
                self.startup_checkbox.blockSignals(False)

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
        elevate()
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