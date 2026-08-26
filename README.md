# GDID Removal Tool

A full‑featured Windows GUI application to **block and delete the Global Device Identifier (GDID)**. It disables the services and network endpoints that Microsoft uses to sync and restore GDID, then removes the identifier from your registry. The tool also offers background monitoring to alert you if GDID ever reappears.

> **⚠️ DISCLAIMER**  
> This tool makes permanent system changes. Read the [Warnings](#warnings) section carefully before using it. By proceeding, you accept all risks.

---

## What is GDID?

**Global Device Identifier (GDID)** is a unique, permanent digital fingerprint that Windows automatically assigns to a device. Importantly, **GDID is generated even if you never sign in with a Microsoft account** – it is tied to the Windows installation and hardware profile from the start. When you do use a Microsoft account, the identifier becomes linked to that account as well, but its existence is not dependent on account usage.

GDID can be read directly by Microsoft regardless of VPN usage. It is stored in the Windows Registry at:

```
HKEY_CURRENT_USER\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties
```

Value name: **`LID`**

Because GDID is designed to be permanent, Microsoft provides no official way to delete or block it. This tool automates the process of disabling the underlying services and blocking the network endpoints that would otherwise restore the identifier, followed by deletion of the registry value.

---

## Privacy & Network Behaviour

This tool is **privacy‑respecting by design**:

- **No automatic internet connection.** The application does **not** connect to the internet on its own. It works entirely offline using a built‑in list of known Microsoft endpoints.
- The only network request occurs **if you manually click the “Update from GitHub” button** in the Endpoint List section. This optional action fetches the latest endpoint list from the `no-gdid` repository. Without your explicit action, no network traffic is generated.
- The tool does not send any data to Microsoft or any third party. All operations are local to your machine.

---

## Features

- **Modern, intuitive GUI** built with PySide6 (Qt for Python).
- **One‑click GDID check** – read and display the current GDID value.
- **Service disabling** – stops and disables the five Windows services involved in GDID synchronisation:
  - Connected Device Platform Service (`CDPSvc`)
  - Connected Device Platform User Service (`CDPUserSvc_*`)
  - Device Optimization (`DoSvc`)
  - Connected User Experience and Telemetry (`DiagTrack`)
  - Windows Live ID Sign‑in Assistant (`wlidsvc`)
- **Endpoint blocking** – adds Microsoft GDID/telemetry endpoints to the `hosts` file to prevent network access.
  - Built‑in list of over 50 known endpoints.
  - **Manual update from GitHub** – fetch the latest endpoint list from the `no-gdid` repository **only when you choose**.
  - Load a custom endpoint list from a `.txt` file.
- **GDID deletion** – removes the `LID` value from the registry.
- **Verification** – checks that GDID is gone, services are disabled, and endpoints are blocked.
- **Rollback** – re‑enable services and remove hosts entries if you change your mind.
- **Tray monitoring** – runs in the background and checks periodically if GDID reappears; shows a system notification if it does.
- **Start with Windows** – creates an elevated scheduled task to launch the tool at logon **silently** (no GUI window) and begin monitoring if previously enabled.
- **No network activity without consent** – the app does not connect to the internet unless you manually click “Update from GitHub”.

---

## Requirements

- **Windows 10 or Windows 11** (64‑bit recommended)
- **Administrator privileges** – the tool must run elevated to modify services and the hosts file.
- **Python 3.8+** (if running from source)
- **PySide6** – `pip install PySide6`
- **requests** (optional, only needed for the “Update from GitHub” feature) – `pip install requests`

---

## Installation & First Run

### Run from source

1. Clone or download this repository.
2. Install dependencies:
   ```bash
   pip install PySide6 requests
   ```
3. Run the script **as administrator**:
   ```bash
   pythonw.exe gdid_remover.py
   ```
   The script will prompt for elevation if not already elevated.

---

## How to Use

### Main Window Overview

The GUI is divided into four tabs:

- **Status** – shows the current GDID status and a button to check it.
- **Actions** – contains the removal steps and endpoint management.
- **Tray Monitor** – configure background monitoring and startup behaviour.
- **Log** – displays a timestamped log of all operations.

### Step‑by‑Step Removal

1. **Check GDID**  
   Click the **“Check GDID”** button in the Status tab. If a value appears, continue.

2. **Disable Services**  
   In the Actions tab, click **“1. Disable GDID Services”**.  
   The tool will stop each service and set its startup type to **Disabled** via the registry.

3. **Block Endpoints**  
   Choose an endpoint list:
   - **Built‑in list** (default) – contains many known Microsoft endpoints.
   - **Load from File** – import your own list (one domain per line).
   - **Update from GitHub** – fetches the latest list from the `no-gdid` repository.  
   Then click **“2. Block GDID Endpoints”**. The domains will be added to your `hosts` file.

4. **Delete GDID**  
   Click **“3. Delete GDID Registry Value”**. The `LID` value will be removed.

5. **Verify**  
   Click **“4. Verify All Changes”** to confirm that:
   - GDID is not present.
   - All five services are disabled (`Start=4`).
   - All chosen endpoints are present in the hosts file.

### Background Monitoring

- In the **Tray Monitor** tab, tick **“Monitor in background”** and set the check interval.
- Click **“Start Monitoring”**. The window will hide to the system tray.
- The app will periodically check if GDID has reappeared. If it has, a balloon notification will appear.
- Closing the window while monitoring is active will minimise it to the tray instead of exiting. To fully quit, right‑click the tray icon and choose **Exit**.

### Start with Windows (Elevated)

- In the **Tray Monitor** tab, tick **“Start with Windows (elevated, background)”**.
- This creates a **Scheduled Task** that runs at logon with **highest privileges**.
- The task launches the app in the background (no window) and automatically starts monitoring if you had enabled it previously.
- Untick the checkbox to remove the scheduled task.

> **Note:** You must run the app at least once as administrator to create the scheduled task. The scheduled task itself will always run elevated.

---

## Warnings

Blocking and deleting GDID will impact or break several Windows features. This is by design – GDID is deeply integrated into Microsoft account services.

### What you will lose or break

- **Phone Link** – will no longer sync with your phone.
- **Nearby Sharing** – Windows file sharing between nearby devices stops working.
- **Some Bluetooth features** – certain cross‑device experiences may be affected.
- **Windows Update** – may become slower or stop working entirely. **Windows Update is intentionally disabled** to prevent OS updates from undoing the changes.
- **Microsoft Store** – the Store app may not work; use the web version instead.
- **OneDrive** – desktop sync will break; web version remains usable.
- **Xbox** – Xbox app and services tied to your Microsoft account will not function; use web versions.
- **Other Microsoft account services** – Office 365, Windows Insider, etc. may fail; browser‑based versions still work.

### Other possible side effects

- **Graphics driver issue**  
  Some users have reported that after removing GDID, their dedicated GPU (e.g., NVIDIA RTX) is no longer detected and Windows falls back to the basic display driver.  
  **Fix:** Reinstall your graphics drivers from the manufacturer’s website.

- **Windows Defender updates**  
  Windows Update is disabled, so Defender definitions will not update automatically.  
  You must manually download and install them from [Microsoft Security Intelligence](https://www.microsoft.com/en-us/wdsi/defenderupdates) (file `mpam-fe.exe`). Do this periodically (e.g., every few months).

- **Service failure messages**  
  During the disabling process, you may see errors like `Access is denied` or `The parameter is incorrect` for certain services (especially `DoSvc` and `CDPUserSvc_*`). This is normal – the registry `Start=4` value is still written, which prevents the service from starting after reboot.

---

## Rollback

If you want to undo the changes, open the Actions tab and click **“Rollback (Restore Services & Hosts)”**. This will:

- Set all disabled services back to **Manual** start.
- Remove all previously added hosts entries.

Note that if you deleted GDID, it may reappear after rollback if the services are re‑enabled and the machine reconnects to Microsoft.

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| “Access denied” when disabling services | Make sure the tool is running as **administrator**. |
| `DiagTrack` service not found | Your Windows version may not have this service. The registry entry is still set; ignore the warning. |
| Endpoints not blocked | Check that the `hosts` file is writable (not read‑only) and that you have admin rights. |
| GDID reappears after deletion | Ensure all services are disabled (`Start=4`) and all endpoints are blocked. Reboot and verify again. |
| App does not start at logon | Confirm the scheduled task exists: `schtasks /Query /TN GDIDRemover`. Re‑create it by toggling the checkbox. |
| Window doesn’t close | Monitoring is active. Right‑click the tray icon and choose **Exit**, or stop monitoring from the GUI first. |

---

## Credits & Thanks

This tool is based on the original research and guide by **saturniandragon**.  
A thank you to [saturniandragon@tumblr](https://www.tumblr.com/saturniandragon/822909706639163392/tumblr-people-ive-figured-out-a-way-to-delete) for publishing the method for GDID removal.

The endpoint list and service information were adapted from the [`no-gdid`](https://github.com/Korben00/no-gdid) project by Korben, Claude, and Berbe.

---
