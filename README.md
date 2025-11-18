<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt=" Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls, as recent network logs reveal unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is detected, please notify the management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-11-17T19:29:55.2698869Z`. These events began at `2025-11-17T18:59:59.2915942Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where Timestamp >= datetime(2025-11-17T18:59:59.2915942Z)
| where DeviceName == "threat-hunt-lab" and InitiatingProcessAccountName == "employee"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any ProcessCommandLine that contained the string `tor-browser-windows-x86_64-portable-15.0.1.exe`. Based on the logs returned, at `2025-11-17T19:03:52.7622377Z`, an employee on the `threat-hunt-lab` device ran the file `tor-browser-windows-x86_64-portable-15.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2025-11-17T18:59:59.2915942Z)
| where DeviceName == "threat-hunt-lab" and ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.1.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that the user `employee` actually opened the TOR browser. There was evidence that they did open it at `2025-11-17T19:07:58.6644188Z`. There were several other instances of `firefox.exe (TOR)` as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2025-11-17T18:59:59.2915942Z)
| where DeviceName == "threat-hunt-lab" and ProcessCommandLine has_any ("tor.exe", "firefox.exe", "tor-browser.exe", "start-tor-browser.exe", "start-tor-browser.desktop", "Tor Browser.lnk")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

---

### 4. Searched the DeviceNetworkEvents Table for TOR Network Connections

Searched for any indication that the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-11-17T19:08:44.8020421Z`, an employee on the `threat-hunt-lab` device successfully established a connection to the remote IP address `46.4.103.29` on port 9001. The connection was initiated by the process `tor.exe`, located in the folder `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where Timestamp >= datetime(2025-11-17T18:59:59.2915942Z)
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151", "9040")
| project Timestamp, DeviceName, Account = InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-11-17T18:59:59.2915942Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.1.exe`
- **SHA256:** `66793f7208919a15087bac96d8e31151ff53f9620d9fd7bfd340794fa6d5f86c`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-11-17T19:03:52.7622377Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-15.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-11-17T19:07:58.6644188Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with the TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-11-17T19:08:44.8020421Z`
- **Event:** A network connection to IP `46.4.103.29` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:** `2025-11-17T19:09:08Z` to `2025-11-17T19:10:34Z`
- **Event:** Additional TOR network connections were established to various IP addresses, including `64.65.0.7`, `84.201.5.75`, and `91.143.81.27` on ports `9001` and `443`, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-11-17T19:29:55.2698869Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and create various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
