"""Build the benign test sets: 44 synthetic alerts of normal enterprise activity, plus 20 fresh ones.

Half are routine (Office, browsers, updates, dev tools). The other half are hard negatives:
legitimate activity that looks like an attack at first glance (Defender reading LSASS, SCCM
running PowerShell with -ExecutionPolicy Bypass, a logon script mapping drives, MSBuild, ...).
Every alert is labelled benign and marked synthetic in the manifest.

  python data/build_benign_set.py
"""
import json, random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = 20261104
USERS = ["CORP\\akhan", "CORP\\mlopez", "CORP\\jchen", "CORP\\rpatel", "CORP\\sbrown", "CORP\\tnguyen"]
WORKSTATIONS = ["HOST-06", "HOST-07", "HOST-08"]
SYSTEM = "NT AUTHORITY\\SYSTEM"
WIN = "C:\\Windows\\System32\\"


def proc(image, cmd, parent, user, pcmd=None):
    ev = {"event_id": 1, "Image": image, "CommandLine": cmd, "ParentImage": parent, "User": user}
    if pcmd:
        ev["ParentCommandLine"] = pcmd
    return ev


def net(image, ip, port, user=None):
    ev = {"event_id": 3, "Image": image, "DestinationIp": ip, "DestinationPort": str(port)}
    if user:
        ev["User"] = user
    return ev


def home(user):
    return "C:\\Users\\" + user.split("\\")[1]


# ---- routine activity ------------------------------------------------------------------

def office(u, r):
    word = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
    outlook = "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"
    doc = f"{home(u)}\\Documents\\{r.choice(['Q3_review', 'team_notes', 'vendor_contract'])}.docx"
    return [proc(outlook, f'"{outlook}"', "C:\\Windows\\explorer.exe", u),
            net(outlook, "52.96.166.2", 443, u),
            proc(word, f'"{word}" /n "{doc}"', "C:\\Windows\\explorer.exe", u),
            {"event_id": 11, "Image": word, "TargetFilename": doc.replace(".docx", "~$.docx")},
            net(word, "52.109.12.19", 443, u)]


def browser(u, r):
    chrome = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    pdf = f"{home(u)}\\Downloads\\{r.choice(['benefits_guide', 'travel_policy', 'invoice_1182'])}.pdf"
    return [proc(chrome, f'"{chrome}"', "C:\\Windows\\explorer.exe", u),
            proc(chrome, f'"{chrome}" --type=renderer --lang=en-US', chrome, u),
            net(chrome, "142.250.72.78", 443, u),
            net(chrome, "151.101.1.69", 443, u),
            {"event_id": 11, "Image": chrome, "TargetFilename": pdf}]


def teams(u, r):
    base = f"{home(u)}\\AppData\\Local\\Microsoft\\Teams"
    return [proc(f"{base}\\Update.exe", f'"{base}\\Update.exe" --processStart "Teams.exe"', "C:\\Windows\\explorer.exe", u),
            proc(f"{base}\\current\\Teams.exe", f'"{base}\\current\\Teams.exe"', f"{base}\\Update.exe", u),
            net(f"{base}\\current\\Teams.exe", "52.113.194.132", 443, u),
            {"event_id": 11, "Image": f"{base}\\Update.exe", "TargetFilename": f"{base}\\packages\\Teams-1.7.00.13456-full.nupkg"}]


def windows_update(u, r):
    worker = WIN + "MoUsoCoreWorker.exe"
    return [proc(worker, f"{worker} -Embedding", WIN + "svchost.exe", SYSTEM),
            net(worker, "13.107.4.50", 443),
            proc("C:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack\\TiWorker.exe",
                 "C:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack\\TiWorker.exe -Embedding", WIN + "svchost.exe", SYSTEM),
            {"event_id": 11, "Image": worker, "TargetFilename": "C:\\Windows\\SoftwareDistribution\\Download\\kb5031356.cab"}]


def defender_update(u, r):
    mp = "C:\\Program Files\\Windows Defender\\MpCmdRun.exe"
    return [proc(mp, f'"{mp}" -SignatureUpdate -MMPC', "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.23110.3-0\\MsMpEng.exe", SYSTEM),
            net(mp, "23.35.229.160", 443),
            {"event_id": 11, "Image": mp, "TargetFilename": "C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\Updates\\mpavdlta.vdm"}]


def dev_git(u, r):
    code = f"{home(u)}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"
    git = "C:\\Program Files\\Git\\cmd\\git.exe"
    py = f"{home(u)}\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"
    repo = f"{home(u)}\\source\\{r.choice(['billing-api', 'inventory-ui', 'etl-jobs'])}"
    return [proc(code, f'"{code}"', "C:\\Windows\\explorer.exe", u),
            proc(git, f'"{git}" fetch --all', code, u),
            net(git, "140.82.112.3", 443, u),
            proc(py, f'"{py}" -m pytest -q tests', code, u),
            {"event_id": 11, "Image": py, "TargetFilename": f"{repo}\\.pytest_cache\\v\\cache\\lastfailed"}]


def zoom_install(u, r):
    msi = f"{home(u)}\\Downloads\\ZoomInstallerFull.msi"
    return [proc(WIN + "msiexec.exe", f'"{WIN}msiexec.exe" /i "{msi}"', "C:\\Windows\\explorer.exe", u),
            proc(WIN + "msiexec.exe", f"{WIN}msiexec.exe /V", WIN + "services.exe", SYSTEM),
            {"event_id": 11, "Image": WIN + "msiexec.exe", "TargetFilename": "C:\\Program Files\\Zoom\\bin\\Zoom.exe"},
            net("C:\\Program Files\\Zoom\\bin\\Zoom.exe", "170.114.52.2", 443, u)]


def acrobat(u, r):
    acro = "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe"
    pdf = f"{home(u)}\\Downloads\\{r.choice(['W-2_2025', 'offer_summary', 'lease_renewal'])}.pdf"
    return [proc(acro, f'"{acro}" "{pdf}"', "C:\\Windows\\explorer.exe", u),
            net(acro, "23.62.226.180", 443, u),
            proc("C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\AcroCEF\\AcroCEF.exe",
                 '"C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\AcroCEF\\AcroCEF.exe" --type=renderer', acro, u)]


def interactive_logon(u, r):
    name = u.split("\\")[1]
    return [{"event_id": 4624, "TargetUserName": name, "LogonType": "2", "IpAddress": "127.0.0.1",
             "ProcessName": WIN + "svchost.exe"},
            proc(WIN + "userinit.exe", WIN + "userinit.exe", WIN + "winlogon.exe", u),
            proc("C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE", WIN + "userinit.exe", u),
            proc("C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
                 '"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background', "C:\\Windows\\explorer.exe", u)]


def excel_macro_free(u, r):
    excel = "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"
    xlsx = f"\\\\fs01\\finance\\{r.choice(['forecast_2027', 'headcount', 'opex_by_dept'])}.xlsx"
    return [proc(excel, f'"{excel}" "{xlsx}"', "C:\\Windows\\explorer.exe", u),
            net(excel, "10.10.2.15", 445, u),
            {"event_id": 11, "Image": excel, "TargetFilename": f"{home(u)}\\AppData\\Local\\Microsoft\\Office\\16.0\\OfficeFileCache\\cache.dat"}]


def slack(u, r):
    slack_exe = f"{home(u)}\\AppData\\Local\\slack\\slack.exe"
    return [proc(slack_exe, f'"{slack_exe}" --startup', "C:\\Windows\\explorer.exe", u),
            net(slack_exe, "3.232.62.45", 443, u),
            proc(slack_exe, f'"{slack_exe}" --type=gpu-process', slack_exe, u)]


# ---- hard negatives ---------------------------------------------------------------------

def defender_lsass(u, r):
    eng = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.23110.3-0\\MsMpEng.exe"
    return [proc("C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
                 '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -Scan -ScanType 1', eng, SYSTEM),
            {"event_id": 10, "SourceImage": eng, "TargetImage": WIN + "lsass.exe", "GrantedAccess": "0x1410"},
            {"event_id": 10, "SourceImage": eng, "TargetImage": WIN + "winlogon.exe", "GrantedAccess": "0x1410"},
            {"event_id": 11, "Image": eng, "TargetFilename": "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory\\scan.log"}]


def sccm_inventory(u, r):
    ps = WIN + "WindowsPowerShell\\v1.0\\powershell.exe"
    script = "C:\\Windows\\CCM\\SystemTemp\\" + r.choice(["HardwareInventory.ps1", "ComplianceCheck.ps1"])
    return [proc(ps, f'"{ps}" -NoProfile -ExecutionPolicy Bypass -File "{script}"', "C:\\Windows\\CCM\\CcmExec.exe", SYSTEM),
            {"event_id": 4104, "ScriptBlockText": "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory"},
            {"event_id": 4104, "ScriptBlockText": "Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select DisplayName, DisplayVersion"},
            net("C:\\Windows\\CCM\\CcmExec.exe", "10.10.1.40", 443)]


def logon_script(u, r):
    name = u.split("\\")[1]
    cmd = WIN + "cmd.exe"
    return [proc(cmd, f'{cmd} /c "\\\\corp.local\\NETLOGON\\logon.bat"', WIN + "userinit.exe", u),
            proc(WIN + "net.exe", f"net use H: \\\\fs01\\home\\{name} /persistent:no", cmd, u),
            proc(WIN + "net.exe", "net use P: \\\\fs01\\printers", cmd, u),
            net(WIN + "net.exe", "10.10.2.15", 445, u),
            {"event_id": 5140, "ShareName": "\\\\*\\home", "IpAddress": "10.10.4.33", "SubjectUserName": name}]


def onedrive_run_key(u, r):
    setup = f"{home(u)}\\AppData\\Local\\Microsoft\\OneDrive\\Update\\OneDriveSetup.exe"
    od = f"{home(u)}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"
    return [proc(setup, f'"{setup}" /update /restart', "C:\\Windows\\explorer.exe", u),
            {"event_id": 13, "Image": setup, "TargetObject": "HKU\\S-1-5-21-1004\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
             "Details": f'"{od}" /background'},
            proc(od, f'"{od}" /background', setup, u),
            net(od, "13.107.42.12", 443, u)]


def google_update_task(u, r):
    gu = "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe"
    return [proc(gu, f'"{gu}" /install "appguid={{8A69D345-D564-463C-AFF1-A69D9E530F96}}" /silent', "C:\\Windows\\explorer.exe", u),
            {"event_id": 4698, "TaskName": "\\GoogleUpdateTaskMachineUA", "SubjectUserName": "SYSTEM"},
            proc(gu, f'"{gu}" /ua /installsource scheduler', WIN + "svchost.exe", SYSTEM),
            net(gu, "142.250.72.78", 443)]


def msbuild_dev(u, r):
    devenv = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\devenv.exe"
    msb = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\MSBuild\\Current\\Bin\\amd64\\MSBuild.exe"
    sln = f"{home(u)}\\source\\repos\\{r.choice(['InventoryApp', 'PayrollTools'])}\\App.sln"
    return [proc(devenv, f'"{devenv}" "{sln}"', "C:\\Windows\\explorer.exe", u),
            proc(msb, f'"{msb}" "{sln}" /t:Build /p:Configuration=Debug /m', devenv, u),
            {"event_id": 11, "Image": msb, "TargetFilename": sln.replace("App.sln", "bin\\Debug\\App.exe")},
            net(devenv, "13.107.6.158", 443, u)]


def certutil_hash(u, r):
    cmd = WIN + "cmd.exe"
    msi = f"{home(u)}\\Downloads\\{r.choice(['putty-64bit-0.81-installer.msi', 'node-v20.11.1-x64.msi'])}"
    return [proc(cmd, f'"{cmd}"', "C:\\Windows\\explorer.exe", u),
            proc(WIN + "certutil.exe", f'certutil -hashfile "{msi}" SHA256', cmd, u),
            proc(WIN + "msiexec.exe", f'"{WIN}msiexec.exe" /i "{msi}"', "C:\\Windows\\explorer.exe", u)]


def backup_vss(u, r):
    svc = "C:\\Program Files\\Veeam\\Endpoint Backup\\Veeam.EndPoint.Service.exe"
    return [proc(WIN + "vssadmin.exe", "vssadmin.exe list shadows", svc, SYSTEM),
            proc(WIN + "VSSVC.exe", WIN + "VSSVC.exe", WIN + "services.exe", SYSTEM),
            {"event_id": 11, "Image": svc, "TargetFilename": "\\\\nas01\\backups\\daily\\vbk\\job_2026-11-02.vbk"},
            net(svc, "10.10.3.20", 445)]


def procdump_own_app(u, r):
    pd = f"{home(u)}\\tools\\Sysinternals\\procdump64.exe"
    app = f"{home(u)}\\source\\repos\\InventoryApp\\bin\\Debug\\InventoryApp.exe"
    return [proc(app, f'"{app}"', "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\devenv.exe", u),
            proc(pd, f'"{pd}" -accepteula -ma InventoryApp.exe {home(u)}\\dumps\\', WIN + "cmd.exe", u),
            {"event_id": 10, "SourceImage": pd, "TargetImage": app, "GrantedAccess": "0x1fffff"},
            {"event_id": 11, "Image": pd, "TargetFilename": f"{home(u)}\\dumps\\InventoryApp.exe_261102_101544.dmp"}]


def printer_install(u, r):
    rd = WIN + "rundll32.exe"
    queue = r.choice(["HP-Floor2", "Canon-Lobby"])
    return [proc(rd, f'rundll32.exe printui.dll,PrintUIEntry /in /n "\\\\printsrv01\\{queue}"', "C:\\Windows\\explorer.exe", u),
            net(WIN + "spoolsv.exe", "10.10.2.30", 445),
            {"event_id": 11, "Image": WIN + "spoolsv.exe", "TargetFilename": WIN + "spool\\drivers\\x64\\3\\hpcu270u.dll"}]


def log_export(u, r):
    agent = "C:\\Program Files\\LogCollector\\collector.exe"
    return [proc(WIN + "wevtutil.exe", 'wevtutil.exe epl Application "C:\\Logs\\export\\Application_2026-11-02.evtx"', agent, SYSTEM),
            {"event_id": 11, "Image": WIN + "wevtutil.exe", "TargetFilename": "C:\\Logs\\export\\Application_2026-11-02.evtx"},
            net(agent, "10.10.1.60", 514)]


# ---- a second, independent set, written after the first benign run, to check later rule changes ----

def edge_update(u, r):
    up = "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe"
    return [proc(up, f'"{up}" /ua /installsource scheduler', WIN + "svchost.exe", SYSTEM),
            net(up, "13.107.246.40", 443),
            {"event_id": 11, "Image": up, "TargetFilename": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\Download\\edge_update.exe"}]


def zip_extract(u, r):
    z = "C:\\Program Files\\7-Zip\\7zG.exe"
    arc = f"{home(u)}\\Downloads\\{r.choice(['project_assets', 'q3_photos'])}.zip"
    return [proc(z, f'"{z}" x -o"{home(u)}\\Downloads\\unzipped" "{arc}"', "C:\\Windows\\explorer.exe", u),
            {"event_id": 11, "Image": z, "TargetFilename": f"{home(u)}\\Downloads\\unzipped\\readme.txt"},
            {"event_id": 11, "Image": z, "TargetFilename": f"{home(u)}\\Downloads\\unzipped\\logo.png"}]


def pip_install(u, r):
    py = f"{home(u)}\\source\\analytics\\.venv\\Scripts\\python.exe"
    pkg = r.choice(["pandas==2.2.3", "requests==2.32.3"])
    return [proc(py, f'"{py}" -m pip install {pkg}', "C:\\Program Files\\PowerShell\\7\\pwsh.exe", u),
            net(py, "151.101.0.223", 443, u),
            {"event_id": 11, "Image": py, "TargetFilename": f"{home(u)}\\source\\analytics\\.venv\\Lib\\site-packages\\{pkg.split('==')[0]}\\__init__.py"}]


def notepadpp(u, r):
    npp = "C:\\Program Files\\Notepad++\\notepad++.exe"
    return [proc(npp, f'"{npp}" "{home(u)}\\Documents\\meeting_notes.txt"', "C:\\Windows\\explorer.exe", u),
            {"event_id": 11, "Image": npp, "TargetFilename": f"{home(u)}\\Documents\\meeting_notes.txt"}]


def adobe_updater_task(u, r):
    arm = "C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe"
    return [proc(WIN + "schtasks.exe", 'schtasks.exe /create /tn "Adobe Acrobat Update Task" /tr "\\"' + arm + '\\"" /sc daily /f',
                 "C:\\Program Files\\Adobe\\Acrobat DC\\Setup Files\\setup.exe", SYSTEM),
            {"event_id": 4698, "TaskName": "\\Adobe Acrobat Update Task", "SubjectUserName": "SYSTEM"},
            net(arm, "23.62.226.180", 443)]


def helpdesk_ad_lookup(u, r):
    ps = WIN + "WindowsPowerShell\\v1.0\\powershell.exe"
    return [proc(ps, f'"{ps}"', "C:\\Windows\\explorer.exe", "CORP\\helpdesk01"),
            {"event_id": 4104, "ScriptBlockText": "Get-ADUser -Identity " + u.split("\\")[1] + " -Properties LockedOut, LastLogonDate"},
            {"event_id": 4104, "ScriptBlockText": "Unlock-ADAccount -Identity " + u.split("\\")[1]},
            net(ps, "10.10.1.10", 9389, "CORP\\helpdesk01")]


def inventory_wmic(u, r):
    agent = "C:\\Program Files\\AssetAgent\\assetagent.exe"
    return [proc(WIN + "wbem\\WMIC.exe", "wmic.exe product get name,version /format:csv", agent, SYSTEM),
            proc(WIN + "wbem\\WMIC.exe", "wmic.exe logicaldisk get size,freespace", agent, SYSTEM),
            net(agent, "10.10.1.70", 443)]


def admin_rdp(u, r):
    return [{"event_id": 4624, "TargetUserName": "it-admin", "LogonType": "10", "IpAddress": "10.10.5.20",
             "ProcessName": WIN + "svchost.exe"},
            proc(WIN + "rdpclip.exe", "rdpclip", WIN + "svchost.exe", "CORP\\it-admin"),
            proc("C:\\Windows\\System32\\mmc.exe", '"C:\\Windows\\system32\\mmc.exe" "C:\\Windows\\system32\\services.msc"',
                 "C:\\Windows\\explorer.exe", "CORP\\it-admin")]


def firewall_rule_installer(u, r):
    return [proc(WIN + "netsh.exe", 'netsh advfirewall firewall add rule name="Zoom Video Meetings" dir=in action=allow program="C:\\Program Files\\Zoom\\bin\\Zoom.exe"',
                 WIN + "msiexec.exe", SYSTEM),
            {"event_id": 11, "Image": WIN + "msiexec.exe", "TargetFilename": "C:\\Program Files\\Zoom\\bin\\Zoom.exe"}]


def procexp_admin(u, r):
    pe = "C:\\Tools\\Sysinternals\\procexp64.exe"
    return [proc(pe, f'"{pe}"', "C:\\Windows\\explorer.exe", "CORP\\it-admin"),
            {"event_id": 10, "SourceImage": pe, "TargetImage": WIN + "svchost.exe", "GrantedAccess": "0x1000"},
            {"event_id": 10, "SourceImage": pe, "TargetImage": "C:\\Windows\\explorer.exe", "GrantedAccess": "0x1000"}]


FRESH = [edge_update, zip_extract, pip_install, notepadpp, adobe_updater_task, helpdesk_ad_lookup,
         inventory_wmic, admin_rdp, firewall_rule_installer, procexp_admin]


ROUTINE = [office, browser, teams, windows_update, defender_update, dev_git, zoom_install, acrobat,
           interactive_logon, excel_macro_free, slack]
HARD = [defender_lsass, sccm_inventory, logon_script, onedrive_run_key, google_update_task, msbuild_dev,
        certutil_hash, backup_vss, procdump_own_app, printer_install, log_export]
HOSTS = {windows_update: ["HOST-02", "HOST-03"], backup_vss: ["HOST-02", "HOST-03"], log_export: ["HOST-01", "HOST-05"],
         dev_git: ["HOST-09", "HOST-07"], msbuild_dev: ["HOST-09", "HOST-07"], procdump_own_app: ["HOST-09", "HOST-07"]}


def build(name="benign", groups=None, prefix="N", seed=SEED):
    rng = random.Random(seed)
    alerts, context, rows = [], {}, []
    for group, makers in groups or (("routine", ROUTINE), ("hard_negative", HARD)):
        for make in makers:
            for variant in range(2):
                aid = f"{prefix}{len(alerts) + 1:03d}"
                user = rng.choice(USERS)
                host = HOSTS.get(make, WORKSTATIONS)[variant % len(HOSTS.get(make, WORKSTATIONS))]
                events = make(user, rng)
                alerts.append({"alert_id": aid, "host": host, "events": events,
                               "label_tactic": "Benign", "label_verdict": "benign"})
                context[aid] = [e for other in rng.sample(ROUTINE, 2) for e in other(user, rng)]
                rows.append({"alert_id": aid, "source": f"synthetic/{make.__name__}", "group": group})
    out = ROOT / "data" / "eval"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{name}.jsonl").write_text("".join(json.dumps(a) + "\n" for a in alerts))
    (out / f"{name}_context.jsonl").write_text("".join(json.dumps({"alert_id": k, "events": v}) + "\n" for k, v in context.items()))
    (out / f"{name}_manifest.json").write_text(json.dumps({"dataset": name, "seed": seed, "synthetic": True,
                                                           "alerts": rows}, indent=2) + "\n")
    print(f"{name}: {len(alerts)} alerts")


if __name__ == "__main__":
    build()
    build("benign_fresh", (("mixed", FRESH),), "F", SEED + 1)
