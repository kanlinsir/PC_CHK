import os
import socket
import subprocess
import json
import winreg
import platform

def main():
    computer_name = platform.node()  # 電腦名稱
    local_ip = get_local_ip_address()  # 第一個區網 IPv4

    # 各項資料
    system_info       = get_system_info()
    defender_info     = get_defender_info()
    updates           = get_installed_updates()
    programs          = get_installed_programs()
    user_accounts     = get_local_user_accounts()
    password_policy   = get_password_policy()
    network_settings  = get_network_settings()

    # 產生 HTML 內容
    html_content = generate_html(
        computer_name, local_ip,
        system_info, defender_info, updates,
        programs, user_accounts, password_policy, network_settings
    )

    # 依「電腦名稱_區網IP.html」命名檔案
    filename = f"{computer_name}_{local_ip}.html"
    if os.path.exists(filename):
        response = input(f"檔案 {filename} 已存在，是否覆蓋? (Y/N): ")
        if response.strip().lower() != 'y':
            print("取消覆蓋，程式終止。")
            return

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"系統資訊已匯出至 {filename}")

def generate_html(computer_name, local_ip, system_info, defender_info, updates,
                  programs, user_accounts, password_policy, network_settings):
    """
    產生 HTML 格式的報告 (使用 Bootstrap 5)
    並在頁面上方加入導覽列 (Navbar)，可快速跳轉到各區段。
    """
    html = []
    html.append("<!DOCTYPE html>")
    html.append("<html lang='zh-Hant'>")
    html.append("<head>")
    html.append("<meta charset='UTF-8'>")
    html.append("<meta name='viewport' content='width=device-width, initial-scale=1.0'>")
    html.append(f"<title>系統資訊報告 - {computer_name} ({local_ip})</title>")
    # 引入 Bootstrap 5 CSS
    html.append("<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>")
    # 自訂 CSS (可根據需求調整)
    html.append("<style>")
    html.append("body { padding-top: 4.5rem; }")  # 留出 Navbar 高度
    html.append(".section { margin-bottom: 40px; }")
    html.append("h2 { margin-top: 20px; }")
    html.append("table { width: 100%; margin-bottom: 20px; }")
    html.append("th { cursor: pointer; }")
    html.append("</style>")
    html.append("</head>")
    html.append("<body>")

    # 導覽列 (Navbar) - Bootstrap 5
    # 可依需求調整樣式，如 navbar-dark bg-dark / navbar-light bg-light
    html.append("""
<nav class="navbar navbar-expand-lg navbar-light bg-light fixed-top">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">系統資訊報告</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent"
      aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="切換導覽列">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarSupportedContent">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        <li class="nav-item"><a class="nav-link" href="#system_info">系統資訊</a></li>
        <li class="nav-item"><a class="nav-link" href="#defender">Windows Defender</a></li>
        <li class="nav-item"><a class="nav-link" href="#updates">已安裝更新</a></li>
        <li class="nav-item"><a class="nav-link" href="#programs">已安裝程式</a></li>
        <li class="nav-item"><a class="nav-link" href="#users">使用者帳號</a></li>
        <li class="nav-item"><a class="nav-link" href="#policy">密碼原則</a></li>
        <li class="nav-item"><a class="nav-link" href="#network">網路設定</a></li>
      </ul>
    </div>
  </div>
</nav>
""")

    html.append("<div class='container'>")
    html.append("<div class='row'>")
    html.append("<div class='col'>")
    html.append("<h1 class='mb-4'>系統資訊報告</h1>")
    html.append(f"<p><strong>電腦名稱：</strong>{computer_name}<br>")
    html.append(f"<strong>區網 IP：</strong>{local_ip}</p>")

    # 依序產生各區段表格
    # table_id 與導覽列對應
    html.append(generate_html_section("系統資訊", system_info, "system_info"))
    html.append(generate_html_section("Windows Defender", defender_info, "defender"))
    html.append(generate_html_section("已安裝更新", updates, "updates"))
    html.append(generate_html_section("已安裝程式", programs, "programs"))
    html.append(generate_html_section("使用者帳號", user_accounts, "users"))
    html.append(generate_html_section("密碼原則", password_policy, "policy"))
    html.append(generate_html_section("網路設定", network_settings, "network"))

    html.append("</div></div></div>")  # end of container, row, col

    # 簡易版排序函式 (在點擊表頭時觸發)
    html.append("""
<script>
function sortTable(tableId, columnIndex) {
    var table = document.getElementById(tableId);
    if (!table) return;
    var switching = true;
    var dir = "asc"; 
    var switchcount = 0;

    while (switching) {
        switching = false;
        var rows = table.getElementsByTagName("TR");
        for (var i = 1; i < rows.length - 1; i++) {
            var shouldSwitch = false;
            var x = rows[i].getElementsByTagName("TD")[columnIndex];
            var y = rows[i + 1].getElementsByTagName("TD")[columnIndex];
            if (!x || !y) continue;

            // 用 localeCompare 進行比較 (數字也能大致排序)
            var cmp = x.innerHTML.localeCompare(y.innerHTML, 'zh-Hant', { numeric: true, sensitivity: 'base' });
            if (dir === "asc" && cmp > 0) {
                shouldSwitch = true;
                break;
            } else if (dir === "desc" && cmp < 0) {
                shouldSwitch = true;
                break;
            }
        }
        if (shouldSwitch) {
            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
            switching = true;
            switchcount++;
        } else {
            if (switchcount === 0 && dir === "asc") {
                dir = "desc";
                switching = true;
            }
        }
    }
}
</script>
""")

    # Bootstrap 5 JS (不依賴 jQuery)
    html.append("<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'></script>")
    html.append("</body>")
    html.append("</html>")
    return "\n".join(html)

def generate_html_section(title, data, table_id):
    """
    將 List[Dict] 資料轉換為 HTML 區段，若 data 為空則顯示「無資料」。
    同時在 <th> 上加上 onclick 排序功能。
    """
    html = []
    # 加上對應的錨點 (id)
    html.append(f"<div class='section' id='{table_id}'>")
    html.append(f"<h2>{title}</h2>")

    if not data:
        html.append("<p>無資料</p>")
        html.append("</div>")
        return "\n".join(html)

    # 假設 data 為 List[Dict]，以第一筆的鍵值作為表頭
    if isinstance(data, list) and data and isinstance(data[0], dict):
        headers = list(data[0].keys())
        html.append(f"<table class='table table-bordered table-sm' id='{table_id}_table'>")
        html.append("<thead class='table-light'><tr>")
        for i, header in enumerate(headers):
            # onclick 觸發 sortTable 函式
            html.append(f"<th onclick=\"sortTable('{table_id}_table', {i})\">{header}</th>")
        html.append("</tr></thead>")
        html.append("<tbody>")
        for item in data:
            html.append("<tr>")
            for header in headers:
                value = item.get(header, "")
                # 若是 dict，且包含 "DateTime" 就只顯示該欄位
                if isinstance(value, dict):
                    if "DateTime" in value:
                        value = value["DateTime"]
                    else:
                        value = str(value)
                elif isinstance(value, list):
                    # 若 value 為 list，則用逗號分隔
                    value = ", ".join(value)
                html.append(f"<td>{value}</td>")
            html.append("</tr>")
        html.append("</tbody>")
        html.append("</table>")
    else:
        # 若非 List[Dict] 或空，則直接列出
        for item in data:
            html.append(f"<p>{item}</p>")

    html.append("</div>")
    return "\n".join(html)

#------------------------------------------------------------------------------
# 以下為系統資訊蒐集函式，和前版本大同小異
#------------------------------------------------------------------------------ 

def get_system_info():
    data = []
    data.append({"項目": "電腦名稱", "內容": platform.node()})
    data.append({"項目": "區網 IP", "內容": get_local_ip_address()})
    data.append({"項目": "Windows 版本", "內容": platform.platform()})
    return data

def get_local_ip_address():
    """只抓第一個 IPv4（排除 127.*）"""
    host_name = socket.gethostname()
    for addr_info in socket.getaddrinfo(host_name, None):
        ip = addr_info[4][0]
        if ":" not in ip and not ip.startswith("127."):
            return ip
    return "未知"

def get_external_ip_address():
    """若需要對外 IP，可使用此函式 (需連上外網)"""
    try:
        result = subprocess.run(
            ["powershell", "-Command", "Invoke-RestMethod https://api.ipify.org"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass
    return "未知"

def get_defender_info():
    """
    以 PowerShell 執行 Get-MpComputerStatus 擷取四個欄位，轉成 JSON 後解析回 List[Dict]
    """
    ps_cmd = r'''
Get-MpComputerStatus |
Select-Object AMProductVersion,AMServiceVersion,AntispywareSignatureVersion,AntivirusSignatureVersion |
ConvertTo-Json
'''
    result_json = run_powershell(ps_cmd)
    try:
        data = json.loads(result_json)
        if isinstance(data, dict):
            data = [data]
        return data
    except:
        return [{"AMProductVersion": "無法取得",
                 "AMServiceVersion": "",
                 "AntispywareSignatureVersion": "",
                 "AntivirusSignatureVersion": ""}]

def get_installed_updates():
    """
    透過 PowerShell 取得 Win32_QuickFixEngineering 的 HotFixID、Description、InstalledOn，
    轉成 JSON 後解析回 List[Dict]
    """
    ps_cmd = r'''
Get-WmiObject Win32_QuickFixEngineering |
Select-Object HotFixID,Description,InstalledOn |
ConvertTo-Json
'''
    result_json = run_powershell(ps_cmd)
    try:
        data = json.loads(result_json)
        if isinstance(data, dict):
            data = [data]
        return data
    except:
        return []

def get_installed_programs():
    r"""
    從登錄讀取已安裝程式資訊：
      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
      HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
      以及 HKCU 對應路徑
    回傳 List[Dict]，包含：名稱、版本、發行者
    """
    data = []
    registry_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ]
    hives = [
        (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
        (winreg.HKEY_CURRENT_USER, "HKCU")
    ]
    for hive, _ in hives:
        for path in registry_paths:
            try:
                with winreg.OpenKey(hive, path) as reg_key:
                    for i in range(winreg.QueryInfoKey(reg_key)[0]):
                        subkey_name = winreg.EnumKey(reg_key, i)
                        try:
                            with winreg.OpenKey(reg_key, subkey_name) as subkey:
                                display_name = get_reg_value(subkey, "DisplayName")
                                if not display_name:
                                    continue
                                display_version = get_reg_value(subkey, "DisplayVersion")
                                publisher = get_reg_value(subkey, "Publisher")
                                data.append({
                                    "名稱": display_name,
                                    "版本": display_version if display_version else "",
                                    "發行者": publisher if publisher else ""
                                })
                        except:
                            pass
            except:
                pass
    return data

def get_reg_value(key, value_name):
    try:
        return winreg.QueryValueEx(key, value_name)[0]
    except:
        return None

def get_local_user_accounts():
    """
    透過 PowerShell 呼叫 Get-WmiObject 取得 Win32_UserAccount (LocalAccount=True) 資料，
    轉成 JSON 後解析回 List[Dict]
    """
    ps_cmd = r'''
Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" |
Select-Object Name,Domain,Description,Disabled |
ConvertTo-Json
'''
    result_json = run_powershell(ps_cmd)
    try:
        data = json.loads(result_json)
        if isinstance(data, dict):
            data = [data]
        result = []
        for item in data:
            disabled = item.get("Disabled", False)
            result.append({
                "帳號名稱": item.get("Name", ""),
                "網域": item.get("Domain", ""),
                "描述": item.get("Description", ""),
                "是否啟用": "停用" if disabled else "啟用"
            })
        return result
    except:
        return []

def get_password_policy():
    """
    執行 net accounts 指令，將文字輸出解析為 List[Dict]
    """
    raw_output = run_powershell("net accounts")
    lines = raw_output.splitlines()
    data = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            key = parts[0].strip()
            val = parts[1].strip()
            data.append({"設定": key, "值": val})
    return data

def get_network_settings():
    """
    利用 PowerShell 及 WMI 查詢 IPEnabled=True 的網路介面，取得 Description、IPAddress、IPSubnet 及 DNSServerSearchOrder，
    回傳 List[Dict]，每筆資料包含：介面名稱、IP位址、子網遮罩、DNS server
    """
    ps_cmd = r'''
Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" |
Select-Object Description, IPAddress, IPSubnet, DNSServerSearchOrder |
ConvertTo-Json
'''
    result_json = run_powershell(ps_cmd)
    try:
        data = json.loads(result_json)
        if isinstance(data, dict):
            data = [data]
        network_settings = []
        for item in data:
            interface = item.get("Description", "")
            ip_list = item.get("IPAddress", [])
            subnet_list = item.get("IPSubnet", [])
            dns_list = item.get("DNSServerSearchOrder", [])
            ip_str = ", ".join(ip_list) if isinstance(ip_list, list) else str(ip_list)
            subnet_str = ", ".join(subnet_list) if isinstance(subnet_list, list) else str(subnet_list)
            dns_str = ", ".join(dns_list) if (isinstance(dns_list, list) and dns_list) else (str(dns_list) if dns_list else "")
            network_settings.append({
                "介面名稱": interface,
                "IP位址": ip_str,
                "子網遮罩": subnet_str,
                "DNS server": dns_str
            })
        return network_settings
    except Exception as e:
        print("Error parsing network settings:", e)
        return [{"介面名稱": "無", "IP位址": "無", "子網遮罩": "無", "DNS server": "無法取得"}]

def run_powershell(command):
    """
    呼叫 PowerShell 指令，回傳標準輸出 (str)
    """
    proc = subprocess.run(["powershell", "-Command", command],
                          capture_output=True, text=True)
    return proc.stdout

if __name__ == "__main__":
    main()
