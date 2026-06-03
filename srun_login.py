#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XJTU 校园网（深澜 Srun）自动登录 —— 跨平台（macOS / Windows / Linux）

子命令：
  setup      交互式填写账号密码，生成 creds.json
  login      认证上网（已在线则跳过；门户地址/ac_id 自动发现）
  logout     注销
  status     查询在线状态
  discover   仅探测当前网络的门户地址（调试用）
  auto       供自启调度调用：判断网段→登录→写日志（已在线静默退出）
  install    注册开机自启（macOS=LaunchAgent / Windows=任务计划 / Linux=systemd）
  uninstall  移除开机自启
"""
import os, re, sys, json, time, hmac, math, hashlib, subprocess
from urllib.request import urlopen, Request
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError

# ===== 默认配置（可被 creds.json 覆盖；账号密码请用 `setup` 写入，勿硬编码）=====
DEFAULT_HOST     = "http://10.6.18.2"   # 门户发现失败时的兜底（XJTU 常见节点）
AC_ID            = "1"
CAMPUS_PREFIXES  = ["10."]              # auto 的网段闸门：本机 IP 不在这些前缀则跳过
N                = "200"
TYPE             = "1"
OS_FIELD         = "Pro"
NAME_FIELD       = "Pro"

BASE = DEFAULT_HOST                      # 当前门户 base，由 resolve_portal() 动态设置
_DIR = os.path.dirname(os.path.abspath(__file__))
_CREDS = os.path.join(_DIR, "creds.json")
_LAST  = os.path.join(_DIR, "last_host.json")
_LOG   = os.path.join(_DIR, "autologin.log")

# ---------- 配置 ----------
def load_config():
    try:
        return json.load(open(_CREDS, encoding="utf-8"))
    except (OSError, ValueError):
        return {}

def apply_config(c):
    """用 creds.json 覆盖默认门户/ac_id/网段。"""
    global DEFAULT_HOST, AC_ID, BASE, CAMPUS_PREFIXES
    if c.get("default_host"):
        DEFAULT_HOST = c["default_host"]; BASE = DEFAULT_HOST
    if c.get("ac_id"):
        AC_ID = str(c["ac_id"])
    if c.get("campus_prefixes"):
        CAMPUS_PREFIXES = list(c["campus_prefixes"])

# ---------- Srun 自定义加密（已与服务器原版 JS 逐字节比对一致，勿改）----------
def _ordat(s, i):
    return ord(s[i]) if i < len(s) else 0

def _sencode(msg, key):
    l = len(msg)
    pwd = [_ordat(msg, i) | _ordat(msg, i+1) << 8 | _ordat(msg, i+2) << 16 | _ordat(msg, i+3) << 24
           for i in range(0, l, 4)]
    if key:
        pwd.append(l)
    return pwd

def _lencode(pwd, key):
    l = len(pwd)
    ll = (l - 1) << 2
    if key:
        m = pwd[l-1]
        if m < ll - 3 or m > ll:
            return ""
        ll = m
    out = []
    for i in range(l):
        out.append(chr(pwd[i] & 0xff) + chr(pwd[i] >> 8 & 0xff)
                   + chr(pwd[i] >> 16 & 0xff) + chr(pwd[i] >> 24 & 0xff))
    s = "".join(out)
    return s[:ll] if key else s

def _xencode(msg, key):
    if msg == "":
        return ""
    pwd = _sencode(msg, True)
    pwdk = _sencode(key, False)
    if len(pwdk) < 4:
        pwdk += [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]; d = 0
    q = math.floor(6 + 52 / (n + 1))
    while q > 0:
        d = d + 0x9E3779B9 & 0xffffffff
        e = d >> 2 & 3
        for p in range(n):
            y = pwd[p + 1]
            m = (z >> 5 ^ y << 2) + ((y >> 3 ^ z << 4) ^ (d ^ y)) + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & 0xffffffff
            z = pwd[p]
        y = pwd[0]
        m = (z >> 5 ^ y << 2) + ((y >> 3 ^ z << 4) ^ (d ^ y)) + (pwdk[(n & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & 0xffffffff
        z = pwd[n]
        q -= 1
    return _lencode(pwd, False)

_B64 = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
def _base64(s):
    pad = "="
    x = []
    imax = len(s) - len(s) % 3
    for i in range(0, imax, 3):
        b = (ord(s[i]) << 16) | (ord(s[i+1]) << 8) | ord(s[i+2])
        x += [_B64[b >> 18], _B64[b >> 12 & 0x3f], _B64[b >> 6 & 0x3f], _B64[b & 0x3f]]
    rem = len(s) - imax
    if rem == 1:
        b = ord(s[imax]) << 16
        x += [_B64[b >> 18], _B64[b >> 12 & 0x3f], pad, pad]
    elif rem == 2:
        b = (ord(s[imax]) << 16) | (ord(s[imax+1]) << 8)
        x += [_B64[b >> 18], _B64[b >> 12 & 0x3f], _B64[b >> 6 & 0x3f], pad]
    return "".join(x)

def _md5_hmac(value, key):
    return hmac.new(key.encode(), value.encode(), hashlib.md5).hexdigest()

def _sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()

# ---------- HTTP ----------
def _get(path, params, retries=8):
    url = BASE + path + "?" + urlencode(params)
    req = Request(url, headers={"User-Agent": "Mozilla/5.0", "Referer": BASE})
    last = None
    for _ in range(retries):
        try:
            raw = urlopen(req, timeout=10).read().decode("utf-8", "ignore")
            i, j = raw.find("("), raw.rfind(")")
            return json.loads(raw[i+1:j]) if i >= 0 and j > i else json.loads(raw)
        except HTTPError as e:
            last = "HTTP %s: %s" % (e.code, e.read().decode("utf-8", "ignore")[:120])
        except (URLError, json.JSONDecodeError, OSError) as e:
            last = str(e)
        time.sleep(1.5)
    raise RuntimeError("请求 %s 失败(%d次): %s" % (path, retries, last))

def get_local_ip():
    """取本机出口网卡 IP（UDP connect 不实际发包），跨平台。"""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return ""

# ---------- 门户自动发现 ----------
_UA = {"User-Agent": "Mozilla/5.0"}
_PROBES = ["http://captive.apple.com/hotspot-detect.html",
           "http://www.msftconnecttest.com/redirect",
           "http://1.1.1.1/"]

def _find_portal_url(text):
    if not text:
        return None
    m = re.search(r'https?://(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?[^\s"\'<>]*', text)
    return m.group(0) if m else None

def _host_of(url):
    m = re.match(r'(https?://\d{1,3}(?:\.\d{1,3}){3})', url or "")
    return m.group(1) if m else None

def _acid_of(url):
    m = re.search(r'[?&]ac_id=(\d+)', url or "")
    return m.group(1) if m else None

def discover():
    """('ONLINE',None,None) / ('PORTAL', base, ac_id) / (None,None,None)。
    原理：未认证时访问外网被校园门户拦截，重定向/WISPr 含真实 LoginURL。"""
    for p in _PROBES:
        body = final = loc = ""
        try:
            r = urlopen(Request(p, headers=_UA), timeout=5)
            body = r.read().decode("utf-8", "ignore"); final = r.geturl()
            if "Success" in body and "apple" in p:
                return ("ONLINE", None, None)
        except HTTPError as e:
            try: body = e.read().decode("utf-8", "ignore")
            except Exception: body = ""
            loc = e.headers.get("Location", "") if e.headers else ""
        except (URLError, OSError):
            continue
        u = _find_portal_url(loc) or _find_portal_url(body) or _find_portal_url(final)
        if u:
            host, ac = _host_of(u), _acid_of(u)
            if host and not ac:
                try:
                    rr = urlopen(Request(host + "/", headers=_UA), timeout=5)
                    ac = _acid_of(rr.geturl())
                except Exception:
                    pass
            if host:
                return ("PORTAL", host, ac)
    return (None, None, None)

def _save_last(base, ac):
    try:
        json.dump({"base": base, "ac_id": ac}, open(_LAST, "w"))
    except OSError:
        pass

def _load_last():
    try:
        d = json.load(open(_LAST)); return d.get("base"), d.get("ac_id")
    except (OSError, ValueError):
        return None, None

def resolve_portal():
    global BASE
    state, base, ac = discover()
    if state == "PORTAL":
        BASE = base
        return state, base, ac
    if state == "ONLINE":
        lb, la = _load_last()
        if lb: BASE = lb
        return state, BASE, la
    lb, la = _load_last()
    BASE = lb or DEFAULT_HOST
    return None, BASE, la

# ---------- 认证动作 ----------
def status():
    resolve_portal()
    return _get("/cgi-bin/rad_user_info", {"callback": "j", "_": int(time.time()*1000)})

def _do_login(username, password, ac_id):
    ip = get_local_ip()
    ch = _get("/cgi-bin/get_challenge",
              {"callback": "j", "username": username, "ip": ip, "_": int(time.time()*1000)})
    token = ch["challenge"]
    ip = ch.get("client_ip") or ip
    info_obj = {"username": username, "password": password, "ip": ip, "acid": ac_id, "enc_ver": "srun_bx1"}
    info = "{SRBX1}" + _base64(_xencode(json.dumps(info_obj, separators=(",", ":")), token))
    hmd5 = _md5_hmac(password, token)
    chk = token + username + token + hmd5 + token + ac_id + token + ip + token + N + token + TYPE + token + info
    params = {
        "callback": "j", "action": "login", "username": username,
        "password": "{MD5}" + hmd5, "ac_id": ac_id, "ip": ip,
        "chksum": _sha1(chk), "info": info, "n": N, "type": TYPE,
        "os": OS_FIELD, "name": NAME_FIELD, "double_stack": "0", "_": int(time.time()*1000),
    }
    return _get("/cgi-bin/srun_portal", params)

def login(username, password, ac_id=None):
    state, base, ac = resolve_portal()
    if state == "ONLINE":
        return {"error": "ok", "res": "ok", "suc_msg": "already_online_local"}
    if state != "PORTAL":
        raise RuntimeError("未发现校园认证门户（可能不在校园网，或网络异常）。当前 BASE=%s" % BASE)
    ac_id = ac_id or ac or AC_ID
    r = _do_login(username, password, ac_id)
    if isinstance(r, dict) and (r.get("error") == "ok" or r.get("ecode") == "E2620"):
        _save_last(BASE, ac_id)
    return r

def logout(username):
    resolve_portal()
    ip = get_local_ip()
    _, ac = _load_last()
    params = {"callback": "j", "action": "logout", "username": username,
              "ip": ip, "ac_id": ac or AC_ID, "_": int(time.time()*1000)}
    return _get("/cgi-bin/srun_portal", params)

# ---------- setup：交互式引导 ----------
def cmd_setup():
    import getpass
    cur = load_config()
    print("=== XJTU 校园网自动登录 · 初始化 ===")
    hint = ("（回车保留当前 %s）" % cur["username"]) if cur.get("username") else "（形如 学号@stu）"
    u = input("用户名%s: " % hint).strip() or cur.get("username", "")
    p = getpass.getpass("密码（输入不回显，回车保留原密码）: ") or cur.get("password", "")
    ac = input("ac_id（认证区域号，直接回车=自动发现）: ").strip()
    if not u or not p:
        print("用户名和密码不能为空，已取消。"); return 1
    cfg = {"username": u, "password": p}
    if ac:
        cfg["ac_id"] = ac
    elif cur.get("ac_id"):
        cfg["ac_id"] = cur["ac_id"]
    for k in ("default_host", "campus_prefixes"):
        if k in cur:
            cfg[k] = cur[k]
    with open(_CREDS, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(_CREDS, 0o600)
    except OSError:
        pass
    print("\n已写入 %s（权限 600，请勿提交到 Git）。" % _CREDS)
    print("下一步：python %s install   # 开启开机自启" % os.path.basename(__file__))
    print("或手动登录测试：python %s login" % os.path.basename(__file__))
    return 0

# ---------- auto：供自启调度调用 ----------
def _log(msg):
    try:
        with open(_LOG, "a", encoding="utf-8") as f:
            f.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except OSError:
        pass

def cmd_auto(cfg):
    # 网段闸门：本机 IP 不在校园网前缀则静默退出（省去在家/热点探测）
    ip = get_local_ip()
    if CAMPUS_PREFIXES and not any(ip.startswith(pre) for pre in CAMPUS_PREFIXES):
        return 0
    user, pwd = cfg.get("username", ""), cfg.get("password", "")
    if not user or not pwd:
        _log("未配置账号，请先运行 setup"); return 1
    ac = cfg.get("ac_id")
    for i in range(1, 6):
        try:
            r = login(user, pwd, ac)
        except Exception as e:
            r = {"error": "exception", "msg": str(e)}
        if isinstance(r, dict):
            if r.get("suc_msg") == "already_online_local":
                return 0  # 已在线，静默
            if r.get("error") == "ok" or r.get("ecode") == "E2620":
                _log("[%s] 登录成功: %s" % (ip, json.dumps(r, ensure_ascii=False)))
                return 0
        _log("[%s] 第%d次失败: %s" % (ip, i, json.dumps(r, ensure_ascii=False) if isinstance(r, dict) else str(r)))
        time.sleep(2)
    _log("[%s] 多次尝试后仍失败" % ip)
    return 1

# ---------- install / uninstall：跨平台开机自启 ----------
LABEL = "com.xjtu.autologin"          # macOS LaunchAgent label
TASK  = "XJTU_STU-auto-login"         # Windows 计划任务名
UNIT  = "xjtu-autologin"              # Linux systemd 单元名

def _script_path():
    return os.path.abspath(__file__)

def _xml_escape(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))

def _which(name):
    from shutil import which
    return which(name)

_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{py}</string>
        <string>{script}</string>
        <string>auto</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>WatchPaths</key>
    <array>
        <string>/var/run/resolv.conf</string>
        <string>/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist</string>
        <string>/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist</string>
    </array>
    <key>StartInterval</key><integer>90</integer>
    <key>ProcessType</key><string>Background</string>
    <key>LowPriorityIO</key><true/>
    <key>StandardErrorPath</key><string>{err}</string>
</dict>
</plist>
"""

def install_macos():
    d = os.path.expanduser("~/Library/LaunchAgents")
    os.makedirs(d, exist_ok=True)
    plist = os.path.join(d, LABEL + ".plist")
    content = _PLIST.format(label=LABEL, py=_xml_escape(sys.executable or "python3"),
                            script=_xml_escape(_script_path()),
                            err=_xml_escape(os.path.join(_DIR, "launchd.err")))
    open(plist, "w").write(content)
    subprocess.run(["launchctl", "unload", plist], capture_output=True)
    subprocess.run(["launchctl", "load", "-w", plist], check=False)
    print("已安装 LaunchAgent：%s" % plist)
    print("开机/网络变化/每90秒会自动认证。日志：%s" % _LOG)
    return 0

def uninstall_macos():
    plist = os.path.expanduser("~/Library/LaunchAgents/%s.plist" % LABEL)
    subprocess.run(["launchctl", "unload", plist], capture_output=True)
    if os.path.exists(plist):
        os.remove(plist)
    print("已移除 LaunchAgent：%s" % plist)
    return 0

_TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>XJTU 校园网自动登录</Description></RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Repetition><Interval>PT2M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>{py}</Command><Arguments>"{script}" auto</Arguments></Exec>
  </Actions>
</Task>
"""

def _pythonw():
    exe = sys.executable or "python"
    cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
    return cand if os.path.exists(cand) else exe

def install_windows():
    import tempfile
    xml = _TASK_XML.format(py=_xml_escape(_pythonw()), script=_xml_escape(_script_path()))
    fd, path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    with open(path, "w", encoding="utf-16") as f:
        f.write(xml)
    r = subprocess.run(["schtasks", "/create", "/tn", TASK, "/xml", path, "/f"],
                       capture_output=True, text=True)
    os.remove(path)
    if r.returncode != 0:
        print("创建计划任务失败：", r.stdout, r.stderr); return 1
    print("已创建计划任务：%s（登录自启 + 每2分钟兜底）" % TASK)
    print("日志：%s" % _LOG)
    return 0

def uninstall_windows():
    subprocess.run(["schtasks", "/delete", "/tn", TASK, "/f"], capture_output=True)
    print("已删除计划任务：%s" % TASK)
    return 0

_SERVICE = """[Unit]
Description=XJTU 校园网自动登录
After=network-online.target

[Service]
Type=oneshot
ExecStart={py} {script} auto
"""
_TIMER = """[Unit]
Description=XJTU 校园网自动登录定时器

[Timer]
OnBootSec=30
OnUnitActiveSec=90
Persistent=true

[Install]
WantedBy=timers.target
"""

def install_linux():
    if not _which("systemctl"):
        print("未检测到 systemd。可用 cron 或网络钩子手动调用：%s %s auto"
              % (sys.executable or "python3", _script_path()))
        return 1
    d = os.path.expanduser("~/.config/systemd/user")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, UNIT + ".service"), "w").write(
        _SERVICE.format(py=sys.executable or "python3", script=_script_path()))
    open(os.path.join(d, UNIT + ".timer"), "w").write(_TIMER)
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "--user", "enable", "--now", UNIT + ".timer"], check=False)
    print("已安装 systemd 用户定时器：%s.timer" % UNIT)
    print("提示：如需登出后仍运行，执行 `sudo loginctl enable-linger $USER`。日志：%s" % _LOG)
    return 0

def uninstall_linux():
    subprocess.run(["systemctl", "--user", "disable", "--now", UNIT + ".timer"], capture_output=True)
    d = os.path.expanduser("~/.config/systemd/user")
    for f in (UNIT + ".service", UNIT + ".timer"):
        p = os.path.join(d, f)
        if os.path.exists(p):
            os.remove(p)
    subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    print("已移除 systemd 用户定时器：%s" % UNIT)
    return 0

def cmd_install():
    if sys.platform == "darwin":
        return install_macos()
    if sys.platform == "win32":
        return install_windows()
    if sys.platform.startswith("linux"):
        return install_linux()
    print("不支持的平台：%s" % sys.platform); return 1

def cmd_uninstall():
    if sys.platform == "darwin":
        return uninstall_macos()
    if sys.platform == "win32":
        return uninstall_windows()
    if sys.platform.startswith("linux"):
        return uninstall_linux()
    print("不支持的平台：%s" % sys.platform); return 1

# ---------- CLI ----------
def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "login"
    cfg = load_config()
    apply_config(cfg)

    if cmd == "setup":
        return cmd_setup()
    if cmd == "install":
        return cmd_install()
    if cmd == "uninstall":
        return cmd_uninstall()
    if cmd == "auto":
        return cmd_auto(cfg)

    user, pwd = cfg.get("username", ""), cfg.get("password", "")
    ac = sys.argv[2] if len(sys.argv) > 2 else cfg.get("ac_id")
    try:
        if cmd == "status":
            print(json.dumps(status(), ensure_ascii=False))
        elif cmd == "logout":
            print(json.dumps(logout(user), ensure_ascii=False))
        elif cmd == "discover":
            print(json.dumps(discover(), ensure_ascii=False))
        elif cmd == "login":
            if not user or not pwd:
                print("尚未配置账号，请先运行：python %s setup" % os.path.basename(__file__)); return 1
            print(json.dumps(login(user, pwd, ac), ensure_ascii=False))
        else:
            print("未知命令：%s\n用法：setup | login | logout | status | discover | auto | install | uninstall" % cmd)
            return 1
    except Exception as e:
        print(json.dumps({"error": "exception", "msg": str(e), "base": BASE}, ensure_ascii=False))
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())
