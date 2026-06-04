# XJTU_STU-auto-login

西安交通大学校园网（`XJTU_STU` 等，深澜 Srun 认证）**自动登录**工具。连上校园网后自动完成 Web 认证，开机自启、断网自愈，无需每次手动打开认证页。

- ✅ 纯 Python 标准库，**零第三方依赖**
- ✅ 跨平台：**macOS / Windows / Linux**
- ✅ **门户地址与 ac_id 自动发现**——不同教学楼/区域的认证服务器 IP 不同（如 `10.6.18.2`、`10.6.21.2`），脚本自动识别
- ✅ 交互式初始化，开机自启一键安装

> 仅供在校学生认证**本人**账号使用。请勿用于他人账号或任何未授权用途。

> ⚠️ **测试状态**：目前仅在 **macOS** 环境实测通过；Windows / Linux 的自动登录与开机自启逻辑已编写但**未实测，可靠性未知**。如遇问题，欢迎及时提 [Issue](../../issues) 或 [Pull Request](../../pulls)。

---

## 工作原理

校园网用的是深澜（Srun）Web 门户认证。本工具：

1. 访问一次外网，被校园网关拦截重定向，从返回的 `LoginURL` 里**解析出当前区域的门户地址和 ac_id**；
2. 走 Srun 的标准认证流程：`get_challenge` 拿令牌 → `HMAC-MD5` + 自定义 `xEncode`/`base64` 加密账号信息 → `SHA1` 校验 → 提交 `srun_portal`；
3. 已在线则自动跳过；登录成功后记住门户地址，方便后续直接复用。

---

## 快速开始

需要 **Python 3.8+**（macOS / Linux 自带；Windows 到 [python.org](https://www.python.org/downloads/) 安装，安装时勾选 “Add Python to PATH”）。

```bash
# 1. 获取代码
git clone https://github.com/AstralArtisan/XJTU_STU-auto-login.git
cd XJTU_STU-auto-login

# 2. 初始化：填写你的学号和密码（密码输入时不回显）
python srun_login.py setup

# 3. 安装开机自启（自动识别当前操作系统）
python srun_login.py install
```

完成后，每次连上校园网会自动认证。Windows 上若 `python` 不可用，请用 `py` 代替。

---

## 命令一览

| 命令 | 作用 |
|------|------|
| `python srun_login.py setup` | 交互式填写/更新账号密码（写入本地 `creds.json`，权限 600） |
| `python srun_login.py login` | 立即认证上网（已在线则跳过） |
| `python srun_login.py status` | 查询当前在线状态 |
| `python srun_login.py logout` | 注销下线 |
| `python srun_login.py discover` | 仅探测当前网络的门户地址（排查用） |
| `python srun_login.py log` | 查看自动登录日志（`log 50` 看末 50 行 / `log -f` 实时跟随 / `log clear` 清空） |
| `python srun_login.py install` | 安装开机自启 |
| `python srun_login.py uninstall` | 移除开机自启 |
| `python srun_login.py auto` | 自启调度内部调用（手动一般用不到） |

---

## 自动登录怎么触发的

`install` 会按操作系统注册对应的后台任务，统一调用 `srun_login.py auto`：

- **macOS** — `LaunchAgent`（`~/Library/LaunchAgents/com.xjtu.autologin.plist`）：开机/登录、**网络变化即时触发**、外加每 90 秒兜底。
- **Windows** — 任务计划程序任务 `XJTU_STU-auto-login`：登录时启动 + 每 2 分钟兜底（用 `pythonw` 静默运行，无黑窗）。
- **Linux** — `systemd --user` 定时器 `xjtu-autologin.timer`：开机后 + 每 90 秒。

`auto` 会先看本机 IP 是否在校园网网段（默认 `10.x`，可在 `creds.json` 的 `campus_prefixes` 调整），不在则秒退，避免在家/热点时空跑。

---

## 卸载

```bash
python srun_login.py uninstall   # 移除开机自启
```

随后删除整个目录即可。`creds.json` 仅存在本地，删除目录即清除。

---

## 安全说明

- 账号密码以**明文**保存在本地 `creds.json`，靠文件权限（POSIX 下 600）+ `.gitignore` 保护，**绝不会被提交到 Git**。
- 本仓库 `.gitignore` 已排除 `creds.json`、`*.log`、`last_host.json` 等本地文件。请确认你 fork/克隆后不要手动提交它们。
- 请仅使用**本人**校园网账号。

---

## 故障排查

- **没自动登录？** 看日志 `autologin.log`，并手动跑 `python srun_login.py discover` 看是否发现门户。正常应返回 `["PORTAL","http://10.6.x.x", "<ac_id>"]` 或 `["ONLINE", null, null]`。
- **认证失败 `auth_info_error` / `ac_id` 相关报错？** 可能 ac_id 没自动取到，`setup` 时手动填一个（连上校园网用浏览器登录认证页，地址栏里的 `ac_id=` 即是）。
- **macOS 提示放在 `~/Desktop` 跑不起来？** macOS 的 `~/Desktop`、`~/Documents`、`~/Downloads` 是隐私（TCC）保护目录，后台任务无法读取其中脚本。请把本工具放在**非这些目录**（如用户主目录下普通文件夹）。
- **Windows 黑窗一闪？** 正常用 `pythonw` 应无窗口；若有，确认 Python 安装包含 `pythonw.exe`。

---

## 致谢与免责

- 深澜 Srun 认证加密逻辑参考其门户前端公开 JS 实现。
- 本工具按 “现状” 提供，作者不对使用后果负责。使用即代表你同意自行承担风险，并遵守学校网络使用规定。

## License

[MIT](LICENSE)
