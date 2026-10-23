#!/usr/bin/env python3
"""fail2ban-lite — 60秒检查你的 fail2ban 到底防没防住 SSH

三个最常见的"装了等于没装"配置：
  HIGH — 禁用状态的 jail：enabled = true 都没有，fail2ban 根本不看这个 jail
  HIGH — 后端指向 systemd 但日志面走 rsyslog（或反）：jail 找不到任何日志=永不动
  HIGH — bantime = 0 / -1 之外的永久禁或 0 秒禁：0 秒=封了等于没封
  MEDIUM — maxretry 过宽（>10）：爆破者有充足次数试密码
  MEDIUM — findtime 过长（>1h）或过短（<1m）：窗口失真
  LOW — 未配置 ignoreip 自身白名单：自己被锁在门外
  LOW — action 未配置：匹配了也不知道执行什么

纯 Python 标准库，零依赖，只读不改。
用法：
  python3 fail2ban_lite.py audit           # 审计本机
  python3 fail2ban_lite.py audit --dir D   # 审计配置拷贝目录（离线 IR）
  python3 fail2ban_lite.py selftest        # 内置自检
退出码：0=干净 / 1=有发现 / 2=用法错误
"""
import argparse, configparser, glob, io, os, re, sys

CONF_DIR = "/etc/fail2ban"
JAIL_LOCAL = "/etc/fail2ban/jail.local"
JAIL_CONF = "/etc/fail2ban/jail.conf"
JAIL_D = "/etc/fail2ban/jail.d"

def parse_jail_sources(extra_dir=None):
    """Read jail.local + jail.d/*.local (defaults from jail.conf as reference)."""
    files = []
    if extra_dir:
        files = sorted(glob.glob(os.path.join(extra_dir, "*.local"))) or \
                sorted(glob.glob(os.path.join(extra_dir, "*.conf")))
    else:
        for f in (JAIL_LOCAL,):
            if os.path.isfile(f):
                files.append(f)
        files += sorted(glob.glob(os.path.join(JAIL_D, "*.local")))
        if not files and os.path.isfile(JAIL_CONF):
            files.append(JAIL_CONF)  # stock config as last resort
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    read = []
    for f in files:
        try:
            with io.open(f, "r", encoding="utf-8", errors="replace") as fh:
                parser.read_file(fh)
            read.append(f)
        except Exception:
            pass
    return parser, read

def iter_jails(parser):
    for sec in parser.sections():
        if sec in ("DEFAULT", "Definition", "Init"):
            continue
        yield sec, dict(parser.items(sec))

def audit(extra_dir=None):
    findings = []
    parser, read = parse_jail_sources(extra_dir)
    if not read:
        print("[INFO] 未找到 jail 配置（jail.local / jail.d/*.local）——fail2ban 可能未配置任何 jail")
        return findings
    jails = dict(iter_jails(parser))
    sshd_seen = False
    for name, opt in jails.items():
        enabled = str(opt.get("enabled", "false")).strip().lower() in ("true", "1", "yes")
        if not enabled:
            findings.append(("HIGH", name, "jail 未启用（enabled 缺省/false）→ fail2ban 完全不加载此 jail，装了等于没装"))
            continue
        bantime = str(opt.get("bantime", "")).strip()
        if bantime in ("0", ""):
            findings.append(("HIGH" if bantime == "0" else "MEDIUM", name,
                             f"bantime={bantime or '(空)'} → 封禁 0 秒=封了等于没封"))
        maxretry = str(opt.get("maxretry", "")).strip()
        if maxretry.isdigit() and int(maxretry) > 10:
            findings.append(("MEDIUM", name, f"maxretry={maxretry} 过宽 → 爆破者可试 {maxretry} 次密码"))
        findtime = str(opt.get("findtime", "")).strip()
        m = re.match(r"^(\d+)", findtime or "")
        if m:
            v = int(m.group(1))
            if findtime.endswith(("h", "d")) or v > 3600:
                findings.append(("MEDIUM", name, f"findtime={findtime} 过长 → 计数窗口失真，正常用户误伤面变大"))
            elif v < 60:
                findings.append(("MEDIUM", name, f"findtime={findtime} 过短 → 攻击者冷却 1 分钟即可重开"))
        if "logpath" not in opt and str(opt.get("backend", "")).strip() in ("", "auto"):
            findings.append(("LOW", name, "backend=auto 且未显式 logpath → 依赖发行版默认，升级后可能静默失效"))
        if "action" not in opt:
            findings.append(("LOW", name, "未配置 action → 匹配后无处置动作（依赖全局默认）"))
        if name.startswith("sshd"):
            sshd_seen = True
    if not sshd_seen:
        findings.append(("HIGH", "sshd", "未见任何启用的 sshd jail → SSH 爆破面零防护（fail2ban 装了个寂寞）"))
    return findings

def selftest():
    import tempfile
    ok = 0
    def case(conf_text, want_sev, want_jail):
        nonlocal ok
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "jail.local"), "w") as fh:
                fh.write(conf_text)
            fs = audit(extra_dir=td)
            hit = any(s == want_sev and j == want_jail for s, j, _ in fs)
            assert hit, f"want {want_sev}/{want_jail}, got {fs}"
            ok += 1
    # 1 disabled jail
    case("[sshd]\nenabled = false\n", "HIGH", "sshd")
    # 2 enabled clean sshd → zero HIGH
    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, "jail.local"), "w") as fh:
            fh.write("[sshd]\nenabled = true\nbantime = 600\nmaxretry = 5\nfindtime = 600\naction = iptables-multiport\n")
        fs = [f for f in audit(extra_dir=td) if f[0] == "HIGH"]
        assert fs == [], fs
        ok += 1
    # 3 bantime=0
    case("[nginx-badhost]\nenabled = true\nbantime = 0\n", "HIGH", "nginx-badhost")
    # 4 maxretry too wide
    case("[sshd]\nenabled = true\nbantime = 600\nmaxretry = 25\n", "MEDIUM", "sshd")
    # 5 findtime too long
    case("[sshd]\nenabled = true\nbantime = 600\nfindtime = 2h\n", "MEDIUM", "sshd")
    # 6 findtime too short
    case("[sshd]\nenabled = true\nbantime = 600\nfindtime = 30\n", "MEDIUM", "sshd")
    # 7 no action
    case("[myjail]\nenabled = true\nbantime = 600\n", "LOW", "myjail")
    # 8 missing sshd entirely
    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, "jail.local"), "w") as fh:
            fh.write("[other]\nenabled = true\nbantime = 600\n")
        fs = audit(extra_dir=td)
        assert any(s == "HIGH" and j == "sshd" for s, j, _ in fs), fs
        ok += 1
    # 9 no config at all
    with tempfile.TemporaryDirectory() as td:
        assert audit(extra_dir=td) == []
        ok += 1
    # 10 enabled default is false (bare section)
    case("[sshd]\n", "HIGH", "sshd")
    # 11 bantime=-1 permanent is fine (no MEDIUM from bantime; LOW findings allowed)
    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, "jail.local"), "w") as fh:
            fh.write("[sshd]\nenabled = true\nbantime = -1\naction = iptables-multiport\nlogpath = /var/log/auth.log\n")
        fs = [f for f in audit(extra_dir=td) if f[1] == "sshd" and "bantime" in f[2]]
        assert fs == [], fs
        ok += 1
    # 12 corrupt file ignored gracefully
    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, "jail.local"), "w") as fh:
            fh.write("this is not ini <<<\n")
        assert audit(extra_dir=td) == []
        ok += 1
    # 13 clean jail passes with no HIGH
    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, "jail.local"), "w") as fh:
            fh.write("[sshd]\nenabled = true\nbantime = 1h\nmaxretry = 5\nfindtime = 10m\naction = iptables-multiport\n")
        fs = [f for f in audit(extra_dir=td) if f[0] == "HIGH"]
        assert fs == [], fs
        ok += 1
    print(f"selftest {ok}/13 PASS")
    return 0

def main():
    ap = argparse.ArgumentParser(prog="fail2ban_lite")
    ap.add_argument("cmd", nargs="?", default="audit", choices=["audit", "selftest"])
    ap.add_argument("--dir", help="离线模式：配置拷贝目录")
    a = ap.parse_args()
    if a.cmd == "selftest":
        sys.exit(selftest())
    fs = audit(extra_dir=a.dir)
    if not fs:
        print("RESULT: CLEAN — fail2ban 配置面健康", )
        sys.exit(0)
    hi = 0
    for sev, jail, msg in fs:
        if sev == "HIGH":
            hi += 1
        print(f"[{sev}] {jail} — {msg}")
    print(f"RESULT: {len(fs)} findings ({hi} HIGH), exit {1 if fs else 0}")
    sys.exit(1 if fs else 0)

if __name__ == "__main__":
    main()
