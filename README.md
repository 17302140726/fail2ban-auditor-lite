# fail2ban-lite

**60秒回答："我装的 fail2ban 到底防没防住 SSH？"**

fail2ban 是 Linux 服务器装得最多的防护工具，但大量机器"装了等于没装"：
jail 忘了 `enabled = true`、`bantime = 0` 封了等于没封、`maxretry = 20`
给爆破者充足弹药。本工具把 `/etc/fail2ban/jail.local` + `jail.d/*.local`
静态扫一遍，一次列出：

- **HIGH — jail 未启用**：没有 `enabled = true` 的 jail fail2ban 根本不加载
- **HIGH — bantime = 0**：封禁 0 秒 = 封了等于没封
- **HIGH — 未见启用的 sshd jail**：SSH 爆破面零防护（装了个寂寞）
- **MEDIUM — maxretry > 10**：爆破者可试 N 次密码
- **MEDIUM — findtime 过长（>1h）/过短（<1m）**：计数窗口失真
- **LOW — backend=auto 未显式 logpath / 未配置 action**：升级后可能静默失效

纯 Python 标准库，零依赖，只读不改，任何密钥/日志内容永不离开本机。

## 快速开始

```bash
chmod +x fail2ban_lite.py
./fail2ban_lite.py audit        # 审计本机
./fail2ban_lite.py selftest     # 内置 13 项自检
```

示例输出：

```
[HIGH] nginx-limit-req — bantime=0 → 封禁 0 秒=封了等于没封
[HIGH] postfix — jail 未启用（enabled 缺省/false）→ fail2ban 完全不加载此 jail
[MEDIUM] sshd — maxretry=20 过宽 → 爆破者可试 20 次密码
RESULT: 8 findings (2 HIGH), exit 1
```

**退出码即 API**：0=干净 / 1=有发现 / 2=用法错误。直接挂进 cron：

```
0 9 * * 1  /opt/fail2ban_lite.py audit --quiet || echo "fail2ban drift" | mail -s sre@you
```

离线模式：`--dir` 指向别的机器拷来的配置目录（应急响应取证）。

## 与完整版的差距

完整版 **Fail2Ban Auditor** 额外包含（路线图）：

| 能力 | lite | 完整版 |
|---|---|---|
| 未启用 jail / bantime=0 / maxretry·findtime 阈值 | ✅ | ✅ |
| logpath/filter 文件存在性核查（filter 缺失=静默失效） | — | ✅ |
| fail2ban-client 实时态对拍（iptables 链/ banned IP 台账） | — | ✅ |
| `--allow` 豁免模式 | — | ✅ |
| `--baseline` 增量 ratchet（只报新增漂移） | — | ✅ |
| `--json` 结构化输出 | — | ✅ |
| 自检断言 | 13 | 40+ |

👉 [Fail2Ban Auditor — $19](https://qiliang.gumroad.com)
（上架后此处将更新为直链；一次购买，永久使用，离线运行，无订阅无遥测）

## 同类工具（同店在售）

- [SSH Hardening Auditor](https://qiliang.gumroad.com) — sshd_config 配置面
- [Auth Log Auditor](https://qiliang.gumroad.com) — 谁在爆破我、有没有人真登进来
- [User Account Auditor](https://qiliang.gumroad.com) — 有几个账户、谁能 sudo

fail2ban 是**防护**，Auth Log Auditor 是**审计报告**——封了 1000 个 IP
你不知道谁在打、打成了没有。两个一起用。

## License

MIT
