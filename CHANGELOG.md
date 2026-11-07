# Changelog

## v2.0.0 — 2026-11-07

### 支持系统

| 系统 | 版本 |
| --- | --- |
| Debian | 11 / 12 / 13 |
| Ubuntu | 20.04 / 22.04 / 24.04 / 26.04 |

需要 systemd、Python 3.8+（缺少时 `bootstrap.sh` 自动安装）。其他 Debian/Ubuntu 版本或衍生版可设置 `HY2HOP_ALLOW_UNTESTED=1` 自行承担风险。

### 升级方式

已用 V1 安装的服务器直接执行，无需先 restore：

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/hcloudlab/Hysteria2-Hop/main/bootstrap.sh)" _ update
```

`update` 会自动替换 `/usr/local/sbin/hcloudlab-hy2hop`、更新 systemd 服务，并重建一次 NAT 规则。

### 重要修复

- NAT 规则只重定向**目的地是本机**的 UDP（`fib daddr type local`）。V1 会把 Docker 容器、WireGuard 客户端等经本机转发、目标端口落在跳跃范围内的 UDP 流量也转到 Hysteria2 端口。
- 中文系统语言下 UFW 状态识别失败（`ufw status` 输出被翻译），导致不放行端口。
- Debian 用 `su`（不带 `-`）切换 root 时找不到 `nft` / `ufw`。
- 系统大版本升级后，开机恢复规则不再因版本检查失败导致节点掉线。
- `bootstrap.sh` 运行后不再残留临时目录。

### 改进

- Docker 主机不再一律拒绝安装：只有可能覆盖跳跃范围的 UDP DNAT / redirect / TPROXY 规则（含 iptables-legacy）才会拒绝。
- Xray 出站使用的临时 UDP 端口不再被误判为端口冲突。
- 其他入站的 Hop Ports 填错不再阻塞当前入站。
- 内核支持 IPv6 即创建 IPv6 规则，不再依赖安装时是否已有公网 IPv6 地址；内核不支持 IPv6 NAT 时自动只建 IPv4。
- 首次开机 apt 被 unattended-upgrades 占用时自动等待；Ubuntu 20.04 缺少 universe 源时给出明确提示。
- systemd 服务跟随 `nftables.service` 的启动 / 重启 / 重载自动恢复跳跃规则。
- `status` 显示转发数据包计数；`restore` 同时删除已安装的 CLI。
- 跳跃范围与系统临时端口段重叠时给出提醒。
- 兼容 nftables 0.9.3 ~ 1.1.x（NAT 优先级改为数值 `-100`）。

### 验证状态

- ✅ 56 项单元测试：Python 3.8 / 3.10 / 3.11 / 3.12 / 3.13 / 3.14。
- ✅ Ubuntu 20.04 / 22.04 / 24.04 / 26.04：debootstrap 根文件系统 + 隔离网络命名空间，真实 apt / nft / ufw，20 项端到端检查全部通过（含真实 UDP 跳跃转发穿过 UFW、update 幂等、改端口后 update、模拟开机恢复、Docker 共存、restore）。
- ⚠️ 未验证：Debian 11/12/13 真实系统；IPv6 转发；真实 systemd 重启；实机 VPS + 3X-UI + 真实客户端。
