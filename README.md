# HCloudLab · 3X-UI Hysteria2 端口跳跃  V2 — Debian / Ubuntu

## 适用范围

| 系统 | 版本 |
| --- | --- |
| Debian | 11 / 12 / 13 |
| Ubuntu | 20.04 / 22.04 / 24.04 / 26.04 |

- 3X-UI 面板中的 Hysteria2 入站：数据库 `protocol=hysteria`
- 在面板填写 **Hop Ports**，例如 `20000-30000`；脚本只读数据库，不修改 x-ui.db。
- 需要 systemd、Python 3.8+（缺少时 `bootstrap.sh` 自动安装 `python3`）。其他 Debian/Ubuntu 版本或衍生版可设置 `HY2HOP_ALLOW_UNTESTED=1` 自行承担风险。
- IPv4 必定创建规则；内核支持 IPv6 时同时创建 IPv6 规则（不再要求安装时已有公网 IPv6 地址）。
- 只重定向**目的地是本机**的 UDP（`fib daddr type local`），不会误伤 Docker 容器、WireGuard 等经本机转发的流量。
- UFW 开启时自动添加跳跃范围 **和 Hysteria2 实际监听端口** 的 UDP 放行规则；nftables 未安装时从系统软件源自动安装（Ubuntu 20.04 需启用 universe 源）。
  - 这里说的是服务器自身的 UFW，不是 DMIT/其他云厂商控制台里的"安全组"。安全组仍需自己在面板放行跳跃范围和监听端口。
  - 使用 firewalld 时脚本只提示、不修改，需要自行放行。
- 可与 Docker 的 TCP 端口映射共存；只有**可能覆盖跳跃范围的 UDP** DNAT / redirect / TPROXY 规则（含 iptables-legacy）才会拒绝安装。
- 不支持 OpenVZ / LXC 等不允许 nftables NAT 的容器型 VPS。

## V2 更新

- 适配 Debian 11/12/13、Ubuntu 20.04/22.04/24.04/26.04；兼容 nftables 0.9.3 ~ 1.1.x、Python 3.8 ~ 3.14。
- 修复：Debian 用 `su`（不带 `-`）切 root 时找不到 `nft`/`ufw`；中文系统语言下 UFW 状态识别失败；`bootstrap.sh` 运行后临时目录残留。
- NAT 规则只匹配本机目的地址，不再劫持经本机转发的流量。
- Docker 主机不再被一刀切拒绝；冲突检测精确到 UDP 端口范围。
- 其他入站的 Hop Ports 填错不再阻塞当前入站的安装/更新/状态检查。
- 首次开机 apt 被 unattended-upgrades 占用时自动等待。
- 系统大版本升级后，开机恢复规则不会因版本检查失败而导致节点掉线。
- `update` 会自动升级已安装的脚本和 systemd 服务；V1 安装直接执行 `update` 即可升级，无需先 `restore`。
- `status` 显示转发数据包计数；`restore` 同时清理 `/usr/local/sbin/hcloudlab-hy2hop`。

## 🎧 图文配置教程

[🎧 3X-UI Hysteria2 端口跳跃配置教程（面板参数、Shadowrocket、脚本命令）](docs/🎧-Hysteria2端口跳跃配置.md)

## 一键安装

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/hcloudlab/Hysteria2-Hop/main/bootstrap.sh)"
```

`bootstrap.sh` 只下载 `hy2hop.py` 本身（单文件，无其他依赖），编译检查后立即运行，不会在系统上留下安装脚本本身。安装后执行 `/usr/local/sbin/hcloudlab-hy2hop` 可再次打开菜单。

本地已有完整仓库时，也可以直接在仓库目录执行 `sudo bash install.sh`。

## VPS / ISP 推荐

以下服务可按实际需求选用，**不是使用 Hysteria2-Hop 的必要条件**。

| 名称 | 主要特点 | 链接 |
| --- | --- | --- |
| **搬瓦工 VPS — DC9** | **CN2 GIA + CMIN2 + 联通 Premium**，面向中国大陆方向提供多运营商优质线路；当前推荐套餐 **$49.99 / 季度**。 | [购买 DC9](https://bwh81.net/aff.php?aff=82473&a=add&pid=87&billingcycle=quarterly&configoption%5B17%5D=55) |
| **DMIT** | **CN2 GIA 顶级线路，国内访问速度一流**。 | [访问 DMIT](https://www.dmit.io/aff.php?aff=20932) |
| **Proxy-Seller ISP** | 静态住宅代理 ISP，价格约 **$3 / 月起**；优惠码 **HCLOUD15**。 | [购买 ISP](https://proxy-seller.com/?partner=8Y51DM71OGR26N) |

> 以上为 Affiliate 推广链接，可能为项目维护者带来佣金。Hysteria2-Hop 只负责 3X-UI Hysteria2 的端口跳跃规则，不提供 VPS、线路或 ISP 出口。价格、套餐和优惠以服务商实际页面为准。

## 验收

1. 首次安装（Debian/Ubuntu 各版本）：检查是否自动安装 nftables，读取 Hop Ports 并生成 IPv4/IPv6 映射，确认 UFW 同时放行了跳跃范围和实际监听端口（`ufw status numbered`）。
2. `sudo /usr/local/sbin/hcloudlab-hy2hop status`：检查当前配置；缺少监听端口或跳跃范围的任一条 UFW 规则都应报告 `STATUS: FAIL`。
3. 更新客户端订阅，真实连接并确认跳跃端口的 UDP 流量计数增加。
4. 连续执行 `update` 3 次，确保没有重复规则。
5. 重启 VPS，再执行 `status`，验证客户端仍可连接。
6. 在 3X-UI 修改监听端口和/或 Hop Ports，再执行 `update`，检查旧端口/旧范围的 UFW 规则消失、新端口/新范围的规则生效。
7. 执行 `restore`，确认原 443/UDP 节点可用、其他防火墙规则不变（包括安装前已存在的 UFW 规则）。
8. 出现错误立即停止并提供完整终端输出；不要手工执行 `nft flush ruleset` 或关闭 UFW。

## 内部验证范围

### V2（2026-11）

- 51 项单元测试在 Python 3.8 / 3.10 / 3.11 / 3.12 / 3.13 / 3.14 下全部通过。
- 在 Ubuntu 20.04 / 22.04 / 24.04 / 26.04 的 debootstrap 根文件系统 + 隔离网络命名空间中，用真实的 `apt-get`/`nft`/`ufw`/`ss` 跑通 20 项端到端检查（每个版本均 20/20）：
  自动安装 nftables、install、真实 UDP 包从跳跃端口转到监听端口并穿过 UFW、直连监听端口、经本机转发的流量不被重定向、status、update ×3 幂等、修改端口和范围后 update（旧 UFW 规则清理）、模拟开机 reload、Docker TCP 映射共存、范围内 UDP DNAT 拒绝、restore（保留原有 UFW 规则）。
  - Ubuntu 20.04 覆盖 iptables-legacy 后端的 UFW + nftables 0.9.3 混用，以及 iptables-legacy 下的 Docker 规则检测。
  - 测试时使用不含 `/usr/sbin` 的 PATH，复现 Debian `su` 环境。
- **未验证**：Debian 11/12/13 未做真实系统测试（测试环境无法访问 Debian 软件源），仅覆盖其 os-release 识别以及同范围的 Python / nftables 版本；IPv6 转发未实测（测试内核无 IPv6）；systemd 用替身程序模拟，未做真实重启；未在 DMIT 等实机 + 真实 3X-UI + 真实客户端上复测。

### V1

- Python 语法检查与 31 项 mock/SQLite 自动化测试通过（新增跳跃范围 + 监听端口双 UFW 规则的安装/更新/恢复/状态检查/旧版本升级/失败回滚用例）。
- 在隔离的 Ubuntu 24.04 容器中，用真实 `ss`/`nft`/`ufw`/`apt-get` 命令（非 mock）端到端跑通了完整的
  `install → status → update ×3（确认幂等、规则不重复）→ restore` 流程，并单独确认：
  - `apt-get install nftables` 在全新安装时不会自动启用/启动 `nftables.service`；
  - `ufw`/`nft -a list ruleset` 的真实输出格式与代码里的字符串匹配、正则解析完全一致；
  - 存在其他 DNAT/redirect 规则时能正确检测并拒绝安装，自身规则不会被误判为冲突。
- **已在 DMIT Ubuntu 24.04 实机验证**（修复前的基础功能）：3X-UI Hysteria2 入站、Shadowrocket IPv4 端口跳跃连接、修改 Hop Ports 后执行 `update`、重复 `update` 幂等，以及 VPS 重启后服务与客户端连通性。**尚未完成公网 IPv6 双栈连通性验证。** `status PASS` 仅代表本机配置检查通过。
- **本次新增的"监听端口 UFW 放行"修复尚未在 DMIT 实机复测**：目前只验证了本地 mock 测试中实际执行的 `ufw`/`nft` 命令字符串和状态文件逻辑，没有在真实 DMIT + 3X-UI + UFW/nftables 环境中重新跑过 install → status → update → restore 全流程，也没有用真实客户端确认监听端口位于跳跃范围之外时的连接恢复。
- 跨 nftables/UFW/systemd 的自动回滚实现了尽力清理；断电、SIGKILL、外部系统同时修改规则等情况下，不能保证严格事务原子性。
- 恢复不卸载 nftables 软件包，不修改 3X-UI 数据库。

