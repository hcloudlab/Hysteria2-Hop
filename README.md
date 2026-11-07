# HCloudLab · 3X-UI Hysteria2 端口跳跃 — Ubuntu 24.04 / Debian 12、13

## 适用范围

- 3X-UI 面板中的 Hysteria2 入站：数据库 `protocol=hysteria`
- 在面板填写 **Hop Ports**，例如 `20000-30000`；脚本只读数据库，不修改 x-ui.db。
- 支持 Ubuntu 24.04、Debian 12/13 + systemd；IPv4，存在全局 IPv6 地址时也创建 IPv6 规则。
- UFW 开启时自动添加跳跃范围 **和 Hysteria2 实际监听端口** 的 UDP 放行规则；nftables 未安装时通过系统 apt 软件源自动安装。
  - 这里说的是服务器自身的 UFW，不是 DMIT/其他云厂商控制台里的"安全组"。安全组仍需自己在面板放行跳跃范围和监听端口。
- 本版本不保证与 Docker 或其他自定义 NAT 规则共存；检测到其他 DNAT/redirect 将安全拒绝安装。

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

1. 首次安装：检查是否自动安装 nftables，读取 Hop Ports 并生成 IPv4/IPv6 映射，确认 UFW 同时放行了跳跃范围和实际监听端口（`ufw status numbered`）。
2. `sudo /usr/local/sbin/hcloudlab-hy2hop status`：检查当前配置；缺少监听端口或跳跃范围的任一条 UFW 规则都应报告 `STATUS: FAIL`。
3. 更新客户端订阅，真实连接并确认跳跃端口的 UDP 流量计数增加。
4. 连续执行 `update` 3 次，确保没有重复规则。
5. 重启 VPS，再执行 `status`，验证客户端仍可连接。
6. 在 3X-UI 修改监听端口和/或 Hop Ports，再执行 `update`，检查旧端口/旧范围的 UFW 规则消失、新端口/新范围的规则生效。
7. 执行 `restore`，确认原 443/UDP 节点可用、其他防火墙规则不变（包括安装前已存在的 UFW 规则）。
8. 出现错误立即停止并提供完整终端输出；不要手工执行 `nft flush ruleset` 或关闭 UFW。

## 内部验证范围

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


## Debian 适配状态

- Debian 12（Bookworm）和 Debian 13（Trixie）已纳入系统版本检测；保持与 Ubuntu 24.04 相同的安装命令和管理接口。
- Debian 默认可能没有安装或启用 UFW：脚本不会自行安装或启用 UFW。若主机使用其他防火墙策略，必须由管理员另外放行监听端口及跳跃端口范围。
- 当前 Debian 支持属于待验收适配：必须在干净的 Debian 12/13 + 3X-UI 环境执行 install → status → update → restore、重启恢复和客户端 UDP 跳跃测试后，才能宣称实机验证通过。
- 不支持的发行版或版本继续拒绝运行；不修改 3X-UI 数据库，不清空全局 nftables 规则。
