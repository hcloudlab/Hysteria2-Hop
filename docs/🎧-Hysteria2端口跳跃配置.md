# 🎧 3X-UI Hysteria2 端口跳跃配置教程

适用：Debian 11/12/13、Ubuntu 20.04/22.04/24.04/26.04、3X-UI、Hysteria2。
端口跳跃需要三件事同时生效，少一件客户端就连不上：

1. 一段"跳跃端口范围"（比如 `20000-30000`）的 UDP 流量，被转发到 Hysteria2 真正监听的那个端口（比如 `443`）。
2. 服务器自己的防火墙（UFW）要放行这段跳跃范围的 UDP。
3. 服务器自己的防火墙（UFW）**也要放行 Hysteria2 真正监听的那个端口**的 UDP——这条很容易被忽略：很多人只记得开跳跃范围，忘了开监听端口本身，结果客户端完全连不上，排查半天。

`hy2hop.py` 会自动把这三件事都配置好，并且在 `status` 时三项都检查，你只需要在 3X-UI 里填好配置，剩下交给脚本。

## 一、3X-UI 入站配置

打开 **3X-UI → 入站列表 → 添加/修改 Hysteria2 入站**。

### 基础配置

![图 1：Hysteria2 基础配置，监听端口不能位于跳跃端口范围内](images/hy2-hop-step-1.png)


**注意：监听端口必须位于 Hop Ports 范围之外。** 例如监听端口 `24447` 与跳跃范围 `20000-50000` 重叠，脚本会拒绝安装；改为 `14447` 或其他不在该范围内的未占用端口即可。端口 `443` 只是示例，实际端口以你的 3X-UI 入站为准。


| 配置项 | 本次实测值 |
| --- | --- |
| 协议 | Hysteria |
| 监听地址 | 留空（监听所有 IP） |
| 监听端口 | `443`（示例；**不能落在跳跃端口范围内**） |

### 传输配置

**图 2：传输配置（上半部分）**

![图 2：Hysteria2 传输配置与 Salamander 混淆设置](images/hy2-hop-step-2.png)

**图 3：传输配置（UDP Hop 与 QUIC 参数）**

![图 3：Hysteria2 UDP Hop 端口范围及跳跃间隔](images/hy2-hop-step-3.png)


传输页面分为上下两部分：图 2 主要是 **UDP Masks / Salamander、QUIC Params、拥塞控制**；图 3 主要是 **UDP Hop、Hop Ports、Hop Interval** 及其余 QUIC 参数。按面板向下滚动即可找到，不是两个不同的配置页面。

**UDP Mask Password 属于 Salamander 混淆密码，不等于 Hysteria2 用户的认证密码。** 使用混淆时，服务端与客户端必须填写同一混淆密码；不要把示例截图中的密码直接用于自己的节点。


| 配置项 | 本次实测值 |
| --- | --- |
| UDP 空闲超时 | 60 秒 |
| 伪装 | 开启 |
| 伪装类型 | default (404 page) |
| Sockopt | 关闭 |
| UDP Masks | 添加 UDP Mask 1 |
| UDP Mask Type | Salamander (Hysteria2) |
| Mode | Salamander |
| Salamander Password | 自行生成，客户端保持一致 |
| QUIC Params | 开启 |
| Congestion | BBR |
| BBR Profile | standard |
| Debug | 关闭 |
| UDP Hop | **开启** |
| Hop Ports | **`20000-30000`** |
| Hop Interval | **30 秒** |
| Max Idle Timeout | 30 秒 |
| Keep Alive Period | 10 秒 |
| Disable Path MTU Discovery | 开启（本次实测设置） |
| Disable Chrome Parrot | 关闭 |
| Disable GSO | 关闭 |
| Disable Stateless Reset | 关闭 |
| Max Incoming Streams | 1024 |
| Init Stream Window | 8388608 |
| Max Stream Window | 8388608 |
| Init Conn Window | 20971520 |
| Max Conn Window | 20971520 |

**配置重点：**

- **UDP Hop：开启**；**Hop Ports：`20000-30000`**（示例）；**Hop Interval：30 秒**。
- Hop Ports 可以调整，但必须与监听端口互不重叠。比如 Hop Ports 为 `20000-30000` 时，监听端口就不能使用 `24447`。
- 客户端的端口范围需要与面板的 Hop Ports 一致；修改范围后需要执行脚本 `update`，再同步更新客户端。
- Disable Path MTU Discovery 的开启状态仅为本次实测设置，不是所有网络环境的强制要求；其他开关先按图示设置，不必额外调整。

### 安全配置

![图 4：Hysteria2 安全配置，SNI 与面板证书选择](Dark%20UI%20Security%20Configuration%20Panel.png)


**SNI 可以填写域名，也可以填写 VPS 公网 IP**，但前提是所使用的 TLS 证书能够匹配这个域名或 IP；不是任意填写一个地址都可以。

**数字证书 1：建议点击「从面板设置证书」**，选择已在 3X-UI 面板中配置好的证书，让面板自动填入公钥和私钥路径。截图中的 `/root/cert/ip/` 只是示例路径，不要直接照抄。


| 配置项 | 本次实测值 |
| --- | --- |
| 安全 | TLS |
| SNI | **域名或 VPS 公网 IP**（必须与证书匹配） |
| TLS 最小 / 最大版本 | 1.2 / 1.3 |
| ALPN | `h3` |
| 拒绝未知 SNI | 关闭 |
| 禁用系统根 | 关闭 |
| 会话恢复 | 关闭 |
| 数字证书 1 | 点击 **从面板设置证书** 选择现有证书（自动填入文件路径） |

本次实测证书路径（**仅示例，按实际证书修改**）：

```text
证书：/root/cert/ip/fullchain.pem
私钥：/root/cert/ip/privkey.pem
```

**特别提醒：** 面板和客户端的 SNI、证书校验设置要一致。如果使用 IP 证书，证书中必须包含对应 IP 地址；如果使用域名证书，证书必须覆盖所填域名。

其他未列出的选项保持默认。配置完成后点击 **保存更改**。

## 二、安装 Hysteria2-Hop

SSH 登录 VPS，执行：

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/hcloudlab/Hysteria2-Hop/main/bootstrap.sh)"
```

本地已经有完整仓库的话，也可以在仓库目录里直接：

```bash
sudo bash install.sh
```

脚本只读 3X-UI 数据库，根据入站的监听端口和 Hop Ports 配置 nftables UDP 转发、UFW 规则和 systemd 启动恢复，具体会自动做这几件事：

- 读取 3X-UI 数据库里 Hysteria2 的监听端口和 Hop Ports（只读，不会改 3X-UI 的数据库）。
- 如果没装 nftables，自动用 `apt-get` 装上（Ubuntu 20.04 需先启用 universe 软件源）。
- 生成跳跃端口范围 → 监听端口的 NAT 转发规则。
- **如果 UFW 是开着的**：自动放行跳跃范围和监听端口这两条 UDP 规则，已经存在的规则不会重复添加。
- **如果 UFW 没开**：脚本不会帮你打开 UFW，也不会因为这个报错——它假定你清楚自己在做什么。
- 设置一个 systemd 服务，保证服务器重启后规则自动恢复。

**云厂商安全组（Security Group）需要另行放行监听端口和所选跳跃端口范围的 UDP** —— 安全组是云厂商控制台网页上配置的网络层规则，和服务器本地的 UFW 是两件不同的东西，脚本只管 UFW，安全组必须自己去控制台（比如 DMIT 的管理面板）配置。


## 三、脚本常用命令

**查看配置状态：**

```bash
sudo /usr/local/sbin/hcloudlab-hy2hop status
```

会检查 3X-UI 配置是否变化、Hysteria2 是否真的在监听、nftables 转发规则、systemd 服务，以及 **UFW 开着时跳跃范围和监听端口这两条放行规则是否都在**——少一条都算 `FAIL`。显示 `STATUS: PASS` 仅代表本机规则检查通过，仍需客户端联网验证。

**在 3X-UI 修改监听端口或 Hop Ports 并保存后更新规则：**

```bash
sudo /usr/local/sbin/hcloudlab-hy2hop update
```

脚本会自动识别新配置，把新端口/新范围需要的 UFW 规则和 NAT 转发加上，同时把脚本自己之前加的、现在不再需要的旧规则清理掉。**你手动加的、脚本安装前就已经存在的 UFW 规则不会被动。** 多次执行 `update` 不会产生重复规则。

如果你用的是旧版本脚本装的（当时还没有监听端口的 UFW 规则），直接执行 `update` 就行，脚本会自动把缺的那条监听端口规则补上，不需要先 `restore` 再重装。

有多个符合条件的入站时，指定实际入站 ID（`5` 为示例）：

```bash
sudo /usr/local/sbin/hcloudlab-hy2hop update --inbound-id 5
```

更新后记得同步修改客户端端口范围。

**查看 NAT / UFW：**

```bash
sudo nft list table ip hcloudlab_hy2hop
sudo ufw status
```

**查看开机自启与服务运行状态：**

```bash
systemctl is-enabled hcloudlab-hy2hop.service
systemctl is-active hcloudlab-hy2hop.service
```

正常启动后分别显示 `enabled`、`active`。

**查看支持的命令：**

```bash
sudo /usr/local/sbin/hcloudlab-hy2hop --help
```

**撤销脚本管理的配置：**

```bash
sudo /usr/local/sbin/hcloudlab-hy2hop restore
```

只会清理脚本自己加的东西：它创建的 nftables 规则、它加的那两条 UFW 规则（跳跃范围 + 监听端口）、它注册的 systemd 服务。装之前就有的 UFW 规则、3X-UI 的数据库、nftables 软件包都不会动。执行 restore 前确认不再需要端口跳跃功能。

## 五、常见问题

**改完配置客户端连不上了？**
先执行 `status`，看报错具体指哪一条规则缺失。常见原因就是监听端口没有被 UFW 放行，现在脚本会自动处理；如果还报错说明环境比较特殊，带着 `status` 的完整输出去反馈。

**UFW 和云厂商安全组是不是一个东西？**
不是。UFW 是跑在服务器系统里的防火墙，`ufw status` 能看到；安全组是云厂商在控制台网页上配置的网络层规则，和服务器内部无关。两边都要放行对应端口，缺一个都连不上。脚本只负责 UFW，安全组必须你自己去控制台配。

**脚本会不会把我 UFW 关掉或打开？**
不会。脚本只在 UFW **已经是开着**的情况下帮你加/删它自己管理的那两条规则；UFW 本身开不开，一直由你自己决定。

[返回 README](../README.md)
