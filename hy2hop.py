#!/usr/bin/env python3
"""HCloudLab HY2 Hop: Debian/Ubuntu, read-only 3X-UI, dedicated nft NAT table."""
import sys

if sys.version_info < (3, 8):
    sys.stderr.write('ERROR: 需要 Python 3.8 或更高版本\n')
    sys.exit(1)

import argparse
import contextlib
import fcntl
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

VERSION = '2.0.0'
DB = Path('/etc/x-ui/x-ui.db')
BASE = Path('/var/lib/hcloudlab-hy2hop')
STATE = BASE / 'state.json'
SELF = Path('/usr/local/sbin/hcloudlab-hy2hop')
UNIT = Path('/etc/systemd/system/hcloudlab-hy2hop.service')
SERVICE = UNIT.name
TABLE = 'hcloudlab_hy2hop'
# Directly under /run (root:root 0755), not /run/lock (world-writable,
# 1777 sticky): /run/lock lets any local unprivileged user pre-create a
# file at this predictable name and hold flock() on it indefinitely,
# permanently denial-of-servicing every future install/update/status/
# restore run (including root's) - only root can place a file in /run.
LOCK = Path('/run/hcloudlab-hy2hop.lock')

# Tested release matrix. Other Debian/Ubuntu releases need HY2HOP_ALLOW_UNTESTED=1.
SUPPORTED = {
    'debian': ('11', '12', '13'),
    'ubuntu': ('20.04', '22.04', '24.04', '26.04'),
}

# Debian's `su` (without "-") drops /usr/sbin from PATH, which hides nft/ufw.
os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:' + os.environ.get('PATH', '')
# ufw/ss/apt output is translated under zh_CN etc.; parsing needs the C locale.
CHILD_ENV = dict(os.environ, LC_ALL='C', LANG='C', LANGUAGE='C', DEBIAN_FRONTEND='noninteractive')
NAT_WORDS = re.compile(r'\b(dnat|redirect|tproxy)\b', re.I)


def run(cmd, check=True, input_text=None):
    p = subprocess.run(cmd, input=input_text, text=True, capture_output=True, env=CHILD_ENV)
    if check and p.returncode:
        raise RuntimeError(f"{' '.join(cmd)}: {p.stderr.strip() or p.stdout.strip()}")
    return p


def warn(msg):
    print('WARN: ' + msg, file=sys.stderr)


# ---------------------------------------------------------------- environment

def os_release(path=Path('/etc/os-release')):
    data = {}
    for line in path.read_text().splitlines():
        key, sep, value = line.partition('=')
        if sep and key.strip() and not key.startswith('#'):
            data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def check_os(info):
    """Return a printable OS name; raise on unsupported systems."""
    ident = info.get('ID', '')
    version = info.get('VERSION_ID', '')
    name = info.get('PRETTY_NAME') or f'{ident} {version}'
    if version in SUPPORTED.get(ident, ()):
        return name
    family = {ident} | set(info.get('ID_LIKE', '').split())
    if family & set(SUPPORTED) and os.environ.get('HY2HOP_ALLOW_UNTESTED') == '1':
        warn(f'{name} 不在测试列表中，按 HY2HOP_ALLOW_UNTESTED=1 继续')
        return name
    supported = ', '.join(f'{k.capitalize()} {"/".join(v)}' for k, v in SUPPORTED.items())
    raise RuntimeError(f'不支持的系统 {name}。支持：{supported}'
                       '（其他 Debian/Ubuntu 衍生版可设置 HY2HOP_ALLOW_UNTESTED=1 自行承担风险）')


def prerequisites(check_release=True):
    if os.geteuid():
        raise RuntimeError('需要 root 权限')
    if not Path('/run/systemd/system').exists():
        raise RuntimeError('需要 systemd')
    if check_release:
        check_os(os_release())
    for command in ('systemctl', 'ss', 'ip', 'apt-get'):
        if not shutil.which(command):
            raise RuntimeError(f'缺少系统命令 {command}')


def container_type():
    p = run(['systemd-detect-virt', '-c'], False) if shutil.which('systemd-detect-virt') else None
    kind = p.stdout.strip() if p and p.returncode == 0 else ''
    return '' if kind in ('', 'none') else kind


# ---------------------------------------------------------------- 3X-UI

def parse_inbound(ident, port, raw, listen):
    """Return (start, end, port) or raise ValueError with a readable reason."""
    try:
        data = json.loads(raw or '{}')
        hop = data.get('finalmask', {}).get('quicParams', {}).get('udpHop', {}).get('ports')
    except (TypeError, ValueError, AttributeError):
        raise ValueError('stream_settings 无效') from None
    if not hop:
        return None
    m = re.fullmatch(r'\s*(\d+)\s*-\s*(\d+)\s*', str(hop))
    if not m:
        raise ValueError(f'Hop Ports 格式错误（只支持 起始-结束，例如 20000-30000），当前为 {hop!r}')
    a, b = map(int, m.groups())
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValueError('监听端口无效') from None
    if not (1 <= a <= b <= 65535 and 1 <= port <= 65535):
        raise ValueError('端口超出范围')
    if a <= port <= b:
        raise ValueError('Hop 范围包含监听端口')
    if listen not in (None, '', '::', '0.0.0.0'):
        raise ValueError('暂不支持绑定指定 IP')
    return a, b, port


def inbounds():
    """Return (valid configs, {id: reason}) for enabled Hysteria2 inbounds with Hop Ports."""
    if not DB.is_file():
        raise RuntimeError(f'未找到 3X-UI 数据库 {DB}')
    with contextlib.closing(sqlite3.connect(f'file:{DB}?mode=ro', uri=True, timeout=10)) as con:
        rows = con.execute("SELECT id,remark,port,enable,stream_settings,listen FROM inbounds "
                           "WHERE protocol='hysteria' ORDER BY id").fetchall()
    valid, invalid = [], {}
    for ident, remark, port, enabled, raw, listen in rows:
        if not enabled:
            continue
        try:
            parsed = parse_inbound(ident, port, raw, listen)
        except ValueError as e:
            invalid[ident] = f'入站 {ident}: {e}'
            continue
        if parsed:
            a, b, port = parsed
            valid.append(dict(id=ident, remark=remark or '', port=port, start=a, end=b))
    return valid, invalid


def choose(ident=None):
    options, invalid = inbounds()
    if ident is not None:
        if ident in invalid:
            raise RuntimeError(invalid[ident])
        match = next((x for x in options if x['id'] == ident), None)
        if not match:
            raise RuntimeError(f'未找到有效的 Hysteria2 UDP Hop 入站 ID={ident}')
        return match
    for reason in invalid.values():
        warn(reason + '（已跳过）')
    if not options:
        if invalid:
            raise RuntimeError('没有可用的 Hysteria2 Hop 入站：' + '; '.join(invalid.values()))
        raise RuntimeError('未找到启用且填写 Hop Ports 的 Hysteria2 入站，请先在 3X-UI 配置')
    if len(options) == 1:
        return options[0]
    if not sys.stdin.isatty():
        raise RuntimeError('多个入站时，非交互模式必须传 --inbound-id')
    for i, c in enumerate(options, 1):
        print(f"{i}. ID={c['id']} {c['remark']} UDP:{c['port']} Hop:{c['start']}-{c['end']}")
    try:
        i = int(input('请选择入站编号: '))
    except ValueError:
        raise RuntimeError('无效选择') from None
    if not 1 <= i <= len(options):
        raise RuntimeError('无效选择')
    return options[i - 1]


# ---------------------------------------------------------------- packages

def apt_install(packages):
    cmd = ['apt-get', '-y', '-o', 'DPkg::Lock::Timeout=300', '--no-install-recommends', 'install'] + packages
    if run(cmd, False).returncode == 0:
        return
    # Package lists may be missing (fresh image) or stale; apt-get update can also
    # race with unattended-upgrades on first boot, so retry a few times.
    for attempt in range(3):
        if run(['apt-get', '-o', 'DPkg::Lock::Timeout=300', 'update'], False).returncode == 0:
            break
        time.sleep(10)
    run(cmd)


def dependency():
    if shutil.which('nft'):
        return
    was_active = run(['systemctl', 'is-active', 'nftables.service'], False).stdout.strip() == 'active'
    print('自动安装 nftables（不会启用系统 nftables.service）')
    try:
        apt_install(['nftables'])
    except RuntimeError as e:
        hint = ''
        if 'installation candidate' in str(e) or 'Unable to locate' in str(e):
            # Ubuntu 20.04 ships nftables in "universe", which some minimal images disable.
            hint = '（Ubuntu 20.04 请先启用 universe 软件源：add-apt-repository universe 或在 sources.list 加入 universe）'
        raise RuntimeError(f'nftables 安装失败{hint}: {e}') from None
    if not shutil.which('nft'):
        raise RuntimeError('nftables 安装失败')
    if not was_active and run(['systemctl', 'is-active', 'nftables.service'], False).stdout.strip() == 'active':
        warn('nftables.service 在安装后被启动，它会加载 /etc/nftables.conf；如 UFW/Docker 规则异常请执行 ufw reload 或重启 Docker')


# ---------------------------------------------------------------- nftables

def ipv6_available():
    return Path('/proc/net/if_inet6').exists()


def owned_tables():
    return [fam for fam in ('ip', 'ip6') if run(['nft', 'list', 'table', fam, TABLE], False).returncode == 0]


def rules(cfg, fams, present=()):
    lines = [f'delete table {f} {TABLE}' for f in present]
    for f in fams:
        # fib daddr type local: only redirect packets addressed to this host, never
        # forwarded traffic (Docker containers, WireGuard clients...) that happens to
        # target a remote UDP port inside the hop range. priority -100 == dstnat,
        # numeric for nftables < 0.9.1 compatibility.
        lines += [f'add table {f} {TABLE}',
                  f'add chain {f} {TABLE} prerouting {{ type nat hook prerouting priority -100; policy accept; }}',
                  f'add rule {f} {TABLE} prerouting fib daddr type local udp dport {cfg["start"]}-{cfg["end"]} '
                  f'counter redirect to :{cfg["port"]}']
    return '\n'.join(lines) + '\n'


def families(cfg):
    fam = ['ip']
    if ipv6_available():
        # Dry-run in the kernel: some VPS kernels/containers lack IPv6 NAT.
        if run(['nft', '-c', '-f', '-'], False, rules(cfg, ['ip6'])).returncode == 0:
            fam.append('ip6')
        else:
            warn('内核不支持 IPv6 NAT，仅创建 IPv4 规则')
    return fam


def apply(cfg, fams):
    # nft -f is a single kernel transaction, including delete + create.
    try:
        run(['nft', '-f', '-'], input_text=rules(cfg, fams, owned_tables()))
    except RuntimeError as e:
        kind = container_type()
        hint = f'（当前为 {kind} 容器，宿主机可能不允许 nftables NAT，请换 KVM VPS）' if kind else ''
        raise RuntimeError(f'nftables 规则写入失败{hint}: {e}') from None


def delete_tables():
    present = owned_tables()
    if present:
        run(['nft', '-f', '-'], input_text=rules({}, [], present))


# ---------------------------------------------------------------- port checks

def udp_sockets():
    """Return [(local_addr, port, raw_line)] for unconnected UDP sockets."""
    p = run(['ss', '-H', '-lunp'], False)
    if p.returncode:
        p = run(['ss', '-H', '-lun'], False)
    if p.returncode:
        raise RuntimeError('无法检查 UDP 监听')
    result = []
    for line in p.stdout.splitlines():
        t = line.split()
        if t and t[0] in ('udp', 'udp6'):
            t = t[1:]
        if len(t) < 4:
            continue
        m = re.fullmatch(r'(.*):(\d+)', t[3])
        if m:
            result.append((m.group(1), int(m.group(2)), line.strip()))
    return result


def is_loopback(addr):
    addr = addr.strip('[]').split('%')[0]
    return addr.startswith('127.') or addr == '::1'


def listener(cfg):
    hits = [a for a, port, _ in udp_sockets() if port == cfg['port']]
    if not hits:
        raise RuntimeError(f'UDP {cfg["port"]} 未监听（3X-UI/Xray 是否在运行？）')
    if all(is_loopback(a) for a in hits):
        raise RuntimeError(f'UDP {cfg["port"]} 只监听在回环地址')


def ephemeral_range():
    try:
        lo, hi = map(int, Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split())
        return lo, hi
    except (OSError, ValueError):
        return 32768, 60999


def port_spec_overlaps(text, start, end):
    """True/False for an nft/iptables port expression, None if it can't be parsed."""
    text = text.strip().strip('{}').replace(':', '-')
    found = False
    for part in re.split(r'[,\s]+', text):
        if not part:
            continue
        m = re.fullmatch(r'(\d+)(?:-(\d+))?', part)
        if not m:
            return None
        a = int(m.group(1))
        b = int(m.group(2) or a)
        found = True
        if a <= end and b >= start:
            return True
    return False if found else None


def nat_rule_conflicts(rule, start, end):
    """Decide whether one NAT/TPROXY rule line can capture UDP in [start, end]."""
    low = rule.lower()
    udp_ports = re.findall(r'\b(?:udp|th) dport (\{[^}]*\}|\S+)', low)
    udp_ports += re.findall(r'--dports? (\S+)', low) if re.search(r'-p udp\b', low) else []
    if re.search(r'dport !=|! --dports?\b', low):
        return True  # negated port match captures almost everything
    if udp_ports:
        verdicts = [port_spec_overlaps(x, start, end) for x in udp_ports]
        return any(v is not False for v in verdicts)
    if re.search(r'\btcp\b', low) and not re.search(r'\budp\b|\bth\b', low):
        return False  # TCP-only port forward (typical Docker -p 8080:80)
    return True  # generic redirect without a port filter


def legacy_nat_rules():
    """Rules in iptables-legacy nat/mangle tables (invisible to `nft list ruleset`).

    Read only when the kernel already has those legacy tables loaded, so we never
    autoload iptable_nat on nft-only systems."""
    out = []
    for names, tool in (('/proc/net/ip_tables_names', 'iptables-legacy-save'),
                        ('/proc/net/ip6_tables_names', 'ip6tables-legacy-save')):
        try:
            loaded = Path(names).read_text().split()
        except OSError:
            continue
        exe = shutil.which(tool)
        if not exe:
            continue
        for table in ('nat', 'mangle'):
            if table in loaded:
                p = run([exe, '-t', table], False)
                if p.returncode == 0:
                    out += [l for l in p.stdout.splitlines() if l.startswith('-A ')]
    return out


def conflicts(cfg):
    lo, hi = ephemeral_range()
    for addr, port, line in udp_sockets():
        if cfg['start'] <= port <= cfg['end']:
            if lo <= port <= hi:
                # Unconnected outbound UDP sockets (DNS/QUIC clients) get random
                # ephemeral ports; they show up in `ss -l` but are not services.
                warn(f'跳跃范围内有临时端口 UDP 套接字，忽略: {line}')
                continue
            raise RuntimeError(f'跳跃端口与 UDP 监听冲突: {line}')
    p = run(['nft', 'list', 'ruleset'], False)
    if p.returncode:
        raise RuntimeError('无法读取现有 nftables 规则')
    other = re.sub(r'(?ms)^table (?:ip|ip6) ' + TABLE + r' \{.*?^\}\n?', '', p.stdout)
    candidates = [l.strip() for l in other.splitlines() if NAT_WORDS.search(l)]
    candidates += [l for l in legacy_nat_rules() if re.search(r'-j (DNAT|REDIRECT|TPROXY)\b', l)]
    for rule in candidates:
        if nat_rule_conflicts(rule, cfg['start'], cfg['end']):
            raise RuntimeError('检测到可能覆盖跳跃范围的其他 NAT/TPROXY 规则，为避免影响现有业务已停止'
                               f'（需要人工审查）: {rule}')


def check_ranges(cfg):
    lo, hi = ephemeral_range()
    if cfg['start'] <= hi and cfg['end'] >= lo:
        warn(f'跳跃范围与系统临时端口 {lo}-{hi} 重叠，可正常使用；如追求稳定建议改为不重叠的范围（例如 20000-30000）')


# ---------------------------------------------------------------- firewall

def specs(cfg):
    """UFW specs this tool must own for a config: hop range, then listen port."""
    return f'{cfg["start"]}:{cfg["end"]}/udp', f'{cfg["port"]}/udp'


def ufw_active():
    if not shutil.which('ufw'):
        return False
    p = run(['ufw', 'status'], False)
    if p.returncode:
        raise RuntimeError('无法检查 UFW')
    return 'Status: active' in p.stdout


def ufw_has(spec):
    p = run(['ufw', 'show', 'added'], False)
    if p.returncode:
        raise RuntimeError('无法读取 UFW 规则')
    return any(line.strip() == 'ufw allow ' + spec for line in p.stdout.splitlines())


def ufw_add(spec):
    if not ufw_active() or ufw_has(spec):
        return False
    run(['ufw', 'allow', spec])
    return True


def ufw_delete(spec):
    if ufw_active() and ufw_has(spec):
        run(['ufw', '--force', 'delete', 'allow', spec])


def other_firewall_hint(cfg):
    if ufw_active():
        return
    if shutil.which('firewall-cmd') and run(['firewall-cmd', '--state'], False).returncode == 0:
        warn(f'检测到 firewalld，本脚本不修改它，请自行放行 UDP {cfg["port"]} 与 {cfg["start"]}-{cfg["end"]}')


# ---------------------------------------------------------------- state & service

def read_state():
    return json.loads(STATE.read_text()) if STATE.exists() else None


def write_state(state):
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    state = dict(state, version=VERSION)
    fd, name = tempfile.mkstemp(prefix='.state-', dir=BASE)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(state, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, 0o600)
        os.replace(name, STATE)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def unit_content():
    return ('[Unit]\n'
            'Description=HCloudLab Hysteria2 UDP Hop\n'
            'After=network-online.target nftables.service ufw.service firewalld.service x-ui.service\n'
            'Wants=network-online.target\n'
            # nftables.service (if the admin uses it) runs `flush ruleset` on
            # start/restart/reload; follow it so the hop table comes back:
            # stop/restart via PartOf, reload via ReloadPropagatedFrom, and a
            # later start via WantedBy=nftables.service below.
            'PartOf=nftables.service\n'
            'ReloadPropagatedFrom=nftables.service\n'
            '[Service]\n'
            'Type=oneshot\n'
            'RemainAfterExit=yes\n'
            'Environment=PYTHONIOENCODING=utf-8\n'
            f'ExecStart={SELF} reload\n'
            f'ExecReload={SELF} reload\n'
            f'ExecStop={SELF} stop-rules\n'
            '[Install]\n'
            'WantedBy=multi-user.target nftables.service\n')


def setup_service():
    """Install/refresh the CLI copy and unit; idempotent, so update() also upgrades old installs."""
    source = Path(__file__).resolve()
    if source != SELF.resolve():
        if not SELF.exists() or SELF.read_bytes() != source.read_bytes():
            tmp = SELF.with_name('.' + SELF.name + '.new')
            shutil.copyfile(source, tmp)
            tmp.chmod(0o755)
            os.replace(tmp, SELF)
    SELF.chmod(0o755)
    content = unit_content()
    if not UNIT.exists() or UNIT.read_text() != content:
        UNIT.write_text(content)
        run(['systemctl', 'daemon-reload'])
    if run(['systemctl', 'is-enabled', SERVICE], False).stdout.strip() != 'enabled':
        run(['systemctl', 'enable', SERVICE])


def clean_service():
    run(['systemctl', 'disable', SERVICE], False)
    UNIT.unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])


# ---------------------------------------------------------------- actions

def install(ident=None):
    if STATE.exists() or UNIT.exists():
        raise RuntimeError('已有安装，请选择更新或状态检查')
    cfg = choose(ident)
    listener(cfg)
    dependency()
    if owned_tables():
        raise RuntimeError('发现没有状态记录的专属 nft 表，拒绝覆盖')
    conflicts(cfg)
    check_ranges(cfg)
    fam = families(cfg)
    hop_spec, port_spec = specs(cfg)
    added = []
    try:
        for spec in (hop_spec, port_spec):
            if ufw_add(spec):
                added.append(spec)
        apply(cfg, fam)
        write_state(dict(config=cfg, families=fam, ufw_owned=added))
        setup_service()
    except BaseException:
        # Best-effort rollback; preserve state if cleanup fails for subsequent recovery.
        errors = []
        for operation in (delete_tables, *[(lambda s=s: ufw_delete(s)) for s in added], clean_service):
            try:
                operation()
            except Exception as e:
                errors.append(str(e))
        if not errors:
            STATE.unlink(missing_ok=True)
        else:
            print('回滚不完整，请保留状态文件并检查: ' + '; '.join(errors), file=sys.stderr)
        raise
    other_firewall_hint(cfg)
    print(f'安装完成: 入站 {cfg["id"]} UDP {cfg["start"]}-{cfg["end"]} → {cfg["port"]}（{"/".join(fam)}）')
    print('请更新客户端订阅并实测；云厂商安全组需自行允许跳跃范围及监听端口 UDP。')


def update(ident=None):
    old = read_state()
    if not old:
        return install(ident)
    cfg = choose(ident if ident is not None else old['config']['id'])
    listener(cfg)
    dependency()
    conflicts(cfg)
    check_ranges(cfg)
    fam = families(cfg)
    new_hop, new_port = specs(cfg)
    old_owned = list(old.get('ufw_owned', []))
    # Old versions created a rule without `fib daddr type local`: rebuild once.
    unchanged = cfg == old['config'] and fam == old['families'] and old.get('version') == VERSION
    # Specs this tool owned before that neither new spec needs any more
    # (covers both a changed range/port and pre-fix state missing the port spec).
    stale = [s for s in old_owned if s not in (new_hop, new_port)]
    added = []
    try:
        for spec in (new_hop, new_port):
            if spec not in old_owned and ufw_add(spec):
                added.append(spec)
    except BaseException:
        for spec in added:
            ufw_delete(spec)
        raise
    if unchanged and not added and not stale:
        setup_service()
        print('配置无变化')
        return
    owned = list(dict.fromkeys([s for s in old_owned if s in (new_hop, new_port)] + added))
    replaced = False
    try:
        if not unchanged:
            apply(cfg, fam)
            replaced = True
        # Keep stale specs in state until their deletion below completes.
        transitional = dict(old, config=cfg, families=fam, ufw_owned=list(dict.fromkeys(owned + stale)))
        write_state(transitional)
    except BaseException:
        if replaced:
            try:
                apply(old['config'], old['families'])
            except Exception as e:
                print(f'CRITICAL: nft 回滚失败: {e}', file=sys.stderr)
                raise
        for spec in added:
            ufw_delete(spec)
        write_state(old)
        raise
    for spec in stale:
        # If deletion fails, state still records stale ownership for safe retry.
        ufw_delete(spec)
    if stale:
        transitional['ufw_owned'] = owned
        write_state(transitional)
    setup_service()
    other_firewall_hint(cfg)
    print(f'更新完成: 入站 {cfg["id"]} UDP {cfg["start"]}-{cfg["end"]} → {cfg["port"]}（{"/".join(fam)}）')


def reload_rules():
    state = read_state()
    if not state:
        raise RuntimeError('未安装')
    apply(state['config'], state['families'])


def restore():
    state = read_state()
    if not state:
        if UNIT.exists() or (shutil.which('nft') and owned_tables()):
            raise RuntimeError('存在无状态的工具资源，拒绝盲目删除')
        print('无需恢复')
        return
    # Disable first; do not call systemctl stop (ExecStop can race with cleanup).
    run(['systemctl', 'disable', SERVICE], False)
    delete_tables()
    for spec in state.get('ufw_owned', []):
        ufw_delete(spec)
    clean_service()
    STATE.unlink()
    with contextlib.suppress(OSError):
        BASE.rmdir()
    SELF.unlink(missing_ok=True)
    print('恢复完成：只清理本工具规则和服务；3X-UI 与 nftables 软件包保留')


def counters(fam):
    p = run(['nft', 'list', 'chain', fam, TABLE, 'prerouting'], False)
    m = re.search(r'packets (\d+) bytes (\d+)', p.stdout)
    return m.groups() if m else None


def status():
    state = read_state()
    if not state:
        print('尚未安装')
        return 1
    cfg = state['config']
    errors = []
    try:
        valid, invalid = inbounds()
        current = next((x for x in valid if x['id'] == cfg['id']), None)
        if cfg['id'] in invalid:
            errors.append(invalid[cfg['id']])
        elif current != cfg:
            errors.append('3X-UI 入站配置已改变，请执行更新')
        listener(cfg)
    except Exception as e:
        errors.append(str(e))
    for fam in state['families']:
        p = run(['nft', 'list', 'chain', fam, TABLE, 'prerouting'], False)
        if p.returncode or f'{cfg["start"]}-{cfg["end"]}' not in p.stdout or f'redirect to :{cfg["port"]}' not in p.stdout:
            errors.append(f'{fam} 端口映射缺失或不匹配')
    if run(['systemctl', 'is-enabled', SERVICE], False).stdout.strip() != 'enabled':
        errors.append('systemd 持久化服务未启用')
    if ufw_active():
        hop_spec, port_spec = specs(cfg)
        if not ufw_has(hop_spec):
            errors.append('UFW 未显示跳跃端口范围放行规则')
        if not ufw_has(port_spec):
            errors.append('UFW 未显示监听端口放行规则')
    print(f'配置: 入站 {cfg["id"]} {cfg.get("remark", "")} UDP {cfg["start"]}-{cfg["end"]} → {cfg["port"]}')
    for fam in state['families']:
        c = counters(fam)
        if c:
            print(f'  {fam:<3} 已转发 {c[0]} 个数据包 / {c[1]} 字节')
    print('STATUS:', 'PASS' if not errors else 'FAIL')
    for error in errors:
        print(' -', error)
    print('注意：PASS 只表示本机配置状态；真实客户端跳跃及重启后连通性须实机验证')
    return int(bool(errors))


def main():
    p = argparse.ArgumentParser(description=f'HCloudLab Hysteria2 UDP Hop {VERSION}')
    p.add_argument('action', nargs='?', choices=['install', 'update', 'status', 'restore', 'reload', 'stop-rules'])
    p.add_argument('--inbound-id', type=int)
    p.add_argument('--version', action='version', version=VERSION)
    args = p.parse_args()
    # reload/stop-rules run from systemd at boot: never refuse them just because
    # the OS was upgraded to an untested release, or the node would go offline.
    prerequisites(check_release=args.action not in ('reload', 'stop-rules'))
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open('a+') as fd:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('已有另一进程正在操作') from None
        action = args.action
        if action is None:
            print(f'\nHCloudLab · Hysteria2 UDP Hop {VERSION}\n1. 一键安装\n2. 更新配置\n3. 状态检查\n4. 一键恢复\n5. 退出')
            action = {'1': 'install', '2': 'update', '3': 'status', '4': 'restore', '5': 'exit'}.get(input('请选择: ').strip())
        if action == 'install':
            install(args.inbound_id)
        elif action == 'update':
            update(args.inbound_id)
        elif action == 'status':
            return status()
        elif action == 'restore':
            restore()
        elif action == 'reload':
            reload_rules()
        elif action == 'stop-rules':
            delete_tables()
        elif action != 'exit':
            raise RuntimeError('无效操作')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (EOFError, KeyboardInterrupt):
        print('\n已取消', file=sys.stderr)
        sys.exit(130)
    except (RuntimeError, OSError, ValueError, sqlite3.Error) as e:
        print('ERROR:', e, file=sys.stderr)
        sys.exit(1)
