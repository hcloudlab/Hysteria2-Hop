#!/usr/bin/env python3
"""HCloudLab HY2 Hop: Ubuntu 24.04, read-only 3X-UI, dedicated nft NAT."""
import argparse
import fcntl
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

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
# restore run (including root's) with "已有另一进程正在操作" - /run
# itself is not world-writable, so only root can place a file here.
LOCK = Path('/run/hcloudlab-hy2hop.lock')


def run(cmd, check=True, input_text=None):
    p = subprocess.run(cmd, input=input_text, text=True, capture_output=True)
    if check and p.returncode:
        raise RuntimeError(f"{' '.join(cmd)}: {p.stderr.strip() or p.stdout.strip()}")
    return p


def supported_os(os_release):
    """Accept only explicitly supported distribution/version pairs."""
    fields = {}
    for line in os_release.splitlines():
        if '=' not in line or line.lstrip().startswith('#'):
            continue
        key, value = line.split('=', 1)
        fields[key] = value.strip().strip('"').strip("'")
    return (fields.get('ID'), fields.get('VERSION_ID')) in {
        ('ubuntu', '24.04'),
        ('debian', '12'),
        ('debian', '13'),
    }


def prerequisites():
    if os.geteuid():
        raise RuntimeError('需要 root 权限')
    if not Path('/run/systemd/system').exists():
        raise RuntimeError('需要 systemd')
    text = Path('/etc/os-release').read_text()
    if not supported_os(text):
        raise RuntimeError('仅支持 Ubuntu 24.04、Debian 12/13（需要 systemd）')
    for command in ('systemctl', 'ss', 'ip', 'apt-get'):
        if not shutil.which(command):
            raise RuntimeError(f'缺少系统命令 {command}')


def inbounds():
    if not DB.is_file():
        raise RuntimeError('未找到 3X-UI 数据库')
    with sqlite3.connect(f'file:{DB}?mode=ro', uri=True) as con:
        rows = con.execute("SELECT id,remark,port,enable,stream_settings,listen FROM inbounds WHERE protocol='hysteria' ORDER BY id").fetchall()
    result = []
    for ident, remark, port, enabled, raw, listen in rows:
        if not enabled:
            continue
        try:
            data = json.loads(raw or '{}')
            hop = data.get('finalmask', {}).get('quicParams', {}).get('udpHop', {}).get('ports')
        except (TypeError, ValueError):
            raise RuntimeError(f'入站 {ident}: stream_settings 无效') from None
        if not hop:
            continue
        m = re.fullmatch(r'\s*(\d+)\s*-\s*(\d+)\s*', str(hop))
        if not m:
            raise RuntimeError(f'入站 {ident}: Hop Ports 格式错误')
        a, b = map(int, m.groups())
        port = int(port)
        if not (1 <= a <= b <= 65535 and 1 <= port <= 65535):
            raise RuntimeError(f'入站 {ident}: 端口超出范围')
        if a <= port <= b:
            raise RuntimeError(f'入站 {ident}: Hop 范围包含监听端口')
        if listen not in (None, '', '::', '0.0.0.0'):
            raise RuntimeError(f'入站 {ident}: 暂不支持绑定指定 IP')
        result.append(dict(id=ident, remark=remark or '', port=port, start=a, end=b))
    return result


def choose(ident=None):
    options = inbounds()
    if ident is not None:
        match = next((x for x in options if x['id'] == ident), None)
        if not match:
            raise RuntimeError(f'未找到有效的 Hysteria2 UDP Hop 入站 ID={ident}')
        return match
    if not options:
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


def dependency():
    if shutil.which('nft'):
        return
    print('自动安装 nftables（不会启动系统 nftables.service）')
    run(['apt-get', 'update'])
    run(['apt-get', 'install', '-y', 'nftables'])
    if not shutil.which('nft'):
        raise RuntimeError('nftables 安装失败')


def families():
    fam = ['ip']
    p = run(['ip', '-6', '-o', 'addr', 'show', 'scope', 'global'], False)
    if p.returncode:
        raise RuntimeError('无法检测 IPv6 地址')
    if p.stdout.strip():
        fam.append('ip6')
    return fam


def owned_tables():
    return [fam for fam in ('ip', 'ip6') if run(['nft', 'list', 'table', fam, TABLE], False).returncode == 0]


def rules(cfg, fams, present=()):
    lines = [f'delete table {f} {TABLE}' for f in present]
    for f in fams:
        lines += [f'add table {f} {TABLE}',
                  f'add chain {f} {TABLE} prerouting {{ type nat hook prerouting priority dstnat; policy accept; }}',
                  f'add rule {f} {TABLE} prerouting udp dport {cfg["start"]}-{cfg["end"]} counter redirect to :{cfg["port"]}']
    return '\n'.join(lines) + '\n'


def apply(cfg, fams):
    # nft -f is a single kernel transaction, including delete + create.
    run(['nft', '-f', '-'], input_text=rules(cfg, fams, owned_tables()))


def delete_tables():
    present = owned_tables()
    if present:
        run(['nft', '-f', '-'], input_text=rules({}, [], present))


def listener(cfg):
    p = run(['ss', '-H', '-lun'], False)
    if p.returncode:
        raise RuntimeError('无法检查 UDP 监听')
    if not any(re.search(r':' + str(cfg['port']) + r'\s', line + ' ') for line in p.stdout.splitlines()):
        raise RuntimeError(f'UDP {cfg["port"]} 未监听')


def conflicts(cfg):
    p = run(['ss', '-H', '-lun'], False)
    if p.returncode:
        raise RuntimeError('无法检查 UDP 端口占用')
    for line in p.stdout.splitlines():
        parts = line.split()
        addr = parts[4] if len(parts) > 5 else (parts[3] if len(parts) > 3 else '')
        m = re.search(r':(\d+)$', addr)
        if m and cfg['start'] <= int(m.group(1)) <= cfg['end']:
            raise RuntimeError(f'跳跃端口与 UDP 监听冲突: {line}')
    p = run(['nft', '-a', 'list', 'ruleset'], False)
    if p.returncode:
        raise RuntimeError('无法读取现有 nftables 规则')
    # Conservative: avoid interfering with preexisting DNAT/redirect on host.
    other = re.sub(r'(?ms)^table (?:ip|ip6) ' + TABLE + r' \{.*?^\}\n?', '', p.stdout)
    if re.search(r'\b(dnat|redirect)\b', other, re.I):
        raise RuntimeError('检测到其他 NAT 重定向规则，为避免覆盖现有业务已停止（需要人工审查）')


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


def read_state():
    return json.loads(STATE.read_text()) if STATE.exists() else None


def write_state(state):
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
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
    return ('[Unit]\nDescription=HCloudLab Hysteria2 UDP Hop\nAfter=network-online.target ufw.service x-ui.service\n'
            'Wants=network-online.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            f'ExecStart={SELF} reload\nExecStop={SELF} stop-rules\n'
            '[Install]\nWantedBy=multi-user.target\n')


def setup_service():
    source = Path(__file__).resolve()
    if source != SELF.resolve():
        shutil.copy2(source, SELF)
    SELF.chmod(0o755)
    UNIT.write_text(unit_content())
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', SERVICE])


def clean_service():
    run(['systemctl', 'disable', SERVICE], False)
    UNIT.unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])


def install(ident=None):
    if STATE.exists() or UNIT.exists():
        raise RuntimeError('已有安装，请选择更新或状态检查')
    cfg = choose(ident)
    listener(cfg)
    dependency()
    if owned_tables():
        raise RuntimeError('发现没有状态记录的专属 nft 表，拒绝覆盖')
    conflicts(cfg)
    fam = families()
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
    print(f'安装完成: 入站 {cfg["id"]} UDP {cfg["start"]}-{cfg["end"]} → {cfg["port"]}')
    print('请更新客户端订阅并实测；云厂商安全组需自行允许跳跃范围及监听端口 UDP。')


def update(ident=None):
    old = read_state()
    if not old:
        return install(ident)
    cfg = choose(ident if ident is not None else old['config']['id'])
    listener(cfg)
    dependency()
    conflicts(cfg)
    fam = families()
    new_hop, new_port = specs(cfg)
    old_owned = list(old.get('ufw_owned', []))
    unchanged = cfg == old['config'] and fam == old['families']
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
    print('更新完成:', cfg)


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
    print('恢复完成：只清理本工具规则和服务；3X-UI 与 nftables 软件包保留')


def status():
    state = read_state()
    if not state:
        print('尚未安装')
        return 1
    cfg = state['config']
    errors = []
    try:
        current = next((x for x in inbounds() if x['id'] == cfg['id']), None)
        if current != cfg:
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
    print('配置:', cfg)
    print('STATUS:', 'PASS' if not errors else 'FAIL')
    for error in errors:
        print(' -', error)
    print('注意：PASS 只表示本机配置状态；真实客户端跳跃及重启后连通性须实机验证')
    return int(bool(errors))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', nargs='?', choices=['install', 'update', 'status', 'restore', 'reload', 'stop-rules'])
    p.add_argument('--inbound-id', type=int)
    args = p.parse_args()
    prerequisites()
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open('a+') as fd:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('已有另一进程正在操作') from None
        action = args.action
        if action is None:
            print('\nHCloudLab · Hysteria2 UDP Hop\n1. 一键安装\n2. 更新配置\n3. 状态检查\n4. 一键恢复\n5. 退出')
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
    except (RuntimeError, OSError, ValueError, sqlite3.Error) as e:
        print('ERROR:', e, file=sys.stderr)
        sys.exit(1)
