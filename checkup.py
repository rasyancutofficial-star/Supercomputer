"""Read-only helpers: audit-log alert wording and the /보안점검 server checkup.

Nothing here calls Discord or changes anything. Functions only read attributes, so they are
easy to unit-test with simple stand-in objects.
"""
from __future__ import annotations

import discord

from core import protection_active

# 새로 부여되면 즉시 알릴 서버 권한. 값은 로그에 보일 한국어 이름이다.
ALERT_PERMISSIONS = {
    'administrator': '관리자', 'manage_guild': '서버 관리', 'manage_roles': '역할 관리',
    'manage_channels': '채널 관리', 'manage_webhooks': '웹훅 관리',
    'ban_members': '멤버 차단', 'kick_members': '멤버 추방',
}
# @everyone 기본 역할에 있으면 위험한 권한(점검용).
EVERYONE_RISKS = {**ALERT_PERMISSIONS, 'moderate_members': '멤버 타임아웃', 'mention_everyone': '@everyone 멘션'}
CRITICAL_PERMISSIONS = {'administrator', 'manage_guild', 'manage_roles'}
ALERT_ACTIONS = {
    discord.AuditLogAction.bot_add, discord.AuditLogAction.role_update,
    discord.AuditLogAction.member_role_update, discord.AuditLogAction.webhook_create,
    discord.AuditLogAction.member_prune,
}
LEVEL_ICON = {'ok': '✅', 'warn': '⚠️', 'info': 'ℹ️'}


def gained_permissions(before, after, names=ALERT_PERMISSIONS) -> list[str]:
    """before에는 없고 after에는 있는 권한 키 목록."""
    return [key for key in names
            if getattr(after, key, False) and not (before is not None and getattr(before, key, False))]


def _label(keys, names=ALERT_PERMISSIONS) -> str:
    return ', '.join(names.get(k, k) for k in keys)


def _name(obj) -> str:
    name = getattr(obj, 'name', None)
    return str(name) if name else f'ID {getattr(obj, "id", "?")}'


def describe_audit_entry(entry):
    """경보 대상이면 (제목, 상세, 중요 여부)를, 아니면 None을 돌려준다."""
    actor = f'<@{entry.user_id}>'
    action = entry.action
    guild = entry.guild
    if action is discord.AuditLogAction.bot_add:
        target = getattr(entry, 'target', None)
        return ('봇 추가 감지',
                f'새 봇: {_name(target)} (<@{getattr(target, "id", 0)}>)\n추가한 사람: {actor}\n'
                '낯선 봇이면 즉시 제거하고, 봇에 부여된 권한을 확인하세요.', True)
    if action is discord.AuditLogAction.role_update:
        gained = gained_permissions(getattr(entry.before, 'permissions', None),
                                    getattr(entry.after, 'permissions', None))
        if not gained:
            return None
        role = getattr(entry, 'target', None)
        everyone = getattr(role, 'id', None) == getattr(guild, 'id', object())
        critical = everyone or bool(CRITICAL_PERMISSIONS & set(gained))
        scope = ' (@everyone — 모든 멤버에게 적용)' if everyone else ''
        return ('역할 권한 상승 감지',
                f'역할: {_name(role)}{scope}\n추가된 권한: {_label(gained)}\n변경한 사람: {actor}', critical)
    if action is discord.AuditLogAction.member_role_update:
        added = getattr(entry.after, 'roles', None) or []
        lookup = getattr(guild, 'get_role', None)
        risky, critical = [], False
        for role in added:
            full = (lookup(role.id) if lookup else None) or role
            perms = getattr(full, 'permissions', None)
            gained = gained_permissions(None, perms) if perms is not None else []
            if gained:
                risky.append(f'{_name(full)}({_label(gained)})')
                critical = critical or bool(CRITICAL_PERMISSIONS & set(gained))
        if not risky:
            return None
        member = getattr(entry, 'target', None)
        return ('위험 권한 역할 부여 감지',
                f'대상: <@{getattr(member, "id", 0)}>\n부여된 역할: {", ".join(risky)}\n부여한 사람: {actor}', critical)
    if action is discord.AuditLogAction.webhook_create:
        return ('웹훅 생성 감지',
                f'생성한 사람: {actor}\n웹훅 주소가 유출되면 누구나 이 서버에 글을 올릴 수 있습니다. '
                '모르는 웹훅이면 서버 설정에서 삭제하세요.', False)
    if action is discord.AuditLogAction.member_prune:
        removed = getattr(getattr(entry, 'extra', None), 'members_removed', '알 수 없음')
        return ('멤버 일괄 정리 감지', f'실행한 사람: {actor}\n정리된 멤버 수: {removed}', True)
    return None


def run_checkup(guild, cfg, me, required_labels, now) -> list[tuple[str, str]]:
    """서버 설정을 읽기 전용으로 점검해 (등급, 문장) 목록을 만든다. 등급: ok / warn / info."""
    items: list[tuple[str, str]] = []

    def add(level, text):
        items.append((level, text))

    # 1) 서버 수준 설정
    if getattr(guild, 'mfa_level', None) == discord.MFALevel.require_2fa:
        add('ok', '관리 권한 작업에 2단계 인증이 요구됩니다.')
    else:
        add('warn', '관리 권한 작업에 2단계 인증이 요구되지 않습니다. 서버 주인이 서버 설정에서 켤 수 있습니다.')
    verification = getattr(guild, 'verification_level', None)
    if verification == discord.VerificationLevel.none:
        add('warn', '서버 인증 수준이 "없음"입니다. 신규 계정의 도배·스캠이 쉬워집니다.')
    else:
        add('ok', f'서버 인증 수준: {verification}')
    if getattr(guild, 'explicit_content_filter', None) == discord.ContentFilter.disabled:
        add('warn', '유해 미디어 필터가 꺼져 있습니다.')
    else:
        add('ok', '유해 미디어 필터가 켜져 있습니다.')

    # 2) @everyone 기본 권한
    everyone = getattr(guild, 'default_role', None)
    risky = [k for k in EVERYONE_RISKS if getattr(getattr(everyone, 'permissions', None), k, False)]
    if risky:
        add('warn', f'@everyone(모든 멤버)에게 위험 권한이 있습니다: {_label(risky, EVERYONE_RISKS)}')
    else:
        add('ok', '@everyone 기본 역할에 위험 권한이 없습니다.')

    # 3) 관리자 권한 역할과 봇
    roles = [r for r in getattr(guild, 'roles', []) if getattr(r.permissions, 'administrator', False)
             and r != everyone]
    human_roles = [r for r in roles if not getattr(r, 'managed', False)]
    if human_roles:
        shown = ', '.join(f'{r.name}({len(getattr(r, "members", []))}명)' for r in human_roles[:8])
        more = f' 외 {len(human_roles) - 8}개' if len(human_roles) > 8 else ''
        add('warn' if len(human_roles) > 3 else 'info', f'관리자 권한 역할 {len(human_roles)}개: {shown}{more}')
    admin_bots = [m for m in getattr(guild, 'members', [])
                  if getattr(m, 'bot', False) and m.id != me.id and m.guild_permissions.administrator]
    if admin_bots:
        names = ', '.join(m.name for m in admin_bots[:8])
        add('warn', f'관리자 권한을 가진 다른 봇 {len(admin_bots)}개: {names}. 필요한 권한만 주는 것이 안전합니다.')
    else:
        add('ok', '관리자 권한을 가진 다른 봇이 없습니다.')

    # 4) Guardian 자신
    if me.guild_permissions.administrator:
        add('warn', 'Guardian에 관리자 권한이 있습니다. 필요한 권한만 부여해도 모든 기능이 동작합니다.')
    missing = [label for key, label in required_labels.items()
               if key != 'administrator' and not getattr(me.guild_permissions, key, False)]
    if missing:
        add('warn', f'Guardian에 부족한 서버 권한: {", ".join(missing)}')
    else:
        add('ok', 'Guardian에 필요한 서버 권한이 모두 있습니다.')
    higher = [m for m in getattr(guild, 'members', [])
              if not getattr(m, 'bot', False) and m.id != guild.owner_id
              and m.guild_permissions.administrator and m.top_role >= me.top_role]
    if higher:
        add('info', f'관리자 {len(higher)}명은 Guardian보다 높은(또는 같은) 역할이라 자동 차단·타임아웃 대상이 될 수 없습니다.')

    # 5) 기록·감지 설정
    log_channel = guild.get_channel(cfg['log_channel_id']) if cfg['log_channel_id'] else None
    if log_channel is None:
        add('warn', '로그 채널이 설정되지 않았습니다. /로그설정으로 운영진 전용 채널을 지정하세요.')
    elif log_channel.permissions_for(everyone).view_channel:
        add('warn', f'로그 채널 {log_channel.mention}을 모든 멤버가 볼 수 있습니다. 운영진만 보도록 바꾸세요.')
    else:
        add('ok', f'로그 채널 {log_channel.mention}은 비공개입니다.')
    for key, label in (('spam_enabled', '도배·멘션 감지'), ('raid_enabled', '대량 입장 감지'),
                       ('nuke_enabled', '대량 삭제·추방·차단 감지'), ('files_enabled', '위험 첨부파일 차단'),
                       ('alerts_enabled', '관리 변경 경보')):
        if not cfg[key]:
            add('warn', f'{label}이(가) 꺼져 있습니다.')
    if not cfg['blocked_domains']:
        add('info', '차단 도메인 목록이 비어 있어 링크 검사가 동작하지 않습니다.')
    if not cfg['invites_enabled']:
        add('info', '디스코드 초대 링크 차단이 꺼져 있습니다. 홍보 스팸이 문제라면 켜세요.')
    if cfg['account_age_days'] == 0:
        add('info', '신규 계정 보호가 꺼져 있습니다. /감지기준으로 켤 수 있습니다.')
    if not protection_active(cfg, now):
        add('warn', '전체 자동 보안이 일시정지 중입니다. /보안전체 켜기로 다시 켜세요.')
    if cfg['raid_until'] > now:
        add('warn', '지금 대량 입장 보호가 진행 중입니다.')
    return items


def format_checkup(items, limit: int = 1900) -> str:
    warns = sum(1 for level, _ in items if level == 'warn')
    lines = [f'**보안 점검** · 확인 필요 {warns}건']
    lines += [f'{LEVEL_ICON[level]} {text}' for level, text in sorted(items, key=lambda x: x[0] != 'warn')]
    lines.append('이 점검은 읽기 전용이며 설정을 바꾸지 않습니다. 디스코드 서버 설정은 서버 주인·관리자가 직접 바꿔야 합니다.')
    text = '\n'.join(lines)
    return text if len(text) <= limit else text[:limit - 1] + '…'
