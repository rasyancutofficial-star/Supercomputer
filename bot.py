"""Discord Guardian — Korean slash commands, persistent moderation and guards."""
from __future__ import annotations

import asyncio
import logging
import math
import os
import sqlite3
import time
from datetime import timedelta
from pathlib import Path

import aiohttp
import discord
from discord import app_commands
from discord.ext import tasks
from dotenv import load_dotenv

from checkup import ALERT_ACTIONS, describe_audit_entry, format_checkup, run_checkup
from core import (INVITE_RE, LIMIT_RANGES, Store, Windows, blocked_attachment, blocked_link,
                  newcomer_violation, normalize_domain, normalize_extension, protection_active, timeout_duration)

LOG = logging.getLogger('guardian')
BASE = Path(__file__).resolve().parent
ACTION_LABEL = {'ban': '서버 차단', 'kick': '추방'}
WARN_TIMEOUT_DAYS = {1: 1, 2: 3, 3: 5, 4: 15}
WhitelistChannel = (discord.TextChannel | discord.ForumChannel | discord.Thread |
                    discord.VoiceChannel | discord.StageChannel)
PERMISSION_LABEL = {
    'moderate_members': '멤버 타임아웃', 'kick_members': '멤버 추방',
    'ban_members': '멤버 차단', 'administrator': '관리자',
    'view_audit_log': '감사 로그 보기', 'manage_messages': '메시지 관리',
}
FEATURE_CHOICES = [
    app_commands.Choice(name='도배·멘션 감지', value='spam_enabled'),
    app_commands.Choice(name='대량 입장 감지', value='raid_enabled'),
    app_commands.Choice(name='대량 삭제·추방·차단 감지', value='nuke_enabled'),
    app_commands.Choice(name='등록 도메인 차단', value='links_enabled'),
    app_commands.Choice(name='위험 첨부 파일 차단', value='files_enabled'),
    app_commands.Choice(name='디스코드 초대 링크 차단', value='invites_enabled'),
    app_commands.Choice(name='관리 변경 경보(봇 추가·권한 상승)', value='alerts_enabled'),
    app_commands.Choice(name='중요 경보 시 서버 주인 멘션', value='ping_owner'),
    app_commands.Choice(name='같은 문구 교차 게시 감지', value='crosspost_enabled'),
    app_commands.Choice(name='신규 멤버 링크·첨부 제한', value='newcomer_minutes'),
    app_commands.Choice(name='신규 계정 보호', value='account_age_days'),
]
FEATURE_NAME = {c.value: c.name for c in FEATURE_CHOICES}
# 숫자 기준으로 켜고 끄는 기능: 켤 때 기준이 0이면 이 값을 쓰고, 끄면 0으로 둔다.
TOGGLE_DEFAULTS = {'newcomer_minutes': 10, 'account_age_days': 3}
TOGGLE_UNIT = {'newcomer_minutes': '분', 'account_age_days': '일'}
# 패널 버튼 순서와 짧은 이름
PANEL_ITEMS = [
    ('spam_enabled', '도배·멘션'), ('crosspost_enabled', '교차 게시'), ('links_enabled', '차단 도메인'),
    ('files_enabled', '위험 파일'), ('invites_enabled', '초대 링크'), ('newcomer_minutes', '신규 멤버 제한'),
    ('account_age_days', '신규 계정 보호'), ('raid_enabled', '대량 입장'), ('nuke_enabled', '대량 파괴'),
    ('alerts_enabled', '변경 경보'), ('ping_owner', '주인 멘션'),
]
LIMIT_CHOICES = [
    app_commands.Choice(name='5초 내 메시지 수', value='spam_limit'),
    app_commands.Choice(name='한 메시지의 고유 멘션 수', value='mention_limit'),
    app_commands.Choice(name='15초 내 동일 문구 수', value='repeat_limit'),
    app_commands.Choice(name='10초 내 입장 인원', value='raid_limit'),
    app_commands.Choice(name='20초 내 위험 관리 작업 수', value='nuke_limit'),
    app_commands.Choice(name='10분 내 같은 문구를 올린 채널 수', value='crosspost_limit'),
    app_commands.Choice(name='신규 계정 보호 기준(일, 0=끔)', value='account_age_days'),
    app_commands.Choice(name='입장 직후 링크·첨부 제한(분, 0=끔)', value='newcomer_minutes'),
]
NUKE_ACTIONS = {discord.AuditLogAction.channel_delete, discord.AuditLogAction.role_delete,
                discord.AuditLogAction.kick, discord.AuditLogAction.ban}


class UserError(app_commands.AppCommandError):
    pass


def need_permission(member, name):
    if not getattr(member.guild_permissions, name):
        raise UserError(f'{PERMISSION_LABEL.get(name, name)} 권한이 필요합니다.')


def check_target(actor, member, me):
    """Check caller and bot hierarchy; bot permission checks are action-specific."""
    if member.id == member.guild.owner_id:
        raise UserError('서버 주인에게는 이 조치를 할 수 없습니다.')
    if member.id == me.id or (actor and member.id == actor.id):
        raise UserError('봇 자신 또는 명령 실행자 자신은 대상이 될 수 없습니다.')
    if actor and actor.id != member.guild.owner_id and member.top_role >= actor.top_role:
        raise UserError('본인과 같거나 높은 역할의 멤버에게 조치할 수 없습니다.')
    if member.top_role >= me.top_role:
        raise UserError('봇 역할을 대상자의 가장 높은 역할보다 위로 이동해주세요.')


def warning_name(user):
    return discord.utils.escape_markdown(user.name)


def fail_text(exc, prefix):
    """UserError는 설명 그대로, 디스코드 HTTP 오류는 코드만 짧게 보여준다."""
    return str(exc) if isinstance(exc, UserError) else f'{prefix}(코드 {exc.code})'


def master_text(cfg, now):
    if protection_active(cfg, now):
        return '자동 보안: 켜짐'
    if cfg['master_resume_at']:
        return f'자동 보안: ⏸️ 일시정지 중 — <t:{int(cfg["master_resume_at"])}:R> 자동 재개'
    return '자동 보안: ⏸️ 일시정지 중 — 직접 켜기 전까지 유지'


def latency_text(seconds):
    """재연결 중에는 latency가 NaN/inf라서 round()가 오류를 낸다. 측정 불가로 표시한다."""
    return f'{round(seconds * 1000)}ms' if math.isfinite(seconds) else '측정 불가'


def count_mentions(message):
    return len({m.id for m in message.mentions}) + len({r.id for r in message.role_mentions})


def message_text(message):
    """링크 검사용 글: 본문 + 전달(포워드) 메시지 + 봇·웹훅 임베드. 도배 판정에는 본문만 쓴다."""
    parts = [message.content or '']
    for snapshot in getattr(message, 'message_snapshots', None) or ():
        parts.append(getattr(snapshot, 'content', '') or '')
    automated = bool(getattr(message, 'webhook_id', None) or getattr(message.author, 'bot', False))
    for embed in getattr(message, 'embeds', None) or ():
        parts.append(embed.url or '')
        if automated:
            parts.append(embed.description or '')
            parts += [field.value or '' for field in embed.fields]
    return '\n'.join(part for part in parts if part)


def message_files(message):
    names = [a.filename for a in getattr(message, 'attachments', None) or ()]
    for snapshot in getattr(message, 'message_snapshots', None) or ():
        names += [a.filename for a in getattr(snapshot, 'attachments', None) or ()]
    return names


def page_lines(items, page, title, unit, render, footer=None):
    pages = max(1, (len(items) + 19) // 20)
    if page > pages:
        raise UserError(f'목록은 {pages}페이지까지 있습니다.')
    lines = [f'**{title}** · 총 {len(items)}{unit} · {page}/{pages}페이지']
    lines += [render(item) for item in items[(page - 1) * 20:page * 20]]
    if not items:
        lines.append(f'등록된 {"대상" if unit == "명" else "채널"}이 없습니다.')
    if footer:
        lines.append(footer)
    return '\n'.join(lines)


async def reply(interaction, text, *, ephemeral=True):
    if interaction.response.is_done():
        await interaction.followup.send(text, ephemeral=ephemeral, allowed_mentions=discord.AllowedMentions.none())
    else:
        await interaction.response.send_message(text, ephemeral=ephemeral, allowed_mentions=discord.AllowedMentions.none())


class TimeoutOffer(discord.ui.View):
    """One moderator's one-time DM confirmation; no action until a button click."""
    def __init__(self, bot, guild_id, target_id, moderator_id, case_id, days):
        super().__init__(timeout=300)
        self.bot = bot
        self.guild_id = guild_id
        self.target_id = target_id
        self.moderator_id = moderator_id
        self.case_id = case_id
        self.days = days
        self.expires_at = time.time() + 300
        self.decided = False
        self.decision_lock = asyncio.Lock()
        self.message = None

    async def interaction_check(self, interaction):
        if interaction.user.id != self.moderator_id:
            await reply(interaction, '이 확인 버튼은 해당 경고를 추가한 관리자만 사용할 수 있습니다.')
            return False
        return True

    def disable(self):
        for button in self.children:
            button.disabled = True
        self.stop()

    async def decide(self, interaction, apply):
        if not await self.interaction_check(interaction):
            return
        await interaction.response.defer()
        async with self.decision_lock:
            if self.decided:
                await reply(interaction, '이미 처리되었거나 만료된 요청입니다.')
                return
            self.decided = True
            self.disable()
            if time.time() >= self.expires_at:
                result = '확인 시간이 만료되었습니다. 타임아웃을 적용하지 않았습니다.'
            elif not apply:
                result = '타임아웃 적용을 취소했습니다. 추가한 경고는 그대로 유지됩니다.'
            else:
                try:
                    result = await self.bot.apply_timeout_offer(self)
                except UserError as exc:
                    result = '타임아웃 미적용: ' + str(exc)
                except discord.NotFound:
                    result = '타임아웃 미적용: 대상 또는 명령 실행자가 서버에 없습니다.'
                except discord.HTTPException as exc:
                    result = f'타임아웃 요청 실패(코드 {exc.code}). 현재 상태를 확인한 뒤 /타임아웃으로 처리해주세요.'
                except Exception:
                    LOG.exception('후속 타임아웃 처리 오류: case=%s', self.case_id)
                    result = '처리 중 오류가 발생했습니다. 실제 타임아웃 상태와 운영 기록을 확인해주세요.'
            # Discord has already acknowledged the click; update the DM in place.
            try:
                await interaction.edit_original_response(content=result, view=self,
                                                         allowed_mentions=discord.AllowedMentions.none())
            except discord.HTTPException:
                LOG.warning('DM 결과 갱신 실패: case=%s', self.case_id)

    @discord.ui.button(label='적용', style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.decide(interaction, True)

    @discord.ui.button(label='취소', style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.decide(interaction, False)

    async def on_timeout(self):
        async with self.decision_lock:
            if self.decided:
                return
            self.decided = True
            self.disable()
            if self.message:
                try:
                    await self.message.edit(content='확인 시간이 만료되었습니다. 타임아웃을 적용하지 않았습니다.', view=self)
                except discord.HTTPException:
                    pass

    async def on_error(self, interaction, error, item):
        await self.bot.command_error(interaction, error)


class SecurityPanel(discord.ui.View):
    """서버 주인 전용 ON/OFF 버튼 패널. 버튼을 누를 때마다 최신 설정을 읽어 다시 그린다."""
    def __init__(self, bot, guild_id, owner_id):
        super().__init__(timeout=300)
        self.bot = bot
        self.guild_id = guild_id
        self.owner_id = owner_id
        self.interaction = None
        self.refresh()

    def refresh(self):
        cfg = self.bot.store.config(self.guild_id)
        active = protection_active(cfg, time.time())
        self.clear_items()
        self.add_item(self.make_button('🛡️ 전체 보호 ' + ('켜짐' if active else '정지됨'), active, 'master',
                                       discord.ButtonStyle.success if active else discord.ButtonStyle.danger))
        for key, label in PANEL_ITEMS:
            on = bool(cfg[key])
            self.add_item(self.make_button(f'{"🟢" if on else "⚫"} {label}', on, key,
                                           discord.ButtonStyle.success if on else discord.ButtonStyle.secondary))

    def make_button(self, label, on, key, style):
        button = discord.ui.Button(label=label, style=style)

        async def callback(interaction):
            await self.toggle(interaction, key, not on)
        button.callback = callback
        return button

    def content(self):
        cfg = self.bot.store.config(self.guild_id)
        return ('**Guardian 보안 패널**\n' + master_text(cfg, time.time()) + '\n'
                '버튼을 누르면 바로 켜고 끕니다. 🟢 켜짐 · ⚫ 꺼짐\n'
                '전체 보호를 끄면 60분 뒤 자동으로 다시 켜집니다. 이미 적용된 처분은 유지됩니다.')

    async def interaction_check(self, interaction):
        guild = interaction.guild
        if (interaction.user.id != self.owner_id or guild is None or interaction.user.id != guild.owner_id
                or not self.bot.allowed_guild(guild.id)):
            await reply(interaction, '서버 주인만 사용할 수 있는 패널입니다.')
            return False
        return True

    async def toggle(self, interaction, key, enable):
        guild = interaction.guild
        actor = await guild.fetch_member(interaction.user.id)  # 클릭 순간의 서버 주인 여부를 다시 확인
        if actor.id != guild.owner_id:
            raise UserError('보안 설정은 서버 주인만 변경할 수 있습니다.')
        if key == 'master':
            await self.bot.set_master(guild, actor, enable, 60)
        else:
            await self.bot.set_feature(guild, actor, key, enable)
        self.refresh()
        await interaction.response.edit_message(content=self.content(), view=self,
                                                allowed_mentions=discord.AllowedMentions.none())

    async def on_timeout(self):
        for item in self.children:
            item.disabled = True
        if self.interaction:
            try:
                await self.interaction.edit_original_response(view=self)
            except discord.HTTPException:
                pass

    async def on_error(self, interaction, error, item):
        await self.bot.command_error(interaction, error)


class Guardian(discord.Client):
    def __init__(self, store: Store, test_guild_id: int | None = None, backup_dir: Path | None = None):
        intents = discord.Intents.none()
        intents.guilds = True
        intents.members = True
        intents.guild_messages = True
        intents.message_content = True
        intents.moderation = True
        super().__init__(intents=intents, allowed_mentions=discord.AllowedMentions.none())
        self.store = store
        self.test_guild_id = test_guild_id
        self.backup_dir = backup_dir
        self.tree = app_commands.CommandTree(self)
        self.tree.interaction_check = self.guild_interaction_check
        self.windows = Windows()
        # A fixed pool bounds memory and serializes warning changes across HTTP awaits.
        self.member_locks = [asyncio.Lock() for _ in range(128)]
        self.register_commands()
        self.tree.on_error = self.command_error

    def lock(self, guild_id, user_id):
        return self.member_locks[hash((guild_id, user_id)) % len(self.member_locks)]

    def allowed_guild(self, guild_id):
        # None is useful for isolated unit tests; main/setup_hook require a server ID.
        return guild_id is not None and (self.test_guild_id is None or guild_id == self.test_guild_id)

    async def guild_interaction_check(self, interaction):
        if not self.allowed_guild(interaction.guild_id):
            await reply(interaction, '이 봇은 설정된 전용 서버에서만 사용할 수 있습니다.')
            return False
        return True

    async def setup_hook(self):
        if not self.test_guild_id:
            raise RuntimeError('전용 서버의 GUILD_ID를 설정해주세요.')
        guild = discord.Object(id=self.test_guild_id)
        self.tree.copy_global_to(guild=guild)
        synced = await self.tree.sync(guild=guild)
        LOG.info('슬래시 명령어 %d개 등록 완료', len(synced))
        self.housekeeping.start()

    async def close(self):
        self.housekeeping.cancel()
        await super().close()

    @tasks.loop(minutes=1)
    async def housekeeping(self):
        # discord.py의 tasks.loop는 처리되지 않은 예외가 나면 반복을 멈춘다. 오류를 기록하고 계속 돈다.
        try:
            now = time.time()
            self.windows.clean(now)
            self.store.cleanup(now)
            await self.resume_if_due()
            if self.backup_dir:
                path = self.store.backup_if_due(self.backup_dir)
                if path:
                    LOG.info('데이터베이스 백업 완료: %s', path.name)
        except (OSError, sqlite3.Error):
            LOG.exception('정리·백업 작업 실패')

    async def resume_if_due(self):
        """일시정지 시간이 끝났으면 저장된 상태도 '켜짐'으로 정리하고 기록한다. (판정은 이미 자동 재개 상태)"""
        if not self.test_guild_id:
            return
        cfg = self.store.config(self.test_guild_id)
        if cfg['master_enabled'] or not 0 < cfg['master_resume_at'] <= time.time():
            return
        self.store.setting(self.test_guild_id, master_enabled=True, master_resume_at=0.0)
        guild = self.get_guild(self.test_guild_id)
        if guild:
            await self.record(guild, 0, '전체 자동 보안 자동 재개', '일시정지 시간이 끝나 모든 자동 보안을 다시 켰습니다.')

    async def on_ready(self):
        LOG.info('연결 완료: %s / 서버 %d개', self.user, len(self.guilds))
        if self.test_guild_id and not protection_active(self.store.config(self.test_guild_id), time.time()):
            LOG.warning('자동 보안이 일시정지 상태입니다. /보안전체 켜기로 다시 켜세요.')
        guild = self.get_guild(self.test_guild_id) if self.test_guild_id else None
        if guild is None or guild.me is None:
            LOG.warning('전용 서버(GUILD_ID)에 봇이 없거나 서버 정보를 아직 받지 못했습니다. 초대 여부를 확인하세요.')
            return
        missing = [label for key, label in PERMISSION_LABEL.items()
                   if key != 'administrator' and not getattr(guild.me.guild_permissions, key)]
        if missing:
            LOG.warning('봇에 부족한 서버 권한: %s', ', '.join(missing))
        if guild.me.guild_permissions.administrator:
            LOG.warning('봇에 관리자 권한이 있습니다. 필요한 권한만 부여하는 것이 안전합니다.')

    async def command_error(self, interaction, error):
        original = getattr(error, 'original', error)
        if isinstance(original, (UserError, ValueError)):
            message = str(original)
        elif isinstance(original, (app_commands.MissingPermissions, app_commands.CheckFailure)):
            message = '이 명령어를 사용할 권한이 없습니다. 서버 내에서 권한을 확인해주세요.'
        elif isinstance(original, discord.Forbidden):
            message = '디스코드가 조치를 거부했습니다. 봇 권한과 역할 순서를 확인해주세요.'
        elif isinstance(original, discord.NotFound):
            message = '대상 멤버 또는 채널을 찾지 못했습니다. 현재 상태를 확인해주세요.'
        elif isinstance(original, discord.HTTPException):
            message = f'디스코드 요청이 실패했습니다(코드 {original.code}). 결과를 확인한 뒤 재시도해주세요.'
        else:
            LOG.error('명령어 오류', exc_info=(type(original), original, original.__traceback__))
            message = '처리 중 오류가 발생했습니다. 경고조회와 실행 콘솔에서 결과를 확인해주세요.'
        await reply(interaction, '⚠️ ' + message)

    @staticmethod
    def precheck(interaction, permission, owner):
        """공개 응답(defer)을 보내기 전에, 디스코드가 알려준 권한으로 명백한 무권한 호출을 먼저 거절한다.

        공개로 defer한 뒤의 오류 메시지는 채널의 모두에게 보이므로, 권한 없는 사용자의 호출이
        공개 오류 메시지를 만들지 않게 한다. 최종 판정은 아래 authorize의 최신 멤버 조회가 맡는다.
        """
        perms = getattr(interaction, 'permissions', None)
        if perms is None or interaction.user.id == interaction.guild.owner_id:
            return
        if owner:
            raise UserError('보안 설정은 서버 주인만 변경할 수 있습니다.')
        if permission and not (perms.administrator or getattr(perms, permission, False)):
            raise UserError(f'{PERMISSION_LABEL.get(permission, permission)} 권한이 필요합니다.')

    async def authorize(self, interaction, permission=None, owner=False, *, ephemeral=True):
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            raise UserError('서버 안에서만 사용할 수 있습니다.')
        if not self.allowed_guild(interaction.guild.id):
            raise UserError('이 봇은 설정된 전용 서버에서만 사용할 수 있습니다.')
        self.precheck(interaction, permission, owner)
        # The first follow-up inherits this visibility, so choose before deferring.
        await interaction.response.defer(ephemeral=ephemeral)
        actor = await interaction.guild.fetch_member(interaction.user.id)
        if owner and actor.id != interaction.guild.owner_id:
            raise UserError('보안 설정은 서버 주인만 변경할 수 있습니다.')
        if permission:
            need_permission(actor, permission)
        return actor

    def exempt(self, guild, user_id, cfg):
        return user_id in {guild.owner_id, self.user.id if self.user else 0, *cfg['trusted_ids']}

    def ensure_not_whitelisted(self, member):
        if member.id in self.store.config(member.guild.id)['trusted_ids']:
            raise UserError('화이트리스트에 등록된 대상에게는 경고·타임아웃 부여 또는 경고 처분을 할 수 없습니다. 먼저 화이트리스트에서 제거해주세요.')

    def channel_exempt(self, channel, cfg):
        ids = cfg['trusted_channel_ids']
        return (channel.id in ids or
                (isinstance(channel, discord.Thread) and channel.parent_id in ids))

    def message_exempt(self, message, cfg):
        if self.exempt(message.guild, message.author.id, cfg):
            return True
        # Channel exceptions apply to spam/mentions/invites, never to blocked links or dangerous files.
        strict = ((cfg['links_enabled'] and blocked_link(message_text(message), cfg['blocked_domains'])) or
                  (cfg['files_enabled'] and blocked_attachment(message_files(message), cfg['blocked_extensions'])))
        return self.channel_exempt(message.channel, cfg) and not strict

    async def set_channel_whitelist(self, guild, channel, enabled, actor):
        need_permission(actor, 'administrator')
        if channel.guild.id != guild.id:
            raise UserError('같은 서버의 채널을 선택해주세요.')
        ids = set(self.store.config(guild.id)['trusted_channel_ids'])
        if enabled:
            if len(ids) >= 100 and channel.id not in ids:
                raise UserError('채널 화이트리스트는 서버당 최대 100개입니다.')
            ids.add(channel.id)
        else:
            ids.discard(channel.id)
        # No await between reading and saving, so concurrent settings retain both edits.
        self.store.setting(guild.id, trusted_channel_ids=sorted(ids))
        await self.record(guild, actor.id, '채널 화이트리스트 변경',
                          f'채널 {channel.mention} / 등록={enabled}')
        inherited = self.channel_exempt(channel, self.store.config(guild.id))
        result = f'{channel.mention}: 채널 화이트리스트 {"등록" if enabled else "제거"} 완료.'
        if not enabled and inherited:
            result += '\n상위 채널이 등록되어 있어 이 스레드는 계속 면제됩니다.'
        return result + '\n등록된 채널과 하위 스레드의 도배·멘션 감지만 제외됩니다. 차단 링크 검사·제재와 수동 경고, 서버 전체 보호는 유지됩니다.'

    async def set_whitelist(self, guild, user_id, enabled, actor):
        # Enforce permissions here as well as on the command. The owner is included.
        need_permission(actor, 'administrator')
        async with self.lock(guild.id, user_id):
            ids = set(self.store.config(guild.id)['trusted_ids'])
            if enabled:
                if len(ids) >= 100 and user_id not in ids:
                    raise UserError('화이트리스트는 서버당 최대 100명입니다.')
                ids.add(user_id)
            else:
                ids.discard(user_id)
            # Keep the original field so existing security exceptions carry over.
            self.store.setting(guild.id, trusted_ids=sorted(ids))
            for tag in ('burst', 'repeat', 'cross', 'nuke'):
                self.windows.events.pop((tag, guild.id, user_id), None)
            for tag in ('spam_action', 'nuke_action'):
                self.windows.cooldowns.pop((tag, guild.id, user_id), None)
            joins = self.windows.events.get(('joins', guild.id))
            if joins is not None:
                kept = [(stamp, uid) for stamp, uid in joins if uid != user_id]
                joins.clear()
                joins.extend(kept)
        await self.record(guild, user_id, '화이트리스트 변경', f'실행자 {actor.id} / 등록={enabled}')
        return (f'대상 ID {user_id}: 화이트리스트 {"등록" if enabled else "제거"} 완료.\n'
                '기존 경고 기록과 이미 적용된 타임아웃·차단은 자동 변경하지 않습니다.')

    async def set_feature(self, guild, actor, key, enabled):
        """기능 하나를 켜거나 끈다. /보안설정과 /보안패널이 같은 경로를 쓴다. 호출 전에 서버 주인 확인이 필요하다."""
        name = FEATURE_NAME[key]
        suffix = ''
        if key in TOGGLE_DEFAULTS:
            value = (self.store.config(guild.id)[key] or TOGGLE_DEFAULTS[key]) if enabled else 0
            changes = {key: value}
            suffix = f' (기준 {value}{TOGGLE_UNIT[key]})' if value else ''
        else:
            changes = {key: enabled}
        if key == 'raid_enabled' and not enabled:
            changes['raid_until'] = 0.0
        self.store.setting(guild.id, **changes)
        state = f'{"켜짐" if enabled else "꺼짐"}{suffix}'
        await self.record(guild, actor.id, '보안 설정 변경', f'{name}: {state}')
        return f'{name}: {state}'

    async def set_master(self, guild, actor, enabled, minutes=60):
        """모든 자동 감지·처분을 일시정지하거나 재개한다. 수동 명령과 관리 변경 경보는 계속 동작한다."""
        if enabled:
            self.store.setting(guild.id, master_enabled=True, master_resume_at=0.0)
            text = '전체 자동 보안을 다시 켰습니다.'
            await self.record(guild, actor.id, '전체 자동 보안 재개', text)
            return text
        resume_at = time.time() + minutes * 60 if minutes > 0 else 0.0
        self.store.setting(guild.id, master_enabled=False, master_resume_at=resume_at)
        if resume_at:
            text = f'전체 자동 보안을 일시정지했습니다. <t:{int(resume_at)}:R>에 자동으로 다시 켜집니다.'
        else:
            text = '전체 자동 보안을 일시정지했습니다. 직접 다시 켜기 전까지 꺼져 있습니다.'
        await self.record(guild, actor.id, '전체 자동 보안 일시정지', text, critical=True)
        return text

    async def record(self, guild, user_id, kind, detail, *, target_name=None, critical=False):
        self.store.incident(guild.id, user_id, kind, detail)
        LOG.info('[%s] guild=%s user=%s %s', kind, guild.id, user_id, detail)
        cfg = self.store.config(guild.id)
        channel_id = cfg['log_channel_id']
        channel = guild.get_channel(channel_id) if channel_id else None
        if not isinstance(channel, discord.TextChannel):
            return
        embed = discord.Embed(title=kind[:256], description=detail[:3500], color=0x6D72F6,
                              timestamp=discord.utils.utcnow())
        if user_id:
            if kind.startswith('경고'):
                embed.add_field(name='대상', value=target_name or '사용자')
            else:
                embed.add_field(name='대상 ID', value=str(user_id))
        send = {'embed': embed, 'allowed_mentions': discord.AllowedMentions.none()}
        if critical and cfg['ping_owner'] and guild.owner_id:
            # 서버 주인 한 명에게만 알림이 가도록 허용 멘션을 그 사용자로 제한한다.
            send['content'] = f'🚨 <@{guild.owner_id}> 중요 보안 알림'
            send['allowed_mentions'] = discord.AllowedMentions(everyone=False, roles=False, replied_user=False,
                                                                users=[discord.Object(id=guild.owner_id)])
        try:
            await channel.send(**send)
        except discord.HTTPException as exc:
            LOG.warning('로그 채널 전송 실패: HTTP %s / %s', exc.status, exc.code)

    async def enforce_warning(self, member, action, actor=None):
        self.ensure_not_whitelisted(member)
        me = member.guild.me
        if me is None:
            raise UserError('봇의 서버 정보를 아직 불러오지 못했습니다.')
        check_target(actor, member, me)
        permission = 'ban_members' if action == 'ban' else 'kick_members'
        need_permission(me, permission)
        if actor:
            need_permission(actor, permission)
        reason = f'Guardian: 경고 한도 도달 / 실행자 {actor.name if actor else "자동 감지"}'
        if action == 'ban':
            await member.ban(reason=reason, delete_message_seconds=0)
        else:
            await member.kick(reason=reason)
        return ACTION_LABEL[action] + ' 완료'

    async def change_warning(self, member, delta, reason, actor=None):
        """Caller holds member lock. Commit points before API; preserve failed outcomes."""
        guild = member.guild
        if delta > 0:
            self.ensure_not_whitelisted(member)
        cfg = self.store.config(guild.id)
        old = self.store.points(guild.id, member.id)
        crosses = delta > 0 and old + delta >= cfg['warn_limit']
        if actor and crosses:
            # A moderator cannot use warnings to bypass their own ban/kick permission.
            need_permission(actor, 'ban_members' if cfg['warn_action'] == 'ban' else 'kick_members')
        result = '처분 대기' if crosses else '처분 없음'
        total, case = self.store.change(guild.id, member.id, actor.id if actor else 0, delta, reason, result)
        if crosses:
            try:
                result = await self.enforce_warning(member, cfg['warn_action'], actor)
            except (UserError, discord.HTTPException) as exc:
                error = str(exc) if isinstance(exc, UserError) else f'Discord HTTP {exc.status}, 코드 {exc.code}'
                result = '처분 실패: ' + error + ' / 권한 수정 후 /경고집행 사용'
            self.store.outcome(case, result)
        actual = total - old
        detail = (f'대상: {warning_name(member)}\n경고 {old} → {total}/{cfg["warn_limit"]} ({actual:+d})\n'
                  f'실행자: {warning_name(actor) if actor else "자동 감지"}\n'
                  f'사유: {discord.utils.escape_markdown(reason)}\n{result}\n기록 #{case}')
        await self.record(guild, member.id, '경고 변경', detail, target_name=warning_name(member))
        return detail

    async def timeout_until(self, member, until, reason, label):
        """자동 타임아웃의 공통 안전 점검. 이미 더 긴 타임아웃이 있으면 줄이지 않는다."""
        self.ensure_not_whitelisted(member)
        me = member.guild.me
        if me is None:
            raise UserError('봇의 서버 정보 없음')
        check_target(None, member, me)
        need_permission(me, 'moderate_members')
        if member.bot or member.guild_permissions.administrator:
            raise UserError('관리자 또는 봇 계정은 자동 타임아웃 대상에서 제외됩니다.')
        if member.timed_out_until and member.timed_out_until >= until:
            return '기존의 더 긴 타임아웃 유지'
        await member.timeout(until, reason=reason[:400])
        return f'{label} 완료'

    async def auto_timeout(self, member, minutes, reason):
        until = discord.utils.utcnow() + timedelta(minutes=minutes)
        return await self.timeout_until(member, until, reason, f'{minutes}분 타임아웃')

    async def send_timeout_offer(self, interaction, member, moderator, points, case_id):
        days = WARN_TIMEOUT_DAYS.get(points)
        if days is None:
            return
        # Recheck after the receipt has been sent; warnings may have changed meanwhile.
        cfg = self.store.config(member.guild.id)
        rows = self.store.history(member.guild.id, member.id)
        if (member.id in cfg['trusted_ids'] or not rows or rows[0]['id'] != case_id or
                rows[0]['result'] != '처분 없음' or
                self.store.points(member.guild.id, member.id) >= cfg['warn_limit']):
            return
        view = TimeoutOffer(self, member.guild.id, member.id, moderator.id, case_id, days)
        name = discord.utils.escape_markdown(member.name)
        content = (f'타임아웃 {days}일을 주시겠습니까?\n\n'
                   f'서버: {discord.utils.escape_markdown(member.guild.name)}\n'
                   f'대상: {name}\n'
                   f'이번 추가 경고: {points} · 기록 #{case_id}\n'
                   '5분 안에 선택해주세요. 적용 버튼을 눌러야 실행됩니다.')
        try:
            view.message = await moderator.send(content, view=view, allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException as exc:
            view.stop()
            LOG.warning('타임아웃 확인 DM 전송 실패: moderator=%s case=%s code=%s', moderator.id, case_id, exc.code)
            await reply(interaction, '경고는 정상 저장되었습니다. 개인 메시지를 보낼 수 없어 타임아웃 질문을 전달하지 못했습니다. DM 수신 설정을 확인하거나 /타임아웃을 사용해주세요.')

    async def apply_timeout_offer(self, offer):
        if not self.allowed_guild(offer.guild_id):
            raise UserError('설정된 전용 서버에 대한 요청이 아닙니다.')
        guild = self.get_guild(offer.guild_id)
        if guild is None:
            raise UserError('봇이 서버에 연결되어 있지 않습니다.')
        async with self.lock(guild.id, offer.target_id):
            # DM interaction.user is a User: fetch both memberships from the origin guild.
            moderator = await guild.fetch_member(offer.moderator_id)
            member = await guild.fetch_member(offer.target_id)
            me = await guild.fetch_member(self.user.id)
            need_permission(moderator, 'moderate_members')
            need_permission(me, 'moderate_members')
            self.ensure_not_whitelisted(member)
            check_target(moderator, member, me)
            if member.bot or member.guild_permissions.administrator:
                raise UserError('관리자 또는 봇 계정은 타임아웃할 수 없습니다.')
            rows = self.store.history(guild.id, member.id)
            if not rows or rows[0]['id'] != offer.case_id:
                raise UserError('경고가 추가·감소되거나 새 처분 기록이 생겨 이전 확인 요청이 취소되었습니다.')
            row = rows[0]
            if (row['actor'] != moderator.id or row['result'] != '처분 없음' or
                    WARN_TIMEOUT_DAYS.get(row['delta']) != offer.days):
                raise UserError('원래 경고 기록과 일치하지 않는 요청입니다.')
            if self.store.points(guild.id, member.id) >= self.store.config(guild.id)['warn_limit']:
                raise UserError('현재 경고 한도에 도달했습니다. 경고 처분 상태를 먼저 확인해주세요.')
            until = discord.utils.utcnow() + timeout_duration(offer.days, 'days')
            if member.timed_out_until and member.timed_out_until >= until:
                raise UserError('기존 타임아웃이 더 길어서 그대로 유지했습니다.')
            await member.timeout(until, reason=f'Guardian: 경고 #{offer.case_id} 후속 타임아웃 / 실행자 {moderator.name}')
            result = f'{warning_name(member)}에게 {offer.days}일 타임아웃을 적용했습니다.\n종료: <t:{int(until.timestamp())}:F>'
            await self.record(guild, member.id, '경고 후속 타임아웃',
                              f'경고 #{offer.case_id} / 실행자 {warning_name(moderator)}\n{result}',
                              target_name=warning_name(member))
            return result

    def newcomer_check(self, message, cfg):
        minutes = cfg['newcomer_minutes']
        if minutes <= 0:
            return None
        # 웹훅 작성자 등 joined_at이 없는 경우는 대상이 아니다.
        return newcomer_violation(getattr(message.author, 'joined_at', None), discord.utils.utcnow(), minutes,
                                  message_text(message), bool(message_files(message)))

    async def on_message(self, message):
        if not message.guild or not self.allowed_guild(message.guild.id) or (self.user and message.author.id == self.user.id):
            return
        guild = message.guild
        cfg = self.store.config(guild.id)
        if not protection_active(cfg, time.time()) or self.message_exempt(message, cfg):
            return
        now = time.time()
        violation = self.windows.message_violation(
            guild.id, message.author.id, message.content, count_mentions(message), message.mention_everyone,
            cfg, now, channel_id=message.channel.id, filenames=message_files(message),
            link_text=message_text(message))
        violation = violation or self.newcomer_check(message, cfg)
        if not violation:
            return
        async with self.lock(guild.id, message.author.id):
            cfg = self.store.config(guild.id)
            if self.message_exempt(message, cfg):
                return
            deletion = '감지 메시지 삭제 완료'
            try:
                await message.delete()
            except discord.NotFound:
                deletion = '메시지가 이미 삭제됨'
            except discord.HTTPException as exc:
                deletion = f'메시지 삭제 실패(코드 {exc.code})'
            if not self.windows.ready(('spam_action', guild.id, message.author.id), time.time(), 60):
                return
            if message.webhook_id:
                await self.record(guild, message.author.id, '웹훅 도배 감지', f'{violation}; {deletion}; 웹훅 자체는 삭제하지 않았습니다.')
                return
            try:
                member = await guild.fetch_member(message.author.id)
            except discord.NotFound:
                return
            cfg = self.store.config(guild.id)
            if self.message_exempt(message, cfg):
                return
            try:
                result = await self.auto_timeout(member, 10, f'Guardian: {violation}')
            except (UserError, discord.HTTPException) as exc:
                result = fail_text(exc, '타임아웃 실패')
            await self.record(guild, member.id, '메시지 테러 감지', f'{violation}; {deletion}; {result}')
            try:
                detail = await self.change_warning(member, 1, '자동: ' + violation)
            except UserError as exc:
                # 처리 도중 화이트리스트에 등록된 경우 등. 이벤트 처리기가 예외로 끝나지 않게 한다.
                LOG.info('자동 경고를 건너뜁니다: %s', exc)
                return
            try:
                await message.channel.send(f'{warning_name(member)}에게 1만큼 경고를 넣었습니다.\n\n{detail}',
                                           allowed_mentions=discord.AllowedMentions.none())
            except discord.HTTPException as exc:
                LOG.warning('자동 경고 공개 알림 실패: channel=%s code=%s', message.channel.id, exc.code)

    async def on_raw_message_edit(self, payload):
        # Edited messages are rescanned only for blocked URLs / excessive mentions.
        if not self.allowed_guild(payload.guild_id) or 'content' not in payload.data:
            return
        guild = self.get_guild(payload.guild_id)
        channel = guild.get_channel_or_thread(payload.channel_id) if guild else None
        if channel is None:
            return
        cfg = self.store.config(guild.id)
        if not protection_active(cfg, time.time()):
            return
        if self.channel_exempt(channel, cfg) and not cfg['links_enabled']:
            return
        try:
            message = await channel.fetch_message(payload.message_id)
        except discord.HTTPException:
            return
        cfg = self.store.config(guild.id)
        text = message_text(message)
        if ((cfg['links_enabled'] and blocked_link(text, cfg['blocked_domains'])) or
                (cfg['invites_enabled'] and INVITE_RE.search(text)) or
                (cfg['spam_enabled'] and (message.mention_everyone or
                                          count_mentions(message) >= cfg['mention_limit'])) or
                self.newcomer_check(message, cfg)):
            await self.on_message(message)

    async def protect_new_account(self, member, cfg):
        """기준 나이보다 어린 계정은 기준 나이가 될 때까지(최대 20일) 타임아웃한다. 경고 점수는 올리지 않는다."""
        created = getattr(member, 'created_at', None)
        days = cfg['account_age_days']
        if created is None:
            return
        now = discord.utils.utcnow()
        until = created + timedelta(days=days)
        if until - now < timedelta(seconds=60):
            return
        async with self.lock(member.guild.id, member.id):
            try:
                result = await self.timeout_until(member, until, f'Guardian: 신규 계정 보호(기준 {days}일)', '신규 계정 타임아웃')
            except discord.NotFound:
                return
            except (UserError, discord.HTTPException) as exc:
                result = fail_text(exc, '실패')
            await self.record(member.guild, member.id, '신규 계정 보호',
                              f'계정 생성 {(now - created).days}일 전 / 기준 {days}일 / 종료 <t:{int(until.timestamp())}:F>\n'
                              f'{result} / 경고 점수는 추가하지 않습니다.')

    async def on_member_join(self, member):
        guild = member.guild
        if not self.allowed_guild(guild.id):
            return
        cfg = self.store.config(guild.id)
        if not protection_active(cfg, time.time()) or self.exempt(guild, member.id, cfg):
            return
        if cfg['account_age_days'] > 0:
            await self.protect_new_account(member, cfg)
        if not cfg['raid_enabled']:
            return
        now = time.time()
        recent = self.windows.add(('joins', guild.id), now, 10, member.id)
        ids = {uid for _, uid in recent}
        if cfg['raid_until'] > now:
            ids = {member.id}
        elif len(ids) >= cfg['raid_limit']:
            self.store.setting(guild.id, raid_until=now + 120)
            await self.record(guild, 0, '대량 입장 감지', '2분간 신규 입장자 + 감지에 포함된 최근 입장자에게 10분 타임아웃을 시도합니다.',
                              critical=True)
        else:
            return
        for uid in ids:
            async with self.lock(guild.id, uid):
                if self.exempt(guild, uid, self.store.config(guild.id)):
                    continue
                try:
                    target = await guild.fetch_member(uid)
                    result = await self.auto_timeout(target, 10, 'Guardian: 대량 입장 보호')
                except discord.NotFound:
                    continue
                except (UserError, discord.HTTPException) as exc:
                    result = fail_text(exc, '실패')
                await self.record(guild, uid, '대량 입장 보호', result + ' / 경고 점수는 추가하지 않습니다.')

    async def audit_alert(self, entry):
        """봇 추가·권한 상승 같은 관리 변경을 기록한다. 경보만 하고 자동 처분은 하지 않는다."""
        guild = entry.guild
        cfg = self.store.config(guild.id)
        now = time.time()
        if (not cfg['alerts_enabled'] or entry.user_id == (self.user.id if self.user else 0)
                or not -5 <= now - entry.created_at.timestamp() <= 60):
            return
        info = describe_audit_entry(entry)
        if info is None or not self.store.audit_once(entry.id, now):
            return
        title, detail, critical = info
        await self.record(guild, entry.user_id, title, detail, critical=critical)

    async def on_audit_log_entry_create(self, entry):
        if entry.user_id is None or not self.allowed_guild(entry.guild.id):
            return
        if entry.action in ALERT_ACTIONS:
            await self.audit_alert(entry)
            return
        if entry.action not in NUKE_ACTIONS:
            return
        guild, uid = entry.guild, entry.user_id
        cfg = self.store.config(guild.id)
        now = time.time()
        age = now - entry.created_at.timestamp()
        if (not cfg['nuke_enabled'] or not protection_active(cfg, now) or self.exempt(guild, uid, cfg)
                or not -5 <= age <= 60):
            return
        if not self.store.audit_once(entry.id, now):
            return
        # Count original event timestamps, so delayed unrelated events are not clustered.
        recent = self.windows.add(('nuke', guild.id, uid), now, 60, (entry.created_at.timestamp(), entry.action.name))
        events = [v for _, v in recent if now - 20 <= v[0] <= now + 5]
        if len(events) < cfg['nuke_limit'] or not self.windows.ready(('nuke_action', guild.id, uid), now, 20):
            return
        async with self.lock(guild.id, uid):
            if self.exempt(guild, uid, self.store.config(guild.id)):
                return
            try:
                actor = await guild.fetch_member(uid)
                me = guild.me
                if me is None:
                    raise UserError('봇 서버 정보 없음')
                check_target(None, actor, me)
                need_permission(me, 'ban_members')
                await actor.ban(reason='Guardian: 감사 로그상 20초 내 위험 관리 작업 한도 초과', delete_message_seconds=0)
                result = '실행자 서버 차단 완료'
            except discord.NotFound:
                result = '실행자가 이미 서버를 떠나 조치를 생략했습니다.'
            except (UserError, discord.HTTPException) as exc:
                result = fail_text(exc, '차단 실패')
            await self.record(guild, uid, '대량 파괴 감지',
                              f'20초 내 {len(events)}회: {", ".join(v[1] for v in events)}\n{result}\n이미 삭제된 채널·역할·메시지는 복원되지 않습니다.',
                              critical=True)

    def register_commands(self):
        tree = self.tree

        @tree.command(name='도움말', description='명령어와 기본 보안 동작을 확인합니다.')
        @app_commands.guild_only()
        async def help_command(i: discord.Interaction):
            await reply(i, '**Guardian — 보안·관리 봇**\n'
                '`/경고추가` `/경고감소` `/경고조회` `/경고집행`\n'
                '`/경고한도` `/경고처분` `/타임아웃` `/타임아웃해제`\n'
                '`/보안설정` `/보안전체` `/보안패널` `/감지기준` `/보안예외` `/차단도메인` `/차단확장자` `/로그설정` `/상태` `/보안점검`\n\n'
                '`/화이트리스트추가` `/화이트리스트제거` `/화이트리스트조회` — 관리자 전용\n'
                '화이트리스트: 경고·타임아웃 부여·경고 처분·모든 자동 보안 대응 제외.\n\n'
                '`/채널화이트리스트추가` `/채널화이트리스트제거` `/채널화이트리스트조회` — 관리자 전용\n'
                '채널 화이트리스트: 해당 채널·하위 스레드의 도배·멘션 감지 제외. 차단 링크는 계속 검사·제재.\n'
                '경고 명령 결과는 해당 채널에 공개되며 사용자 이름으로 표시됩니다.\n\n'
                '기본: 경고 5점에서 서버 차단, 타임아웃 최대 20일.\n'
                '수동 경고 추가 후 관리자 DM 확인: 추가 1·2·3·4점 → 타임아웃 1·3·5·15일.\n'
                '도배 감지: 감지 메시지 삭제 + 10분 타임아웃 + 경고 1점(멤버당 60초 간격).\n'
                '대량 입장: 10초 내 10명 → 최근/신규 입장자 10분 타임아웃.\n'
                '대량 파괴: 동일 실행자의 채널/역할 삭제·추방·차단 합계 20초 내 3회 → 실행자 차단.\n'
                '추가 보안: 위험 첨부 파일(exe 등) 삭제 · 여러 채널 동일 문구 감지 · 초대 링크/신규 멤버 링크 제한(선택) · '
                '신규 계정 보호(선택) · 봇 추가·권한 상승 경보.\n'
                '계정 해킹 자체, 봇보다 높은 역할, 오프라인 중 공격은 막을 수 없습니다.')

        @tree.command(name='경고추가', description='경고를 추가합니다. 한도 이상이면 설정된 추방 또는 차단을 실행합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(moderate_members=True)
        @app_commands.rename(member='대상', points='수치', reason='사유')
        async def warn_add(i: discord.Interaction, member: discord.Member,
                           points: app_commands.Range[int, 1, 1000] = 1,
                           reason: app_commands.Range[str, 1, 300] = '사유 미입력'):
            actor = await self.authorize(i, 'moderate_members', ephemeral=False)
            async with self.lock(i.guild_id, member.id):
                member = await i.guild.fetch_member(member.id)
                check_target(actor, member, i.guild.me)
                result = await self.change_warning(member, points, reason, actor)
                case_id = self.store.history(i.guild_id, member.id)[0]['id']
            name = discord.utils.escape_markdown(member.name)
            await reply(i, f'{name}에게 {points}만큼 경고를 넣었습니다.\n\n{result}', ephemeral=False)
            await self.send_timeout_offer(i, member, actor, points, case_id)

        @tree.command(name='경고감소', description='경고를 감소시킵니다. 최솟값은 0점입니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(moderate_members=True)
        @app_commands.rename(member='대상', points='수치', reason='사유')
        async def warn_remove(i: discord.Interaction, member: discord.Member,
                              points: app_commands.Range[int, 1, 1000] = 1,
                              reason: app_commands.Range[str, 1, 300] = '경고 감소'):
            actor = await self.authorize(i, 'moderate_members', ephemeral=False)
            async with self.lock(i.guild_id, member.id):
                member = await i.guild.fetch_member(member.id)
                check_target(actor, member, i.guild.me)
                result = await self.change_warning(member, -points, reason, actor)
            await reply(i, result + '\n이미 실행된 추방·차단·타임아웃은 자동 해제되지 않습니다.', ephemeral=False)

        @tree.command(name='경고조회', description='본인 또는 관리 대상의 경고와 최근 10개 기록을 확인합니다.')
        @app_commands.guild_only()
        @app_commands.rename(user='대상')
        async def warn_view(i: discord.Interaction, user: discord.User | None = None):
            actor = await self.authorize(i, ephemeral=False)
            user = user or actor
            if user.id != actor.id:
                need_permission(actor, 'moderate_members')
            cfg = self.store.config(i.guild_id)
            history = self.store.history(i.guild_id, user.id)
            lines = [f'대상: {warning_name(user)} / 경고 **{self.store.points(i.guild_id, user.id)}/{cfg["warn_limit"]}** / 한도 처분: {ACTION_LABEL[cfg["warn_action"]]}']
            if user.id in cfg['trusted_ids']:
                lines.append('화이트리스트 등록 중: 신규 경고·경고 처분이 면제됩니다. 아래는 기존 기록입니다.')
            for row in history:
                reason = discord.utils.escape_markdown(row['reason']).replace('\n', ' ')[:55]
                result = row['result'][:65]
                lines.append(f'#{row["id"]} · {row["delta"]:+d} → {row["total"]}점 · {reason} · {result}')
            if not history:
                lines.append('기록이 없습니다.')
            await reply(i, '\n'.join(lines), ephemeral=False)

        @tree.command(name='경고집행', description='현재 경고가 한도 이상인 멤버의 처분을 다시 시도합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(moderate_members=True)
        @app_commands.rename(member='대상')
        async def warn_enforce(i: discord.Interaction, member: discord.Member):
            actor = await self.authorize(i, 'moderate_members', ephemeral=False)
            async with self.lock(i.guild_id, member.id):
                member = await i.guild.fetch_member(member.id)
                self.ensure_not_whitelisted(member)
                cfg = self.store.config(i.guild_id)
                if self.store.points(i.guild_id, member.id) < cfg['warn_limit']:
                    raise UserError('현재 경고가 한도 미만입니다.')
                check_target(actor, member, i.guild.me)
                need_permission(actor, 'ban_members' if cfg['warn_action'] == 'ban' else 'kick_members')
                _, case = self.store.change(i.guild_id, member.id, actor.id, 0, '경고 처분 재시도', '처분 대기')
                try:
                    result = await self.enforce_warning(member, cfg['warn_action'], actor)
                except (UserError, discord.HTTPException) as exc:
                    result = '처분 실패: ' + (str(exc) if isinstance(exc, UserError) else f'Discord 코드 {exc.code}')
                self.store.outcome(case, result)
                await self.record(i.guild, member.id, '경고 처분 재시도',
                                  f'실행자 {warning_name(actor)} / 기록 #{case} / {result}',
                                  target_name=warning_name(member))
            await reply(i, f'{warning_name(member)}: {result}', ephemeral=False)

        @tree.command(name='경고한도', description='서버 경고 한도를 변경합니다. 기본값은 5입니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(limit='수치')
        async def warn_limit(i: discord.Interaction, limit: app_commands.Range[int, 1, 1000]):
            actor = await self.authorize(i, 'administrator', ephemeral=False)
            self.store.setting(i.guild_id, warn_limit=limit)
            await self.record(i.guild, actor.id, '경고 설정 변경', f'경고 한도 → {limit}', target_name=warning_name(actor))
            await reply(i, f'경고 한도를 {limit}점으로 변경했습니다.\n기존 멤버를 즉시 처분하지 않습니다. 다음 경고 추가 또는 /경고집행 때 적용됩니다.', ephemeral=False)

        @tree.command(name='경고처분', description='경고 한도 도달 시 추방 또는 서버 차단 중 하나를 고릅니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(action='방식')
        @app_commands.choices(action=[app_commands.Choice(name='추방 — 재입장 가능', value='kick'),
                                      app_commands.Choice(name='서버 차단 — 재입장 금지', value='ban')])
        async def warn_action(i: discord.Interaction, action: app_commands.Choice[str]):
            actor = await self.authorize(i, 'administrator', ephemeral=False)
            self.store.setting(i.guild_id, warn_action=action.value)
            await self.record(i.guild, actor.id, '경고 설정 변경', f'한도 처분 → {ACTION_LABEL[action.value]}', target_name=warning_name(actor))
            await reply(i, f'한도 처분을 {ACTION_LABEL[action.value]}으로 변경했습니다. 기존 경고는 유지됩니다.', ephemeral=False)

        @tree.command(name='타임아웃', description='수치와 분·시간·일을 선택합니다. 최대 20일입니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(moderate_members=True)
        @app_commands.rename(member='대상', amount='수치', unit='단위', reason='사유')
        @app_commands.choices(unit=[app_commands.Choice(name='분', value='minutes'),
                                    app_commands.Choice(name='시간', value='hours'),
                                    app_commands.Choice(name='일', value='days')])
        async def timeout(i: discord.Interaction, member: discord.Member,
                          amount: app_commands.Range[int, 1, 28800], unit: app_commands.Choice[str],
                          reason: app_commands.Range[str, 1, 300] = '사유 미입력'):
            actor = await self.authorize(i, 'moderate_members')
            duration = timeout_duration(amount, unit.value)
            async with self.lock(i.guild_id, member.id):
                member = await i.guild.fetch_member(member.id)
                self.ensure_not_whitelisted(member)
                check_target(actor, member, i.guild.me)
                need_permission(i.guild.me, 'moderate_members')
                if member.guild_permissions.administrator or member.bot:
                    raise UserError('관리자 또는 봇 계정에는 타임아웃을 적용할 수 없습니다.')
                until = discord.utils.utcnow() + duration
                await member.timeout(until, reason=f'{actor.id}: {reason}'[:400])
                detail = f'{amount}{unit.name} 타임아웃 / 종료 <t:{int(until.timestamp())}:F>\n실행자 {actor.id} / 사유: {reason}'
                await self.record(i.guild, member.id, '타임아웃', detail)
            await reply(i, detail + '\n기존 타임아웃이 있었다면 방금 입력한 기간으로 교체됩니다.')

        @tree.command(name='타임아웃해제', description='멤버의 타임아웃을 해제합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(moderate_members=True)
        @app_commands.rename(member='대상', reason='사유')
        async def timeout_remove(i: discord.Interaction, member: discord.Member,
                                 reason: app_commands.Range[str, 1, 300] = '관리자 해제'):
            actor = await self.authorize(i, 'moderate_members')
            async with self.lock(i.guild_id, member.id):
                member = await i.guild.fetch_member(member.id)
                check_target(actor, member, i.guild.me)
                need_permission(i.guild.me, 'moderate_members')
                await member.timeout(None, reason=f'{actor.id}: {reason}'[:400])
                await self.record(i.guild, member.id, '타임아웃 해제', f'실행자 {actor.id} / 사유: {reason}')
            await reply(i, '타임아웃을 해제했습니다.')

        @tree.command(name='보안설정', description='서버 주인 전용: 보안 기능을 켜거나 끕니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(feature='기능', enabled='활성화')
        @app_commands.choices(feature=FEATURE_CHOICES)
        async def security(i: discord.Interaction, feature: app_commands.Choice[str], enabled: bool):
            actor = await self.authorize(i, owner=True)
            result = await self.set_feature(i.guild, actor, feature.value, enabled)
            await reply(i, f'{result}. 이미 적용된 처분은 유지됩니다.')

        @tree.command(name='보안전체', description='서버 주인 전용: 모든 자동 보안을 일시정지하거나 다시 켭니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(state='상태', minutes='분')
        @app_commands.describe(minutes='끌 때 자동으로 다시 켤 시간(분). 0이면 직접 켤 때까지 꺼짐')
        @app_commands.choices(state=[app_commands.Choice(name='켜기', value='on'),
                                     app_commands.Choice(name='끄기(일시정지)', value='off')])
        async def security_master(i: discord.Interaction, state: app_commands.Choice[str],
                                  minutes: app_commands.Range[int, 0, 1440] = 60):
            actor = await self.authorize(i, owner=True)
            result = await self.set_master(i.guild, actor, state.value == 'on', minutes)
            await reply(i, result + '\n수동 명령과 관리 변경 경보는 계속 동작하며, 이미 적용된 처분은 유지됩니다.')

        @tree.command(name='보안패널', description='서버 주인 전용: 버튼으로 보안 기능을 켜고 끕니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        async def security_panel(i: discord.Interaction):
            actor = await self.authorize(i, owner=True)
            view = SecurityPanel(self, i.guild_id, actor.id)
            view.interaction = i
            await i.followup.send(view.content(), view=view, ephemeral=True,
                                  allowed_mentions=discord.AllowedMentions.none())

        @tree.command(name='감지기준', description='서버 주인 전용: 자동 감지 횟수·인원 기준을 변경합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(item='항목', value='수치')
        @app_commands.choices(item=LIMIT_CHOICES)
        async def thresholds(i: discord.Interaction, item: app_commands.Choice[str], value: app_commands.Range[int, 0, 1440]):
            actor = await self.authorize(i, owner=True)
            low, high = LIMIT_RANGES[item.value]
            if not low <= value <= high:
                raise UserError(f'{item.name}은(는) {low}~{high} 사이로 입력하세요.')
            self.store.setting(i.guild_id, **{item.value: value})
            await self.record(i.guild, actor.id, '감지 기준 변경', f'{item.name}: {value}')
            await reply(i, f'{item.name} 기준을 {value}(으)로 변경했습니다.')

        @tree.command(name='화이트리스트추가', description='관리자 전용: 경고·타임아웃·자동 보안 대응을 면제할 대상을 등록합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(member='대상')
        async def whitelist_add(i: discord.Interaction, member: discord.Member):
            actor = await self.authorize(i, 'administrator')
            await reply(i, await self.set_whitelist(i.guild, member.id, True, actor))

        @tree.command(name='화이트리스트제거', description='관리자 전용: 화이트리스트에서 대상을 제거합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(user='대상')
        async def whitelist_remove(i: discord.Interaction, user: discord.User):
            actor = await self.authorize(i, 'administrator')
            await reply(i, await self.set_whitelist(i.guild, user.id, False, actor))

        @tree.command(name='화이트리스트조회', description='관리자 전용: 서버 화이트리스트를 20명씩 확인합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(page='페이지')
        async def whitelist_view(i: discord.Interaction, page: app_commands.Range[int, 1, 5] = 1):
            await self.authorize(i, 'administrator')
            ids = sorted(self.store.config(i.guild_id)['trusted_ids'])
            await reply(i, page_lines(ids, page, '화이트리스트', '명', lambda uid: f'<@{uid}> · ID {uid}'))

        @tree.command(name='채널화이트리스트추가', description='관리자 전용: 채널·하위 스레드의 도배·멘션 감지를 제외합니다. 차단 링크는 검사합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(channel='채널')
        async def channel_whitelist_add(i: discord.Interaction, channel: WhitelistChannel):
            actor = await self.authorize(i, 'administrator')
            await reply(i, await self.set_channel_whitelist(i.guild, channel, True, actor))

        @tree.command(name='채널화이트리스트제거', description='관리자 전용: 채널 화이트리스트에서 채널을 제거합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(channel='채널')
        async def channel_whitelist_remove(i: discord.Interaction, channel: WhitelistChannel):
            actor = await self.authorize(i, 'administrator')
            await reply(i, await self.set_channel_whitelist(i.guild, channel, False, actor))

        @tree.command(name='채널화이트리스트조회', description='관리자 전용: 등록된 채널을 20개씩 확인합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(page='페이지')
        async def channel_whitelist_view(i: discord.Interaction, page: app_commands.Range[int, 1, 5] = 1):
            await self.authorize(i, 'administrator')
            ids = sorted(self.store.config(i.guild_id)['trusted_channel_ids'])
            await reply(i, page_lines(ids, page, '채널 화이트리스트', '개', lambda cid: f'<#{cid}>',
                                      footer='하위 스레드도 도배·멘션·초대 링크 감지를 제외합니다. '
                                             '차단 링크와 위험 첨부 파일은 계속 검사·제재합니다.'))

        @tree.command(name='보안예외', description='관리자 전용: 화이트리스트 추가·제거의 기존 호환 명령어입니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(member='대상', enabled='예외여부')
        async def trust(i: discord.Interaction, member: discord.Member, enabled: bool):
            actor = await self.authorize(i, 'administrator')
            await reply(i, await self.set_whitelist(i.guild, member.id, enabled, actor))

        @tree.command(name='차단도메인', description='서버 주인 전용: 알려진 위험 도메인을 추가·제거합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(domain='도메인', enabled='차단여부')
        async def domain(i: discord.Interaction, domain: str, enabled: bool):
            actor = await self.authorize(i, owner=True)
            domain = normalize_domain(domain)
            domains = set(self.store.config(i.guild_id)['blocked_domains'])
            if enabled:
                if len(domains) >= 100 and domain not in domains:
                    raise UserError('도메인은 최대 100개입니다.')
                domains.add(domain)
            else:
                domains.discard(domain)
            self.store.setting(i.guild_id, blocked_domains=sorted(domains))
            await self.record(i.guild, actor.id, '차단 도메인 변경', f'{domain}: {enabled}')
            await reply(i, f'`{domain}` 및 하위 도메인 차단 {"등록" if enabled else "해제"}.\n목록에 없는 피싱 사이트나 단축 URL의 최종 목적지는 판별하지 않습니다.')

        @tree.command(name='차단확장자', description='서버 주인 전용: 삭제할 첨부 파일 확장자를 추가·제거합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(extension='확장자', enabled='차단여부')
        async def blocked_extension(i: discord.Interaction, extension: str, enabled: bool):
            actor = await self.authorize(i, owner=True)
            ext = normalize_extension(extension)
            extensions = set(self.store.config(i.guild_id)['blocked_extensions'])
            if enabled:
                if len(extensions) >= 50 and ext not in extensions:
                    raise UserError('확장자는 최대 50개입니다.')
                extensions.add(ext)
            else:
                extensions.discard(ext)
            self.store.setting(i.guild_id, blocked_extensions=sorted(extensions))
            await self.record(i.guild, actor.id, '차단 확장자 변경', f'.{ext}: {enabled}')
            await reply(i, f'`.{ext}` 첨부 파일 차단 {"등록" if enabled else "해제"}.\n'
                           '마지막 확장자를 기준으로 검사하며(예: invoice.pdf.exe), 압축 파일 내부는 검사하지 않습니다.')

        @tree.command(name='로그설정', description='서버 주인 전용: 보안·경고 기록을 보낼 채널을 설정합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        @app_commands.rename(channel='채널')
        async def log_channel(i: discord.Interaction, channel: discord.TextChannel):
            actor = await self.authorize(i, owner=True)
            if channel.guild.id != i.guild_id:
                raise UserError('같은 서버의 채널을 선택해주세요.')
            perms = channel.permissions_for(i.guild.me)
            if not (perms.view_channel and perms.send_messages and perms.embed_links):
                raise UserError('선택한 채널에서 봇의 채널 보기·메시지 보내기·링크 첨부 권한이 필요합니다.')
            # Test delivery before persisting; use the normal response on failure.
            await channel.send('Guardian 로그 채널로 설정되었습니다.', allowed_mentions=discord.AllowedMentions.none())
            self.store.setting(i.guild_id, log_channel_id=channel.id)
            await self.record(i.guild, actor.id, '로그 설정 변경', f'채널 ID {channel.id}')
            note = ''
            if channel.permissions_for(i.guild.default_role).view_channel:
                note = '\n⚠️ 이 채널은 모든 멤버가 볼 수 있습니다. 경고·보안 기록이 공개되니 운영진 전용으로 바꾸세요.'
            await reply(i, f'{channel.mention}에 기록합니다. 운영진만 볼 수 있는 채널을 권장합니다.{note}')

        @tree.command(name='보안점검', description='관리자 전용: 서버 보안 설정을 읽기 전용으로 점검합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        async def checkup(i: discord.Interaction):
            await self.authorize(i, 'administrator')
            items = run_checkup(i.guild, self.store.config(i.guild_id), i.guild.me, PERMISSION_LABEL, time.time())
            await reply(i, format_checkup(items))

        @tree.command(name='상태', description='관리자 전용: 설정, 감지 기준, 봇 권한을 확인합니다.')
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        async def status(i: discord.Interaction):
            await self.authorize(i, 'administrator')
            cfg = self.store.config(i.guild_id)
            me = i.guild.me
            missing = [label for key, label in PERMISSION_LABEL.items()
                       if key != 'administrator' and not getattr(me.guild_permissions, key)]
            domain_text = ', '.join(cfg['blocked_domains']) or '없음 — 링크 검사 목록이 비어 있습니다.'
            trusted_text = ', '.join(str(x) for x in cfg['trusted_ids']) or '없음'
            lines = [f'**Guardian 상태** · 응답 {latency_text(self.latency)}',
                     master_text(cfg, time.time()),
                     f'경고 {cfg["warn_limit"]}점 → {ACTION_LABEL[cfg["warn_action"]]} / 타임아웃 최대 20일',
                     f'로그 채널: {cfg["log_channel_id"] or "미설정(콘솔·DB에 기록)"}',
                     f'봇 역할: {me.top_role.name} / 아래에 있는 역할만 조치 가능',
                     '부족한 서버 권한: ' + (', '.join(missing) or '없음'),
                     '채널별 권한 덮어쓰기는 각 채널에서 별도 확인하세요.']
            lines += [f'{c.name}: {"켜짐" if cfg[c.value] else "꺼짐"}' for c in FEATURE_CHOICES]
            lines += [f'{c.name}: {cfg[c.value]}' for c in LIMIT_CHOICES]
            lines += [f'입장 보호: {"진행 중" if cfg["raid_until"] > time.time() else "대기"}',
                      f'화이트리스트 ID: {trusted_text[:400]}',
                      f'채널 화이트리스트: {len(cfg["trusted_channel_ids"])}개 · /채널화이트리스트조회',
                      f'차단 도메인: {domain_text[:500]}',
                      f'차단 확장자: {", ".join(cfg["blocked_extensions"]) or "없음"}'[:300]]
            await reply(i, '\n'.join(lines)[:1950])


def main():
    load_dotenv(BASE / '.env')
    token = os.getenv('DISCORD_TOKEN', '').strip()
    if not token or token == 'PUT_YOUR_BOT_TOKEN_HERE':
        raise SystemExit('.env.example을 .env로 복사하고 DISCORD_TOKEN을 입력해주세요. 토큰을 채팅에 올리지 마세요.')
    raw_guild = os.getenv('GUILD_ID', '').strip() or os.getenv('TEST_GUILD_ID', '').strip()
    if not raw_guild.isdigit() or int(raw_guild) <= 0:
        raise SystemExit('.env의 GUILD_ID에 사용할 서버 ID 숫자를 입력해주세요. 기존 TEST_GUILD_ID도 호환됩니다.')
    path = Path(os.getenv('DATABASE_PATH', 'data/guardian.sqlite3'))
    if not path.is_absolute():
        path = BASE / path
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    store = Store(path)
    client = Guardian(store, int(raw_guild), backup_dir=path.parent / 'backups')
    try:
        client.run(token, log_handler=None)
    except discord.LoginFailure:
        raise SystemExit('봇 토큰이 유효하지 않습니다. Developer Portal에서 토큰을 확인해주세요.')
    except discord.PrivilegedIntentsRequired:
        raise SystemExit('Developer Portal에서 Server Members Intent와 Message Content Intent를 켜주세요.')
    except aiohttp.ClientConnectorError:
        raise SystemExit('디스코드에 연결할 수 없습니다. 인터넷 연결과 방화벽·프록시 설정을 확인해주세요.')
    finally:
        store.close()


if __name__ == '__main__':
    main()
