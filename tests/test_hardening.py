"""보안 강화·성능 개선 항목 테스트. 실제 디스코드 연결 없이 가짜 객체로 검증한다."""
import json
import os
import sqlite3
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

import discord
from discord.audit_logs import AuditLogDiff

from bot import Guardian, PERMISSION_LABEL, UserError, message_files, message_text
from checkup import describe_audit_entry, format_checkup, run_checkup
from core import (DEFAULTS, Store, Windows, blocked_attachment, blocked_link, has_link,
                  newcomer_violation, INVITE_RE)

EXTS = DEFAULTS['blocked_extensions']


class PureDetectionTests(unittest.TestCase):
    def test_bare_domains_are_detected_but_lookalikes_are_not(self):
        domains = ['example.com']
        for text in ['visit example.com/claim now', 'SUB.EXAMPLE.COM', 'go to example.com.',
                     '(example.com)', 'a.b.example.com:8080/x']:
            self.assertEqual(blocked_link(text, domains), 'example.com', text)
        for text in ['notexample.com', 'a.notexample.com', 'example.community', 'mail me@example.com',
                     'example.com.safe.test', 'example.com-evil.net', 'https://safe.test/?u=example.com',
                     'example.com@good.test', 'hello world']:
            self.assertIsNone(blocked_link(text, domains), text)
        # 기존 동작: 스킴 링크는 실제 호스트 기준.
        self.assertEqual(blocked_link('https://good.test@example.com/', domains), 'example.com')
        self.assertIsNone(blocked_link('https://example.com@good.test', domains))

    def test_invite_links(self):
        for text in ['discord.gg/abc123', 'https://discord.com/invite/abc', 'HTTP://DISCORDAPP.COM/invite/x1',
                     'dsc.gg/xy', 'join: www.discord.gg/korea']:
            self.assertTrue(INVITE_RE.search(text), text)
        for text in ['notdiscord.gg/abc', 'https://discord.com/channels/1/2', 'discord.gg', 'discord.gg/a',
                     'mydiscord.gg/xyz', 'discord.com']:
            self.assertIsNone(INVITE_RE.search(text), text)

    def test_attachment_extensions(self):
        for names in [['a.exe'], ['invoice.pdf.exe'], ['PHOTO.EXE'], ['x.scr '], ['a.exe.'], ['ok.png', 'b.bat']]:
            self.assertIsNotNone(blocked_attachment(names, EXTS), names)
        for names in [['a.png'], ['exe'], ['a.exe.png'], [], ['readme']]:
            self.assertIsNone(blocked_attachment(names, EXTS), names)
        self.assertIsNone(blocked_attachment(['a.exe'], []))

    def test_links_for_newcomer_check(self):
        for text in ['https://a.test', 'foo.xyz/abc', 'discord.gg/abc', 'www.site.test']:
            self.assertTrue(has_link(text), text)
        for text in ['hello', 'file.py', 'node.js', 'e.g. this', 'a@b.com']:
            self.assertFalse(has_link(text), text)
        now = datetime.now(timezone.utc)
        recent = now - timedelta(minutes=2)
        self.assertIn('신규 멤버', newcomer_violation(recent, now, 10, 'https://a.test', False))
        self.assertIn('신규 멤버', newcomer_violation(recent, now, 10, 'hi', True))
        self.assertIsNone(newcomer_violation(recent, now, 10, 'hi', False))
        self.assertIsNone(newcomer_violation(now - timedelta(minutes=20), now, 10, 'https://a.test', True))
        self.assertIsNone(newcomer_violation(recent, now, 0, 'https://a.test', True))
        self.assertIsNone(newcomer_violation(None, now, 10, 'https://a.test', True))

    def test_cross_channel_repeat(self):
        text = 'free discord nitro claim here now'
        w = Windows()
        results = [w.message_violation(1, 2, text, 0, False, DEFAULTS, 100 + i * 60, channel_id=10 + i)
                   for i in range(3)]
        self.assertEqual(results[:2], [None, None])
        self.assertIn('여러 채널', results[2])
        # 같은 채널의 반복은 교차 채널 규칙이 아니다.
        w = Windows()
        self.assertEqual([w.message_violation(1, 2, text, 0, False, DEFAULTS, 100 + i * 60, channel_id=10)
                          for i in range(3)], [None] * 3)
        # 짧은 말과 서로 다른 문장은 제외.
        w = Windows()
        for n in range(6):
            self.assertIsNone(w.message_violation(1, 2, 'lol', 0, False, DEFAULTS, 100 + n * 20, channel_id=n))
            self.assertIsNone(w.message_violation(1, 3, f'a different long message number {n}', 0, False,
                                                  DEFAULTS, 100 + n * 20, channel_id=n))
        # 10분이 지나면 창이 만료된다.
        w = Windows()
        self.assertIsNone(w.message_violation(1, 2, text, 0, False, DEFAULTS, 100, channel_id=1))
        self.assertIsNone(w.message_violation(1, 2, text, 0, False, DEFAULTS, 300, channel_id=2))
        self.assertIsNone(w.message_violation(1, 2, text, 0, False, DEFAULTS, 800, channel_id=3))
        # 서버·사용자 분리.
        w = Windows()
        for n, (g, u) in enumerate([(1, 2), (2, 2), (1, 3)]):
            self.assertIsNone(w.message_violation(g, u, text, 0, False, DEFAULTS, 100 + n, channel_id=n))

    def test_long_windows_survive_cleanup_and_expire_later(self):
        w = Windows()
        w.add(('cross', 1, 2), 100, 600)
        w.clean(500)
        self.assertIn(('cross', 1, 2), w.events)
        w.clean(800)
        self.assertNotIn(('cross', 1, 2), w.events)
        self.assertNotIn(('cross', 1, 2), w.horizon)

    def test_invite_and_file_rules_in_violation_checker(self):
        w = Windows()
        on = {**DEFAULTS, 'invites_enabled': True}
        self.assertIsNone(w.message_violation(1, 2, 'discord.gg/abcd', 0, False, DEFAULTS, 100))
        self.assertIn('초대', w.message_violation(1, 2, 'discord.gg/abcd', 0, False, on, 101))
        self.assertIn('.exe', w.message_violation(1, 2, 'hi', 0, False, DEFAULTS, 102, filenames=['x.exe']))
        off = {**DEFAULTS, 'files_enabled': False}
        self.assertIsNone(w.message_violation(1, 3, 'hi', 0, False, off, 103, filenames=['x.exe']))
        # 도배 기능을 꺼도 링크·파일 규칙은 독립적으로 동작한다.
        no_spam = {**DEFAULTS, 'spam_enabled': False}
        self.assertIn('.exe', w.message_violation(1, 4, 'hi', 0, False, no_spam, 104, filenames=['x.exe']))


class StoreHardeningTests(unittest.TestCase):
    def test_validation_rejects_bad_values_and_keeps_old(self):
        s = Store(':memory:')
        bad = [dict(crosspost_limit=1), dict(account_age_days=21), dict(account_age_days=-1),
               dict(newcomer_minutes=1441), dict(spam_limit=True), dict(blocked_extensions=['EXE']),
               dict(blocked_extensions=['a b']), dict(blocked_extensions='exe'),
               dict(blocked_extensions=['a'] * 51)]
        for changes in bad:
            with self.assertRaises(ValueError, msg=str(changes)):
                s.setting(1, **changes)
        self.assertEqual(s.config(1)['account_age_days'], 0)
        with self.assertRaises(ValueError):
            s.setting(1, nonexistent=1)
        s.close()

    def test_config_cache_is_isolated_and_updates(self):
        s = Store(':memory:')
        cfg = s.config(1)
        cfg['trusted_ids'].append(5)
        cfg['blocked_extensions'].append('zzz')
        self.assertEqual(s.config(1)['trusted_ids'], [])
        self.assertNotIn('zzz', s.config(1)['blocked_extensions'])
        s.setting(1, account_age_days=3)
        self.assertEqual(s.config(1)['account_age_days'], 3)
        self.assertEqual(s.config(2)['account_age_days'], 0)
        s.close()

    def test_new_settings_persist_and_old_rows_get_defaults(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'db.sqlite3'
            s = Store(path)
            s.setting(1, invites_enabled=True, newcomer_minutes=15, blocked_extensions=['exe', 'docm'])
            with s.db:  # 이전 버전이 저장한 것처럼 새 항목이 없는 JSON.
                s.db.execute('INSERT INTO settings VALUES(?,?)', (7, json.dumps({'warn_limit': 9})))
            s.close()
            s = Store(path)
            cfg = s.config(1)
            self.assertEqual((cfg['invites_enabled'], cfg['newcomer_minutes'], cfg['blocked_extensions']),
                             (True, 15, ['exe', 'docm']))
            old = s.config(7)
            self.assertEqual(old['warn_limit'], 9)
            self.assertTrue(old['files_enabled'])
            self.assertFalse(old['invites_enabled'])
            self.assertEqual(old['account_age_days'], 0)
            self.assertIn('exe', old['blocked_extensions'])
            s.close()

    def test_backup_is_consistent_rotated_and_rate_limited(self):
        with tempfile.TemporaryDirectory() as temp:
            s = Store(Path(temp) / 'db.sqlite3')
            s.change(1, 2, 3, 4, 'x')
            s.setting(1, warn_limit=8)
            backups = Path(temp) / 'backups'
            now = time.time()
            first = s.backup_if_due(backups, now=now)
            self.assertTrue(first.exists())
            restored = sqlite3.connect(first)
            self.assertEqual(restored.execute('SELECT points FROM warnings').fetchone()[0], 4)
            restored.close()
            self.assertIsNone(s.backup_if_due(backups, now=now + 100))
            for k in range(1, 8):
                self.assertIsNotNone(s.backup_if_due(backups, keep=3, now=now + k * 2 * 86400))
            self.assertEqual(len(list(backups.glob('guardian-*.sqlite3'))), 3)
            s.close()
        memory = Store(':memory:')
        self.assertIsNone(memory.backup_if_due('unused'))
        memory.close()


class HardeningBotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store = Store(':memory:')
        self.bot = Guardian(self.store)
        self.bot._connection.user = NS(id=999)
        self.bot.record = AsyncMock()
        self.guild = NS(id=100, owner_id=1, name='테스트 서버', default_role=NS(id=100))
        self.guild.me = NS(id=999, top_role=10, guild_permissions=discord.Permissions.all())
        self.member = self.make_member(20)
        self.guild.fetch_member = AsyncMock(return_value=self.member)
        self.actor = NS(id=5, name='moderator', top_role=8, guild_permissions=discord.Permissions.all(),
                        send=AsyncMock())
        self.channel = NS(id=400, guild=self.guild, mention='<#400>', send=AsyncMock(), fetch_message=AsyncMock())
        self.interaction = NS(guild=self.guild, guild_id=100, response=NS(is_done=lambda: True),
                              followup=NS(send=AsyncMock()))

    async def asyncTearDown(self):
        await self.bot.close()
        self.store.close()

    def make_member(self, uid, **changes):
        values = dict(id=uid, name=f'user{uid}', guild=self.guild, top_role=3, bot=False,
                      guild_permissions=discord.Permissions.none(), timed_out_until=None,
                      ban=AsyncMock(), kick=AsyncMock(), timeout=AsyncMock())
        values.update(changes)
        return NS(**values)

    def make_message(self, content='hello', channel=None, author=None, attachments=(), **changes):
        values = dict(guild=self.guild, channel=channel or self.channel, author=author or self.member,
                      content=content, mentions=[], role_mentions=[], mention_everyone=False,
                      webhook_id=None, delete=AsyncMock(), attachments=list(attachments))
        values.update(changes)
        return NS(**values)

    def new_channel(self, cid):
        return NS(id=cid, send=AsyncMock())

    # ---------- 첨부 파일 ----------
    async def test_dangerous_attachment_is_deleted_and_penalized(self):
        message = self.make_message('보세요', attachments=[NS(filename='invoice.pdf.exe')])
        await self.bot.on_message(message)
        message.delete.assert_awaited_once()
        self.member.timeout.assert_awaited_once()
        self.assertEqual(self.store.points(100, 20), 1)
        self.assertIn('위험 파일 형식(.exe)', self.channel.send.call_args.args[0])

    async def test_dangerous_attachment_enforced_in_whitelisted_channel_but_harmless_files_pass(self):
        self.store.setting(100, trusted_channel_ids=[400])
        harmless = self.make_message('사진', attachments=[NS(filename='cat.png')])
        await self.bot.on_message(harmless)
        harmless.delete.assert_not_awaited()
        danger = self.make_message('파일', attachments=[NS(filename='setup.bat')])
        await self.bot.on_message(danger)
        danger.delete.assert_awaited_once()

    async def test_attachment_filter_toggle_and_user_whitelist(self):
        self.store.setting(100, files_enabled=False)
        message = self.make_message(attachments=[NS(filename='a.exe')])
        await self.bot.on_message(message)
        message.delete.assert_not_awaited()
        self.store.setting(100, files_enabled=True, trusted_ids=[20])
        message = self.make_message(attachments=[NS(filename='a.exe')])
        await self.bot.on_message(message)
        message.delete.assert_not_awaited()

    async def test_forwarded_content_is_scanned(self):
        self.store.setting(100, blocked_domains=['example.com'])
        snapshot = NS(content='go to https://example.com/x', attachments=[])
        message = self.make_message('전달', message_snapshots=[snapshot])
        await self.bot.on_message(message)
        message.delete.assert_awaited_once()
        other = self.make_member(21)
        message = self.make_message('전달', author=other, message_snapshots=[NS(content='', attachments=[NS(filename='x.scr')])])
        await self.bot.on_message(message)
        message.delete.assert_awaited_once()

    async def test_embed_text_is_scanned_only_for_bots_and_webhooks(self):
        embed = NS(url='', description='visit https://example.com now', fields=[NS(value='f')])
        human = self.make_message('hi', embeds=[embed])
        self.assertNotIn('example.com', message_text(human))
        bot_message = self.make_message('hi', embeds=[embed], webhook_id=5)
        self.assertIn('example.com', message_text(bot_message))
        self.assertEqual(message_files(self.make_message(attachments=[NS(filename='a.txt')])), ['a.txt'])

    async def test_bare_domain_message_is_deleted(self):
        self.store.setting(100, blocked_domains=['example.com'])
        message = self.make_message('무료 선물 example.com/claim')
        await self.bot.on_message(message)
        message.delete.assert_awaited_once()

    # ---------- 초대 링크 ----------
    async def test_invites_off_by_default_and_enforced_when_on(self):
        message = self.make_message('discord.gg/abcdef')
        await self.bot.on_message(message)
        message.delete.assert_not_awaited()
        self.store.setting(100, invites_enabled=True)
        message = self.make_message('discord.gg/abcdef')
        await self.bot.on_message(message)
        message.delete.assert_awaited_once()
        self.assertIn('디스코드 초대 링크', self.channel.send.call_args.args[0])

    async def test_channel_whitelist_exempts_invites_only_there(self):
        self.store.setting(100, invites_enabled=True, trusted_channel_ids=[400])
        allowed = self.make_message('discord.gg/abcdef')
        await self.bot.on_message(allowed)
        allowed.delete.assert_not_awaited()
        elsewhere = self.make_message('discord.gg/abcdef', channel=self.new_channel(401))
        await self.bot.on_message(elsewhere)
        elsewhere.delete.assert_awaited_once()

    async def test_edited_invite_is_rescanned(self):
        self.store.setting(100, invites_enabled=True)
        self.bot.get_guild = lambda gid: self.guild
        self.guild.get_channel_or_thread = lambda cid: self.channel
        message = self.make_message('discord.gg/abcdef')
        self.channel.fetch_message.return_value = message
        await self.bot.on_raw_message_edit(NS(guild_id=100, channel_id=400, message_id=1, data={'content': 'x'}))
        message.delete.assert_awaited_once()

    # ---------- 교차 채널 ----------
    async def test_same_text_in_three_channels_is_deleted_on_third(self):
        text = 'free discord nitro claim at the link'
        messages = [self.make_message(text, channel=self.new_channel(500 + n)) for n in range(3)]
        for message in messages:
            await self.bot.on_message(message)
        messages[0].delete.assert_not_awaited()
        messages[1].delete.assert_not_awaited()
        messages[2].delete.assert_awaited_once()
        self.assertEqual(self.store.points(100, 20), 1)

    # ---------- 신규 멤버 ----------
    async def test_newcomer_restriction(self):
        self.store.setting(100, newcomer_minutes=10)
        self.member.joined_at = discord.utils.utcnow() - timedelta(minutes=2)
        link = self.make_message('https://safe.test/a')
        await self.bot.on_message(link)
        link.delete.assert_awaited_once()
        plain = self.make_message('안녕하세요', author=self.make_member(21, joined_at=discord.utils.utcnow()))
        await self.bot.on_message(plain)
        plain.delete.assert_not_awaited()
        picture = self.make_message('사진', author=self.make_member(22, joined_at=discord.utils.utcnow()),
                                    attachments=[NS(filename='cat.png')])
        await self.bot.on_message(picture)
        picture.delete.assert_awaited_once()
        veteran = self.make_message('https://safe.test/a', author=self.make_member(
            23, joined_at=discord.utils.utcnow() - timedelta(hours=2)))
        await self.bot.on_message(veteran)
        veteran.delete.assert_not_awaited()

    async def test_newcomer_restriction_default_off_whitelist_and_edit(self):
        self.member.joined_at = discord.utils.utcnow()
        message = self.make_message('https://safe.test/a')
        await self.bot.on_message(message)
        message.delete.assert_not_awaited()
        self.store.setting(100, newcomer_minutes=10, trusted_ids=[20])
        message = self.make_message('https://safe.test/a')
        await self.bot.on_message(message)
        message.delete.assert_not_awaited()
        self.store.setting(100, trusted_ids=[])
        self.bot.get_guild = lambda gid: self.guild
        self.guild.get_channel_or_thread = lambda cid: self.channel
        edited = self.make_message('https://safe.test/a')
        self.channel.fetch_message.return_value = edited
        await self.bot.on_raw_message_edit(NS(guild_id=100, channel_id=400, message_id=2, data={'content': 'x'}))
        edited.delete.assert_awaited_once()

    # ---------- 신규 계정 보호 ----------
    async def test_new_account_is_timed_out_until_it_reaches_the_age(self):
        self.store.setting(100, account_age_days=3)
        member = self.make_member(30, created_at=discord.utils.utcnow() - timedelta(days=1))
        await self.bot.on_member_join(member)
        member.timeout.assert_awaited_once()
        until = member.timeout.call_args.args[0]
        self.assertLess(abs((until - (member.created_at + timedelta(days=3))).total_seconds()), 1)
        kinds = [c.args[2] for c in self.bot.record.await_args_list]
        self.assertIn('신규 계정 보호', kinds)
        self.assertEqual(self.store.points(100, 30), 0)

    async def test_new_account_protection_skips_old_default_exempt_and_longer_timeouts(self):
        old = self.make_member(31, created_at=discord.utils.utcnow() - timedelta(days=10))
        young = self.make_member(32, created_at=discord.utils.utcnow() - timedelta(days=1))
        await self.bot.on_member_join(young)           # 기본값 0=꺼짐
        young.timeout.assert_not_awaited()
        self.store.setting(100, account_age_days=3)
        await self.bot.on_member_join(old)
        old.timeout.assert_not_awaited()
        owner = self.make_member(1, created_at=discord.utils.utcnow())
        await self.bot.on_member_join(owner)
        owner.timeout.assert_not_awaited()
        self.store.setting(100, trusted_ids=[33])
        trusted = self.make_member(33, created_at=discord.utils.utcnow())
        await self.bot.on_member_join(trusted)
        trusted.timeout.assert_not_awaited()
        longer = self.make_member(34, created_at=discord.utils.utcnow() - timedelta(days=1),
                                  timed_out_until=discord.utils.utcnow() + timedelta(days=10))
        await self.bot.on_member_join(longer)
        longer.timeout.assert_not_awaited()
        almost = self.make_member(35, created_at=discord.utils.utcnow() - timedelta(days=3) + timedelta(seconds=20))
        await self.bot.on_member_join(almost)
        almost.timeout.assert_not_awaited()
        admin = self.make_member(36, created_at=discord.utils.utcnow(),
                                 guild_permissions=discord.Permissions(administrator=True))
        await self.bot.on_member_join(admin)
        admin.timeout.assert_not_awaited()

    async def test_new_account_protection_works_even_if_raid_detection_is_off(self):
        self.store.setting(100, account_age_days=2, raid_enabled=False)
        member = self.make_member(37, created_at=discord.utils.utcnow())
        await self.bot.on_member_join(member)
        member.timeout.assert_awaited_once()

    # ---------- 감사 로그 경보 ----------
    def audit(self, action, uid=20, entry_id=1, age=0, **extra):
        return NS(guild=self.guild, id=entry_id, user_id=uid, action=action, before=AuditLogDiff(),
                  after=AuditLogDiff(), created_at=datetime.now(timezone.utc) - timedelta(seconds=age), **extra)

    def last_alert(self):
        call = self.bot.record.await_args
        return call.args[2], call.args[3], call.kwargs.get('critical')

    async def test_bot_add_alert_is_critical(self):
        await self.bot.on_audit_log_entry_create(
            self.audit(discord.AuditLogAction.bot_add, target=NS(id=77, name='newbot')))
        title, detail, critical = self.last_alert()
        self.assertEqual((title, critical), ('봇 추가 감지', True))
        self.assertIn('newbot', detail)
        self.assertIn('<@20>', detail)

    async def test_role_permission_escalation_alerts(self):
        entry = self.audit(discord.AuditLogAction.role_update, target=NS(id=500, name='스태프'))
        entry.before.permissions = discord.Permissions(send_messages=True)
        entry.after.permissions = discord.Permissions(administrator=True)
        await self.bot.on_audit_log_entry_create(entry)
        title, detail, critical = self.last_alert()
        self.assertEqual((title, critical), ('역할 권한 상승 감지', True))
        self.assertIn('관리자', detail)

        self.bot.record.reset_mock()
        quiet = self.audit(discord.AuditLogAction.role_update, entry_id=2, target=NS(id=501, name='칭호'))
        quiet.before.permissions = discord.Permissions(send_messages=True)
        quiet.after.permissions = discord.Permissions(send_messages=True, manage_messages=True)
        await self.bot.on_audit_log_entry_create(quiet)
        unchanged = self.audit(discord.AuditLogAction.role_update, entry_id=3, target=NS(id=502, name='이미관리자'))
        unchanged.before.permissions = discord.Permissions(administrator=True)
        unchanged.after.permissions = discord.Permissions(administrator=True)
        await self.bot.on_audit_log_entry_create(unchanged)
        no_perm_change = self.audit(discord.AuditLogAction.role_update, entry_id=4, target=NS(id=503, name='이름변경'))
        await self.bot.on_audit_log_entry_create(no_perm_change)
        self.bot.record.assert_not_awaited()

        everyone = self.audit(discord.AuditLogAction.role_update, entry_id=5, target=NS(id=100, name='@everyone'))
        everyone.before.permissions = discord.Permissions.none()
        everyone.after.permissions = discord.Permissions(ban_members=True)
        await self.bot.on_audit_log_entry_create(everyone)
        title, detail, critical = self.last_alert()
        self.assertTrue(critical)
        self.assertIn('@everyone', detail)

    async def test_dangerous_role_grant_alerts(self):
        roles = {600: NS(id=600, name='관리자역할', permissions=discord.Permissions(administrator=True)),
                 601: NS(id=601, name='손님', permissions=discord.Permissions(send_messages=True)),
                 602: NS(id=602, name='차단권한', permissions=discord.Permissions(ban_members=True))}
        self.guild.get_role = roles.get
        admin = self.audit(discord.AuditLogAction.member_role_update, entry_id=10, target=NS(id=30))
        admin.after.roles = [NS(id=600)]
        await self.bot.on_audit_log_entry_create(admin)
        title, detail, critical = self.last_alert()
        self.assertEqual((title, critical), ('위험 권한 역할 부여 감지', True))
        self.assertIn('관리자역할', detail)
        self.bot.record.reset_mock()
        harmless = self.audit(discord.AuditLogAction.member_role_update, entry_id=11, target=NS(id=30))
        harmless.after.roles = [NS(id=601)]
        await self.bot.on_audit_log_entry_create(harmless)
        self.bot.record.assert_not_awaited()
        ban_role = self.audit(discord.AuditLogAction.member_role_update, entry_id=12, target=NS(id=30))
        ban_role.after.roles = [NS(id=602)]
        await self.bot.on_audit_log_entry_create(ban_role)
        self.assertFalse(self.last_alert()[2])  # 차단 권한 정도는 중요 경보가 아니라 일반 경보

    async def test_webhook_and_prune_alerts(self):
        await self.bot.on_audit_log_entry_create(self.audit(discord.AuditLogAction.webhook_create, entry_id=20))
        title, _, critical = self.last_alert()
        self.assertEqual((title, critical), ('웹훅 생성 감지', False))
        await self.bot.on_audit_log_entry_create(
            self.audit(discord.AuditLogAction.member_prune, entry_id=21, extra=NS(members_removed=42)))
        title, detail, critical = self.last_alert()
        self.assertEqual((title, critical), ('멤버 일괄 정리 감지', True))
        self.assertIn('42', detail)

    async def test_alert_filters(self):
        make = lambda entry_id, **kw: self.audit(discord.AuditLogAction.webhook_create, entry_id=entry_id, **kw)
        await self.bot.on_audit_log_entry_create(make(30, uid=999))       # 봇 자신
        await self.bot.on_audit_log_entry_create(make(31, age=300))       # 오래된 항목
        self.store.setting(100, alerts_enabled=False)
        await self.bot.on_audit_log_entry_create(make(32))                # 경보 끔
        self.bot.record.assert_not_awaited()
        self.store.setting(100, alerts_enabled=True)
        await self.bot.on_audit_log_entry_create(make(33))
        await self.bot.on_audit_log_entry_create(make(33))                # 같은 항목 중복
        self.assertEqual(self.bot.record.await_count, 1)
        self.bot.test_guild_id = 200
        await self.bot.on_audit_log_entry_create(make(34))                # 전용 서버가 아님
        self.assertEqual(self.bot.record.await_count, 1)

    async def test_critical_alert_pings_only_the_owner(self):
        log = MagicMock(spec=discord.TextChannel)
        log.send = AsyncMock()
        self.guild.get_channel = lambda cid: log
        self.store.setting(100, log_channel_id=444)
        record = Guardian.record.__get__(self.bot, Guardian)
        await record(self.guild, 20, '봇 추가 감지', '상세', critical=True)
        kwargs = log.send.call_args.kwargs
        self.assertIn('<@1>', kwargs['content'])
        mentions = kwargs['allowed_mentions']
        self.assertEqual(([u.id for u in mentions.users], mentions.everyone, mentions.roles), ([1], False, False))
        log.send.reset_mock()
        await record(self.guild, 20, '일반', '상세')
        self.assertNotIn('content', log.send.call_args.kwargs)
        self.assertFalse(log.send.call_args.kwargs['allowed_mentions'].users)
        self.store.setting(100, ping_owner=False)
        log.send.reset_mock()
        await record(self.guild, 20, '봇 추가 감지', '상세', critical=True)
        self.assertNotIn('content', log.send.call_args.kwargs)

    # ---------- 점검·설정 명령 ----------
    def risky_guild(self):
        everyone = NS(id=100, permissions=discord.Permissions(mention_everyone=True, send_messages=True))
        admin_role = NS(id=700, name='운영진', managed=False, permissions=discord.Permissions(administrator=True),
                        members=[NS(), NS()])
        bot_member = NS(id=888, name='수상한봇', bot=True, guild_permissions=discord.Permissions(administrator=True),
                        top_role=1)
        human_admin = NS(id=40, name='관리자', bot=False, guild_permissions=discord.Permissions(administrator=True),
                         top_role=99)
        log = MagicMock()
        log.mention = '<#444>'
        log.permissions_for = lambda who: discord.Permissions(view_channel=True)
        guild = NS(id=100, owner_id=1, mfa_level=discord.MFALevel.disabled,
                   verification_level=discord.VerificationLevel.none,
                   explicit_content_filter=discord.ContentFilter.disabled, default_role=everyone,
                   roles=[everyone, admin_role], members=[bot_member, human_admin],
                   get_channel=lambda cid: log if cid == 444 else None)
        me = NS(id=999, top_role=10, guild_permissions=discord.Permissions(administrator=True))
        return guild, me

    async def test_checkup_flags_risks_and_formats_safely(self):
        guild, me = self.risky_guild()
        cfg = self.store.config(100)
        cfg['log_channel_id'] = 444
        items = run_checkup(guild, cfg, me, PERMISSION_LABEL, time.time())
        text = format_checkup(items)
        for needle in ['2단계 인증', '인증 수준', '유해 미디어', '@everyone', '관리자 권한 역할 1개',
                       '수상한봇', 'Guardian에 관리자', '모든 멤버가 볼 수 있습니다', '차단 도메인 목록이 비어']:
            self.assertIn(needle, text, needle)
        self.assertIn('보다 높은', text)
        self.assertLessEqual(len(text), 1900)
        self.assertTrue(text.startswith('**보안 점검**'))

    async def test_checkup_reports_clean_server(self):
        everyone = NS(id=100, permissions=discord.Permissions(send_messages=True))
        log = MagicMock()
        log.mention = '<#444>'
        log.permissions_for = lambda who: discord.Permissions(view_channel=False)
        guild = NS(id=100, owner_id=1, mfa_level=discord.MFALevel.require_2fa,
                   verification_level=discord.VerificationLevel.high,
                   explicit_content_filter=discord.ContentFilter.all_members, default_role=everyone,
                   roles=[everyone], members=[], get_channel=lambda cid: log)
        me = NS(id=999, top_role=10, guild_permissions=discord.Permissions(
            moderate_members=True, kick_members=True, ban_members=True, view_audit_log=True, manage_messages=True))
        self.store.setting(100, log_channel_id=444, blocked_domains=['example.com'], invites_enabled=True,
                           account_age_days=3)
        items = run_checkup(guild, self.store.config(100), me, PERMISSION_LABEL, time.time())
        self.assertEqual([t for level, t in items if level == 'warn'], [])
        self.assertIn('확인 필요 0건', format_checkup(items))

    async def test_checkup_command_is_read_only_and_ephemeral(self):
        guild, me = self.risky_guild()
        guild.me = me
        self.interaction.guild = guild
        self.bot.authorize = AsyncMock(return_value=self.actor)
        before = self.store.config(100)
        await self.bot.tree.get_command('보안점검').callback(self.interaction)
        self.bot.authorize.assert_awaited_with(self.interaction, 'administrator')
        kwargs = self.interaction.followup.send.call_args.kwargs
        self.assertTrue(kwargs['ephemeral'])
        self.assertFalse(kwargs['allowed_mentions'].users)
        self.assertLessEqual(len(self.interaction.followup.send.call_args.args[0]), 2000)
        self.assertEqual(self.store.config(100), before)

    async def test_extension_command(self):
        self.bot.authorize = AsyncMock(return_value=self.actor)
        command = self.bot.tree.get_command('차단확장자').callback
        await command(self.interaction, 'EXE', False)
        self.assertNotIn('exe', self.store.config(100)['blocked_extensions'])
        await command(self.interaction, '.Docm', True)
        self.assertIn('docm', self.store.config(100)['blocked_extensions'])
        self.bot.authorize.assert_awaited_with(self.interaction, owner=True)
        with self.assertRaises(ValueError):
            await command(self.interaction, 'a b', True)
        self.store.setting(100, blocked_extensions=[f'e{n}' for n in range(50)])
        with self.assertRaises(UserError):
            await command(self.interaction, 'extra', True)

    async def test_security_toggles_and_threshold_ranges(self):
        self.bot.authorize = AsyncMock(return_value=self.actor)
        toggle = self.bot.tree.get_command('보안설정').callback
        choice = discord.app_commands.Choice
        await toggle(self.interaction, choice(name='초대', value='invites_enabled'), True)
        self.assertTrue(self.store.config(100)['invites_enabled'])
        await toggle(self.interaction, choice(name='주인 멘션', value='ping_owner'), False)
        self.assertFalse(self.store.config(100)['ping_owner'])
        limit = self.bot.tree.get_command('감지기준').callback
        await limit(self.interaction, choice(name='나이', value='account_age_days'), 0)
        await limit(self.interaction, choice(name='나이', value='account_age_days'), 20)
        await limit(self.interaction, choice(name='분', value='newcomer_minutes'), 1440)
        await limit(self.interaction, choice(name='채널', value='crosspost_limit'), 5)
        self.assertEqual(self.store.config(100)['crosspost_limit'], 5)
        for value, number in [('account_age_days', 21), ('spam_limit', 1), ('newcomer_minutes', 1441),
                              ('crosspost_limit', 0), ('raid_limit', 51)]:
            with self.assertRaises(UserError):
                await limit(self.interaction, choice(name='x', value=value), number)

    async def test_status_lists_new_settings_within_message_limit(self):
        self.bot.authorize = AsyncMock(return_value=self.actor)
        self.guild.me.top_role = NS(name='Guardian')
        self.guild.me.guild_permissions = discord.Permissions.all()
        self.store.setting(100, blocked_domains=[f'domain{n}.example.com' for n in range(40)],
                           trusted_ids=list(range(10 ** 17, 10 ** 17 + 30)))
        await self.bot.tree.get_command('상태').callback(self.interaction)  # 연결 전이라 latency는 NaN
        text = self.interaction.followup.send.call_args.args[0]
        self.assertIn('측정 불가', text)
        self.assertLessEqual(len(text), 2000)
        for needle in ['위험 첨부 파일 차단', '디스코드 초대 링크 차단', '신규 계정 보호', '입장 직후', '차단 확장자']:
            self.assertIn(needle, text)

    async def test_log_channel_command_warns_when_public(self):
        self.bot.authorize = AsyncMock(return_value=self.actor)
        for public in (True, False):
            channel = MagicMock(spec=discord.TextChannel)
            channel.guild, channel.id, channel.mention = self.guild, 444, '<#444>'
            channel.send = AsyncMock()
            channel.permissions_for = lambda who, p=public: (
                discord.Permissions.all() if who is self.guild.me else discord.Permissions(view_channel=p))
            await self.bot.tree.get_command('로그설정').callback(self.interaction, channel)
            text = self.interaction.followup.send.call_args.args[0]
            self.assertEqual('모든 멤버가 볼 수 있습니다' in text, public)

    # ---------- 인증·안정성 ----------
    async def test_precheck_rejects_unauthorized_before_any_public_acknowledgement(self):
        user = MagicMock(spec=discord.Member)
        user.id = 77
        interaction = NS(guild=self.guild, user=user, permissions=discord.Permissions(send_messages=True),
                         response=NS(defer=AsyncMock()))
        with self.assertRaises(UserError):
            await Guardian.authorize(self.bot, interaction, 'moderate_members', ephemeral=False)
        with self.assertRaises(UserError):
            await Guardian.authorize(self.bot, interaction, owner=True)
        interaction.response.defer.assert_not_awaited()
        # 권한이 있으면 통과해 공개 defer까지 진행. 최신 멤버 조회가 최종 판정을 맡는다.
        actor = MagicMock(spec=discord.Member)
        actor.id, actor.guild_permissions = 77, discord.Permissions(moderate_members=True)
        self.guild.fetch_member.return_value = actor
        interaction.permissions = discord.Permissions(moderate_members=True)
        await Guardian.authorize(self.bot, interaction, 'moderate_members', ephemeral=False)
        interaction.response.defer.assert_awaited_once_with(ephemeral=False)
        # 서버 주인은 사전 검사를 통과한다.
        interaction.response.defer.reset_mock()
        user.id = 1
        actor.id = 1
        interaction.permissions = discord.Permissions.none()
        await Guardian.authorize(self.bot, interaction, 'moderate_members', ephemeral=False)
        interaction.response.defer.assert_awaited_once()

    async def test_precheck_cannot_override_the_fresh_permission_check(self):
        # 디스코드가 준 권한이 충분해 보여도 최신 조회 결과가 부족하면 거절한다.
        user = MagicMock(spec=discord.Member)
        user.id = 77
        interaction = NS(guild=self.guild, user=user, permissions=discord.Permissions.all(),
                         response=NS(defer=AsyncMock()))
        stale = self.make_member(77)
        self.guild.fetch_member.return_value = stale
        with self.assertRaises(UserError):
            await Guardian.authorize(self.bot, interaction, 'moderate_members')

    async def test_automatic_warning_survives_a_mid_flight_whitelist_change(self):
        self.bot.change_warning = AsyncMock(side_effect=UserError('화이트리스트'))
        message = self.make_message(mention_everyone=True)
        await self.bot.on_message(message)  # 예외가 밖으로 나오면 실패
        message.delete.assert_awaited_once()
        self.channel.send.assert_not_awaited()

    async def test_housekeeping_backs_up_and_never_raises(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / 'db.sqlite3')
            store.change(100, 20, 5, 2, 'x')
            bot = Guardian(store, backup_dir=Path(temp) / 'backups')
            await bot.housekeeping.coro(bot)
            self.assertEqual(len(list((Path(temp) / 'backups').glob('guardian-*.sqlite3'))), 1)
            blocker = Path(temp) / 'afile'
            blocker.write_text('not a directory')
            broken = Guardian(store, backup_dir=blocker)
            await broken.housekeeping.coro(broken)  # OSError는 기록만 하고 반복을 멈추지 않는다.
            await bot.close()
            await broken.close()
            store.close()

    async def test_command_registry_and_help_length(self):
        names = {c.name for c in self.bot.tree.get_commands()}
        self.assertEqual(len(names), 25)
        self.assertTrue({'보안점검', '차단확장자', '보안전체', '보안패널'} <= names)
        self.assertTrue(all(c.to_dict(self.bot.tree)['dm_permission'] is False for c in self.bot.tree.get_commands()))
        await self.bot.tree.get_command('도움말').callback(self.interaction)
        self.assertLessEqual(len(self.interaction.followup.send.call_args.args[0]), 2000)


if __name__ == '__main__':
    unittest.main()
