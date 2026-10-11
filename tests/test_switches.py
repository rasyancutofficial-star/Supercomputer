"""ON/OFF 기능 테스트: 전체 일시정지, 기능별 스위치, 버튼 패널."""
import tempfile
import time
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

import discord
from discord.audit_logs import AuditLogDiff

from bot import Guardian, UserError, SecurityPanel, FEATURE_CHOICES, PANEL_ITEMS
from checkup import run_checkup
from core import DEFAULTS, Store, Windows, protection_active, validate_config

Choice = discord.app_commands.Choice


class PureSwitchTests(unittest.TestCase):
    def test_protection_active_rules(self):
        base = {**DEFAULTS}
        self.assertTrue(protection_active(base, 1000))
        paused = {**base, 'master_enabled': False, 'master_resume_at': 0.0}
        self.assertFalse(protection_active(paused, 1000))
        self.assertFalse(protection_active({**paused, 'master_resume_at': 2000.0}, 1000))
        self.assertTrue(protection_active({**paused, 'master_resume_at': 2000.0}, 2000.0))
        self.assertTrue(protection_active({**paused, 'master_resume_at': 2000.0}, 5000))

    def test_new_settings_are_validated_and_default_on(self):
        self.assertTrue(DEFAULTS['master_enabled'])
        self.assertEqual(DEFAULTS['master_resume_at'], 0.0)
        self.assertTrue(DEFAULTS['crosspost_enabled'])
        s = Store(':memory:')
        for bad in [dict(master_enabled='no'), dict(master_enabled=1), dict(crosspost_enabled=None),
                    dict(master_resume_at=-1), dict(master_resume_at='soon'), dict(master_resume_at=True)]:
            with self.assertRaises(ValueError, msg=str(bad)):
                s.setting(1, **bad)
        s.setting(1, master_enabled=False, master_resume_at=1234.5)
        self.assertEqual((s.config(1)['master_enabled'], s.config(1)['master_resume_at']), (False, 1234.5))
        self.assertTrue(s.config(2)['master_enabled'])  # 서버 분리
        s.close()

    def test_crosspost_can_be_switched_off(self):
        text = 'free discord nitro claim here now'
        off = {**DEFAULTS, 'crosspost_enabled': False}
        w = Windows()
        self.assertEqual([w.message_violation(1, 2, text, 0, False, off, 100 + n * 60, channel_id=n)
                          for n in range(3)], [None] * 3)
        on = {**DEFAULTS, 'crosspost_enabled': True}
        w = Windows()
        self.assertIsNotNone([w.message_violation(1, 2, text, 0, False, on, 100 + n * 60, channel_id=n)
                              for n in range(3)][-1])


class SwitchBotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store = Store(':memory:')
        self.bot = Guardian(self.store)
        self.bot._connection.user = NS(id=999)
        self.bot.record = AsyncMock()
        self.guild = NS(id=100, owner_id=1, name='테스트 서버', default_role=NS(id=100))
        self.guild.me = NS(id=999, top_role=10, guild_permissions=discord.Permissions.all())
        self.member = self.make_member(20)
        self.owner = NS(id=1, name='owner', top_role=100, guild_permissions=discord.Permissions.all(), send=AsyncMock())
        self.guild.fetch_member = AsyncMock(return_value=self.member)
        self.channel = NS(id=400, guild=self.guild, mention='<#400>', send=AsyncMock(), fetch_message=AsyncMock())
        self.interaction = NS(guild=self.guild, guild_id=100, response=NS(is_done=lambda: True),
                              followup=NS(send=AsyncMock()), edit_original_response=AsyncMock())

    async def asyncTearDown(self):
        await self.bot.close()
        self.store.close()

    def make_member(self, uid, **changes):
        values = dict(id=uid, name=f'user{uid}', guild=self.guild, top_role=3, bot=False,
                      guild_permissions=discord.Permissions.none(), timed_out_until=None,
                      ban=AsyncMock(), kick=AsyncMock(), timeout=AsyncMock())
        values.update(changes)
        return NS(**values)

    def make_message(self, content='hello', channel=None, author=None, **changes):
        values = dict(guild=self.guild, channel=channel or self.channel, author=author or self.member,
                      content=content, mentions=[], role_mentions=[], mention_everyone=False,
                      webhook_id=None, delete=AsyncMock(), attachments=[])
        values.update(changes)
        return NS(**values)

    def kinds(self):
        return [c.args[2] for c in self.bot.record.await_args_list]

    # ---------- 전체 일시정지 ----------
    async def test_pause_stops_every_automatic_detection_but_not_manual_actions_or_alerts(self):
        await self.bot.set_master(self.guild, self.owner, False, 30)
        self.assertFalse(protection_active(self.store.config(100), time.time()))
        self.store.setting(100, account_age_days=3, raid_until=time.time() + 120)
        self.bot.record.reset_mock()

        spam = self.make_message(mention_everyone=True)
        await self.bot.on_message(spam)
        danger = self.make_message('f', attachments=[NS(filename='a.exe')])
        await self.bot.on_message(danger)
        spam.delete.assert_not_awaited()
        danger.delete.assert_not_awaited()

        young = self.make_member(30, created_at=discord.utils.utcnow())
        await self.bot.on_member_join(young)
        young.timeout.assert_not_awaited()

        for n in range(4):
            await self.bot.on_audit_log_entry_create(NS(guild=self.guild, id=100 + n, user_id=20,
                action=discord.AuditLogAction.channel_delete, created_at=datetime.now(timezone.utc)))
        self.member.ban.assert_not_awaited()

        self.bot.get_guild = lambda gid: self.guild
        self.guild.get_channel_or_thread = lambda cid: self.channel
        await self.bot.on_raw_message_edit(NS(guild_id=100, channel_id=400, message_id=1, data={'content': 'x'}))
        self.channel.fetch_message.assert_not_awaited()

        # 수동 경고는 계속 동작한다.
        actor = NS(id=5, name='mod', top_role=8, guild_permissions=discord.Permissions.all(), send=AsyncMock())
        await self.bot.change_warning(self.member, 1, 'manual', actor)
        self.assertEqual(self.store.points(100, 20), 1)

        # 경보 기록은 계속 동작한다.
        entry = NS(guild=self.guild, id=9001, user_id=20, action=discord.AuditLogAction.webhook_create,
                   created_at=datetime.now(timezone.utc), before=AuditLogDiff(), after=AuditLogDiff())
        self.bot.record.reset_mock()
        await self.bot.on_audit_log_entry_create(entry)
        self.assertIn('웹훅 생성 감지', self.kinds())

        # 다시 켜면 즉시 동작한다.
        await self.bot.set_master(self.guild, self.owner, True)
        again = self.make_message(mention_everyone=True)
        await self.bot.on_message(again)
        again.delete.assert_awaited_once()

    async def test_pause_ends_by_itself_and_housekeeping_cleans_up(self):
        self.bot.test_guild_id = 100
        self.bot.get_guild = lambda gid: self.guild
        self.store.setting(100, master_enabled=False, master_resume_at=time.time() + 600)
        await self.bot.housekeeping.coro(self.bot)
        self.assertFalse(self.store.config(100)['master_enabled'])      # 아직 정지 중
        self.bot.record.assert_not_awaited()

        self.store.setting(100, master_enabled=False, master_resume_at=time.time() - 1)
        message = self.make_message(mention_everyone=True)
        await self.bot.on_message(message)                               # 저장 상태와 무관하게 이미 재개
        message.delete.assert_awaited_once()
        await self.bot.housekeeping.coro(self.bot)
        cfg = self.store.config(100)
        self.assertEqual((cfg['master_enabled'], cfg['master_resume_at']), (True, 0.0))
        self.assertIn('전체 자동 보안 자동 재개', self.kinds())

    async def test_indefinite_pause_never_resumes_by_itself(self):
        self.bot.test_guild_id = 100
        text = await self.bot.set_master(self.guild, self.owner, False, 0)
        self.assertIn('직접', text)
        self.assertEqual(self.store.config(100)['master_resume_at'], 0.0)
        await self.bot.housekeeping.coro(self.bot)
        self.assertFalse(self.store.config(100)['master_enabled'])
        self.assertFalse(protection_active(self.store.config(100), time.time() + 10 ** 9))

    async def test_set_master_records_and_pings_only_for_pause(self):
        text = await self.bot.set_master(self.guild, self.owner, False, 30)
        cfg = self.store.config(100)
        self.assertAlmostEqual(cfg['master_resume_at'], time.time() + 1800, delta=5)
        self.assertIn('자동으로 다시 켜집니다', text)
        call = self.bot.record.await_args
        self.assertEqual((call.args[2], call.kwargs['critical']), ('전체 자동 보안 일시정지', True))
        await self.bot.set_master(self.guild, self.owner, True)
        self.assertEqual(self.bot.record.await_args.args[2], '전체 자동 보안 재개')
        self.assertFalse(self.bot.record.await_args.kwargs.get('critical'))

    async def test_master_command(self):
        self.bot.authorize = AsyncMock(return_value=self.owner)
        command = self.bot.tree.get_command('보안전체').callback
        await command(self.interaction, Choice(name='끄기', value='off'), 15)
        self.bot.authorize.assert_awaited_with(self.interaction, owner=True)
        self.assertFalse(self.store.config(100)['master_enabled'])
        self.assertIn('수동 명령', self.interaction.followup.send.call_args.args[0])
        await command(self.interaction, Choice(name='켜기', value='on'), 15)
        self.assertTrue(self.store.config(100)['master_enabled'])

    # ---------- 기능별 스위치 ----------
    async def test_numeric_features_toggle_and_remember_a_nonzero_value(self):
        self.assertIn('기준 3일', await self.bot.set_feature(self.guild, self.owner, 'account_age_days', True))
        self.assertEqual(self.store.config(100)['account_age_days'], 3)
        self.assertIn('꺼짐', await self.bot.set_feature(self.guild, self.owner, 'account_age_days', False))
        self.assertEqual(self.store.config(100)['account_age_days'], 0)
        self.store.setting(100, newcomer_minutes=25)
        await self.bot.set_feature(self.guild, self.owner, 'newcomer_minutes', True)   # 이미 켜져 있으면 값 유지
        self.assertEqual(self.store.config(100)['newcomer_minutes'], 25)
        await self.bot.set_feature(self.guild, self.owner, 'newcomer_minutes', False)
        await self.bot.set_feature(self.guild, self.owner, 'newcomer_minutes', True)   # 0에서 켜면 기본값
        self.assertEqual(self.store.config(100)['newcomer_minutes'], 10)

    async def test_boolean_features_and_raid_state(self):
        self.store.setting(100, raid_until=time.time() + 100)
        await self.bot.set_feature(self.guild, self.owner, 'raid_enabled', False)
        self.assertEqual((self.store.config(100)['raid_enabled'], self.store.config(100)['raid_until']), (False, 0.0))
        await self.bot.set_feature(self.guild, self.owner, 'crosspost_enabled', False)
        text = 'free discord nitro claim at the link'
        for n in range(3):  # 교차 게시 기준(3채널)에 도달하지만 4회 반복 규칙은 넘지 않는다.
            message = self.make_message(text, channel=NS(id=500 + n, send=AsyncMock()))
            await self.bot.on_message(message)
            message.delete.assert_not_awaited()
        await self.bot.set_feature(self.guild, self.owner, 'crosspost_enabled', True)
        self.assertTrue(self.store.config(100)['crosspost_enabled'])
        again = self.make_message(text, channel=NS(id=600, send=AsyncMock()))
        await self.bot.on_message(again)
        again.delete.assert_awaited_once()  # 켜면 같은 창 안의 4번째 채널부터 바로 감지

    async def test_security_command_uses_the_shared_switch_and_lists_every_panel_feature(self):
        keys = {c.value for c in FEATURE_CHOICES}
        self.assertTrue({'crosspost_enabled', 'newcomer_minutes', 'account_age_days'} <= keys)
        self.assertTrue({key for key, _ in PANEL_ITEMS} <= keys)
        self.bot.authorize = AsyncMock(return_value=self.owner)
        await self.bot.tree.get_command('보안설정').callback(
            self.interaction, Choice(name='신규 계정 보호', value='account_age_days'), True)
        self.assertEqual(self.store.config(100)['account_age_days'], 3)
        self.assertIn('기준 3일', self.interaction.followup.send.call_args.args[0])

    # ---------- 상태 표시 ----------
    async def test_status_and_checkup_show_the_pause(self):
        self.bot.authorize = AsyncMock(return_value=self.owner)
        self.guild.me.top_role = NS(name='Guardian')
        await self.bot.tree.get_command('상태').callback(self.interaction)
        self.assertIn('자동 보안: 켜짐', self.interaction.followup.send.call_args.args[0])
        await self.bot.set_master(self.guild, self.owner, False, 30)
        await self.bot.tree.get_command('상태').callback(self.interaction)
        self.assertIn('일시정지 중', self.interaction.followup.send.call_args.args[0])
        everyone = NS(id=100, permissions=discord.Permissions.none())
        guild = NS(id=100, owner_id=1, mfa_level=discord.MFALevel.require_2fa,
                   verification_level=discord.VerificationLevel.high,
                   explicit_content_filter=discord.ContentFilter.all_members, default_role=everyone,
                   roles=[everyone], members=[], get_channel=lambda cid: None)
        me = NS(id=999, top_role=1, guild_permissions=discord.Permissions.all())
        items = run_checkup(guild, self.store.config(100), me, {}, time.time())
        self.assertTrue(any('일시정지' in text for level, text in items if level == 'warn'))

    # ---------- 버튼 패널 ----------
    async def open_panel(self):
        self.bot.authorize = AsyncMock(return_value=self.owner)
        await self.bot.tree.get_command('보안패널').callback(self.interaction)
        call = self.interaction.followup.send.call_args
        self.assertTrue(call.kwargs['ephemeral'])
        return call.kwargs['view'], call.args[0]

    def click_target(self):
        return NS(user=NS(id=1), guild=self.guild, guild_id=100,
                  response=NS(edit_message=AsyncMock(), is_done=lambda: False, send_message=AsyncMock()),
                  followup=NS(send=AsyncMock()))

    @staticmethod
    def find(view, text):
        return next(b for b in view.children if text in b.label)

    async def test_panel_shows_current_state_on_buttons(self):
        view, content = await self.open_panel()
        self.bot.authorize.assert_awaited_with(self.interaction, owner=True)
        self.assertIn('보안 패널', content)
        self.assertEqual(len(view.children), 12)
        self.assertTrue(all(isinstance(b, discord.ui.Button) for b in view.children))
        self.assertTrue(view.children[0].label.startswith('🛡️ 전체 보호 켜짐'))
        self.assertEqual(view.children[0].style, discord.ButtonStyle.success)
        self.assertIn('🟢', self.find(view, '도배·멘션').label)
        self.assertIn('⚫', self.find(view, '초대 링크').label)
        self.assertIn('⚫', self.find(view, '신규 멤버 제한').label)
        view.stop()

    async def test_panel_buttons_toggle_and_redraw(self):
        view, _ = await self.open_panel()
        click = self.click_target()
        self.guild.fetch_member = AsyncMock(return_value=self.owner)
        await self.find(view, '초대 링크').callback(click)
        self.assertTrue(self.store.config(100)['invites_enabled'])
        click.response.edit_message.assert_awaited_once()
        self.assertIs(click.response.edit_message.call_args.kwargs['view'], view)
        self.assertIn('🟢', self.find(view, '초대 링크').label)
        self.assertEqual(self.find(view, '초대 링크').style, discord.ButtonStyle.success)
        await self.find(view, '초대 링크').callback(self.click_target())
        self.assertFalse(self.store.config(100)['invites_enabled'])
        await self.find(view, '신규 멤버 제한').callback(self.click_target())
        self.assertEqual(self.store.config(100)['newcomer_minutes'], 10)
        await self.find(view, '신규 멤버 제한').callback(self.click_target())
        self.assertEqual(self.store.config(100)['newcomer_minutes'], 0)
        view.stop()

    async def test_panel_master_button_pauses_for_an_hour_and_resumes(self):
        view, _ = await self.open_panel()
        self.guild.fetch_member = AsyncMock(return_value=self.owner)
        await view.children[0].callback(self.click_target())
        cfg = self.store.config(100)
        self.assertFalse(cfg['master_enabled'])
        self.assertAlmostEqual(cfg['master_resume_at'], time.time() + 3600, delta=5)
        self.assertIn('정지됨', view.children[0].label)
        self.assertEqual(view.children[0].style, discord.ButtonStyle.danger)
        self.assertIn('일시정지', view.content())
        await view.children[0].callback(self.click_target())
        self.assertTrue(self.store.config(100)['master_enabled'])
        self.assertIn('켜짐', view.children[0].label)
        view.stop()

    async def test_panel_rejects_everyone_but_the_current_owner(self):
        view, _ = await self.open_panel()
        stranger = NS(user=NS(id=77), guild=self.guild, guild_id=100,
                      response=NS(is_done=lambda: False, send_message=AsyncMock()), followup=NS(send=AsyncMock()))
        self.assertFalse(await view.interaction_check(stranger))
        stranger.response.send_message.assert_awaited_once()
        # 소유권이 바뀐 뒤 이전 소유자의 패널도 거절한다.
        self.guild.owner_id = 2
        self.assertFalse(await view.interaction_check(self.click_target()))
        self.guild.owner_id = 1
        self.assertTrue(await view.interaction_check(self.click_target()))
        # 클릭 순간 최신 조회로 서버 주인이 아니면 변경하지 않는다.
        self.guild.fetch_member = AsyncMock(return_value=self.make_member(77))
        with self.assertRaises(UserError):
            await view.toggle(self.click_target(), 'invites_enabled', True)
        self.assertFalse(self.store.config(100)['invites_enabled'])
        view.stop()

    async def test_panel_disables_itself_on_timeout(self):
        view, _ = await self.open_panel()
        await view.on_timeout()
        self.assertTrue(all(b.disabled for b in view.children))
        self.interaction.edit_original_response.assert_awaited_once_with(view=view)
        view.stop()

    async def test_help_mentions_new_commands(self):
        await self.bot.tree.get_command('도움말').callback(self.interaction)
        text = self.interaction.followup.send.call_args.args[0]
        self.assertIn('/보안전체', text)
        self.assertIn('/보안패널', text)
        self.assertLessEqual(len(text), 2000)


if __name__ == '__main__':
    unittest.main()
