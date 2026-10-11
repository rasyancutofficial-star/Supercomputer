import asyncio
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

import discord

from bot import Guardian, TimeoutOffer, UserError, WARN_TIMEOUT_DAYS, check_target
from core import DEFAULTS, Store, Windows, blocked_link, normalize_domain, timeout_duration


class PolicyTests(unittest.TestCase):
    def test_timeout_boundaries_in_all_units(self):
        for amount, unit in [(20, 'days'), (480, 'hours'), (28800, 'minutes')]:
            self.assertEqual(timeout_duration(amount, unit).total_seconds(), 1728000)
            with self.assertRaises(ValueError):
                timeout_duration(amount + 1, unit)
        for amount, unit in [(0, 'minutes'), (-1, 'days'), (1, 'weeks'), (1.5, 'hours'), (True, 'hours')]:
            with self.assertRaises(ValueError):
                timeout_duration(amount, unit)
        self.assertEqual(timeout_duration(1, 'minutes').total_seconds(), 60)

    def test_domain_boundaries_and_userinfo(self):
        self.assertEqual(normalize_domain('ExAmPlE.com.'), 'example.com')
        self.assertEqual(blocked_link('https://sub.example.com/claim', ['example.com']), 'example.com')
        self.assertEqual(blocked_link('https://good.test@example.com/', ['example.com']), 'example.com')
        self.assertEqual(blocked_link('www.example.com/a', ['example.com']), 'example.com')
        for text in ['https://notexample.com', 'https://example.com.safe.test', 'https://example.com@good.test']:
            self.assertIsNone(blocked_link(text, ['example.com']))
        for text in ['https://example.com', '*.example.com', 'a..com', 'a.com/path', 'com', 'example.com:80']:
            with self.assertRaises(ValueError):
                normalize_domain(text)

    def test_spam_windows_are_isolated_and_expire(self):
        w = Windows()
        for n in range(5):
            self.assertIsNone(w.message_violation(1, 2, str(n), 0, False, DEFAULTS, 100 + n / 10))
        self.assertIn('도배', w.message_violation(1, 2, 'six', 0, False, DEFAULTS, 101))
        self.assertIsNone(w.message_violation(2, 2, 'six', 0, False, DEFAULTS, 101))
        self.assertIsNone(w.message_violation(1, 3, 'six', 0, False, DEFAULTS, 101))
        self.assertIsNone(w.message_violation(1, 2, 'fresh', 0, False, DEFAULTS, 110))

    def test_repeat_and_mentions(self):
        w = Windows()
        for n in range(3):
            self.assertIsNone(w.message_violation(1, 2, 'repeat', 0, False, DEFAULTS, 100 + n * 3))
        self.assertIn('반복', w.message_violation(1, 2, 'REPEAT', 0, False, DEFAULTS, 109))
        self.assertIn('멘션', w.message_violation(1, 3, 'hey', 8, False, DEFAULTS, 109))
        self.assertIn('멘션', w.message_violation(1, 4, '@everyone', 0, True, DEFAULTS, 109))

    def test_cooldown_cleanup(self):
        w = Windows()
        self.assertTrue(w.ready('x', 100, 60))
        self.assertFalse(w.ready('x', 101, 60))
        self.assertTrue(w.ready('x', 160, 60))
        w.add('old', 100, 10)
        w.clean(300)
        self.assertEqual(len(w.events), 0)
        self.assertEqual(len(w.cooldowns), 0)

    def test_persistence_floor_history_and_guild_isolation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'data.sqlite'
            s = Store(path)
            self.assertEqual(s.config(1)['warn_limit'], 5)
            s.setting(1, warn_limit=7, warn_action='kick')
            self.assertEqual(s.change(1, 2, 3, 4, 'a')[0], 4)
            self.assertEqual(s.change(1, 2, 3, -100, 'b')[0], 0)
            self.assertEqual(s.history(1, 2)[0]['delta'], -4)
            s.change(1, 2, 3, 8, 'c')
            s.close()
            s = Store(path)
            self.assertEqual(s.points(1, 2), 8)
            self.assertEqual(s.points(2, 2), 0)
            self.assertEqual(s.config(1)['warn_limit'], 7)
            self.assertEqual(s.config(2)['warn_limit'], 5)
            self.assertTrue(s.audit_once(555, 100))
            self.assertFalse(s.audit_once(555, 101))
            s.close()

    def test_owner_and_role_hierarchy(self):
        guild = NS(owner_id=1)
        me = NS(id=999, top_role=10)
        actor = NS(id=5, top_role=8)
        for target in [NS(id=1, guild=guild, top_role=1), NS(id=6, guild=guild, top_role=8),
                       NS(id=5, guild=guild, top_role=1), NS(id=999, guild=guild, top_role=1)]:
            with self.assertRaises(UserError):
                check_target(actor, target, me)
        with self.assertRaises(UserError):
            check_target(NS(id=1, top_role=100), NS(id=6, guild=guild, top_role=10), me)


class BotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store = Store(':memory:')
        self.bot = Guardian(self.store)
        self.bot._connection.user = NS(id=999)
        self.bot.record = AsyncMock()
        self.guild = NS(id=100, owner_id=1, name='테스트 서버')
        self.guild.me = NS(id=999, top_role=10, guild_permissions=discord.Permissions.all())
        self.member = self.make_member(20)
        self.guild.fetch_member = AsyncMock(return_value=self.member)
        self.actor = NS(id=5, name='moderator', top_role=8, guild_permissions=discord.Permissions.all(), send=AsyncMock())
        self.channel = NS(id=400, guild=self.guild, mention='<#400>', send=AsyncMock(), fetch_message=AsyncMock())

    def make_member(self, uid):
        return NS(id=uid, name=f'user{uid}', guild=self.guild, top_role=3, bot=False,
                  guild_permissions=discord.Permissions.none(), timed_out_until=None,
                  ban=AsyncMock(), kick=AsyncMock(), timeout=AsyncMock())

    def make_message(self, content='hello', channel=None, **changes):
        values = dict(guild=self.guild, channel=channel or self.channel, author=self.member,
                      content=content, mentions=[], role_mentions=[], mention_everyone=False,
                      webhook_id=None, delete=AsyncMock())
        values.update(changes)
        return NS(**values)

    async def asyncTearDown(self):
        await self.bot.close()
        self.store.close()

    async def test_commands_serialize_with_korean_options(self):
        commands = self.bot.tree.get_commands()
        payload = [c.to_dict(self.bot.tree) for c in commands]
        timeout = next(c for c in payload if c['name'] == '타임아웃')
        units = next(p for p in timeout['options'] if p['name'] == '단위')['choices']
        self.assertEqual([x['name'] for x in units], ['분', '시간', '일'])
        self.assertTrue(all(c['dm_permission'] is False for c in payload))

    async def test_warning_default_ban_at_exact_limit(self):
        await self.bot.change_warning(self.member, 4, 'test', self.actor)
        self.member.ban.assert_not_awaited()
        await self.bot.change_warning(self.member, 1, 'test', self.actor)
        self.member.ban.assert_awaited_once()
        self.assertEqual(self.store.points(100, 20), 5)
        self.assertIn('완료', self.store.history(100, 20)[0]['result'])

    async def test_warning_skip_over_limit_kick_and_decrease(self):
        self.store.setting(100, warn_action='kick')
        await self.bot.change_warning(self.member, 7, 'test', self.actor)
        self.member.kick.assert_awaited_once()
        self.member.ban.assert_not_awaited()
        await self.bot.change_warning(self.member, -20, 'reduce', self.actor)
        self.assertEqual(self.store.points(100, 20), 0)
        self.member.kick.assert_awaited_once()

    async def test_no_permission_escalation_through_warnings(self):
        self.actor.guild_permissions = discord.Permissions(moderate_members=True)
        await self.bot.change_warning(self.member, 4, 'test', self.actor)
        with self.assertRaises(UserError):
            await self.bot.change_warning(self.member, 1, 'test', self.actor)
        self.assertEqual(self.store.points(100, 20), 4)
        self.member.ban.assert_not_awaited()

    async def test_failed_ban_preserves_warning_and_failure(self):
        self.member.ban.side_effect = discord.Forbidden(NS(status=403, reason='Forbidden'),
                                                       {'message': 'Missing Permissions', 'code': 50013})
        result = await self.bot.change_warning(self.member, 5, 'test', self.actor)
        self.assertEqual(self.store.points(100, 20), 5)
        self.assertIn('처분 실패', result)
        self.assertIn('실패', self.store.history(100, 20)[0]['result'])

    async def test_concurrent_warning_changes(self):
        self.store.setting(100, warn_limit=100)
        async def change():
            async with self.bot.lock(100, 20):
                await self.bot.change_warning(self.member, 1, 'parallel', self.actor)
        await asyncio.gather(*(change() for _ in range(20)))
        self.assertEqual(self.store.points(100, 20), 20)

    async def test_auto_timeout_never_shortens_existing(self):
        self.member.timed_out_until = discord.utils.utcnow() + timeout_duration(3, 'days')
        result = await self.bot.auto_timeout(self.member, 10, 'auto')
        self.assertIn('유지', result)
        self.member.timeout.assert_not_awaited()

    async def test_message_guard_deletes_and_warns_once_per_cooldown(self):
        messages = []
        for n in range(8):
            message = self.make_message(f'message {n}')
            messages.append(message)
            await self.bot.on_message(message)
        self.assertEqual(self.store.points(100, 20), 1)
        self.member.timeout.assert_awaited_once()
        self.channel.send.assert_awaited_once()
        self.assertIn('user20에게 1만큼 경고를 넣었습니다.', self.channel.send.call_args.args[0])
        for message in messages[:5]:
            message.delete.assert_not_awaited()
        for message in messages[5:]:
            message.delete.assert_awaited_once()

    async def test_nuke_uses_actor_id_and_deduplicates_entries(self):
        created = datetime.now(timezone.utc)
        entries = [NS(guild=self.guild, id=800 + n, user_id=20,
                      action=discord.AuditLogAction.channel_delete, created_at=created) for n in range(3)]
        await self.bot.on_audit_log_entry_create(entries[0])
        await self.bot.on_audit_log_entry_create(entries[0])
        await self.bot.on_audit_log_entry_create(entries[1])
        self.member.ban.assert_not_awaited()
        await self.bot.on_audit_log_entry_create(entries[2])
        self.guild.fetch_member.assert_awaited_with(20)
        self.member.ban.assert_awaited_once()

    async def test_nuke_ignores_owner_self_trusted_and_stale(self):
        self.store.setting(100, trusted_ids=[55])
        for uid in [1, 999, 55]:
            for n in range(4):
                await self.bot.on_audit_log_entry_create(NS(guild=self.guild, id=uid * 100 + n, user_id=uid,
                    action=discord.AuditLogAction.ban, created_at=datetime.now(timezone.utc)))
        for n in range(4):
            await self.bot.on_audit_log_entry_create(NS(guild=self.guild, id=9000 + n, user_id=20,
                action=discord.AuditLogAction.kick, created_at=datetime.fromtimestamp(time.time() - 120, timezone.utc)))
        self.member.ban.assert_not_awaited()

    async def test_raid_protects_entire_triggering_cohort(self):
        members = {uid: self.make_member(uid) for uid in range(20, 30)}
        async def fetch(uid):
            return members[uid]
        self.guild.fetch_member.side_effect = fetch
        for member in list(members.values())[:9]:
            await self.bot.on_member_join(member)
        self.assertTrue(all(m.timeout.await_count == 0 for m in members.values()))
        await self.bot.on_member_join(members[29])
        self.assertTrue(all(m.timeout.await_count == 1 for m in members.values()))
        self.assertGreater(self.store.config(100)['raid_until'], time.time())
        self.assertTrue(all(self.store.points(100, uid) == 0 for uid in members))

    async def test_runtime_authorization_rejects_nonmoderator(self):
        actor = self.make_member(77)
        self.guild.fetch_member.return_value = actor
        interaction = NS(guild=self.guild, user=MagicMock(spec=discord.Member),
                         response=NS(defer=AsyncMock()))
        interaction.user.id = 77
        with self.assertRaises(UserError):
            await self.bot.authorize(interaction, 'moderate_members')
        with self.assertRaises(UserError):
            await self.bot.authorize(interaction, owner=True)

    async def test_nonowner_admin_can_manage_whitelist(self):
        self.assertNotEqual(self.actor.id, self.guild.owner_id)
        await self.bot.set_whitelist(self.guild, 20, True, self.actor)
        await self.bot.set_whitelist(self.guild, 20, True, self.actor)
        self.assertEqual(self.store.config(100)['trusted_ids'], [20])
        self.assertEqual(self.store.config(200)['trusted_ids'], [])
        await self.bot.set_whitelist(self.guild, 20, False, self.actor)
        self.assertEqual(self.store.config(100)['trusted_ids'], [])
        await self.bot.change_warning(self.member, 1, 'after removal', self.actor)
        self.assertEqual(self.store.points(100, 20), 1)

    async def test_nonadmin_cannot_manage_whitelist(self):
        self.actor.guild_permissions = discord.Permissions(moderate_members=True)
        for enabled in [True, False]:
            with self.assertRaises(UserError):
                await self.bot.set_whitelist(self.guild, 20, enabled, self.actor)
        self.assertEqual(self.store.config(100)['trusted_ids'], [])

    async def test_whitelist_blocks_warnings_enforcement_and_auto_timeout(self):
        self.store.change(100, 20, 5, 5, 'previous warning')
        await self.bot.set_whitelist(self.guild, 20, True, self.actor)
        for actor in [None, self.actor]:
            with self.assertRaises(UserError):
                await self.bot.change_warning(self.member, 1, 'blocked', actor)
        for action in ['kick', 'ban']:
            with self.assertRaises(UserError):
                await self.bot.enforce_warning(self.member, action, self.actor)
        with self.assertRaises(UserError):
            await self.bot.auto_timeout(self.member, 10, 'blocked')
        self.assertEqual(self.store.points(100, 20), 5)
        self.assertEqual(len(self.store.history(100, 20)), 1)
        self.member.timeout.assert_not_awaited()
        self.member.ban.assert_not_awaited()
        self.member.kick.assert_not_awaited()
        await self.bot.change_warning(self.member, -2, 'correction', self.actor)
        self.assertEqual(self.store.points(100, 20), 3)

    async def test_whitelist_bypasses_all_automatic_handlers(self):
        self.store.setting(100, trusted_ids=[20], blocked_domains=['example.com'], raid_until=time.time() + 120)
        for n in range(8):
            msg = NS(guild=self.guild, author=self.member, content='https://example.com', mentions=[],
                     role_mentions=[], mention_everyone=True, webhook_id=None, delete=AsyncMock())
            await self.bot.on_message(msg)
            msg.delete.assert_not_awaited()
            await self.bot.on_audit_log_entry_create(NS(guild=self.guild, id=7000 + n, user_id=20,
                action=discord.AuditLogAction.role_delete, created_at=datetime.now(timezone.utc)))
        await self.bot.on_member_join(self.member)
        self.guild.fetch_member.assert_not_awaited()
        self.member.timeout.assert_not_awaited()
        self.member.ban.assert_not_awaited()
        self.assertEqual(self.store.points(100, 20), 0)

    async def test_whitelist_blocks_manual_timeout_and_retry_before_history_write(self):
        self.store.setting(100, trusted_ids=[20])
        self.store.change(100, 20, 5, 5, 'old')
        self.bot.authorize = AsyncMock(return_value=self.actor)
        i = NS(guild=self.guild, guild_id=100)
        with self.assertRaises(UserError):
            await self.bot.tree.get_command('타임아웃').callback(i, self.member, 1,
                discord.app_commands.Choice(name='일', value='days'))
        with self.assertRaises(UserError):
            await self.bot.tree.get_command('경고집행').callback(i, self.member)
        self.member.timeout.assert_not_awaited()
        self.assertEqual(len(self.store.history(100, 20)), 1)

    async def test_whitelist_persistence_and_existing_exceptions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'state.sqlite'
            old = Store(path)
            old.setting(100, trusted_ids=[20])
            old.close()
            restored = Store(path)
            self.assertEqual(restored.config(100)['trusted_ids'], [20])
            restored.close()

    async def test_whitelist_command_checks_admin_and_lists_without_pinging(self):
        self.bot.authorize = AsyncMock(return_value=self.actor)
        i = NS(guild=self.guild, guild_id=100, response=NS(is_done=lambda: True),
               followup=NS(send=AsyncMock()))
        await self.bot.tree.get_command('화이트리스트추가').callback(i, self.member)
        self.bot.authorize.assert_awaited_with(i, 'administrator')
        await self.bot.tree.get_command('화이트리스트조회').callback(i, 1)
        self.assertIn('총 1명', i.followup.send.call_args.args[0])
        self.assertFalse(i.followup.send.call_args.kwargs['allowed_mentions'].users)
        await self.bot.tree.get_command('화이트리스트제거').callback(i, NS(id=20))
        self.bot.authorize.assert_awaited_with(i, 'administrator')
        self.assertEqual(self.store.config(100)['trusted_ids'], [])

    async def test_whitelist_registration_clears_old_detection_counters(self):
        self.bot.windows.add(('burst', 100, 20), time.time(), 5)
        self.bot.windows.add(('nuke', 100, 20), time.time(), 20)
        self.bot.windows.add(('joins', 100), time.time(), 10, 20)
        self.bot.windows.add(('joins', 100), time.time(), 10, 30)
        await self.bot.set_whitelist(self.guild, 20, True, self.actor)
        self.assertNotIn(('burst', 100, 20), self.bot.windows.events)
        self.assertNotIn(('nuke', 100, 20), self.bot.windows.events)
        self.assertEqual([uid for _, uid in self.bot.windows.events[('joins', 100)]], [30])

    def offer_fixture(self, points=1):
        total, case_id = self.store.change(100, 20, self.actor.id, points, 'test offer')
        self.bot.get_guild = lambda gid: self.guild if gid == 100 else None
        async def fetch(uid):
            return {5: self.actor, 20: self.member, 999: self.guild.me}[uid]
        self.guild.fetch_member.side_effect = fetch
        offer = TimeoutOffer(self.bot, 100, 20, 5, case_id, WARN_TIMEOUT_DAYS[points])
        interaction = NS(user=NS(id=5), response=NS(defer=AsyncMock(), is_done=lambda: True),
                         followup=NS(send=AsyncMock()), edit_original_response=AsyncMock())
        return offer, interaction

    async def test_warning_receipt_precedes_dm_prompt(self):
        self.bot.authorize = AsyncMock(return_value=self.actor)
        i = NS(guild=self.guild, guild_id=100, response=NS(is_done=lambda: True), followup=NS(send=AsyncMock()))
        async def sent_after_receipt(*args):
            self.assertTrue(i.followup.send.await_count)
            self.assertTrue(i.followup.send.call_args.args[0].startswith('user20에게 1만큼 경고를 넣었습니다.'))
            self.assertFalse(i.followup.send.call_args.kwargs['ephemeral'])
        self.bot.send_timeout_offer = AsyncMock(side_effect=sent_after_receipt)
        await self.bot.tree.get_command('경고추가').callback(i, self.member, 1, 'test')
        self.bot.authorize.assert_awaited_with(i, 'moderate_members', ephemeral=False)
        self.bot.send_timeout_offer.assert_awaited_once()

    async def test_offer_mapping_and_no_timeout_without_confirmation(self):
        self.store.setting(100, warn_limit=100)
        for points, days in {1: 1, 2: 3, 3: 5, 4: 15}.items():
            _, case = self.store.change(100, 20, 5, points, 'offer')
            await self.bot.send_timeout_offer(NS(), self.member, self.actor, points, case)
            call = self.actor.send.call_args
            self.assertTrue(call.args[0].startswith(f'타임아웃 {days}일을 주시겠습니까?'))
            self.assertEqual(call.kwargs['view'].days, days)
            self.assertEqual([c.label for c in call.kwargs['view'].children], ['적용', '취소'])
            call.kwargs['view'].stop()
        self.member.timeout.assert_not_awaited()

    async def test_dm_failure_keeps_warning_and_reports_failure(self):
        _, case = self.store.change(100, 20, 5, 1, 'offer')
        self.actor.send.side_effect = discord.Forbidden(NS(status=403, reason='Forbidden'),
                                                       {'message': 'Cannot send messages', 'code': 50007})
        i = NS(response=NS(is_done=lambda: True), followup=NS(send=AsyncMock()))
        await self.bot.send_timeout_offer(i, self.member, self.actor, 1, case)
        self.assertEqual(self.store.points(100, 20), 1)
        self.assertIn('경고는 정상 저장', i.followup.send.call_args.args[0])
        self.member.timeout.assert_not_awaited()

    async def test_offer_skipped_for_threshold_and_unmapped_points(self):
        self.store.setting(100, warn_limit=2)
        _, case = self.store.change(100, 20, 5, 2, 'offer')
        await self.bot.send_timeout_offer(NS(), self.member, self.actor, 2, case)
        await self.bot.send_timeout_offer(NS(), self.member, self.actor, 5, case)
        self.actor.send.assert_not_awaited()

    async def test_confirmation_applies_once_even_with_concurrent_clicks(self):
        offer, i = self.offer_fixture(2)
        await asyncio.gather(offer.decide(i, True), offer.decide(i, True))
        self.member.timeout.assert_awaited_once()
        until = self.member.timeout.call_args.args[0]
        self.assertAlmostEqual((until - discord.utils.utcnow()).total_seconds(), 3 * 86400, delta=2)
        self.assertTrue(all(c.disabled for c in offer.children))

    async def test_cancel_expiry_and_wrong_user_do_not_apply(self):
        offer, i = self.offer_fixture()
        i.user.id = 88
        await offer.decide(i, True)
        self.assertFalse(offer.decided)
        i.user.id = 5
        await offer.decide(i, False)
        self.assertTrue(offer.decided)
        self.assertIn('취소', i.edit_original_response.call_args.kwargs['content'])
        expired, j = self.offer_fixture()
        expired.expires_at = time.time() - 1
        await expired.decide(j, True)
        self.assertIn('만료', j.edit_original_response.call_args.kwargs['content'])
        self.member.timeout.assert_not_awaited()

    async def test_confirmation_rechecks_permission_whitelist_and_newer_warnings(self):
        offer, i = self.offer_fixture()
        self.actor.guild_permissions = discord.Permissions.none()
        await offer.decide(i, True)
        self.assertIn('권한', i.edit_original_response.call_args.kwargs['content'])
        self.actor.guild_permissions = discord.Permissions.all()
        offer, i = self.offer_fixture()
        await self.bot.set_whitelist(self.guild, 20, True, self.actor)
        await offer.decide(i, True)
        self.assertIn('화이트리스트', i.edit_original_response.call_args.kwargs['content'])
        await self.bot.set_whitelist(self.guild, 20, False, self.actor)
        offer, i = self.offer_fixture()
        self.store.change(100, 20, 5, -1, 'changed')
        await offer.decide(i, True)
        self.assertIn('이전 확인 요청', i.edit_original_response.call_args.kwargs['content'])
        self.member.timeout.assert_not_awaited()

    async def test_offer_preserves_longer_timeout(self):
        offer, i = self.offer_fixture()
        self.member.timed_out_until = discord.utils.utcnow() + timeout_duration(10, 'days')
        await offer.decide(i, True)
        self.member.timeout.assert_not_awaited()
        self.assertIn('더 길어서', i.edit_original_response.call_args.kwargs['content'])

    async def test_single_server_rejects_commands_and_automatic_events_elsewhere(self):
        self.bot.test_guild_id = 100
        other = NS(id=200)
        i = NS(guild_id=200, response=NS(is_done=lambda: True), followup=NS(send=AsyncMock()))
        self.assertFalse(await self.bot.guild_interaction_check(i))
        await self.bot.on_message(NS(guild=other))
        await self.bot.on_member_join(NS(guild=other))
        await self.bot.on_audit_log_entry_create(NS(guild=other, user_id=20, action=discord.AuditLogAction.ban))
        self.guild.fetch_member.assert_not_awaited()
        self.assertTrue(self.bot.allowed_guild(100))
        self.assertFalse(self.bot.allowed_guild(None))

    async def test_dm_cannot_target_a_different_server(self):
        offer, i = self.offer_fixture()
        self.bot.test_guild_id = 200
        await offer.decide(i, True)
        self.member.timeout.assert_not_awaited()
        self.assertIn('전용 서버', i.edit_original_response.call_args.kwargs['content'])

    async def test_channel_whitelist_admin_permissions_commands_and_persistence(self):
        self.bot.authorize = AsyncMock(return_value=self.actor)
        i = NS(guild=self.guild, guild_id=100, response=NS(is_done=lambda: True),
               followup=NS(send=AsyncMock()))
        await self.bot.tree.get_command('채널화이트리스트추가').callback(i, self.channel)
        self.bot.authorize.assert_awaited_with(i, 'administrator')
        await self.bot.tree.get_command('채널화이트리스트조회').callback(i, 1)
        self.assertIn('<#400>', i.followup.send.call_args.args[0])
        self.assertEqual(self.store.config(100)['trusted_channel_ids'], [400])
        self.assertEqual(self.store.config(200)['trusted_channel_ids'], [])
        await self.bot.tree.get_command('채널화이트리스트제거').callback(i, self.channel)
        self.assertEqual(self.store.config(100)['trusted_channel_ids'], [])
        self.actor.guild_permissions = discord.Permissions(moderate_members=True)
        for enabled in (True, False):
            with self.assertRaises(UserError):
                await self.bot.set_channel_whitelist(self.guild, self.channel, enabled, self.actor)
        self.actor.guild_permissions = discord.Permissions.all()
        foreign = NS(id=401, guild=NS(id=200))
        with self.assertRaises(UserError):
            await self.bot.set_channel_whitelist(self.guild, foreign, True, self.actor)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'state.sqlite'
            old = Store(path)
            old.setting(100, trusted_ids=[20])
            old.close()
            restored = Store(path)
            self.assertEqual(restored.config(100)['trusted_channel_ids'], [])
            restored.setting(100, trusted_channel_ids=[400])
            restored.close()
            restored = Store(path)
            self.assertEqual(restored.config(100)['trusted_channel_ids'], [400])
            self.assertEqual(restored.config(100)['trusted_ids'], [20])
            restored.close()

    async def test_channel_whitelist_skips_spam_without_poisoning_other_channels(self):
        await self.bot.set_channel_whitelist(self.guild, self.channel, True, self.actor)
        for _ in range(10):
            message = self.make_message(mention_everyone=True)
            await self.bot.on_message(message)
            message.delete.assert_not_awaited()
        self.assertEqual(self.store.points(100, self.member.id), 0)
        self.member.timeout.assert_not_awaited()
        self.assertNotIn(('burst', 100, self.member.id), self.bot.windows.events)
        other = NS(id=401, send=AsyncMock())
        message = self.make_message(channel=other)
        await self.bot.on_message(message)
        message.delete.assert_not_awaited()
        await self.bot.set_channel_whitelist(self.guild, self.channel, False, self.actor)
        message = self.make_message(mention_everyone=True)
        await self.bot.on_message(message)
        message.delete.assert_awaited_once()
        self.assertEqual(self.store.points(100, self.member.id), 1)

    async def test_channel_whitelist_keeps_blocked_links_and_manual_warnings_active(self):
        self.store.setting(100, blocked_domains=['example.com'])
        await self.bot.set_channel_whitelist(self.guild, self.channel, True, self.actor)
        await self.bot.change_warning(self.member, 1, 'manual', self.actor)
        self.assertEqual(self.store.points(100, self.member.id), 1)
        message = self.make_message('https://sub.example.com/blocked')
        await self.bot.on_message(message)
        message.delete.assert_awaited_once()
        self.member.timeout.assert_awaited_once()
        self.assertEqual(self.store.points(100, self.member.id), 2)
        self.channel.send.assert_awaited_once()
        self.assertIn('자동: 등록된 차단 도메인', self.channel.send.call_args.args[0])
        # User-level whitelist retains its original, stronger exception.
        self.store.setting(100, trusted_ids=[self.member.id])
        exempt = self.make_message('https://example.com')
        await self.bot.on_message(exempt)
        exempt.delete.assert_not_awaited()

    async def test_channel_whitelist_threads_and_edited_links(self):
        thread = MagicMock(spec=discord.Thread)
        thread.id, thread.parent_id, thread.guild = 401, 400, self.guild
        thread.send, thread.fetch_message = AsyncMock(), AsyncMock()
        self.store.setting(100, trusted_channel_ids=[400], blocked_domains=['example.com'])
        self.bot.get_guild = lambda gid: self.guild
        self.guild.get_channel_or_thread = lambda cid: thread if cid == 401 else self.channel
        self.assertTrue(self.bot.channel_exempt(thread, self.store.config(100)))
        harmless = self.make_message('@everyone', channel=thread, mention_everyone=True)
        thread.fetch_message.return_value = harmless
        payload = NS(guild_id=100, channel_id=401, message_id=600, data={'content': '@everyone'})
        await self.bot.on_raw_message_edit(payload)
        harmless.delete.assert_not_awaited()
        blocked = self.make_message('https://example.com', channel=thread)
        thread.fetch_message.return_value = blocked
        payload.data = {'content': blocked.content}
        await self.bot.on_raw_message_edit(payload)
        blocked.delete.assert_awaited_once()
        self.member.timeout.assert_awaited_once()
        self.assertEqual(self.store.points(100, self.member.id), 1)
        thread.send.assert_awaited_once()
        result = await self.bot.set_channel_whitelist(self.guild, thread, False, self.actor)
        self.assertIn('상위 채널이 등록', result)

    async def test_channel_whitelist_keeps_server_wide_raid_and_nuke_guards(self):
        self.store.setting(100, trusted_channel_ids=[400], raid_until=time.time() + 120)
        await self.bot.on_member_join(self.member)
        self.member.timeout.assert_awaited_once()
        for n in range(3):
            await self.bot.on_audit_log_entry_create(NS(guild=self.guild, id=900 + n, user_id=20,
                action=discord.AuditLogAction.channel_delete, created_at=datetime.now(timezone.utc)))
        self.member.ban.assert_awaited_once()

    async def test_all_warning_commands_use_public_defer_and_public_reply_without_user_ids(self):
        self.actor.id, self.member.id = 123456789012345670, 123456789012345671
        self.bot.authorize = AsyncMock(return_value=self.actor)
        self.bot.send_timeout_offer = AsyncMock()
        i = NS(guild=self.guild, guild_id=100, response=NS(is_done=lambda: True),
               followup=NS(send=AsyncMock()))
        calls = [
            ('경고추가', (self.member, 1, 'test')),
            ('경고감소', (self.member, 1, 'test')),
            ('경고조회', (self.member,)),
            ('경고한도', (1,)),
            ('경고처분', (discord.app_commands.Choice(name='추방', value='kick'),)),
            ('경고집행', (self.member,)),
        ]
        for command, args in calls:
            if command == '경고집행':
                self.store.change(100, self.member.id, self.actor.id, 1, 'test')
            await self.bot.tree.get_command(command).callback(i, *args)
            self.assertFalse(self.bot.authorize.call_args.kwargs['ephemeral'], command)
            self.assertFalse(i.followup.send.call_args.kwargs['ephemeral'], command)
            content = i.followup.send.call_args.args[0]
            self.assertNotIn(str(self.member.id), content)
            self.assertNotIn(str(self.actor.id), content)
            self.assertFalse(i.followup.send.call_args.kwargs['allowed_mentions'].users)
        # The actual acknowledgement must also be public, not just the final follow-up.
        actor = MagicMock(spec=discord.Member)
        actor.id, actor.guild_permissions = self.actor.id, discord.Permissions.all()
        self.guild.fetch_member.return_value = actor
        i.user, i.response.defer = actor, AsyncMock()
        await Guardian.authorize(self.bot, i, 'moderate_members', ephemeral=False)
        i.response.defer.assert_awaited_once_with(ephemeral=False)

    async def test_warning_dm_and_log_embed_use_names_with_ids_only_in_internal_storage(self):
        self.actor.id, self.member.id = 123456789012345670, 123456789012345671
        log = MagicMock(spec=discord.TextChannel)
        log.send = AsyncMock()
        self.guild.get_channel = lambda cid: log
        self.store.setting(100, log_channel_id=444)
        self.bot.record = Guardian.record.__get__(self.bot, Guardian)
        detail = await self.bot.change_warning(self.member, 1, 'test', self.actor)
        embed = log.send.call_args.kwargs['embed'].to_dict()
        self.assertIn('user20', str(embed))
        self.assertIn('moderator', detail)
        self.assertNotIn(str(self.member.id), str(embed))
        self.assertNotIn(str(self.actor.id), str(embed))
        case_id = self.store.history(100, self.member.id)[0]['id']
        await self.bot.send_timeout_offer(NS(), self.member, self.actor, 1, case_id)
        self.assertNotIn(str(self.member.id), self.actor.send.call_args.args[0])
        self.actor.send.call_args.kwargs['view'].stop()
        self.assertEqual(self.store.points(100, self.member.id), 1)
        self.assertEqual(self.store.history(100, self.member.id)[0]['actor'], self.actor.id)

    async def test_failed_public_auto_notice_preserves_warning(self):
        self.channel.send.side_effect = discord.Forbidden(NS(status=403, reason='Forbidden'),
                                                         {'message': 'Missing Permissions', 'code': 50013})
        message = self.make_message(mention_everyone=True)
        await self.bot.on_message(message)
        self.assertEqual(self.store.points(100, self.member.id), 1)
        message.delete.assert_awaited_once()


if __name__ == '__main__':
    unittest.main()
