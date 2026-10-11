"""Pure policies and durable SQLite storage. No Discord connection is needed."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

# 일반 커뮤니티에서 거의 쓰이지 않는 실행형 파일 형식. 서버 주인이 /차단확장자로 조정한다.
DEFAULT_BLOCKED_EXTENSIONS = (
    'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'msi', 'lnk',
    'vbs', 'vbe', 'wsf', 'hta', 'ps1', 'jar', 'reg', 'cpl',
)
DEFAULTS = {
    'warn_limit': 5, 'warn_action': 'ban', 'log_channel_id': None,
    'spam_enabled': True, 'raid_enabled': True, 'nuke_enabled': True,
    'links_enabled': True, 'spam_limit': 6, 'mention_limit': 8,
    'repeat_limit': 4, 'raid_limit': 10, 'nuke_limit': 3,
    'trusted_ids': [], 'trusted_channel_ids': [], 'blocked_domains': [], 'raid_until': 0.0,
    # --- 보안 강화 항목. 저장된 기존 설정에 없으면 아래 기본값이 적용된다. ---
    'invites_enabled': False,      # 디스코드 초대 링크 차단(정책 선택이라 기본 꺼짐)
    'files_enabled': True,         # 위험 첨부 파일 형식 차단
    'alerts_enabled': True,        # 관리 권한 변경·봇 추가 등 경보(기록만, 자동 처분 없음)
    'ping_owner': True,            # 중요 경보 시 로그 채널에서 서버 주인 멘션
    'crosspost_limit': 3,          # 10분 내 같은 문구를 올린 서로 다른 채널 수
    'account_age_days': 0,         # 0=끔. 이보다 어린 계정은 기준 나이가 될 때까지 타임아웃
    'newcomer_minutes': 0,         # 0=끔. 입장 직후 멤버의 링크·첨부 파일 제한
    'blocked_extensions': list(DEFAULT_BLOCKED_EXTENSIONS),
    'crosspost_enabled': True,     # 같은 문구 교차 게시 감지
    # 전체 일시정지 스위치: False면 자동 감지·자동 처분이 모두 멈춘다(수동 명령과 경보는 유지).
    'master_enabled': True,
    'master_resume_at': 0.0,       # 0이 아니면 이 시각(epoch 초)에 자동으로 다시 켠다. 0=수동 재개
}
# 숫자 설정의 허용 범위. 슬래시 명령과 저장소가 같은 표를 사용한다.
LIMIT_RANGES = {
    'spam_limit': (2, 50), 'mention_limit': (2, 50), 'repeat_limit': (2, 50),
    'raid_limit': (2, 50), 'nuke_limit': (2, 50), 'crosspost_limit': (2, 50),
    'account_age_days': (0, 20), 'newcomer_minutes': (0, 1440),
}
MAX_TIMEOUT = 20 * 86400

URL_RE = re.compile(r'(?:https?://|www\.)[^\s<>]+', re.I)
# 초대 링크 전용 서비스까지 포함한다. 앞글자가 이어진 도메인(notdiscord.gg)은 제외한다.
INVITE_RE = re.compile(
    r'(?<![\w.-])(?:https?://)?(?:www\.)?'
    r'(?:discord(?:app)?\.com/invite|discord\.gg|discord\.me|discord\.io|discord\.link|dsc\.gg|invite\.gg)'
    r'/[a-z0-9-]{2,}', re.I)
# 스킴 없이 적은 도메인도 디스코드는 클릭 가능한 링크로 표시한다. 신규 멤버 제한에서만 쓰는 넓은 목록.
_TLDS = ('com|net|org|io|gg|xyz|top|info|club|online|site|shop|store|live|app|dev|me|co|kr|jp|cn|ru|'
         'tk|ml|ga|cf|gq|link|click|icu|cc|ws|vip|fun|pro|biz|us|uk|to|ly|gift|gifts|win|bid|cyou|buzz|work')
BARE_LINK_RE = re.compile(rf'(?<![\w@.-])(?:[a-z0-9-]+\.)+(?:{_TLDS})(?![\w@-])', re.I)


def protection_active(cfg: dict, now: float) -> bool:
    """자동 보안이 동작해야 하는지. 일시정지 중이어도 재개 시각이 지났으면 동작한다."""
    return bool(cfg['master_enabled']) or (0 < cfg['master_resume_at'] <= now)


def timeout_duration(amount: int, unit: str) -> timedelta:
    scales = {'minutes': 60, 'hours': 3600, 'days': 86400}
    if unit not in scales or not isinstance(amount, int) or isinstance(amount, bool):
        raise ValueError('분·시간·일 중 하나와 정수를 입력하세요.')
    seconds = amount * scales[unit]
    if not 60 <= seconds <= MAX_TIMEOUT:
        raise ValueError('타임아웃은 1분 이상, 최대 20일(480시간/28,800분)입니다.')
    return timedelta(seconds=seconds)


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip('.')
    if any(c in value for c in '/:@?#*'):
        raise ValueError('https://, 경로, 포트 없이 도메인만 입력하세요. 예: example.com')
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('올바른 도메인이 아닙니다.') from exc
    if len(value) > 253 or '.' not in value or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
        for part in value.split('.')
    ):
        raise ValueError('올바른 도메인이 아닙니다.')
    return value


def normalize_extension(value: str) -> str:
    value = value.strip().lower().lstrip('.')
    if not re.fullmatch(r'[a-z0-9]{1,10}', value):
        raise ValueError('확장자는 영문·숫자 1~10자로 입력하세요. 예: exe')
    return value


@lru_cache(maxsize=256)
def _bare_domain_pattern(domain: str):
    # 앞은 다른 단어·이메일(@)·점으로 이어지지 않고, 뒤는 다른 도메인 라벨로 이어지지 않아야 한다.
    return re.compile(rf'(?<![\w@.-])(?:[a-z0-9-]+\.)*{re.escape(domain)}(?![\w@-])(?!\.[a-z0-9])', re.I)


def blocked_link(content: str, domains: list[str]) -> str | None:
    """등록 도메인 검사. 스킴·www 링크는 실제 호스트로, 스킴 없는 표기는 본문에서 따로 찾는다."""
    for match in URL_RE.finditer(content):
        raw = match.group(0).rstrip('.,;!?)]}')
        try:
            host = urlsplit(raw if '://' in raw else 'https://' + raw).hostname
            if not host:
                continue
            host = host.rstrip('.').lower().encode('idna').decode('ascii')
        except (ValueError, UnicodeError):
            continue
        for domain in domains:
            if host == domain or host.endswith('.' + domain):
                return domain
    # 이미 호스트를 검사한 URL은 제외하고 남은 글에서 스킴 없는 도메인(scam.example/claim)을 찾는다.
    remainder = URL_RE.sub(' ', content)
    for domain in domains:
        if _bare_domain_pattern(domain).search(remainder):
            return domain
    return None


def blocked_attachment(filenames, extensions) -> str | None:
    """마지막 확장자가 차단 목록에 있으면 그 확장자를 반환한다. 'invoice.pdf.exe'도 잡는다."""
    blocked = set(extensions)
    for name in filenames:
        cleaned = str(name).strip().rstrip('. ')  # 윈도우는 끝의 점·공백을 무시한다.
        if '.' not in cleaned:
            continue
        ext = cleaned.rsplit('.', 1)[1].lower()
        if ext in blocked:
            return ext
    return None


def has_link(text: str) -> bool:
    return bool(URL_RE.search(text) or INVITE_RE.search(text) or BARE_LINK_RE.search(text))


def newcomer_violation(joined_at, now: datetime, minutes: int, text: str, has_attachments: bool) -> str | None:
    if minutes <= 0 or joined_at is None or now - joined_at >= timedelta(minutes=minutes):
        return None
    if has_attachments or has_link(text):
        return f'입장 {minutes}분 이내 신규 멤버의 링크·첨부 파일'
    return None


class Windows:
    """Bounded short-lived events, with an explicit timestamp for deterministic tests."""
    def __init__(self):
        self.events = defaultdict(lambda: deque(maxlen=100))
        self.cooldowns = {}
        self.horizon = {}  # 키별로 보관해야 하는 최대 시간(초). 긴 감지 창이 조기 삭제되지 않게 한다.

    def add(self, key, now: float, seconds: float, value=None):
        items = self.events[key]
        self.horizon[key] = max(self.horizon.get(key, 0), seconds)
        while items and items[0][0] < now - seconds:
            items.popleft()
        items.append((now, value))
        return list(items)

    def ready(self, key, now: float, seconds: float) -> bool:
        if self.cooldowns.get(key, 0) > now:
            return False
        self.cooldowns[key] = now + seconds
        return True

    def clean(self, now: float):
        for key in list(self.events):
            keep = max(120, self.horizon.get(key, 0))
            if not self.events[key] or self.events[key][-1][0] < now - keep:
                del self.events[key]
        for key in list(self.horizon):
            if key not in self.events:
                del self.horizon[key]
        for key in list(self.cooldowns):
            if self.cooldowns[key] <= now:
                del self.cooldowns[key]

    def message_violation(self, guild_id, user_id, content, mentions, everyone, cfg, now,
                          channel_id=None, filenames=(), link_text=None):
        key = (guild_id, user_id)
        text = content if link_text is None else link_text
        if cfg['links_enabled']:
            domain = blocked_link(text, cfg['blocked_domains'])
            if domain:
                return f'등록된 차단 도메인: {domain}'
        if cfg['invites_enabled'] and INVITE_RE.search(text):
            return '디스코드 초대 링크'
        if cfg['files_enabled']:
            ext = blocked_attachment(filenames, cfg['blocked_extensions'])
            if ext:
                return f'위험 파일 형식(.{ext})'
        if not cfg['spam_enabled']:
            return None
        burst = self.add(('burst', *key), now, 5)
        normalized = ' '.join(content.split()).casefold()
        fingerprint = hashlib.sha256(normalized.encode()).hexdigest() if normalized else None
        repeated = self.add(('repeat', *key), now, 15, fingerprint)
        # 계정 탈취·스캠 봇의 전형: 같은 긴 문구를 여러 채널에 천천히 뿌린다. 짧은 말(ㅋㅋ 등)은 제외.
        cross_channels = set()
        if cfg['crosspost_enabled'] and channel_id is not None and fingerprint and len(normalized) >= 20:
            cross = self.add(('cross', *key), now, 600, (channel_id, fingerprint))
            cross_channels = {v[0] for _, v in cross if v[1] == fingerprint}
        if everyone or mentions >= cfg['mention_limit']:
            return '대량 멘션'
        if len(burst) >= cfg['spam_limit']:
            return '5초 내 메시지 도배'
        if fingerprint and sum(v == fingerprint for _, v in repeated) >= cfg['repeat_limit']:
            return '15초 내 동일 문구 반복'
        if len(cross_channels) >= cfg['crosspost_limit']:
            return '10분 내 여러 채널에 동일 문구 게시'
        return None


def validate_config(cfg: dict) -> None:
    if not 1 <= cfg['warn_limit'] <= 1000 or cfg['warn_action'] not in {'kick', 'ban'}:
        raise ValueError('Invalid warning configuration')
    for key, (low, high) in LIMIT_RANGES.items():
        value = cfg[key]
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise ValueError(f'Invalid value for {key}')
    for key in ('master_enabled', 'crosspost_enabled'):
        if not isinstance(cfg[key], bool):
            raise ValueError(f'Invalid value for {key}')
    resume = cfg['master_resume_at']
    if isinstance(resume, bool) or not isinstance(resume, (int, float)) or resume < 0:
        raise ValueError('Invalid value for master_resume_at')
    extensions = cfg['blocked_extensions']
    if (not isinstance(extensions, list) or len(extensions) > 50 or
            any(not isinstance(e, str) or not re.fullmatch(r'[a-z0-9]{1,10}', e) for e in extensions)):
        raise ValueError('Invalid blocked_extensions')


class Store:
    def __init__(self, path: str | Path):
        self.in_memory = str(path) == ':memory:'
        if not self.in_memory:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self._configs: dict[int, dict] = {}  # 메시지마다 DB를 읽지 않도록 서버별 설정을 메모리에 둔다.
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS settings(guild INTEGER PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS warnings(
                guild INTEGER, user INTEGER, points INTEGER NOT NULL CHECK(points >= 0),
                PRIMARY KEY(guild,user));
            CREATE TABLE IF NOT EXISTS history(
                id INTEGER PRIMARY KEY, guild INTEGER, user INTEGER, actor INTEGER,
                delta INTEGER, total INTEGER, reason TEXT, created REAL, result TEXT);
            CREATE INDEX IF NOT EXISTS history_lookup ON history(guild,user,id DESC);
            CREATE TABLE IF NOT EXISTS incidents(
                id INTEGER PRIMARY KEY, guild INTEGER, user INTEGER,
                kind TEXT, detail TEXT, created REAL);
            CREATE TABLE IF NOT EXISTS audit_seen(id INTEGER PRIMARY KEY, created REAL);
        ''')

    def config(self, guild: int):
        cached = self._configs.get(guild)
        if cached is None:
            row = self.db.execute('SELECT data FROM settings WHERE guild=?', (guild,)).fetchone()
            cached = copy.deepcopy(DEFAULTS)  # 서버끼리 리스트 기본값이 섞이지 않게 복사한다.
            if row:
                cached.update(json.loads(row['data']))
            self._configs[guild] = cached
        return copy.deepcopy(cached)

    def setting(self, guild: int, **changes):
        if changes.keys() - DEFAULTS.keys():
            raise ValueError('Unknown setting')
        cfg = self.config(guild)
        cfg.update(changes)
        validate_config(cfg)
        with self.db:
            self.db.execute('INSERT INTO settings VALUES(?,?) ON CONFLICT(guild) DO UPDATE SET data=excluded.data',
                            (guild, json.dumps(cfg, ensure_ascii=False)))
        self._configs[guild] = copy.deepcopy(cfg)  # DB 저장이 성공한 뒤에만 캐시를 바꾼다.
        return cfg

    def points(self, guild: int, user: int) -> int:
        row = self.db.execute('SELECT points FROM warnings WHERE guild=? AND user=?', (guild, user)).fetchone()
        return row['points'] if row else 0

    def change(self, guild, user, actor, delta, reason, result='처분 없음'):
        # One transaction covers balance + immutable history; no awaits occur inside it.
        with self.db:
            old = self.points(guild, user)
            total = max(0, old + delta)
            self.db.execute('INSERT INTO warnings VALUES(?,?,?) ON CONFLICT(guild,user) DO UPDATE SET points=excluded.points',
                            (guild, user, total))
            cursor = self.db.execute('INSERT INTO history(guild,user,actor,delta,total,reason,created,result) VALUES(?,?,?,?,?,?,?,?)',
                                     (guild, user, actor, total - old, total, reason, time.time(), result))
        return total, cursor.lastrowid

    def history(self, guild, user):
        return self.db.execute('SELECT * FROM history WHERE guild=? AND user=? ORDER BY id DESC LIMIT 10',
                               (guild, user)).fetchall()

    def outcome(self, case_id, result):
        with self.db:
            self.db.execute('UPDATE history SET result=? WHERE id=?', (result, case_id))

    def incident(self, guild, user, kind, detail):
        with self.db:
            self.db.execute('INSERT INTO incidents(guild,user,kind,detail,created) VALUES(?,?,?,?,?)',
                            (guild, user, kind, detail, time.time()))

    def audit_once(self, entry_id, now):
        with self.db:
            cursor = self.db.execute('INSERT OR IGNORE INTO audit_seen VALUES(?,?)', (entry_id, now))
        return bool(cursor.rowcount)

    def cleanup(self, now):
        with self.db:
            self.db.execute('DELETE FROM audit_seen WHERE created < ?', (now - 86400,))
            self.db.execute('DELETE FROM incidents WHERE created < ?', (now - 90 * 86400,))

    def backup_if_due(self, directory: str | Path, *, interval: float = 86400, keep: int = 7,
                      now: float | None = None) -> Path | None:
        """SQLite 온라인 백업 API로 일관된 복사본을 만든다. 마지막 백업이 interval보다 새로우면 건너뛴다."""
        if self.in_memory:
            return None
        now = time.time() if now is None else now
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        existing = sorted(directory.glob('guardian-*.sqlite3'))
        if existing and now - existing[-1].stat().st_mtime < interval:
            return None
        stamp = datetime.fromtimestamp(now, timezone.utc).strftime('%Y%m%d-%H%M%S')
        target = directory / f'guardian-{stamp}.sqlite3'
        dest = sqlite3.connect(str(target))
        try:
            self.db.backup(dest)
        finally:
            dest.close()
        for old in sorted(directory.glob('guardian-*.sqlite3'))[:-keep]:
            old.unlink()
        return target

    def close(self):
        self.db.close()
