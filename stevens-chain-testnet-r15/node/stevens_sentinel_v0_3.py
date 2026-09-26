# Stevens Sentinel v0.3 — Swarm / Cluster Defense
# Defensive, testnet-only extension of Sentinel v0.2.
#
# Local state machine (unchanged):
#   NORMAL -> WATCH -> CHALLENGE -> QUARANTINE -> ISOLATE
# Global modes:
#   CALM -> WATCH -> GLOBAL_CHALLENGE -> GLOBAL_HIGH
#
# This does not alter blockchain consensus, hack back, or let AI apply policy.

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from pathlib import Path

from stevens_sentinel_v0_2 import (
    StevensSentinel as BaseSentinel,
    SentinelConfig,
    SEVERITY_WEIGHT,
)

VERSION = '0.3'
GLOBAL_MODES = ('CALM', 'WATCH', 'GLOBAL_CHALLENGE', 'GLOBAL_HIGH')


@dataclass(frozen=True)
class SwarmPolicy:
    window_seconds: int = 5 * 60
    min_unique_sources: int = 20
    watch_score: float = 80.0
    challenge_score: float = 160.0
    high_score: float = 350.0
    unique_source_weight: float = 0.50
    unique_node_weight: float = 0.25
    category_cluster_weight: float = 0.75
    challenge_extra_bits: int = 2
    high_extra_bits: int = 4
    pass_ttl_seconds: int = 15 * 60
    max_events_considered: int = 20000

    def to_dict(self) -> dict:
        return {'format': 'StevensSentinelSwarmPolicy', 'version': 1, **self.__dict__}

    @classmethod
    def from_dict(cls, d: dict) -> 'SwarmPolicy':
        if d.get('format') != 'StevensSentinelSwarmPolicy':
            raise ValueError('not a Stevens Sentinel swarm policy')
        if int(d.get('version', 1)) != 1:
            raise ValueError('unsupported swarm policy version')
        defaults = cls()
        return cls(**{k: d.get(k, getattr(defaults, k)) for k in defaults.__dict__})

    def validate(self, base_config: SentinelConfig) -> None:
        if self.window_seconds < 30:
            raise ValueError('swarm window must be at least 30 seconds')
        if self.min_unique_sources < 2:
            raise ValueError('min_unique_sources must be at least 2')
        if not (0 <= self.watch_score < self.challenge_score < self.high_score):
            raise ValueError('swarm thresholds must strictly increase')
        if self.challenge_extra_bits < 0 or self.high_extra_bits < self.challenge_extra_bits:
            raise ValueError('invalid swarm challenge bit increments')
        if base_config.challenge_difficulty_bits + self.high_extra_bits > 28:
            raise ValueError('global challenge difficulty would exceed cap')
        if self.pass_ttl_seconds <= 0:
            raise ValueError('pass TTL must be positive')
        if self.max_events_considered < 100:
            raise ValueError('max_events_considered too small')


class StevensSentinel(BaseSentinel):
    def __init__(self, data_dir, config, swarm_policy: SwarmPolicy | None = None):
        super().__init__(data_dir, config)
        self.swarm_policy_path = self.data_dir / 'sentinel_swarm_policy.json'
        self.swarm_policy = swarm_policy or self._load_or_create_swarm_policy()
        self.swarm_policy.validate(self.config)
        self._init_swarm_db()

    @classmethod
    def load_or_create(cls, data_dir, public_base_url='http://127.0.0.1'):
        base = BaseSentinel.load_or_create(data_dir, public_base_url)
        return cls(base.data_dir, base.config)

    def _load_or_create_swarm_policy(self) -> SwarmPolicy:
        if self.swarm_policy_path.exists():
            policy = SwarmPolicy.from_dict(json.loads(self.swarm_policy_path.read_text()))
        else:
            policy = SwarmPolicy()
            self._write_private_json(self.swarm_policy_path, policy.to_dict())
        return policy

    def _persist_swarm_policy(self) -> None:
        self.swarm_policy.validate(self.config)
        self._write_private_json(self.swarm_policy_path, self.swarm_policy.to_dict())

    def _init_swarm_db(self) -> None:
        with self._connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS global_challenge_passes(
                    source_ip TEXT PRIMARY KEY,
                    passed_ts INTEGER NOT NULL
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS global_state(
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    mode TEXT NOT NULL,
                    score REAL NOT NULL,
                    updated_ts INTEGER NOT NULL
                )
            """)
            con.execute("""
                INSERT OR IGNORE INTO global_state(id,mode,score,updated_ts)
                VALUES(1,'CALM',0,0)
            """)

    def _recent_global_pass(self, source_ip: str, now: int | None = None) -> bool:
        now = int(now or time.time())
        cutoff = now - self.swarm_policy.pass_ttl_seconds
        with self._connect() as con:
            row = con.execute(
                'SELECT passed_ts FROM global_challenge_passes WHERE source_ip=?',
                (source_ip,)
            ).fetchone()
            con.execute('DELETE FROM global_challenge_passes WHERE passed_ts<?', (cutoff,))
        return bool(row and int(row[0]) >= cutoff)

    def _mark_global_pass(self, source_ip: str, now: int | None = None) -> None:
        now = int(now or time.time())
        with self._connect() as con:
            con.execute("""
                INSERT INTO global_challenge_passes(source_ip,passed_ts)
                VALUES(?,?)
                ON CONFLICT(source_ip) DO UPDATE SET passed_ts=excluded.passed_ts
            """, (source_ip, now))

    def verify_challenge(self, source_ip: str, nonce: str | None, solution: str | None) -> bool:
        ok = super().verify_challenge(source_ip, nonce, solution)
        if ok:
            self._mark_global_pass(source_ip)
        return ok

    def clear_subject(self, source_ip: str) -> None:
        super().clear_subject(source_ip)
        with self._connect() as con:
            con.execute('DELETE FROM global_challenge_passes WHERE source_ip=?', (source_ip,))

    def global_threat(self, now: int | None = None, track_transition: bool = True) -> dict:
        now = int(now or time.time())
        p = self.swarm_policy
        cutoff = now - p.window_seconds
        with self._connect() as con:
            rows = con.execute("""
                SELECT timestamp,severity,category,source_ip,source_node_id
                FROM events
                WHERE timestamp>=?
                  AND source_ip IS NOT NULL
                  AND severity IN ('MEDIUM','HIGH','CRITICAL')
                ORDER BY id DESC
                LIMIT ?
            """, (cutoff, p.max_events_considered)).fetchall()

        weighted = 0.0
        sources = set()
        nodes = set()
        category_sources = {}
        severity_counts = {'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        for _, severity, category, source_ip, source_node_id in rows:
            weighted += float(SEVERITY_WEIGHT.get(severity, 0.0))
            sources.add(source_ip)
            if source_node_id:
                nodes.add(source_node_id)
            category_sources.setdefault(category, set()).add(source_ip)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        max_cluster = max((len(v) for v in category_sources.values()), default=0)
        score = (
            weighted
            + len(sources) * p.unique_source_weight
            + len(nodes) * p.unique_node_weight
            + max_cluster * p.category_cluster_weight
        )

        if len(sources) < p.min_unique_sources:
            mode = 'CALM'
        elif score >= p.high_score:
            mode = 'GLOBAL_HIGH'
        elif score >= p.challenge_score:
            mode = 'GLOBAL_CHALLENGE'
        elif score >= p.watch_score:
            mode = 'WATCH'
        else:
            mode = 'CALM'

        top_clusters = sorted(
            ({'category': k, 'unique_sources': len(v)} for k, v in category_sources.items()),
            key=lambda x: x['unique_sources'], reverse=True
        )[:10]

        result = {
            'sentinel_version': VERSION,
            'mode': mode,
            'score': round(score, 3),
            'window_seconds': p.window_seconds,
            'suspicious_events': len(rows),
            'unique_sources': len(sources),
            'unique_node_ids': len(nodes),
            'max_category_cluster_sources': max_cluster,
            'severity_counts': severity_counts,
            'top_category_clusters': top_clusters,
            'minimum_unique_sources': p.min_unique_sources,
            'thresholds': {
                'watch': p.watch_score,
                'global_challenge': p.challenge_score,
                'global_high': p.high_score,
            },
            'challenge_extra_bits': (
                p.high_extra_bits if mode == 'GLOBAL_HIGH'
                else p.challenge_extra_bits if mode == 'GLOBAL_CHALLENGE'
                else 0
            ),
            'generated_at': now,
        }

        if track_transition:
            with self._connect() as con:
                prev = con.execute('SELECT mode,score FROM global_state WHERE id=1').fetchone()
                previous_mode = prev[0] if prev else 'CALM'
                con.execute("""
                    INSERT INTO global_state(id,mode,score,updated_ts) VALUES(1,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                        mode=excluded.mode,score=excluded.score,updated_ts=excluded.updated_ts
                """, (mode, float(score), now))
            if previous_mode != mode:
                self.record(
                    'INFO', 'global_state_transition',
                    details={
                        'from': previous_mode,
                        'to': mode,
                        'score': round(score, 3),
                        'unique_sources': len(sources),
                        'suspicious_events': len(rows),
                    },
                    affect_score=False,
                )
        return result

    def _global_challenge(self, source_ip: str, global_info: dict) -> dict:
        challenge = self.get_or_issue_challenge(source_ip)
        extra = int(global_info.get('challenge_extra_bits', 0))
        target_bits = min(
            28,
            max(int(challenge['difficulty_bits']), int(self.config.challenge_difficulty_bits) + extra)
        )
        if target_bits != int(challenge['difficulty_bits']):
            with self._connect() as con:
                con.execute('UPDATE challenges SET difficulty_bits=? WHERE source_ip=?',
                            (target_bits, source_ip))
            challenge = dict(challenge)
            challenge['difficulty_bits'] = target_bits
        challenge['scope'] = 'global-swarm-defense'
        challenge['global_mode'] = global_info['mode']
        return challenge

    def preflight(self, source_ip: str, challenge_nonce: str | None = None,
                  challenge_solution: str | None = None) -> dict:
        local = super().preflight(source_ip, challenge_nonce, challenge_solution)
        if local['action'] != 'ALLOW':
            return local

        global_info = self.global_threat()
        if global_info['mode'] not in ('GLOBAL_CHALLENGE', 'GLOBAL_HIGH'):
            local['global_threat'] = global_info
            return local

        if self._recent_global_pass(source_ip):
            local['global_threat'] = global_info
            local['global_pass'] = True
            return local

        if challenge_nonce and challenge_solution:
            if self.verify_challenge(source_ip, challenge_nonce, challenge_solution):
                return {
                    'action': 'ALLOW',
                    'subject': self.subject(source_ip),
                    'global_threat': global_info,
                    'global_pass': True,
                    'challenge_passed': True,
                }

        return {
            'action': 'CHALLENGE',
            'subject': self.subject(source_ip),
            'challenge': self._global_challenge(source_ip, global_info),
            'global_threat': global_info,
            'challenge_reason': 'distributed_swarm_anomaly',
        }

    def review_bundle(self, event_limit: int = 500, subject_limit: int = 100) -> dict:
        bundle = super().review_bundle(event_limit, subject_limit)
        bundle['sentinel_version'] = VERSION
        bundle['global_threat'] = self.global_threat(track_transition=False)
        bundle['policy']['global_swarm_detection'] = True
        bundle['policy']['automatic_rule_application'] = False
        bundle['policy']['human_approval_required_for_policy_changes'] = True
        return bundle

    def summary(self) -> dict:
        summary = super().summary()
        summary['sentinel_version'] = VERSION
        summary['mode'] = 'adaptive-defense-plus-swarm-detection'
        summary['global_threat'] = self.global_threat(track_transition=False)
        summary['ai_in_consensus'] = False
        summary['automatic_ai_policy_changes'] = False
        return summary


def _cli():
    ap = argparse.ArgumentParser(description='Stevens Sentinel v0.3 Swarm Defense')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_init = sub.add_parser('init')
    p_init.add_argument('--data-dir', required=True)
    p_init.add_argument('--public-base-url', default='http://127.0.0.1')

    p_status = sub.add_parser('status')
    p_status.add_argument('--data-dir', required=True)

    p_verify = sub.add_parser('verify')
    p_verify.add_argument('--data-dir', required=True)

    p_global = sub.add_parser('global-threat')
    p_global.add_argument('--data-dir', required=True)

    p_export = sub.add_parser('export-review')
    p_export.add_argument('--data-dir', required=True)
    p_export.add_argument('--output', required=True)

    args = ap.parse_args()
    s = StevensSentinel.load_or_create(
        args.data_dir, getattr(args, 'public_base_url', 'http://127.0.0.1')
    )
    if args.cmd == 'init':
        print(json.dumps({
            'initialized': True,
            'sentinel_version': VERSION,
            'data_dir': str(Path(args.data_dir).resolve()),
            'local_state_machine': ['NORMAL','WATCH','CHALLENGE','QUARANTINE','ISOLATE'],
            'global_modes': list(GLOBAL_MODES),
            'warning': 'TESTNET ONLY. Keep Sentinel config and decoys private.',
        }, indent=2))
    elif args.cmd == 'status':
        print(json.dumps(s.summary(), indent=2))
    elif args.cmd == 'verify':
        print('PASS' if s.verify_log_chain() else 'FAIL')
    elif args.cmd == 'global-threat':
        print(json.dumps(s.global_threat(), indent=2))
    elif args.cmd == 'export-review':
        Path(args.output).write_text(json.dumps(s.review_bundle(), indent=2))
        print(args.output)


if __name__ == '__main__':
    _cli()
