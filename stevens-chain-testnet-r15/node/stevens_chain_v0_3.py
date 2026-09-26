"""
Stevens Chain v0.5.2 hardened networking / consensus layer.

v0.3 deliberately keeps the v0.2 transaction + Stevens Note ledger format,
and adds:
- deterministic 256-bit recovery seeds
- SQLite-backed block/mempool persistence
- dynamic proof-of-work difficulty
- cumulative-work fork choice
- deterministic tie-breaking for equal-work forks
- transaction/block size limits
- external block append and full-chain adoption
- resynchronization support for peer nodes

Research/devnet software only.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import secrets
import shutil
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import stevens_chain_v0_2 as ledger


NETWORK_VERSION = "0.3"
NETWORK_ID = "stevens-devnet-v0.3"

INITIAL_DIFFICULTY_BITS = 12
MIN_DIFFICULTY_BITS = 8
MAX_DIFFICULTY_BITS = 24
DIFFICULTY_INTERVAL = 4
TARGET_BLOCK_SECONDS = 10
MEDIAN_TIME_WINDOW = 11
MAX_FUTURE_BLOCK_SECONDS = 120

MAX_TX_BYTES = 64 * 1024
MAX_BLOCK_BYTES = 1 * 1024 * 1024
MAX_TX_PER_BLOCK = 500
MAX_MEMPOOL_TX = 2000
MAX_MEMPOOL_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024 * 1024

SEED_SIGN_SALT = b"StevensChain-v0.3-ed25519"
SEED_ENC_SALT = b"StevensChain-v0.3-x25519"


def recovery_seed() -> bytes:
    import secrets
    return secrets.token_bytes(32)


def wallet_from_seed(seed: bytes) -> ledger.Wallet:
    if len(seed) != 32:
        raise ValueError("Stevens recovery seed must be exactly 32 bytes")
    sign_seed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SEED_SIGN_SALT,
        info=b"signing-key",
    ).derive(seed)
    enc_seed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SEED_ENC_SALT,
        info=b"note-encryption-key",
    ).derive(seed)
    return ledger.Wallet(
        Ed25519PrivateKey.from_private_bytes(sign_seed),
        X25519PrivateKey.from_private_bytes(enc_seed),
    )


def wallet_from_seed_hex(seed_hex: str) -> ledger.Wallet:
    try:
        seed = bytes.fromhex(seed_hex.strip())
    except ValueError as e:
        raise ValueError("recovery seed must be hexadecimal") from e
    return wallet_from_seed(seed)


def seed_fingerprint(seed: bytes) -> str:
    # Safe short identifier; not a replacement for backing up the seed.
    return hashlib.sha256(b"StevensSeed" + seed).hexdigest()[:16]


def json_size(obj) -> int:
    return len(ledger.canonical_json(obj))


def block_work(block: dict) -> int:
    # Our toy target is 2^(256-difficulty_bits), so expected work is
    # proportional to 2^difficulty_bits.
    return 1 << int(block["difficulty_bits"])


def cumulative_work(blocks: List[dict]) -> int:
    return sum(block_work(b) for b in blocks)


def median_time_past(blocks: List[dict], next_height: int) -> int:
    """Median timestamp of the recent chain prefix before next_height."""
    if next_height <= 0 or not blocks:
        return 0
    end = min(next_height, len(blocks))
    start = max(0, end - MEDIAN_TIME_WINDOW)
    values = sorted(int(b["timestamp"]) for b in blocks[start:end])
    return values[len(values) // 2] if values else 0


def validate_block_timestamp(blocks: List[dict], height: int, now: int | None = None) -> None:
    """Reject non-monotone-MTP and excessively future-dated blocks."""
    if height < 0 or height >= len(blocks):
        raise ValueError("timestamp validation height out of range")
    ts = int(blocks[height]["timestamp"])
    now = int(time.time()) if now is None else int(now)
    if ts > now + MAX_FUTURE_BLOCK_SECONDS:
        raise ValueError(
            f"block timestamp too far in future: {ts} > {now + MAX_FUTURE_BLOCK_SECONDS}"
        )
    if height > 0:
        mtp = median_time_past(blocks, height)
        if ts <= mtp:
            raise ValueError(
                f"block timestamp not greater than median-time-past: {ts} <= {mtp}"
            )


def expected_difficulty(blocks: List[dict], next_height: int) -> int:
    if next_height == 0:
        return INITIAL_DIFFICULTY_BITS
    if not blocks:
        return INITIAL_DIFFICULTY_BITS

    previous = int(blocks[next_height - 1]["difficulty_bits"])
    if next_height < DIFFICULTY_INTERVAL:
        return previous
    if next_height % DIFFICULTY_INTERVAL != 0:
        return previous

    start = int(blocks[next_height - DIFFICULTY_INTERVAL]["timestamp"])
    end = int(blocks[next_height - 1]["timestamp"])
    actual = max(1, end - start)
    target = TARGET_BLOCK_SECONDS * max(1, DIFFICULTY_INTERVAL - 1)

    if actual < max(1, target // 2):
        return min(MAX_DIFFICULTY_BITS, previous + 1)
    if actual > target * 2:
        return max(MIN_DIFFICULTY_BITS, previous - 1)
    return previous


def chain_is_better(candidate: List[dict], current: List[dict]) -> bool:
    """Return True only when the candidate has strictly greater chain work."""
    cw = cumulative_work(candidate)
    ow = cumulative_work(current)

    # Equal-work forks do not replace the node's current chain.
    return cw > ow


class NetworkChain(ledger.Blockchain):
    def __init__(self, data_dir: Optional[str | Path] = None):
        # Do not call v0.2 disk JSON persistence; v0.3 uses SQLite.
        super().__init__(data_dir=None)
        self.v03_data_dir = Path(data_dir) if data_dir else None
        self.db_path = (
            self.v03_data_dir / "stevens_chain_v03.sqlite3"
            if self.v03_data_dir else None
        )

        # Derived, non-consensus caches rebuilt only from a fully validated
        # canonical chain. Public read paths must not rescan all historical
        # blocks merely to report already-known canonical metadata.
        self._canonical_cumulative_work = 0
        self._canonical_chain_json_bytes = 0

        if self.v03_data_dir:
            self.v03_data_dir.mkdir(parents=True, exist_ok=True)
            self._init_db()

    def _connect(self):
        if not self.db_path:
            raise ValueError("no SQLite data directory configured")
        con = sqlite3.connect(self.db_path, timeout=10)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=FULL")
        return con

    def _init_db(self):
        with self._connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS blocks(
                    height INTEGER PRIMARY KEY,
                    hash TEXT NOT NULL UNIQUE,
                    data TEXT NOT NULL
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS mempool(
                    txid TEXT PRIMARY KEY,
                    data TEXT NOT NULL
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS metadata(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS canonical_dkg(
                    epoch INTEGER PRIMARY KEY,
                    status TEXT NOT NULL,
                    transcript_hash TEXT,
                    anchor_height INTEGER
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS dkg_transcripts(
                    transcript_hash TEXT PRIMARY KEY,
                    epoch INTEGER NOT NULL,
                    data TEXT NOT NULL
                )
            """)
            con.execute(
                "INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)",
                ("network_id", NETWORK_ID),
            )
            con.execute(
                "INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)",
                ("network_version", NETWORK_VERSION),
            )

    def _mempool_encoded_bytes(self, txs=None) -> int:
        txs = self.mempool if txs is None else txs
        return sum(len(json.dumps(tx, separators=(",", ":")).encode("utf-8")) for tx in txs)

    def _check_mempool_limits(self, txs=None) -> None:
        txs = self.mempool if txs is None else txs
        if len(txs) > MAX_MEMPOOL_TX:
            raise ValueError("mempool transaction-count limit exceeded")
        if self._mempool_encoded_bytes(txs) > MAX_MEMPOOL_BYTES:
            raise ValueError("mempool byte limit exceeded")

    @staticmethod
    def _fsync_parent(path: Path) -> None:
        try:
            dfd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            # Directory fsync is not uniformly supported (notably Windows).
            pass

    def store_dkg_transcript(
        self,
        transcript: dict,
        *,
        expected_hash: str | None = None,
    ) -> str:
        """Validate and durably store canonical Stevens Dual v3 transcript data.

        Transcript bytes are data availability only. Storing a transcript does
        NOT make it canonical or ACTIVE; canonical DKG state is still derived
        exclusively from validated chain state.
        """
        if not self.db_path:
            raise ValueError(
                "DKG transcript storage requires SQLite-backed chain"
            )

        import stevens_dual_v3_research as dual_v3

        canonical = dual_v3.validate_dkg_transcript(
            transcript
        )

        actual_hash = dual_v3.dkg_transcript_hash_v3(
            canonical
        )

        if expected_hash is not None:
            if (
                not isinstance(expected_hash, str)
                or len(expected_hash) != 64
                or expected_hash != expected_hash.lower()
            ):
                raise ValueError(
                    "invalid expected DKG transcript hash"
                )

            try:
                raw = bytes.fromhex(
                    expected_hash
                )
            except ValueError as e:
                raise ValueError(
                    "invalid expected DKG transcript hash"
                ) from e

            if len(raw) != 32:
                raise ValueError(
                    "invalid expected DKG transcript hash"
                )

            if actual_hash != expected_hash:
                raise ValueError(
                    "DKG transcript hash mismatch"
                )

        data = json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
        )

        epoch = int(
            canonical["epoch"]
        )

        with self._connect() as con:
            con.execute(
                "BEGIN IMMEDIATE"
            )

            existing = con.execute(
                """
                SELECT epoch,data
                FROM dkg_transcripts
                WHERE transcript_hash=?
                """,
                (
                    actual_hash,
                ),
            ).fetchone()

            if existing is not None:
                existing_epoch = int(
                    existing[0]
                )
                existing_data = existing[1]

                if (
                    existing_epoch != epoch
                    or existing_data != data
                ):
                    raise ValueError(
                        "conflicting stored DKG transcript"
                    )

                return actual_hash

            con.execute(
                """
                INSERT INTO dkg_transcripts(
                    transcript_hash,
                    epoch,
                    data
                )
                VALUES (?, ?, ?)
                """,
                (
                    actual_hash,
                    epoch,
                    data,
                ),
            )

        return actual_hash

    def _desired_canonical_dkg_rows(self):
        """Derive DKG cache rows only from validated chain state.

        Public Stevens Chain v2 derives no DKG state.

        Stevens Dual research v3 must first pass the explicit v3
        header/linkage/hash/PoW validation gate. Mature anchors remain
        BLOCKED_DATA until exact transcript data is independently
        available and verified by the transactional ACTIVE gate.

        NOTE: the current v3 validator is still a research header/PoW
        validator. Ticket proofs, Dual proofs, transaction/Merkle payload
        validation and difficulty-retarget consensus remain separate work.
        """
        if not self.blocks:
            return []

        versions = set()

        for block in self.blocks:
            if not isinstance(block, dict):
                raise ValueError(
                    "invalid block object for DKG derivation"
                )

            version = block.get("version")

            if (
                isinstance(version, bool)
                or
                not isinstance(version, int)
            ):
                raise ValueError(
                    "invalid block version for DKG derivation"
                )

            versions.add(version)

        # Existing Stevens Chain v2 behavior remains unchanged.
        if versions == {2}:
            return []

        # Mixed v2/v3 activation semantics are not defined yet.
        # Fail closed rather than guessing an activation rule.
        if versions != {3}:
            raise ValueError(
                "mixed/unsupported block versions for DKG derivation"
            )

        import stevens_dual_v3_research as dual_v3

        # Critical gate:
        # no DKG state may be derived until the entire v3 header chain
        # passes linkage, commitment, block-hash and PoW validation.
        dual_v3.validate_v3_chain(
            self.blocks
        )

        activation_depth = 6
        rows = []

        for height, block in enumerate(self.blocks):
            anchor = block.get(
                "dkg_anchor"
            )

            if anchor is None:
                continue

            # Re-validation here also gives us the canonical anchor object.
            canonical_anchor = dual_v3.validate_dkg_anchor(
                anchor
            )

            descendants = (
                len(self.blocks) - 1 - height
            )

            status = (
                "PENDING"
                if descendants < activation_depth
                else "BLOCKED_DATA"
            )

            rows.append(
                (
                    canonical_anchor["epoch"],
                    status,
                    canonical_anchor["transcript_hash"],
                    height,
                )
            )

        return rows

    def _normalize_canonical_dkg_rows(self, rows):
        allowed_status = {
            "PENDING",
            "ACTIVE",
            "BLOCKED_DATA",
        }

        desired = {}

        for raw in rows:
            if not isinstance(raw, (tuple, list)) or len(raw) != 4:
                raise ValueError("invalid canonical DKG row")

            epoch, status, transcript_hash, anchor_height = raw

            epoch = int(epoch)
            anchor_height = int(anchor_height)
            status = str(status)

            if epoch < 0:
                raise ValueError("negative DKG epoch")

            if anchor_height < 0:
                raise ValueError("negative DKG anchor height")

            if status not in allowed_status:
                raise ValueError("invalid canonical DKG status")

            if (
                not isinstance(transcript_hash, str)
                or len(transcript_hash) != 64
            ):
                raise ValueError("invalid DKG transcript hash")

            try:
                bytes.fromhex(transcript_hash)
            except ValueError as e:
                raise ValueError("invalid DKG transcript hash") from e

            transcript_hash = transcript_hash.lower()

            if epoch in desired:
                raise ValueError("duplicate canonical DKG epoch")

            desired[epoch] = (
                status,
                transcript_hash,
                anchor_height,
            )

        return desired

    def _verified_dkg_transcript_available_in_tx(
        self,
        con,
        epoch: int,
        transcript_hash: str,
    ) -> bool:
        """Return True only for exact, canonical, hash-matching transcript data."""
        row = con.execute(
            """
            SELECT epoch,data
            FROM dkg_transcripts
            WHERE transcript_hash=?
            """,
            (
                transcript_hash,
            ),
        ).fetchone()

        if row is None:
            return False

        stored_epoch, data = row

        if int(stored_epoch) != int(epoch):
            return False

        try:
            transcript = json.loads(data)

            import stevens_dual_v3_research as dual_v3

            canonical = dual_v3.validate_dkg_transcript(
                transcript
            )

            if int(canonical["epoch"]) != int(epoch):
                return False

            actual_hash = dual_v3.dkg_transcript_hash_v3(
                canonical
            )

            if actual_hash != transcript_hash:
                return False

            # Stored bytes themselves must be the exact canonical JSON form.
            canonical_data = json.dumps(
                canonical,
                sort_keys=True,
                separators=(",", ":"),
            )

            if data != canonical_data:
                return False

        except Exception:
            # Transcript availability must fail closed.
            return False

        return True

    def _sync_canonical_dkg_in_tx(self, con) -> None:
        """Synchronize derived DKG state inside the caller's SQLite tx."""
        desired = self._normalize_canonical_dkg_rows(
            self._desired_canonical_dkg_rows()
        )

        # A mature on-chain anchor begins as BLOCKED_DATA.
        # Promote it to ACTIVE only when the exact canonical transcript
        # exists locally and re-verifies against the anchored hash.
        promoted = {}

        for epoch, (
            status,
            transcript_hash,
            anchor_height,
        ) in desired.items():

            if (
                status == "BLOCKED_DATA"
                and
                self._verified_dkg_transcript_available_in_tx(
                    con,
                    epoch,
                    transcript_hash,
                )
            ):
                status = "ACTIVE"

            promoted[epoch] = (
                status,
                transcript_hash,
                anchor_height,
            )

        desired = promoted

        persisted = {
            int(epoch): (
                status,
                transcript_hash,
                int(anchor_height),
            )
            for (
                epoch,
                status,
                transcript_hash,
                anchor_height,
            ) in con.execute(
                """
                SELECT
                    epoch,
                    status,
                    transcript_hash,
                    anchor_height
                FROM canonical_dkg
                """
            ).fetchall()
        }

        for epoch in set(persisted) - set(desired):
            con.execute(
                "DELETE FROM canonical_dkg WHERE epoch=?",
                (epoch,),
            )

        for epoch, (
            status,
            transcript_hash,
            anchor_height,
        ) in desired.items():

            wanted = (
                status,
                transcript_hash,
                anchor_height,
            )

            if persisted.get(epoch) == wanted:
                continue

            con.execute(
                """
                INSERT OR REPLACE INTO canonical_dkg(
                    epoch,
                    status,
                    transcript_hash,
                    anchor_height
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    epoch,
                    status,
                    transcript_hash,
                    anchor_height,
                ),
            )

    def _reconcile_canonical_dkg_from_chain(self) -> None:
        """Rebuild derived DKG cache from the already-validated chain."""
        if not self.db_path:
            return

        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            self._sync_canonical_dkg_in_tx(con)

    def save(self) -> None:
        """Persist only the changed chain suffix and mempool delta.

        Earlier versions deleted/reinserted the entire block table for every
        transaction, block, or reorg. r6 keeps the same SQLite transaction
        boundary but rewrites only the divergent suffix, avoiding O(chain)
        write amplification as the testnet grows.
        """
        if not self.db_path:
            return
        self._check_mempool_limits()
        desired_mp = {
            tx["txid"]: json.dumps(tx, separators=(",", ":"))
            for tx in self.mempool
        }
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")

            persisted = con.execute(
                "SELECT height,hash FROM blocks ORDER BY height"
            ).fetchall()
            common = 0
            max_common = min(len(persisted), len(self.blocks))
            while common < max_common:
                h, bh = persisted[common]
                if int(h) != common or bh != self.blocks[common].get("hash"):
                    break
                common += 1
            if common < len(persisted):
                con.execute("DELETE FROM blocks WHERE height>=?", (common,))
            for b in self.blocks[common:]:
                con.execute(
                    "INSERT INTO blocks(height,hash,data) VALUES(?,?,?)",
                    (int(b["height"]), b["hash"], json.dumps(b, separators=(",", ":"))),
                )

            # DKG state is derived from the same canonical block view and
            # persisted inside this exact block/mempool/metadata transaction.
            self._sync_canonical_dkg_in_tx(con)

            persisted_mp = {
                row[0]: row[1] for row in
                con.execute("SELECT txid,data FROM mempool").fetchall()
            }
            for txid in set(persisted_mp) - set(desired_mp):
                con.execute("DELETE FROM mempool WHERE txid=?", (txid,))
            for txid, data in desired_mp.items():
                if persisted_mp.get(txid) != data:
                    con.execute(
                        "INSERT OR REPLACE INTO mempool(txid,data) VALUES(?,?)",
                        (txid, data),
                    )

            con.execute(
                "INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)",
                ("tip", self.blocks[-1]["hash"] if self.blocks else ""),
            )
            con.execute(
                "INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)",
                ("cumulative_work", str(self.canonical_cumulative_work())),
            )

    def export_snapshot(self, path: str | Path) -> dict:
        """Atomically export a self-validating SQLite recovery snapshot.

        This is an operational recovery snapshot, not a consensus checkpoint
        and not permission to prune historical blocks.
        """
        if not self.db_path:
            raise ValueError("snapshot export requires SQLite-backed chain")
        self.save()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".tmp-" + secrets.token_hex(8))
        try:
            with self._connect() as src, sqlite3.connect(tmp) as dst:
                src.backup(dst)
                dst.commit()
                # Recovery snapshots must be self-contained single files. A
                # WAL-mode database can require sidecar -wal/-shm files even
                # when the main file itself looks complete. Normalize the
                # exported copy to rollback-journal mode before sealing it.
                dst.execute("PRAGMA journal_mode=DELETE").fetchone()
                dst.execute(
                    "INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)",
                    ("snapshot_format", "StevensChainSnapshot-v1"),
                )
                dst.execute(
                    "INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)",
                    ("snapshot_height", str(len(self.blocks) - 1)),
                )
                dst.execute(
                    "INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)",
                    ("snapshot_tip", self.blocks[-1]["hash"] if self.blocks else ""),
                )
                check = dst.execute("PRAGMA quick_check").fetchone()
                if not check or check[0] != "ok":
                    raise ValueError("snapshot SQLite integrity check failed")
            fd = os.open(str(tmp), os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, target)
            self._fsync_parent(target)
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
        return {
            "path": str(target),
            "height": len(self.blocks) - 1,
            "tip": self.blocks[-1]["hash"] if self.blocks else "",
            "cumulative_work": self.canonical_cumulative_work(),
        }

    def _validate_snapshot_file(self, path: str | Path):
        path = Path(path)
        try:
            size = path.stat().st_size
        except OSError as e:
            raise ValueError("unable to stat snapshot") from e
        if size <= 0 or size > MAX_SNAPSHOT_BYTES:
            raise ValueError("snapshot size outside safety bounds")
        uri = f"file:{path.resolve()}?mode=ro"
        try:
            con = sqlite3.connect(uri, uri=True, timeout=10)
            try:
                check = con.execute("PRAGMA quick_check").fetchone()
                if not check or check[0] != "ok":
                    raise ValueError("snapshot SQLite integrity check failed")
                meta = dict(con.execute("SELECT key,value FROM metadata").fetchall())
                if meta.get("network_id") != NETWORK_ID:
                    raise ValueError("snapshot storage network mismatch")
                if meta.get("snapshot_format") != "StevensChainSnapshot-v1":
                    raise ValueError("unsupported or missing snapshot format")
                rows = con.execute("SELECT data FROM blocks ORDER BY height").fetchall()
                mp_rows = con.execute(
                    "SELECT data FROM mempool ORDER BY rowid LIMIT ?",
                    (MAX_MEMPOOL_TX + 1,),
                ).fetchall()
                if len(mp_rows) > MAX_MEMPOOL_TX:
                    raise ValueError("snapshot mempool exceeds count limit")
            finally:
                con.close()
        except sqlite3.DatabaseError as e:
            raise ValueError("invalid or partial SQLite snapshot") from e

        blocks = [json.loads(r[0]) for r in rows]
        candidates = [json.loads(r[0]) for r in mp_rows]
        if not blocks:
            raise ValueError("snapshot contains no chain")
        if meta.get("snapshot_tip") != blocks[-1].get("hash"):
            raise ValueError("snapshot tip metadata mismatch")
        if int(meta.get("snapshot_height", -2)) != len(blocks) - 1:
            raise ValueError("snapshot height metadata mismatch")

        tester = type(self)()
        tester.blocks = copy.deepcopy(blocks)
        tester.validate_chain(rebuild=True)
        tester.mempool = []
        for tx in candidates:
            tester.submit_tx(tx, save=False)
        tester._check_mempool_limits()
        return blocks, candidates

    @staticmethod
    def _remove_sqlite_sidecars(db_path: Path) -> None:
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(db_path) + suffix)
            try:
                if sidecar.exists():
                    sidecar.unlink()
            except OSError:
                # Import will validate after replacement; inability to clear a
                # stale sidecar must fail rather than risk mixed database state.
                raise

    def import_snapshot(self, path: str | Path, *, allow_rollback: bool = False) -> dict:
        """Validate then atomically install a recovery snapshot.

        By default a snapshot may not reduce cumulative work relative to the
        current valid chain. A partial/corrupt snapshot is rejected before the
        live database is touched.
        """
        if not self.db_path:
            raise ValueError("snapshot import requires SQLite-backed chain")
        blocks, candidates = self._validate_snapshot_file(path)
        if self.blocks:
            if blocks[0].get("hash") != self.blocks[0].get("hash"):
                raise ValueError("snapshot belongs to a different genesis")
            if not allow_rollback and cumulative_work(blocks) < cumulative_work(self.blocks):
                raise ValueError("snapshot would roll back cumulative work")

        target = Path(self.db_path)
        incoming = target.with_name(target.name + ".incoming-" + secrets.token_hex(8))
        backup = target.with_name(target.name + ".preimport-" + secrets.token_hex(8))
        try:
            # Copy through SQLite's backup API so the incoming image is a clean
            # single-file database even if the source was produced in WAL mode.
            src_uri = f"file:{Path(path).resolve()}?mode=ro"
            with sqlite3.connect(src_uri, uri=True, timeout=10) as src, sqlite3.connect(incoming) as dst:
                src.backup(dst)
                dst.commit()
                dst.execute("PRAGMA journal_mode=DELETE").fetchone()
                check = dst.execute("PRAGMA quick_check").fetchone()
                if not check or check[0] != "ok":
                    raise ValueError("incoming snapshot copy failed integrity check")
            fd = os.open(str(incoming), os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

            if target.exists():
                # Make the current main DB self-contained before copying it.
                # Otherwise an old WAL could contain committed pages that are
                # not present in the main file yet.
                with self._connect() as live:
                    live.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                shutil.copy2(target, backup)
                bfd = os.open(str(backup), os.O_RDONLY)
                try:
                    os.fsync(bfd)
                finally:
                    os.close(bfd)
            # WAL/SHM files are tied to the old main database image. They must
            # never survive across an atomic snapshot replacement.
            self._remove_sqlite_sidecars(target)
            os.replace(incoming, target)
            self._fsync_parent(target)
            try:
                self.load()
                if self.blocks[-1].get("hash") != blocks[-1].get("hash"):
                    raise ValueError("installed snapshot tip mismatch")
            except Exception:
                if backup.exists():
                    self._remove_sqlite_sidecars(target)
                    os.replace(backup, target)
                    self._fsync_parent(target)
                    self.load()
                raise
        finally:
            for q in (incoming, backup):
                try:
                    if q.exists():
                        q.unlink()
                except OSError:
                    pass
        return {
            "height": len(self.blocks) - 1,
            "tip": self.blocks[-1]["hash"],
            "cumulative_work": self.canonical_cumulative_work(),
        }

    def pruning_status(self) -> dict:
        return {
            "enabled": False,
            "reason": (
                "historical pruning is intentionally disabled until a formally "
                "specified trusted-checkpoint/state-commitment design exists"
            ),
        }

    def load(self) -> None:
        if not self.db_path:
            raise ValueError("no SQLite data directory configured")
        with self._connect() as con:
            row = con.execute(
                "SELECT value FROM metadata WHERE key='network_id'"
            ).fetchone()
            if row and row[0] != NETWORK_ID:
                raise ValueError("SQLite database belongs to a different network")
            rows = con.execute(
                "SELECT data FROM blocks ORDER BY height"
            ).fetchall()
            self.blocks = [json.loads(r[0]) for r in rows]
            mp = con.execute(
                "SELECT data FROM mempool ORDER BY rowid LIMIT ?",
                (MAX_MEMPOOL_TX + 1,),
            ).fetchall()
            if len(mp) > MAX_MEMPOOL_TX:
                raise ValueError("persisted mempool exceeds count limit")
            candidates = [json.loads(r[0]) for r in mp]

        if self.blocks:
            self.validate_chain(rebuild=True)

        # canonical_dkg is a derived cache, never an independent source of
        # consensus truth. Rebuild it from the validated canonical chain.
        self._reconcile_canonical_dkg_from_chain()

        self.mempool = []
        for tx in candidates:
            try:
                super().submit_tx(tx, save=False)
            except ValueError:
                pass

    def initialize_from_genesis_block(self, block: dict) -> None:
        if self.blocks:
            if self.blocks[0]["hash"] != block["hash"]:
                raise ValueError("existing node has a different genesis")
            return
        self.blocks = [copy.deepcopy(block)]
        self.validate_chain(rebuild=True)
        self.save()

    def _limits_check_tx(self, tx: dict) -> None:
        n = json_size(tx)
        if n > MAX_TX_BYTES:
            raise ValueError(f"transaction too large: {n} > {MAX_TX_BYTES} bytes")

    def _limits_check_block(self, block: dict) -> None:
        # Untrusted peer data must fail closed before any .get(), len(),
        # or transaction-field access can leak Python container exceptions.
        if not isinstance(block, dict):
            raise ValueError("invalid block object")

        txs = block.get("transactions")

        if not isinstance(txs, list):
            raise ValueError("block transactions must be list")

        if len(txs) > MAX_TX_PER_BLOCK + 1:
            raise ValueError("too many transactions in block")

        n = json_size(block)

        if n > MAX_BLOCK_BYTES:
            raise ValueError(f"block too large: {n} > {MAX_BLOCK_BYTES} bytes")

        for tx in txs:
            if not isinstance(tx, dict):
                raise ValueError("invalid transaction object")

            if tx.get("kind") == "payment":
                self._limits_check_tx(tx)

    def validate_chain(self, rebuild: bool = False) -> bool:
        if self.blocks:
            genesis_hash = self.blocks[0]["hash"]
        else:
            genesis_hash = None

        now = int(time.time())
        for height, block in enumerate(self.blocks):
            self._limits_check_block(block)
            validate_block_timestamp(self.blocks, height, now=now)
            want = expected_difficulty(self.blocks[:height], height)
            got = int(block["difficulty_bits"])
            if got != want:
                raise ValueError(
                    f"wrong difficulty at height {height}: got {got}, expected {want}"
                )
            if height > 0 and self.blocks[0]["hash"] != genesis_hash:
                raise ValueError("genesis changed inside chain")

        valid = super().validate_chain(rebuild=rebuild)

        if rebuild:
            # These scans happen only while rebuilding already-validated
            # canonical state. Normal public reads use the derived caches.
            self._canonical_cumulative_work = cumulative_work(
                self.blocks
            )
            self._canonical_chain_json_bytes = sum(
                json_size(block)
                for block in self.blocks
            )

        return valid

    def canonical_cumulative_work(self) -> int:
        return int(self._canonical_cumulative_work)

    def canonical_chain_json_bytes(self) -> int:
        return int(self._canonical_chain_json_bytes)

    def submit_tx(self, tx: dict, save: bool = True) -> str:
        self._limits_check_tx(tx)
        old_mp = list(self.mempool)
        if len(old_mp) >= MAX_MEMPOOL_TX:
            raise ValueError("mempool transaction-count limit exceeded")
        projected_bytes = self._mempool_encoded_bytes(old_mp) + len(
            json.dumps(tx, separators=(",", ":")).encode("utf-8")
        )
        if projected_bytes > MAX_MEMPOOL_BYTES:
            raise ValueError("mempool byte limit exceeded")
        txid = super().submit_tx(tx, save=False)
        if save:
            try:
                self.save()
            except Exception:
                # Keep in-memory and durable state aligned if persistence fails.
                # A caller must never observe a transaction as accepted locally
                # when the durable mempool write was rolled back.
                self.mempool = old_mp
                raise
        return txid

    def mine_mempool(self, miner) -> dict:
        if not self.blocks:
            raise ValueError("chain not initialized")

        old_mp = list(self.mempool)
        temp = dict(self.utxos)
        valid_txs = []
        total_fees = 0
        estimated_payload = 4096  # headroom for header + coinbase

        for tx in self.mempool:
            if len(valid_txs) >= MAX_TX_PER_BLOCK:
                break
            self._limits_check_tx(tx)
            tx_bytes = json_size(tx)
            if estimated_payload + tx_bytes > MAX_BLOCK_BYTES:
                break
            try:
                fee = self._apply_payment(tx, temp)
            except ValueError:
                continue
            valid_txs.append(tx)
            total_fees += fee
            estimated_payload += tx_bytes

        height = len(self.blocks)
        coinbase = ledger.make_coinbase_tx(
            miner,
            ledger.BLOCK_REWARD + total_fees,
            height,
            f"v0.3 block {height} mining reward + fees",
        )
        diff = expected_difficulty(self.blocks, height)
        mtp = median_time_past(self.blocks, height)
        mine_ts = max(int(time.time()), mtp + 1)
        block = ledger.mine_block(
            height,
            self.blocks[-1]["hash"],
            [coinbase] + valid_txs,
            difficulty_bits=diff,
            timestamp=mine_ts,
        )
        self._limits_check_block(block)

        old_blocks = self.blocks
        self.blocks = old_blocks + [block]
        try:
            self.validate_chain(rebuild=True)
        except Exception:
            self.blocks = old_blocks
            self.validate_chain(rebuild=True)
            raise

        mined = {x["txid"] for x in valid_txs}
        self.mempool = [x for x in self.mempool if x.get("txid") not in mined]
        try:
            self.save()
        except Exception:
            # save() is a single SQLite transaction. If it fails, restore the
            # pre-mine in-memory view so process state cannot get ahead of disk.
            self.blocks = old_blocks
            self.mempool = old_mp
            self.validate_chain(rebuild=True)
            raise
        return block

    def append_external_block(self, block: dict) -> bool:
        self._limits_check_block(block)
        if not self.blocks:
            raise ValueError("node has no genesis")
        if int(block["height"]) != len(self.blocks):
            raise ValueError("external block is not the next height")
        if block["previous_hash"] != self.blocks[-1]["hash"]:
            raise ValueError("external block does not extend current tip")
        want = expected_difficulty(self.blocks, len(self.blocks))
        if int(block["difficulty_bits"]) != want:
            raise ValueError("external block has wrong difficulty")

        old = self.blocks
        old_mp = list(self.mempool)
        self.blocks = old + [copy.deepcopy(block)]
        try:
            self.validate_chain(rebuild=True)
        except Exception:
            self.blocks = old
            self.mempool = old_mp
            self.validate_chain(rebuild=True)
            raise

        confirmed = {
            tx["txid"] for tx in block["transactions"]
            if tx.get("kind") == "payment"
        }
        self.mempool = [tx for tx in old_mp if tx["txid"] not in confirmed]

        # Revalidate remaining mempool against new confirmed state.
        survivors = list(self.mempool)
        self.mempool = []
        for tx in survivors:
            try:
                super().submit_tx(tx, save=False)
            except ValueError:
                pass
        try:
            self.save()
        except Exception:
            self.blocks = old
            self.mempool = old_mp
            self.validate_chain(rebuild=True)
            raise
        return True

    def try_adopt_chain(self, candidate_blocks: List[dict]) -> bool:
        if not candidate_blocks:
            return False
        if self.blocks and candidate_blocks[0]["hash"] != self.blocks[0]["hash"]:
            raise ValueError("candidate belongs to a different genesis network")

        tester = NetworkChain()
        tester.blocks = copy.deepcopy(candidate_blocks)
        tester.validate_chain(rebuild=True)

        if not chain_is_better(candidate_blocks, self.blocks):
            return False

        old_mempool = list(self.mempool)
        included = {
            tx["txid"]
            for b in candidate_blocks
            for tx in b.get("transactions", [])
            if tx.get("kind") == "payment"
        }

        self.blocks = copy.deepcopy(candidate_blocks)
        self.validate_chain(rebuild=True)
        self.mempool = []

        for tx in old_mempool:
            if tx.get("txid") in included:
                continue
            try:
                super().submit_tx(tx, save=False)
            except ValueError:
                pass

        self.save()
        return True

    def public_status(self) -> dict:
        base = super().public_status()
        base.update({
            "network_id": NETWORK_ID,
            "network_version": NETWORK_VERSION,
            "cumulative_work": self.canonical_cumulative_work(),
            "next_difficulty_bits": (
                expected_difficulty(self.blocks, len(self.blocks))
                if self.blocks else INITIAL_DIFFICULTY_BITS
            ),
            "storage": "sqlite" if self.db_path else "memory",
            "max_tx_bytes": MAX_TX_BYTES,
            "max_block_bytes": MAX_BLOCK_BYTES,
        })
        return base
