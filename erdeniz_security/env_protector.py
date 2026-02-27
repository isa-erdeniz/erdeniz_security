"""
erdeniz_security/env_protector.py — .env şifreleme/çözme.
Master password → key derivation → Fernet. ENCRYPTED_PREFIX = "ENC:v1:"
"""
from __future__ import annotations

import base64
import re
import secrets
from hashlib import sha256
from pathlib import Path

from cryptography.fernet import Fernet

from .encryption import DecryptionError

ENCRYPTED_PREFIX = "ENC:v1:"
HEADER_SALT = "# Salt:"
SENSITIVE_PATTERNS = [
    r".*PASSWORD.*",
    r".*SECRET.*",
    r".*KEY.*",
    r".*TOKEN.*",
    r".*API.*",
    r".*DATABASE_URL.*",
    r".*DSN.*",
    r".*CREDENTIALS.*",
    r".*PRIVATE.*",
]


def _compile_patterns() -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in SENSITIVE_PATTERNS]


def _is_sensitive_key(key: str) -> bool:
    return any(p.search(key) for p in _compile_patterns())


def _derive_key(master_password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or secrets.token_bytes(16)
    raw = master_password.encode("utf-8") + salt
    key_b64 = base64.urlsafe_b64encode(sha256(raw).digest())
    return key_b64, salt


class EnvProtector:
    """Master password ile .env şifreleme/çözme."""

    def __init__(self, master_password: str, salt: bytes | None = None) -> None:
        if not master_password or not master_password.strip():
            raise ValueError("Master password boş olamaz")
        self._master_password = master_password
        self._key_b64, self._salt = _derive_key(master_password, salt)
        self._fernet = Fernet(self._key_b64)

    def encrypt_env(self, input_path: str | Path, output_path: str | Path | None = None) -> str:
        """.env → .env.encrypted"""
        inp = Path(input_path)
        out = Path(output_path) if output_path else inp.with_name(inp.name + ".encrypted")
        if not inp.exists():
            raise FileNotFoundError(str(inp))
        lines = inp.read_text(encoding="utf-8", errors="replace").splitlines()
        out_lines = [
            "# ErdenizVault Encrypted Environment",
            f"# Project: {inp.parent.name}",
            f"# Encrypted: {__import__('datetime').datetime.utcnow().isoformat()}Z",
            "# Algorithm: Fernet (AES-128-CBC + HMAC-SHA256)",
            f"{HEADER_SALT} {self._salt.hex()}",
            "",
        ]
        for line in lines:
            s = line.rstrip()
            if not s.strip() or s.strip().startswith("#"):
                out_lines.append(line)
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                key, value = k.strip(), v.strip().strip("'\"")
                if _is_sensitive_key(key) and value and not value.startswith(ENCRYPTED_PREFIX):
                    enc = self._fernet.encrypt(value.encode("utf-8")).decode("ascii")
                    out_lines.append(f"{key}=ENC:v1:{enc}")
                else:
                    out_lines.append(line)
            else:
                out_lines.append(line)
        out.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
        return str(out)

    def decrypt_env(self, input_path: str | Path, output_path: str | Path | None = None) -> str:
        """.env.encrypted → .env. Salt header'dan okunur."""
        inp = Path(input_path)
        out = Path(output_path) if output_path else inp.with_name(inp.name.replace(".encrypted", "").replace(".env.encrypted", ".env"))
        if not inp.exists():
            raise FileNotFoundError(str(inp))
        content = inp.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
        salt_hex = None
        for line in lines:
            if line.strip().startswith(HEADER_SALT):
                salt_hex = line.split(HEADER_SALT, 1)[-1].strip()
                break
        decryptor = self
        if salt_hex:
            try:
                decryptor = EnvProtector(self._master_password, bytes.fromhex(salt_hex))
            except Exception:
                pass
        out_lines = []
        for line in lines:
            if line.strip().startswith("#") or not line.strip():
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                key, value = k.strip(), v.strip().strip("'\"")
                if value.startswith(ENCRYPTED_PREFIX):
                    try:
                        dec = decryptor._fernet.decrypt(value[len(ENCRYPTED_PREFIX):].encode("ascii")).decode("utf-8")
                        out_lines.append(f"{key}={dec}")
                    except Exception:
                        raise DecryptionError(f"Değer çözülemedi: {key}")
                else:
                    out_lines.append(line)
            else:
                out_lines.append(line)
        out.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
        return str(out)

    def get_value(self, encrypted_env_path: str | Path, key: str) -> str:
        """Şifreli .env'den tek değer çöz."""
        inp = Path(encrypted_env_path)
        if not inp.exists():
            raise FileNotFoundError(str(inp))
        for line in inp.read_text(encoding="utf-8").splitlines():
            if "=" not in line or line.strip().startswith("#"):
                continue
            k, _, v = line.partition("=")
            if k.strip() != key:
                continue
            value = v.strip().strip("'\"")
            if self.is_encrypted(value):
                return self._fernet.decrypt(value[len(ENCRYPTED_PREFIX):].encode("ascii")).decode("utf-8")
            return value
        raise KeyError(key)

    @staticmethod
    def is_encrypted(value: str) -> bool:
        return value.strip().startswith(ENCRYPTED_PREFIX)

    def rotate_encryption(self, env_path: str | Path, new_password: str) -> None:
        """Eski şifreyi çöz, yeni şifreyle tekrar şifrele."""
        dec_path = Path(env_path).with_suffix(".env.tmp")
        self.decrypt_env(env_path, dec_path)
        EnvProtector(new_password).encrypt_env(dec_path, env_path)
        dec_path.unlink(missing_ok=True)
