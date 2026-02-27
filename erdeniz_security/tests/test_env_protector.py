from erdeniz_security.env_protector import EnvProtector, _is_sensitive_key


def test_is_sensitive_key():
    assert _is_sensitive_key("DATABASE_PASSWORD") is True
    assert _is_sensitive_key("SECRET_KEY") is True
    assert _is_sensitive_key("DEBUG") is False


def test_encrypt_decrypt_env(tmp_path):
    (tmp_path / ".env").write_text("SECRET_KEY=mysecret\nDEBUG=False\n")
    p = EnvProtector("master123")
    p.encrypt_env(tmp_path / ".env", tmp_path / ".env.encrypted")
    content = (tmp_path / ".env.encrypted").read_text()
    assert "SECRET_KEY=ENC:v1:" in content
    p.decrypt_env(tmp_path / ".env.encrypted", tmp_path / ".env.dec")
    assert "SECRET_KEY=mysecret" in (tmp_path / ".env.dec").read_text()
