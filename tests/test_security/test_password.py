import pytest

from fastapi_auth.auth_settings import get_auth_settings
from fastapi_auth.security.password import (
    Argon2PasswordHasher,
    BCryptPasswordHasher,
    HashedPassword,
    PasswordChecker,
    PasswordHasher,
    PBKDF2PasswordHasher,
    RawPassword,
)

argon_hasher = Argon2PasswordHasher()
pbkdf_hasher = PBKDF2PasswordHasher()
bcrypt_hasher = BCryptPasswordHasher()


def test_default_password() -> None:
    checker = get_auth_settings().password_checker
    password = RawPassword("password")
    hashed = checker.make_sync(password)
    assert checker.check_sync(password, hashed).success
    assert not checker.check_sync(RawPassword("not password"), hashed).success


def test_multi_checker() -> None:
    checker = PasswordChecker([bcrypt_hasher, pbkdf_hasher, argon_hasher])
    password = RawPassword("password")
    hashed = pbkdf_hasher.make_sync(password)
    result = checker.check_sync(password, hashed)
    assert result.success
    assert result.requires_update
    assert result.valid_algorithm
    assert not checker.check_sync(RawPassword("not password"), hashed).success


def test_invalid_algorithm() -> None:
    checker = PasswordChecker([argon_hasher])
    password = RawPassword("password")
    hashed = pbkdf_hasher.make_sync(password)
    result = checker.check_sync(password, hashed)
    assert result.success is False
    assert result.requires_update is False
    assert result.valid_algorithm is False


def test_argon_fail() -> None:
    assert argon_hasher.check_sync(RawPassword("hello"), HashedPassword("argon2$blah")).success is False


@pytest.mark.parametrize("hasher", [argon_hasher, bcrypt_hasher, pbkdf_hasher])
def test_salt_fail(hasher: PasswordHasher) -> None:
    with pytest.raises(ValueError) as exc_info:
        hasher.generate_salt(length=0)
    assert str(exc_info.value) == "Salt length must be greater than zero."


@pytest.mark.asyncio
@pytest.mark.parametrize("hasher", [argon_hasher, bcrypt_hasher, pbkdf_hasher])
async def test_hashers_async(hasher: PasswordHasher) -> None:
    password = RawPassword("password")
    hashed = await hasher.make(password)
    assert (await hasher.check(password, hashed)).success
