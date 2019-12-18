"""
Based on https://github.com/encode/starlette/pull/529/files
"""
import abc
import base64
import binascii
import hashlib
import hmac
import random
from typing import Any, Callable, ClassVar, NewType, Sequence

from starlette.concurrency import run_in_threadpool

try:
    import argon2
except ImportError:  # pragma: no cover
    argon2 = None

try:
    import bcrypt
except ImportError:  # pragma: no cover
    bcrypt = None

ALNUM_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

RawPassword = NewType("RawPassword", str)
HashedPassword = NewType("HashedPassword", str)


class PasswordCheckingResult:
    __slots__ = ("success", "requires_update", "valid_algorithm")

    def __init__(self, success: bool, requires_update: bool = False, valid_algorithm: bool = True):
        self.success = success
        self.requires_update = requires_update
        self.valid_algorithm = valid_algorithm


class PasswordHasher(abc.ABC):
    algorithm: ClassVar[str] = ""

    async def make(self, password: RawPassword, salt: str = None, **kwargs: Any) -> HashedPassword:
        return await run_in_threadpool(self.make_sync, password, salt, **kwargs)

    async def check(self, password: RawPassword, encoded: HashedPassword) -> PasswordCheckingResult:
        return await run_in_threadpool(self.check_sync, password, encoded)

    @abc.abstractmethod
    def make_sync(self, password: RawPassword, salt: str = None, **kwargs: Any) -> HashedPassword:
        raise NotImplementedError

    @abc.abstractmethod
    def check_sync(self, password: RawPassword, encoded: HashedPassword) -> PasswordCheckingResult:
        raise NotImplementedError

    def generate_salt(self, length: int = 8) -> str:
        if length <= 0:
            raise ValueError("Salt length must be greater than zero.")
        randomizer = random.SystemRandom()
        randomizer.seed()
        return "".join(randomizer.choice(ALNUM_CHARS) for _ in range(length))


class PasswordChecker(PasswordHasher):
    """
    Checks password using multiple hashers.
    The first hasher is considered default and used to hash passwords.
    All the rest are used to check the passed password.
    """

    def __init__(self, hashers: Sequence[PasswordHasher]):
        assert len(hashers) > 0
        self._hashers = hashers

    def check_sync(self, password: RawPassword, encoded: HashedPassword) -> PasswordCheckingResult:
        algorithm, _ = encoded.split("$", 1)

        requires_update = False
        for hasher in self._hashers:
            if hasher.algorithm == algorithm:
                result = hasher.check_sync(password, encoded)
                return PasswordCheckingResult(success=result.success, requires_update=requires_update)

            # the first hasher is the default; if another is used, the password should be updated
            requires_update = True
        return PasswordCheckingResult(success=False, valid_algorithm=False)

    def make_sync(self, password: RawPassword, salt: str = None, **kwargs: Any) -> HashedPassword:
        return self._hashers[0].make_sync(password, salt, **kwargs)


class BCryptPasswordHasher(PasswordHasher):
    algorithm: ClassVar[str] = "bcrypt_sha256"
    rounds: int = 12
    digest: Callable[..., Any] = hashlib.sha256

    def __init__(self) -> None:
        assert bcrypt, "bcrypt library is not installed."

    def check_sync(self, password: RawPassword, encoded: HashedPassword) -> PasswordCheckingResult:
        algorithm, data = encoded.split("$", 1)
        assert algorithm == self.algorithm
        reference = self.make_sync(password, data)
        success = hmac.compare_digest(encoded.encode(), reference.encode())
        return PasswordCheckingResult(success=success)

    def make_sync(self, password: RawPassword, salt: str = None, *args: Any, **kwargs: Any) -> HashedPassword:
        salt = salt or self.generate_salt()

        password = RawPassword(binascii.hexlify(self.digest(password.encode()).digest()).decode())
        hash_ = bcrypt.hashpw(password.encode(), salt.encode())
        return HashedPassword("%s$%s" % (self.algorithm, hash_.decode()))

    def generate_salt(self, length: int = 8) -> str:
        if length <= 0:
            raise ValueError("Salt length must be greater than zero.")
        return bcrypt.gensalt(self.rounds).decode()


class Argon2PasswordHasher(PasswordHasher):
    algorithm: ClassVar[str] = "argon2"
    time_cost: int = 2
    memory_cost: int = 512
    parallelism: int = 2

    def __init__(self) -> None:
        assert argon2, "argon2 library is not installed."

    def check_sync(self, password: RawPassword, encoded: HashedPassword) -> PasswordCheckingResult:
        algorithm, data = encoded.split("$", 1)
        assert algorithm == self.algorithm

        try:
            success = argon2.low_level.verify_secret(
                ("$" + data).encode(), password.encode(), type=argon2.low_level.Type.I
            )
        except argon2.exceptions.VerificationError:
            success = False
        return PasswordCheckingResult(success=success)

    def make_sync(self, password: RawPassword, salt: str = None, **kwargs: Any) -> HashedPassword:
        salt = salt or self.generate_salt()
        data = argon2.low_level.hash_secret(
            password.encode(),
            salt.encode(),
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=argon2.DEFAULT_HASH_LENGTH,
            type=argon2.low_level.Type.I,
        ).decode()
        return HashedPassword(self.algorithm + data)


class PBKDF2PasswordHasher(PasswordHasher):
    algorithm: ClassVar[str] = "pbkdf2_sha256"
    rounds: int = 150000
    digest: Callable[..., Any] = hashlib.sha256

    def check_sync(self, password: RawPassword, encoded: HashedPassword) -> PasswordCheckingResult:
        algorithm, rounds, salt, hash_ = encoded.split("$", 3)
        assert algorithm == self.algorithm
        reference = self.make_sync(password, salt, rounds=int(rounds))
        success = hmac.compare_digest(encoded.encode(), reference.encode())
        return PasswordCheckingResult(success=success)

    def make_sync(self, password: RawPassword, salt: str = None, rounds: int = None, **kwargs: Any) -> HashedPassword:
        rounds = rounds or self.rounds
        salt = salt or self.generate_salt()
        hash_bytes = hashlib.pbkdf2_hmac(self.digest().name, password.encode(), salt.encode(), int(rounds), **kwargs)
        hash_b64 = base64.b64encode(hash_bytes).decode().strip()
        return HashedPassword("%s$%d$%s$%s" % (self.algorithm, self.rounds, salt, hash_b64))
