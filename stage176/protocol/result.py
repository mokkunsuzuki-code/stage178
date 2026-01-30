# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, Optional, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class Result(Generic[T]):
    """
    Stage167-B unified return type:
      - Ok(value)
      - Err(failure)
    """
    ok: bool
    value: Optional[T] = None
    failure: Optional["Failure"] = None

    @staticmethod
    def Ok(v: T) -> "Result[T]":
        return Result(ok=True, value=v, failure=None)

    @staticmethod
    def Err(f: "Failure") -> "Result[T]":
        return Result(ok=False, value=None, failure=f)

    def unwrap(self) -> T:
        if not self.ok or self.value is None:
            raise RuntimeError(f"unwrap() on Err: {self.failure}")
        return self.value

    def unwrap_err(self) -> "Failure":
        if self.ok or self.failure is None:
            raise RuntimeError("unwrap_err() on Ok")
        return self.failure


# NOTE: Failure is defined in protocol/failure.py
from protocol.failure import Failure  # noqa: E402
