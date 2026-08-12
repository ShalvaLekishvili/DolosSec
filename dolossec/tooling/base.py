from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..models import Observation


class Tool(ABC):
    name: str

    @abstractmethod
    async def run(self, arguments: dict[str, Any]) -> Observation:
        raise NotImplementedError
