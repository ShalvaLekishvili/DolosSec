from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Observation, PlannerTurn, Target


class Planner(ABC):
    name: str

    @abstractmethod
    async def next_turn(self, target: Target, observations: list[Observation], step: int) -> PlannerTurn:
        raise NotImplementedError
