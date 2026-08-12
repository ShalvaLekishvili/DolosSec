from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DOLOS_", env_file=".env", extra="ignore")

    llm_provider: str = "none"
    model: str = ""
    max_steps: int = 8
    output_dir: Path = Path("./dolos_runs")
    web_browse_root: Path = Path.home()
    web_max_concurrent_scans: int = 2


settings = Settings()
