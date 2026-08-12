from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DOLOS_", env_file=".env", extra="ignore")

    llm_provider: str = "none"
    model: str = ""
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_allow_remote: bool = False
    ollama_timeout_seconds: float = 180.0
    ollama_num_ctx: int = 32768
    ollama_num_predict: int = 1200
    ollama_temperature: float = 0.1
    ollama_keep_alive: str = "10m"
    max_steps: int = 8
    output_dir: Path = Path("./dolos_runs")
    web_browse_root: Path = Path.home()
    web_max_concurrent_scans: int = 2
    enable_external_tools: bool = False
    external_tool_timeout_seconds: int = 180
    external_tool_max_output_bytes: int = 2_000_000


settings = Settings()
