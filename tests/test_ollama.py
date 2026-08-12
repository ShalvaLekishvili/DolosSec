import json

import httpx
import pytest

from dolossec.llm.ollama_provider import OllamaClient, OllamaPlanner
from dolossec.models import Target, TargetKind


def test_ollama_blocks_remote_host_by_default():
    with pytest.raises(ValueError, match="remote Ollama hosts are blocked"):
        OllamaClient("http://192.0.2.10:11434")


@pytest.mark.asyncio
async def test_ollama_client_status_and_models():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "9.9.9"})
        if request.url.path == "/api/tags":
            return httpx.Response(
                200,
                json={
                    "models": [
                        {
                            "name": "qwen3.5:9b",
                            "model": "qwen3.5:9b",
                            "size": 123,
                            "details": {"parameter_size": "9B", "quantization_level": "Q4_K_M"},
                        }
                    ]
                },
            )
        return httpx.Response(404)

    client = OllamaClient(transport=httpx.MockTransport(handler))
    assert await client.version() == "9.9.9"
    models = await client.list_models()
    assert models[0]["name"] == "qwen3.5:9b"


@pytest.mark.asyncio
async def test_ollama_planner_uses_structured_schema_without_executing_tools():
    seen = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path != "/api/chat":
            return httpx.Response(404)
        body = json.loads(request.content)
        seen.update(body)
        return httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": json.dumps(
                        {
                            "summary": "Map the authorized source tree first.",
                            "actions": [
                                {
                                    "tool": "source_map",
                                    "arguments": {"path": "/authorized/app"},
                                    "reason": "Establish application structure before review.",
                                }
                            ],
                        }
                    ),
                },
                "done": True,
            },
        )

    client = OllamaClient(transport=httpx.MockTransport(handler))
    planner = OllamaPlanner("qwen3.5:9b", client=client)
    turn = await planner.next_turn(Target(kind=TargetKind.local_path, value="/authorized/app"), [], 0)
    assert turn.actions[0].tool == "source_map"
    assert seen["model"] == "qwen3.5:9b"
    assert seen["stream"] is False
    assert seen["think"] is False
    assert seen["format"]["type"] == "object"
