"""HTTP fuzzing service with bounded, structured results."""
from __future__ import annotations

from dataclasses import dataclass, asdict
import time
from typing import Any, Callable, Iterable

import requests

from .detectors import detect_indicators
from .payloads import Payload
from .recon import ReconConfig, ReconProfile, recon_target

MAX_TIMEOUT = 120.0
MAX_PAUSE = 60.0
MAX_REQUESTS = 500
AUTO_PARAMETER = "auto"


@dataclass(frozen=True)
class FuzzConfig:
    url: str
    parameter: str
    method: str = "GET"
    body_type: str = "form"
    timeout: float = 10.0
    pause: float = 0.5
    timing_threshold: float | None = None
    max_requests: int = MAX_REQUESTS

    def validate(self) -> None:
        if not self.url.startswith(("http://", "https://")):
            raise ValueError("La URL debe comenzar con http:// o https://")
        if not self.parameter.strip():
            raise ValueError("El parámetro objetivo es obligatorio; usa 'auto' para detectarlo desde recon")
        if self.method.upper() not in {"GET", "POST"}:
            raise ValueError("El método debe ser GET o POST")
        if self.body_type not in {"form", "json"}:
            raise ValueError("body_type debe ser form o json")
        if not 0.1 <= self.timeout <= MAX_TIMEOUT:
            raise ValueError(f"timeout debe estar entre 0.1 y {MAX_TIMEOUT}")
        if not 0 <= self.pause <= MAX_PAUSE:
            raise ValueError(f"pause debe estar entre 0 y {MAX_PAUSE}")
        if not 1 <= self.max_requests <= MAX_REQUESTS:
            raise ValueError(f"max_requests debe estar entre 1 y {MAX_REQUESTS}")


@dataclass
class FuzzResult:
    category: str
    technique: str
    parameter: str
    payload: str
    status_code: int | None
    response_length: int
    elapsed: float
    indicators: list[str]
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parameters_for(config: FuzzConfig, profile: ReconProfile | None) -> list[str]:
    if config.parameter.strip().lower() != AUTO_PARAMETER:
        return [config.parameter.strip()]
    if profile is None:
        raise ValueError("El modo automático requiere un perfil de reconocimiento")
    if not profile.parameters:
        raise ValueError("Recon no encontró parámetros candidatos en el target")
    return profile.parameters


def fuzz_target(
    config: FuzzConfig,
    payloads: Iterable[Payload],
    *,
    session: requests.Session | None = None,
    on_result: Callable[[FuzzResult], None] | None = None,
    on_recon: Callable[[ReconProfile], None] | None = None,
    perform_recon: bool = True,
    recon_profile: ReconProfile | None = None,
) -> list[FuzzResult]:
    config.validate()
    client = session or requests.Session()
    profile = recon_profile
    if profile is None and perform_recon:
        profile = recon_target(ReconConfig(config.url, min(config.timeout, 30.0)), session=client)
        if on_recon:
            on_recon(profile)
    parameters = _parameters_for(config, profile)
    payload_list = list(payloads)
    results: list[FuzzResult] = []
    threshold = config.timing_threshold if config.timing_threshold is not None else max(4.0, config.timeout * 0.75)
    request_index = 0
    for parameter in parameters:
        for payload in payload_list:
            if request_index >= config.max_requests:
                return results
            request_index += 1
            started = time.monotonic()
            try:
                data = {parameter: payload.value}
                if config.method.upper() == "GET":
                    response = client.get(config.url, params=data, timeout=config.timeout)
                elif config.body_type == "json":
                    response = client.post(config.url, json=data, timeout=config.timeout)
                else:
                    response = client.post(config.url, data=data, timeout=config.timeout)
                elapsed = time.monotonic() - started
                result = FuzzResult(payload.category, payload.technique, parameter, payload.value, response.status_code,
                                    len(response.text), elapsed,
                                    detect_indicators(payload, response.text, elapsed, timing_threshold=threshold))
            except requests.RequestException as exc:
                elapsed = time.monotonic() - started
                result = FuzzResult(payload.category, payload.technique, parameter, payload.value, None, 0, elapsed, [], str(exc))
            results.append(result)
            if on_result:
                on_result(result)
            if request_index < config.max_requests and config.pause:
                time.sleep(config.pause)
    return results


__all__ = ["AUTO_PARAMETER", "FuzzConfig", "FuzzResult", "fuzz_target"]
