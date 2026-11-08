"""VAULT_* settings of agents-vault."""

import ipaddress
import re

from agents_common.settings import BaseServiceSettings, CsvList, SettingsError
from agents_common.settings import load_settings as _load
from pydantic import Field, ValidationInfo, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

__all__ = ["Settings", "SettingsError", "load_settings"]

_DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


class Settings(BaseServiceSettings):
    """Environment-driven settings shared by every process (web, service, sweeper, migrate)."""

    model_config = SettingsConfigDict(env_prefix="VAULT_", extra="ignore")

    allowed_cidrs: CsvList = ["127.0.0.1/32"]
    service_port: int = Field(8002, ge=1, le=65535)
    service_tokens_file: str = ""
    namespace: str
    sweeper_interval_seconds: float = Field(60, ge=5, le=3600)
    pin_grace_seconds: int = Field(600, ge=60, le=86400)
    max_value_bytes: int = Field(1048576, ge=1, le=1048576)

    @field_validator("allowed_cidrs")
    @classmethod
    def _cidrs(cls, value: list[str], info: ValidationInfo) -> list[str]:
        for item in value:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError(
                    f"VAULT_{str(info.field_name).upper()}::not a CIDR: {item!r}"
                ) from None
        return value

    @field_validator("namespace")
    @classmethod
    def _namespace(cls, value: str) -> str:
        if len(value) > 63 or not _DNS_LABEL.fullmatch(value):
            raise ValueError("VAULT_NAMESPACE::not a DNS-1123 label (at most 63 characters)")
        return value

    @model_validator(mode="after")
    def _ports(self) -> "Settings":
        if self.service_port == self.http_port:
            raise ValueError("VAULT_SERVICE_PORT::must differ from VAULT_HTTP_PORT")
        return self

    def api_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(c, strict=False) for c in self.allowed_cidrs]


def load_settings() -> Settings:
    """Load Settings from the environment or raise SettingsError naming every bad variable."""
    return _load(Settings)
