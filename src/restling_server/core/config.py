"""Application configuration loaded from environment variables."""

from typing import Literal, Self

from pydantic import (
    AnyHttpUrl,
    EmailStr,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated server configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    postgres_user: str = Field(min_length=1)
    postgres_password: SecretStr
    postgres_db: str = Field(min_length=1)

    postgres_host: str = "127.0.0.1"
    postgres_port: int = Field(default=5432, ge=1, le=65535)

    invitation_expiry_hours: int = Field(
        default=24,
        ge=1,
        validation_alias="RESTLING_INVITATION_EXPIRY_HOURS",
    )

    public_url: AnyHttpUrl | None = Field(
        default=None,
        validation_alias="RESTLING_PUBLIC_URL",
    )

    @field_validator("public_url")
    @classmethod
    def validate_public_url(
        cls,
        value: AnyHttpUrl | None,
    ) -> AnyHttpUrl | None:
        """Require a trusted HTTPS URL or local development HTTP."""
        if value is None:
            return None

        if value.username is not None or value.password is not None:
            raise ValueError("Public URL must not contain credentials.")

        if value.query is not None or value.fragment is not None:
            raise ValueError("Public URL must not contain a query or fragment.")

        local_hosts = {"localhost", "127.0.0.1", "[::1]"}

        if value.scheme != "https" and value.host not in local_hosts:
            raise ValueError("Public URL must use HTTPS outside localhost.")

        return value

    # SMTP is optional. Without a host, invitations use manual delivery.
    smtp_host: str | None = Field(
        default=None,
        validation_alias="RESTLING_SMTP_HOST",
    )
    smtp_port: int = Field(
        default=587,
        ge=1,
        le=65535,
        validation_alias="RESTLING_SMTP_PORT",
    )
    smtp_security: Literal["starttls", "ssl", "none"] = Field(
        default="starttls",
        validation_alias="RESTLING_SMTP_SECURITY",
    )
    smtp_username: str | None = Field(
        default=None,
        validation_alias="RESTLING_SMTP_USERNAME",
    )
    smtp_password: SecretStr | None = Field(
        default=None,
        validation_alias="RESTLING_SMTP_PASSWORD",
    )
    smtp_from_email: EmailStr | None = Field(
        default=None,
        validation_alias="RESTLING_SMTP_FROM_EMAIL",
    )

    @model_validator(mode="after")
    def validate_smtp_configuration(self) -> Self:
        """Reject incomplete SMTP configurations."""
        if self.smtp_host is not None:
            self.smtp_host = self.smtp_host.strip()

            if not self.smtp_host:
                raise ValueError("SMTP host must not be empty.")

        if self.smtp_host is None:
            if any(
                value is not None
                for value in (
                    self.smtp_username,
                    self.smtp_password,
                    self.smtp_from_email,
                )
            ):
                raise ValueError(
                    "SMTP host is required when SMTP credentials "
                    "or sender email are configured."
                )

            return self

        if self.smtp_from_email is None:
            raise ValueError("SMTP sender email is required when SMTP is enabled.")

        if (self.smtp_username is None) != (self.smtp_password is None):
            raise ValueError("SMTP username and password must be configured together.")

        if self.smtp_security == "none":
            local_hosts = {"localhost", "127.0.0.1", "::1", "[::1]"}

            if self.smtp_host not in local_hosts:
                raise ValueError("Unencrypted SMTP is permitted only on localhost.")

        if self.smtp_security == "none" and self.smtp_username is not None:
            raise ValueError("SMTP authentication requires an encrypted connection.")

        return self
