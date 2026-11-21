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

    # Verified email-change configuration.
    email_change_expiry_minutes: int = Field(
        default=30,
        ge=1,
        validation_alias="RESTLING_EMAIL_CHANGE_EXPIRY_MINUTES",
    )

    email_change_cooldown_seconds: int = Field(
        default=60,
        ge=1,
        validation_alias="RESTLING_EMAIL_CHANGE_COOLDOWN_SECONDS",
    )

    email_change_hourly_limit: int = Field(
        default=5,
        ge=1,
        validation_alias="RESTLING_EMAIL_CHANGE_HOURLY_LIMIT",
    )

    email_change_smtp_attempt_hourly_limit: int = Field(
        default=10,
        ge=1,
        validation_alias="RESTLING_EMAIL_CHANGE_SMTP_ATTEMPT_HOURLY_LIMIT",
    )

    password_reset_expiry_minutes: int = Field(
        default=30,
        ge=1,
        validation_alias="RESTLING_PASSWORD_RESET_EXPIRY_MINUTES",
    )

    # Opaque authentication tokens and active-session limits.
    access_token_expiry_minutes: int = Field(
        default=15,
        ge=1,
        validation_alias="RESTLING_ACCESS_TOKEN_EXPIRY_MINUTES",
    )

    refresh_session_expiry_days: int = Field(
        default=7,
        ge=1,
        validation_alias="RESTLING_REFRESH_SESSION_EXPIRY_DAYS",
    )

    max_active_sessions: int = Field(
        default=2,
        ge=1,
        validation_alias="RESTLING_MAX_ACTIVE_SESSIONS",
    )

    session_history_retention_days: int = Field(
        default=30,
        ge=1,
        validation_alias="RESTLING_SESSION_HISTORY_RETENTION_DAYS",
    )

    one_time_token_retention_days: int = Field(
        default=30,
        ge=1,
        validation_alias="RESTLING_ONE_TIME_TOKEN_RETENTION_DAYS",
    )

    expired_access_token_retention_hours: int = Field(
        default=1,
        ge=1,
        validation_alias="RESTLING_EXPIRED_ACCESS_TOKEN_RETENTION_HOURS",
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
