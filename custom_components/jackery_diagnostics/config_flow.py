"""Config flow for Jackery Diagnostics."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries

from .api import JackeryAuthenticationError, JackeryConnectionError, JackeryDiagnosticsClient
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

CONF_EMAIL = "email"
CONF_PASSWORD = "password"


class JackeryDiagnosticsConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Jackery Diagnostics."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        errors: dict[str, str] = {}

        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_EMAIL].lower())
            self._abort_if_unique_id_configured()

            try:
                token = await self.hass.async_add_executor_job(
                    self._validate_credentials,
                    user_input[CONF_EMAIL],
                    user_input[CONF_PASSWORD],
                )
            except JackeryAuthenticationError:
                errors["base"] = "invalid_auth"
            except JackeryConnectionError:
                errors["base"] = "cannot_connect"
            except Exception:  # pragma: no cover - defensive guard
                _LOGGER.exception("Unexpected error validating Jackery credentials")
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(
                    title=user_input[CONF_EMAIL],
                    data={
                        CONF_EMAIL: user_input[CONF_EMAIL],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        "token": token,
                    },
                )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    @staticmethod
    def _validate_credentials(email: str, password: str) -> str:
        """Validate credentials by performing the Jackery login flow."""
        return JackeryDiagnosticsClient(email, password).login()
