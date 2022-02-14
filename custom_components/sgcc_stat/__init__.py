import logging

from homeassistant import config_entries
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .sgcc import AccessToken, EncryptKeys

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the 国家电网 component."""
    _LOGGER.debug("async_setup in __init__ config: %s", config)
    hass.data.setdefault(DOMAIN, {})
    # keys_store = storage.Store(hass, 1, "sgcc/keys.json")
    # token_store = storage.Store(hass, 1, "sgcc/access-token.json")
    # keys = await keys_store.async_load()
    # if keys:
    #     hass.data[DOMAIN]['keys'] = from_dict(EncryptKeys, keys)
    # token = await token_store.async_load()
    # if token:
    #     hass.data[DOMAIN]['token'] = from_dict(AccessToken, token)
    return True


async def async_setup_entry(
        hass: HomeAssistant, entry: config_entries.ConfigEntry
) -> bool:
    """Set up platform from a ConfigEntry."""
    _LOGGER.debug("async_setup_entry in __init__, config: %s", entry.data)

    # Forward the setup to the sensor platform.
    hass.async_create_task(
        hass.config_entries.async_forward_entry_setup(entry, "sensor")
    )
    return True
