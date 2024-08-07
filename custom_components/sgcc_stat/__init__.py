import dataclasses
import logging

from dacite import from_dict
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .const import DOMAIN, DATA_COORDINATORS, DATA_KEYS, DATA_TOKEN, DATA_ACCOUNT
from .sensor import SGCCCoordinator, _LOCK
from .sgcc import AccessToken, EncryptKeys, SGCCAccount, SGCC

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the 国家电网 component."""
    _LOGGER.debug("async_setup in __init__ config: %s", config)
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(
        hass: HomeAssistant, entry: config_entries.ConfigEntry
) -> bool:
    """Set up platform from a ConfigEntry."""
    _LOGGER.debug("async_setup_entry in __init__, config: %s", entry.data)

    account = from_dict(SGCCAccount, entry.data.get(DATA_ACCOUNT))
    keys_and_token = {
        DATA_KEYS: from_dict(EncryptKeys, entry.data.get(DATA_KEYS)) if entry.data.get(
            DATA_KEYS) else None,
        DATA_TOKEN: from_dict(AccessToken, entry.data.get(DATA_TOKEN)) if entry.data.get(
            DATA_TOKEN) else None
    }

    api, coordinators = await _initialize_coordinators(hass, account, keys_and_token, entry)

    if not coordinators:
        _LOGGER.error("No valid coordinators found during setup.")
        raise ConfigEntryNotReady("Coordinator setup failed.")

    # Update the entry with the new data
    new_data = {
        **entry.data,
        DATA_KEYS: dataclasses.asdict(keys_and_token[DATA_KEYS]),
        DATA_TOKEN: dataclasses.asdict(keys_and_token[DATA_TOKEN]),
        DATA_ACCOUNT: dataclasses.asdict(api.account)
    }
    await hass.config_entries.async_update_entry(entry, new_data)

    # Forward the setup to the sensor platform.
    await hass.config_entries.async_forward_entry_setups(entry, ["sensor"])
    return True


async def _initialize_coordinators(
        hass: HomeAssistant,
        account: SGCCAccount,
        keys_and_token: dict,
        entry: config_entries.ConfigEntry
) -> tuple:
    """Initialize and refresh coordinators."""
    api = SGCC(account=account, keys_and_token=keys_and_token, data_lock=_LOCK)
    coordinators = []

    for user in account.power_users:
        if user.id in entry.data.get('selected_power_users'):
            _LOGGER.debug("Initializing coordinator for user %s", user.id)
            coordinator = SGCCCoordinator(api, user, hass)
            try:
                await coordinator.async_config_entry_first_refresh()
                coordinators.append(coordinator)
            except Exception as e:
                _LOGGER.error("Failed to initialize coordinator for user %s: %s", user.id, str(e))
                raise ConfigEntryNotReady from e

    hass.data[DOMAIN][entry.entry_id] = {DATA_COORDINATORS: coordinators}
    return api, coordinators
