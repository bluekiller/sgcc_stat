import dataclasses
import logging
from typing import Any, Dict, Optional

import aiohttp
import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

from .const import DOMAIN, DATA_ACCOUNT, DATA_KEYS, DATA_TOKEN
from .sgcc import SGCC, SGCCLoginError

_LOGGER = logging.getLogger(__name__)

AUTH_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
    }
)


class SGCCConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """国家电网 config flow."""

    def __init__(self):
        self.data = {}

    async def async_step_user(self, user_input: Optional[Dict[str, Any]] = None):
        """Invoked when a user initiates a flow via the user interface."""
        errors: Dict[str, str] = {}
        desc = '登录我的95588'
        session = aiohttp.ClientSession()
        if user_input is not None:
            try:
                sgcc = SGCC(
                    user_input[CONF_USERNAME],
                    user_input[CONF_PASSWORD],
                    keys_and_token=self.hass.data
                )
                self.data['sgcc'] = sgcc
                await sgcc.login(session)
                await sgcc.search_user(session)
            except SGCCLoginError as e:
                errors['base'] = 'invalid_auth'
                desc = '错误信息：\n' + e.msg
            if not errors:
                return await self.async_step_select()

        return self.async_show_form(
            step_id="user", data_schema=AUTH_SCHEMA, errors=errors, description_placeholders={"desc": desc}
        )

    async def async_step_select(self, user_input: Optional[Dict[str, Any]] = None):
        """选择用电户号"""
        errors: Dict[str, str] = {}
        sgcc: SGCC = self.data['sgcc']
        if user_input is not None:
            _LOGGER.info("async_step_select %s", user_input)
            return self.async_create_entry(title=sgcc.account.account_name, data={
                'selected_power_users': user_input['list'],
                DATA_ACCOUNT: dataclasses.asdict(sgcc.account),
                DATA_KEYS: dataclasses.asdict(sgcc.get_keys()),
                DATA_TOKEN: dataclasses.asdict(sgcc.get_token())
            })

        lst = {}
        for _ in sgcc.account.power_users:
            lst[_.id] = _.cons_no_dst
        schema = vol.Schema({"list": cv.multi_select(lst)})
        return self.async_show_form(
            step_id="select", data_schema=schema, errors=errors
        )
