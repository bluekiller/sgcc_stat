import dataclasses
import logging
from typing import Any, Dict, Optional

from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
import homeassistant.helpers.config_validation as cv
import voluptuous as vol

from .const import DOMAIN
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
        self.data = None

    async def async_step_user(self, user_input: Optional[Dict[str, Any]] = None):
        """Invoked when a user initiates a flow via the user interface."""
        errors: Dict[str, str] = {}
        desc = '登录我的95588'
        if user_input is not None:
            try:
                sgcc = SGCC(
                    user_input[CONF_USERNAME],
                    user_input[CONF_PASSWORD],
                    keys_and_token=self.hass.data
                )
                self.data['sgcc'] = sgcc
                await self.hass.async_add_executor_job(sgcc.login)
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
                'account': dataclasses.asdict(sgcc.account)
            })

        lst = {}
        for _ in sgcc.account.power_users:
            lst[_.id] = _.cons_no_dst
        schema = vol.Schema({"list": cv.multi_select(lst)})
        return self.async_show_form(
            step_id="select", data_schema=schema, errors=errors
        )
