from __future__ import annotations

import asyncio
import dataclasses
import datetime
import logging
from typing import Any, List

from aiohttp import ClientSession
from homeassistant.components.sensor import SensorEntity, SensorDeviceClass, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfEnergy
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator, UpdateFailed,
)

from .const import *
from .sgcc import SGCC, SGCCPowerUser, DailyPowerConsumption, AccountBalance, SGCCNeedLoginError

_LOGGER = logging.getLogger(__name__)
_LOCK = asyncio.Lock()


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    """Set up sensors for the integration."""
    _LOGGER.debug("Setting up sensor entry with config: %s", config_entry.data)
    coordinators: List[SGCCCoordinator] = hass.data[DOMAIN][config_entry.entry_id][DATA_COORDINATORS]
    if not coordinators:
        _LOGGER.warning("No coordinators found for config entry %s", config_entry.entry_id)
        return False
    entities = []
    for _ in coordinators:
        entities.append(SGCCAccountBalanceSensor(_))
        entities.append(PowerConsumptionSensor(_, CYCLE_DAILY))
        entities.append(PowerConsumptionSensor(_, CYCLE_MONTHLY))
    async_add_entities(entities)
    _LOGGER.debug("Added %d sensor entities for config entry %s", len(entities), config_entry.entry_id)
    return True


class SGCCUpdater:

    def __init__(self, api: SGCC, hass: HomeAssistant):
        self._sgcc = api
        self._hass = hass

    async def _do_update(self, session: ClientSession) -> Any:
        ...

    async def update_data(self):
        session = await async_get_clientsession(self._hass)
        try:
            return await self._do_update(session)
        except SGCCNeedLoginError:
            await self._sgcc.login(session)
            return await self._do_update(session)


class SGCCCoordinator(SGCCUpdater, DataUpdateCoordinator):

    def __init__(self, api: SGCC, power_user: SGCCPowerUser, hass: HomeAssistant):
        SGCCUpdater.__init__(self, api, hass)
        DataUpdateCoordinator.__init__(self, hass, _LOGGER, name='sgcc_power_consumption_sensor',
                                       update_interval=datetime.timedelta(hours=UPDATE_INTERVAL))
        self.power_user = power_user

    async def _do_update(self, session: ClientSession):
        start = datetime.date.today().replace(day=1)
        end = datetime.date.today()
        return {
            "daily_usage": await self._sgcc.get_daily_usage(self.power_user, start, end, session),
            "account_balance": await self._sgcc.get_account_balance(self.power_user, session)
        }

    async def _async_update_data(self):
        try:
            return await self.update_data()
        except Exception as err:
            raise UpdateFailed(f"Error communicating with API: {err}")


class BaseSGCCEntity(SGCCUpdater, SensorEntity):

    def __init__(self, api: SGCC, power_user: SGCCPowerUser, sensor_type: str):
        super().__init__(api)
        self._power_user = power_user
        self._attr_unique_id = f"{self._power_user.id}_{sensor_type}"

    async def async_update(self):
        await self.update_data()


class PowerConsumptionSensor(CoordinatorEntity, SensorEntity):

    def __init__(self, coordinator: SGCCCoordinator, cycle: str):
        super().__init__(coordinator)
        self._cycle = cycle
        self._consumption: DailyPowerConsumption | None = None
        self._attr_unique_id = f"{coordinator.power_user.id}_{cycle}_consumption"
        self._attr_name = f"{CYCLE_NAME.get(cycle)}用电量(户号: {coordinator.power_user.cons_no_dst})"
        self._attr_device_class = SensorDeviceClass.ENERGY
        self._attr_state_class = SensorStateClass.TOTAL_INCREASING
        self._attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR

    def _has_data(self):
        return self.coordinator.data and len(self.coordinator.data['daily_usage']) > 0

    def _get_consumption(self) -> DailyPowerConsumption:
        return self._get_data()[0]

    def _get_data(self):
        return self.coordinator.data["daily_usage"]

    @property
    def native_value(self):
        """Return the state of the sensor."""
        if self._cycle == CYCLE_DAILY:
            return self._get_consumption().day_ele_pq if self._has_data() else None
        if self._cycle == CYCLE_MONTHLY:
            _LOGGER.debug(str(self.coordinator.data))
            return sum(_.day_ele_pq for _ in self._get_data()) if self._get_data() else None

    @property
    def extra_state_attributes(self):
        if self._cycle == CYCLE_DAILY:
            return dataclasses.asdict(self._get_consumption()) if self._has_data() else None
        if self._cycle == CYCLE_MONTHLY:
            return {
                'period': f"{self._get_data()[-1].day}~{self._get_data()[0].day}",
                'n_pq': sum(_.n_pq for _ in self._get_data()),
                'v_pq': sum(_.v_pq for _ in self._get_data()),
                'p_pq': sum(_.p_pq for _ in self._get_data()),
                't_pq': sum(_.t_pq for _ in self._get_data())
            } if self._has_data() else None
        return None

    # @property
    # def last_reset(self):
    #     if self._cycle == CYCLE_DAILY:
    #         return datetime.datetime.strptime(self.get_consumption().day, '%Y%m%d') if self.has_data() else None
    #     if self._cycle == CYCLE_MONTHLY:
    #         return datetime.datetime.strptime(self.coordinator.data[-1].day, '%Y%m%d') if self.has_data() else None


class SGCCAccountBalanceSensor(CoordinatorEntity, SensorEntity):

    def __init__(self, coordinator: SGCCCoordinator):
        super().__init__(coordinator)
        self._account_balance: AccountBalance | None = None
        self._attr_name = f"账户余额(户号: {coordinator.power_user.cons_no_dst})"
        self._attr_native_unit_of_measurement = '元'
        self._attr_unique_id = f"{coordinator.power_user.id}_account_balance"
        self._attr_device_class = SensorDeviceClass.MONETARY
        self._attr_state_class = SensorStateClass.TOTAL

    def _has_data(self):
        return self.coordinator.data and self.coordinator.data["account_balance"]

    def _get_account_balance(self) -> AccountBalance:
        return self.coordinator.data["account_balance"]

    @property
    def native_value(self):
        """Return the state of the sensor."""
        return self._get_account_balance().sum_money if self._has_data() else None

    @property
    def extra_state_attributes(self):
        return dataclasses.asdict(self._get_account_balance()) if self._has_data() else None
