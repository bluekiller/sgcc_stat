from __future__ import annotations

from typing import Any

from dacite import from_dict
from homeassistant.components.sensor import STATE_CLASS_TOTAL_INCREASING, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import DEVICE_CLASS_ENERGY, ENERGY_KILO_WATT_HOUR
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import *
from .sgcc import *

_LOGGER = logging.getLogger(__name__)
_LOCK = threading.Lock()
SCAN_INTERVAL = datetime.timedelta(minutes=30)


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    """Setup entry"""
    _LOGGER.debug("Setup sensor entry, conf: %s", config_entry.data)
    account: SGCCAccount = from_dict(SGCCAccount, config_entry.data.get('account'))
    entities = []
    for _ in account.power_users:
        if _.id in config_entry.data.get('selected_power_users'):
            api = SGCC(account=account, keys_and_token=hass.data, data_lock=_LOCK)
            entities.append(SGCCAccountBalanceSensor(api, _))
            coordinator = PowerConsumptionCoordinator(api, _, hass)
            entities.append(PowerConsumptionSensor(coordinator, CYCLE_DAILY))
            entities.append(PowerConsumptionSensor(coordinator, CYCLE_MONTHLY))
            # await coordinator.async_config_entry_first_refresh()
    async_add_entities(entities, True)
    _LOGGER.debug("Sensor entry setup finished")
    return True


class SGCCUpdater:

    def __init__(self, api: SGCC):
        self._sgcc = api

    def _do_update(self) -> Any:
        ...

    def update_data(self):
        try:
            self._sgcc.renew_token()
            return self._do_update()
        except SGCCNeedLoginError:
            self._sgcc.login()
            return self._do_update()


class PowerConsumptionCoordinator(SGCCUpdater, DataUpdateCoordinator):

    def __init__(self, api: SGCC, power_user: SGCCPowerUser, hass: HomeAssistant):
        SGCCUpdater.__init__(self, api)
        DataUpdateCoordinator.__init__(self, hass, _LOGGER, name='sgcc_power_consumption_sensor',
                                       update_interval=datetime.timedelta(hours=1))
        self.power_user = power_user

    def _do_update(self):
        start = datetime.date.today().replace(day=1)
        end = datetime.date.today()
        return self._sgcc.get_daily_usage(self.power_user, start, end)

    async def _async_update_data(self):
        return await self.hass.async_add_executor_job(self.update_data)


class BaseSGCCEntity(SGCCUpdater, SensorEntity):

    def __init__(self, api: SGCC, power_user: SGCCPowerUser, sensor_type: str):
        super().__init__(api)
        self._power_user = power_user
        self._attr_unique_id = f"{self._power_user.id}_{sensor_type}"

    async def async_update(self):
        await self.hass.async_add_executor_job(self.update_data)


class PowerConsumptionSensor(CoordinatorEntity, SensorEntity):

    def __init__(self, coordinator: PowerConsumptionCoordinator, cycle: str):
        super().__init__(coordinator)
        self._cycle = cycle
        self._consumption: DailyPowerConsumption | None = None
        self._attr_unique_id = f"{coordinator.power_user.id}_{cycle}_consumption"
        self._attr_name = f"{CYCLE_NAME.get(cycle)}用电量(户号: {coordinator.power_user.cons_no_dst})"
        self._attr_device_class = DEVICE_CLASS_ENERGY
        self._attr_state_class = STATE_CLASS_TOTAL_INCREASING
        self._attr_native_unit_of_measurement = ENERGY_KILO_WATT_HOUR

    def has_data(self):
        return self.coordinator.data and len(self.coordinator.data) > 0

    def get_consumption(self) -> DailyPowerConsumption:
        return self.coordinator.data[0]

    @property
    def native_value(self):
        """Return the state of the sensor."""
        if self._cycle == CYCLE_DAILY:
            return self.get_consumption().day_ele_pq if self.has_data() else None
        if self._cycle == CYCLE_MONTHLY:
            _LOGGER.debug(str(self.coordinator.data))
            return sum(_.day_ele_pq for _ in self.coordinator.data) if self.coordinator.data else None

    @property
    def extra_state_attributes(self):
        if self._cycle == CYCLE_DAILY:
            return dataclasses.asdict(self.get_consumption()) if self.has_data() else None
        if self._cycle == CYCLE_MONTHLY:
            return {
                'period': f"{self.coordinator.data[-1].day}~{self.coordinator.data[0].day}",
                'n_pq': sum(_.n_pq for _ in self.coordinator.data),
                'v_pq': sum(_.v_pq for _ in self.coordinator.data),
                'p_pq': sum(_.p_pq for _ in self.coordinator.data),
                't_pq': sum(_.t_pq for _ in self.coordinator.data)
            } if self.has_data() else None
        return None

    @property
    def last_reset(self):
        if self._cycle == CYCLE_DAILY:
            return datetime.datetime.strptime(self.get_consumption().day, '%Y%m%d') if self.has_data() else None
        if self._cycle == CYCLE_MONTHLY:
            return datetime.datetime.strptime(self.coordinator.data[-1].day, '%Y%m%d') if self.has_data() else None


class SGCCAccountBalanceSensor(BaseSGCCEntity):

    def __init__(self, api: SGCC, power_user: SGCCPowerUser):
        super().__init__(api, power_user, 'balance')
        self._account_balance: AccountBalance | None = None
        self._attr_name = f"账户余额(户号: {self._power_user.cons_no_dst})"
        self._attr_native_unit_of_measurement = '元'

    @property
    def native_value(self):
        """Return the state of the sensor."""
        return self._account_balance.sum_money if self._account_balance else None

    @property
    def extra_state_attributes(self):
        return dataclasses.asdict(self._account_balance) if self._account_balance else None

    def _do_update(self):
        self._account_balance = self._sgcc.get_account_balance(self._power_user)