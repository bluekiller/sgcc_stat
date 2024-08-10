DOMAIN = "sgcc_stat"

CYCLE_DAILY = 'daily'
CYCLE_MONTHLY = 'monthly'
CYCLE_NAME: dict[str, str] = {CYCLE_DAILY: '昨日', CYCLE_MONTHLY: '当月'}

DATA_COORDINATORS = 'coordinators'
DATA_KEYS = 'keys'
DATA_TOKEN = 'token'
DATA_ACCOUNT = 'account'
DATA_POWER_USERS = 'power_users'

MAX_RETRIES = 3  # Maximum number of retries for login
RETRY_DELAY = 5  # Delay between retries in seconds

UPDATE_INTERVAL = 6  # Coordinator update interval in hours
