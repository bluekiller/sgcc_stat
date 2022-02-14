import base64
import dataclasses
from dataclasses import dataclass
import datetime
import hashlib
import json
import logging
import random
import threading
import time
from typing import List

from gmssl import func
from gmssl.sm2 import CryptSM2
from gmssl.sm3 import sm3_hash
from gmssl.sm4 import SM4_DECRYPT, SM4_ENCRYPT, CryptSM4
import requests

SM4_KEY = b'5713304465539328'
PUB_KEY = 'DF69EABE94C764A779CB22D86256081DC097E215B463828128E98D796889ED5CF4B3D27B916206FEE4906F4DE53472209682830278643AC306709444108DB1FA'

_LOGGER = logging.getLogger(__name__)


class SGCCError(Exception):
    def __init__(self, msg):
        self.msg = msg


class SGCCLoginError(SGCCError):
    ...


class SGCCNeedLoginError(SGCCError):
    def __init__(self, msg='没有登录，请登录后再尝试！'):
        super().__init__(msg)


class AuthorizeTokenExpiredError(SGCCError):
    ...


class Updatable:
    def update(self, new):
        for key, value in new.items():
            if hasattr(self, key):
                setattr(self, key, value)


@dataclass
class EncryptKeys(Updatable):
    key_code: str
    private_key: str
    public_key: str


@dataclass
class AccessToken(Updatable):
    access_token: str
    app_key: str
    expire_time: str

    def expired(self) -> bool:
        return datetime.datetime.fromisoformat(self.expire_time) > datetime.datetime.now()


@dataclass
class SGCCPowerUser:
    id: str
    org_name: str
    org_no: str
    elec_type_code: str
    const_type: str
    cons_no: str
    cons_no_dst: str
    province_id: str
    pro_no: str


@dataclass
class SGCCAccount:
    account_name: str
    user_id: str
    token: str
    token_expiration_date: str
    password_hash: str
    power_users: List[SGCCPowerUser] = dataclasses.field(default_factory=list)

    def is_token_expired(self):
        return datetime.datetime.fromisoformat(self.token_expiration_date) < datetime.datetime.now()


@dataclass
class AccountBalance:
    date: str  # 2022-02-11 09:31:17
    esti_amt: str  # 19.11
    pro_code: str  # 31102
    sum_money: str  # -19.11
    penalty: str  # 0
    penalty_end_date: str  # 2022-02-11
    total_pq: str  # 99
    cons_no: str  # 1379874937
    uuid: str  # osg-uc:150d9042-efc9-4537-8ce1-b7c0c0dda454
    overdue_number: str  #
    prepay_bal: str  #
    cons_type: str  # 1
    amt_time: str  # 2022-02-10 14:17:09
    scene_type: str  # 01
    warning_value: str  #
    day_num: str  # -11


@dataclass
class DailyPowerConsumption:
    day: str
    day_ele_pq: float
    v_pq: float
    p_pq: float
    n_pq: float
    t_pq: float


class SGCC:
    def __init__(self, username: str = None, password: str = None, account: SGCCAccount = None,
                 data_lock: threading.Lock = None, keys_and_token=None):
        if keys_and_token is None:
            keys_and_token = dict()
        self.username = username
        self.password = password
        self.account = account
        self._keys_and_token = keys_and_token
        self._data_lock = data_lock

    def renew_token(self):
        if self._data_lock:
            self._data_lock.acquire()
        try:
            keys: EncryptKeys = self._keys_and_token.get('keys')
            token: AccessToken = self._keys_and_token.get('token')
            if not keys:
                keys = get_encrypt_key()
                self._keys_and_token['keys'] = keys

            if not token:
                token = get_auth_token(keys)
                self._keys_and_token['token'] = token

            if token.expired():
                keys.update(dataclasses.asdict(get_encrypt_key()))
                token.update(dataclasses.asdict(get_auth_token(keys)))
        finally:
            if self._data_lock:
                self._data_lock.release()

    def _post_request(self, url: str, request: str) -> str:
        headers = _get_common_header(self._get_keys(), self._get_token(), self.account)
        headers['wsgwType'] = 'http'
        _LOGGER.debug("post request to %s", url)
        _LOGGER.debug("headers: %s", headers)
        _LOGGER.debug("original request: %s", request)
        encrypted_request = EncryptUtil.encrypt_request(request, self._get_keys(), self._get_token(), self.account)
        _LOGGER.debug("encrypted request: %s", encrypted_request)
        r = requests.post(url, data=encrypted_request, headers=headers)
        _LOGGER.debug("original response: %s", r.text)
        response = EncryptUtil.decrypt_data(r.json()['encryptData'], self._get_keys().private_key)
        _LOGGER.debug("decrypted response: %s", response)
        return response

    def _get_keys(self) -> EncryptKeys:
        return self._keys_and_token.get('keys')

    def _get_token(self) -> AccessToken:
        return self._keys_and_token.get('token')

    def login(self) -> SGCCAccount:
        self.renew_token()

        if self._data_lock:
            self._data_lock.acquire()
        try:
            username = self.username if self.username else self.account.account_name
            if self.password:
                hl = hashlib.md5()
                hl.update(self.password.encode("utf-8"))
                password = hl.hexdigest()
            else:
                password = self.account.password_hash

            t = {
                "uscInfo": {
                    "devciceIp": "",
                    "tenant": "state_grid",
                    "member": "0902",
                    "devciceId": ""
                },
                "quInfo": {
                    "optSys": "android",
                    "pushId": "000000",
                    "addressProvince": 110100,
                    "password": password,
                    "addressRegion": 110101,
                    "account": username,
                    "addressCity": 330100
                }
            }
            r = self._post_request("https://osg-web.sgcc.com.cn/api/osg-open-uc0001/member/c8/f23", json.dumps(t))
            json_resp = json.loads(r)

            if json_resp['code'] != 1 or json_resp['data']['srvrt']['resultCode'] != '0000':
                raise SGCCLoginError(json_resp['data']['srvrt']['resultMessage'])

            user_info = json_resp['data']['bizrt']['userInfo'][0]
            account = SGCCAccount(
                password_hash=password,
                account_name=user_info['loginAccount'],
                user_id=user_info['userId'],
                token=json_resp['data']['bizrt']['token'],
                token_expiration_date=datetime.datetime.strptime(json_resp['data']['bizrt']['expirationDate'],
                                                                 '%Y%m%d%H%M').isoformat()
            )
            for _ in user_info['powerUserList']:
                power_user = SGCCPowerUser(
                    id=_['id'],
                    province_id=_['provinceId'],
                    pro_no=_['proNo'],
                    org_no=_['orgNo'],
                    org_name=_['orgName'],
                    elec_type_code=_['elecTypeCode'],
                    const_type=_['constType'],
                    cons_no=_['consNo'],
                    cons_no_dst=_['consNo_dst']
                )
                account.power_users.append(power_user)
            self.account = account
            return account
        finally:
            if self._data_lock:
                self._data_lock.release()

    def get_account_balance(self, power_user: SGCCPowerUser) -> AccountBalance:
        if not self.account or self.account.is_token_expired():
            raise SGCCNeedLoginError()

        request = {
            'data': {
                "srvCode": "",
                "serialNo": "",
                "channelCode": "0902",
                "funcCode": "WEBA1007200",
                "acctId": self.account.user_id,
                "userName": self.account.user_id,
                "promotType": "1",
                "promotCode": "1",
                "userAccountId": self.account.account_name,
                "list": {
                    "consNoSrc": power_user.cons_no_dst,
                    "proCode": power_user.pro_no,
                    "sceneType": power_user.elec_type_code,
                    "consNo": power_user.cons_no,
                    "orgNo": power_user.org_no
                }
            },
            "serviceCode": "0101143",
            "source": "SGAPP",
            "target": power_user.pro_no
        }
        r = self._post_request('https://osg-web.sgcc.com.cn/api/osg-open-bc0001/member/c05/f01', json.dumps(request))
        json_resp = json.loads(r)
        if json_resp['code'] == 10015:
            raise AuthorizeTokenExpiredError(json_resp['message'])
        if json_resp['code'] == 10002:
            raise SGCCNeedLoginError(json_resp['message'])
        if json_resp['code'] != 1:
            raise SGCCError(json_resp['message'])
        if 'data' not in json_resp or json_resp['data']['rtnCode'] != '1':
            raise SGCCError('未知错误，错误编码：' + json_resp['data']['rtnCode'])
        if 'list' not in json_resp['data'] or len(json_resp['data']['list']) == 0:
            raise SGCCError('暂无数据')
        balance = json_resp['data']['list'][0]
        return AccountBalance(
            date=balance['date'],
            esti_amt=balance['estiAmt'],
            pro_code=balance['proCode'],
            sum_money=balance['sumMoney'],
            penalty=balance['penalty'],
            penalty_end_date=balance['penaltyEndDate'],
            total_pq=balance['totalPq'],
            cons_no=balance['consNo'],
            uuid=balance['uuid'],
            overdue_number=balance['overdueNumber'],
            prepay_bal=balance['prepayBal'],
            cons_type=balance['consType'],
            amt_time=balance['amtTime'],
            scene_type=balance['sceneType'],
            warning_value=balance['warningValue'],
            day_num=balance['dayNum']
        )

    def get_bill_list(self, power_user: SGCCPowerUser, year: str):
        request = {
            "data":
                {
                    "acctId": self.account.user_id,
                    "channelCode": "0902",
                    "clearCache": "11",
                    "consType": power_user.const_type,
                    "funcCode": "ALIPAY_01",
                    "orgNo": power_user.org_no,
                    "proCode": power_user.pro_no,
                    "promotCode": "1",
                    "promotType": "1",
                    "serialNo": "",
                    "srvCode": "",
                    "userName": self.account.account_name,
                    "provinceCode": power_user.pro_no,
                    "userAccountId": self.account.user_id,
                    "consNo": power_user.cons_no,
                    "queryYear": year
                },
            "serviceCode": "BCP_000026",
            "source": "app",
            "target": power_user.pro_no
        }
        return self._post_request("https://osg-web.sgcc.com.cn/api/osg-open-bc0001/member/c01/f02",
                                  json.dumps(request))

    def get_daily_usage(
            self, power_user: SGCCPowerUser, start: datetime.date, end: datetime.date
    ) -> List[DailyPowerConsumption]:
        request = {
            "params1":
                {
                    "serviceCode":
                        {
                            "order": "0101154",
                            "uploadPic": "0101296",
                            "pauseSCode": "0101250",
                            "pauseTCode": "0101251",
                            "listconsumers": "0101093",
                            "messageList": "0101343",
                            "submit": "0101003",
                            "sbcMsg": "0101210",
                            "powercut": "0104514",
                            "BkAuth01": "f15",
                            "BkAuth02": "f18",
                            "BkAuth03": "f02",
                            "BkAuth04": "f17",
                            "BkAuth05": "f05",
                            "BkAuth06": "f16",
                            "BkAuth07": "f01",
                            "BkAuth08": "f03"
                        },
                    "source": "SGAPP",
                    "target": power_user.pro_no,
                    "uscInfo":
                        {
                            "member": "0902",
                            "devciceIp": "",
                            "devciceId": "",
                            "tenant": "state_grid"
                        },
                    "quInfo":
                        {
                            "userId": self.account.user_id
                        },
                    "token": self.account.token
                },
            "params3":
                {
                    "data":
                        {
                            "acctId": self.account.user_id,
                            "consNo": power_user.cons_no_dst,
                            "consType": "01",
                            "endTime": end.strftime('%Y-%m-%d'),
                            "orgNo": power_user.org_no,
                            "proCode": power_user.pro_no,
                            "serialNo": "",
                            "srvCode": "",
                            "startTime": start.strftime('%Y-%m-%d'),
                            "userName": self.account.account_name,
                            "funcCode": "WEBALIPAY_01",
                            "channelCode": "0902",
                            "clearCache": "11",
                            "promotCode": "1",
                            "promotType": "1"
                        },
                    "serviceCode": "BCP_000026",
                    "source": "app",
                    "target": power_user.pro_no
                },
            "params4": "010103"
        }
        r = self._post_request("https://osg-web.sgcc.com.cn/api/osg-web0004/member/c24/f01", json.dumps(request))
        json_resp = json.loads(r)
        if json_resp['code'] == 10015:
            raise AuthorizeTokenExpiredError(json_resp['message'])
        if json_resp['code'] == 10002:
            raise SGCCNeedLoginError(json_resp['message'])
        if json_resp['code'] != 1:
            raise SGCCError(json_resp['message'])
        if 'data' not in json_resp or json_resp['data']['returnCode'] != '1':
            raise SGCCError('未知错误，错误编码：' + json_resp['data']['returnCode'])
        if 'sevenEleList' not in json_resp['data'] or len(json_resp['data']['sevenEleList']) == 0:
            raise SGCCError('暂无数据')
        daily_usage_list = []
        for _ in json_resp['data']['sevenEleList']:
            if _['dayElePq'] != '-':
                daily_usage_list.append(
                    DailyPowerConsumption(
                        day=_['day'],
                        day_ele_pq=float(_['dayElePq']),
                        v_pq=float(_['thisVPq']),
                        p_pq=float(_['thisPPq']),
                        n_pq=float(_['thisNPq']),
                        t_pq=float(_['thisTPq'])
                    )
                )
        return daily_usage_list


class EncryptUtil:
    @staticmethod
    def encrypt_sm4_js_data(data):
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(SM4_KEY, SM4_ENCRYPT)
        return base64.b64encode(crypt_sm4.crypt_ecb(data))  # bytes类型

    @staticmethod
    def decrypt_sm4_js_data(encrypted):
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(SM4_KEY, SM4_DECRYPT)
        return json.loads(crypt_sm4.crypt_ecb(base64.b64decode(encrypted)).decode("utf-8"))

    @staticmethod
    def sign_data(data):
        return sm3_hash(func.bytes_to_list(data))

    @staticmethod
    def encrypt_data(str_data: str, public_key: str = PUB_KEY):
        if len(public_key) > 128:
            public_key = public_key[len(public_key) - 128:]
        sm2_crypt = CryptSM2(None, public_key)
        return '04' + sm2_crypt.encrypt(str_data.encode("utf-8").hex().encode("utf-8")).hex()

    @staticmethod
    def decrypt_data(hex_str, private_key):
        sm2_crypt = CryptSM2(private_key, None)
        return bytes.fromhex(sm2_crypt.decrypt(bytes.fromhex(hex_str[2:])).decode("utf-8")).decode("utf-8")

    @staticmethod
    def encrypt_request(request, encrypt_keys: EncryptKeys, auth_token: AccessToken, account: SGCCAccount = None):
        public_key = encrypt_keys.public_key
        access_token = auth_token.access_token
        token = ''
        if account:
            token = account.token
        timestamp = _get_time_stamp()
        request = '{"_access_token": "' + access_token[int(len(access_token) / 2):] + '","_t": "' + token[int(len(
            token) / 2):] + '","_data":' + request + ',"timestamp": ' + str(timestamp) + '}'
        encrypted_request = EncryptUtil.encrypt_data(request, public_key)
        sign = EncryptUtil.sign_data((encrypted_request + access_token + str(timestamp)).encode("utf-8"))
        new_request = '{"encryptData": "' + encrypted_request + '","sign": "' + sign + '","timestamp":' + str(
            timestamp) + '}'
        return new_request


def _build_generate_key_request():
    request_key_prams = b'{      "appKey": "1020",      "appSecret": "20382b57-7020-4cd8-96e4-3625cdae701d"    }'
    encrypted_data = EncryptUtil.encrypt_sm4_js_data(request_key_prams)
    random_value = str(random.randrange(1000000000000000, 9999999999999999))
    skey = EncryptUtil.encrypt_data(SM4_KEY.decode() + random_value)
    timestamp = _get_time_stamp()
    data_to_sign = skey + encrypted_data.decode("utf8") + str(timestamp)
    sign = EncryptUtil.sign_data(data_to_sign.encode("utf-8"))
    request_data = {
        "encryptData": encrypted_data.decode("utf-8"),
        "sign": sign,
        "timestamp": str(timestamp),
        "skey": skey
    }
    return request_data


def _get_time_stamp():
    return int(time.time() * 1000)


def _get_common_header(encrypt_keys: EncryptKeys = None, access_token: AccessToken = None,
                       account: SGCCAccount = None):
    headers = {
        "Content-Type": "application/json;charset=UTF-8",
        "version": "1.0",
        "source": "0901",
        "timestamp": str(_get_time_stamp()),
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/96.0.4664.110 Safari/537.36 "
    }
    if encrypt_keys:
        headers['keyCode'] = encrypt_keys.key_code
    if account:
        headers['t'] = account.token[:int(len(account.token) / 2)]
    if access_token:
        length = len(access_token.access_token)
        headers['accessToken'] = access_token.access_token
        headers['Authorization'] = 'Bearer ' + access_token.access_token[:int(length / 2)]
    return headers.copy()


def get_encrypt_key() -> EncryptKeys:
    headers = _get_common_header()
    r = requests.post("https://osg-web.sgcc.com.cn/api/open/c1/f04", json=_build_generate_key_request(),
                      headers=headers)
    _LOGGER.debug("get_encrypt_key encrypted result: %s", r.text)
    json_resp = r.json()
    if json_resp['code'] != 10000:
        raise SGCCError(json_resp['message'])
    decrypted_data = EncryptUtil.decrypt_sm4_js_data(r.json()['data']['encodeData'])
    _LOGGER.debug("get_encrypt_key result: %s", decrypted_data)
    return EncryptKeys(decrypted_data['keyCode'], decrypted_data['privateKey'], decrypted_data['publicKey'])


def get_auth_token(encrypt_keys: EncryptKeys) -> AccessToken:
    headers = _get_common_header(encrypt_keys=encrypt_keys)
    r = requests.post("https://osg-web.sgcc.com.cn/api/open/c2/f04", json=_build_generate_key_request(),
                      headers=headers)
    _LOGGER.debug("get_auth_token encrypted result: %s", r.text)
    decrypted_data = EncryptUtil.decrypt_sm4_js_data(r.json()['data']['encodeData'])
    _LOGGER.debug("get_auth_token result: %s", decrypted_data)
    return AccessToken(decrypted_data['access_token'], decrypted_data['appKey'],
                       datetime.datetime.fromtimestamp(time.time() + int(decrypted_data['expires_in'])).isoformat())


def get_login_verification_code():
    request = '{"loginKey": "0.9266604589952432"}'
    # return _post_request("https://osg-web.sgcc.com.cn/api/osg-web0004/open/c44/f01", request)


def login_with_code(username: str, password: str, login_key="", verify_code=""):
    hl = hashlib.md5()
    hl.update(password.encode("utf-8"))
    t = {
        "uscInfo": {
            "devciceIp": "",
            "tenant": "state_grid",
            "member": "0902",
            "devciceId": ""
        },
        "quInfo": {
            "optSys": "android",
            "pushId": "000000",
            "addressProvince": 110100,
            "password": hl.hexdigest(),
            "addressRegion": 110101,
            "account": username,
            "addressCity": 330100
        }
    }
    s = {
        "loginKey": login_key,
        "code": verify_code,
        "params": t
    }


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.WARN)
    _LOGGER.setLevel(logging.DEBUG)
    sgcc = SGCC('xxx', 'xxx')
    sgcc.login()
    # sgcc.get_account_balance(sgcc.account.power_users[0])
    # sgcc.get_bill_list(sgcc.account.power_users[0], '2021')
    sgcc.get_daily_usage(sgcc.account.power_users[0], datetime.date.today() - datetime.timedelta(days=6),
                         datetime.date.today())
    sgcc.get_bill_list(sgcc.account.power_users[0], '2022')
