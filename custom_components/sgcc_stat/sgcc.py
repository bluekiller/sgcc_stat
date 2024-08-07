import asyncio
import base64
import dataclasses
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
import time
from io import BytesIO
from typing import List

import pytz
from PIL import Image
from aiohttp import ClientSession
from gmssl import func
from gmssl.sm2 import CryptSM2
from gmssl.sm3 import sm3_hash
from gmssl.sm4 import SM4_DECRYPT, SM4_ENCRYPT, CryptSM4
from .onnx import ONNX

SM4_KEY = '54fe588bf24b88f09e7ff0b2da2d27a8'
PUB_KEY = '042BC7AD510BF9793B7744C8854C56A8C95DD1027EE619247A332EC6ED5B279F435A23D62441FE861F4B0C963347ECD5792F380B64CA084BE8BE41151F8B8D19C8'
APP_KEY = '3def6c365d284881bf1a9b2b502ee68c'
APP_SECRET = 'ab7357dae64944a197ace37398897f64'

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
        return datetime.fromisoformat(self.expire_time) > datetime.now()


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
        token_expiration = datetime.fromisoformat(self.token_expiration_date)
        current_time = datetime.now(timezone.utc).astimezone(token_expiration.tzinfo)
        return token_expiration < current_time


@dataclass
class AccountBalance:
    date: str  # 2022-02-11 09:31:17
    # esti_amt: str  # 19.11
    pro_code: str  # 31102
    sum_money: str  # -19.11
    penalty: str  # 0
    # penalty_end_date: str  # 2022-02-11
    total_pq: str  # 99
    cons_no: str  # 1379874937
    uuid: str  # osg-uc:150d9042-efc9-4537-8ce1-b7c0c0dda454
    overdue_number: str  #
    prepay_bal: str  #
    cons_type: str  # 1
    amt_time: str  # 2022-02-10 14:17:09
    scene_type: str  # 01
    # warning_value: str  #
    # day_num: str  # -11


@dataclass
class DailyPowerConsumption:
    day: str
    day_ele_pq: float
    v_pq: float
    p_pq: float
    n_pq: float
    t_pq: float


MAX_RETRIES = 3  # Maximum number of retries
RETRY_DELAY = 5  # Delay between retries in seconds


class SGCC:
    def __init__(self, username: str = None, password: str = None, account: SGCCAccount = None,
                 data_lock: asyncio.Lock = None, keys_and_token=None):
        if keys_and_token is None:
            keys_and_token = dict()
        self.username = username
        self.password = password
        self.account = account
        self._keys_and_token = keys_and_token
        self._data_lock = data_lock
        component_dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(component_dir, 'captcha.onnx')
        self.onnx = ONNX(path)

    async def renew_token(self, session):
        if self._data_lock:
            await self._data_lock.acquire()
        try:
            keys: EncryptKeys = self._get_keys()
            token: AccessToken = self._get_token()
            if not keys:
                keys = await get_encrypt_key(session)
                self._keys_and_token['keys'] = keys

            if (token is None or token.expired()) and self.account and not self.account.is_token_expired():
                _LOGGER.info("trying to renew access token")
                auth_code = await get_auth_code(keys, self.account.token, session)
                token = await get_auth_token(keys, auth_code, session)
                self._keys_and_token['token'] = token

        finally:
            if self._data_lock:
                self._data_lock.release()

    async def _post_request(self, url: str, request: str, session: ClientSession) -> dict:
        headers = _get_common_header(self._get_keys(), self._get_token(), self.account)
        _LOGGER.debug("post request to %s", url)
        _LOGGER.debug("headers: %s", headers)
        _LOGGER.debug("original request: %s", request)
        encrypted_request = EncryptUtil.encrypt_request(request, self._get_keys(), self._get_token(), self.account)
        _LOGGER.debug("encrypted request: %s", encrypted_request)
        async with session.post(url, data=encrypted_request, headers=headers) as r:
            resp_txt = await r.text()
            _LOGGER.debug("original response: %s", resp_txt)
            resp_json = json.loads(resp_txt)
            response = EncryptUtil.decrypt_sm4_js_data(resp_json['encryptData'], self._get_keys().key_code)
            _LOGGER.debug("decrypted response: %s", response)
            return response

    def _get_keys(self) -> EncryptKeys:
        return self._keys_and_token.get('keys')

    def _get_token(self) -> AccessToken:
        return self._keys_and_token.get('token')

    async def get_verification_code(self, session: ClientSession):
        username = self.username if self.username else self.account.account_name
        if self.password:
            hl = hashlib.md5()
            hl.update(self.password.encode("utf-8"))
            password = hl.hexdigest()
        else:
            password = self.account.password_hash
        request = {
            "password": password.upper(),
            "account": username,
            "canvasHeight": 200,
            "canvasWidth": 410
        }
        response = await self._post_request("https://www.95598.cn/api/osg-web0004/open/c44/f05",
                                            json.dumps(request), session)
        base64_data = re.sub('^data:image/.+;base64,', '', response['data']['canvasSrc'])
        byte_data = base64.b64decode(base64_data)
        image_data = BytesIO(byte_data)
        img = Image.open(image_data)
        distance = self.onnx.get_distance(img)
        _LOGGER.info(f"Image CaptCHA distance is {distance}.\r")
        return {"code": distance, "login_key": response['data']['ticket']}

    async def login(self, session: ClientSession) -> SGCCAccount:
        attempt = 0
        while attempt < MAX_RETRIES:
            attempt += 1
            if self._data_lock:
                await self._data_lock.acquire()
            try:
                if self.account and not self.account.is_token_expired():
                    return self.account
                username = self.username if self.username else self.account.account_name
                if self.password:
                    hl = hashlib.md5()
                    hl.update(self.password.encode("utf-8"))
                    password = hl.hexdigest()
                else:
                    password = self.account.password_hash

                # login_key = str(random())
                code = await self.get_verification_code(session)

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
                        "password": password.upper(),
                        "addressRegion": 110101,
                        "account": username,
                        "addressCity": 330100
                    }
                }
                s = {
                    "loginKey": code['login_key'],
                    "code": round(code['code']),
                    "params": t
                }

                await asyncio.sleep(3)
                r = await self._post_request("https://www.95598.cn/api/osg-web0004/open/c44/f06", json.dumps(s),
                                             session)

                if r['code'] != 1 or r['data']['srvrt']['resultCode'] != '0000':
                    message = r.get("message")
                    if r.get("data"):
                        message = r['data']['srvrt']['resultMessage']
                    raise SGCCLoginError(message)

                user_info = r['data']['bizrt']['userInfo'][0]
                # Timezone GMT+8
                gmt_plus_8 = pytz.timezone('Asia/Shanghai')
                account = SGCCAccount(
                    password_hash=password,
                    account_name=user_info['loginAccount'],
                    user_id=user_info['userId'],
                    token=r['data']['bizrt']['token'],
                    token_expiration_date=gmt_plus_8.localize(
                        datetime.strptime(r['data']['bizrt']['expirationDate'],
                                          '%Y%m%d%H%M')).isoformat()
                )
                auth_code = await get_auth_code(self._get_keys(), account.token, session)
                access_token = await get_auth_token(self._get_keys(), auth_code, session)
                self._keys_and_token["token"] = access_token
                self.account = account
                return account
            except Exception as e:
                _LOGGER.error(f"Login attempt {attempt} failed: {e}")
                if attempt >= MAX_RETRIES:
                    raise e  # Re-raise the last exception if max retries exceeded
                await asyncio.sleep(RETRY_DELAY)
            finally:
                if self._data_lock:
                    self._data_lock.release()

    async def get_account_balance(self, power_user: SGCCPowerUser, session: ClientSession) -> AccountBalance:
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
                "list": [{
                    "consNoSrc": power_user.cons_no_dst,
                    "proCode": power_user.pro_no,
                    "sceneType": power_user.elec_type_code,
                    "consNo": power_user.cons_no,
                    "orgNo": power_user.org_no
                }]
            },
            "serviceCode": "0101143",
            "source": "SGAPP",
            "target": power_user.pro_no
        }
        r = await self._post_request('https://www.95598.cn/api/osg-open-bc0001/member/c05/f01', json.dumps(request),
                                     session)
        if r['code'] == 10015:
            raise AuthorizeTokenExpiredError(r['message'])
        if r['code'] == 10002:
            raise SGCCNeedLoginError(r['message'])
        if r['code'] != 1:
            raise SGCCError(r['message'])
        if 'data' not in r:
            raise SGCCError('暂无数据')
        if r['data']['rtnCode'] != '1':
            raise SGCCError('未知错误，错误编码：' + r['data']['rtnCode'])
        if 'list' not in r['data'] or len(r['data']['list']) == 0:
            raise SGCCError('暂无数据')
        balance = r['data']['list'][0]
        return AccountBalance(
            date=balance['date'],
            # esti_amt=balance['estiAmt'],
            pro_code=balance['proCode'],
            sum_money=balance['sumMoney'],
            penalty=balance['penalty'],
            # penalty_end_date=balance['penaltyEndDate'],
            total_pq=balance['totalPq'],
            cons_no=balance['consNo'],
            uuid=balance['uuid'],
            overdue_number='overdueNumber',
            prepay_bal=balance['prepayBal'],
            cons_type=balance['consType'],
            amt_time=balance['amtTime'],
            scene_type=balance['sceneType'],
            # warning_value=balance['warningValue'],
            # day_num=balance['dayNum']
        )

    async def get_bill_list(self, power_user: SGCCPowerUser, year: str, session: ClientSession):
        if not self.account or self.account.is_token_expired():
            raise SGCCNeedLoginError()

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
        return await self._post_request("https://www.95598.cn/api/osg-open-bc0001/member/c01/f02",
                                        json.dumps(request), session)

    async def search_user(self, session: ClientSession):
        if not self.account or self.account.is_token_expired():
            raise SGCCNeedLoginError()
        request = {
            "serviceCode": "01008183",
            "source": "SGAPP",
            "target": "23101",
            "uscInfo": {
                "member": "0902",
                "devciceIp": "",
                "devciceId": "",
                "tenant": "state_grid"
            },
            "quInfo": {
                "userId": self.account.user_id
            },
            "token": self.account.token
        }
        r = await self._post_request("https://www.95598.cn/api/osg-open-uc0001/member/c9/f02",
                                     json.dumps(request), session)
        if r['code'] != 1 or r['data']['srvrt']['resultCode'] != '0000':
            raise SGCCError(r['data']['srvrt']['resultMessage'])
        for _ in r['data']['bizrt']['powerUserList']:
            power_user = SGCCPowerUser(
                id=_['userId'],
                province_id=_['provinceId'],
                pro_no=_['proNo'],
                org_no=_['orgNo'],
                org_name=_['orgName'],
                elec_type_code=_['elecTypeCode'],
                const_type=_['constType'],
                cons_no=_['consNo'],
                cons_no_dst=_['consNo_dst']
            )
            self.account.power_users.append(power_user)

    async def get_daily_usage(
            self, power_user: SGCCPowerUser, start: datetime.date, end: datetime.date
            , session: ClientSession) -> List[DailyPowerConsumption]:
        if not self.account or self.account.is_token_expired():
            raise SGCCNeedLoginError()

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
        json_resp = await self._post_request("https://www.95598.cn/api/osg-web0004/member/c24/f01", json.dumps(request),
                                             session)
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
    def encrypt_sm4_js_data(data, key=SM4_KEY):
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(key.encode("utf-8"), SM4_ENCRYPT)
        iv = key[0:8] + key[len(key) - 8:len(key)]
        return base64.b64encode(crypt_sm4.crypt_cbc(iv.encode("utf-8"), data))  # bytes类型

    @staticmethod
    def decrypt_sm4_js_data(encrypted, key=SM4_KEY):
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(key.encode("utf-8"), SM4_DECRYPT)
        iv = key[0:8] + key[len(key) - 8:len(key)]
        return json.loads(crypt_sm4.crypt_cbc(iv.encode("utf-8"), base64.b64decode(encrypted)).decode("utf8"))

    @staticmethod
    def sign_data(data):
        return sm3_hash(func.bytes_to_list(data))

    @staticmethod
    def encrypt_data(str_data: str, public_key: str = PUB_KEY):
        if len(public_key) > 128:
            public_key = public_key[len(public_key) - 128:]
        sm2_crypt = CryptSM2(None, public_key, mode=1)
        return '04' + sm2_crypt.encrypt(str_data.encode("utf-8").hex().encode("utf-8")).hex()

    @staticmethod
    def decrypt_data(hex_str, private_key):
        sm2_crypt = CryptSM2(private_key, PUB_KEY, mode=1)
        return bytes.fromhex(sm2_crypt.decrypt(bytes.fromhex(hex_str[2:])).decode("utf-8")).decode("utf-8")

    @staticmethod
    def encrypt_request(request, encrypt_keys: EncryptKeys, auth_token: AccessToken, account: SGCCAccount = None):
        public_key = encrypt_keys.public_key
        access_token = ""
        if auth_token:
            access_token = auth_token.access_token
        token = ''
        if account:
            token = account.token
        timestamp = _get_time_stamp()
        request = '{"_access_token": "' + access_token[int(len(access_token) / 2):] + '","_t": "' + token[int(len(
            token) / 2):] + '","_data":' + request + ',"timestamp": ' + str(timestamp) + '}'
        _LOGGER.debug("wrapped request: %s", request)
        encrypted_request = EncryptUtil.encrypt_sm4_js_data(request.encode("utf8"), encrypt_keys.key_code)
        sign = EncryptUtil.sign_data((encrypted_request.decode("utf-8") + str(timestamp)).encode("utf-8"))
        skey = EncryptUtil.encrypt_data(encrypt_keys.key_code, public_key)
        new_request = '{"data": "' + encrypted_request.decode("utf-8") + sign + '","timestamp":' + str(
            timestamp) + ', "skey": "' + skey + '"}'
        return new_request


def _sha256_hash(input_data):
    # If input_data is a string, encode it as bytes using UTF-8
    if isinstance(input_data, str):
        input_data = input_data.encode('utf-8')

    # Create a SHA-256 hash object
    sha256 = hashlib.sha256()

    # Update the hash object with the input data
    sha256.update(input_data)

    # Get the hexadecimal representation of the hash
    hash_hex = sha256.hexdigest()

    return hash_hex


def _build_generate_key_request():
    request_key_prams = {"client_id": APP_KEY, "client_secret": APP_SECRET}
    encrypted_data = EncryptUtil.encrypt_sm4_js_data(json.dumps(request_key_prams).encode("utf-8"))
    skey = EncryptUtil.encrypt_data(SM4_KEY)
    timestamp = _get_time_stamp()
    data_to_sign = encrypted_data.decode("utf8") + str(timestamp)
    sign = EncryptUtil.sign_data(data_to_sign.encode("utf-8"))
    request_data = {
        "client_id": APP_KEY,
        "data": encrypted_data.decode("utf-8") + sign,
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
                      "Chrome/96.0.4664.110 Safari/537.36 ",
        "wsgwtype": "web",
        "appkey": APP_KEY
    }
    if encrypt_keys:
        headers['keyCode'] = encrypt_keys.key_code
    if account:
        headers['t'] = account.token[:int(len(account.token) / 2)]
    if access_token:
        length = len(access_token.access_token)
        headers['accessToken'] = access_token.access_token
        headers['Authorization'] = 'Bearer ' + access_token.access_token[:int(length / 2)]
    headers['sessionId'] = "web" + headers['timestamp']
    headers['retryCount'] = "1"
    return headers.copy()


async def get_encrypt_key(session) -> EncryptKeys:
    headers = _get_common_header()
    headers.pop("t", None)
    data = _build_generate_key_request()
    _LOGGER.debug(headers)
    _LOGGER.debug(data)
    async with session.post("https://www.95598.cn/api/oauth2/outer/c02/f02", json=data, headers=headers) as r:
        resp_txt = await r.text()
        _LOGGER.debug("get_encrypt_key encrypted result: %s", resp_txt)
        json_resp = json.loads(resp_txt)
        if not json_resp.get('encryptData'):
            raise SGCCError(json_resp.get('message'))
        decrypted_data = EncryptUtil.decrypt_sm4_js_data(json_resp['encryptData'])
        _LOGGER.debug("get_encrypt_key result: %s", decrypted_data)
        return EncryptKeys(decrypted_data['data']['keyCode'], "", decrypted_data['data']['publicKey'])


def _build_get_token_request(encrypt_keys: EncryptKeys, authorize_code: str):
    timestamp = str(_get_time_stamp())
    request = {
        "grant_type": "authorization_code",
        "sign": EncryptUtil.sign_data((APP_KEY + timestamp).encode("utf-8")),
        "client_secret": APP_SECRET,
        "state": "464606a4-184c-4beb-b442-2ab7761d0796",
        "key_code": encrypt_keys.key_code,
        "client_id": APP_KEY,
        "timestamp": timestamp,
        "code": authorize_code
    }
    _LOGGER.debug("get_auth_token request: %s", request)
    encrypt = EncryptUtil.encrypt_sm4_js_data(json.dumps(request).encode("utf-8"), encrypt_keys.key_code).decode(
        "utf-8")
    skey = EncryptUtil.encrypt_data(encrypt_keys.key_code, encrypt_keys.public_key)
    encrpyt_req = {
        "data": encrypt + EncryptUtil.sign_data((encrypt + timestamp).encode("utf-8")),
        "skey": skey,
        "timestamp": timestamp
    }
    return encrpyt_req


async def get_auth_token(encrypt_keys: EncryptKeys, authorize_code: str, session: ClientSession) -> AccessToken:
    headers = _get_common_header(encrypt_keys=encrypt_keys)
    headers.pop("t", None)
    request = _build_get_token_request(encrypt_keys, authorize_code)
    _LOGGER.debug("get_auth_token headers: %s", headers)
    _LOGGER.debug("get_auth_token encrypted request: %s", request)
    async with session.post("https://www.95598.cn/api/oauth2/outer/getWebToken", json=request, headers=headers) as r:
        resp_txt = await r.text()
        _LOGGER.debug("get_auth_token encrypted result: %s", resp_txt)
        decrypted_data = EncryptUtil.decrypt_sm4_js_data(json.loads(resp_txt)['encryptData'], encrypt_keys.key_code)
        _LOGGER.debug("get_auth_token result: %s", decrypted_data)
        return AccessToken(decrypted_data['data']['access_token'], APP_KEY,
                           datetime.fromtimestamp(
                               time.time() + int(decrypted_data['data']['expiresIn'])).isoformat())


def _build_get_auth_code_request(token):
    request = f"client_id={APP_KEY}&response_type=code&redirect_url=/test&timestamp={str(_get_time_stamp())}&rsi={token}"
    return request


async def get_auth_code(encrypt_keys: EncryptKeys, token: str, session: ClientSession) -> str:
    headers = _get_common_header(encrypt_keys=encrypt_keys)
    headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
    headers.pop("t", None)
    _LOGGER.debug("get_auth_code headers: %s", headers)
    request = _build_get_auth_code_request(token)
    _LOGGER.debug("get_auth_code request: %s", request)
    async with session.post("https://www.95598.cn/api/oauth2/oauth/authorize", data=request,
                            headers=headers) as r:
        resp_txt = await r.text()
        _LOGGER.debug("get_auth_code encrypted result: %s", resp_txt)

        decrypted_data = EncryptUtil.decrypt_sm4_js_data(json.loads(resp_txt)['data'], token)
        _LOGGER.debug("get_auth_code result: %s", decrypted_data)
        if decrypted_data['code'] == '1':
            _, auth_code = decrypted_data['data']['redirect_url'].split('code=')
            return auth_code
        else:
            raise SGCCError(decrypted_data.get('message') or '获取Authorize Code失败！')
