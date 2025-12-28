# fortigate_api_helper.py

import requests
import logging
import ipaddress
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class FortigateAPIHelper:
    def __init__(
        self,
        base_url: str,
        token: str,
        vdom: str = "root",
        verify_ssl: bool = False,
        timeout: int = 10,
        retries: int = 3
    ):
        self.base_url = base_url.rstrip("/")
        self.vdom = vdom
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        })

        retry_strategy = Retry(
            total=retries,
            backoff_factor=1,
            status_forcelist=[429, 502, 503, 504],  # 500 عمداً حذف شده
            allowed_methods=["GET", "POST", "PUT", "DELETE"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _request(self, method, endpoint, data=None, params=None):
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        if params is None:
            params = {}
        params["vdom"] = self.vdom

        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            response.raise_for_status()

            if not response.text:
                return {}

            result = response.json()

            if isinstance(result, dict) and result.get("status") == "error":
                logger.error(f"FortiGate API error: {result}")
                raise RuntimeError(result)

            return result

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed [{method} {url}]: {e}")
            raise

    def get(self, endpoint, params=None):
        return self._request("GET", endpoint, params=params)

    def post(self, endpoint, data):
        return self._request("POST", endpoint, data=data)

    def put(self, endpoint, data):
        return self._request("PUT", endpoint, data=data)

    def delete(self, endpoint):
        return self._request("DELETE", endpoint)

    @staticmethod
    def validate_ip(ip_str: str) -> bool:
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            logger.warning(f"Invalid IP address: {ip_str}")
            return False
