# fortigate_api_helper.py
import requests
import logging
import ipaddress
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any, List

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
        retries: int = 3,
        status_forcelist: Optional[List[int]] = None
    ):
        """
        Helper for FortiGate API.
        - status_forcelist: list of status codes that should trigger retry (default [429,502,503,504])
          Note: 500 intentionally excluded by default because FortiGate often returns 500 for bad payloads.
        """
        self.base_url = base_url.rstrip("/")
        self.vdom = vdom
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        if status_forcelist is None:
            status_forcelist = [429, 502, 503, 504]

        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        })

        retry_strategy = Retry(
            total=retries,
            backoff_factor=1,
            status_forcelist=status_forcelist,
            allowed_methods=["GET", "POST", "PUT", "DELETE"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _safe_json(self, response: requests.Response) -> Any:
        """Try to parse JSON, otherwise return text."""
        if not response.text:
            return {}
        try:
            return response.json()
        except ValueError:
            return response.text

    def _request(self, method: str, endpoint: str, data: Optional[Dict] = None, params: Optional[Dict] = None) -> Any:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        if params is None:
            params = {}
        params["vdom"] = self.vdom

        logger.debug("Request: %s %s params=%s data=%s", method, url, params, data)

        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed [{method} {url}]: {e}")
            raise

        # Try to parse body (JSON or text) for logging / error propagation
        body = self._safe_json(response)
        logger.debug("Response %s %s -> %s", response.status_code, url, body)

        # If HTTP error status -> log body and raise HTTPError (response attached)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as he:
            logger.error("HTTP error for %s %s: %s", method, url, body)
            # re-raise the HTTPError (has response attached)
            raise

        # If FortiGate returns an API-level error in JSON (e.g. {"status":"error", ...})
        if isinstance(body, dict) and body.get("status") == "error":
            logger.error("FortiGate API returned error payload: %s", body)
            # raise a RuntimeError with body included for caller to inspect
            raise RuntimeError(body)

        return body

    def get(self, endpoint: str, params: Optional[Dict] = None) -> Any:
        return self._request("GET", endpoint, params=params)

    def post(self, endpoint: str, data: Dict) -> Any:
        return self._request("POST", endpoint, data=data)

    def put(self, endpoint: str, data: Dict) -> Any:
        return self._request("PUT", endpoint, data=data)

    def delete(self, endpoint: str) -> Any:
        return self._request("DELETE", endpoint)

    @staticmethod
    def validate_ip(ip_str: str) -> bool:
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            logger.warning(f"Invalid IP address: {ip_str}")
            return False
