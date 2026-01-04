#!/usr/bin/env python3
"""
Fortigate API helper (syslog-enabled).

Provides a simple wrapper around FortiGate CMDB REST API with:
- Automatic retries for transient errors
- Syslog + console logging
- JSON-safe parsing and error handling
- vdom handling for all requests
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any, List

from logging_config import setup_syslog_logger

logger = setup_syslog_logger("fortigate_api_helper")


class FortigateAPIHelper:
    """
    Simple FortiGate CMDB API wrapper.
    Provides GET/POST/PUT/DELETE methods with logging, retries, and vdom support.
    """

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
        Initialize API helper.

        Args:
            base_url (str): FortiGate API base URL (e.g., http://192.168.1.99/api/v2/cmdb)
            token (str): Bearer API token
            vdom (str): VDOM to operate in (default "root")
            verify_ssl (bool): Verify SSL certificates (default False)
            timeout (int): Request timeout in seconds (default 10)
            retries (int): Number of retries for transient HTTP errors (default 3)
            status_forcelist (List[int], optional): HTTP status codes to retry
        """
        self.base_url = base_url.rstrip("/")
        self.vdom = vdom
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.token = token

        if status_forcelist is None:
            status_forcelist = [429, 502, 503, 504]

        # Session with retry
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

        logger.info("FortigateAPIHelper initialized (vdom=%s, base_url=%s)", self.vdom, self.base_url)

    def _safe_json(self, response: requests.Response) -> Any:
        """
        Parse response body safely as JSON. Return raw text if JSON fails.

        Args:
            response (requests.Response): Response object

        Returns:
            dict or str: Parsed JSON or raw text
        """
        if not response.text:
            return {}
        try:
            return response.json()
        except ValueError:
            return response.text

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Any:
        """
        Internal request handler with logging, retries, vdom, and error handling.

        Args:
            method (str): HTTP method (GET/POST/PUT/DELETE)
            endpoint (str): CMDB endpoint (e.g., "firewall/address")
            data (dict, optional): JSON payload for POST/PUT
            params (dict, optional): Query parameters

        Returns:
            dict or list or str: Parsed response

        Raises:
            requests.exceptions.RequestException: For HTTP/network errors
            RuntimeError: If FortiGate returns {"status":"error", ...}
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        if params is None:
            params = {}
        # Always include vdom
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
            logger.error("Request failed [%s %s]: %s", method, url, e)
            raise

        body = self._safe_json(response)
        logger.debug("Response %s %s -> %s", response.status_code, url, body)

        # Raise HTTPError for 4xx/5xx
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as he:
            try:
                body_preview = body if isinstance(body, dict) else str(body)[:400]
            except Exception:
                body_preview = "<unreadable-response-body>"

            logger.error(
                "HTTP error for %s %s: status=%s body=%s",
                method, url, response.status_code, body_preview
            )
            raise

        # Check for logical FortiGate API errors
        if isinstance(body, dict) and body.get("status") == "error":
            logger.error("FortiGate API returned error payload: %s", body)
            raise RuntimeError(body)

        return body

    # ---------------- Public API Wrappers ----------------
    def get(self, endpoint: str, params: Optional[Dict] = None) -> Any:
        """Perform GET request"""
        return self._request("GET", endpoint, params=params)

    def post(self, endpoint: str, data: Dict) -> Any:
        """Perform POST request"""
        return self._request("POST", endpoint, data=data)

    def put(self, endpoint: str, data: Dict) -> Any:
        """Perform PUT request"""
        return self._request("PUT", endpoint, data=data)

    def delete(self, endpoint: str) -> Any:
        """Perform DELETE request"""
        return self._request("DELETE", endpoint)
