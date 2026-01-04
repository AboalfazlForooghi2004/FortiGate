#!/usr/bin/env python3
"""
Fortigate API helper (Enhanced & Fixed Version)

Improvements:
- Fixed monitor endpoint support
- Better error handling and messages
- SSL verification configurable
- Pagination support
- Rate limiting protection
"""

import requests
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any, List
from logging_config import setup_syslog_logger

logger = setup_syslog_logger("fortigate_api_helper")


class FortigateAPIHelper:
    """Enhanced FortiGate API wrapper with monitor endpoint support"""

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
        # Remove /cmdb/ suffix if present to support both cmdb and monitor
        self.base_url = base_url.rstrip("/").replace("/api/v2/cmdb", "/api/v2")
        self.vdom = vdom
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.token = token
        self._last_request_time = 0
        self._min_request_interval = 0.1  # Rate limiting: 10 req/sec max

        if status_forcelist is None:
            status_forcelist = [429, 502, 503, 504]

        # Session with retry
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        })

        # Disable SSL warnings if verify_ssl is False
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        retry_strategy = Retry(
            total=retries,
            backoff_factor=1,
            status_forcelist=status_forcelist,
            allowed_methods=["GET", "POST", "PUT", "DELETE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        logger.info(
            "FortigateAPIHelper initialized (vdom=%s, base_url=%s, ssl_verify=%s)",
            self.vdom, self.base_url, self.verify_ssl
        )

    def _rate_limit(self):
        """Simple rate limiting to avoid overwhelming FortiGate"""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_request_interval:
            time.sleep(self._min_request_interval - elapsed)
        self._last_request_time = time.time()

    def _safe_json(self, response: requests.Response) -> Any:
        """Parse response body safely as JSON"""
        if not response.text:
            return {}
        try:
            return response.json()
        except ValueError as e:
            logger.warning("Failed to parse JSON response: %s", e)
            return {"error": "invalid_json", "raw_text": response.text[:500]}

    def _build_url(self, endpoint: str, api_type: str = "cmdb") -> str:
        """Build full URL with proper API type (cmdb or monitor)"""
        endpoint = endpoint.lstrip("/")
        return f"{self.base_url}/{api_type}/{endpoint}"

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        api_type: str = "cmdb"
    ) -> Any:
        """Internal request handler with enhanced error handling"""
        self._rate_limit()
        
        url = self._build_url(endpoint, api_type)
        if params is None:
            params = {}
        
        # Always include vdom
        if "vdom" not in params:
            params["vdom"] = self.vdom

        logger.debug("Request: %s %s params=%s", method, url, params)

        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
        except requests.exceptions.Timeout as e:
            logger.error("Request timeout [%s %s]: %s", method, url, e)
            raise RuntimeError(f"FortiGate request timeout: {e}")
        except requests.exceptions.ConnectionError as e:
            logger.error("Connection error [%s %s]: %s", method, url, e)
            raise RuntimeError(f"Cannot connect to FortiGate: {e}")
        except requests.exceptions.RequestException as e:
            logger.error("Request failed [%s %s]: %s", method, url, e)
            raise

        body = self._safe_json(response)
        
        # Enhanced error logging
        if response.status_code >= 400:
            error_msg = self._extract_error_message(body, response)
            logger.error(
                "HTTP %d for %s %s: %s",
                response.status_code, method, url, error_msg
            )

        # Raise HTTPError for 4xx/5xx
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            raise RuntimeError(self._extract_error_message(body, response))

        # Check for logical FortiGate API errors
        if isinstance(body, dict):
            if body.get("status") == "error":
                error_msg = body.get("cli_error") or body.get("error") or "Unknown error"
                logger.error("FortiGate API error: %s", error_msg)
                raise RuntimeError(f"FortiGate API error: {error_msg}")

        return body

    def _extract_error_message(self, body: Any, response: requests.Response) -> str:
        """Extract meaningful error message from FortiGate response"""
        if isinstance(body, dict):
            # Priority order for error messages
            for key in ["cli_error", "error", "message"]:
                if key in body and body[key]:
                    return str(body[key])
            
            # If status is error but no message
            if body.get("status") == "error":
                return f"FortiGate returned error status (code: {body.get('error', 'unknown')})"
        
        # Fallback to HTTP status
        return f"HTTP {response.status_code}: {response.reason}"

    # ---------------- CMDB API Methods ----------------
    def get(self, endpoint: str, params: Optional[Dict] = None) -> Any:
        """GET request for CMDB endpoints"""
        return self._request("GET", endpoint, params=params, api_type="cmdb")

    def post(self, endpoint: str, data: Dict) -> Any:
        """POST request for CMDB endpoints"""
        return self._request("POST", endpoint, data=data, api_type="cmdb")

    def put(self, endpoint: str, data: Dict) -> Any:
        """PUT request for CMDB endpoints"""
        return self._request("PUT", endpoint, data=data, api_type="cmdb")

    def delete(self, endpoint: str) -> Any:
        """DELETE request for CMDB endpoints"""
        return self._request("DELETE", endpoint, api_type="cmdb")

    # ---------------- Monitor API Methods ----------------
    def monitor_get(self, endpoint: str, params: Optional[Dict] = None) -> Any:
        """GET request for monitor endpoints (logs, stats, etc.)"""
        return self._request("GET", endpoint, params=params, api_type="monitor")

    # ---------------- Pagination Support ----------------
    def get_all(self, endpoint: str, page_size: int = 500) -> List[Dict]:
        """Get all objects with automatic pagination"""
        all_results = []
        start = 0
        
        while True:
            params = {"start": start, "count": page_size}
            response = self.get(endpoint, params)
            
            results = response.get("results", [])
            if not results:
                break
            
            all_results.extend(results)
            
            # Check if we got all results
            total = response.get("total", len(results))
            if len(all_results) >= total:
                break
            
            start += page_size
            
            # Safety limit
            if len(all_results) > 10000:
                logger.warning("Hit safety limit of 10000 objects")
                break
        
        return all_results

    # ---------------- Utility Methods ----------------
    def test_connection(self) -> bool:
        """Test API connection and credentials"""
        try:
            result = self.get("system/interface")
            return result.get("status") != "error"
        except Exception as e:
            logger.error("Connection test failed: %s", e)
            return False

    def get_vdom_list(self) -> List[str]:
        """Get list of available VDOMs"""
        try:
            response = self.get("system/vdom")
            return [v.get("name") for v in response.get("results", [])]
        except Exception as e:
            logger.error("Failed to get VDOM list: %s", e)
            return ["root"]