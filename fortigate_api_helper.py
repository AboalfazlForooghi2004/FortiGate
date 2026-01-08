#!/usr/bin/env python3
"""
FortiGate API Helper v2.0 - Enhanced Error Handling
Comprehensive error handling, retry logic, connection validation
"""

import requests
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any, List
from logging_config import setup_syslog_logger
from error_handler import (
    ErrorHandler, NetworkError, APIError, AuthenticationError,
    TimeoutError, ValidationError, retry_on_error, Validator
)

logger = setup_syslog_logger("fortigate_api_helper")


class FortigateAPIHelper:
    """Enhanced FortiGate API wrapper with comprehensive error handling"""

    def __init__(
        self,
        base_url: str,
        token: str,
        vdom: str = "root",
        verify_ssl: bool = False,
        timeout: int = 10,
        retries: int = 3,
        status_forcelist: Optional[List[int]] = None,
        error_handler: ErrorHandler = None
    ):
        # Initialize error handler
        self.error_handler = error_handler or ErrorHandler()
        self.validator = Validator()
        
        # Validate inputs
        try:
            self._validate_init_params(base_url, token, vdom, timeout, retries)
        except ValidationError as e:
            self.error_handler.log_error(e, {"component": "api_init"})
            raise
        
        # Configuration
        self.base_url = base_url.rstrip("/").replace("/api/v2/cmdb", "/api/v2")
        self.vdom = vdom
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.token = token
        self._last_request_time = 0
        self._min_request_interval = 0.1
        self._connection_tested = False

        if status_forcelist is None:
            status_forcelist = [429, 502, 503, 504]

        # Session setup
        self.session = self._setup_session(token, retries, status_forcelist)
        
        # Disable SSL warnings if needed
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        logger.info(
            "FortigateAPIHelper initialized (vdom=%s, base_url=%s, ssl_verify=%s)",
            self.vdom, self.base_url, self.verify_ssl
        )
    
    def _validate_init_params(self, base_url: str, token: str, vdom: str, 
                             timeout: int, retries: int):
        """Validate initialization parameters"""
        if not base_url:
            raise ValidationError("base_url cannot be empty")
        
        if not token:
            raise ValidationError("API token cannot be empty")
        
        if not vdom:
            raise ValidationError("VDOM cannot be empty")
        
        if timeout <= 0:
            raise ValidationError(f"timeout must be positive, got {timeout}")
        
        if retries < 0:
            raise ValidationError(f"retries must be non-negative, got {retries}")
    
    def _setup_session(self, token: str, retries: int, 
                       status_forcelist: List[int]) -> requests.Session:
        """Setup requests session with retry strategy"""
        session = requests.Session()
        session.headers.update({
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
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session

    def _rate_limit(self):
        """Rate limiting to avoid overwhelming FortiGate"""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_request_interval:
            time.sleep(self._min_request_interval - elapsed)
        self._last_request_time = time.time()

    def _safe_json(self, response: requests.Response) -> Any:
        """Safely parse JSON response"""
        if not response.text:
            return {}
        try:
            return response.json()
        except ValueError as e:
            logger.warning("Failed to parse JSON: %s", e)
            error = ValidationError(
                "Invalid JSON response from FortiGate",
                {"response_text": response.text[:200], "error": str(e)}
            )
            self.error_handler.log_error(error, {"endpoint": response.url})
            return {"error": "invalid_json", "raw_text": response.text[:500]}

    def _build_url(self, endpoint: str, api_type: str = "cmdb") -> str:
        """Build full URL with proper API type"""
        endpoint = endpoint.lstrip("/")
        return f"{self.base_url}/{api_type}/{endpoint}"

    @retry_on_error(max_retries=2, delay=1.0)
    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        api_type: str = "cmdb"
    ) -> Any:
        """Internal request handler with comprehensive error handling"""
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
            error = TimeoutError(
                f"Request timeout after {self.timeout}s",
                {"method": method, "url": url, "error": str(e)}
            )
            self.error_handler.log_error(error, {"endpoint": endpoint})
            raise error
        
        except requests.exceptions.ConnectionError as e:
            error = NetworkError(
                "Cannot connect to FortiGate",
                {"method": method, "url": url, "error": str(e)}
            )
            self.error_handler.log_error(error, {"endpoint": endpoint})
            raise error
        
        except requests.exceptions.RequestException as e:
            error = NetworkError(
                f"Network error: {str(e)}",
                {"method": method, "url": url}
            )
            self.error_handler.log_error(error, {"endpoint": endpoint})
            raise error

        body = self._safe_json(response)
        
        # Handle HTTP errors
        if response.status_code >= 400:
            error_msg = self._extract_error_message(body, response)
            
            # Categorize by status code
            if response.status_code == 401:
                error = AuthenticationError(
                    "Authentication failed - Invalid token",
                    {"status": response.status_code, "endpoint": endpoint}
                )
            elif response.status_code == 403:
                error = APIError(
                    "Permission denied",
                    {"status": response.status_code, "endpoint": endpoint}
                )
            elif response.status_code == 404:
                error = APIError(
                    f"Resource not found: {endpoint}",
                    {"status": response.status_code}
                )
            elif response.status_code >= 500:
                error = APIError(
                    f"FortiGate server error: {error_msg}",
                    {"status": response.status_code}
                )
            else:
                error = APIError(
                    error_msg,
                    {"status": response.status_code}
                )
            
            logger.error("HTTP %d for %s %s: %s", 
                        response.status_code, method, url, error_msg)
            self.error_handler.log_error(error, {"method": method, "endpoint": endpoint})
            
            raise error

        # Check for FortiGate API errors
        if isinstance(body, dict):
            if body.get("status") == "error":
                error_msg = body.get("cli_error") or body.get("error") or "Unknown error"
                error_code = body.get("error", -1)
                
                error = APIError(
                    f"FortiGate API error: {error_msg}",
                    {"error_code": error_code, "endpoint": endpoint, "method": method}
                )
                logger.error("FortiGate API error: %s", error_msg)
                self.error_handler.log_error(error, {"endpoint": endpoint})
                
                raise error

        return body

    def _extract_error_message(self, body: Any, response: requests.Response) -> str:
        """Extract meaningful error message"""
        if isinstance(body, dict):
            for key in ["cli_error", "error", "message"]:
                if key in body and body[key]:
                    return str(body[key])
            
            if body.get("status") == "error":
                return f"FortiGate returned error (code: {body.get('error', 'unknown')})"
        
        return f"HTTP {response.status_code}: {response.reason}"

    # ==================== CMDB API Methods ====================
    def get(self, endpoint: str, params: Optional[Dict] = None) -> Any:
        """GET request for CMDB endpoints with error handling"""
        try:
            return self._request("GET", endpoint, params=params, api_type="cmdb")
        except Exception as e:
            # Errors already logged by _request
            raise

    def post(self, endpoint: str, data: Dict) -> Any:
        """POST request for CMDB endpoints with validation"""
        if not data:
            error = ValidationError("POST data cannot be empty")
            self.error_handler.log_error(error, {"endpoint": endpoint})
            raise error
        
        try:
            return self._request("POST", endpoint, data=data, api_type="cmdb")
        except Exception as e:
            raise

    def put(self, endpoint: str, data: Dict) -> Any:
        """PUT request for CMDB endpoints with validation"""
        if not data:
            error = ValidationError("PUT data cannot be empty")
            self.error_handler.log_error(error, {"endpoint": endpoint})
            raise error
        
        try:
            return self._request("PUT", endpoint, data=data, api_type="cmdb")
        except Exception as e:
            raise

    def delete(self, endpoint: str) -> Any:
        """DELETE request for CMDB endpoints"""
        try:
            return self._request("DELETE", endpoint, api_type="cmdb")
        except Exception as e:
            raise

    # ==================== Monitor API Methods ====================
    def monitor_get(self, endpoint: str, params: Optional[Dict] = None) -> Any:
        """GET request for monitor endpoints with error handling"""
        try:
            return self._request("GET", endpoint, params=params, api_type="monitor")
        except Exception as e:
            raise

    # ==================== Pagination ====================
    def get_all(self, endpoint: str, page_size: int = 500, 
                max_results: int = 10000) -> List[Dict]:
        """Get all objects with automatic pagination and safety limit"""
        all_results = []
        start = 0
        
        try:
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
                if len(all_results) >= max_results:
                    logger.warning("Hit safety limit of %d objects", max_results)
                    break
            
            return all_results
        
        except Exception as e:
            logger.error("Pagination failed at start=%d: %s", start, e)
            # Return partial results instead of failing completely
            if all_results:
                logger.info("Returning %d partial results", len(all_results))
            raise

    # ==================== Health Check ====================
    @retry_on_error(max_retries=3, delay=2.0)
    def test_connection(self) -> bool:
        """Test API connection and credentials with retry"""
        try:
            result = self.get("system/interface")
            
            if result.get("status") == "error":
                return False
            
            self._connection_tested = True
            logger.info("✅ Connection test successful")
            return True
        
        except AuthenticationError:
            logger.error("❌ Authentication failed")
            return False
        
        except NetworkError:
            logger.error("❌ Network connection failed")
            return False
        
        except Exception as e:
            logger.error("❌ Connection test failed: %s", e)
            return False
    
    def ensure_connection(self):
        """Ensure connection is working, raise error if not"""
        if not self._connection_tested:
            if not self.test_connection():
                error = NetworkError(
                    "Failed to establish connection to FortiGate",
                    {"base_url": self.base_url, "vdom": self.vdom}
                )
                self.error_handler.log_error(error)
                raise error

    # ==================== Utility Methods ====================
    def get_vdom_list(self) -> List[str]:
        """Get list of available VDOMs"""
        try:
            response = self.get("system/vdom")
            return [v.get("name") for v in response.get("results", [])]
        except Exception as e:
            logger.error("Failed to get VDOM list: %s", e)
            return ["root"]
    
    def object_exists(self, path: str, name: str) -> bool:
        """Check if object exists without raising errors"""
        try:
            response = self.get(f"{path}/{name}")
            return response.get("status") != "error"
        except APIError:
            return False
        except Exception:
            return False
    
    def get_error_summary(self) -> Dict:
        """Get error summary from error handler"""
        return self.error_handler.get_error_summary()


# ==================== Example Usage ====================
if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    
    # Initialize with error handling
    try:
        api = FortigateAPIHelper(
            base_url=f"http://{os.getenv('FORTIGATE_IP')}/api/v2/cmdb/",
            token=os.getenv('FORTIGATE_TOKEN'),
            vdom=os.getenv('FORTIGATE_VDOM', 'root')
        )
        
        # Test connection
        if api.test_connection():
            print("✅ Connected successfully")
            
            # Example operations
            try:
                addresses = api.get("firewall/address")
                print(f"✅ Found {len(addresses.get('results', []))} addresses")
            except Exception as e:
                print(f"❌ Failed to get addresses: {e}")
        else:
            print("❌ Connection test failed")
        
        # Print error summary
        summary = api.get_error_summary()
        if summary['total_errors'] > 0:
            print(f"\n📊 Total errors: {summary['total_errors']}")
    
    except Exception as e:
        print(f"❌ Initialization failed: {e}")