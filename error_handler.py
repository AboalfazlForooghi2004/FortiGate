#!/usr/bin/env python3
"""
Central Error Handler for FortiGate Automation
Comprehensive error handling, logging, and recovery
"""

import sys
import json
import traceback
from enum import Enum
from typing import Dict, Any, Optional, Callable
from pathlib import Path
from datetime import datetime
from functools import wraps
import logging

# ===================== Error Categories =====================
class ErrorCategory(Enum):
    """Error classification for better handling"""
    NETWORK = "network_error"
    API = "api_error"
    VALIDATION = "validation_error"
    CONFIGURATION = "configuration_error"
    AUTHENTICATION = "authentication_error"
    PERMISSION = "permission_error"
    TIMEOUT = "timeout_error"
    RESOURCE = "resource_error"
    UNKNOWN = "unknown_error"


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ===================== Custom Exceptions =====================
class FortiGateError(Exception):
    """Base exception for FortiGate operations"""
    def __init__(self, message: str, category: ErrorCategory = ErrorCategory.UNKNOWN,
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM, details: Dict = None):
        self.message = message
        self.category = category
        self.severity = severity
        self.details = details or {}
        self.timestamp = datetime.now().isoformat()
        super().__init__(self.message)

    def to_dict(self) -> Dict:
        return {
            "error": self.message,
            "category": self.category.value,
            "severity": self.severity.value,
            "details": self.details,
            "timestamp": self.timestamp
        }


class NetworkError(FortiGateError):
    """Network connectivity errors"""
    def __init__(self, message: str, details: Dict = None):
        super().__init__(message, ErrorCategory.NETWORK, ErrorSeverity.HIGH, details)


class APIError(FortiGateError):
    """FortiGate API errors"""
    def __init__(self, message: str, details: Dict = None):
        super().__init__(message, ErrorCategory.API, ErrorSeverity.MEDIUM, details)


class ValidationError(FortiGateError):
    """Input validation errors"""
    def __init__(self, message: str, details: Dict = None):
        super().__init__(message, ErrorCategory.VALIDATION, ErrorSeverity.LOW, details)


class AuthenticationError(FortiGateError):
    """Authentication/Authorization errors"""
    def __init__(self, message: str, details: Dict = None):
        super().__init__(message, ErrorCategory.AUTHENTICATION, ErrorSeverity.CRITICAL, details)


class TimeoutError(FortiGateError):
    """Operation timeout errors"""
    def __init__(self, message: str, details: Dict = None):
        super().__init__(message, ErrorCategory.TIMEOUT, ErrorSeverity.MEDIUM, details)


# ===================== Error Handler =====================
class ErrorHandler:
    """Central error handler with logging and recovery"""
    
    def __init__(self, log_dir: Path = None, error_log_file: str = "errors.json"):
        self.log_dir = log_dir or Path("result_json")
        self.log_dir.mkdir(exist_ok=True)
        self.error_log_path = self.log_dir / error_log_file
        self.errors = self._load_errors()
        
    def _load_errors(self) -> list:
        """Load previous errors from log file"""
        try:
            if self.error_log_path.exists():
                with open(self.error_log_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get('errors', [])
        except Exception as e:
            print(f"⚠️  Warning: Could not load error log: {e}")
        return []
    
    def _save_errors(self):
        """Save errors to log file"""
        try:
            with open(self.error_log_path, 'w', encoding='utf-8') as f:
                json.dump({
                    'errors': self.errors[-1000:],  # Keep last 1000 errors
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"⚠️  Warning: Could not save error log: {e}")
    
    def log_error(self, error: FortiGateError, context: Dict = None):
        """Log error with context"""
        error_entry = error.to_dict()
        if context:
            error_entry['context'] = context
        
        self.errors.append(error_entry)
        self._save_errors()
        
        # Print user-friendly message
        self._print_error(error)
    
    def _print_error(self, error: FortiGateError):
        """Print formatted error message"""
        icon = {
            ErrorSeverity.LOW: "ℹ️",
            ErrorSeverity.MEDIUM: "⚠️",
            ErrorSeverity.HIGH: "❌",
            ErrorSeverity.CRITICAL: "🚨"
        }.get(error.severity, "⚠️")
        
        print(f"\n{icon} {error.severity.value.upper()}: {error.message}")
        
        if error.details:
            print(f"   Details: {json.dumps(error.details, ensure_ascii=False)}")
        
        if error.category == ErrorCategory.AUTHENTICATION:
            print("   💡 Hint: Check FORTIGATE_TOKEN in .env file")
        elif error.category == ErrorCategory.NETWORK:
            print("   💡 Hint: Verify FortiGate IP and network connectivity")
        elif error.category == ErrorCategory.VALIDATION:
            print("   💡 Hint: Check input format and values")
    
    def handle_exception(self, exc: Exception, context: Dict = None) -> FortiGateError:
        """Convert generic exception to FortiGateError"""
        import requests
        
        # Map common exceptions to custom errors
        if isinstance(exc, requests.exceptions.ConnectionError):
            error = NetworkError(
                "Cannot connect to FortiGate",
                {"original_error": str(exc), "type": type(exc).__name__}
            )
        elif isinstance(exc, requests.exceptions.Timeout):
            error = TimeoutError(
                "Request timed out",
                {"original_error": str(exc)}
            )
        elif isinstance(exc, requests.exceptions.HTTPError):
            status = exc.response.status_code if exc.response else 0
            if status == 401:
                error = AuthenticationError(
                    "Authentication failed - Invalid token",
                    {"status_code": status}
                )
            elif status == 403:
                error = FortiGateError(
                    "Permission denied",
                    ErrorCategory.PERMISSION,
                    ErrorSeverity.HIGH,
                    {"status_code": status}
                )
            else:
                error = APIError(
                    f"HTTP error {status}",
                    {"status_code": status, "response": exc.response.text[:200] if exc.response else ""}
                )
        elif isinstance(exc, (ValueError, TypeError)):
            error = ValidationError(
                str(exc),
                {"type": type(exc).__name__}
            )
        elif isinstance(exc, FortiGateError):
            error = exc
        else:
            error = FortiGateError(
                f"Unexpected error: {str(exc)}",
                ErrorCategory.UNKNOWN,
                ErrorSeverity.HIGH,
                {"type": type(exc).__name__, "traceback": traceback.format_exc()}
            )
        
        self.log_error(error, context)
        return error
    
    def get_error_summary(self) -> Dict:
        """Get summary of logged errors"""
        from collections import Counter
        
        categories = Counter(e.get('category') for e in self.errors)
        severities = Counter(e.get('severity') for e in self.errors)
        
        return {
            "total_errors": len(self.errors),
            "by_category": dict(categories),
            "by_severity": dict(severities),
            "recent_errors": self.errors[-10:]
        }


# ===================== Decorators =====================
def handle_errors(error_handler: ErrorHandler = None, context: Dict = None):
    """Decorator for automatic error handling"""
    if error_handler is None:
        error_handler = ErrorHandler()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                func_context = {
                    "function": func.__name__,
                    "args": str(args)[:100],
                    "kwargs": str(kwargs)[:100]
                }
                if context:
                    func_context.update(context)
                
                error = error_handler.handle_exception(e, func_context)
                
                # Return error dict instead of raising
                return {
                    "success": False,
                    "error": error.to_dict()
                }
        return wrapper
    return decorator


def retry_on_error(max_retries: int = 3, delay: float = 1.0, 
                   backoff: float = 2.0, retry_on: tuple = None):
    """Decorator for retrying failed operations"""
    import time
    
    if retry_on is None:
        retry_on = (NetworkError, TimeoutError)
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            current_delay = delay
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retry_on as e:
                    last_exception = e
                    if attempt < max_retries:
                        print(f"   🔄 Retry {attempt + 1}/{max_retries} after {current_delay:.1f}s...")
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        raise
                except Exception as e:
                    # Don't retry on other exceptions
                    raise
            
            # Should never reach here
            raise last_exception
        return wrapper
    return decorator


# ===================== Validation Helpers =====================
class Validator:
    """Input validation utilities"""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IPv4/IPv6 address"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            raise ValidationError(f"Invalid IP address: {ip}")
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number"""
        if not (1 <= port <= 65535):
            raise ValidationError(f"Invalid port number: {port} (must be 1-65535)")
        return True
    
    @staticmethod
    def validate_non_empty(value: str, field_name: str) -> bool:
        """Validate non-empty string"""
        if not value or not value.strip():
            raise ValidationError(f"{field_name} cannot be empty")
        return True
    
    @staticmethod
    def validate_choice(value: str, choices: list, field_name: str) -> bool:
        """Validate value is in allowed choices"""
        if value not in choices:
            raise ValidationError(
                f"Invalid {field_name}: {value}. Must be one of: {', '.join(choices)}"
            )
        return True


# ===================== Recovery Manager =====================
class RecoveryManager:
    """Manage operation recovery and rollback"""
    
    def __init__(self, backup_dir: Path = None):
        self.backup_dir = backup_dir or Path("result_json/backups")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.operations = []
    
    def backup_state(self, operation_name: str, state: Dict) -> Path:
        """Backup current state before operation"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"{operation_name}_{timestamp}.json"
        
        try:
            with open(backup_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'operation': operation_name,
                    'timestamp': timestamp,
                    'state': state
                }, f, indent=2, ensure_ascii=False)
            
            self.operations.append({
                'operation': operation_name,
                'backup_file': str(backup_file),
                'timestamp': timestamp
            })
            
            return backup_file
        except Exception as e:
            print(f"⚠️  Warning: Could not create backup: {e}")
            return None
    
    def get_latest_backup(self, operation_name: str) -> Optional[Dict]:
        """Get latest backup for operation"""
        backups = sorted(
            self.backup_dir.glob(f"{operation_name}_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        
        if backups:
            try:
                with open(backups[0], 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️  Warning: Could not load backup: {e}")
        
        return None
    
    def cleanup_old_backups(self, keep_last: int = 10):
        """Remove old backup files"""
        backups = sorted(
            self.backup_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        
        for backup in backups[keep_last:]:
            try:
                backup.unlink()
            except Exception as e:
                print(f"⚠️  Warning: Could not delete backup {backup}: {e}")


# ===================== Example Usage =====================
if __name__ == "__main__":
    # Initialize error handler
    handler = ErrorHandler()
    validator = Validator()
    recovery = RecoveryManager()
    
    # Example 1: Using decorator
    @handle_errors(handler)
    def test_operation():
        validator.validate_ip("192.168.1.1")
        return {"success": True, "message": "Operation completed"}
    
    # Example 2: Using retry decorator
    @retry_on_error(max_retries=3, delay=1.0)
    def test_network_operation():
        import requests
        response = requests.get("http://192.168.1.1", timeout=5)
        return response.json()
    
    # Example 3: Manual error handling
    try:
        validator.validate_ip("invalid_ip")
    except ValidationError as e:
        handler.log_error(e, {"operation": "ip_validation"})
    
    # Example 4: Recovery
    backup_file = recovery.backup_state("test_op", {"data": "important"})
    print(f"✅ Backup created: {backup_file}")
    
    # Print error summary
    print("\n📊 Error Summary:")
    print(json.dumps(handler.get_error_summary(), indent=2))