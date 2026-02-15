#!/usr/bin/env python3
"""
FINAL PHASE v2.0 – WAN FAILOVER MONITOR
Enhanced with comprehensive error handling, state management, and recovery
"""

import os
import time
import json
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
from dotenv import load_dotenv

# Import enhanced modules
try:
    from fortigate_api_helper_v2 import FortigateAPIHelper
    from error_handler import (
        ErrorHandler, NetworkError, APIError,
        ValidationError, retry_on_error, Validator,
        RecoveryManager
    )
    from logging_config import setup_syslog_logger
except ImportError:
    print("❌ Required modules not found")
    sys.exit(1)

# ================= Setup =================
logger = setup_syslog_logger("final_phase")
error_handler = ErrorHandler()
validator = Validator()
recovery = RecoveryManager()

# ================= Load ENV =================
load_dotenv()

FGT_IP = os.getenv("FORTIGATE_IP")
TOKEN = os.getenv("FORTIGATE_TOKEN")
VDOM = os.getenv("FORTIGATE_VDOM", "root")
PROTO = os.getenv("FORTIGATE_PROTOCOL", "http")
TIMEOUT = int(os.getenv("FORTIGATE_TIMEOUT", 10))

# Validate configuration
try:
    validator.validate_non_empty(FGT_IP, "FORTIGATE_IP")
    validator.validate_non_empty(TOKEN, "FORTIGATE_TOKEN")
except ValidationError as e:
    error_handler.log_error(e, {"component": "config"})
    print(f"❌ Configuration error: {e}")
    sys.exit(1)

BASE_URL = f"{PROTO}://{FGT_IP}/api/v2/cmdb"

# ================= WAN Configuration =================
WAN1 = os.getenv("WAN1_INTERFACE", "port1")
WAN2 = os.getenv("WAN2_INTERFACE", "port2")
VIP1 = os.getenv("VIP1_NAME", "VIP_FAILOVER_WAN1")
VIP2 = os.getenv("VIP2_NAME", "VIP_FAILOVER_WAN2")

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))
DEBOUNCE_COUNT = int(os.getenv("DEBOUNCE_COUNT", "3"))
MODE = os.getenv("MODE", "LIVE")

# ================= JSON Output =================
RESULT_DIR = Path("result_json")
RESULT_DIR.mkdir(exist_ok=True)
STATE_FILE = RESULT_DIR / "phase_state.json"
HISTORY_FILE = RESULT_DIR / "phase_history.json"
ERROR_SUMMARY_FILE = RESULT_DIR / "failover_errors.json"

# ================= State Manager =================
class StateManager:
    """Enhanced state management with error handling"""
    
    def __init__(self):
        self.state = self._load_state()
        self.history = self._load_history()
        self.errors = []
    
    def _load_state(self) -> Dict:
        """Load state with error handling"""
        try:
            if STATE_FILE.exists():
                with STATE_FILE.open("r", encoding="utf-8") as f:
                    state = json.load(f)
                    logger.info("State loaded successfully")
                    return state
        except json.JSONDecodeError as e:
            logger.error(f"Corrupted state file: {e}")
            print(f"⚠️  Warning: Corrupted state file, using defaults")
        except Exception as e:
            logger.error(f"Could not load state: {e}")
        
        # Default state
        return {
            "check": 0,
            "last_active_vip": None,
            "failover_count": 0,
            "wan1_down_count": 0,
            "wan2_down_count": 0,
            "both_down_count": 0,
            "last_failover": None,
            "uptime_start": datetime.now().isoformat()
        }
    
    def _load_history(self) -> list:
        """Load history with error handling"""
        try:
            if HISTORY_FILE.exists():
                with HISTORY_FILE.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("events", [])
        except Exception as e:
            logger.warning(f"Could not load history: {e}")
        return []
    
    def save_state(self, check: int, wan1_up: bool, wan2_up: bool, 
                   active_vip: Optional[str], failovers: int):
        """Save state with error handling"""
        self.state.update({
            "check": check,
            "timestamp": datetime.now().isoformat(),
            "WAN1": {"interface": WAN1, "status": "UP" if wan1_up else "DOWN"},
            "WAN2": {"interface": WAN2, "status": "UP" if wan2_up else "DOWN"},
            "active_vip": active_vip,
            "failover_count": failovers,
            "mode": MODE,
            "last_update": datetime.now().isoformat()
        })
        
        try:
            # Create backup before overwriting
            if STATE_FILE.exists():
                backup_data = {
                    "previous_state": self.state,
                    "timestamp": datetime.now().isoformat()
                }
                recovery.backup_state("state_update", backup_data)
            
            # Save new state
            with STATE_FILE.open("w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2, ensure_ascii=False)
            
            logger.debug("State saved successfully")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
            self.errors.append(f"State save failed: {str(e)}")
    
    def add_history_event(self, event_type: str, details: Dict):
        """Add event to history with error handling"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "details": details
        }
        self.history.append(event)
        
        # Keep last 100 events
        if len(self.history) > 100:
            self.history = self.history[-100:]
        
        try:
            with HISTORY_FILE.open("w", encoding="utf-8") as f:
                json.dump({
                    "events": self.history,
                    "last_updated": datetime.now().isoformat()
                }, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save history: {e}")
    
    def save_error_summary(self):
        """Save error summary"""
        try:
            summary = {
                "total_errors": len(self.errors),
                "errors": self.errors[-50:],  # Last 50 errors
                "timestamp": datetime.now().isoformat()
            }
            with ERROR_SUMMARY_FILE.open("w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save error summary: {e}")


state_manager = StateManager()

# ================= API Initialization =================
def initialize_api() -> Optional[FortigateAPIHelper]:
    """Initialize API with comprehensive error handling"""
    try:
        api = FortigateAPIHelper(
            base_url=BASE_URL,
            token=TOKEN,
            vdom=VDOM,
            timeout=TIMEOUT,
            verify_ssl=False,
            error_handler=error_handler
        )
        
        logger.info("API initialized successfully")
        return api
    
    except ValidationError as e:
        error_handler.log_error(e, {"component": "api_init"})
        print(f"\n❌ API initialization failed: {e}")
        return None
    
    except Exception as e:
        error = error_handler.handle_exception(e, {"component": "api_init"})
        print(f"\n❌ Failed to initialize API: {error.message}")
        return None


# ================= Interface Status =================
@retry_on_error(max_retries=3, delay=2.0)
def interface_up(api: FortigateAPIHelper, name: str) -> bool:
    """Check interface status with retry and error handling"""
    try:
        data = api.get(f"system/interface/{name}")
        if data and "results" in data and data["results"]:
            status = data["results"][0].get("status", "down")
            return status == "up"
        
        logger.warning(f"No results for interface {name}")
        return False
    
    except APIError as e:
        if "not found" in str(e).lower():
            logger.error(f"Interface {name} not found")
            raise ValidationError(f"Interface {name} does not exist")
        raise
    
    except Exception as e:
        logger.error(f"Error checking interface {name}: {e}")
        raise


# ================= VIP Operations =================
def vip_exists(api: FortigateAPIHelper, vip_name: str) -> bool:
    """Check if VIP exists with error handling"""
    try:
        return api.object_exists("firewall/vip", vip_name)
    except Exception as e:
        logger.error(f"Error checking VIP {vip_name}: {e}")
        return False


def validate_vips(api: FortigateAPIHelper) -> bool:
    """Validate that both VIPs exist"""
    missing = []
    
    try:
        if not vip_exists(api, VIP1):
            missing.append(VIP1)
        if not vip_exists(api, VIP2):
            missing.append(VIP2)
        
        if missing:
            error = ValidationError(
                f"VIPs not found: {', '.join(missing)}",
                {"missing_vips": missing}
            )
            error_handler.log_error(error, {"component": "vip_validation"})
            print(f"\n❌ VIPs not found: {', '.join(missing)}")
            print("Please create these VIPs before running failover monitor.")
            return False
        
        logger.info("VIPs validated successfully")
        return True
    
    except Exception as e:
        logger.error(f"VIP validation error: {e}")
        return False


# ================= Policy Management =================
@retry_on_error(max_retries=2, delay=1.0)
def policies_using_vip(api: FortigateAPIHelper, vip: str) -> list:
    """Get policies using VIP with error handling"""
    try:
        response = api.get("firewall/policy")
        policies = response.get("results", [])
        
        used = []
        for p in policies:
            dst = [d.get("name", "") for d in p.get("dstaddr", [])]
            if vip in dst:
                used.append(p["policyid"])
        
        return used
    
    except Exception as e:
        logger.error(f"Error getting policies for VIP {vip}: {e}")
        return []


@retry_on_error(max_retries=2, delay=1.0)
def set_policy(api: FortigateAPIHelper, pid: int, enable: bool) -> bool:
    """Enable/disable policy with retry"""
    try:
        api.put(f"firewall/policy/{pid}", {
            "status": "enable" if enable else "disable"
        })
        
        action = "enabled" if enable else "disabled"
        logger.info(f"Policy {pid} {action}")
        return True
    
    except APIError as e:
        logger.error(f"Failed to modify policy {pid}: {e}")
        return False
    
    except Exception as e:
        logger.error(f"Unexpected error modifying policy {pid}: {e}")
        return False


def activate(api: FortigateAPIHelper, vip_on: str, vip_off: str) -> Dict:
    """Activate vip_on and deactivate vip_off"""
    result = {
        "success": True,
        "vip_on": vip_on,
        "vip_off": vip_off,
        "policies_enabled": [],
        "policies_disabled": [],
        "errors": []
    }
    
    # Enable policies for active VIP
    for pid in policies_using_vip(api, vip_on):
        if set_policy(api, pid, True):
            result["policies_enabled"].append(pid)
        else:
            result["errors"].append(f"Failed to enable policy {pid}")
            result["success"] = False
    
    # Disable policies for inactive VIP
    for pid in policies_using_vip(api, vip_off):
        if set_policy(api, pid, False):
            result["policies_disabled"].append(pid)
        else:
            result["errors"].append(f"Failed to disable policy {pid}")
            result["success"] = False
    
    return result


# ================= Display =================
def icon(up: bool) -> str:
    """Get status icon"""
    return "🟢 UP  " if up else "🔴 DOWN"


def print_box(check: int, w1: bool, w2: bool, active_vip: Optional[str],
              failovers: int, both_down_count: int, errors: list):
    """Display monitoring status"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if active_vip == VIP1:
        active_path = "WAN1 (Primary)"
    elif active_vip == VIP2:
        active_path = "WAN2 (Backup)"
    else:
        active_path = "⚠️  NONE (BOTH DOWN)"

    print("\n" + "="*62)
    print("║      FortiGate WAN Failover Live Monitor (v2.0)     ║")
    print("="*62)
    print(f"║ Check #:        {check:<38}║")
    print(f"║ Time:           {now:<38}║")
    print("="*62)
    print(f"║ {WAN1:8s}:      {icon(w1):<38}║")
    print(f"║ {WAN2:8s}:      {icon(w2):<38}║")
    print("="*62)
    print(f"║ Active Path:    ➜ {active_path:<34}║")
    print(f"║ Active VIP:     🔵 {active_vip or 'NONE':<34}║")
    print("="*62)
    print(f"║ Failovers:      ⚠️  {failovers:<34}║")
    
    if both_down_count > 0:
        print(f"║ Both Down:      🚨 {both_down_count} checks{'':<26}║")
    
    if errors:
        print(f"║ Errors (session): ❌ {len(errors):<29}║")
    
    print(f"║ Mode:           {MODE:<38}║")
    print("="*62)
    print("Press Ctrl+C to stop monitoring")


# ================= Shutdown Handler =================
shutdown_flag = False

def signal_handler(sig, frame):
    """Handle shutdown signals"""
    global shutdown_flag
    print("\n\n🛑 Shutdown signal received...")
    shutdown_flag = True

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ================= Main Loop =================
def main() -> int:
    """Main monitoring loop with comprehensive error handling"""
    global shutdown_flag
    
    print(f"""
==========================================
  FINAL PHASE v2.0 – WAN FAILOVER MONITOR
==========================================
FortiGate : {FGT_IP}
VDOM      : {VDOM}
WAN1      : {WAN1} -> {VIP1}
WAN2      : {WAN2} -> {VIP2}
Interval  : {POLL_INTERVAL}s
Debounce  : {DEBOUNCE_COUNT} checks
Mode      : {MODE}
==========================================
""")

    # Initialize API
    print("🔌 Initializing API connection...")
    api = initialize_api()
    if not api:
        return 1
    
    # Test connection
    print("🔌 Testing connection...")
    try:
        if not api.test_connection():
            print("❌ Connection test failed")
            return 1
    except Exception as e:
        print(f"❌ Connection test failed: {e}")
        return 1
    
    print("✅ Connection successful")
    
    # Validate VIPs
    print("🔍 Validating VIPs...")
    if not validate_vips(api):
        return 1
    print("✅ VIPs validated\n")
    
    # Initialize state
    failovers = state_manager.state.get("failover_count", 0)
    last_active = state_manager.state.get("last_active_vip")
    check = state_manager.state.get("check", 0)
    both_down_count = 0
    session_errors = []
    
    # Debouncing state
    pending_change = None
    pending_count = 0

    try:
        while not shutdown_flag:
            check += 1

            # Check interface status
            try:
                w1 = interface_up(api, WAN1)
            except Exception as e:
                logger.error(f"Failed to check {WAN1}: {e}")
                session_errors.append(f"WAN1 check failed: {str(e)}")
                w1 = False
            
            try:
                w2 = interface_up(api, WAN2)
            except Exception as e:
                logger.error(f"Failed to check {WAN2}: {e}")
                session_errors.append(f"WAN2 check failed: {str(e)}")
                w2 = False

            # Determine desired VIP
            if w1:
                desired_vip = VIP1
            elif w2:
                desired_vip = VIP2
            else:
                desired_vip = None
                both_down_count += 1
                logger.critical("BOTH WANS DOWN!")

            # Debouncing logic
            if desired_vip != last_active:
                if pending_change == desired_vip:
                    pending_count += 1
                else:
                    pending_change = desired_vip
                    pending_count = 1
                
                # Execute change after debounce threshold
                if pending_count >= DEBOUNCE_COUNT:
                    if last_active is not None:
                        failovers += 1

                    try:
                        if desired_vip == VIP1:
                            result = activate(api, VIP1, VIP2)
                            msg = "FAILBACK → WAN1 ACTIVE"
                            event_type = "FAILBACK"
                            logger.warning(msg)
                            
                        elif desired_vip == VIP2:
                            result = activate(api, VIP2, VIP1)
                            msg = "FAILOVER → WAN2 ACTIVE"
                            event_type = "FAILOVER"
                            logger.warning(msg)
                            
                        else:
                            result = {"success": True, "errors": []}
                            msg = "BOTH WANS DOWN – NO ACTIVE VIP"
                            event_type = "BOTH_DOWN"
                            logger.error(msg)
                        
                        # Record event
                        state_manager.add_history_event(event_type, {
                            "from": last_active,
                            "to": desired_vip,
                            "success": result.get("success"),
                            "errors": result.get("errors", [])
                        })
                        
                        if not result.get("success"):
                            session_errors.extend(result.get("errors", []))
                        
                        last_active = desired_vip
                        pending_change = None
                        pending_count = 0
                    
                    except Exception as e:
                        logger.exception(f"Failover execution error: {e}")
                        session_errors.append(f"Failover failed: {str(e)}")
                        
            else:
                # State is stable
                pending_change = None
                pending_count = 0
                both_down_count = 0

            # Save state
            try:
                state_manager.save_state(check, w1, w2, last_active, failovers)
            except Exception as e:
                logger.error(f"State save error: {e}")
                session_errors.append(f"State save failed: {str(e)}")

            # Display status
            print_box(check, w1, w2, last_active, failovers, 
                     both_down_count, session_errors)

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\n\n⚠️  Monitoring stopped by user")
    
    except Exception as e:
        logger.exception(f"Fatal error in main loop: {e}")
        print(f"\n❌ Fatal error: {e}")
        return 1
    
    finally:
        # Save error summary
        state_manager.errors = session_errors
        state_manager.save_error_summary()
        
        # Final summary
        logger.info("Monitoring stopped gracefully")
        print("\n" + "="*60)
        print("   Monitoring Session Summary")
        print("="*60)
        print(f"Total checks:        {check}")
        print(f"Total failovers:     {failovers}")
        print(f"Session errors:      {len(session_errors)}")
        print(f"State saved to:      {STATE_FILE}")
        print(f"History saved to:    {HISTORY_FILE}")
        if session_errors:
            print(f"Error summary:       {ERROR_SUMMARY_FILE}")
        print("="*60 + "\n")
    
    return 0


# ================= Run =================
if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception as e:
        logger.exception("Fatal error")
        print(f"\n❌ Fatal error: {e}")
        exit_code = 1
    finally:
        # Cleanup old backups
        try:
            recovery.cleanup_old_backups(keep_last=20)
        except:
            pass
    
    sys.exit(exit_code)