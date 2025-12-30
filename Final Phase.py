#!/usr/bin/env python3
"""
Final Phase - WAN Failover Monitoring & VIP Management

Creates dual VIPs on WAN1/WAN2 and monitors interface status.
Automatically enables/disables VIPs based on WAN availability:
- WAN1 UP → VIP1 active (primary)
- WAN1 DOWN, WAN2 UP → VIP2 active (failover)
- Both DOWN → All VIPs disabled (warning state)

Features:
- Real-time interface monitoring via Monitor API
- Automatic VIP failover
- Policy status management
- Health check logging
- Graceful shutdown (Ctrl+C)
- Dry-run mode for testing

Outputs:
- final_phase_monitor.log (monitoring history)
- final_phase_state.json (current state snapshot)
"""

import argparse
import json
import signal
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, Optional, Tuple

import requests
from fortigate_api_helper import FortigateAPIHelper, logger

# ----------------------------- Configuration -------------------------------
DEFAULT_FGT_IP = "192.168.55.238"
DEFAULT_TOKEN = "f1kQf0Q3pjhsw11HmgkcHG5r6s4Qm9"
DEFAULT_VDOM = "root"

DEFAULT_WAN1_INTF = "port1"
DEFAULT_WAN2_INTF = "port2"

DEFAULT_EXTIP_WAN1 = "203.0.113.10"
DEFAULT_EXTIP_WAN2 = "203.0.113.11"
DEFAULT_MAPPEDIP = "192.168.1.100"
DEFAULT_PORT = 80

DEFAULT_VIP1_NAME = "VIP_FAILOVER_WAN1"
DEFAULT_VIP2_NAME = "VIP_FAILOVER_WAN2"

DEFAULT_POLL_INTERVAL = 10  # seconds

STATE_FILE = "final_phase_state.json"
MONITOR_LOG = "final_phase_monitor.log"


# ----------------------------- Data Classes --------------------------------

@dataclass
class InterfaceStatus:
    """Interface status information"""
    name: str
    is_up: bool
    timestamp: str
    details: Optional[Dict] = None


@dataclass
class VIPState:
    """VIP configuration state"""
    name: str
    interface: str
    extip: str
    mappedip: str
    port: int
    is_active: bool
    last_toggled: Optional[str] = None


@dataclass
class MonitorState:
    """Overall monitoring state"""
    wan1: InterfaceStatus
    wan2: InterfaceStatus
    vip1: VIPState
    vip2: VIPState
    active_wan: Optional[str]
    failover_count: int
    last_check: str


# ----------------------------- Global State --------------------------------

class MonitorManager:
    """Manages monitoring state and graceful shutdown"""
    
    def __init__(self):
        self.running = True
        self.state: Optional[MonitorState] = None
        self.failover_count = 0
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"\n🛑 Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    def save_state(self):
        """Save current state to file"""
        if self.state:
            try:
                with open(STATE_FILE, 'w', encoding='utf-8') as f:
                    json.dump(asdict(self.state), f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error(f"Failed to save state: {e}")


monitor_manager = MonitorManager()


# ----------------------------- VIP Operations ------------------------------

def vip_exists(api: FortigateAPIHelper, vip_name: str) -> bool:
    """Check if VIP exists"""
    try:
        api.get(f'firewall/vip/{vip_name}')
        return True
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            return False
        raise
    except Exception:
        return False


def create_vip(api: FortigateAPIHelper, name: str, extintf: str, extip: str,
               mappedip: str, port: int, protocol: str = "tcp",
               dry_run: bool = False) -> Dict[str, any]:
    """
    Create VIP with new format (compatible with FortiOS 7.4+)
    """
    result = {"vip_name": name, "success": False}
    
    # Check if exists
    if vip_exists(api, name):
        logger.info(f"ℹ️  VIP '{name}' already exists")
        result["success"] = True
        result["status"] = "exists"
        return result
    
    payload = {
        "name": name,
        "extintf": extintf,
        "extip": extip,
        "mappedip": [{"range": mappedip}],  # New format
        "portforward": "enable",
        "protocol": protocol,
        "extport": port,
        "mappedport": port,
        "comment": f"Failover VIP on {extintf}"
    }
    
    if dry_run:
        logger.info(f"[DRY RUN] Would create VIP '{name}'")
        result["success"] = True
        result["dry_run"] = True
        result["payload"] = payload
        return result
    
    try:
        resp = api.post('firewall/vip', payload)
        logger.info(f"✅ VIP '{name}' created on {extintf}")
        result["success"] = True
        result["status"] = "created"
        result["response"] = resp
        return result
    
    except Exception as e:
        logger.error(f"❌ Failed to create VIP '{name}': {e}")
        result["error"] = str(e)
        return result


def get_vip_status(api: FortigateAPIHelper, vip_name: str) -> Optional[str]:
    """
    Get VIP status (note: VIPs don't have status field in some FortiOS versions)
    Returns: 'enable', 'disable', or None
    """
    try:
        resp = api.get(f'firewall/vip/{vip_name}')
        results = resp.get('results', [])
        if results:
            # Some FortiOS versions don't have status field for VIPs
            # We'll check if the field exists
            return results[0].get('status', None)
        return None
    except Exception as e:
        logger.error(f"Failed to get VIP status for '{vip_name}': {e}")
        return None


def toggle_vip_via_policy(api: FortigateAPIHelper, vip_name: str, 
                          enable: bool, dry_run: bool = False) -> Dict[str, any]:
    """
    Enable/disable VIP by controlling associated policies
    (VIPs themselves may not have status field, so we manage via policy)
    """
    result = {"vip": vip_name, "action": "enable" if enable else "disable", "success": False}
    
    try:
        # Find policies using this VIP
        all_policies = api.get('firewall/policy').get('results', [])
        policies_with_vip = []
        
        for policy in all_policies:
            dstaddrs = [d.get('name') for d in policy.get('dstaddr', [])]
            if vip_name in dstaddrs:
                policies_with_vip.append(policy)
        
        if not policies_with_vip:
            logger.warning(f"⚠️  No policies found using VIP '{vip_name}'")
            result["warning"] = "no_policies_found"
            result["success"] = True  # Not necessarily an error
            return result
        
        # Update each policy
        updated_policies = []
        for policy in policies_with_vip:
            policy_id = policy.get('policyid')
            policy_name = policy.get('name', f'Policy-{policy_id}')
            
            new_status = "enable" if enable else "disable"
            
            if dry_run:
                logger.info(f"[DRY RUN] Would set policy '{policy_name}' status to {new_status}")
                updated_policies.append({"id": policy_id, "name": policy_name, "dry_run": True})
                continue
            
            update_payload = {"status": new_status}
            api.put(f'firewall/policy/{policy_id}', update_payload)
            
            logger.info(f"✅ Policy '{policy_name}' (ID: {policy_id}) set to {new_status}")
            updated_policies.append({"id": policy_id, "name": policy_name, "status": new_status})
            
            time.sleep(0.2)  # Rate limiting
        
        result["success"] = True
        result["policies_updated"] = updated_policies
        return result
    
    except Exception as e:
        logger.error(f"❌ Failed to toggle VIP policies: {e}")
        result["error"] = str(e)
        return result


# ----------------------------- Interface Monitoring ------------------------

def get_interface_status(api: FortigateAPIHelper, interface: str) -> InterfaceStatus:
    """
    Get interface status via Monitor API
    
    Note: Monitor API endpoint is different from CMDB API
    Endpoint: /api/v2/monitor/system/interface/select
    """
    timestamp = datetime.now().isoformat()
    
    try:
        # Monitor API uses different base path
        monitor_endpoint = f'system/interface/select'
        params = {'interface_name': interface}
        
        # Make request to monitor API
        # We need to construct the full URL manually
        base_url = api.base_url.replace('/cmdb/', '/monitor/')
        
        url = f"{base_url}{monitor_endpoint}"
        headers = {"Authorization": f"Bearer {api.token}"}
        
        if api.vdom:
            params['vdom'] = api.vdom
        
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            results = data.get('results', [])
            
            if results:
                intf_data = results[0]
                is_up = intf_data.get('link', False)
                
                return InterfaceStatus(
                    name=interface,
                    is_up=is_up,
                    timestamp=timestamp,
                    details=intf_data
                )
        
        # Fallback: interface not found or API issue
        logger.warning(f"⚠️  Could not get status for interface '{interface}'")
        return InterfaceStatus(
            name=interface,
            is_up=False,
            timestamp=timestamp,
            details={"error": "interface_not_found"}
        )
    
    except Exception as e:
        logger.error(f"❌ Error getting interface status for '{interface}': {e}")
        return InterfaceStatus(
            name=interface,
            is_up=False,
            timestamp=timestamp,
            details={"error": str(e)}
        )


# ----------------------------- Failover Logic ------------------------------

def determine_active_wan(wan1_status: InterfaceStatus, 
                        wan2_status: InterfaceStatus) -> Tuple[Optional[str], str]:
    """
    Determine which WAN should be active based on interface status
    
    Priority:
    1. WAN1 (primary)
    2. WAN2 (failover)
    3. None (both down)
    
    Returns: (active_wan, reason)
    """
    if wan1_status.is_up:
        return "wan1", "WAN1 is up (primary)"
    elif wan2_status.is_up:
        return "wan2", "WAN1 down, WAN2 up (failover)"
    else:
        return None, "Both WANs are down"


def apply_failover_state(api: FortigateAPIHelper, active_wan: Optional[str],
                        vip1_name: str, vip2_name: str, 
                        dry_run: bool = False) -> Dict[str, any]:
    """
    Apply failover state by enabling/disabling VIPs
    
    States:
    - wan1: Enable VIP1, Disable VIP2
    - wan2: Disable VIP1, Enable VIP2
    - None: Disable both VIPs
    """
    result = {"active_wan": active_wan, "actions": []}
    
    if active_wan == "wan1":
        # Primary: VIP1 active
        res1 = toggle_vip_via_policy(api, vip1_name, enable=True, dry_run=dry_run)
        res2 = toggle_vip_via_policy(api, vip2_name, enable=False, dry_run=dry_run)
        result["actions"] = [res1, res2]
        logger.info("🟢 WAN1 ACTIVE: VIP1 enabled, VIP2 disabled")
    
    elif active_wan == "wan2":
        # Failover: VIP2 active
        res1 = toggle_vip_via_policy(api, vip1_name, enable=False, dry_run=dry_run)
        res2 = toggle_vip_via_policy(api, vip2_name, enable=True, dry_run=dry_run)
        result["actions"] = [res1, res2]
        logger.info("🟡 WAN2 ACTIVE: VIP1 disabled, VIP2 enabled (FAILOVER)")
    
    else:
        # Both down: disable all
        res1 = toggle_vip_via_policy(api, vip1_name, enable=False, dry_run=dry_run)
        res2 = toggle_vip_via_policy(api, vip2_name, enable=False, dry_run=dry_run)
        result["actions"] = [res1, res2]
        logger.warning("🔴 BOTH WANS DOWN: All VIPs disabled")
    
    return result


# ----------------------------- Setup Phase ---------------------------------

def setup_vips(api: FortigateAPIHelper, args: argparse.Namespace) -> Dict[str, any]:
    """
    Initial setup: Create VIPs and policies
    """
    print("\n" + "="*60)
    print("SETUP PHASE: Creating VIPs")
    print("="*60)
    
    result = {"vip1": None, "vip2": None, "policies": []}
    
    # Create VIP1 on WAN1
    print(f"\n[1/2] Creating VIP on {args.wan1_intf}...")
    result["vip1"] = create_vip(
        api, args.vip1_name, args.wan1_intf, args.extip_wan1,
        args.mappedip, args.port, dry_run=args.dry_run
    )
    
    # Create VIP2 on WAN2
    print(f"\n[2/2] Creating VIP on {args.wan2_intf}...")
    result["vip2"] = create_vip(
        api, args.vip2_name, args.wan2_intf, args.extip_wan2,
        args.mappedip, args.port, dry_run=args.dry_run
    )
    
    print("\n✅ Setup phase completed")
    return result


# ----------------------------- Monitor Loop --------------------------------

def monitoring_loop(api: FortigateAPIHelper, args: argparse.Namespace):
    """
    Main monitoring loop
    """
    print("\n" + "="*60)
    print("MONITORING PHASE: Starting WAN failover monitor")
    print("="*60)
    print(f"Poll interval: {args.poll_interval} seconds")
    print(f"Press Ctrl+C to stop\n")
    
    last_active_wan = None
    check_count = 0
    
    while monitor_manager.running:
        check_count += 1
        timestamp = datetime.now().isoformat()
        
        print(f"\n[Check #{check_count}] {timestamp}")
        print("-" * 60)
        
        # Get interface statuses
        wan1_status = get_interface_status(api, args.wan1_intf)
        wan2_status = get_interface_status(api, args.wan2_intf)
        
        print(f"WAN1 ({args.wan1_intf}): {'🟢 UP' if wan1_status.is_up else '🔴 DOWN'}")
        print(f"WAN2 ({args.wan2_intf}): {'🟢 UP' if wan2_status.is_up else '🔴 DOWN'}")
        
        # Determine active WAN
        active_wan, reason = determine_active_wan(wan1_status, wan2_status)
        print(f"Decision: {reason}")
        
        # Check if failover occurred
        if active_wan != last_active_wan:
            if last_active_wan is not None:
                monitor_manager.failover_count += 1
                logger.warning(f"⚠️  FAILOVER #{monitor_manager.failover_count}: {last_active_wan} → {active_wan}")
            
            # Apply new state
            print(f"\n🔄 Applying state change...")
            apply_result = apply_failover_state(
                api, active_wan, args.vip1_name, args.vip2_name, args.dry_run
            )
            
            last_active_wan = active_wan
        else:
            print(f"✓ State unchanged (Active WAN: {active_wan or 'None'})")
        
        # Update monitoring state
        monitor_manager.state = MonitorState(
            wan1=wan1_status,
            wan2=wan2_status,
            vip1=VIPState(
                name=args.vip1_name,
                interface=args.wan1_intf,
                extip=args.extip_wan1,
                mappedip=args.mappedip,
                port=args.port,
                is_active=(active_wan == "wan1"),
                last_toggled=timestamp if active_wan == "wan1" else None
            ),
            vip2=VIPState(
                name=args.vip2_name,
                interface=args.wan2_intf,
                extip=args.extip_wan2,
                mappedip=args.mappedip,
                port=args.port,
                is_active=(active_wan == "wan2"),
                last_toggled=timestamp if active_wan == "wan2" else None
            ),
            active_wan=active_wan,
            failover_count=monitor_manager.failover_count,
            last_check=timestamp
        )
        
        # Save state
        monitor_manager.save_state()
        
        # Wait for next poll
        print(f"\n⏱️  Next check in {args.poll_interval} seconds...")
        time.sleep(args.poll_interval)
    
    # Graceful shutdown
    print("\n\n" + "="*60)
    print("SHUTDOWN")
    print("="*60)
    print(f"Total checks performed: {check_count}")
    print(f"Total failovers: {monitor_manager.failover_count}")
    print(f"Final state saved to: {STATE_FILE}")
    print("\n✅ Monitoring stopped gracefully\n")


# ----------------------------- CLI -----------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Final Phase: WAN Failover Monitoring (FortiGate Automation)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    p.add_argument("--ip", default=DEFAULT_FGT_IP, help=f"FortiGate IP (default: {DEFAULT_FGT_IP})")
    p.add_argument("--token", default=DEFAULT_TOKEN, help="API Token")
    p.add_argument("--vdom", default=DEFAULT_VDOM, help=f"VDOM (default: {DEFAULT_VDOM})")
    p.add_argument("--https", action="store_true", help="Use HTTPS instead of HTTP")
    
    p.add_argument("--wan1-intf", default=DEFAULT_WAN1_INTF, help=f"WAN1 interface (default: {DEFAULT_WAN1_INTF})")
    p.add_argument("--wan2-intf", default=DEFAULT_WAN2_INTF, help=f"WAN2 interface (default: {DEFAULT_WAN2_INTF})")
    
    p.add_argument("--extip-wan1", default=DEFAULT_EXTIP_WAN1, help=f"External IP for WAN1 (default: {DEFAULT_EXTIP_WAN1})")
    p.add_argument("--extip-wan2", default=DEFAULT_EXTIP_WAN2, help=f"External IP for WAN2 (default: {DEFAULT_EXTIP_WAN2})")
    p.add_argument("--mappedip", default=DEFAULT_MAPPEDIP, help=f"Mapped IP (default: {DEFAULT_MAPPEDIP})")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Service port (default: {DEFAULT_PORT})")
    
    p.add_argument("--vip1-name", default=DEFAULT_VIP1_NAME, help=f"VIP1 name (default: {DEFAULT_VIP1_NAME})")
    p.add_argument("--vip2-name", default=DEFAULT_VIP2_NAME, help=f"VIP2 name (default: {DEFAULT_VIP2_NAME})")
    
    p.add_argument("--poll-interval", type=int, default=DEFAULT_POLL_INTERVAL, 
                   help=f"Polling interval in seconds (default: {DEFAULT_POLL_INTERVAL})")
    
    p.add_argument("--dry-run", action="store_true", help="Simulate actions without making changes")
    p.add_argument("--skip-setup", action="store_true", help="Skip VIP creation, go straight to monitoring")
    
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    
    # Setup API
    scheme = "https" if args.https else "http"
    base_url = f"{scheme}://{args.ip}/api/v2/cmdb/"
    
    api = FortigateAPIHelper(
        base_url=base_url,
        token=args.token,
        vdom=args.vdom
    )
    
    print("\n" + "="*60)
    print("   FINAL PHASE – WAN Failover Monitoring")
    print("="*60)
    print(f"FortiGate IP  : {args.ip}")
    print(f"VDOM          : {args.vdom}")
    print(f"Transport     : {'HTTPS' if args.https else 'HTTP'}")
    print(f"Mode          : {'DRY RUN' if args.dry_run else 'LIVE'}")
    print(f"\nWAN1 Interface: {args.wan1_intf} → {args.extip_wan1}")
    print(f"WAN2 Interface: {args.wan2_intf} → {args.extip_wan2}")
    print(f"Mapped IP     : {args.mappedip}:{args.port}")
    print("="*60)
    
    try:
        # Setup phase
        if not args.skip_setup:
            setup_result = setup_vips(api, args)
            time.sleep(1)
        else:
            print("\n⏭️  Skipping setup phase (--skip-setup)")
        
        # Monitoring phase
        monitoring_loop(api, args)
        
        return 0
    
    except KeyboardInterrupt:
        print("\n\n🛑 Interrupted by user")
        monitor_manager.save_state()
        return 130
    
    except Exception as e:
        logger.exception("Final phase failed with error")
        print(f"\n❌ Fatal error: {e}")
        monitor_manager.save_state()
        return 1


if __name__ == "__main__":
    sys.exit(main())