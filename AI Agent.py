#!/usr/bin/env python3
"""
AI Agent - Intelligent FortiGate Assistant with Log Analysis (Enhanced + Fixed)
Improvements & Fixes:
- Uses .env for all credentials
- Better LLM response parsing (robust regex for JSON extraction)
- Enhanced error handling
- Improved log analysis performance
- Safer search operations
- Fixed PUT endpoint construction (require name)
- Optimized search_logs (avoid full json.dumps when possible)
- Minor cleanups and safety checks
"""
import argparse
import json
import re
import time
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import Counter
from pathlib import Path
import requests
from dotenv import load_dotenv
from fortigate_api_helper import FortigateAPIHelper, logger

# Load environment variables
load_dotenv()

# ----------------------------- Paths for Audit and Cache -----------------------------
BASE_DIR = Path(__file__).resolve().parent
AUDIT_LOG = BASE_DIR / "ai_agent_audit.json"
LOGS_CACHE = BASE_DIR / "fortigate_logs_cache.json"

# ----------------------------- Configuration from .env -------------------------------
DEFAULT_FGT_IP = os.getenv("FORTIGATE_IP", "192.168.55.238")
DEFAULT_FGT_TOKEN = os.getenv("FORTIGATE_TOKEN", "")
DEFAULT_VDOM = os.getenv("FORTIGATE_VDOM", "root")
LLM_API_URL = os.getenv("LLM_API_URL", "https://llm-net.partcorp.ir/v1/chat/completions")
LLM_TOKEN = os.getenv("LLM_TOKEN", "")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-oss-120b")

# Validation
if not DEFAULT_FGT_TOKEN:
    logger.warning("FORTIGATE_TOKEN not set in .env")
if not LLM_TOKEN:
    logger.warning("LLM_TOKEN not set in .env")

DANGEROUS_KEYWORDS = [
    'delete all', 'حذف همه', 'پاک کردن همه',
    'disable security', 'غیرفعال امنیت',
    'remove all', 'حذف تمام',
    'shutdown', 'خاموش کردن',
    'format', 'فرمت'
]

ALLOWED_OPERATIONS = [
    'create_address', 'create_vip', 'create_policy',
    'list_addresses', 'list_policies', 'list_vips',
    'query_traffic_logs', 'analyze_logs', 'search_logs'
]

# ----------------------------- Data Classes --------------------------------
@dataclass
class APICall:
    operation: str
    method: str
    endpoint: str
    data: Optional[Dict] = None
    description: str = ""
    safe: bool = True
    warnings: List[str] = field(default_factory=list)

@dataclass
class LogQuery:
    category: str
    subcategory: Optional[str] = None
    start_time: Optional[str] = None
    limit: int = 100
    filters: Optional[Dict] = None

@dataclass
class AgentAction:
    timestamp: str
    user_request: str
    llm_interpretation: str
    api_call: Optional[APICall]
    log_query: Optional[LogQuery]
    confirmed: bool
    executed: bool
    result: Optional[Dict] = None
    error: Optional[str] = None

# ----------------------------- LLM Client ----------------------------------
class LLMClient:
    def __init__(self, api_url: str = LLM_API_URL, token: str = LLM_TOKEN, model: str = LLM_MODEL):
        self.api_url = api_url
        self.token = token
        self.model = model
        self.max_retries = 3

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.1) -> Optional[str]:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature
        }
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    self.api_url,
                    headers=headers,
                    json=payload,
                    timeout=30
                )
                response.raise_for_status()
                data = response.json()
                content = data.get('choices', [{}])[0].get('message', {}).get('content', '').strip()
                if not content:
                    logger.warning("Empty response from LLM (attempt %d)", attempt + 1)
                    continue
                return content
            except requests.exceptions.Timeout:
                logger.warning("LLM timeout (attempt %d)", attempt + 1)
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                continue
            except requests.exceptions.RequestException as e:
                logger.error("LLM API error: %s", e)
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                continue
            except Exception as e:
                logger.error("Unexpected LLM error: %s", e)
                break
        return None

# ----------------------------- Log Analyzer --------------------------------
class FortiGateLogAnalyzer:
    def __init__(self, api: FortigateAPIHelper):
        self.api = api
        self.cache = self._load_cache()
        self.max_cache_size = 10000

    def _load_cache(self) -> Dict:
        try:
            with open(LOGS_CACHE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return {"logs": [], "last_update": None}
        except json.JSONDecodeError as e:
            logger.error("Cache file corrupted: %s", e)
            return {"logs": [], "last_update": None}

    def _save_cache(self):
        try:
            if len(self.cache["logs"]) > self.max_cache_size:
                self.cache["logs"] = self.cache["logs"][-self.max_cache_size:]
            with open(LOGS_CACHE, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Cache save error: {e}")

    def fetch_logs(self, log_query: LogQuery) -> Dict[str, any]:
     result = {"success": False, "logs": [], "count": 0}
    try:
        endpoint = f"log/device/{log_query.category}"
        if log_query.subcategory:
            endpoint += f"/{log_query.subcategory}"
        params = {"rows": min(log_query.limit, 1000)}
        if log_query.start_time:
            params["start"] = log_query.start_time
        if log_query.filters:
            params.update(log_query.filters)
        
        logger.info(f"Fetching logs: {endpoint} with params {params}")
        
        # Try monitor_get first, fallback to manual request
        try:
            if hasattr(self.api, 'monitor_get'):
                resp = self.api.monitor_get(endpoint, params)
                logs = resp.get('results', [])
            else:
                raise AttributeError("No monitor_get method")
        except (AttributeError, Exception) as e:
            logger.warning(f"monitor_get failed, using fallback: {e}")
            # Fallback: manual request
            base_url = self.api.base_url.replace('/cmdb/', '/monitor/')
            url = f"{base_url}{endpoint}"
            headers = {"Authorization": f"Bearer {self.api.token}"}
            params['vdom'] = self.api.vdom
            
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            resp = requests.get(url, headers=headers, params=params, 
                              timeout=30, verify=False)
            
            if resp.status_code != 200:
                result["error"] = f"HTTP {resp.status_code}: {resp.text[:200]}"
                return result
            
            data = resp.json()
            logs = data.get('results', [])
        
        result["success"] = True
        result["logs"] = logs
        result["count"] = len(logs)
        
        self.cache["logs"].extend(logs)
        self.cache["last_update"] = datetime.now().isoformat()
        self._save_cache()
        
        logger.info(f"Fetched {len(logs)} logs successfully")
        
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"Fetch logs error: {e}")
    
    return result

    def analyze_logs(self, logs: List[Dict], analysis_type: str = "summary") -> Dict[str, any]:
        if not logs:
            return {"error": "No logs to analyze"}
        analysis = {
            "total_logs": len(logs),
            "analysis_type": analysis_type,
            "timestamp": datetime.now().isoformat()
        }
        try:
            if analysis_type == "summary":
                actions = Counter(log.get('action', 'unknown') for log in logs)
                protocols = Counter(log.get('proto', 'unknown') for log in logs)
                services = Counter(log.get('service', 'unknown') for log in logs)
                analysis.update({
                    "actions": dict(actions),
                    "protocols": dict(protocols),
                    "top_services": dict(services.most_common(10))
                })
            elif analysis_type == "top_sources":
                sources = Counter(log.get('srcip', 'unknown') for log in logs)
                analysis["top_sources"] = sources.most_common(10)
            elif analysis_type == "top_destinations":
                destinations = Counter(log.get('dstip', 'unknown') for log in logs)
                analysis["top_destinations"] = destinations.most_common(10)
            elif analysis_type == "blocked_traffic":
                blocked = [log for log in logs if log.get('action') in ['deny', 'block', 'drop']]
                blocked_sources = Counter(log.get('srcip', 'unknown') for log in blocked)
                analysis.update({
                    "total_blocked": len(blocked),
                    "blocked_percentage": (len(blocked) / len(logs) * 100) if logs else 0,
                    "top_blocked_sources": blocked_sources.most_common(5)
                })
            elif analysis_type == "security_events":
                security_logs = [log for log in logs if log.get('type') in ['utm', 'ips', 'av', 'waf']]
                event_types = Counter(log.get('subtype', 'unknown') for log in security_logs)
                analysis.update({
                    "total_security_events": len(security_logs),
                    "event_types": dict(event_types),
                    "security_percentage": (len(security_logs) / len(logs) * 100) if logs else 0
                })
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            analysis["error"] = str(e)
        return analysis

    def search_logs(self, keyword: str, logs: Optional[List[Dict]] = None) -> List[Dict]:
        if logs is None:
            logs = self.cache.get("logs", [])
        if not keyword:
            return []
        results = []
        keyword_lower = keyword.lower()
        # Priority fields for faster search
        priority_fields = ['srcip', 'dstip', 'srcport', 'dstport', 'action', 'msg', 'policyname', 'user']
        try:
            for log in logs:
                # Fast check on priority fields
                if any(keyword_lower in str(log.get(field, '')).lower() for field in priority_fields):
                    results.append(log)
                    continue
                # Fallback: broader fields
                broader_fields = ['srcname', 'dstname', 'service', 'proto']
                if any(keyword_lower in str(log.get(field, '')).lower() for field in broader_fields):
                    results.append(log)
                if len(results) >= 100:
                    logger.info("Search limited to 100 results")
                    break
        except Exception as e:
            logger.error(f"Search error: {e}")
        return results

# ----------------------------- Security ------------------------------------
def check_dangerous_request(text: str) -> Tuple[bool, List[str]]:
    text_lower = text.lower()
    matched = [p for p in DANGEROUS_KEYWORDS if p in text_lower]
    return len(matched) > 0, matched

def validate_operation(operation: str) -> bool:
    return operation in ALLOWED_OPERATIONS

# ----------------------------- LLM Prompts ---------------------------------
def build_system_prompt() -> str:
    return """You are a FortiGate assistant. Parse Persian/English requests and return ONLY valid JSON.
Response Formats:
**CONFIG OPERATION:**
{
  "type": "config",
  "operation": "create_address",
  "method": "POST",
  "endpoint": "firewall/address",
  "data": {"name": "ADDR_10_10_10_10", "type": "ipmask", "subnet": "10.10.10.10 255.255.255.255"},
  "description": "Create address for 10.10.10.10",
  "safe": true
}
**LOG QUERY:**
{
  "type": "log_query",
  "operation": "query_traffic_logs",
  "log_query": {"category": "traffic", "limit": 100},
  "analysis_type": "summary",
  "description": "Query traffic logs",
  "safe": true
}
**LOG SEARCH:**
{
  "type": "log_query",
  "operation": "search_logs",
  "log_query": {"category": "traffic", "limit": 500},
  "search_keyword": "192.168.1.50",
  "description": "Search for IP 192.168.1.50",
  "safe": true
}
Analysis types: summary, top_sources, top_destinations, blocked_traffic, security_events
Rules:
- Return ONLY valid JSON, no markdown, no extra text
- Extract IPs, ports, names from Persian/English text
- Use descriptive names (e.g., ADDR_IP_ADDRESS)
- Set safe=false for risky operations
"""

# ----------------------------- LLM Response Parsing -------------------------
def parse_llm_response(llm_output: str) -> Tuple[Optional[APICall], Optional[LogQuery], Optional[str]]:
    if not llm_output:
        return None, None, None
    try:
        cleaned = llm_output.strip()
        # Extract from code blocks first
        code_block_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', cleaned, re.DOTALL | re.IGNORECASE)
        if code_block_match:
            cleaned = code_block_match.group(1)
        else:
            # Fallback: extract any JSON object
            json_match = re.search(r'\{.*\}', cleaned, re.DOTALL)
            if json_match:
                cleaned = json_match.group(0)
            else:
                raise ValueError("No JSON found")
        data = json.loads(cleaned)
        response_type = data.get('type', 'config')
        if response_type == 'config':
            api_call = APICall(
                operation=data['operation'],
                method=data['method'],
                endpoint=data['endpoint'],
                data=data.get('data'),
                description=data.get('description', ''),
                safe=data.get('safe', True),
                warnings=data.get('warnings', [])
            )
            return api_call, None, None
        elif response_type == 'log_query':
            log_query_data = data.get('log_query', {})
            log_query = LogQuery(
                category=log_query_data.get('category', 'traffic'),
                subcategory=log_query_data.get('subcategory'),
                start_time=log_query_data.get('start_time'),
                limit=log_query_data.get('limit', 100),
                filters=log_query_data.get('filters')
            )
            analysis_type = data.get('analysis_type', 'summary')
            search_keyword = data.get('search_keyword')
            return None, log_query, search_keyword if search_keyword else analysis_type
        return None, None, None
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"JSON parse error: {e}\nOutput: {llm_output[:200]}")
        return None, None, None
    except Exception as e:
        logger.error(f"Parse error: {e}\nOutput: {llm_output[:200]}")
        return None, None, None

# ----------------------------- Request Analysis -----------------------------
def analyze_request(user_request: str, llm_client: LLMClient) -> Tuple[Optional[APICall], Optional[LogQuery], str, Optional[str]]:
    is_dangerous, matched = check_dangerous_request(user_request)
    if is_dangerous:
        return None, None, f"⚠️ Dangerous keywords detected: {', '.join(matched)}", None
    messages = [
        {"role": "system", "content": build_system_prompt()},
        {"role": "user", "content": user_request}
    ]
    llm_response = llm_client.chat(messages)
    if not llm_response:
        return None, None, "❌ LLM service unavailable", None
    logger.info(f"LLM Response: {llm_response[:200]}")
    api_call, log_query, extra = parse_llm_response(llm_response)
    if not api_call and not log_query:
        return None, None, "❌ Could not understand request", None
    if api_call and not validate_operation(api_call.operation):
        api_call.safe = False
        api_call.warnings.append(f"Operation '{api_call.operation}' is not allowed")
    return api_call, log_query, llm_response, extra

# ----------------------------- Execute API Calls ---------------------------
def execute_api_call(api: FortigateAPIHelper, api_call: APICall, dry_run: bool = False) -> Dict:
    result = {"success": False, "dry_run": dry_run}
    if dry_run:
        result["success"] = True
        result["message"] = "✓ Dry-run mode - no changes made"
        return result
    try:
        if api_call.method == "GET":
            response = api.get(api_call.endpoint)
        elif api_call.method == "POST":
            response = api.post(api_call.endpoint, api_call.data)
        elif api_call.method == "PUT":
            obj_name = api_call.data.get('name') if api_call.data else None
            if not obj_name:
                raise ValueError("Name is required for PUT operation")
            endpoint = f"{api_call.endpoint}/{obj_name}"
            response = api.put(endpoint, api_call.data)
        elif api_call.method == "DELETE":
            response = api.delete(api_call.endpoint)
        else:
            raise ValueError(f"Unsupported method: {api_call.method}")
        result["success"] = True
        result["response"] = response
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"Execution error: {e}")
    return result

# ----------------------------- Execute Log Queries -------------------------
def execute_log_query(log_analyzer: FortiGateLogAnalyzer, log_query: LogQuery, extra: Optional[str] = None) -> Dict:
    result = {"success": False}
    try:
        fetch_result = log_analyzer.fetch_logs(log_query)
        if not fetch_result.get("success"):
            result["error"] = fetch_result.get("error")
            return result
        logs = fetch_result["logs"]
        result["log_count"] = len(logs)
        if extra and extra not in ['summary', 'top_sources', 'top_destinations', 'blocked_traffic', 'security_events']:
            search_results = log_analyzer.search_logs(extra, logs)
            result.update({"success": True, "search_keyword": extra, "results": search_results, "result_count": len(search_results)})
            return result
        analysis_type = extra or "summary"
        analysis = log_analyzer.analyze_logs(logs, analysis_type)
        result.update({"success": True, "analysis": analysis})
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"Log query error: {e}")
    return result
# ----------------------------- Display Functions ---------------------------

def display_api_call(api_call: APICall):
    print("\n" + "="*60)
    print("📋 Suggested API Call")
    print("="*60)
    print(f"Operation: {api_call.operation}")
    print(f"Description: {api_call.description}")
    print(f"Method: {api_call.method}")
    print(f"Endpoint: {api_call.endpoint}")
    if api_call.data:
        print(f"\nData:")
        print(json.dumps(api_call.data, indent=2, ensure_ascii=False))
    print(f"\nSafe: {'✅' if api_call.safe else '❌'}")
    if api_call.warnings:
        print(f"\n⚠️ Warnings:")
        for w in api_call.warnings:
            print(f"  - {w}")
    print("="*60)

def display_log_query(log_query: LogQuery, extra: Optional[str] = None):
    print("\n" + "="*60)
    print("📊 Log Query")
    print("="*60)
    print(f"Category: {log_query.category}")
    if log_query.subcategory:
        print(f"Subcategory: {log_query.subcategory}")
    print(f"Limit: {log_query.limit}")
    if extra:
        print(f"Type: {extra}")
    print("="*60)

def display_log_results(result: Dict):
    print("\n" + "="*60)
    print("📈 Results")
    print("="*60)
    if "search_keyword" in result:
        print(f"Search: {result['search_keyword']}")
        print(f"Found: {result['result_count']}")
        if result['result_count'] > 0:
            print("\nSample:")
            for i, log in enumerate(result['results'][:5], 1):
                print(f"{i}. {log.get('srcip')} → {log.get('dstip')} | {log.get('action')}")
    elif "analysis" in result:
        analysis = result["analysis"]
        print(f"Total Logs: {analysis.get('total_logs', 0)}")
        atype = analysis.get("analysis_type")
        if atype == "summary" and "actions" in analysis:
            print("\nActions:")
            for action, count in analysis["actions"].items():
                print(f"  {action}: {count}")
        elif atype == "top_sources":
            print("\nTop Sources:")
            for ip, count in analysis.get("top_sources", []):
                print(f"  {ip}: {count}")
        elif atype == "top_destinations":
            print("\nTop Destinations:")
            for ip, count in analysis.get("top_destinations", []):
                print(f"  {ip}: {count}")
        elif atype == "blocked_traffic":
            print(f"\nBlocked: {analysis.get('total_blocked', 0)}")
            print(f"Percentage: {analysis.get('blocked_percentage', 0):.2f}%")
        elif atype == "security_events":
            print(f"\nSecurity Events: {analysis.get('total_security_events', 0)}")
    print("\n" + "="*60)

# ----------------------------- Interactive Session -------------------------

def yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    response = input(prompt + suffix).strip().lower()
    return response in ('y', 'yes') if response else default

def save_audit(action: AgentAction):
    try:
        try:
            with open(AUDIT_LOG, 'r', encoding='utf-8') as f:
                audit = json.load(f)
        except FileNotFoundError:
            audit = {"actions": []}
        audit["actions"].append(asdict(action))
        with open(AUDIT_LOG, 'w', encoding='utf-8') as f:
            json.dump(audit, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Audit save error: {e}")

def interactive_session(api: FortigateAPIHelper, llm_client: LLMClient, log_analyzer: FortiGateLogAnalyzer, args):
    print("\n" + "="*60)
    print("   🤖 FortiGate Assistant with Log Analysis")
    print("="*60)
    print("Examples:")
    print("  • Create address for 10.10.10.10")
    print("  • Traffic logs for last hour")
    print("  • Top source IPs")
    print("  • Search for 192.168.1.50")
    print("\nType 'exit' to quit")
    print("="*60 + "\n")
    while True:
        try:
            req = input("\n💬 Request: ").strip()
            if not req or req.lower() in ['exit', 'quit']:
                print("\n👋 Goodbye!")
                break
            action = AgentAction(
                timestamp=datetime.now().isoformat(),
                user_request=req,
                llm_interpretation="",
                api_call=None,
                log_query=None,
                confirmed=False,
                executed=False
            )
            print("\n🔍 Analyzing...")
            api_call, log_query, interp, extra = analyze_request(req, llm_client)
            action.llm_interpretation = interp
            if not api_call and not log_query:
                print(f"\n❌ {interp}")
                action.error = interp
                save_audit(action)
                continue
            if api_call:
                action.api_call = api_call
                if not api_call.safe:
                    print("\n⚠️ Unsafe operation!")
                    if not args.force and not yes_no("Continue?"):
                        save_audit(action)
                        continue
                display_api_call(api_call)
                if not args.force and not yes_no("\nExecute?"):
                    save_audit(action)
                    continue
                action.confirmed = True
                print("\n⚙️ Executing...")
                result = execute_api_call(api, api_call, args.dry_run)
                action.result = result
                action.executed = result.get('success', False)
                if result.get('success'):
                    print("\n✅ Success!")
                else:
                    print(f"\n❌ {result.get('error')}")
            elif log_query:
                action.log_query = log_query
                display_log_query(log_query, extra)
                if not args.force and not yes_no("\nExecute?", True):
                    save_audit(action)
                    continue
                action.confirmed = True
                print("\n⚙️ Fetching logs...")
                result = execute_log_query(log_analyzer, log_query, extra)
                action.result = result
                action.executed = result.get('success', False)
                if result.get('success'):
                    display_log_results(result)
                else:
                    print(f"\n❌ {result.get('error')}")
            save_audit(action)
        except KeyboardInterrupt:
            print("\n\n🛑 Stopped")
            break
        except Exception as e:
            logger.exception("Error")
            print(f"\n❌ {e}")

# ----------------------------- Main ----------------------------------------

def build_parser():
    p = argparse.ArgumentParser(description="AI Agent with Log Analysis")
    p.add_argument("--ip", default=DEFAULT_FGT_IP)
    p.add_argument("--token", default=DEFAULT_FGT_TOKEN)
    p.add_argument("--vdom", default=DEFAULT_VDOM)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--force", action="store_true")
    p.add_argument("--single", metavar="REQUEST")
    return p

def main():
    args = build_parser().parse_args()
    base_url = f"http://{args.ip}/api/v2/cmdb/"
    api = FortigateAPIHelper(base_url, args.token, args.vdom)
    llm_client = LLMClient()
    log_analyzer = FortiGateLogAnalyzer(api)
    print("\n" + "="*60)
    print("   AI AGENT + LOG ANALYSIS")
    print("="*60)
    print(f"FortiGate: {args.ip}")
    print(f"Mode: {'DRY RUN' if args.dry_run else 'LIVE'}")
    print("="*60)
    try:
        if args.single:
            api_call, log_query, interp, extra = analyze_request(args.single, llm_client)
            if api_call:
                display_api_call(api_call)
                if args.force or yes_no("\nExecute?"):
                    result = execute_api_call(api, api_call, args.dry_run)
                    return 0 if result.get('success') else 1
            elif log_query:
                display_log_query(log_query, extra)
                if args.force or yes_no("\nExecute?"):
                    result = execute_log_query(log_analyzer, log_query, extra)
                    if result.get('success'):
                        display_log_results(result)
                        return 0
                    return 1
            print(f"❌ {interp}")
            return 1
        else:
            interactive_session(api, llm_client, log_analyzer, args)
            return 0
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        logger.exception("Failed")
        return 1
        
if __name__ == "__main__":
    exit(main())