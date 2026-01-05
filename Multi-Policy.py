#!/usr/bin/env python3
"""
FortiGate Automation with Jinja2 Templates
Enhanced version with template-based configuration
"""

import os
import json
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, Template
from dotenv import load_dotenv
from typing import Dict, List

load_dotenv()

# ===================== Jinja2 Setup =====================
TEMPLATE_DIR = Path("templates")
TEMPLATE_DIR.mkdir(exist_ok=True)

env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    trim_blocks=True,
    lstrip_blocks=True
)

# ===================== Template Definitions =====================

# VIP Template
VIP_TEMPLATE = """
{
  "name": "{{ name }}",
  "type": "{{ type | default('static-nat') }}",
  "extintf": "{{ extintf }}",
  "extip": "{{ extip }}",
  "mappedip": [{"range": "{{ mappedip }}-{{ mappedip }}"}],
  "arp-reply": "{{ arp_reply | default('enable') }}"
  {% if portforward == 'enable' %},
  "portforward": "enable",
  "protocol": "{{ protocol | default('tcp') }}",
  "extport": "{{ extport }}",
  "mappedport": "{{ mappedport }}"
  {% endif %}
}
"""

# Policy Template
POLICY_TEMPLATE = """
{
  "name": "{{ name }}",
  "srcintf": [{% for intf in srcintf %}{"name": "{{ intf }}"}{% if not loop.last %},{% endif %}{% endfor %}],
  "dstintf": [{% for intf in dstintf %}{"name": "{{ intf }}"}{% if not loop.last %},{% endif %}{% endfor %}],
  "srcaddr": [{% for addr in srcaddr %}{"name": "{{ addr }}"}{% if not loop.last %},{% endif %}{% endfor %}],
  "dstaddr": [{% for addr in dstaddr %}{"name": "{{ addr }}"}{% if not loop.last %},{% endif %}{% endfor %}],
  "action": "{{ action | default('accept') }}",
  "schedule": "{{ schedule | default('always') }}",
  "service": [{% for svc in service %}{"name": "{{ svc }}"}{% if not loop.last %},{% endif %}{% endfor %}],
  "logtraffic": "{{ logtraffic | default('all') }}",
  "nat": "{{ nat | default('disable') }}"
}
"""

# HTML Report Template
HTML_REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s ease;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 12px rgba(0,0,0,0.15);
        }
        .stat-card h3 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .stat-card p {
            color: #666;
            font-size: 1.1em;
        }
        .content {
            padding: 30px;
        }
        .section {
            margin-bottom: 30px;
        }
        .section h2 {
            color: #333;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th {
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-warning { background: #fff3cd; color: #856404; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            border-top: 1px solid #eee;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ {{ title }}</h1>
            <p>Generated on {{ timestamp }}</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <h3>{{ summary.total_logs }}</h3>
                <p>Total Logs</p>
            </div>
            <div class="stat-card">
                <h3>{{ summary.blocked_count }}</h3>
                <p>Blocked Traffic</p>
            </div>
            <div class="stat-card">
                <h3>{{ summary.allowed_count }}</h3>
                <p>Allowed Traffic</p>
            </div>
            <div class="stat-card">
                <h3>{{ summary.unique_sources }}</h3>
                <p>Unique Sources</p>
            </div>
        </div>

        <div class="content">
            {% if top_sources %}
            <div class="section">
                <h2>📊 Top Source IPs</h2>
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Source IP</th>
                            <th>Request Count</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for src in top_sources %}
                        <tr>
                            <td>{{ loop.index }}</td>
                            <td><strong>{{ src.ip }}</strong></td>
                            <td>{{ src.count }}</td>
                            <td>
                                {% if src.blocked %}
                                <span class="badge badge-danger">Blocked</span>
                                {% else %}
                                <span class="badge badge-success">Active</span>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}

            {% if blocked_traffic %}
            <div class="section">
                <h2>🚫 Blocked Traffic</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Service</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for traffic in blocked_traffic %}
                        <tr>
                            <td>{{ traffic.srcip }}</td>
                            <td>{{ traffic.dstip }}</td>
                            <td>{{ traffic.service }}</td>
                            <td><span class="badge badge-warning">{{ traffic.reason }}</span></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}

            {% if vips %}
            <div class="section">
                <h2>🌐 VIP Configuration</h2>
                <table>
                    <thead>
                        <tr>
                            <th>VIP Name</th>
                            <th>External IP</th>
                            <th>Mapped IP</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for vip in vips %}
                        <tr>
                            <td><strong>{{ vip.name }}</strong></td>
                            <td>{{ vip.extip }}</td>
                            <td>{{ vip.mappedip }}</td>
                            <td><span class="badge badge-success">Active</span></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
        </div>

        <div class="footer">
            <p>FortiGate Automation System | Generated by Jinja2 Template Engine</p>
        </div>
    </div>
</body>
</html>
"""

# ===================== Template Functions =====================

def generate_vip_config(name: str, extip: str, mappedip: str, **kwargs) -> dict:
    """Generate VIP configuration from template"""
    template = Template(VIP_TEMPLATE)
    config_str = template.render(
        name=name,
        extip=extip,
        mappedip=mappedip,
        **kwargs
    )
    return json.loads(config_str)

def generate_policy_config(name: str, srcintf: List[str], dstintf: List[str], 
                          srcaddr: List[str], dstaddr: List[str], 
                          service: List[str], **kwargs) -> dict:
    """Generate Policy configuration from template"""
    template = Template(POLICY_TEMPLATE)
    config_str = template.render(
        name=name,
        srcintf=srcintf,
        dstintf=dstintf,
        srcaddr=srcaddr,
        dstaddr=dstaddr,
        service=service,
        **kwargs
    )
    return json.loads(config_str)

def generate_html_report(data: Dict) -> str:
    """Generate beautiful HTML report"""
    template = Template(HTML_REPORT_TEMPLATE)
    return template.render(**data)

# ===================== Bulk Configuration =====================

def bulk_vip_creation_from_yaml():
    """Create multiple VIPs from YAML template"""
    
    # Example YAML structure (you'd load from file)
    vip_definitions = [
        {
            "name": "VIP_WEB_SERVER_1",
            "extip": "10.8.10.10",
            "mappedip": "192.168.1.10",
            "extintf": "port2"
        },
        {
            "name": "VIP_WEB_SERVER_2",
            "extip": "10.8.10.11",
            "mappedip": "192.168.1.11",
            "extintf": "port2",
            "portforward": "enable",
            "extport": "8080",
            "mappedport": "80",
            "protocol": "tcp"
        },
        {
            "name": "VIP_SSH_SERVER",
            "extip": "10.8.10.12",
            "mappedip": "192.168.1.12",
            "extintf": "port2",
            "portforward": "enable",
            "extport": "2222",
            "mappedport": "22",
            "protocol": "tcp"
        }
    ]
    
    configs = []
    for vip_def in vip_definitions:
        config = generate_vip_config(**vip_def)
        configs.append(config)
    
    return configs

# ===================== Example Usage =====================

def demo_jinja2_integration():
    """Demonstrate Jinja2 integration"""
    
    print("🎨 FortiGate Jinja2 Integration Demo\n")
    
    # 1. Generate VIP Config
    print("1️⃣ Generating VIP Configuration...")
    vip_config = generate_vip_config(
        name="VIP_DEMO_SERVER",
        extip="10.8.10.100",
        mappedip="192.168.1.100",
        extintf="port2"
    )
    print(json.dumps(vip_config, indent=2))
    
    # 2. Generate Policy Config
    print("\n2️⃣ Generating Policy Configuration...")
    policy_config = generate_policy_config(
        name="POLICY_ALLOW_WEB",
        srcintf=["port2"],
        dstintf=["port4"],
        srcaddr=["all"],
        dstaddr=["VIP_DEMO_SERVER"],
        service=["HTTP", "HTTPS"],
        action="accept",
        nat="disable"
    )
    print(json.dumps(policy_config, indent=2))
    
    # 3. Bulk VIP Creation
    print("\n3️⃣ Bulk VIP Creation...")
    bulk_vips = bulk_vip_creation_from_yaml()
    print(f"Generated {len(bulk_vips)} VIP configurations")
    
    # 4. Generate HTML Report
    print("\n4️⃣ Generating HTML Report...")
    report_data = {
        "title": "FortiGate Traffic Analysis",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_logs": 2450,
            "blocked_count": 385,
            "allowed_count": 2065,
            "unique_sources": 47
        },
        "top_sources": [
            {"ip": "192.168.1.10", "count": 850, "blocked": False},
            {"ip": "192.168.1.15", "count": 620, "blocked": False},
            {"ip": "10.0.0.50", "count": 150, "blocked": True},
        ],
        "blocked_traffic": [
            {"srcip": "10.0.0.50", "dstip": "192.168.1.10", 
             "service": "SSH", "reason": "Policy Deny"},
            {"srcip": "10.0.0.51", "dstip": "192.168.1.11", 
             "service": "RDP", "reason": "Blocked by IPS"},
        ],
        "vips": [
            {"name": "VIP_WEB_SERVER_1", "extip": "10.8.10.10", 
             "mappedip": "192.168.1.10"},
            {"name": "VIP_WEB_SERVER_2", "extip": "10.8.10.11", 
             "mappedip": "192.168.1.11"},
        ]
    }
    
    html_report = generate_html_report(report_data)
    
    # Save report
    report_file = Path("result_json/report.html")
    report_file.write_text(html_report)
    print(f"✅ HTML Report saved to: {report_file}")
    
    print("\n✨ Demo completed!")

if __name__ == "__main__":
    demo_jinja2_integration()