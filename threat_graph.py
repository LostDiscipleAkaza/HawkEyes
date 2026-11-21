"""
Stage 9: Threat Graph
Constructs a unified cybersecurity entity graph connecting:
  - Input URL -> Redirect Hops -> Final URL
  - Domain / Subdomains
  - Resolved IP Addresses
  - DNS Infrastructure (NameServers, MX Records)
  - TLS Certificates & CA Issuers
  - Targeted Brands (Typosquatting / Homoglyphs / Impersonation)
  - Threat Intelligence Hits (URLhaus, Safe Browsing, Phishing Kit Signatures)

Supports rendering to:
  - Terminal ASCII/Unicode relationship tree
  - Standalone interactive HTML graph (drag & zoom force-directed SOC UI)
  - Graphviz DOT format
  - JSON graph data
"""
import json
import os
from urllib.parse import urlparse


NODE_COLORS = {
    "url": "#60a5fa",            # blue
    "domain": "#a78bfa",         # purple
    "ip": "#34d399",             # green
    "dns": "#38bdf8",            # light blue
    "tls": "#fbbf24",            # yellow/amber
    "brand": "#f472b6",          # pink
    "threat": "#ef4444",         # red
    "redirect": "#fb923c",       # orange
}


def build_threat_graph(scan_result: dict) -> dict:
    """
    Transforms the multi-stage scan result into an entity graph of nodes and edges.
    """
    nodes = []
    edges = []
    node_ids = set()

    def add_node(nid: str, label: str, ntype: str, category: str = "asset", risk: str = "info", details: dict = None):
        if nid not in node_ids:
            node_ids.add(nid)
            nodes.append({
                "id": nid,
                "label": label,
                "type": ntype,
                "category": category,
                "risk": risk,
                "color": NODE_COLORS.get(ntype, "#94a3b8"),
                "details": details or {},
            })

    def add_edge(src: str, dst: str, relation: str, risk: str = "info"):
        if src in node_ids and dst in node_ids:
            edges.append({
                "source": src,
                "target": dst,
                "relation": relation,
                "risk": risk,
            })

    parsed = scan_result.get("parsed", {})
    input_url = scan_result.get("input_url") or parsed.get("original_url") or "unknown"
    final_url = parsed.get("original_url") or input_url
    hostname = parsed.get("hostname") or ""
    reg_domain = parsed.get("registered_domain") or hostname

    # 1. Input URL Node
    add_node("url:input", input_url, "url", category="entrypoint", details={"url": input_url})

    # 2. Redirect chain
    redir = scan_result.get("redirect", {})
    chain = redir.get("redirect_chain", [])
    analysis = redir.get("analysis", {})
    hop_records = analysis.get("hops") or []

    prev_node = "url:input"
    if redir.get("was_redirected") and len(chain) > 1:
        for i, hop_url in enumerate(chain[1:], start=1):
            hop_id = f"url:hop_{i}"
            if hop_url == final_url and i == len(chain) - 1:
                hop_id = "url:final"
            status = ""
            for h in hop_records:
                if h.get("url") == hop_url:
                    status = f" ({h.get('type')})"
                    break
            add_node(hop_id, hop_url + status, "redirect" if hop_id != "url:final" else "url", category="destination" if hop_id == "url:final" else "hop", details={"url": hop_url})
            add_edge(prev_node, hop_id, "REDIRECTS_TO", risk="high" if analysis.get("protocol_downgrade") else "info")
            prev_node = hop_id
    else:
        if "url:final" not in node_ids and final_url != input_url:
            add_node("url:final", final_url, "url", category="destination", details={"url": final_url})
            add_edge("url:input", "url:final", "LANDS_ON")
            prev_node = "url:final"

    # 3. Domain & Subdomain Nodes
    if reg_domain:
        add_node(f"domain:{reg_domain}", reg_domain, "domain", category="apex_domain", details={"domain": reg_domain})
        add_edge(prev_node, f"domain:{reg_domain}", "HOSTED_UNDER")

        if hostname and hostname != reg_domain:
            add_node(f"subdomain:{hostname}", hostname, "domain", category="subdomain", details={"host": hostname})
            add_edge(f"domain:{reg_domain}", f"subdomain:{hostname}", "DELEGATES_SUBDOMAIN")
            add_edge(prev_node, f"subdomain:{hostname}", "RESOLVES_VIA")

    target_host_node = f"subdomain:{hostname}" if (hostname and hostname != reg_domain) else f"domain:{reg_domain}"

    # 4. DNS records (IP addresses, Nameservers, MX)
    dns_res = scan_result.get("dns", {})
    ips = (dns_res.get("A") or []) + (dns_res.get("AAAA") or [])
    for ip in ips[:4]:
        ip_id = f"ip:{ip}"
        add_node(ip_id, ip, "ip", category="network", details={"ip": ip})
        add_edge(target_host_node, ip_id, "RESOLVES_TO")

    ns_list = dns_res.get("NS") or []
    for ns in ns_list[:2]:
        clean_ns = ns.rstrip(".")
        ns_id = f"ns:{clean_ns}"
        add_node(ns_id, clean_ns, "dns", category="nameserver", details={"nameserver": clean_ns})
        add_edge(f"domain:{reg_domain}", ns_id, "MANAGED_BY_NS")

    mx_list = dns_res.get("MX") or []
    for mx in mx_list[:2]:
        clean_mx = mx.split()[-1].rstrip(".") if " " in mx else mx.rstrip(".")
        mx_id = f"mx:{clean_mx}"
        add_node(mx_id, clean_mx, "dns", category="mail_exchange", details={"mx": clean_mx})
        add_edge(f"domain:{reg_domain}", mx_id, "ROUTES_MAIL_VIA")

    # 5. TLS Certificate & Issuer
    tls_res = scan_result.get("tls", {})
    if tls_res.get("valid") or tls_res.get("issuer"):
        issuer = tls_res.get("issuer", {})
        issuer_str = issuer.get("organizationName") or issuer.get("commonName") or "Unknown CA"
        cert_id = "tls:cert"
        risk_level = "high" if tls_res.get("self_signed") or tls_res.get("expired") else "info"
        add_node(cert_id, f"TLS: {tls_res.get('not_after', 'Active')[:10]}", "tls", category="security_cert", risk=risk_level, details=tls_res)
        add_edge(target_host_node, cert_id, "SECURED_BY", risk=risk_level)

        ca_id = f"ca:{issuer_str}"
        add_node(ca_id, f"CA: {issuer_str}", "tls", category="certificate_authority", details={"issuer": issuer_str})
        add_edge(cert_id, ca_id, "ISSUED_BY")

    # 6. Targeted Brand (Phishing / Typosquatting / Homoglyph)
    phish = scan_result.get("phishing", {})
    typo = scan_result.get("typosquatting", {})
    homo = scan_result.get("homoglyph", {})

    brand = phish.get("targeted_brand") or typo.get("matched_brand") or homo.get("target_impersonated")
    if brand:
        brand_id = f"brand:{brand}"
        add_node(brand_id, f"Target Brand: {brand.upper()}", "brand", category="victim_brand", risk="high", details={"brand": brand})
        add_edge(target_host_node, brand_id, "IMPERSONATES", risk="high")

    # 7. Threat Intelligence Nodes (URLhaus, Safe Browsing, Phishing signatures)
    uh = scan_result.get("urlhaus", {})
    if uh.get("listed"):
        uh_id = "threat:urlhaus"
        threat_name = uh.get("threat") or "Malware Download"
        tags = ", ".join(uh.get("tags") or [])
        add_node(uh_id, f"URLhaus: {threat_name} ({tags})" if tags else f"URLhaus: {threat_name}", "threat", category="threat_intel", risk="critical", details=uh)
        add_edge(prev_node, uh_id, "FLAGGED_MALICIOUS", risk="critical")

    sb = scan_result.get("safe_browsing", {})
    if sb.get("matched"):
        sb_id = "threat:safebrowsing"
        types = ", ".join(sb.get("threat_types") or [])
        add_node(sb_id, f"Safe Browsing: {types}", "threat", category="threat_intel", risk="critical", details=sb)
        add_edge(prev_node, sb_id, "BLACKLISTED", risk="critical")

    if phish.get("is_phishing") and phish.get("phishing_kit_detected"):
        kit_id = "threat:phish_kit"
        add_node(kit_id, "Phishing Kit Deployed", "threat", category="malicious_payload", risk="high", details={"indicators": phish.get("indicators")})
        add_edge(prev_node, kit_id, "EXHIBITS", risk="high")

    for exfil in phish.get("exfiltration_endpoints", [])[:2]:
        parsed_exfil = urlparse(exfil)
        exfil_host = parsed_exfil.hostname or "Exfiltration Target"
        exfil_id = f"threat:exfil_{exfil_host}"
        add_node(exfil_id, f"Exfil Drop: {exfil_host}", "threat", category="exfiltration_drop", risk="critical", details={"endpoint": exfil})
        add_edge(prev_node, exfil_id, "STOLEN_DATA_SENT_TO", risk="critical")

    if homo.get("has_homoglyphs"):
        homo_id = "threat:homoglyph"
        desc = "Mixed Script" if homo.get("is_mixed_script") else "Confusable Glyphs"
        add_node(homo_id, f"Homoglyph: {desc}", "threat", category="obfuscation", risk="high", details={"confusables": homo.get("confusable_chars")})
        add_edge(target_host_node, homo_id, "USES_HOMOGLYPH", risk="high")

    if typo.get("is_typosquat"):
        typo_id = "threat:typosquat"
        add_node(typo_id, f"Typosquat: {typo.get('technique')}", "threat", category="deception", risk="high", details=typo)
        add_edge(target_host_node, typo_id, "TYPOSQUATS", risk="high")

    return {
        "nodes": nodes,
        "edges": edges,
        "entity_count": len(nodes),
        "relationship_count": len(edges),
    }


def format_threat_graph_ascii(graph: dict, use_color: bool = True) -> str:
    """
    Renders the threat graph as an aligned ASCII/Unicode tree structure.
    """
    RESET = "\033[0m" if use_color else ""
    BOLD = "\033[1m" if use_color else ""
    GRAY = "\033[90m" if use_color else ""
    RED = "\033[91m" if use_color else ""
    ORANGE = "\033[38;5;208m" if use_color else ""
    YELLOW = "\033[93m" if use_color else ""
    GREEN = "\033[92m" if use_color else ""
    CYAN = "\033[96m" if use_color else ""
    PURPLE = "\033[95m" if use_color else ""

    nodes_by_id = {n["id"]: n for n in graph.get("nodes", [])}
    edges = graph.get("edges", [])

    lines = []
    lines.append(f"{BOLD}{CYAN}THREAT RELATIONSHIP GRAPH{RESET}")
    lines.append(GRAY + "─" * 70 + RESET)

    # Group connections by source node
    adj = {}
    for edge in edges:
        src = edge["source"]
        dst = edge["target"]
        rel = edge["relation"]
        risk = edge.get("risk", "info")
        adj.setdefault(src, []).append((dst, rel, risk))

    visited = set()

    def print_node_branch(nid: str, prefix: str = "", is_last: bool = True):
        visited.add(nid)
        node = nodes_by_id.get(nid, {"label": nid, "type": "unknown", "risk": "info"})
        ntype = node.get("type")
        risk = node.get("risk", "info")

        # Color based on risk or type
        if risk == "critical":
            color = RED + BOLD
        elif risk == "high":
            color = ORANGE
        elif ntype == "brand":
            color = PURPLE
        elif ntype == "domain":
            color = CYAN
        elif ntype == "ip":
            color = GREEN
        elif ntype == "tls":
            color = YELLOW
        else:
            color = BOLD

        type_badge = f"{GRAY}[{ntype.upper()}]{RESET} "
        marker = "└─ " if is_last else "├─ "
        line_prefix = prefix + GRAY + marker + RESET if prefix else ""
        lines.append(f"{line_prefix}{type_badge}{color}{node['label']}{RESET}")

        children = adj.get(nid, [])
        new_prefix = prefix + (GRAY + "   " + RESET if is_last else GRAY + "│  " + RESET) if prefix else "  "

        for idx, (child_id, rel, edge_risk) in enumerate(children):
            c_is_last = idx == len(children) - 1
            rel_color = RED if edge_risk in ("high", "critical") else GRAY
            rel_label = f"{new_prefix}{rel_color}──({rel})──>{RESET}"
            lines.append(rel_label)
            if child_id not in visited:
                print_node_branch(child_id, prefix=new_prefix, is_last=c_is_last)
            else:
                cnode = nodes_by_id.get(child_id, {"label": child_id, "type": "ref"})
                c_marker = "└─ " if c_is_last else "├─ "
                lines.append(f"{new_prefix}{GRAY}{c_marker}[REF] {cnode['label']}{RESET}")

    # Start from url:input
    if "url:input" in nodes_by_id:
        print_node_branch("url:input", prefix="", is_last=True)

    # Any unvisited root nodes
    for nid in nodes_by_id:
        if nid not in visited and not any(e["target"] == nid for e in edges):
            print_node_branch(nid, prefix="", is_last=True)

    lines.append(GRAY + "─" * 70 + RESET)
    lines.append(f"  {GRAY}Entities: {graph.get('entity_count', 0)} | Relationships: {graph.get('relationship_count', 0)}{RESET}")
    return "\n".join(lines)


def export_threat_graph_dot(graph: dict) -> str:
    """Exports graph in Graphviz DOT format."""
    lines = ["digraph ThreatGraph {", '  rankdir="LR";', '  bgcolor="#0f172a";', '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontcolor="#ffffff"];', '  edge [fontname="Helvetica", fontsize=9, fontcolor="#94a3b8", color="#475569"];', ""]

    for n in graph.get("nodes", []):
        fill = n.get("color", "#334155")
        label = n.get("label", n["id"]).replace('"', '\\"')
        lines.append(f'  "{n["id"]}" [label="{label}", fillcolor="{fill}"];')

    for e in graph.get("edges", []):
        color = "#ef4444" if e.get("risk") in ("high", "critical") else "#475569"
        lines.append(f'  "{e["source"]}" -> "{e["target"]}" [label="{e.get("relation", "")}", color="{color}"];')

    lines.append("}")
    return "\n".join(lines)


def export_threat_graph_html(graph: dict, output_file: str, title: str = "Threat Relationship Graph") -> str:
    """
    Generates a standalone, beautiful interactive HTML graph with force-directed
    physics, zoom, pan, node dragging, and inspection panel.
    """
    graph_json = json.dumps(graph, default=str)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{title}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: #0b0f19;
      color: #e2e8f0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      height: 100vh;
    }}
    header {{
      background: #111827;
      border-bottom: 1px solid #1f2937;
      padding: 12px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      z-index: 10;
    }}
    header h1 {{
      font-size: 16px;
      font-weight: 700;
      letter-spacing: 0.5px;
      color: #38bdf8;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .badge {{
      background: #1e293b;
      color: #94a3b8;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
    }}
    #container {{
      display: flex;
      flex: 1;
      position: relative;
      overflow: hidden;
    }}
    canvas {{
      flex: 1;
      width: 100%;
      height: 100%;
      cursor: grab;
    }}
    canvas:active {{ cursor: grabbing; }}
    #sidebar {{
      width: 340px;
      background: #111827;
      border-left: 1px solid #1f2937;
      padding: 16px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 12px;
      z-index: 10;
    }}
    .panel-title {{
      font-size: 13px;
      font-weight: 600;
      text-transform: uppercase;
      color: #64748b;
      letter-spacing: 0.5px;
    }}
    .detail-card {{
      background: #1e293b;
      border-radius: 6px;
      padding: 12px;
      border: 1px solid #334155;
    }}
    .detail-row {{
      display: flex;
      justify-content: space-between;
      margin-bottom: 6px;
      font-size: 12px;
    }}
    .detail-label {{ color: #94a3b8; }}
    .detail-value {{ font-weight: 600; color: #f8fafc; word-break: break-all; }}
    .legend {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }}
    .legend-item {{
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      color: #94a3b8;
    }}
    .dot {{
      width: 10px;
      height: 10px;
      border-radius: 50%;
    }}
  </style>
</head>
<body>
  <header>
    <h1>&#x1F6E1;&#xFE0F; URL Scanner - Threat Relationship Graph</h1>
    <div>
      <span class="badge" id="stat-nodes">0 Nodes</span>
      <span class="badge" id="stat-edges">0 Edges</span>
    </div>
  </header>
  <div id="container">
    <canvas id="viewport"></canvas>
    <div id="sidebar">
      <div class="panel-title">Node Inspector</div>
      <div id="node-info" class="detail-card">
        <div style="color: #94a3b8; font-size: 12px;">Click any node to inspect entity relationships & attributes.</div>
      </div>
      <div class="panel-title" style="margin-top: 10px;">Graph Legend</div>
      <div class="legend">
        <div class="legend-item"><div class="dot" style="background:#60a5fa"></div>URL</div>
        <div class="legend-item"><div class="dot" style="background:#fb923c"></div>Redirect</div>
        <div class="legend-item"><div class="dot" style="background:#a78bfa"></div>Domain</div>
        <div class="legend-item"><div class="dot" style="background:#34d399"></div>IP Address</div>
        <div class="legend-item"><div class="dot" style="background:#38bdf8"></div>DNS / MX</div>
        <div class="legend-item"><div class="dot" style="background:#fbbf24"></div>TLS / CA</div>
        <div class="legend-item"><div class="dot" style="background:#f472b6"></div>Target Brand</div>
        <div class="legend-item"><div class="dot" style="background:#ef4444"></div>Threat / Payload</div>
      </div>
    </div>
  </div>

  <script>
    const data = {graph_json};
    document.getElementById("stat-nodes").textContent = data.nodes.length + " Nodes";
    document.getElementById("stat-edges").textContent = data.edges.length + " Edges";

    const canvas = document.getElementById("viewport");
    const ctx = canvas.getContext("2d");

    function resize() {{
      canvas.width = canvas.parentElement.clientWidth - 340;
      canvas.height = canvas.parentElement.clientHeight;
    }}
    window.addEventListener("resize", resize);
    resize();

    // Node layout positions
    const nodeMap = {{}};
    const width = canvas.width;
    const height = canvas.height;

    data.nodes.forEach((n, idx) => {{
      const angle = (idx / data.nodes.length) * Math.PI * 2;
      const radius = Math.min(width, height) * 0.32;
      nodeMap[n.id] = {{
        ...n,
        x: width / 2 + Math.cos(angle) * radius + (Math.random() - 0.5) * 50,
        y: height / 2 + Math.sin(angle) * radius + (Math.random() - 0.5) * 50,
        vx: 0,
        vy: 0,
        radius: n.risk === "critical" ? 18 : (n.risk === "high" ? 15 : 12)
      }};
    }});

    // Simple spring simulation
    function simulate() {{
      const nodes = Object.values(nodeMap);
      // Repulsion
      for (let i = 0; i < nodes.length; i++) {{
        for (let j = i + 1; j < nodes.length; j++) {{
          const dx = nodes[j].x - nodes[i].x;
          const dy = nodes[j].y - nodes[i].y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          if (dist < 200) {{
            const force = (200 - dist) / dist * 0.6;
            nodes[i].x -= dx * force * 0.05;
            nodes[i].y -= dy * force * 0.05;
            nodes[j].x += dx * force * 0.05;
            nodes[j].y += dy * force * 0.05;
          }}
        }}
      }}
      // Edges attraction
      data.edges.forEach(e => {{
        const s = nodeMap[e.source];
        const t = nodeMap[e.target];
        if (s && t) {{
          const dx = t.x - s.x;
          const dy = t.y - s.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const targetDist = 110;
          const force = (dist - targetDist) * 0.02;
          s.x += (dx / dist) * force;
          s.y += (dy / dist) * force;
          t.x -= (dx / dist) * force;
          t.y -= (dy / dist) * force;
        }}
      }});
      // Center gravity
      nodes.forEach(n => {{
        n.x += (width / 2 - n.x) * 0.005;
        n.y += (height / 2 - n.y) * 0.005;
      }});
    }}

    let selectedNode = null;
    let draggedNode = null;

    function draw() {{
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Draw edges
      data.edges.forEach(e => {{
        const s = nodeMap[e.source];
        const t = nodeMap[e.target];
        if (s && t) {{
          ctx.beginPath();
          ctx.moveTo(s.x, s.y);
          ctx.lineTo(t.x, t.y);
          ctx.strokeStyle = e.risk === "critical" ? "#ef4444" : (e.risk === "high" ? "#fb923c" : "#334155");
          ctx.lineWidth = e.risk === "critical" ? 2.5 : 1.5;
          ctx.stroke();

          // Edge label
          const mx = (s.x + t.x) / 2;
          const my = (s.y + t.y) / 2;
          ctx.fillStyle = "#64748b";
          ctx.font = "9px monospace";
          ctx.fillText(e.relation, mx + 4, my - 4);
        }}
      }});

      // Draw nodes
      Object.values(nodeMap).forEach(n => {{
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        ctx.fillStyle = n.color || "#60a5fa";
        ctx.fill();

        if (n === selectedNode) {{
          ctx.lineWidth = 3;
          ctx.strokeStyle = "#ffffff";
          ctx.stroke();
        }} else if (n.risk === "critical" || n.risk === "high") {{
          ctx.lineWidth = 2;
          ctx.strokeStyle = "#ef4444";
          ctx.stroke();
        }}

        // Label
        ctx.fillStyle = "#f1f5f9";
        ctx.font = "11px sans-serif";
        const shortLabel = n.label.length > 24 ? n.label.substring(0, 22) + "..." : n.label;
        ctx.fillText(shortLabel, n.x + n.radius + 6, n.y + 4);
      }});
    }}

    function loop() {{
      if (!draggedNode) simulate();
      draw();
      requestAnimationFrame(loop);
    }}
    loop();

    // Interaction handlers
    canvas.addEventListener("mousedown", (e) => {{
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      let found = null;
      for (const n of Object.values(nodeMap)) {{
        const dx = n.x - x;
        const dy = n.y - y;
        if (Math.sqrt(dx * dx + dy * dy) <= n.radius + 4) {{
          found = n;
          break;
        }}
      }}
      if (found) {{
        draggedNode = found;
        selectedNode = found;
        showNodeDetails(found);
      }}
    }});

    window.addEventListener("mousemove", (e) => {{
      if (draggedNode) {{
        const rect = canvas.getBoundingClientRect();
        draggedNode.x = e.clientX - rect.left;
        draggedNode.y = e.clientY - rect.top;
      }}
    }});

    window.addEventListener("mouseup", () => {{
      draggedNode = null;
    }});

    function showNodeDetails(node) {{
      const infoBox = document.getElementById("node-info");
      let html = `
        <div class="detail-row"><span class="detail-label">ID:</span><span class="detail-value">${{node.id}}</span></div>
        <div class="detail-row"><span class="detail-label">Type:</span><span class="detail-value" style="color:${{node.color}}">${{node.type.toUpperCase()}}</span></div>
        <div class="detail-row"><span class="detail-label">Risk:</span><span class="detail-value">${{node.risk.toUpperCase()}}</span></div>
        <div class="detail-row"><span class="detail-label">Label:</span><span class="detail-value">${{node.label}}</span></div>
      `;
      if (node.details && Object.keys(node.details).length > 0) {{
        html += '<hr style="border:0;border-top:1px solid #334155;margin:8px 0;">';
        for (const [k, v] of Object.entries(node.details)) {{
          if (typeof v === "object") continue;
          html += `<div class="detail-row"><span class="detail-label">${{k}}:</span><span class="detail-value">${{v}}</span></div>`;
        }}
      }}
      infoBox.innerHTML = html;
    }}
  </script>
</body>
</html>
"""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_file


if __name__ == "__main__":
    import sys

    # Quick test graph
    dummy_scan = {
        "input_url": "http://paypal.security-verify.xyz",
        "parsed": {"original_url": "http://paypal.security-verify.xyz", "hostname": "paypal.security-verify.xyz", "registered_domain": "security-verify.xyz"},
        "dns": {"A": ["198.51.100.24"], "NS": ["ns1.dnshost.com"]},
        "tls": {"valid": False, "issuer": {"organizationName": "ZeroSSL"}, "self_signed": True},
        "typosquatting": {"is_typosquat": True, "matched_brand": "paypal", "technique": "combosquatting"},
        "phishing": {"is_phishing": True, "targeted_brand": "paypal", "phishing_kit_detected": True},
    }
    g = build_threat_graph(dummy_scan)
    print(format_threat_graph_ascii(g))

