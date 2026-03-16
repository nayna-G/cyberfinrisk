import json
import logging
import networkx as nx
import google.generativeai as genai
from typing import List
from models.risk_result import AttackChain, RiskResult
from models.company import CompanyContext

logger = logging.getLogger(__name__)

def build_attack_graph(results: List[RiskResult]) -> nx.DiGraph:
    """
    Builds a directed graph of vulnerabilities where an edge A -> B indicates
    that exploiting A can facilitate exploiting B (Prerequisites).
    """
    G = nx.DiGraph()
    
    # 1. Add Nodes
    for r in results:
        G.add_node(r.vulnerability_id, result=r)

    # 2. Add Edges based on preconditions/postconditions
    for node_a in G.nodes:
        r_a: RiskResult = G.nodes[node_a]['result']
        if not r_a.gemini_analysis or not r_a.gemini_analysis.is_exploitable:
            continue

        auth_a = r_a.gemini_analysis.authentication_required
        bug_a  = r_a.bug_type.upper()

        for node_b in G.nodes:
            if node_a == node_b:
                continue
            
            r_b: RiskResult = G.nodes[node_b]['result']
            if not r_b.gemini_analysis or not r_b.gemini_analysis.is_exploitable:
                continue

            auth_b = r_b.gemini_analysis.authentication_required
            
            # Rule 1: Auth Bypass / Credentials Elevation
            # e.g. A is public auth bypass, B requires authenticated_user
            auth_elevators = ["AUTH_BYPASS", "HARDCODED_CREDENTIALS", "ACCESS_CONTROL_ISSUE"]
            
            if bug_a in auth_elevators and auth_a == "public_unauthenticated":
                 if auth_b in ["authenticated_user", "admin_only"]:
                      G.add_edge(node_a, node_b)
                      continue

            # Rule 2: Session Hijacking Vectors (XSS)
            if bug_a == "XSS" and auth_b in ["authenticated_user"]:
                 G.add_edge(node_a, node_b)
                 continue

            # Rule 3: Information Leakage (Path Traversal) providing secrets
            if bug_a in ["PATH_TRAVERSAL", "INFORMATION_DISCLOSURE"] and auth_b in ["authenticated_user", "admin_only"]:
                 G.add_edge(node_a, node_b)
                 continue
                 
            # Rule 4: Shared Namespace/File (Simpler targeting)
            if r_a.file == r_b.file and auth_a == "public_unauthenticated" and auth_b != "public_unauthenticated":
                 G.add_edge(node_a, node_b)
                 continue

    logger.info(f"Attack Graph built with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
    return G

def find_topological_chains(results: List[RiskResult], company: CompanyContext) -> List[AttackChain]:
    """
    Finds paths of length >= 2 in the attack graph and passes them to Gemini
    to generate narrative AttackChain models.
    """
    if len(results) < 2:
        return []

    G = build_attack_graph(results)
    candidate_chains = []

    # Find simple paths using networkx
    # Because graphs are typically tiny and sparse, simple paths calculation is safe
    for node in G.nodes:
         # Find absolute paths of at least length 2 starting from this node
         # Using BFS or descendants checks
         for descendant in nx.descendants(G, node):
              for path in nx.all_simple_paths(G, source=node, target=descendant, cutoff=4):
                   if len(path) >= 2:
                        candidate_chains.append(path)

    if not candidate_chains:
        return []

    # De-duplicate or limit to top candidates to save bills/tokens if heavy
    candidate_chains = candidate_chains[:5] # Limit to top 5 dense chains scaling

    model = genai.GenerativeModel("gemini-2.5-flash")
    final_attack_chains = []

    # Ask Gemini to describe only the topological candidates
    for path_node_ids in candidate_chains:
         involved_results = [G.nodes[nid]['result'] for nid in path_node_ids]
         
         path_summary = [
             {
                 "id": r.vulnerability_id,
                 "type": r.bug_type,
                 "file": r.file,
                 "auth": r.gemini_analysis.authentication_required if r.gemini_analysis else "unknown"
             } for r in involved_results
         ]

         prompt = f"""You are a penetration tester.
Describe an attack chain connecting these vulnerabilities in the order listed:
{json.dumps(path_summary, indent=2)}

Respond ONLY with raw JSON containing:
{{
  "chain_id": "CHAIN_XXX",
  "chain_description": "2 sentences describing the narrative path non-technically",
  "combined_severity": "critical", "high", "medium",
  "chain_endpoint": "rce", "full_data_exfiltration", "privilege_escalation",
  "steps": [
    "Step 1: Attacker does X using VULN1",
    "Step 2: Attacker uses elevation to trigger VULN2"
  ]
}}
"""
         try:
             response = model.generate_content(prompt)
             text = response.text.strip()
             if text.startswith("```"):
                  text = "\n".join(text.split("\n")[1:-1])
             data = json.loads(text)

             AMPLIFIERS = {"rce": 2.2, "full_data_exfiltration": 2.0, "privilege_escalation": 1.7, "partial_data_access": 1.4}
             amp = AMPLIFIERS.get(data.get("chain_endpoint"), 1.5)
             combined_loss = sum(r.expected_loss for r in involved_results) * amp

             final_attack_chains.append(AttackChain(
                 chain_id=data.get("chain_id", "CHAIN_REPLACEMENT"),
                 vulnerability_ids=path_node_ids,
                 chain_description=data.get("chain_description", ""),
                 combined_severity=data.get("combined_severity", "high"),
                 combined_expected_loss=round(combined_loss, 2),
                 chain_steps=data.get("steps", [])
             ))
         except Exception as e:
             logger.warning(f"Failed to generate story for candidate path {path_node_ids}: {e}")

    return final_attack_chains
