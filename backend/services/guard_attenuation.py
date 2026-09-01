"""
Guard Attenuation Model for TDRA.

A guard node attenuates taint flow. Instead of binary present/absent,
each guard has an attenuation score A ∈ [0,1]:
  A=1.0 means the guard fully blocks taint (e.g. parameterized query)
  A=0.5 means partial blocking (e.g. generic validate() call)
  A=0.1 means weak blocking (name-matched heuristic, no annotation)

Path residual risk R = product of (1 - A_i) for all guards on path.
R=0 means fully attenuated (no risk), R=1 means no guards (full risk).

This replaces 1 - guard_density with a product formulation that
correctly models that two weak guards compound their effect.
"""

from backend.services.cdg_guard_detector import cdg_attenuation_boost

# ── CWE-to-sink category mapping ─────────────────────────────────────────────
# Maps sink type keywords to their CWE category
SINK_CWE_MAP = {
    "execute":      ("SQL",     "CWE-89"),
    "executequery": ("SQL",     "CWE-89"),
    "executeupdate":("SQL",     "CWE-89"),
    "createquery":  ("SQL",     "CWE-89"),
    "nativequery":  ("SQL",     "CWE-89"),
    "exec":         ("Command", "CWE-78"),
    "runtime":      ("Command", "CWE-78"),
    "processbuilder":("Command","CWE-78"),
    "eval":         ("Code",    "CWE-95"),
    "write":        ("File",    "CWE-22"),
    "filewriter":   ("File",    "CWE-22"),
    "files.write":  ("File",    "CWE-22"),
    "serialize":    ("Serial",  "CWE-502"),
    "pickle":       ("Serial",  "CWE-502"),
    "invoke":       ("Reflect", "CWE-470"),
    "forname":      ("Reflect", "CWE-470"),
    "getwriter":    ("XSS",     "CWE-79"),
    "response":     ("XSS",     "CWE-79"),
}

# ── Guard attenuation table ───────────────────────────────────────────────────
# Format: {(guard_type, sink_category): attenuation_score}
# guard_type: annotation-based (high confidence) or name-based (low confidence)

ATTENUATION_TABLE = {
    # SQL-specific guards
    ("@Valid",         "SQL"):     0.90,
    ("@Validated",     "SQL"):     0.90,
    ("PreparedStatement","SQL"):   0.95,  # parameterized query = near-complete
    ("@NotNull",       "SQL"):     0.50,  # not-null ≠ SQL-safe
    ("sanitize_name",  "SQL"):     0.70,
    ("escape_name",    "SQL"):     0.80,

    # Command injection guards
    ("@Valid",         "Command"): 0.70,
    ("allowlist_name", "Command"): 0.85,
    ("validate_name",  "Command"): 0.65,

    # File path guards
    ("@Valid",         "File"):    0.60,
    ("canonicalize_name","File"):  0.90,
    ("realpath_name",  "File"):    0.90,

    # XSS guards
    ("escape_name",    "XSS"):     0.85,
    ("encode_name",    "XSS"):     0.85,
    ("@Valid",         "XSS"):     0.55,

    # Generic guards (sink-agnostic)
    ("@Valid",         "Generic"): 0.65,
    ("@Validated",     "Generic"): 0.65,
    ("@NotNull",       "Generic"): 0.35,
    ("@NotBlank",      "Generic"): 0.40,
    ("@Pattern",       "Generic"): 0.70,
    ("@Size",          "Generic"): 0.30,
    ("validate_name",  "Generic"): 0.55,
    ("sanitize_name",  "Generic"): 0.65,
    ("check_name",     "Generic"): 0.45,
    ("escape_name",    "Generic"): 0.60,
    ("filter_name",    "Generic"): 0.50,
    ("authorize_name", "Generic"): 0.75,
    ("authenticate_name","Generic"):0.80,
    ("ispermitted_name","Generic"):0.75,
    ("hasrole_name",   "Generic"): 0.70,
}

# Default attenuation for unrecognized guard nodes
DEFAULT_ANNOTATION_ATTENUATION = 0.65  # has annotation, unknown type
DEFAULT_NAME_ATTENUATION       = 0.35  # name-matched only, no annotation
MINIMUM_ATTENUATION            = 0.10  # floor: any guard provides some reduction


def get_sink_category(sink_label: str) -> str:
    """Classify a sink node into its CWE category."""
    label_lower = sink_label.lower().replace(" ", "").replace(".", "")
    for key, (category, _) in SINK_CWE_MAP.items():
        if key in label_lower:
            return category
    return "Generic"


def get_guard_attenuation(guard_node: dict, sink_category: str) -> float:
    """
    Compute the attenuation score for a single guard node against
    a specific sink category.
    
    guard_node: NetworkX node data dict, must have keys:
      - 'label': str (method name or annotation)
      - 'annotations': list[str] (Java annotations present, may be empty)
      - 'guard_basis': 'annotation' | 'name' | 'position'
    
    Returns float in [MINIMUM_ATTENUATION, 1.0]
    """
    annotations = guard_node.get("annotations", [])
    label = guard_node.get("label", "").lower()
    basis = guard_node.get("guard_basis", "name")

    A = None

    # Try annotation-based lookup first (higher confidence)
    for ann in annotations:
        key = (ann, sink_category)
        if key in ATTENUATION_TABLE:
            A = ATTENUATION_TABLE[key]
            break
        key_generic = (ann, "Generic")
        if key_generic in ATTENUATION_TABLE:
            # Use generic but downscale if sink-specific entry missing
            A = ATTENUATION_TABLE[key_generic] * 0.85
            break

    if A is None:
        # Try name-based lookup
        for pattern, category in [
            ("sanitize",     "sanitize_name"),
            ("escape",       "escape_name"),
            ("validate",     "validate_name"),
            ("check",        "check_name"),
            ("filter",       "filter_name"),
            ("authorize",    "authorize_name"),
            ("authenticate", "authenticate_name"),
            ("canonicalize", "canonicalize_name"),
            ("realpath",     "realpath_name"),
            ("allowlist",    "allowlist_name"),
            ("ispermitted",  "ispermitted_name"),
            ("hasrole",      "hasrole_name"),
        ]:
            if pattern in label:
                key = (category, sink_category)
                if key in ATTENUATION_TABLE:
                    A = ATTENUATION_TABLE[key]
                    break
                key_generic = (category, "Generic")
                if key_generic in ATTENUATION_TABLE:
                    A = ATTENUATION_TABLE[key_generic] * 0.80
                    break

    if A is None:
        # Fallback based on how the guard was detected
        if basis == "annotation":
            A = DEFAULT_ANNOTATION_ATTENUATION
        else:
            A = DEFAULT_NAME_ATTENUATION

    if source_code := guard_node.get("source_code"):
        line = guard_node.get("line", 0)
        boost = cdg_attenuation_boost(guard_node, source_code, line)
        A = min(1.0, A + boost)  # CDG evidence upgrades attenuation

    return A


def compute_path_residual_risk(
    path_nodes: list[str],
    G,  # nx.DiGraph
    sink_node_id: str
) -> dict:
    """
    Compute the residual taint risk for a path using the product formulation.
    
    For each guard g_i on the path with attenuation A_i:
      residual_risk = product of (1 - A_i) for all i
    
    residual_risk = 1.0 → no guards → full taint reaches sink
    residual_risk = 0.0 → fully attenuated → taint blocked
    
    Returns dict with:
      - residual_risk: float [0,1]
      - guard_attenuations: list of {node_id, label, attenuation, basis}
      - effective_guard_strength: 1 - residual_risk
      - path_length: int
      - sink_category: str
      - cwe: str
    """
    sink_data = G.nodes.get(sink_node_id, {})
    sink_label = sink_data.get("label", sink_node_id)
    sink_category = get_sink_category(sink_label)
    
    # Look up CWE
    sink_lower = sink_label.lower().replace(" ", "").replace(".", "")
    cwe = "CWE-Unknown"
    for key, (_, cwe_id) in SINK_CWE_MAP.items():
        if key in sink_lower:
            cwe = cwe_id
            break

    guard_attenuations = []
    residual = 1.0

    for node_id in path_nodes:
        node_data = G.nodes.get(node_id, {})
        if node_data.get("type") not in ("sanitizer", "guard"):
            continue
        
        A = get_guard_attenuation(node_data, sink_category)
        A = max(MINIMUM_ATTENUATION, min(1.0, A))
        residual *= (1.0 - A)
        
        guard_attenuations.append({
            "node_id": node_id,
            "label": node_data.get("label", node_id),
            "attenuation": round(A, 3),
            "basis": node_data.get("guard_basis", "name"),
            "annotations": node_data.get("annotations", []),
        })

    return {
        "residual_risk": round(residual, 4),
        "effective_guard_strength": round(1.0 - residual, 4),
        "guard_attenuations": guard_attenuations,
        "guard_count": len(guard_attenuations),
        "path_length": len(path_nodes),
        "sink_category": sink_category,
        "cwe": cwe,
    }


def compute_delta_attenuation(
    path: tuple,
    G_prev,
    G_curr,
    sink_node_id_prev: str | None,
    sink_node_id_curr: str | None,
) -> dict:
    """
    Compute the change in effective guard strength across versions
    for a shared path. Used in the RF formula.
    
    Returns:
      - attenuation_prev: float (effective guard strength in V_prev)
      - attenuation_curr: float (effective guard strength in V_curr)
      - delta_attenuation: float (positive = guard weakened, negative = guard added)
      - weakening_detected: bool
    """
    path_nodes = list(path)
    
    result_prev = compute_path_residual_risk(
        path_nodes, G_prev, sink_node_id_prev or path_nodes[-1]
    ) if G_prev and G_prev.nodes else {"effective_guard_strength": 0.0}
    
    result_curr = compute_path_residual_risk(
        path_nodes, G_curr, sink_node_id_curr or path_nodes[-1]
    ) if G_curr and G_curr.nodes else {"effective_guard_strength": 0.0}
    
    A_prev = result_prev["effective_guard_strength"]
    A_curr = result_curr["effective_guard_strength"]
    delta = A_prev - A_curr  # positive = weakening (less protection in curr)

    return {
        "attenuation_prev": round(A_prev, 4),
        "attenuation_curr": round(A_curr, 4),
        "delta_attenuation": round(delta, 4),
        "weakening_detected": delta > 0.05,  # threshold: >5% strength drop
        "prev_detail": result_prev,
        "curr_detail": result_curr,
    }
