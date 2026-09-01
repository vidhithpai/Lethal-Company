"""
CDG-based guard detection — borrowed from GitNexus PDG pattern.
Detects guards by their structural position as CDG predicates,
not by name pattern matching alone.
"""

import ast
from dataclasses import dataclass
from typing import Optional


@dataclass
class GuardEvent:
    """A detected guard with its structural basis."""
    method_name: str
    line: int
    guard_basis: str        # 'cdg_predicate' | 'annotation' | 'name_heuristic'
    controls_sink: bool     # True if this guard's CDG edge reaches a sink block
    attenuation_boost: float  # extra attenuation given structural basis
    annotation: Optional[str] = None


SINK_CALLS = {
    'execute','executequery','exec','eval','write','send',
    'serialize','invoke','forname','getwriter','subprocess'
}

GUARD_CALLS = {
    'validate','sanitize','check','escape','filter','clean',
    'encode','verify','authorize','authenticate','ispermitted'
}


def _contains_sink(stmts: list) -> bool:
    """Check if any statement in a block reaches a sink call."""
    for stmt in stmts:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                func = node.func
                name = ''
                if isinstance(func, ast.Attribute):
                    name = func.attr.lower()
                elif isinstance(func, ast.Name):
                    name = func.id.lower()
                if any(s in name for s in SINK_CALLS):
                    return True
    return False


def _extract_call_name(node) -> Optional[str]:
    """Extract the function name from a Call node."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        elif isinstance(node.func, ast.Name):
            return node.func.id
    return None


class CDGGuardDetector(ast.NodeVisitor):
    """
    Detects guards by their role as CDG predicates.
    
    CDG predicate patterns:
    1. if not guard_call(x): raise/return  → early-exit guard
    2. if guard_call(x): <sink block>       → gate guard
    3. assert guard_call(x)                 → assertion guard
    4. @annotation on method containing sink → decorator guard
    """
    
    def __init__(self):
        self.guards: list[GuardEvent] = []
    
    def visit_If(self, node):
        """Detect if-based CDG guard predicates."""
        # Pattern 1: if not validate(x): raise/return (early-exit)
        test = node.test
        guard_call = None
        
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            guard_call = _extract_call_name(test.operand)
            # Check if body is a raise/return (early-exit pattern)
            is_early_exit = any(
                isinstance(s, (ast.Raise, ast.Return)) for s in node.body
            )
            if guard_call and is_early_exit:
                if any(g in guard_call.lower() for g in GUARD_CALLS):
                    self.guards.append(GuardEvent(
                        method_name=guard_call,
                        line=node.lineno,
                        guard_basis='cdg_predicate',
                        controls_sink=_contains_sink(node.orelse or []),
                        attenuation_boost=0.15,  # CDG-structural gives +15% attenuation
                    ))
        
        # Pattern 2: if validate(x): <block with sink>
        elif isinstance(test, ast.Call):
            guard_call = _extract_call_name(test)
            if guard_call and any(g in guard_call.lower() for g in GUARD_CALLS):
                has_sink_in_body = _contains_sink(node.body)
                if has_sink_in_body:
                    self.guards.append(GuardEvent(
                        method_name=guard_call,
                        line=node.lineno,
                        guard_basis='cdg_predicate',
                        controls_sink=True,
                        attenuation_boost=0.20,
                    ))
        
        self.generic_visit(node)
    
    def visit_Assert(self, node):
        """Detect assert guard(x) patterns."""
        guard_call = _extract_call_name(node.test)
        if guard_call and any(g in guard_call.lower() for g in GUARD_CALLS):
            self.guards.append(GuardEvent(
                method_name=guard_call,
                line=node.lineno,
                guard_basis='cdg_predicate',
                controls_sink=True,   # assert is a hard gate
                attenuation_boost=0.10,
            ))
        self.generic_visit(node)


def detect_cdg_guards(source_code: str) -> list[GuardEvent]:
    """Run CDG guard detection on Python source. Returns all detected guards."""
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return []
    detector = CDGGuardDetector()
    detector.visit(tree)
    return detector.guards


def cdg_attenuation_boost(node_data: dict, source_code: str,
                           line: int) -> float:
    """
    Returns extra attenuation to add for a guard node if it is
    structurally a CDG predicate (not just name-matched).
    Called from guard_attenuation.py to upgrade name-heuristic guards.
    """
    guards = detect_cdg_guards(source_code)
    for g in guards:
        if abs(g.line - line) <= 2:   # within 2 lines of the known guard
            return g.attenuation_boost
    return 0.0   # no CDG evidence — keep base attenuation as-is
