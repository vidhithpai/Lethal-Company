"""
REACHING_DEF data dependence for taint propagation.
Borrowed from GitNexus PDG pattern — tracks def→use variable chains
so taint flows through assignments, not just direct calls.
"""

import ast
from dataclasses import dataclass, field
from typing import Set, Dict, Optional


@dataclass
class TaintState:
    """Tracks tainted variables at a program point."""
    tainted: Set[str] = field(default_factory=set)
    
    def copy(self) -> 'TaintState':
        return TaintState(tainted=self.tainted.copy())
    
    def merge(self, other: 'TaintState') -> 'TaintState':
        """Join at merge points — union of tainted sets."""
        return TaintState(tainted=self.tainted | other.tainted)
    
    def is_tainted(self, name: str) -> bool:
        return name in self.tainted
    
    def taint(self, name: str):
        self.tainted.add(name)
    
    def propagate_assignment(self, target: str, value_names: Set[str]):
        """If any name in value_names is tainted, taint target."""
        if any(self.is_tainted(n) for n in value_names):
            self.taint(target)


class ReachingDefAnalyzer(ast.NodeVisitor):
    """
    Performs reaching definition analysis for taint propagation.
    Models: x = tainted_source() → x is tainted
            y = x.upper()       → y is tainted (REACHING_DEF)
            z = y + "const"     → z is tainted
            sink(z)             → VULNERABILITY: tainted data at sink
    """
    
    def __init__(self, source_names: Set[str], sink_patterns: Set[str],
                 guard_names: Set[str]):
        self.state = TaintState(tainted=source_names.copy())
        self.sink_patterns = sink_patterns
        self.guard_names = guard_names
        self.taint_flows: list[dict] = []  # found taint flows
        self._guarded = False
    
    def _extract_names(self, node) -> Set[str]:
        """Extract all Name references from an AST node."""
        names = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                names.add(child.id)
            elif isinstance(child, ast.Attribute):
                names.add(child.attr)
        return names
    
    def _is_sink(self, node) -> Optional[str]:
        """Check if a Call node is a sink. Returns sink name or None."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                name = node.func.attr.lower()
            elif isinstance(node.func, ast.Name):
                name = node.func.id.lower()
            else:
                return None
            if any(s in name for s in self.sink_patterns):
                return name
        return None
    
    def _is_guard(self, node) -> bool:
        """Check if a Call node is a guard/sanitizer."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                name = node.func.attr.lower()
            elif isinstance(node.func, ast.Name):
                name = node.func.id.lower()
            else:
                return False
            return any(g in name for g in self.guard_names)
        return False
    
    def visit_Assign(self, node):
        """x = expr: propagate taint from expr to x."""
        # Check if RHS contains tainted names
        rhs_names = self._extract_names(node.value)
        
        # If RHS is a guard call, it sanitizes — do NOT propagate taint
        if isinstance(node.value, ast.Call) and self._is_guard(node.value):
            # Guard breaks the taint chain for assigned variable
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.state.tainted.discard(target.id)
        else:
            # Propagate taint through assignment (REACHING_DEF)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.state.propagate_assignment(target.id, rhs_names)
        
        self.generic_visit(node)
    
    def visit_AugAssign(self, node):
        """x += expr: propagate taint."""
        rhs_names = self._extract_names(node.value)
        if isinstance(node.target, ast.Name):
            self.state.propagate_assignment(node.target.id, rhs_names)
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Check if tainted data reaches a sink."""
        sink_name = self._is_sink(node)
        if sink_name:
            # Check if any argument is tainted
            for arg in node.args + [kw.value for kw in node.keywords]:
                arg_names = self._extract_names(arg)
                tainted_args = arg_names & self.state.tainted
                if tainted_args:
                    self.taint_flows.append({
                        "sink": sink_name,
                        "tainted_args": list(tainted_args),
                        "line": node.lineno,
                        "guarded": self._guarded,
                        "flow_type": "REACHING_DEF",
                    })
        self.generic_visit(node)
    
    def visit_If(self, node):
        """Handle if/else — check guard conditions."""
        # Check if the condition is a guard call (early return pattern)
        cond_names = self._extract_names(node.test)
        if any(self._is_guard(n) for n in ast.walk(node.test)
               if isinstance(n, ast.Call)):
            old_guarded = self._guarded
            self._guarded = True
            for stmt in node.body:
                self.visit(stmt)
            self._guarded = old_guarded
            for stmt in node.orelse:
                self.visit(stmt)
        else:
            self.generic_visit(node)


def analyze_taint_flows(source_code: str, 
                         entry_names: Set[str],
                         sink_patterns: Set[str] = None,
                         guard_names: Set[str] = None) -> list[dict]:
    """
    Run REACHING_DEF taint analysis on a Python source file.
    Returns list of taint flow dicts found.
    """
    if sink_patterns is None:
        sink_patterns = {'execute','exec','eval','write','send',
                         'open','pickle','invoke','subprocess'}
    if guard_names is None:
        guard_names = {'validate','sanitize','escape','check',
                       'filter','clean','encode','verify'}
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return []
    
    analyzer = ReachingDefAnalyzer(entry_names, sink_patterns, guard_names)
    analyzer.visit(tree)
    return analyzer.taint_flows
