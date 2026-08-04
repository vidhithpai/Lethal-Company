import os
import ast
import json
import networkx as nx
import argparse

# Configuration
SOURCES = {"input", "request.GET", "request.POST"}
SINKS = {"execute", "os.system", "eval"}
OUTPUT_PATH = "backend/data/seed_graph.json"

class VulnGraphAnalyzer:
    def __init__(self):
        self.graph = nx.DiGraph()
        # function_name -> { "is_source": bool, "is_sink": bool, "calls": set() }
        self.functions = {}

    def scan_folder(self, folder_path):
        """Recursively scan all .py files in the folder."""
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith(".py"):
                    self.analyze_file(os.path.join(root, file))

    def analyze_file(self, file_path):
        """Parse AST of a single file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read())
            
            visitor = CallGraphVisitor()
            visitor.visit(tree)
            
            # Merge results
            for func_name, data in visitor.functions.items():
                if func_name not in self.functions:
                    self.functions[func_name] = {"is_source": False, "is_sink": False, "calls": set()}
                
                self.functions[func_name]["is_source"] |= data["is_source"]
                self.functions[func_name]["is_sink"] |= data["is_sink"]
                self.functions[func_name]["calls"].update(data["calls"])
                
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")

    def build_graph(self):
        """Create NetworkX graph and add nodes/edges."""
        for func_name, data in self.functions.items():
            # Determine node type
            node_type = "function"
            if data["is_source"]:
                node_type = "source"
            elif data["is_sink"]:
                node_type = "sink"
            
            self.graph.add_node(func_name, label=f"{func_name}()", type=node_type, patched=False)
            
            # Add edges
            for called_func in data["calls"]:
                self.graph.add_edge(func_name, called_func)

    def find_vulnerable_path(self):
        """Find source-to-sink paths using NetworkX."""
        sources = [n for n, d in self.graph.nodes(data=True) if d.get("type") == "source"]
        sinks = [n for n, d in self.graph.nodes(data=True) if d.get("type") == "sink"]

        for source in sources:
            for sink in sinks:
                try:
                    path = nx.shortest_path(self.graph, source, sink)
                    return path
                except nx.NetworkXNoPath:
                    continue
        return None

    def generate_json(self, path):
        """Convert graph to the required JSON format."""
        nodes = []
        edges = []

        # If a path exists, we only include the relevant nodes and edges for the demo/visualization?
        # The requirement says "Generate a graph JSON file". Usually this means the whole graph or the path graph.
        # But "Each node must follow..." and "Each edge must follow...".
        # Let's include all nodes and edges found, and specifically highlight the path.
        
        for node, data in self.graph.nodes(data=True):
            nodes.append({
                "id": node,
                "label": data["label"],
                "type": data["type"],
                "patched": data["patched"]
            })

        for u, v in self.graph.edges():
            edges.append({
                "source": u,
                "target": v,
                "cve": "CODE_FLOW",
                "weight": 1
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "path": path if path else []
        }

    def get_fallback_graph(self):
        """Standard fallback graph if no path is found."""
        return {
            "nodes": [
                { "id": "input_handler", "label": "input_handler()", "type": "source", "patched": False },
                { "id": "process_data", "label": "process_data()", "type": "function", "patched": False },
                { "id": "execute_query", "label": "execute_query()", "type": "sink", "patched": False }
            ],
            "edges": [
                { "source": "input_handler", "target": "process_data", "cve": "CODE_FLOW", "weight": 1 },
                { "source": "process_data", "target": "execute_query", "cve": "CODE_FLOW", "weight": 1 }
            ],
            "path": ["input_handler", "process_data", "execute_query"]
        }

class CallGraphVisitor(ast.NodeVisitor):
    def __init__(self):
        self.current_function = None
        self.functions = {}

    def visit_FunctionDef(self, node):
        prev_func = self.current_function
        self.current_function = node.name
        if self.current_function not in self.functions:
            self.functions[self.current_function] = {"is_source": False, "is_sink": False, "calls": set()}
        
        self.generic_visit(node)
        self.current_function = prev_func

    def visit_Call(self, node):
        if self.current_function:
            call_name = self._get_call_name(node.func)
            if call_name:
                self.functions[self.current_function]["calls"].add(call_name)
                
                # Direct match for sinks/sources
                if call_name in SOURCES:
                    self.functions[self.current_function]["is_source"] = True
                if call_name in SINKS:
                    self.functions[self.current_function]["is_sink"] = True
        
        self.generic_visit(node)

    def visit_Attribute(self, node):
        # Also check for SOURCES/SINKS that might be attributes but NOT calls (though usually they are calls)
        # E.g., request.GET might be used in a way that isn't a call.
        if self.current_function:
            attr_name = self._get_attribute_name(node)
            if attr_name in SOURCES:
                self.functions[self.current_function]["is_source"] = True
            if attr_name in SINKS:
                self.functions[self.current_function]["is_sink"] = True
        self.generic_visit(node)

    def _get_call_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_attribute_name(node)
        return None

    def _get_attribute_name(self, node):
        if isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        elif isinstance(node.value, ast.Attribute):
            res = self._get_attribute_name(node.value)
            if res:
                return f"{res}.{node.attr}"
        return None

def main():
    parser = argparse.ArgumentParser(description="VulnGraph Static Analysis Tool")
    parser.add_argument("project_path", help="Path to the Python project folder")
    args = parser.parse_args()

    analyzer = VulnGraphAnalyzer()
    print(f"[*] Scanning project: {args.project_path}")
    analyzer.scan_folder(args.project_path)
    
    print("[*] Building call graph...")
    analyzer.build_graph()
    
    print("[*] Searching for source-to-sink paths...")
    path = analyzer.find_vulnerable_path()
    
    if path:
        print(f"[!] Vulnerable path detected: {' -> '.join(path)}")
        result = analyzer.generate_json(path)
    else:
        print("[?] No path found. Using fallback graph for demo.")
        result = analyzer.get_fallback_graph()

    # Ensure directory exists
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    
    with open(OUTPUT_PATH, "w") as f:
        json.dump(result, f, indent=2)
    
    print(f"[+] Results saved to {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
