import json
from pathlib import Path
import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from services.mapper import map_owasp_report_to_graph

data_path = Path('backend/data/seed_graph.json')
print(f"Reading {data_path.absolute()}")
raw = data_path.read_text(encoding='utf-8')
payload = json.loads(raw)
print(f"Keys in payload: {list(payload.keys())}")

if 'dependencies' in payload:
    print("Detected OWASP format, mapping...")
    mapped = map_owasp_report_to_graph(data_path)
    print(f"Mapped nodes: {len(mapped['nodes'])}")
    print(f"Mapped edges: {len(mapped['edges'])}")
    print(json.dumps(mapped, indent=2))
else:
    print("Not OWASP format")
