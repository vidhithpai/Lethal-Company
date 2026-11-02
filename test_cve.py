import asyncio
from backend.services.dependency_parser import discover_dependencies
from backend.services.cve_lookup import fetch_cves_for_dependencies

async def main():
    print("Discovering dependencies...")
    deps = discover_dependencies("demo_project")
    print(f"Found {len(deps)} dependencies.")
    for d in deps:
        print(f"- {d.package} @ {d.version}")
        
    print("\nFetching CVEs...")
    await fetch_cves_for_dependencies(deps)
    
    for d in deps:
        if d.cves:
            print(f"Found {len(d.cves)} CVEs for {d.package}:")
            for cve in d.cves:
                print(f"  - {cve['id']} (CVSS: {cve['cvss']})")
                
if __name__ == "__main__":
    asyncio.run(main())
