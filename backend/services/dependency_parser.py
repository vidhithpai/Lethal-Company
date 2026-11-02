from __future__ import annotations

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    import tomllib
except ImportError:
    try:
        # pyrefly: ignore [missing-import]
        import tomli as tomllib
    except ImportError:
        tomllib = None

class Dependency:
    def __init__(self, package: str, version: str, ecosystem: str, direct: bool = True):
        self.package = package
        self.version = version
        self.ecosystem = ecosystem
        self.direct = direct
        self.cves: List[Any] = []

    def to_dict(self):
        return {
            "package": self.package,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "direct": self.direct,
            "cves": self.cves
        }

class ParserInterface:
    def parse(self, filepath: Path) -> List[Dependency]:
        raise NotImplementedError

class RequirementsTxtParser(ParserInterface):
    def parse(self, filepath: Path) -> List[Dependency]:
        deps = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    match = re.match(r'^([a-zA-Z0-9\-\._]+)[=<>~]+([a-zA-Z0-9\.\-_]+)', line)
                    if match:
                        package = match.group(1)
                        version = match.group(2)
                        deps.append(Dependency(package, version, "PyPI", True))
                    else:
                        pkg_match = re.match(r'^([a-zA-Z0-9\-\._]+)', line)
                        if pkg_match:
                            deps.append(Dependency(pkg_match.group(1), "unknown", "PyPI", True))
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
        return deps

class PyProjectTomlParser(ParserInterface):
    def parse(self, filepath: Path) -> List[Dependency]:
        deps = []
        if tomllib is None:
            print(f"Warning: tomllib not found, cannot parse {filepath}")
            return deps
            
        try:
            with open(filepath, 'rb') as f:
                data = tomllib.load(f)
                
            # Check for poetry dependencies
            poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            for pkg, ver in poetry_deps.items():
                if pkg == "python": continue
                version_str = ver if isinstance(ver, str) else ver.get("version", "unknown")
                version_str = version_str.lstrip("^~=><")
                deps.append(Dependency(pkg, version_str, "PyPI", True))
                
            # Check for standard project dependencies (PEP 621)
            project_deps = data.get("project", {}).get("dependencies", [])
            for dep_str in project_deps:
                match = re.match(r'^([a-zA-Z0-9\-\._]+)[=<>~]+([a-zA-Z0-9\.\-_]+)', dep_str)
                if match:
                    deps.append(Dependency(match.group(1), match.group(2), "PyPI", True))
                else:
                    pkg_match = re.match(r'^([a-zA-Z0-9\-\._]+)', dep_str)
                    if pkg_match:
                        deps.append(Dependency(pkg_match.group(1), "unknown", "PyPI", True))
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
        return deps

class PoetryLockParser(ParserInterface):
    def parse(self, filepath: Path) -> List[Dependency]:
        deps = []
        if tomllib is None:
            return deps
        try:
            with open(filepath, 'rb') as f:
                data = tomllib.load(f)
            packages = data.get("package", [])
            for pkg in packages:
                name = pkg.get("name")
                version = pkg.get("version", "unknown")
                deps.append(Dependency(name, version, "PyPI", False)) # Assume lock files have mostly transitive
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
        return deps

class PipfileParser(ParserInterface):
    def parse(self, filepath: Path) -> List[Dependency]:
        deps = []
        if tomllib is None:
            return deps
        try:
            with open(filepath, 'rb') as f:
                data = tomllib.load(f)
            packages = data.get("packages", {})
            for pkg, ver in packages.items():
                version_str = ver if isinstance(ver, str) else ver.get("version", "unknown")
                version_str = version_str.lstrip("=") if isinstance(version_str, str) else "unknown"
                deps.append(Dependency(pkg, version_str, "PyPI", True))
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
        return deps

class PipfileLockParser(ParserInterface):
    def parse(self, filepath: Path) -> List[Dependency]:
        deps = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            packages = data.get("default", {})
            for pkg, info in packages.items():
                version = info.get("version", "unknown").lstrip("=")
                deps.append(Dependency(pkg, version, "PyPI", False))
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
        return deps

class PomXmlParser(ParserInterface):
    def parse(self, filepath: Path) -> List[Dependency]:
        deps = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            dep_pattern = re.compile(r'<dependency>\s*<groupId>(.*?)</groupId>\s*<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>', re.DOTALL)
            
            for match in dep_pattern.finditer(content):
                group_id = match.group(1).strip()
                artifact_id = match.group(2).strip()
                version = match.group(3).strip()
                
                if version.startswith('${'):
                    version = "unknown"
                    
                package_name = f"{group_id}:{artifact_id}"
                deps.append(Dependency(package_name, version, "Maven", True))
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
        return deps

class GradleParser(ParserInterface):
    def parse(self, filepath: Path) -> List[Dependency]:
        deps = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Simple regex to catch basic implementation 'group:name:version'
            # e.g., implementation 'org.springframework.boot:spring-boot-starter-web:3.1.2'
            pattern = re.compile(r'(?:implementation|compile|api)\s+[\'"]([^:]+):([^:]+):([^:\'"]+)[\'"]')
            for match in pattern.finditer(content):
                group_id = match.group(1).strip()
                artifact_id = match.group(2).strip()
                version = match.group(3).strip()
                package_name = f"{group_id}:{artifact_id}"
                deps.append(Dependency(package_name, version, "Maven", True))
                
            # Basic parsing for structured dependencies, e.g., implementation group: '...', name: '...', version: '...'
            struct_pattern = re.compile(r'(?:implementation|compile|api)\s+group:\s*[\'"]([^\'"]+)[\'"]\s*,\s*name:\s*[\'"]([^\'"]+)[\'"]\s*,\s*version:\s*[\'"]([^\'"]+)[\'"]')
            for match in struct_pattern.finditer(content):
                group_id = match.group(1).strip()
                artifact_id = match.group(2).strip()
                version = match.group(3).strip()
                package_name = f"{group_id}:{artifact_id}"
                deps.append(Dependency(package_name, version, "Maven", True))
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
        return deps

class ParserFactory:
    @staticmethod
    def get_parser(filename: str) -> Optional[ParserInterface]:
        if filename == "requirements.txt": return RequirementsTxtParser()
        if filename == "pyproject.toml": return PyProjectTomlParser()
        if filename == "poetry.lock": return PoetryLockParser()
        if filename == "Pipfile": return PipfileParser()
        if filename == "Pipfile.lock": return PipfileLockParser()
        if filename == "pom.xml": return PomXmlParser()
        if filename in ["build.gradle", "build.gradle.kts"]: return GradleParser()
        return None

def discover_dependencies(project_path: str) -> List[Dependency]:
    all_deps = []
    p = Path(project_path)
    
    if not p.exists() or not p.is_dir():
        return all_deps

    files_to_check = [
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "Pipfile",
        "Pipfile.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts"
    ]
    
    for filename in files_to_check:
        file_path = p / filename
        if file_path.exists():
            parser = ParserFactory.get_parser(filename)
            if parser:
                all_deps.extend(parser.parse(file_path))
        
    # Deduplicate dependencies
    seen = set()
    unique_deps = []
    for dep in all_deps:
        identifier = f"{dep.ecosystem}:{dep.package}:{dep.version}"
        if identifier not in seen:
            seen.add(identifier)
            unique_deps.append(dep)
            
    return unique_deps
