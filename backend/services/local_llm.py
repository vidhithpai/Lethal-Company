from pathlib import Path
import json

# Try to import llama-cpp-python (CPU inference)
try:
    from llama_cpp import Llama
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False

# Try transformers fallback (smaller models)
try:
    from transformers import pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

MODEL_PATH = Path("models/")

class LocalVulnAnalyzer:
    
    def __init__(self):
        self.llm = None
        self.classifier = None
        self.mode = "rule_based"  # fallback always works
        self._try_load_model()
    
    def _try_load_model(self):
        # Option 1: llama.cpp with quantized model (best quality)
        gguf_models = list(MODEL_PATH.glob("*.gguf"))
        if LLAMA_AVAILABLE and gguf_models:
            try:
                self.llm = Llama(
                    model_path=str(gguf_models[0]),
                    n_ctx=2048,
                    n_threads=4,
                    verbose=False
                )
                self.mode = "llama_cpp"
                return
            except Exception as e:
                print(f"llama.cpp load failed: {e}")
        
        # Option 2: HuggingFace transformers (smaller, slower)
        if TRANSFORMERS_AVAILABLE:
            try:
                self.classifier = pipeline(
                    "text-classification",
                    model="mrm8488/codebert-base-finetuned-detect-insecure-code",
                    device=-1  # CPU only
                )
                self.mode = "codebert"
                return
            except Exception as e:
                print(f"CodeBERT load failed: {e}")
        
        # Option 3: Rule-based fallback (always available)
        self.mode = "rule_based"
    
    def explain_vulnerability(self, node: dict, path: list, 
                               context_code: str = "") -> dict:
        """
        Generate a human-readable explanation for a detected vulnerability.
        Works in all three modes.
        """
        if self.mode == "llama_cpp":
            return self._explain_with_llama(node, path, context_code)
        elif self.mode == "codebert":
            return self._explain_with_codebert(node, context_code)
        else:
            return self._explain_with_rules(node, path)
    
    def _explain_with_llama(self, node, path, code):
        prompt = f"""You are a security expert. Analyze this vulnerability:

Node type: {node.get('type')}
File: {node.get('file')}
Line: {node.get('line')}
Path length: {len(path)} hops from user input to this sink
Code context: {code[:300] if code else 'unavailable'}

Explain in 3 sentences: what the vulnerability is, how it can be exploited,
and the single most important fix. Be specific and technical.

Answer:"""
        
        response = self.llm(
            prompt,
            max_tokens=200,
            temperature=0.1,
            stop=["\n\n", "Question:", "Node type:"]
        )
        explanation = response['choices'][0]['text'].strip()
        
        return {
            "mode": "local_llm",
            "model": Path(list(MODEL_PATH.glob("*.gguf"))[0]).stem,
            "explanation": explanation,
            "remediation": self._get_rule_remediation(node)
        }
    
    def _explain_with_codebert(self, node, code):
        if not code:
            return self._explain_with_rules(node, [])
        result = self.classifier(code[:512])[0]
        is_vulnerable = result['label'] == 'LABEL_1'
        confidence = round(result['score'], 3)
        
        return {
            "mode": "codebert",
            "model": "mrm8488/codebert-base-finetuned-detect-insecure-code",
            "confidence": confidence,
            "explanation": (
                f"CodeBERT classifies this code as "
                f"{'VULNERABLE' if is_vulnerable else 'potentially safe'} "
                f"with {confidence:.1%} confidence. "
                + self._get_rule_explanation(node)
            ),
            "remediation": self._get_rule_remediation(node)
        }
    
    def _explain_with_rules(self, node, path):
        return {
            "mode": "rule_based",
            "explanation": self._get_rule_explanation(node),
            "remediation": self._get_rule_remediation(node),
            "path_depth": len(path),
            "guards_on_path": sum(1 for n in path 
                                  if isinstance(n, dict) and 
                                  n.get('type') == 'sanitizer')
        }
    
    def _get_rule_explanation(self, node):
        label = node.get('label', node.get('id', ''))
        explanations = {
            'execute': (
                "SQL Injection (CWE-89): User-controlled data flows directly "
                "into a SQL query without parameterization. An attacker can "
                "manipulate the query structure to extract, modify, or delete data."
            ),
            'subprocess': (
                "Command Injection (CWE-78): User input reaches an OS command "
                "execution call. An attacker can inject shell metacharacters "
                "to execute arbitrary commands on the server."
            ),
            'eval': (
                "Code Injection (CWE-95): User-supplied data is evaluated as "
                "executable code. This allows complete remote code execution "
                "with the permissions of the running process."
            ),
            'open': (
                "Path Traversal (CWE-22): A file path derived from user input "
                "is used to open files. An attacker can use ../ sequences "
                "to read or write files outside the intended directory."
            ),
            'pickle': (
                "Insecure Deserialization (CWE-502): Untrusted data is "
                "deserialized using pickle. Crafted payloads can execute "
                "arbitrary Python code during deserialization."
            ),
            'invoke': (
                "Unsafe Reflection (CWE-470): User-controlled input determines "
                "which class or method is invoked via reflection. Attackers can "
                "call arbitrary methods in the classpath."
            )
        }
        for key, explanation in explanations.items():
            if key in str(label).lower():
                return explanation
        return (
            f"Security sink detected at {node.get('file','unknown')} "
            f"line {node.get('line','?')}. User-controlled data reaches "
            "this operation without sufficient validation."
        )
    
    def _get_rule_remediation(self, node):
        label = str(node.get('label', node.get('id', ''))).lower()
        if 'execute' in label or 'query' in label:
            return "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (user_input,))"
        elif 'subprocess' in label or 'exec' in label:
            return "Use argument arrays: subprocess.run(['cmd', arg], shell=False)"
        elif 'eval' in label:
            return "Remove eval(). Use ast.literal_eval() for safe data parsing or redesign the feature."
        elif 'open' in label or 'file' in label:
            return "Validate paths: use os.path.realpath() and check it starts with the allowed base directory."
        elif 'pickle' in label:
            return "Replace pickle with json.loads() for untrusted data. Never deserialize from untrusted sources."
        else:
            return "Validate and sanitize all user-controlled input before it reaches this operation."

# Singleton instance
_analyzer = None
def get_analyzer() -> LocalVulnAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = LocalVulnAnalyzer()
    return _analyzer
