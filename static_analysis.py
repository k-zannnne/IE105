import ast
import base64
import json
import math
import os
import sys
from collections import Counter

SENSITIVE_APIS = {
    "Execution": {
        "eval", "exec", "compile",
        "os.system", "subprocess.run", "subprocess.Popen"
    },
    "Network": {
        "socket", "requests.post", "requests.get",
        "urllib.request", "urllib.request.urlopen"
    },
    "Persistence": {
        "open", "os.remove", "os.rename"
    }
}


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return entropy


def try_base64_decode(s: str):
    try:
        decoded = base64.b64decode(s, validate=True)
        if decoded:
            return decoded[:80]
    except Exception:
        return None
    return None


class StaticAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.findings = []
        self.strings = []

    def visit_Call(self, node):
        func_name = self.get_full_name(node.func)

        # Detect sensitive APIs
        for category, apis in SENSITIVE_APIS.items():
            if func_name in apis:
                self.findings.append({
                    "type": "Sensitive API",
                    "category": category,
                    "api": func_name,
                    "line": node.lineno
                })

        # Detect getattr(os, "sys" + "tem")
        if isinstance(node.func, ast.Name) and node.func.id == "getattr":
            if len(node.args) >= 2:
                target = self.get_full_name(node.args[0])
                resolved = self.eval_string_expr(node.args[1])
                if target == "os" and resolved == "system":
                    self.findings.append({
                        "type": "Obfuscation",
                        "method": "getattr(os, 'sys'+'tem')",
                        "equivalent_api": "os.system",
                        "line": node.lineno
                    })

        # Detect base64 decode
        if func_name == "base64.b64decode":
            self.findings.append({
                "type": "Obfuscation",
                "method": "base64 decode",
                "line": node.lineno
            })

        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            self.strings.append((node.value, getattr(node, "lineno", -1)))
        self.generic_visit(node)

    def visit_Str(self, node):
        self.strings.append((node.s, getattr(node, "lineno", -1)))
        self.generic_visit(node)

    def get_full_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            left = self.get_full_name(node.value)
            return f"{left}.{node.attr}"
        return ""

    def eval_string_expr(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Str):
            return node.s
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.eval_string_expr(node.left)
            right = self.eval_string_expr(node.right)
            if left is not None and right is not None:
                return left + right
        return None


def classify_entropy(entropy_value: float) -> str:
    if entropy_value > 5.0:
        return "high"
    if entropy_value >= 4.5:
        return "medium"
    return "low"


def analyze_file(filepath: str):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        source = f.read()

    tree = ast.parse(source)
    analyzer = StaticAnalyzer()
    analyzer.visit(tree)

    entropy_hits = []
    decoded_hits = []

    for s, lineno in analyzer.strings:
        ent = shannon_entropy(s)

        if len(s) >= 12 and ent >= 4.5:
            entropy_hits.append({
                "type": "High Entropy String",
                "severity": classify_entropy(ent),
                "string": s[:80],
                "entropy": round(ent, 4),
                "line": lineno
            })

        decoded = try_base64_decode(s)
        if decoded is not None:
            decoded_hits.append({
                "type": "Decoded Base64",
                "encoded": s[:80],
                "decoded_preview": repr(decoded),
                "line": lineno
            })

    return {
        "file": filepath,
        "findings": analyzer.findings,
        "entropy_hits": entropy_hits,
        "decoded_hits": decoded_hits
    }


def analyze_folder(folder: str):
    results = []
    for root, _, files in os.walk(folder):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                try:
                    results.append(analyze_file(path))
                except Exception as e:
                    results.append({
                        "file": path,
                        "error": str(e)
                    })
    return results


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:")
        print("  python3 static_analysis.py file <python_file>")
        print("  python3 static_analysis.py folder <folder_path>")
        sys.exit(1)

    mode = sys.argv[1]
    target = sys.argv[2]

    if mode == "file":
        result = analyze_file(target)
        out_name = "static_result.json"
    elif mode == "folder":
        result = analyze_folder(target)
        out_name = "static_folder_result.json"
    else:
        print("Mode phải là 'file' hoặc 'folder'")
        sys.exit(1)

    with open(out_name, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"\nĐã lưu kết quả vào {out_name}")
