import ast
import json
import os
import sys

SOURCE_APIS = {"os.getenv", "input", "open"}
SINK_APIS = {"os.system", "eval", "exec", "requests.post", "subprocess.run"}


class CallGraphTaintAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.current_function = "GLOBAL"
        self.call_graph = {}
        self.function_defs = set()
        self.taint_vars = {}
        self.taint_flows = []

    def add_edge(self, caller, callee):
        if caller not in self.call_graph:
            self.call_graph[caller] = set()
        self.call_graph[caller].add(callee)

    def visit_FunctionDef(self, node):
        func_name = node.name
        self.function_defs.add(func_name)
        old_function = self.current_function
        self.current_function = func_name
        self.call_graph.setdefault(func_name, set())
        self.generic_visit(node)
        self.current_function = old_function

    def visit_Call(self, node):
        func_name = self.get_full_name(node.func)

        # add call graph edge
        if func_name:
            self.add_edge(self.current_function, func_name)

        # if function args contain tainted variable -> taint flow to sink
        if func_name in SINK_APIS:
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    if self.taint_vars.get(arg.id, False):
                        self.taint_flows.append({
                            "from_var": arg.id,
                            "sink": func_name,
                            "line": node.lineno
                        })

        self.generic_visit(node)

    def visit_Assign(self, node):
        # detect source assignments
        if isinstance(node.value, ast.Call):
            func_name = self.get_full_name(node.value.func)

            # x = os.getenv(...)
            if func_name in SOURCE_APIS:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.taint_vars[target.id] = True
                        self.taint_flows.append({
                            "source": func_name,
                            "to_var": target.id,
                            "line": node.lineno
                        })

            # x = y  and y is tainted
            elif isinstance(node.value, ast.Name):
                if self.taint_vars.get(node.value.id, False):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.taint_vars[target.id] = True

        elif isinstance(node.value, ast.Name):
            if self.taint_vars.get(node.value.id, False):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.taint_vars[target.id] = True

        self.generic_visit(node)

    def get_full_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            left = self.get_full_name(node.value)
            return f"{left}.{node.attr}"
        return ""

    def export_result(self):
        return {
            "call_graph": {k: sorted(list(v)) for k, v in self.call_graph.items()},
            "taint_flows": self.taint_flows
        }


def analyze_file(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        source = f.read()

    tree = ast.parse(source)
    analyzer = CallGraphTaintAnalyzer()
    analyzer.visit(tree)
    return analyzer.export_result()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 callgraph_taint.py <python_file>")
        sys.exit(1)

    result = analyze_file(sys.argv[1])

    with open("callgraph_taint_result.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(json.dumps(result, indent=2, ensure_ascii=False))
    print("\nĐã lưu vào callgraph_taint_result.json")
