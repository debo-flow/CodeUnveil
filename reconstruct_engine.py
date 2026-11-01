import esprima
import json
from typing import Dict, Any, List

class CodeQualityAnalyzer:
    """Calculates Readability and Quality Statistics of Source Code via AST."""
    
    @staticmethod
    def analyze(code: str) -> Dict[str, Any]:
        lines = code.splitlines()
        stats = {
            "total_lines": len(lines),
            "avg_line_length": sum(len(l) for l in lines) / max(len(lines), 1),
            "max_nesting_depth": 0,
            "statement_density": 0,
            "functions": 0
        }
        
        try:
            tree = esprima.parseScript(code, {"tolerant": True})
            stmt_count = [0]
            
            def walk(node, depth):
                if not node or not hasattr(node, 'type'): return
                stats["max_nesting_depth"] = max(stats["max_nesting_depth"], depth)
                
                ntype = node.type
                if 'Statement' in ntype or 'Declaration' in ntype:
                    stmt_count[0] += 1
                if ntype in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']:
                    stats["functions"] += 1
                    
                for key, val in vars(node).items():
                    if key in ['type', 'loc', 'range', 'parent']: continue
                    if isinstance(val, list):
                        for item in val: walk(item, depth + 1)
                    elif hasattr(val, 'type'):
                        walk(val, depth + 1)
                        
            walk(tree, 0)
            stats["statement_density"] = stmt_count[0] / max(stats["total_lines"], 1)
            
        except Exception:
            pass
            
        return stats

class ASTGenerator:
    """Reconstructs standard JavaScript source code directly from an AST."""
    
    def __init__(self, indent_size=4):
        self.indent_size = indent_size
        self.indent_level = 0
        
        # Precedence map to determine when parenthesis are required
        self.precedence = {
            'SequenceExpression': 0,
            'AssignmentExpression': 1, 'YieldExpression': 1,
            'ConditionalExpression': 2,
            'LogicalExpression': 3, # &&, ||
            'BinaryExpression': 4,  # +, -, *, /
            'UnaryExpression': 5, 'UpdateExpression': 5,
            'CallExpression': 6, 'MemberExpression': 6, 'NewExpression': 6
        }

    def _indent(self) -> str:
        return " " * (self.indent_size * self.indent_level)

    def generate(self, node: Any) -> str:
        """Entry point for code generation."""
        return self._visit(node)

    def _visit(self, node: Any, parent_type: str = "") -> str:
        if not node: return ""
        if isinstance(node, list): return "".join(self._visit(n) for n in node)
        if not hasattr(node, 'type'): return str(node)

        visitor = getattr(self, f"_visit_{node.type}", self._visit_Unknown)
        return visitor(node, parent_type)

    def _visit_Unknown(self, node: Any, parent_type: str) -> str:
        return f"/* Unsupported AST Node: {node.type} */"

    def _visit_Program(self, node: Any, _pt) -> str:
        return "\n".join(self._visit(stmt, "Program") for stmt in getattr(node, 'body', []))

    def _visit_BlockStatement(self, node: Any, _pt) -> str:
        self.indent_level += 1
        body_strs = []
        for stmt in getattr(node, 'body', []):
            body_strs.append(self._indent() + self._visit(stmt, "BlockStatement"))
        self.indent_level -= 1
        
        if not body_strs: return "{}"
        return "{\n" + "\n".join(body_strs) + "\n" + self._indent() + "}"

    def _visit_ExpressionStatement(self, node: Any, _pt) -> str:
        return self._visit(node.expression, "ExpressionStatement") + ";"

    def _visit_VariableDeclaration(self, node: Any, _pt) -> str:
        kind = getattr(node, 'kind', 'var')
        decls = [self._visit(d, "VariableDeclaration") for d in getattr(node, 'declarations', [])]
        code = f"{kind} {', '.join(decls)}"
        if _pt not in ['ForStatement', 'ForInStatement', 'ForOfStatement']: code += ";"
        return code

    def _visit_VariableDeclarator(self, node: Any, _pt) -> str:
        id_str = self._visit(node.id, "VariableDeclarator")
        if getattr(node, 'init', None):
            return f"{id_str} = {self._visit(node.init, 'VariableDeclarator')}"
        return id_str

    def _visit_FunctionDeclaration(self, node: Any, _pt) -> str:
        is_async = "async " if getattr(node, 'async', False) else ""
        name = self._visit(node.id) if getattr(node, 'id', None) else ""
        params = ", ".join(self._visit(p) for p in getattr(node, 'params', []))
        body = self._visit(node.body)
        return f"{is_async}function {name}({params}) {body}"

    def _visit_FunctionExpression(self, node: Any, _pt) -> str:
        # Similar to declaration but for expressions
        is_async = "async " if getattr(node, 'async', False) else ""
        name = self._visit(node.id) if getattr(node, 'id', None) else ""
        params = ", ".join(self._visit(p) for p in getattr(node, 'params', []))
        body = self._visit(node.body)
        return f"{is_async}function {name}({params}) {body}"
        
    def _visit_ArrowFunctionExpression(self, node: Any, _pt) -> str:
        is_async = "async " if getattr(node, 'async', False) else ""
        params = ", ".join(self._visit(p) for p in getattr(node, 'params', []))
        body = self._visit(node.body)
        if len(getattr(node, 'params', [])) == 1 and getattr(node.params[0], 'type', '') == 'Identifier':
            param_str = params
        else:
            param_str = f"({params})"
        return f"{is_async}{param_str} => {body}"

    def _visit_IfStatement(self, node: Any, _pt) -> str:
        test = self._visit(node.test)
        cons = self._visit(node.consequent)
        if node.consequent.type != 'BlockStatement': cons = f"{{\n{self._indent()}    {cons}\n{self._indent()}}}"
        code = f"if ({test}) {cons}"
        
        if getattr(node, 'alternate', None):
            alt = self._visit(node.alternate)
            if node.alternate.type not in ['BlockStatement', 'IfStatement']:
                alt = f"{{\n{self._indent()}    {alt}\n{self._indent()}}}"
            code += f" else {alt}"
        return code

    def _visit_ReturnStatement(self, node: Any, _pt) -> str:
        if getattr(node, 'argument', None):
            return f"return {self._visit(node.argument)};"
        return "return;"
        
    def _visit_ThrowStatement(self, node: Any, _pt) -> str:
        return f"throw {self._visit(node.argument)};"

    def _visit_CallExpression(self, node: Any, _pt) -> str:
        callee = self._visit(node.callee, "CallExpression")
        if node.callee.type in ['FunctionExpression', 'ArrowFunctionExpression']:
            callee = f"({callee})"
        args = ", ".join(self._visit(a) for a in getattr(node, 'arguments', []))
        return f"{callee}({args})"

    def _visit_MemberExpression(self, node: Any, _pt) -> str:
        obj = self._visit(node.object, "MemberExpression")
        if node.object.type in ['FunctionExpression', 'ArrowFunctionExpression']:
            obj = f"({obj})"
        prop = self._visit(node.property)
        if getattr(node, 'computed', False):
            return f"{obj}[{prop}]"
        return f"{obj}.{prop}"

    def _visit_BinaryExpression(self, node: Any, parent_type: str) -> str:
        # Simplistic precedence wrapping
        code = f"{self._visit(node.left, 'BinaryExpression')} {node.operator} {self._visit(node.right, 'BinaryExpression')}"
        if parent_type in ['BinaryExpression', 'UnaryExpression', 'CallExpression', 'MemberExpression']:
            return f"({code})"
        return code
        
    def _visit_LogicalExpression(self, node: Any, parent_type: str) -> str:
        code = f"{self._visit(node.left, 'LogicalExpression')} {node.operator} {self._visit(node.right, 'LogicalExpression')}"
        if parent_type in ['LogicalExpression', 'BinaryExpression', 'UnaryExpression']:
            return f"({code})"
        return code

    def _visit_UnaryExpression(self, node: Any, _pt) -> str:
        prefix = node.operator if getattr(node, 'prefix', True) else ""
        suffix = "" if getattr(node, 'prefix', True) else node.operator
        arg = self._visit(node.argument, "UnaryExpression")
        space = " " if node.operator in ['typeof', 'void', 'delete'] else ""
        return f"{prefix}{space}{arg}{suffix}"
        
    def _visit_UpdateExpression(self, node: Any, _pt) -> str:
        prefix = node.operator if getattr(node, 'prefix', True) else ""
        suffix = "" if getattr(node, 'prefix', True) else node.operator
        arg = self._visit(node.argument, "UpdateExpression")
        return f"{prefix}{arg}{suffix}"

    def _visit_AssignmentExpression(self, node: Any, _pt) -> str:
        return f"{self._visit(node.left)} {node.operator} {self._visit(node.right)}"

    def _visit_Identifier(self, node: Any, _pt) -> str:
        return node.name

    def _visit_Literal(self, node: Any, _pt) -> str:
        if getattr(node, 'regex', None): return node.raw
        if isinstance(node.value, str): return json.dumps(node.value, ensure_ascii=False)
        if isinstance(node.value, bool): return "true" if node.value else "false"
        if node.value is None: return "null"
        return str(node.value)
        
    def _visit_ArrayExpression(self, node: Any, _pt) -> str:
        elems = [self._visit(e) if e else "null" for e in getattr(node, 'elements', [])]
        return f"[{', '.join(elems)}]"
        
    def _visit_ObjectExpression(self, node: Any, _pt) -> str:
        props = [self._visit(p) for p in getattr(node, 'properties', [])]
        if not props: return "{}"
        return "{ " + ", ".join(props) + " }"
        
    def _visit_Property(self, node: Any, _pt) -> str:
        key = self._visit(node.key)
        val = self._visit(node.value)
        return f"{key}: {val}"

    def _visit_ForStatement(self, node: Any, _pt) -> str:
        init = self._visit(node.init, "ForStatement") if getattr(node, 'init', None) else ""
        test = self._visit(node.test, "ForStatement") if getattr(node, 'test', None) else ""
        update = self._visit(node.update, "ForStatement") if getattr(node, 'update', None) else ""
        body = self._visit(node.body)
        if node.body.type != 'BlockStatement': body = f"{{\n{self._indent()}    {body}\n{self._indent()}}}"
        return f"for ({init}; {test}; {update}) {body}"

    def _visit_WhileStatement(self, node: Any, _pt) -> str:
        test = self._visit(node.test)
        body = self._visit(node.body)
        if node.body.type != 'BlockStatement': body = f"{{\n{self._indent()}    {body}\n{self._indent()}}}"
        return f"while ({test}) {body}"
        
    def _visit_BreakStatement(self, node: Any, _pt) -> str:
        lbl = f" {node.label.name}" if getattr(node, 'label', None) else ""
        return f"break{lbl};"

    def _visit_ContinueStatement(self, node: Any, _pt) -> str:
        lbl = f" {node.label.name}" if getattr(node, 'label', None) else ""
        return f"continue{lbl};"

    def _visit_SwitchStatement(self, node: Any, _pt) -> str:
        disc = self._visit(node.discriminant)
        cases = []
        self.indent_level += 1
        for c in getattr(node, 'cases', []):
            cases.append(self._visit(c))
        self.indent_level -= 1
        return f"switch ({disc}) {{\n" + "\n".join(cases) + "\n" + self._indent() + "}"
        
    def _visit_SwitchCase(self, node: Any, _pt) -> str:
        test = f"case {self._visit(node.test)}:" if getattr(node, 'test', None) else "default:"
        cons = "\n".join(self._indent() + "    " + self._visit(c) for c in getattr(node, 'consequent', []))
        return f"{self._indent()}{test}\n{cons}"
        
    def _visit_TryStatement(self, node: Any, _pt) -> str:
        block = self._visit(node.block)
        handler = self._visit(node.handler) if getattr(node, 'handler', None) else ""
        fin = f" finally {self._visit(node.finalizer)}" if getattr(node, 'finalizer', None) else ""
        return f"try {block}{handler}{fin}"
        
    def _visit_CatchClause(self, node: Any, _pt) -> str:
        param = f"({self._visit(node.param)})" if getattr(node, 'param', None) else ""
        return f" catch {param} {self._visit(node.body)}"

class ReconstructionPipeline:
    """Manages the fully integrated M1-M12 stage executions."""
    
    @staticmethod
    def rebuild_ast_source(code: str) -> Tuple[bool, str, str]:
        """Validates the code via AST parsing and cleanly regenerates it using the M12 ASTGenerator."""
        try:
            tree = esprima.parseScript(code, {"tolerant": True})
            generator = ASTGenerator(indent_size=4)
            reconstructed = generator.generate(tree)
            return True, reconstructed, "AST successfully regenerated and formatted."
        except Exception as e:
            return False, code, f"AST Reconstruction Failed (Fell back to regex beautifier). Error: {str(e)}"
