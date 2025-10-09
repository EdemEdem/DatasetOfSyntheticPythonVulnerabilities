import ast
import warnings
import pathlib
import importlib.util
import os
import json
import re
import ntpath
import posixpath
from collections import defaultdict
import builtins
import inspect
import types
import sys


def parse_ast_silently(src: str, filename: str = "<unknown>"):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(src, filename=filename)
      
def _compute_builtin_names():
    """Return (builtin_function_names_set, builtin_type_names_set, python_version_tuple)."""
    func_names = set(
        name
        for name, obj in vars(builtins).items()
        if isinstance(obj, (types.BuiltinFunctionType, types.FunctionType))
        and getattr(obj, "__module__", "") == "builtins"
    )
    type_names = set(
        name
        for name, obj in vars(builtins).items()
        if inspect.isclass(obj) and getattr(obj, "__module__", "") == "builtins"
    )
    return func_names, type_names, sys.version_info[:3]

BUILTIN_FUNC_NAMES, BUILTIN_TYPE_NAMES, PYTHON_VERSION = _compute_builtin_names()

def discover_internal_modules(root_path):
    internal = set()
    root = pathlib.Path(root_path).resolve()
    for py in root.rglob("*.py"):
        rel = py.with_suffix("").relative_to(root)
        parts = rel.parts
        if parts:
            internal.add(parts[0])
    return internal


def classify_import(module_name, internal_modules, project_root):
    top = module_name.split(".")[0]
    if top in internal_modules:
        return "internal"
    spec = importlib.util.find_spec(top)
    if spec and spec.origin:
        mod_path = pathlib.Path(spec.origin).resolve()
        try:
            if mod_path.is_relative_to(project_root):
                return "internal"
        except AttributeError:
            common = os.path.commonpath([str(project_root), str(mod_path)])
            if common == str(project_root):
                return "internal"
    return "external"


def find_imports(root_path):
    root = pathlib.Path(root_path).resolve()
    internal_modules = discover_internal_modules(root)
    internal_imports = set()
    external_imports = set()

    for py in root.rglob("*.py"):
        text = py.read_text(encoding="utf-8", errors="ignore")
        #tree = ast.parse(text, filename=str(py))
        tree = parse_ast_silently(text, filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    pkg = alias.name.split(".")[0]
                    kind = classify_import(pkg, internal_modules, root)
                    (internal_imports if kind == "internal" else external_imports).add(pkg)
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.module:
                    pkg = node.module.split(".")[0]
                    internal_imports.add(pkg)
                elif node.module:
                    pkg = node.module.split(".")[0]
                    kind = classify_import(pkg, internal_modules, root)
                    (internal_imports if kind == "internal" else external_imports).add(pkg)
    return internal_imports, external_imports

def extract_external_imports_to_file(root_path, output_path):
    internal_imports, external_imports = find_imports(root_path)
    
    output_file = pathlib.Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with output_file.open("w", encoding="utf-8") as f:
        # First line: internal imports
        f.write(json.dumps({
            "type": "internal",
            "imports": sorted(list(internal_imports))
        }) + "\n")
        
        # Second line: external imports
        f.write(json.dumps({
            "type": "external",
            "imports": sorted(list(external_imports))
        }) + "\n")

def analyze_with_tags(root_path):
    class TagTracker(ast.NodeVisitor):
        def __init__(self):
            super().__init__()
            self.alias_to_pkg = {}
            # per-scope: var -> set of pkg tags
            self.env_stack = [defaultdict(set)]
            # var -> list of full chains
            self.project_chains_stack = [defaultdict(list)]
            self.type_chains_stack = [defaultdict(list)]
            self.import_chains = defaultdict(list)
            self.records = []
            self.records = []
            self.skip_attrs = set()
            self.current_file = None
            self.lines = []
            self.call_counter = 0

        @property
        def env(self):
            return self.env_stack[-1]
        
        @property
        def project_chains(self):
            return self.project_chains_stack[-1]
        
        @property
        def type_chains(self):
            return self.type_chains_stack[-1]
        
        @staticmethod
        def _json_path(p) -> str:
            """
            Normalize a path string robustly and return a POSIX-style path.
            - Uses ntpath for Windows-looking paths (drive/UNC or backslashes)
            - Uses posixpath otherwise
            - No filesystem access; safe on Linux/macOS/Windows
            """
            if not p:
                return ""
            s = str(p)
            _windows_path_re = re.compile(r'^(?:[a-zA-Z]:[\\/]|\\\\)')  # drive or UNC
            # Treat anything that looks Windows-y as Windows
            if _windows_path_re.match(s) or ("\\" in s):
                # Normalize with Windows rules, then convert to POSIX slashes
                s = ntpath.normpath(s)
                return s.replace("\\", "/")
            # POSIX-style path
            return posixpath.normpath(s)
        
        def push_scope(self):
            # inherit imports tags and chains
            base_env = self.env_stack[0]
            base_pch = self.project_chains_stack[0]
            base_tch = self.type_chains_stack[0]
            new_env = defaultdict(set, {k: set(v) for k, v in base_env.items()})
            new_pch = defaultdict(list, {k: [c[:] for c in v] for k, v in base_pch.items()})
            new_tch = defaultdict(list, {k: [c[:] for c in v] for k, v in base_tch.items()})
            self.env_stack.append(new_env)
            self.project_chains_stack.append(new_pch)
            self.type_chains_stack.append(new_tch)

        def pop_scope(self):
            self.env_stack.pop()
            self.project_chains_stack.pop()
            self.type_chains_stack.pop()

        def extract_base(self, node):
            while isinstance(node, ast.Attribute):
                node = node.value
            return node.id if isinstance(node, ast.Name) else None
        
        #extract all the nodes on an attribute chain
        # if node = x.y.z or x.y.z(), this returns ['x','y','z']
        def extract_chain(self, node):
            chain=[]
            if isinstance(node, ast.Call):
                node = node.func
            while isinstance(node, ast.Attribute):
                chain.insert(0,node.attr)
                node=node.value
            if isinstance(node,ast.Name):
                chain.insert(0,node.id)
            return chain
        
        def record_call(self, node, full_chain, package, base):
            self.records.append({
                "file":self._json_path(self.current_file),
                "lineno":node.lineno,
                "col":node.col_offset,
                "node_type":"Call",
                "chain":full_chain,
                "package":package,
                "code":self.lines[node.lineno-1].strip(),
                "tags":sorted(self.env[base]),"call_id":self.call_counter
                })
            for idx, arg in enumerate(node.args):
                expr=arg
                kind="arg"
                # *args
                if isinstance(arg, ast.Starred):
                    expr = arg.value
                    kind = "arg_starred"
                expr_chain = self.extract_chain(expr)
                self.records.append({
                    "file":self._json_path(self.current_file),
                    "lineno":arg.lineno,
                    "col":arg.col_offset,
                    "node_type":kind,
                    "chain":full_chain,
                    "package":package,
                    "code":self.lines[arg.lineno-1].strip(),
                    "tags":sorted(self.env[base]),
                    "arg_pos":idx,
                    "call_id":self.call_counter,
                    "expr_chain":expr_chain
                    })
            for idx, kw in enumerate(node.keywords):
                # kw.arg is a string or None (None means **kwargs)
                expr = kw.value
                expr_chain = self.extract_chain(expr)
                line = getattr(kw, "lineno", getattr(expr, "lineno", node.lineno))
                col = getattr(kw, "col_offset", getattr(expr, "col_offset", node.col_offset))
                kind = "kwarg" if kw.arg is not None else "kwarg_doublestar"
                self.records.append({
                    "file":self._json_path(self.current_file),
                    "lineno": line,
                    "col": col,
                    "node_type": kind,
                    "chain": full_chain,
                    "package": package,
                    "code": self.lines[line - 1].strip(),
                    "tags": sorted(self.env[base]),
                    "kw_name": kw.arg,
                    "call_id": self.call_counter,
                    "expr_chain": expr_chain
                    })
            return

        def visit_FunctionDef(self, node):
            # Handle decorated endpoints: forward decorator import chains to params
            for deco in node.decorator_list:
                deco_chain = self.extract_chain(deco)
                if deco_chain:
                    base_deco = deco_chain[0]
                    # if decorator's base node is in project chain
                    if base_deco in self.project_chains:
                        for arg in node.args.args:
                            name = arg.arg
                            # tag parameter
                            # seed parameter chain
                            for base_chain in self.project_chains[base_deco]:
                                
                                fullchain = base_chain + deco_chain[1:]
                                package = fullchain[0]
                                self.env[name].add(package)
                                self.project_chains[name].append(fullchain)
                                # record parameter as source candidate
                                self.records.append({
                                    "file":self._json_path(self.current_file),
                                    "lineno": getattr(arg, 'lineno', node.lineno),
                                    "col": getattr(arg, 'col_offset', node.col_offset),
                                    "node_type": "param","chain": fullchain,
                                    "package": package,
                                    "code":self.lines[node.lineno-1].strip(),
                                    "tags": [base_deco], "name": name
                                })
                    # if decorator's base node is in import chains
                    elif base_deco in self.import_chains:
                        for arg in node.args.args:
                            name = arg.arg
                            # tag parameter
                            self.env[name].add(base_deco)
                            # seed parameter chain
                            for base_chain in self.import_chains[base_deco]:
                                fullchain = base_chain + deco_chain[1:]
                                self.project_chains[name].append(fullchain)
                                package = fullchain[0]
                                self.env[name].add(package)
                                # record parameter as source candidate
                                self.records.append({
                                    "file":self._json_path(self.current_file),
                                    "lineno": getattr(arg, 'lineno', node.lineno),
                                    "col": getattr(arg, 'col_offset', node.col_offset),
                                    "node_type": "param","chain": fullchain,
                                    "package": package,
                                    "code":self.lines[node.lineno-1].strip(),
                                    "tags": [base_deco], "name": name
                                })
            # simple check for it being a wrapper function
            wrapper_chain = None
            if node.body == 1:
                rv = node.body[0].value
                # direct return of an imported alias
                if isinstance(rv, ast.Name) and rv.id in self.import_chains:
                    wrapper_chain = list(self.import_chains[rv.id][0])
                # return of a call on an imported alias
                elif isinstance(rv, ast.Call) and isinstance(rv.func, ast.Attribute):
                    base = self.extract_base(rv.func)
                    if base in self.import_chains:
                        new_chain = self.import_chains[base][0] + [rv.func.attr]
                        wrapper_chain = list(new_chain)
                        wrapper_chain = list(self.import_chains[base][0])
                elif isinstance(rv, ast.Attribute):
                        base = self.extract_base(rv)
                        if base in self.import_chains:
                            new_chain = self.import_chains[base][0] + [rv.attr]
                            wrapper_chain = list(new_chain)
            if not wrapper_chain and len(node.body) ==2:
                assign_stmt, return_stmt = node.body
                if (
                isinstance(assign_stmt, ast.Assign)
                and isinstance(return_stmt, ast.Return)
                and isinstance(return_stmt.value, ast.Name)
                and len(assign_stmt.targets) == 1
                and isinstance(assign_stmt.targets[0], ast.Name)
                and return_stmt.value.id == assign_stmt.targets[0].id
                ):
                    val = assign_stmt.value
                    # assigned from an imported alias name
                    if isinstance(val, ast.Name) and val.id in self.import_chains:
                        wrapper_chain = list(self.import_chains[val.id][0])
                    # assigned from a call on an imported alias
                    elif isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute):
                        base = self.extract_base(val.func)
                        if base in self.import_chains:
                            new_chain = self.import_chains[base][0] + [val.func.attr]
                            wrapper_chain = list(new_chain)
                    elif isinstance(val, ast.Attribute):
                        base = self.extract_base(val)
                        if base in self.import_chains:
                            new_chain = self.import_chains[base][0] + [val.attr]
                            wrapper_chain = list(new_chain)
                # 2) If it passed, seed under project_chains + env + chains
                if wrapper_chain:
                    wrapper = node.name
                    pkg = wrapper_chain[0]
                    self.project_chains[wrapper].append(wrapper_chain)
                    self.env[wrapper].add(pkg)
            self.push_scope()
            self.generic_visit(node)
            self.pop_scope()

        def visit_AsyncFunctionDef(self, node):
            # Handle decorated endpoints: forward decorator import chains to params
            for deco in node.decorator_list:
                deco_chain = self.extract_chain(deco)
                if deco_chain:
                    base_deco = deco_chain[0]
                    # if decorator's base node is in project chain
                    if base_deco in self.project_chains:
                        for arg in node.args.args:
                            name = arg.arg
                            # tag parameter
                            # seed parameter chain
                            for base_chain in self.project_chains[base_deco]:
                                
                                fullchain = base_chain + deco_chain[1:]
                                package = fullchain[0]
                                self.env[name].add(package)
                                self.project_chains[name].append(fullchain)
                                # record parameter as source candidate
                                self.records.append({
                                    "file":self._json_path(self.current_file),
                                    "lineno": getattr(arg, 'lineno', node.lineno),
                                    "col": getattr(arg, 'col_offset', node.col_offset),
                                    "node_type": "param","chain": fullchain,
                                    "package": package,
                                    "code":self.lines[node.lineno-1].strip(),
                                    "tags": [base_deco], "name": name
                                })
                    # if decorator's base node is in import chains
                    elif base_deco in self.import_chains:
                        for arg in node.args.args:
                            name = arg.arg
                            # tag parameter
                            self.env[name].add(base_deco)
                            # seed parameter chain
                            for base_chain in self.import_chains[base_deco]:
                                fullchain = base_chain + deco_chain[1:]
                                self.project_chains[name].append(fullchain)
                                package = fullchain[0]
                                self.env[name].add(package)
                                # record parameter as source candidate
                                self.records.append({
                                    "file":self._json_path(self.current_file),
                                    "lineno": getattr(arg, 'lineno', node.lineno),
                                    "col": getattr(arg, 'col_offset', node.col_offset),
                                    "node_type": "param","chain": fullchain,
                                    "package": package,
                                    "code":self.lines[node.lineno-1].strip(),
                                    "tags": [base_deco], "name": name
                                })
            # simple check for it being a wrapper function
            wrapper_chain = None
            if node.body == 1:
                rv = node.body[0].value
                # direct return of an imported alias
                if isinstance(rv, ast.Name) and rv.id in self.import_chains:
                    wrapper_chain = list(self.import_chains[rv.id][0])
                # return of a call on an imported alias
                elif isinstance(rv, ast.Call) and isinstance(rv.func, ast.Attribute):
                    base = self.extract_base(rv.func)
                    if base in self.import_chains:
                        new_chain = self.import_chains[base][0] + [rv.func.attr]
                        wrapper_chain = list(new_chain)
                        wrapper_chain = list(self.import_chains[base][0])
                elif isinstance(rv, ast.Attribute):
                        base = self.extract_base(rv)
                        if base in self.import_chains:
                            new_chain = self.import_chains[base][0] + [rv.attr]
                            wrapper_chain = list(new_chain)
            if not wrapper_chain and len(node.body) ==2:
                assign_stmt, return_stmt = node.body
                if (
                isinstance(assign_stmt, ast.Assign)
                and isinstance(return_stmt, ast.Return)
                and isinstance(return_stmt.value, ast.Name)
                and len(assign_stmt.targets) == 1
                and isinstance(assign_stmt.targets[0], ast.Name)
                and return_stmt.value.id == assign_stmt.targets[0].id
                ):
                    val = assign_stmt.value
                    # assigned from an imported alias name
                    if isinstance(val, ast.Name) and val.id in self.import_chains:
                        wrapper_chain = list(self.import_chains[val.id][0])
                    # assigned from a call on an imported alias
                    elif isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute):
                        base = self.extract_base(val.func)
                        if base in self.import_chains:
                            new_chain = self.import_chains[base][0] + [val.func.attr]
                            wrapper_chain = list(new_chain)
                    elif isinstance(val, ast.Attribute):
                        base = self.extract_base(val)
                        if base in self.import_chains:
                            new_chain = self.import_chains[base][0] + [val.attr]
                            wrapper_chain = list(new_chain)
                # 2) If it passed, seed under project_chains + env + chains
                if wrapper_chain:
                    wrapper = node.name
                    pkg = wrapper_chain[0]
                    self.project_chains[wrapper].append(wrapper_chain)
                    self.env[wrapper].add(pkg)
            self.push_scope()
            self.generic_visit(node)
            self.pop_scope()

        def visit_Import(self, node):
            for alias in node.names:
                pkg = alias.name.split(".")[0]
                name = alias.asname or pkg
                # tag and chain seed
                self.alias_to_pkg[name] = pkg
                self.env[name].add(pkg)
                self.import_chains[name].append([pkg])
            self.generic_visit(node)

        def visit_ImportFrom(self, node):
            if not node.module:
                self.generic_visit(node)
                return
            pkg = node.module.split(".")[0]
            for alias in node.names:
                name = alias.asname or alias.name
                self.alias_to_pkg[name] = pkg
                self.env[name].add(pkg)
                self.import_chains[name].append([pkg, name])
                ###extract the node_type that a usage of the name node would be. Then add it to type_chains
                # if not possible, this can be done form elsewhere. Maybe it even should be done from elsewhere
					# because the vaule(or whatever you wanna call it) of the variable/pointer can be changed
            self.generic_visit(node)

        def visit_Assign(self, node):
            # support x = y, x = y.attr, x = y.attr(), x = a or b
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                tgt = node.targets[0].id
                rhs = node.value
                # clear existing tags and chains
                self.env[tgt].clear()
                self.project_chains[tgt].clear()
                # 1) simple name copy: x = y
                if isinstance(rhs, ast.Name) and rhs.id in self.project_chains:
                    self.env[tgt].update(self.env[rhs.id])
                    for c in self.project_chains[rhs.id]:
                        self.project_chains[tgt].append(c[:])
                        self.type_chains[tgt].append("var")
                if isinstance(rhs, ast.Name) and rhs.id in self.import_chains:
                    self.env[tgt].update(self.env[rhs.id])
                    for c in self.import_chains[rhs.id]:
                        self.project_chains[tgt].append(c[:])
                        self.type_chains[tgt].append("var")
                
                # 2) attribute access: x = y.attr
                if isinstance(rhs, ast.Attribute):
                    base = self.extract_base(rhs)
                    if base in self.project_chains:
                        for c in self.project_chains[base]:
                            # propagate tags from base
                            self.env[tgt].update(self.env[base])
                            # extend chain
                            new_chain = c[:] + [rhs.attr]
                            self.project_chains[tgt].append(new_chain)
                            self.type_chains[tgt].append("attr")
                    if base in self.import_chains:
                        for c in self.import_chains[base]:
                            # propagate tags from base
                            self.env[tgt].update(self.env[base])
                            # extend chain
                            new_chain = c[:] + [rhs.attr]
                            self.project_chains[tgt].append(new_chain)
                            self.type_chains[tgt].append("attr")

                # 3) method call: x = y.attr()
                if isinstance(rhs, ast.Call) and isinstance(rhs.func, ast.Attribute):
                    attr_node = rhs.func
                    base = self.extract_base(attr_node)
                    if base in self.project_chains:
                        for c in self.project_chains[base]:
                            self.env[tgt].update(self.env[base])
                            new_chain = c[:] + [attr_node.attr]
                            self.project_chains[tgt].append(new_chain)
                            self.type_chains[tgt].append("call")
                    if base in self.import_chains:
                        for c in self.import_chains[base]:
                            self.env[tgt].update(self.env[base])
                            new_chain = c[:] + [attr_node.attr]
                            self.project_chains[tgt].append(new_chain)
                            self.type_chains[tgt].append("call")
                
                # 4) direct function calls
                if isinstance(rhs, ast.Call) and isinstance(rhs.func, ast.Name):
                    func = rhs.func
                    base = self.extract_base(func)
					# A direct function call, which has been taged and placed in project_chains (could only happen in vist_function_def)
					# Always a wrapper
						# Don't append funciton name to chain
                    if base in self.project_chains:
                        for c in self.project_chains[base]:
                            self.env[tgt].update(self.env[base])
                            self.project_chains[tgt].append(c[:])
                            self.type_chains[tgt].append("call")
                    # Call to imported function
                    elif base in self.import_chains:
                        for c in self.import_chains[base]:
                            self.env[tgt].update(self.env[base])
                            new_chain = c[:]
                            if base != c[-1]:
                                new_chain = c[:] + [func.id]
                                print("[WARNING] Direct call to imported function, and call-name's chain does not end in the call-name")
                                print(f"This sciprt's output-file might not be a correct description of how libraries are used in the project. Check chains similar to {new_chain} and confirm no duplicates or missing nodes")
                            self.project_chains[tgt].append(new_chain)
                            self.type_chains[tgt].append("call")
                    
                # 5) boolean operations: x = a or b
                if isinstance(rhs, ast.BoolOp):
                    for val in rhs.values:
                        base = None
                        node_type = "name"
                        if isinstance(val, ast.Name):
                            base = val.id
                        elif isinstance(val, ast.Attribute):
                            base = self.extract_base(val)
                            node_type = "attr"
                        # propagate tags
                        if base in self.project_chains:
                            for c in self.project_chains[base]:
                                new_chain = c[:] + self.extract_chain(val)
                                self.project_chains[tgt].append(new_chain)
                                self.type_chains[tgt].append(node_type)
                        elif base in self.import_chains:
                            for c in self.import_chains[base]:
                                new_chain = c[:] + self.extract_chain(val)[1:]
                                self.project_chains[tgt].append(new_chain)
                                self.type_chains[tgt].append(node_type)
                                
            # continue traversal
            self.generic_visit(node)
            
        def visit_Call(self, node):
            func=node.func
            self.call_counter += 1
            if isinstance(func, ast.Attribute):
                self.skip_attrs.add(func)
                base=self.extract_base(func) #method=func.attr
                node_chain = self.extract_chain(func)
                if base in self.project_chains:
                    for base_chain in self.project_chains[base]:
                        full_chain=base_chain[:] + node_chain[1:]
                        pkg=base_chain[0]
                        self.record_call(node=node, full_chain=full_chain, package=pkg, base=base)
                # Case: when some variable has the same name as an imported one. Since I think the project variable will override
                elif base in self.import_chains:
                    for base_chain in self.import_chains[base]:
                        full_chain=base_chain[:] + node_chain
                        pkg=base_chain[0]
                        if base_chain[0] == base:
                            full_chain = node_chain
                        self.record_call(node=node, full_chain=full_chain, package=pkg, base=base)
            #A direct call (i.e not a method as above)  since the func node is an ast.Name  
            #func.id is now the base node as it's the only node
            elif isinstance(func,ast.Name) and func.id in self.import_chains:
                for base_chain in self.import_chains[func.id]:
                    fc = base_chain
                    pkg=base_chain[0]
                    self.record_call(node=node, full_chain=fc, package=pkg, base=func.id)
            #If it's a wrapper function
            elif isinstance(func,ast.Name) and func.id in self.project_chains:
                for base_chain in self.project_chains[func.id]:
                    fc = base_chain
                    pkg=base_chain[0]
                    self.record_call(node=node, full_chain=fc, package=pkg, base=func.id)
            #A call to a built-in function or something else we don't have a chain for
            elif isinstance(func,ast.Name) and func.id not in self.import_chains and func.id not in self.project_chains:
                #Has to be a built-in function or type for us to record it
                if func.id in BUILTIN_FUNC_NAMES or func.id in BUILTIN_TYPE_NAMES:
                    fc = ["built_in", func.id]
                    self.record_call(node=node, full_chain=fc, package="built_in", base=func.id)
            self.generic_visit(node)
            
        def visit_Attribute(self, node):
            #skip if attr is a function (those are handled by visit call)
            if node in self.skip_attrs:
                return self.generic_visit(node)
            base = self.extract_base(node)
            if base and base in self.project_chains:
                for base_chain in self.project_chains[base]:
                    node_chain = self.extract_chain(node)
                    full_chain = base_chain[:] + node_chain
                    self.records.append({
                        "file":self._json_path(self.current_file),
                        "lineno": node.lineno,
                        "col": node.col_offset,
                        "node_type": "Attribute",
                        "chain": full_chain,
                        "package": base_chain[0],
                        "code": self.lines[node.lineno-1].strip(),
                        "tags": sorted(self.env.get(base, []))
                    })
            elif base and base in self.import_chains:
                for base_chain in self.import_chains[base]:
                    node_chain = self.extract_chain(node)
                    full_chain = base_chain + node_chain[1:]
                    #if the base node is the package-name, dont extract the chain of the package node
                    if base == base_chain[0]:
                        full_chain = node_chain
                    self.records.append({
                        "file":self._json_path(self.current_file),
                        "lineno": node.lineno,
                        "col": node.col_offset,
                        "node_type": "Attribute",
                        "chain": full_chain,
                        "package": base_chain[0],
                        "code": self.lines[node.lineno-1].strip(),
                        "tags": sorted(self.env.get(base, []))
                    })
            elif base and base not in self.project_chains and base not in self.import_chains:
                fc = ["built_in"] + self.extract_chain(node)[1:]
                self.records.append({
					"file":self._json_path(self.current_file),
                    "lineno": node.lineno,
                    "col": node.col_offset,
                    "node_type": "Attribute",
                    "chain": fc,
                    "package": "built_in",
                    "code": self.lines[node.lineno-1].strip(),
                    "tags" : ["built_in"]
				})
                    
            self.generic_visit(node)            

    root=pathlib.Path(root_path).resolve()
    recs=[]
    for py in root.rglob("*.py"):
        text=py.read_text(encoding="utf-8",errors="ignore")
        tree=ast.parse(text,filename=str(py))
        t=TagTracker(); t.current_file=str(py.relative_to(root)); t.lines=text.splitlines(); t.visit(tree)
        recs.extend(t.records)
    return recs


def analyze_all_samples(base_dir):
    for cwe_dir in os.listdir(base_dir):
        cwe_path = os.path.join(base_dir, cwe_dir)
        if os.path.isdir(cwe_path) and cwe_dir.lower().startswith('cwe'):
            for project_dir in os.listdir(cwe_path):
                project_path = os.path.join(cwe_path, project_dir)
                cwe = cwe_dir
                if os.path.isdir(project_path):
                    project = project_dir
                    vuln_path = os.path.join(project_path, 'vuln')
                    if os.path.isdir(vuln_path):
                        records = analyze_with_tags(vuln_path)
                        records.sort(key=lambda r: (
                            r.get("package", ""),
                            tuple(r.get("chain", [])),
                            r.get("lineno", float('inf'))
                            ))
                        output_path = pathlib.Path(base_dir) / "package_extractor_results" / cwe / project / "vuln" / "usages_sorted.jsonl"
                        os.makedirs(output_path.parent, exist_ok=True)
                        with open(output_path, "w", encoding="utf-8") as out:
                            for rec in records:
                                out.write(json.dumps(rec) + "\n")
                        print(f"Analyzed vuln: {vuln_path}, and wrote {len(records)} usage records to {output_path}")

                    safe_path = os.path.join(project_path, 'safe')
                    if os.path.isdir(safe_path):
                        records = analyze_with_tags(safe_path)
                        records.sort(key=lambda r: (
                            r.get("package", ""),
                            tuple(r.get("chain", [])),
                            r.get("lineno", float('inf'))
                            ))
                        output_path = pathlib.Path(base_dir) / "package_extractor_results"  / cwe / project / "safe" / "usages_sorted.jsonl"
                        os.makedirs(output_path.parent, exist_ok=True)
                        with open(output_path, "w", encoding="utf-8") as out:
                            for rec in records:
                                out.write(json.dumps(rec) + "\n")
                        print(f"Analyzed safe: {safe_path}, and wrote {len(records)} usage records to {output_path}")

def analyze_one_project(project_root, package_analysis_result_path):
    if os.path.isdir(project_root):
        records = analyze_with_tags(project_root)
        records.sort(key=lambda r: (
            r.get("package", ""),
            tuple(r.get("chain", [])),
            r.get("lineno", float('inf'))
            ))
        output_path = pathlib.Path(package_analysis_result_path)
        os.makedirs(output_path.parent, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as out:
            for rec in records:
                out.write(json.dumps(rec) + "\n")
        print(f"Analyzed vuln: {project_root}, and wrote {len(records)} usage records to {output_path}")

    


if __name__ == "__main__":
    PROJECT_CWE = "cwe94"
    PROJECT_REPO = "repos_1-expression_evaluator"
    PROJECT_STATE = "vuln"
    PATH_PROJECT_ROOT = f"/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/{PROJECT_CWE}/{PROJECT_REPO}/{PROJECT_STATE}"
    RESULT_PATH = f"C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/package_extractor_results/{PROJECT_CWE}/{PROJECT_REPO}/{PROJECT_STATE}/usages.jsonl"
    internal_imports, external_imports = find_imports(PATH_PROJECT_ROOT)
    print("Internal imports:", sorted(internal_imports))
    print("External imports:", sorted(external_imports))
    # Adjust this to your project root
    

    #analyze_all_samples(base_dir="/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/")
    analyze_one_project(PATH_PROJECT_ROOT, RESULT_PATH)
    print(BUILTIN_FUNC_NAMES)
    print(BUILTIN_TYPE_NAMES)
    