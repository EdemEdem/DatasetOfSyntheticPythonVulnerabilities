import ast
import pathlib
import importlib.util
import os
import json
from collections import defaultdict

# Adjust this to your project root
PROJECT_CWE = "cwe89"
PROJECT_REPO = "repos_1"
PROJECT_STATE = "vuln"
PATH_PROJECT_ROOT = f"/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/{PROJECT_CWE}/{PROJECT_REPO}/vuln"
RESULT_PATH = f"C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/package_extcractor_results/{PROJECT_CWE}/{PROJECT_REPO}/{PROJECT_STATE}"


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
        tree = ast.parse(text, filename=str(py))
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

def analyze_with_tags(root_path):
    class TagTracker(ast.NodeVisitor):
        def __init__(self):
            super().__init__()
            self.alias_to_pkg = {}
            # per-scope: var -> set of pkg tags
            self.env_stack = [defaultdict(set)]
            # var -> list of full chains
            self.project_chains_stack = [defaultdict(list)]
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
        
        def push_scope(self):
            # inherit imports tags and chains
            base_env = self.env_stack[0]
            base_pch = self.project_chains_stack[0]
            new_env = defaultdict(set, {k: set(v) for k, v in base_env.items()})
            new_pch = defaultdict(list, {k: [c[:] for c in v] for k, v in base_pch.items()})
            self.env_stack.append(new_env)
            self.project_chains_stack.append(new_pch)

        def pop_scope(self):
            self.env_stack.pop()
            self.project_chains_stack.pop()

        def extract_base(self, node):
            while isinstance(node, ast.Attribute):
                node = node.value
            return node.id if isinstance(node, ast.Name) else None
        
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

        def visit_FunctionDef(self, node):
            # Handle decorated endpoints: forward decorator import chains to params
            for deco in node.decorator_list:
                deco_chain = self.extract_chain(deco)
                if deco_chain:
                    pkg = deco_chain[0]
                    # only if imported or project chain
                    if pkg in self.import_chains or pkg in self.project_chains:
                        for arg in node.args.args:
                            name = arg.arg
                            # tag parameter
                            self.env[name].add(pkg)
                            # seed parameter chain
                            for base in self.project_chains[pkg]:
                                fullchain = base + deco_chain
                                self.project_chains[name].append(fullchain)
                                # record parameter as source candidate
                                self.records.append({
                                    "file": self.current_file,
                                    "lineno": getattr(arg, 'lineno', node.lineno),
                                    "col": getattr(arg, 'col_offset', node.col_offset),
                                    "node_type": "param","chain": fullchain,
                                    "package": pkg,
                                    "code":self.lines[node.lineno-1].strip(),
                                    "tags": [pkg]
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
                    pkg = deco_chain[0]
                    # only if imported or project chain
                    if pkg in self.import_chains or pkg in self.project_chains:
                        for arg in node.args.args:
                            name = arg.arg
                            # tag parameter
                            self.env[name].add(pkg)
                            # seed parameter chain
                            for base in self.project_chains[pkg]:
                                fullchain = base + deco_chain
                                self.project_chains[name].append(fullchain)
                                # record parameter as source candidate
                                self.records.append({
                                    "file": self.current_file,
                                    "lineno": getattr(arg, 'lineno', node.lineno),
                                    "col": getattr(arg, 'col_offset', node.col_offset),
                                    "node_type": "param","chain": fullchain,
                                    "package": pkg,
                                    "code":self.lines[node.lineno-1].strip(),
                                    "tags": [pkg]
                                })
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
                self.import_chains[name].append([pkg])
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
                if isinstance(rhs, ast.Name) and rhs.id in self.import_chains:
                    self.env[tgt].update(self.env[rhs.id])
                    for c in self.import_chains[rhs.id]:
                        self.project_chains[tgt].append(c[:])
                
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
                    if base in self.import_chains:
                        for c in self.import_chains[base]:
                            # propagate tags from base
                            self.env[tgt].update(self.env[base])
                            # extend chain
                            new_chain = c[:] + [rhs.attr]
                            self.project_chains[tgt].append(new_chain)
                            

                # 3) method call: x = y.attr()
                if isinstance(rhs, ast.Call) and isinstance(rhs.func, ast.Attribute):
                    attr_node = rhs.func
                    base = self.extract_base(attr_node)
                    if base in self.project_chains:
                        for c in self.project_chains[base]:
                            self.env[tgt].update(self.env[base])
                            new_chain = c[:] + [attr_node.attr]
                            self.project_chains[tgt].append(new_chain)
                    if base in self.import_chains:
                        for c in self.import_chains[base]:
                            self.env[tgt].update(self.env[base])
                            new_chain = c[:] + [attr_node.attr]
                            self.project_chains[tgt].append(new_chain)
                
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
                    # Call to imported function
                    elif base in self.import_chains:
                        for c in self.import_chains[base]:
                            self.env[tgt].update(self.env[base])
                            new_chain = c[:] + [func.id]
                            self.project_chains[tgt].append(new_chain)
                    
                # 5) boolean operations: x = a or b
                if isinstance(rhs, ast.BoolOp):
                    for val in rhs.values:
                        base = None
                        if isinstance(val, ast.Name):
                            base = val.id
                        elif isinstance(val, ast.Attribute):
                            base = self.extract_base(val)
                        # propagate tags
                        if base in self.project_chains:
                            for c in self.project_chains[base]:
                                new_chain = c[:] + self.extract_chain(val)
                                self.project_chains[tgt].append(new_chain)
                        elif base in self.import_chains:
                            for c in self.import_chains[base]:
                                new_chain = c[:] + self.extract_chain(val)
                                self.project_chains[tgt].append(new_chain)
            # continue traversal
            self.generic_visit(node)
            
        def visit_Call(self, node):
            func=node.func
            self.call_counter += 1
            if isinstance(func, ast.Attribute):
                self.skip_attrs.add(func)
                base=self.extract_base(func); #method=func.attr
                node_chain = self.extract_chain(func)
                if base in self.project_chains:
                    for bc in self.project_chains[base]:
                        fc=bc[:] + node_chain[1:]
                        pkg=bc[0]
                        self.records.append({"file":self.current_file,"lineno":node.lineno,"col":node.col_offset,
                                             "node_type":"Call","chain":fc,"package":pkg,
                                             "code":self.lines[node.lineno-1].strip(),
                                             "tags":sorted(self.env[base]),"call_id":self.call_counter})
                        #Adding arguments to the records
                        for idx, arg in enumerate(node.args):
                            expr_chain = self.extract_chain(arg)
                            self.records.append({"file":self.current_file,"lineno":arg.lineno,"col":arg.col_offset,
                                             "node_type":"arg","chain":fc,"package":pkg,
                                             "code":self.lines[arg.lineno-1].strip(),
                                             "tags":sorted(self.env[base]), "arg_pos":idx,"call_id":self.call_counter,
                                             "expr_chain":expr_chain})       
                # Case: when some variable has the same name as an imported one. Since I think the project variable will override
                elif base in self.import_chains:
                    for bc in self.import_chains[base]:
                        fc=bc[:] + node_chain
                        pkg=bc[0]
                        self.records.append({"file":self.current_file,"lineno":node.lineno,"col":node.col_offset,
                                             "node_type":"Call","chain":fc,"package":pkg,
                                             "code":self.lines[node.lineno-1].strip(),
                                             "tags":sorted(self.env[base]),"call_id":self.call_counter})
                        for idx, arg in enumerate(node.args):
                            expr_chain = self.extract_chain(arg)
                            self.records.append({"file":self.current_file,"lineno":arg.lineno,"col":arg.col_offset,
                                             "node_type":"arg","chain":fc,"package":pkg,
                                             "code":self.lines[arg.lineno-1].strip(),
                                             "tags":sorted(self.env[base]), "arg_pos":idx,"call_id":self.call_counter,
                                             "expr_chain":expr_chain})
            #A direct call (i.e not a method as above)  since the func node is an ast.Name  
            #func.id is now the base node as it's the only node
            elif isinstance(func,ast.Name) and func.id in self.import_chains:
                for base_chain in self.import_chains[func.id]:
                    fc = base_chain
                    pkg=base_chain[0]
                    self.records.append({"file":self.current_file,"lineno":node.lineno,"col":node.col_offset,
                        "node_type":"Call","chain":fc,"package":pkg,
                        "code":self.lines[node.lineno-1].strip(),
                        "tags":sorted(self.env[func.id]),"call_id":self.call_counter})
                    for idx, arg in enumerate(node.args):
                        expr_chain = self.extract_chain(arg)
                        self.records.append({"file":self.current_file,"lineno":arg.lineno,"col":arg.col_offset,
                                             "node_type":"arg","chain":fc,"package":pkg,
                                             "code":self.lines[arg.lineno-1].strip(),
                                             "tags":sorted(self.env[func.id]), "arg_pos":idx,"call_id":self.call_counter,
                                             "expr_chain":expr_chain})
            ###If it's a wrapper function
            elif isinstance(func,ast.Name) and func.id in self.project_chains:
                for base_chain in self.project_chains[func.id]:
                    fc = base_chain
                    pkg=base_chain[0]
                    self.records.append({"file":self.current_file,"lineno":node.lineno,"col":node.col_offset,
                        "node_type":"Call","chain":fc,"package":pkg,
                        "code":self.lines[node.lineno-1].strip(),
                        "tags":sorted(self.env[func.id]),"call_id":self.call_counter})
                    for idx, arg in enumerate(node.args):
                        expr_chain = self.extract_chain(arg)
                        self.records.append({"file":self.current_file,"lineno":arg.lineno,"col":arg.col_offset,
                                             "node_type":"arg","chain":fc,"package":pkg,
                                             "code":self.lines[arg.lineno-1].strip(),
                                             "tags":sorted(self.env[func.id]), "arg_pos":idx,"call_id":self.call_counter,
                                             "expr_chain":expr_chain})
                    
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
                        "file": self.current_file,
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
                    full_chain = base_chain[:] + node_chain
                    self.records.append({
                        "file": self.current_file,
                        "lineno": node.lineno,
                        "col": node.col_offset,
                        "node_type": "Attribute",
                        "chain": full_chain,
                        "package": base_chain[0],
                        "code": self.lines[node.lineno-1].strip(),
                        "tags": sorted(self.env.get(base, []))
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
                        output_path = pathlib.Path(base_dir) / "package_extractor_results" / cwe / project / "vuln" / "usages.jsonl"
                        os.makedirs(output_path.parent, exist_ok=True)
                        with open(output_path, "w", encoding="utf-8") as out:
                            for rec in records:
                                out.write(json.dumps(rec) + "\n")
                        print(f"Analyzed vuln: {vuln_path}, and wrote {len(records)} usage records to {output_path}")

                    safe_path = os.path.join(project_path, 'safe')
                    if os.path.isdir(safe_path):
                        records = analyze_with_tags(safe_path)
                        output_path = pathlib.Path(base_dir) / "package_extractor_results"  / cwe / project / "safe" / "usages.jsonl"
                        os.makedirs(output_path.parent, exist_ok=True)
                        with open(output_path, "w", encoding="utf-8") as out:
                            for rec in records:
                                out.write(json.dumps(rec) + "\n")
                        print(f"Analyzed safe: {safe_path}, and wrote {len(records)} usage records to {output_path}")


if __name__ == "__main__":
    internal_imports, external_imports = find_imports(PATH_PROJECT_ROOT)
    print("Internal imports:", sorted(internal_imports))
    print("External imports:", sorted(external_imports))
    
    analyze_all_samples(base_dir="/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/")
