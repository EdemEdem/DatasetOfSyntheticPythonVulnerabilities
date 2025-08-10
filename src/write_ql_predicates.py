import json
import os
import pathlib
QL_param_source_body ="""\
    (
        param.getLocation().getFile().getAbsolutePath().matches("%{filepath}%") and
        param.getLocation().getStartLine() = {startline} and
        param.getName().matches("{node_name}")
    )
    """
QL_metehod_attribute_source_body ="""\
    (
        attr.getLocation().getFile().getAbsolutePath().matches("%{filepath}%") and
        attr.getLocation().getStartLine() = {startline} and
        attr.(Attribute).getName().matches("{node_name}")
    )
    """
QL_method_call_source_body ="""\
    (
        call.getLocation().getFile().getAbsolutePath().matches("%{filepath}%") and
        call.getLocation().getStartLine() = {startline} and
        call.getFunc() instanceof Attribute and
        call.getFunc().(Attribute).getName().matches("{node_name}")
    )
    """
QL_source_predicate ="""\
    import python
    predicate isLLMDetectedAttrSource(Attribute attr) {{
	{attr_sources_body}	
	}}
 
    predicate isLLMDetectedCallSource(Call call) {{
	{call_sources_body}	
	}}
 
    predicate isLLMDetectedParamSource(Parameter param) {{
	{param_sources_body}	
	}}
    """
QL_method_call_sink_body ="""\
    (
        call.getLocation().getFile().getAbsolutePath().matches("%{filepath}%") and
        call.getLocation().getStartLine() = {startline} and
        call.getFunc() instanceof Attribute and
        call.getFunc().(Attribute).getName().matches("{node_name}")
    )
    """
QL_method_call_arg_sink_body ="""\
    (
		expr.getLocation().getFile().getAbsolutePath().matches("%{filepath}%") and
		expr.getLocation().getStartLine() = {startline} and
		exists( Call call |
			call.getLocation().getFile().getAbsolutePath().matches("%{filepath}%") and
			call.getLocation().getStartLine() = {startline_call} and
			call.getFunc().(Attribute).getName().matches("{call_name}") and
			expr = call.getArg({arg_pos})
		)
	)
    """
QL_sink_predicate ="""\
    import python
    predicate isLLMDetectedSinkFunctionCall(Call call) {{
	{call_sinks_body}	
	}}
    
    predicate isLLMDetectedSinkFunctionArg(Expr expr) {{
	{arg_sinks_body}	
	}}
    """
class PredicateWriter:
    def __init__(self,
                 input_source_path: str,
                 input_sink_path: str,
                 output_source_qll_file: str,
                 output_sink_qll_file: str,
                 llm_specifications_dir_path: str,
                 usage_nodes_path: str
                ):
        self.input_source_path = input_source_path
        self.input_sink_path = input_sink_path
        self.output_source_qll_file = output_source_qll_file
        self.output_sink_qll_file = output_sink_qll_file
        self.llm_specifications_dir_path = llm_specifications_dir_path
        self.usage_nodes_path = usage_nodes_path
    
    def get_call_from_id(self, call_id, node_dicts):
        for dict in node_dicts:
            if dict["node_type"] == "Call" and dict["call_id"] == call_id:
                call = dict
        return call
        
    def create_source_predicates(self):
        node_dicts = self.read_source_inputs()
        call_fragments = []
        attr_fragments = []
        param_fragments = []
        for node_dict in node_dicts:
            node_name = node_dict["chain"][-1]
            node_type = node_dict["node_type"]
            filepath = node_dict["file"]
            line = node_dict["lineno"]
            
            if node_type == "Call":
                call_fragments.append(
                    QL_method_call_source_body.format(
                        filepath=filepath,
                        startline=line,
                        node_name=node_name
                        )
                    )
            elif node_type == "Attribute":
                attr_fragments.append(
                    QL_metehod_attribute_source_body.format(
                        filepath=filepath,
                        startline=line,
                        node_name=node_name
                        )
                    )
            elif node_type == "param":
                param_name = node_dict["name"]
                param_fragments.append(
                    QL_param_source_body.format(
                        filepath=filepath,
                        startline=line,
                        node_name=param_name
                        )
                    )
        source_calls = " or ".join(call_fragments)
        source_attributes = " or ".join(attr_fragments)
        source_params = " or ".join(param_fragments)
        if not source_calls:
            source_calls = "1=0"
        if not source_attributes:
            source_attributes = "1=0"
        if not source_params:
            source_params = "1=0"
        
        return QL_source_predicate.format(
            attr_sources_body=source_attributes,
            call_sources_body=source_calls,
            param_sources_body=source_params
            )

    def read_source_inputs(self):
        with open(self.input_source_path, "r") as f:
            return [json.loads(line) for line in f]
    
    def write_source_qll_file(self):
        with open(self.output_source_qll_file, "w") as f:
            #write all the source predicates to file
            f.write(self.create_source_predicates())
    
    def create_sink_predicates(self):
        node_dicts = self.read_sink_inputs()
        call_fragments = []
        arg_fragments = []
        for node_dict in node_dicts:
            node_name = node_dict["chain"][-1]
            node_type = node_dict["node_type"]
            filepath = node_dict["file"]
            line = node_dict["lineno"]
            
            if node_type == "Call":
                call_fragments.append(
                    QL_method_call_sink_body.format(
                        filepath=filepath,
                        startline=line,
                        node_name=node_name
                        )
                    )
            if node_type == "arg":
                call_node = self.get_call_from_id(node_dict["call_id"], node_dicts)
                call_name = call_node["chain"][-1]
                startline_call = call_node["lineno"]
                arg_pos = node_dict["arg_pos"]
                arg_fragments.append(
                    QL_method_call_arg_sink_body.format(
                        filepath=filepath,
                        startline=line,
                        node_name=node_name,
                        call_name=call_name,
                        startline_call=startline_call,
                        arg_pos=arg_pos
                        )
                    )
        sink_calls = " or ".join(call_fragments)
        sink_args = " or ".join(arg_fragments)
        if not sink_calls:
            sink_calls = "1=0"
        if not sink_args:
            sink_args = "1=0"
        
        return QL_sink_predicate.format(
            call_sinks_body=sink_calls,
            arg_sinks_body=sink_args
            )

    def read_sink_inputs(self):
        with open(self.input_sink_path, "r") as f:
            return [json.loads(line) for line in f]
    
    def write_sink_qll_file(self):
        with open(self.output_sink_qll_file, "w") as f:
            #write all the source predicates to file
            f.write(self.create_sink_predicates())
            
    def process_llm_specifications(self):
        llm_specifications_dir_path = self.llm_specifications_dir_path
        usage_nodes_path = self.usage_nodes_path
        # 1) collect sink/source operation names
        sinks = []
        sources = []
        name_pattern = "pre_chain"
        for filename in os.listdir(llm_specifications_dir_path):
            file_path = os.path.join(llm_specifications_dir_path, filename)
            if not filename.endswith(".jsonl") and file_path:
                print(f"filtered out filename: {filename}")
                continue
            if name_pattern not in filename:
                print(f"filtered out filename: {filename}")
                continue
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        spec = json.loads(line)
                    except json.JSONDecodeError:
                        print(line)
                        continue
                    for key, val in spec.items():
                        if val == "sink":
                            sinks.append(key)
                        elif val == "source":
                            sources.append(key)
                # 2) load usage nodes
        nodes = []
        with open(usage_nodes_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    nodes.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        # 3) split nodes by whether their chain is in sinks or sources
        sink_nodes = []
        source_nodes = []
        for node in nodes:
            chain_key = node.get("chain")
            chain = " ".join(chain_key)
            if chain in sinks:
                sink_nodes.append(node)
            if chain in sources:
                source_nodes.append(node)
                
        # 4) write out filtered nodes as JSONL
        os.makedirs(os.path.dirname(self.input_sink_path), exist_ok=True)
        with open(self.input_sink_path, "w", encoding="utf-8") as f:
            for n in sink_nodes:
                f.write(json.dumps(n) + "\n")
            print(f"Wrote {len(sink_nodes)} entries to {self.input_sink_path}")
        os.makedirs(os.path.dirname(self.input_source_path), exist_ok=True)
        with open(self.input_source_path, "w", encoding="utf-8") as f:
            for n in source_nodes:
                f.write(json.dumps(n) + "\n")
            print(f"Wrote {len(source_nodes)} entries to {self.input_source_path}")
        return

            
            
def wirte_for_all_in_cwe(cwe):
    node_extraction_dir="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/package_extractor_results"
    cwe_dir_path = pathlib.Path(node_extraction_dir) / cwe
    for project_dir in os.listdir(cwe_dir_path):
        project_path = os.path.join(cwe_dir_path, project_dir)
        if os.path.isdir(project_path):
            for state in ["vuln", "safe"]:
                path = os.path.join(project_path, state)
                if os.path.isdir(path):
                    input_source_path = pathlib.Path(path) / "source_usages.jsonl"
                    input_sink_path = pathlib.Path(path) / "sink_usages.jsonl"
                    output_source_qll_file = pathlib.Path(path) / "TestSources.qll"
                    output_sink_qll_file = pathlib.Path(path) / "TestSinks.qll"
                    usage_nodes_path = pathlib.Path(path) / "usages_sorted.qll"
                    llm_specifications_dir_path = "C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/llm_results/results"
                    write_for_one_project(input_source_path, input_sink_path, output_source_qll_file, output_sink_qll_file, llm_specifications_dir_path, usage_nodes_path)

        
def write_for_one_project(input_source_path, input_sink_path, output_source_qll_path, output_sink_qll_file, llm_specifications_dir_path, usage_nodes_path):
    predicateWriter = PredicateWriter(
        input_source_path=input_source_path,
        input_sink_path=input_sink_path,
        output_source_qll_file=output_source_qll_path,
        output_sink_qll_file=output_sink_qll_file,
        llm_specifications_dir_path=llm_specifications_dir_path,
        usage_nodes_path=usage_nodes_path
	)

    predicateWriter.write_source_qll_file()
    predicateWriter.write_sink_qll_file()


if __name__ == "__main__":
    #wirte_for_all_in_cwe("cwe89")
    path="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/package_extractor_results/cwe89/repos_3/vuln"
    input_source_path = f"{path}/source_usages.jsonl"
    input_sink_path = f"{path}/sink_usages.jsonl"
    output_source_qll_file =f"{path}/TestSources.qll"
    output_sink_qll_file = f"{path}/TestSinks.qll"
    usage_nodes_path = "C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/package_extractor_results/cwe89/repos_3/vuln/usages_sorted.jsonl"
    llm_specifications_dir_path = "C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/llm_results/results"
    predicateWriter = PredicateWriter(
        input_source_path=input_source_path,
        input_sink_path=input_sink_path,
        output_source_qll_file=output_source_qll_file,
        output_sink_qll_file=output_sink_qll_file,
        llm_specifications_dir_path=llm_specifications_dir_path,
        usage_nodes_path=usage_nodes_path
	)
    predicateWriter.process_llm_specifications()