import json
QL_metehod_param_source_body ="""\
    (
        attr.getLocation().getFile().getAbsolutePath().matches("%{filepath}%") and
        attr.getLocation().getStartLine() = {startline} and
        attr.(Attribute).getName().matches("{node_name}")
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
    """
QL_method_call_sink_body ="""\
    (
        call.getLocation().getFile().getAbsolutePath().matches("%{filepath}%") and
        call.getLocation().getStartLine() = {startline} and
        call.getFunc() instanceof Attribute and
        call.getFunc().(Attribute).getName().matches("{node_name}")
    )
    """
QL_sink_predicate ="""\
    import python
    predicate isLLMDetectedSink(Call call) {{
	{call_sinks_body}	
	}}
    """
class PredicateWriter:
    def __init__(self,
                 input_source_path: str,
                 inputsink_path: str,
                 project_root_path: str,
                 output_source_qll_file: str,
                 output_sink_qll_file: str
                ):
        self.input_source_path = input_source_path
        self.input_sink_path = inputsink_path
        self.project_root_path = project_root_path
        self.output_source_qll_file = output_source_qll_file
        self. output_sink_qll_file = output_sink_qll_file
        
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
                param_fragments.append(
                    QL_method_call_sink_body.format(
                        filepath=filepath,
                        startline=line,
                        node_name=node_name
                        )
                    )
        source_calls = " or ".join(call_fragments)
        source_attributes = " or ".join(attr_fragments)
        return QL_source_predicate.format(
            attr_sources_body=source_attributes,
            call_sources_body=source_calls
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
                arg_fragments.append(
                    QL_method_call_sink_body.format(
                        filepath=filepath,
                        startline=line,
                        node_name=node_name
                        )
                    )
        sink_calls = " or ".join(call_fragments)
        return QL_sink_predicate.format(
            call_sinks_body=sink_calls
            )

    def read_sink_inputs(self):
        with open(self.input_sink_path, "r") as f:
            return [json.loads(line) for line in f]
    
    def write_sink_qll_file(self):
        with open(self.output_sink_qll_file, "w") as f:
            #write all the source predicates to file
            f.write(self.create_sink_predicates())

if __name__ == "__main__":
    predicateWriter = PredicateWriter(
        input_source_path="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/package_extcractor_results/cwe89/repos_1/vuln/source_usages.jsonl",
        inputsink_path="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/package_extcractor_results/cwe89/repos_1/vuln/sink_usages.jsonl",
        project_root_path="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/cwe89/repos_1/vuln",
        output_source_qll_file="C:/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/qlpacks/codeql/python-queries/1.3.0/myQueriesForResearch/TestSources.qll",
        output_sink_qll_file="C:/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/qlpacks/codeql/python-queries/1.3.0/myQueriesForResearch/TestSinks.qll"
	)
    predicateWriter.write_source_qll_file()
    predicateWriter.write_sink_qll_file()