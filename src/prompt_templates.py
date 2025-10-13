PACKAGE_PROMPT_SINK_AND_SOURCE = """You are going to analyze the usage of the package {package}.
You will be supplied with different function calls, arguments, attributes that's been imported from the {package} library and used in a program.
Your job is to define which of this nodes that can be a Source, Sink or none for the weakness {cwe}.
A source is a place where malicious data can enter thh program.
A sink is a dangerous function that when executed with malicous data the vulnerabilty is present.

Reply in json with either source, sink or none for each of these usages:
{body}
"""
PACKAGE_PROMPT_BUILTIN = """You are going to analyze the usage built-in python fuctions and other built nodes.
You will be supplied with different function calls, arguments, attributes that's been which have not been imported, but have been used in a python program.
Keep in mind that there might've been some errors upstream, so if you se a node that you don't recognize as built-python node you can be confident that it's not a built in node, and insted comes from another area of the system.
For node's that you don't recognize as built-in python nodes, you can safely classify them as "none".
Your job is to define which of this nodes that can be a Source, Sink or none for the weakness {cwe}.
A source is a place where malicious data can enter thh program.
A sink is a dangerous function that when executed with malicous data the vulnerabilty is present.

Reply in json with either source, sink or none for each of these usages:
{body}
"""

PACKAGE_PROMPT_SYSTEM_PROMPT = """
"You are a application security assitant. Help the user identify which of these library usages that are potential sources and sinks in vulnerable dataflows, 
and output them in JSON format. 

EXAMPLE INPUT: 
You are going to analyze the usage of the package foo.
Define which of the following nodes that can be a Source, Sink or none for the weakness CWE 89 (SQL injection):
foo bar
foo baz
foo qux

EXAMPLE JSON OUTPUT:
{
  "foo bar": "none",
  "foo bar quux": "none",
  "foo bar quux baz": "sink",
  "foo corge": "none",
  "foo grault": "sink",
  "foo grault plugh": "source"
}
"""


FLOW_PROMPT_SYSTEM_PROMPT = """
"You are a application security assitant. Help the user identify if this dataflow is truely vulnerable to {cwe} or not.
Look for posible sanitizers on the dataflow. {cwe} is commonly prevented by {sanitizer_context}
Reply with Yes if the dataflow is vulnerable, and No if it's not vulnerable, also provide a reason for your judgement, and output them in JSON format.

EXAMPLE JSON OUTPUT:
{{
  "judgement": "yes",
  "reason": "In this dataflow a malicous input can arrive at the source, and travel through all the nodes and arrive at the sink without being neutralized or stopped by a filter. No instance of {sanitizer_context} or similar seems to take place through out the whole dataflow",
}}

"""