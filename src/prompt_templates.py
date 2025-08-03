PACKAGE_PROMPT_SINK_AND_SOURCE = """You are going to analyze the usage of the package {package}.
You will be supplied with different function calls, arguments, attributes that's been imported from the {package} library and used in a program.
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
You are going to analyze the usage of the package click.
Define which of the following nodes that can be a Source, Sink or none for the weakness CWE 89 (SQL injection):
click command
click echo
click option

EXAMPLE JSON OUTPUT:
{
  "click command": "none",
  "click echo": "sink",
  "click option": "source"
}
"""