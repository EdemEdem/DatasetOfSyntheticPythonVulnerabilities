/**
 * @id llm-taint-flow-cwe89
 * @name Taint flow to LLM sink (CWE-89)
 * @kind path-problem
 * @problem.severity error
 * @tags security
 */


import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
import TestSources
import TestSinks


module LlmTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // a data‐flow node is a source if it corresponds to one of your Call expressions
    exists(Attribute a |
      isLLMDetectedAttrSource(a) and
      source.asExpr() = a
    ) or
	exists(Call c |
      isLLMDetectedCallSource(c) and
      source.asExpr() = c
    ) or
	exists(Parameter p |
	  isLLMDetectedParamSource(p) and
	  source.asExpr() = p
	)
  }
  predicate isSink(DataFlow::Node sink) {
    exists(Call c |
      isLLMDetectedSinkFunctionCall(c) and
      sink.asExpr() = c
    ) or isLLMDetectedSinkFunctionArg(sink.asExpr())
	or exists(Keyword kw |
    isLLMDetectedSinkFunctionKwarg(kw) and
    sink = DataFlow::exprNode(kw.getValue())
  )
  }
}

module LlmTaintFlow = TaintTracking::Global<LlmTaintConfig>;
import LlmTaintFlow::PathGraph

from LlmTaintFlow::PathNode source, LlmTaintFlow::PathNode sink
where LlmTaintFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This $@ is written to an sql query.", source.getNode(),
  "potentially dangerous execution of sql-query built on usersupplied data"