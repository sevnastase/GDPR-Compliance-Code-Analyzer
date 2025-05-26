import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.SqlInjection

class SensitiveDataFlow extends TaintTracking::Configuration {
  SensitiveDataFlow() { this = "SensitiveDataFlow" }

  override predicate isSource(DataFlow::Node source) {
    exists(string name |
      name = source.asExpr().(Name).getId() and
      isSensitiveName(name)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
  exists(Call call |
    sink.asExpr() = call.getAnArg() and
    (
      // ...existing code...
      call.getFunc().(Name).getId() in [
        "print", "log", "jsonify", "redirect", "send_file",
        "render_template", "make_response"
      ] or
      call.getFunc().(Attribute).getName() in [
        "info", "debug", "error", "warning", "critical",
        "execute", "executemany"  // SQL operations
      ]
    )
  )
}

from SensitiveDataFlow config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select source, sink, "Sensitive data flow from $@ to $@.",
    source.getNode(), "source",
    sink.getNode(), "sink"