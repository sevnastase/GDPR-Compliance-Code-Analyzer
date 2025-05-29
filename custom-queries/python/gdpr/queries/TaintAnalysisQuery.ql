import python
import semmle.python.dataflow.TaintTracking
import semmle.python.dataflow.DataFlow

class SensitiveToPrintConfig extends TaintTracking::Configuration {
  SensitiveToPrintConfig() { this = "SensitiveToPrint" }

  override predicate isSource(DataFlow::Node source) {
    exists(Expr e |
      e instanceof Name and
      e.toString() in ["email", "ssn", "password", "dob"] and
      source.asExpr() = e
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call c |
      c.getCalleeName() = "print" and
      sink.asExpr() = c.getArgument(0)
    )
  }
}

from SensitiveToPrintConfig cfg, DataFlow::Node src, DataFlow::Node sink
where cfg.hasFlow(src, sink)
select sink, "Sensitive data flows into print()"
