import python

/**
 * Finds occurrences of SQL queries that use string formatting or concatenation
 * with unsanitized user input, which can lead to SQL injection.
 */
from FunctionCall call, DataFlow::Node source, DataFlow::Node sink
where
  call.getTarget().getName() = "execute" and
  source.flowsTo(sink) and
  (
    sink.asExpr().toStringExpr() = source.asExpr().toStringExpr()
  )
select sink, source, "Possible SQL Injection vulnerability"
