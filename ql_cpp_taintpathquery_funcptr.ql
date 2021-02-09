/**
 * @kind path-problem
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph


predicate userInputFunction(Function f, int i) {
    f.hasGlobalOrStdName("buf_create") and i = 0
    // f.hasGlobalOrStdName("buf_op_buf_print") and i = 1
}
predicate memAccessFunction(Function f, int i) {
    f.hasGlobalOrStdName("printf") and i = 2
}
predicate isTaintExpr(Function f, int i, Expr expr) {
    exists (Call c |
        f = c.getTarget() and
        c.getArgument(i) = expr
    )
}
predicate isTaintPara(Function f, int i, Parameter para) {
        f.getParameter(i) = para
}
predicate isTaintNode(Function f, int i, DataFlow::Node node) { 
    isTaintExpr(f, i, node.asDefiningArgument())
    or
    isTaintExpr(f, i, node.asExpr())
    or
    isTaintPara(f, i, node.asParameter())
    or
    isTaintExpr(f, i, node.asPartialDefinition())
}
class TbdConfig extends TaintTracking::Configuration {
    TbdConfig() {
        this = "TbdConfig"
    }
    override predicate isSource(DataFlow::Node source) {
        exists (Function f, int i |
            userInputFunction(f, i)
            and
            isTaintNode(f, i, source)
        )
    }
    override predicate isSink(DataFlow::Node sink) {
        exists (Function f, int i |
            memAccessFunction(f, i)
            and
            isTaintNode(f, i, sink)
        )
    }
    override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
        TaintTracking::localTaintStep(pred, succ)
        or  // func_ptr(pred) -> func_target(succ)
        exists (VariableCall vc, Function f, int i |
            pred.asExpr() = vc.getArgument(i)
            and
            vc.getVariable().getAnAssignedValue().getAChild*().(FunctionAccess).getTarget() = f
            and
            f.getParameter(i) = succ.asParameter()
        )
        or  // succ.a_field = pred
        exists (Parameter struct, VariableAccess field |
            pred.asParameter() = struct
            and
            struct.getAnAccess() = field.getAChild()
            and
            field = succ.asExpr()
        )
    }
}
from TbdConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode().getLocation(), source, sink, "Taint from " + source.getNode().getFunction().getFile().getBaseName() +
    " to " + sink.getNode().getFunction().getFile().getBaseName()

//The whole query is based on Jonas Jensen's answer:
//https://stackoverflow.com/questions/58164464/semmle-ql-tainttracking-hasflow-problem-with-sources-that-taint-their-argumen/58165322#58165322
