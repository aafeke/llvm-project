#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"

using namespace clang;
using namespace ento;
namespace {
class TestChecker : public Checker<check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};
}

void TestChecker::checkPostCall(const CallEvent &Call,
                                   CheckerContext &C) const {

  if(const IdentifierInfo *II = Call.getCalleeIdentifier())
    if(!II->isStr("printf"))
      return;

    // No idea what this check does
    if(!BT)
      BT.reset (new BugType (this, "Call to printf", "Example checker" ));

  // If argument is a call to another fucntion this line will crash the analyzer.
  
  for(unsigned int i = 0; i < Call.getNumArgs(); i++) {
    QualType T = Call.getArgExpr(i)->getType();

    if(!T.isNull() && T->isPointerType()) {
      const ento::SVal sval = Call.getArgSVal(i);

      if(sval.isZeroConstant()) {
        ExplodedNode *N = C.generateErrorNode();

        auto Report = std::make_unique<PathSensitiveBugReport>(*BT, "Portability Warning", N);
        C.emitReport(std::move(Report));
      }
    }
  }
}

void ento::registerTestChecker(CheckerManager &mgr){
  mgr.registerChecker<TestChecker>();
}

bool ento::shouldRegisterTestChecker(const CheckerManager &mgr) { return true; }