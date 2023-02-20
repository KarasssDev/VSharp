#ifndef PROBES_H_
#define PROBES_H_

#include "logging.h"
#include "memory/memory.h"
#include <vector>
#include <algorithm>

namespace vsharp {

/// ------------------------------ Commands ---------------------------

bool areProbesEnabled = false;

void enableProbes() {
    areProbesEnabled = true;
}

void disableProbes() {
    areProbesEnabled = false;
}

void trackCoverage(OFFSET offset, bool &stillExpectsCoverage) {
    if (!addCoverageStep(offset, stillExpectsCoverage)) {
        freeLock();
        FAIL_LOUD("Path divergence")
    }
}

/// ------------------------------ Probes declarations ---------------------------

void Track_Coverage(OFFSET offset) {
    tout << "Track_Coverage" << std::endl;
    if (!areProbesEnabled) return;
    bool commandsDisabled;
    trackCoverage(offset, commandsDisabled);
}

INT_PTR Track_Coverage_Addr = (INT_PTR) &Track_Coverage;
mdSignature Track_Coverage_Sig = 0;

void Branch(OFFSET offset) {
    if (!areProbesEnabled) return;
    bool commandsDisabled;
    trackCoverage(offset, commandsDisabled);
}

INT_PTR Branch_Addr = (INT_PTR) &Branch;
mdSignature Branch_Addr_Sig = 0;

// TODO: add Call probe

void Track_Enter(mdMethodDef token, unsigned moduleToken, INT8 isSpontaneous) {
    LOG(tout << "Track_Enter, token = " << HEX(token) << std::endl);
    if (!areProbesEnabled) {
        LOG(tout << "probes are disalbed; skipped");
        return;
    }
    Stack &stack = vsharp::stack();
    StackFrame *top = stack.isEmpty() ? nullptr : &stack.topFrame();
    unsigned expected = stack.isEmpty() ? 0xFFFFFFFFu : top->resolvedToken();
    if (expected == token || !expected && !isSpontaneous) {
        LOG(tout << "Frame " << stack.framesCount() <<
                    ": entering token " << HEX(token) <<
                    ", expected token is " << HEX(expected) << std::endl);
        if (!expected) top->setResolvedToken(token);
        top->setSpontaneous(false);
    } else {
        LOG(tout << "Spontaneous enter! Details: expected token "
                 << HEX(expected) << ", but entered " << HEX(token) << std::endl);
        stack.pushFrame(token, token);
        top = &stack.topFrame();
        top->setSpontaneous(true);
    }
    top->setEnteredMarker(true);
    top->setModuleToken(moduleToken);
}

INT_PTR Track_Enter_Addr = (INT_PTR) &Track_Enter;
mdSignature Track_Enter_Sig = 0;

void Track_EnterMain(mdMethodDef token, unsigned moduleToken) {
    enableProbes();
    tout << "entered main" << std::endl;
    Stack &stack = vsharp::stack();
    assert(stack.isEmpty());
    stack.pushFrame(token, token);
    Track_Enter(token, moduleToken, 0);
    enterMain();
}

INT_PTR Track_EnterMain_Addr = (INT_PTR) &Track_EnterMain;
mdSignature Track_EnterMain_Sig = 0;

void Track_Leave(OFFSET offset) {
    if (!areProbesEnabled) return;
    Stack &stack = vsharp::stack();
    StackFrame &top = stack.topFrame();
    stack.popFrame();
    LOG(tout << "Managed leave to frame " << stack.framesCount() << std::endl);
}

INT_PTR Track_Leave_Addr = (INT_PTR) &Track_Leave;
mdSignature Track_Leave_Sig = 0;

void Track_LeaveMain(OFFSET offset) {
    disableProbes();
    Stack &stack = vsharp::stack();
    StackFrame &top = stack.topFrame();
    stack.popFrame();
    // NOTE: main left, further exploration is not needed, so only getting commands
    mainLeft();
}

INT_PTR Track_LeaveMain_Addr = (INT_PTR) &Track_LeaveMain;
mdSignature Track_LeaveMain_Sig = 0;

void Finalize_Call(OFFSET offset) {
    if (!areProbesEnabled) return;
    Stack &stack = vsharp::stack();
    if (!stack.topFrame().hasEntered()) {
        // Extern has been called, should pop its frame and push return result onto stack
        stack.popFrame();
        LOG(tout << "Extern left! " << stack.framesCount() << " frames remained" << std::endl);
    }
}

INT_PTR Finalize_Call_Addr = (INT_PTR) &Finalize_Call;
mdSignature Finalize_Call_Sig = 0;

}

#endif // PROBES_H_
