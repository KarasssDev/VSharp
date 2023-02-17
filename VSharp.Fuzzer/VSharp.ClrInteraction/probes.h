#ifndef PROBES_H_
#define PROBES_H_

#include "cor.h"
#include "memory/memory.h"
#include "communication/protocol.h"
#include <vector>
#include <algorithm>

#define COND INT_PTR
#define ADDRESS_SIZE sizeof(INT32) + sizeof(UINT_PTR) + sizeof(UINT_PTR) + sizeof(BYTE) + sizeof(BYTE) * 2;
#define BOXED_OBJ_METADATA_SIZE sizeof(INT_PTR)

// TODO: remove these in the future, they're from storage.cpp
#define ArrayLengthOffset sizeof(UINT_PTR)
#define ArrayLengthSize sizeof(INT64)

namespace vsharp {

/// ------------------------------ Commands ---------------------------

// TODO: sometimes ReJit may not be lazy, so need to start it in probes, so here must be ref to Instrumenter
Protocol *protocol = nullptr;
void setProtocol(Protocol *p) {
    protocol = p;
}

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

std::vector<unsigned long long> ProbesAddresses;

int registerProbe(unsigned long long probe) {
    ProbesAddresses.push_back(probe);
    return 0;
}

#define PROBE(RETTYPE, NAME, ARGS) \
    RETTYPE STDMETHODCALLTYPE NAME ARGS;\
    int NAME##_tmp = registerProbe((unsigned long long)&(NAME));\
    RETTYPE STDMETHODCALLTYPE NAME ARGS

PROBE(void, Track_Coverage, (OFFSET offset)) {
    if (!areProbesEnabled) return;
    bool commandsDisabled;
    trackCoverage(offset, commandsDisabled);
}

inline void branch(OFFSET offset) {
    if (!areProbesEnabled) return;
    bool commandsDisabled;
    trackCoverage(offset, commandsDisabled);
}
// TODO: make it bool, change instrumentation
PROBE(void, BrTrue, (OFFSET offset)) { branch(offset); }
PROBE(void, BrFalse, (OFFSET offset)) { branch(offset); }
PROBE(void, Switch, (OFFSET offset)) { branch(offset); }

PROBE(void, Track_Enter, (mdMethodDef token, unsigned moduleToken, unsigned maxStackSize, unsigned argsCount, unsigned localsCount, INT8 isSpontaneous)) {
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
        auto args = new bool[argsCount];
        memset(args, true, argsCount);
        stack.pushFrame(token, token, args, argsCount, false);
        top = &stack.topFrame();
        top->setSpontaneous(true);
        delete[] args;
    }
    top->setEnteredMarker(true);
    top->configure(maxStackSize, localsCount);
    top->setModuleToken(moduleToken);
}

PROBE(void, Track_EnterMain, (mdMethodDef token, unsigned moduleToken, UINT16 argsCount, bool argsConcreteness, unsigned maxStackSize, unsigned localsCount)) {
    enableProbes();
    tout << "entered main" << std::endl;
    Stack &stack = vsharp::stack();
    assert(stack.isEmpty());
    auto args = new bool[argsCount];
    memset(args, argsConcreteness, argsCount);
    stack.pushFrame(token, token, args, argsCount, false);
    Track_Enter(token, moduleToken, maxStackSize, argsCount, localsCount, 0);
    stack.resetPopsTracking();
    enterMain();
}

PROBE(void, Track_Leave, (UINT8 returnValues, OFFSET offset)) {
    if (!areProbesEnabled) return;
    Stack &stack = vsharp::stack();
    StackFrame &top = stack.topFrame();
    stack.popFrame();
    LOG(tout << "Managed leave to frame " << stack.framesCount() << ". After popping top frame stack balance is " << top.count() << std::endl);
}

void leaveMain(OFFSET offset, UINT8 opsCount, INT_PTR ptr=UNKNOWN_ADDRESS) {
    disableProbes();
    Stack &stack = vsharp::stack();
    StackFrame &top = stack.topFrame();
    stack.popFrame();
    // NOTE: main left, further exploration is not needed, so only getting commands
    mainLeft();
}
PROBE(void, Track_LeaveMain_0, (OFFSET offset)) { leaveMain(offset, 0); }
PROBE(void, Track_LeaveMain_4, (INT32 returnValue, OFFSET offset)) { leaveMain(offset, 1); }
PROBE(void, Track_LeaveMain_8, (INT64 returnValue, OFFSET offset)) { leaveMain(offset, 1); }
PROBE(void, Track_LeaveMain_f4, (FLOAT returnValue, OFFSET offset)) { leaveMain(offset, 1); }
PROBE(void, Track_LeaveMain_f8, (DOUBLE returnValue, OFFSET offset)) { leaveMain(offset, 1); }

PROBE(void, Track_LeaveMain_p, (INT_PTR returnValue, OFFSET offset)) { leaveMain(offset, 1); }

PROBE(void, Finalize_Call, (UINT8 returnValues)) {
    if (!areProbesEnabled) return;
    Stack &stack = vsharp::stack();
    if (!stack.topFrame().hasEntered()) {
        // Extern has been called, should pop its frame and push return result onto stack
        stack.popFrame();
        LOG(tout << "Extern left! " << stack.framesCount() << " frames remained" << std::endl);
    }
}

}

#endif // PROBES_H_
