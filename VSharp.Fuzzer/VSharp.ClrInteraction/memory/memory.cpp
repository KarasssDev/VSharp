#include "memory.h"
#include "stack.h"
#include "logging.h"
#include <mutex>

using namespace vsharp;

ThreadID currentThreadNotConfigured() {
    throw std::logic_error("Current thread getter is not configured!");
}

std::function<ThreadID()> vsharp::currentThread(&currentThreadNotConfigured);


ThreadID lastThreadID = 0;
Stack *currentStack = nullptr;

inline void switchContext() {
    ThreadID tid = currentThread();
    if (tid != lastThreadID) {
        lastThreadID = tid;
        Stack *&s = stacks[tid];
        if (!s) s = new Stack();
        currentStack = s;
    }
}

Stack &vsharp::stack() {
    switchContext();
    return *currentStack;
}

StackFrame &vsharp::topFrame() {
    switchContext();
    return currentStack->topFrame();
}

bool _mainLeft = false;

void vsharp::mainLeft() {
    _mainLeft = true;
}

bool vsharp::isMainLeft() {
    return _mainLeft;
}

bool instrumentationEnabled = true;

bool vsharp::instrumentingEnabled() {
    return instrumentationEnabled;
}

void vsharp::enableInstrumentation() {
    if (instrumentationEnabled)
        LOG(tout << "WARNING: enableInstrumentation, instrumentation already enabled" << std::endl);
    instrumentationEnabled = true;
}

void vsharp::disableInstrumentation() {
    if (!instrumentationEnabled)
        LOG(tout << "WARNING: disableInstrumentation, instrumentation already disabled" << std::endl);
    instrumentationEnabled = false;
}

bool mainEntered = false;

void vsharp::enterMain() {
    assert(!mainEntered);
    mainEntered = true;
}

bool vsharp::isMainEntered() {
    return mainEntered;
}

std::mutex mutex;

void vsharp::getLock() {
    mutex.lock();
}

void vsharp::freeLock() {
    mutex.unlock();
}

void vsharp::setExpectedCoverage(const CoverageNode *expectedCoverage) {
    expectedCoverageStep = expectedCoverage;
    expectedCoverageExpirated = !expectedCoverage;
}

bool vsharp::addCoverageStep(OFFSET offset, bool &stillExpectsCoverage) {
    int threadToken = 0; // TODO: support multithreading
    StackFrame &top = topFrame();
    int moduleToken = top.moduleToken();
    mdMethodDef methodToken = top.resolvedToken();
    if (lastCoverageStep && lastCoverageStep->moduleToken == moduleToken && lastCoverageStep->methodToken == methodToken &&
            lastCoverageStep->offset == offset && lastCoverageStep->threadToken == threadToken)
    {
        stillExpectsCoverage = !expectedCoverageExpirated;
        expectedCoverageExpirated = !expectedCoverageStep;
        return true;
    }
    if (expectedCoverageStep) {
        stillExpectsCoverage = true;
        if (expectedCoverageStep->moduleToken != moduleToken || expectedCoverageStep->methodToken != methodToken ||
                expectedCoverageStep->offset != offset || expectedCoverageStep->threadToken != threadToken) {
            LOG(tout << "Path divergence detected: expected method token " << HEX(expectedCoverageStep->methodToken) <<
                ", got method token " << HEX(methodToken) << ", expected offset " << HEX(expectedCoverageStep->offset) <<
                ", got offset " << HEX(offset) << std::endl);
            return false;
        }
        expectedCoverageStep = expectedCoverageStep->next;
    } else {
        stillExpectsCoverage = false;
        expectedCoverageExpirated = true;
    }
    LOG(tout << "Cover offset " << offset << " of " << HEX(methodToken));
    CoverageNode *newStep = new CoverageNode{moduleToken, methodToken, offset, threadToken, nullptr};
    if (lastCoverageStep) {
        lastCoverageStep->next = newStep;
    }
    lastCoverageStep = newStep;
    if (!newCoverageNodes) {
        newCoverageNodes = newStep;
    }
    return true;
}

const CoverageNode *vsharp::flushNewCoverageNodes() {
    const CoverageNode *result = newCoverageNodes;
    newCoverageNodes = nullptr;
    return result;
}

unsigned CoverageNode::size() const {
    return staticSizeOfCoverageNode;
}

int CoverageNode::count() const {
    if (!next)
        return 1;
    return next->count() + 1;
}

void CoverageNode::serialize(char *&buffer) const {
    WRITE_BYTES(int, buffer, moduleToken);
    WRITE_BYTES(mdMethodDef, buffer, methodToken);
    WRITE_BYTES(OFFSET, buffer, offset);
    WRITE_BYTES(int, buffer, threadToken);
}

void CoverageNode::deserialize(char *&buffer) {
    moduleToken = READ_BYTES(buffer, int);
    methodToken = READ_BYTES(buffer, mdMethodDef);
    offset = READ_BYTES(buffer, OFFSET);
    threadToken = READ_BYTES(buffer, int);
}
