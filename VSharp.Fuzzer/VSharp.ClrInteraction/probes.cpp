#include "probes.h"

using namespace vsharp;

mdSignature ThreadSignature::getSig() {
    ThreadID thread = currentThread();
    mutex.lock();
    auto pos = threadMapping.find(thread);
    if (pos == threadMapping.end()) {
        tout << "returning zero signature on thread" << thread << std::endl;
        return 0;
    }
    mutex.unlock();
    return pos->second;
}

void ThreadSignature::setSig(mdSignature sig) {
    ThreadID thread = currentThread();
    mutex.lock();
    threadMapping[thread] = sig;
    mutex.unlock();
}

CoverageProbes* vsharp::getProbes() {
    return &coverageProbes;
}

void vsharp::InitializeProbes() {
    auto covProbes = vsharp::getProbes();
    covProbes->Track_Coverage_Addr = (INT_PTR) &Track_Coverage;
    covProbes->Branch_Addr = (INT_PTR) &Branch;
    covProbes->Track_Enter_Addr = (INT_PTR) &Track_Enter;
    covProbes->Track_EnterMain_Addr = (INT_PTR) &Track_EnterMain;
    covProbes->Track_Leave_Addr = (INT_PTR) &Track_Leave;
    covProbes->Track_LeaveMain_Addr = (INT_PTR) &Track_LeaveMain;
    covProbes->Finalize_Call_Addr = (INT_PTR) &Finalize_Call;
    covProbes->Track_Call_Addr = (INT_PTR) &Track_Call;
    covProbes->Track_Tailcall_Addr = (INT_PTR) &Track_Tailcall;
    tout << "probes initialized" << std::endl;
}

size_t CoverageRecord::sizeNode() const {
    return sizeof(OFFSET) + sizeof(CoverageEvents) + sizeof(int);
}

size_t CoverageRecord::size() const {
    size_t allNodesSize = 0;
    auto currentNode = this;
    while (currentNode != nullptr) {
        allNodesSize += currentNode->sizeNode();
        currentNode = currentNode->next;
    }
    return allNodesSize;
}

void CoverageRecord::serialize(char *&buffer) const {
    WRITE_BYTES(OFFSET, buffer, offset);
    WRITE_BYTES(CoverageEvents, buffer, event);
    WRITE_BYTES(int, buffer, methodId);
}

static CoverageProbes vsharp::coverageProbes;

static bool vsharp::areProbesEnabled = false;

static std::vector<CoverageHistory*> vsharp::coverageHistory = std::vector<CoverageHistory*>(0);

static CoverageHistory *vsharp::currentCoverage = nullptr;

void vsharp::enableProbes() {
    getLock();
    tout << "enabling probes" << std::endl;
    if (areProbesEnabled) tout << "PROBES ARE ALREADY ENABLED!" << std::endl;
    areProbesEnabled = true;
    freeLock();
}

void vsharp::disableProbes() {
    getLock();
    tout << "disabling probes" << std::endl;
    areProbesEnabled = false;
    freeLock();
}

CoverageHistory::CoverageHistory(OFFSET offset) {
    head = new CoverageRecord({offset, EnterMain, nullptr, currentThread(), 0});
}

void CoverageHistory::AddCoverage(OFFSET offset, CoverageEvents event, int methodId=-1) {
    getLock();
    if (methodId != -1 && visitedMethods.find(methodId) == visitedMethods.end()) {
        visitedMethods.insert(methodId);
    }
    auto nextCoverage = new CoverageRecord({offset, event, nullptr, currentThread(), methodId});
    head->next = nextCoverage;
    head = nextCoverage;
    freeLock();
}

size_t CoverageHistory::size() const {
    size_t sizeBytes = 0;

    // visited methods: int for the amount, then one after another
    sizeBytes += sizeof(int);
    for (auto el : visitedMethods) {
        sizeBytes += collectedMethods[el].size();
    }

    // coverage records: int for the amount, then the whole history
    sizeBytes += sizeof(int);
    sizeBytes += head->size();

    return sizeBytes;
}

void CoverageHistory::serialize(char *&buffer) const {
    int visited = visitedMethods.size();
    WRITE_BYTES(int, buffer, visited);

    // sending only visited methods; changing their ids according to the order they'll be sent in
    std::map<int, int> actualIdToVisitedId;
    int curId = 0;
    for (auto el : visitedMethods) {
        actualIdToVisitedId.insert({el, curId});
        collectedMethods[el].serialize(buffer);
        curId++;
    }

    // remembering the beginning to write the amount later; writing coverage records
    auto beginning = buffer;
    buffer += sizeof(int);
    auto curNode = head;
    int nodes = 0;
    while (curNode != nullptr) {
        // changing methodId before serialization
        if (curNode->methodId != -1) curNode->methodId = actualIdToVisitedId[curNode->methodId];

        curNode->serialize(buffer);
        curNode = curNode->next;
        nodes++;
    }
    WRITE_BYTES(int, beginning, nodes);
}

void vsharp::addCoverage(OFFSET offset, CoverageEvents event, int methodId=-1) {
    if (currentCoverage == nullptr) FAIL_LOUD("adding coverage on uninitialized node!")
    currentCoverage->AddCoverage(offset, event, methodId);
}

void vsharp::trackCoverage(OFFSET offset, bool &stillExpectsCoverage) {
    if (!addCoverageStep(offset, stillExpectsCoverage)) {
        freeLock();
        FAIL_LOUD("Path divergence")
    }
}

size_t MethodInfo::size() const {
    return sizeof(mdMethodDef) + 2 * sizeof(ULONG) + (assemblyNameLength + moduleNameLength) * sizeof(WCHAR);
}

void MethodInfo::serialize(char *&buffer) const {
    WRITE_BYTES(mdMethodDef, buffer, token);

    WRITE_BYTES(ULONG, buffer, assemblyNameLength);
    auto assemblyBytesSize = sizeof(WCHAR) * assemblyNameLength;
    memcpy(buffer, assemblyName, assemblyBytesSize);
    buffer += assemblyBytesSize;

    WRITE_BYTES(ULONG, buffer, moduleNameLength);
    auto moduleBytesSize = sizeof(WCHAR) * moduleNameLength;
    memcpy(buffer, moduleName, moduleBytesSize);
    buffer += moduleBytesSize;
}

static std::vector<MethodInfo> vsharp::collectedMethods;

/// ------------------------------ Probes declarations ---------------------------

void vsharp::Track_Coverage() {
    if (!areProbesEnabled) return;
    tout << "track coverage called" << std::endl;
    bool commandsDisabled;
    trackCoverage(0, commandsDisabled);
}

void vsharp::Branch(OFFSET offset, int methodId) {
    if (!areProbesEnabled) return;
    addCoverage(offset, BranchHit, methodId);
}

void vsharp::Track_Call(OFFSET offset) {
    if (!areProbesEnabled) {
        return;
    }
    addCoverage(offset, Call);
}

void vsharp::Track_Tailcall(OFFSET offset) {
    if (!areProbesEnabled) {
        return;
    }
    // popping frame before tailcall execution
    stackBalanceDown();
    addCoverage(offset, Tailcall);
}

void vsharp::Track_Enter(OFFSET offset, int methodId, int isSpontaneous) {
    if (!areProbesEnabled) {
        return;
    }
    stackBalanceUp();
    addCoverage(offset, Enter, methodId);
}

void vsharp::Track_EnterMain(OFFSET offset, int methodId, int isSpontaneous) {
    enableProbes();
    emptyStacks();
    stackBalanceUp();
    setMainThread();
    currentCoverage = new CoverageHistory(offset);
    coverageHistory.push_back(currentCoverage);
}

void vsharp::Track_Leave(OFFSET offset, int methodId) {
    if (!areProbesEnabled) return;
    addCoverage(offset, Leave, methodId);
    stackBalanceDown();
}

void vsharp::Track_LeaveMain(OFFSET offset, int methodId) {
    disableProbes();
    unsetMainThread();
    addCoverage(offset, LeaveMain);
    // coverage collection ended; waiting for the next EnterMain call
    ::currentCoverage = nullptr;
    if (stackBalanceDown()) FAIL_LOUD("main left but stack is non-empty!")
}

void vsharp::Finalize_Call(OFFSET offset) {
    if (!areProbesEnabled) return;
    tout << "call finalized" << std::endl;
}
