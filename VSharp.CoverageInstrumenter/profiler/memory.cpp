#include <thread>
#include "memory.h"
#include "logging.h"
#include "profiler_assert.h"
#include "instrumenter.h"

using namespace vsharp;

static FunctionID mainFunctionId = incorrectFunctionId;

std::atomic<int> vsharp::shutdownBlockingRequestsCount {0};
size_t vsharp::stackBottom;
ThreadTracker* vsharp::threadTracker;
ThreadInfo* vsharp::threadInfo;

//region ThreadTracker
void ThreadTracker::trackCurrentThread() {
    LOG(tout << "<<Thread tracked>>");
    stackBalances.store(0);
}

void ThreadTracker::stackBalanceUp() {
    profiler_assert(isCurrentThreadTracked());
    LOG(tout << "Stack up");
    stackBalances.update( [] (int value) {
        return value + 1;
    });
}

bool ThreadTracker::stackBalanceDown() {
    profiler_assert(isCurrentThreadTracked());
    LOG(tout << "Stack down");
    int newBalance = stackBalances.update([] (int value) {
        return value - 1;
    });
    return newBalance != 0;
}

bool ThreadTracker::isCurrentThreadTracked() {
    return stackBalances.exist();
}

void ThreadTracker::loseCurrentThread() {
    profiler_assert(isCurrentThreadTracked());
    LOG(tout << "<<Thread lost>>" << std::endl);
    stackBalances.remove();
}

void ThreadTracker::unwindFunctionEnter(FunctionID functionId) {
    profiler_assert(isCurrentThreadTracked());
    profiler_assert(functionId != incorrectFunctionId);
    LOG(tout << "Unwind enter" << std::endl);
    unwindFunctionIds.store(functionId);
}

void ThreadTracker::unwindFunctionLeave() {
    profiler_assert(isCurrentThreadTracked());
    LOG(tout << "Unwind leave" << std::endl);
    auto functionId = unwindFunctionIds.load();
    unwindFunctionIds.remove();
    if (rewriteMainOnly && !vsharp::isMainFunction(functionId)) return;
    if (!threadTracker->stackBalanceDown()) {
        // stack is empty; function left
        threadTracker->loseCurrentThread();
    }
}

void ThreadTracker::mapCurrentThread(int mapId) {
    threadIdMapping.store(mapId);
}

int ThreadTracker::getCurrentThreadMappedId() {
    return threadIdMapping.load();
}

std::vector<std::pair<ThreadID, int>> ThreadTracker::getMapping() {
    return threadIdMapping.items();
}

void ThreadTracker::clear() {
    threadIdMapping.clear();
    unwindFunctionIds.clear();
    stackBalances.clear();
}

bool vsharp::isPossibleStackOverflow() {
    int topOfStackMarker;
    LOG(tout << "ABCD: " << (size_t) &topOfStackMarker);
    LOG(tout << "ABCD: " << stackBottom);
    LOG(tout << "ABCD: " << (size_t) &topOfStackMarker - stackBottom );
    LOG(tout << "ABCD: " << stackBottom - (size_t) &topOfStackMarker );
    return ( stackBottom - (size_t) &topOfStackMarker) > (size_t) (defaultStackLimitByteSize * 0.8);
}

//endregion

//region FunctionId
void vsharp::setMainFunctionId(FunctionID id) {
    profiler_assert(id != incorrectFunctionId);
    mainFunctionId = id;
}

bool vsharp::isMainFunction(FunctionID id) {
    profiler_assert(mainFunctionId != incorrectFunctionId);
    profiler_assert(id != incorrectFunctionId);
    return id == mainFunctionId;
}
//endregion

//region ThreadInfo
ThreadInfo::ThreadInfo(ICorProfilerInfo8* corProfilerInfo_) {
    corProfilerInfo = corProfilerInfo_;
}

ThreadID ThreadInfo::getCurrentThread() {
    ThreadID result;
    profiler_assert(corProfilerInfo != nullptr);
    HRESULT hr = corProfilerInfo->GetCurrentThreadID(&result);
    if (hr != S_OK) {
        LOG_ERROR(tout << "getting current thread failed with HRESULT = " << std::hex << hr);
    }
    return result;
}
//endregion

void vsharp::dumpUncatchableException(const std::string& exceptionName) {
    std::ofstream stream;
    stream.open("exception.info");
    auto threadId = threadTracker->getCurrentThreadMappedId();
    stream << threadId << " " << exceptionName;
    stream.close();
}