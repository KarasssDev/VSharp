#ifndef MEMORY_H_
#define MEMORY_H_

#include "cor.h"

#include "stack.h"

#include <map>
#include <set>
#include <vector>
#include <unordered_set>
#include <functional>

#define staticSizeOfCoverageNode (2 * sizeof(int) + sizeof(mdMethodDef) + sizeof(OFFSET))
#define READ_BYTES(src, type) *(type*)(src); (src) += sizeof(type)
#define WRITE_BYTES(type, dest, src) *(type*)(dest) = (src); (dest) += sizeof(type)

typedef UINT_PTR ThreadID;

namespace vsharp {

extern std::function<ThreadID()> currentThread;
extern std::map<ThreadID, Stack *> stacks;
extern std::map<ThreadID, int> stackBalances;
extern ThreadID mainThread;

void stackBalanceUp();

// returns true if the stack is not empty
bool stackBalanceDown();
void emptyStacks();
void setMainThread();
void unsetMainThread();
bool isMainThread();

// Memory tracking

Stack &stack();
StackFrame &topFrame();

void mainLeft();
bool isMainLeft();

bool instrumentingEnabled();
void enableInstrumentation();
void disableInstrumentation();

void enterMain();
bool isMainEntered();

void getLock();
void freeLock();

unsigned allocateString(const char *s);

// Coverage collection

struct CoverageNode {
    int moduleToken;
    mdMethodDef methodToken;
    OFFSET offset;
    int threadToken;
    CoverageNode *next;

    unsigned size() const;
    int count() const;
    void serialize(char *&buffer) const;
    void deserialize(char *&buffer);
};

static const CoverageNode *expectedCoverageStep = nullptr;
static bool expectedCoverageExpirated = true;
static CoverageNode *lastCoverageStep = nullptr;
static CoverageNode *newCoverageNodes = nullptr;

void setExpectedCoverage(const CoverageNode *expectedCoverage);
bool addCoverageStep(OFFSET offset, bool &stillExpectsCoverage);
const CoverageNode *flushNewCoverageNodes();

}

#endif // MEMORY_H_
