#ifndef MEMORY_H_
#define MEMORY_H_

#include "cor.h"
#include "stack.h"
#include "storage.h"
#include <functional>
#include <map>
#include <set>

#define staticSizeOfCoverageNode (2 * sizeof(int) + sizeof(mdMethodDef) + sizeof(OFFSET))
#define READ_BYTES(src, type) *(type*)(src); (src) += sizeof(type)
#define WRITE_BYTES(type, dest, src) *(type*)(dest) = (src); (dest) += sizeof(type)

typedef UINT_PTR ThreadID;

namespace vsharp {

extern std::function<ThreadID()> currentThread;
static std::map<ThreadID, Stack *> stacks;
extern Storage heap;
#ifdef _DEBUG
extern std::map<unsigned, const char*> stringsPool;
#endif

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

void validateStackEmptyness();

void resolve(INT_PTR p, VirtualAddress &vAddress);

// Exceptions handling

void catchException();
void terminateByException();

enum ExceptionKind {
    Unhandled = 1,
    Caught = 2,
    NoException = 3
};

std::tuple<ExceptionKind, OBJID, bool> exceptionRegister();

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
