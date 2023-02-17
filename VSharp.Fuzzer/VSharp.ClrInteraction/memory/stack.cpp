#include "stack.h"
#include <cstring>
#include <cassert>
#include <algorithm>

using namespace vsharp;

#define CONCRETE UINT32_MAX

StackFrame::StackFrame(unsigned resolvedToken, unsigned unresolvedToken, const bool *args, unsigned argsCount, bool isNewObj, Storage &heap)
    : m_concreteness(nullptr)
    , m_capacity(0)
    , m_concretenessTop(0)
    , m_symbolsCount(0)
    , m_args(new LocalObject[argsCount])
    , m_argsCount(argsCount)
    , m_locals(nullptr)
    , m_localsCount(0)
    , m_resolvedToken(resolvedToken)
    , m_unresolvedToken(unresolvedToken)
    , m_enteredMarker(false)
    , m_spontaneous(false)
    , m_heap(heap)
    , m_ip(0)
{
    for (int i = 0; i < argsCount; i++)
        m_args[i].writeConcretenessWholeObject(args[i]);

    // NOTE: setting default 'this' address to 'null'
    ObjectKey key{};
    key.none = nullptr;
    m_thisAddress = {0, 0, ReferenceType, key};
}

StackFrame::~StackFrame()
{
    m_heap.deleteObjects(allocatedLocals);
    delete [] m_concreteness;
    if (m_localsCount > 0)
        delete [] m_locals;
    if (m_argsCount > 0)
        delete [] m_args;
}

void StackFrame::configure(unsigned maxStackSize, unsigned localsCount)
{
    m_capacity = maxStackSize;
    m_concreteness = new StackCell[maxStackSize];
    m_locals = new LocalObject[localsCount];
    m_localsCount = localsCount;
    for (int i = 0; i < localsCount; i++)
        m_locals[i].writeConcretenessWholeObject(true);
}

bool StackFrame::isEmpty() const
{
    return m_concretenessTop == 0;
}

unsigned StackFrame::count() const
{
    return m_concretenessTop;
}

unsigned StackFrame::resolvedToken() const
{
    return m_resolvedToken;
}

unsigned StackFrame::unresolvedToken() const
{
    return m_unresolvedToken;
}

void StackFrame::setResolvedToken(unsigned resolved)
{
    this->m_resolvedToken = resolved;
}

void StackFrame::thisAddress(VirtualAddress &virtAddress) const
{
    virtAddress = this->m_thisAddress;
}

unsigned StackFrame::ip() const {
    return m_ip;
}

bool StackFrame::hasEntered() const
{
    return m_enteredMarker;
}

void StackFrame::setEnteredMarker(bool entered)
{
    this->m_enteredMarker = entered;
}

bool StackFrame::isSpontaneous() const
{
    return m_spontaneous;
}

void StackFrame::setSpontaneous(bool isUnmanaged)
{
    this->m_spontaneous = isUnmanaged;
}

unsigned StackFrame::moduleToken() const
{
    return m_moduleToken;
}

void StackFrame::setModuleToken(unsigned token)
{
    m_moduleToken = token;
}

Stack::Stack(Storage &heap)
    : m_heap(heap)
{
}

void Stack::pushFrame(unsigned resolvedToken, unsigned unresolvedToken, const bool *args, unsigned argsCount, bool isNewObj)
{
    m_frames.emplace_back(resolvedToken, unresolvedToken, args, argsCount, isNewObj, m_heap);
}


void Stack::popFrame()
{
    popFrameUntracked();
    if (m_frames.size() < m_minTopSinceLastSent) {
        m_minTopSinceLastSent = m_frames.size();
    }
}

void Stack::popFrameUntracked()
{
#ifdef _DEBUG
    if (m_frames.empty()) {
        FAIL_LOUD("Stack is empty! Can't pop frame!");
    } else if (!m_frames.back().isEmpty()) {
        FAIL_LOUD("Corrupted stack: opstack is not empty when popping frame!");
    }
#endif
    m_frames.pop_back();
}

StackFrame &Stack::topFrame()
{
#ifdef _DEBUG
    if (m_frames.empty()) {
        FAIL_LOUD("Requesting top frame of empty stack!");
    }
#endif
    return m_frames.back();
}

const StackFrame &Stack::topFrame() const
{
#ifdef _DEBUG
    if (m_frames.empty()) {
        FAIL_LOUD("Requesting top frame of empty stack!");
    }
#endif
    return m_frames.back();
}

StackFrame &Stack::frameAt(unsigned index) {
#ifdef _DEBUG
    if (index >= m_frames.size()) {
        FAIL_LOUD("Requesting too large frame number!");
    }
#endif
    return m_frames[index];
}

const StackFrame &Stack::frameAt(unsigned index) const {
#ifdef _DEBUG
    if (index >= m_frames.size()) {
        FAIL_LOUD("Requesting too large frame number!");
    }
#endif
    return m_frames[index];
}

bool Stack::isEmpty() const
{
    return m_frames.empty();
}

unsigned Stack::framesCount() const
{
    return m_frames.size();
}

void Stack::resetLastSentTop()
{
    unsigned size = m_frames.size();
    m_minTopSinceLastSent = size;
    m_lastSentTop = size;
}

void Stack::resetPopsTracking()
{
    resetLastSentTop();
}

bool Stack::opmemIsEmpty() const
{
    return m_opmem.empty();
}

Stack::OperandMem &Stack::opmem(UINT32 offset)
{
    if (m_opmem.empty()) {
        m_opmem.emplace_back(m_frames.back(), offset);
    } else {
        const Stack::OperandMem &top = m_opmem.back();
        if (top.offset() != offset || &top.stackFrame() != &m_frames.back()) {
            m_opmem.emplace_back(m_frames.back(), offset);
        }
    }
    return m_opmem.back();
}

const Stack::OperandMem &Stack::lastOpmem() const
{
    return m_opmem.back();
}

void Stack::popOpmem()
{
    m_opmem.pop_back();
}

Stack::OperandMem::OperandMem(const StackFrame &frame, UINT32 offset)
    : m_frame(frame)
    , m_offset(offset)
    , m_entries_count(0)
    , m_data_ptr(0)
    , m_memSize(3)
{
    m_dataPtrs.resize(m_memSize);
    m_data.resize(m_memSize * (sizeof(DOUBLE) + sizeof(CorElementType)));
}
