#ifndef STACK_H_
#define STACK_H_

#include <vector>
#include <stack>
#include "storage.h"

namespace vsharp {

#define OFFSET UINT32

// NOTE: every stack cell (evaluation stack cell, local or argument) contains LocalObject class by value
struct StackCell {
    unsigned content;
    LocalObject cell;
};

class StackFrame {
private:
    StackCell *m_concreteness;
    unsigned m_capacity;
    unsigned m_concretenessTop;

    unsigned m_symbolsCount;

    LocalObject *m_args;
    unsigned m_argsCount;
    LocalObject *m_locals;
    unsigned m_localsCount;
    // NOTE: used to delete from heap all stack cell, which were allocated there
    std::vector<Interval *> allocatedLocals;

    VirtualAddress m_thisAddress;
    unsigned m_resolvedToken;
    unsigned m_unresolvedToken;
    unsigned m_moduleToken;
    bool m_enteredMarker;
    bool m_spontaneous;

    unsigned m_ip;

    Storage &m_heap;

    std::vector<std::pair<unsigned, unsigned>> m_lastPoppedSymbolics;

public:
    StackFrame(unsigned resolvedToken, unsigned unresolvedToken, const bool *args, unsigned argsCount, bool isNewObj, Storage &heap);
    ~StackFrame();

    void configure(unsigned maxStackSize, unsigned localsCount);

    inline bool isEmpty() const;

    unsigned count() const;

    unsigned resolvedToken() const;
    unsigned unresolvedToken() const;
    void setResolvedToken(unsigned resolved);
    void thisAddress(VirtualAddress &virtAddress) const;
    unsigned ip() const;
    bool hasEntered() const;
    void setEnteredMarker(bool entered);
    bool isSpontaneous() const;
    void setSpontaneous(bool isUnmanaged);

    unsigned moduleToken() const;
    void setModuleToken(unsigned token);
};

class Stack {
private:
    std::deque<StackFrame> m_frames;
    unsigned m_lastSentTop;
    unsigned m_minTopSinceLastSent;

    Storage &m_heap;

public:
    struct OperandMem {
    private:
        const StackFrame &m_frame;
        OFFSET m_offset;
        unsigned m_entries_count;
        unsigned m_data_ptr;
        std::vector<char> m_data;
        std::vector<unsigned> m_dataPtrs;

        int m_memSize = 0;

        INT_PTR m_refLikeStructRef;

    public:
        OperandMem(const StackFrame &frame, OFFSET offset);

        const StackFrame &stackFrame() const { return m_frame; }
        OFFSET offset() const { return m_offset; }
    };

private:
    std::deque<OperandMem> m_opmem;

public:
    explicit Stack(Storage &heap);

    void pushFrame(unsigned resolvedToken, unsigned unresolvedToken, const bool *args, unsigned argsCount, bool isNewObj);
    void popFrame();
    void popFrameUntracked();
    StackFrame &topFrame();
    inline const StackFrame &topFrame() const;
    StackFrame &frameAt(unsigned index);
    inline const StackFrame &frameAt(unsigned index) const;

    bool isEmpty() const;
    unsigned framesCount() const;

    void resetLastSentTop();
    void resetPopsTracking();

    bool opmemIsEmpty() const;
    OperandMem &opmem(OFFSET offset);
    const OperandMem &lastOpmem() const;
    void popOpmem();
};

}

#endif // STACK_H_
