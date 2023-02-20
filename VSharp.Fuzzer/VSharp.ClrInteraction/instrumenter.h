#ifndef INSTRUMENTER_H_
#define INSTRUMENTER_H_

#include "ILRewriter.h"

#include <set>
#include <map>

namespace vsharp {

class Instrumenter {
private:
    ICorProfilerInfo8 &m_profilerInfo;  // Does not have ownership

    WCHAR *m_mainModuleName;
    int m_mainModuleSize;
    mdMethodDef m_mainMethod;
    bool m_mainReached;

    mdMethodDef m_jittedToken;
    ModuleID m_moduleId;

    char *m_signatureTokens;
    unsigned m_signatureTokensLength;

    std::set<std::pair<ModuleID, mdMethodDef>> skippedBeforeMain;

    bool m_reJitInstrumentedStarted;

    HRESULT startReJitSkipped();
    HRESULT doInstrumentation(ModuleID oldModuleId, const WCHAR *assemblyName, ULONG assemblyNameLength, const WCHAR *moduleName, ULONG moduleNameLength);

    bool currentMethodIsMain(const WCHAR *moduleName, int moduleSize, mdMethodDef method) const;

public:
    explicit Instrumenter(ICorProfilerInfo8 &profilerInfo);
    ~Instrumenter();

    const char *signatureTokens() const { return m_signatureTokens; }
    unsigned signatureTokensLength() const { return m_signatureTokensLength; }

    HRESULT instrument(FunctionID functionId, bool reJIT);
    HRESULT reInstrument(FunctionID functionId);
};

}

#endif // INSTRUMENTER_H_
