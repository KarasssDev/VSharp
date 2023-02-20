#include "instrumenter.h"
#include "logging.h"
#include "cComPtr.h"
#include <vector>
#include "memory/memory.h"
#include "probes.h"

using namespace vsharp;

#define TOKENPASTE(x, y) x ## y
#define TOKENPASTE2(x, y) TOKENPASTE(x, y)
#define UNIQUE TOKENPASTE2(Sig, __LINE__)
#define SIG_DEF(...) \
    constexpr COR_SIGNATURE UNIQUE[] = {IMAGE_CEE_CS_CALLCONV_STDCALL, __VA_ARGS__};\
    IfFailRet(metadataEmit->GetTokenFromSig(UNIQUE, sizeof(UNIQUE), &signatureToken));\
    tokens.push_back(signatureToken);

#define ELEMENT_TYPE_COND ELEMENT_TYPE_I
#define ELEMENT_TYPE_TOKEN ELEMENT_TYPE_U4
#define ELEMENT_TYPE_OFFSET ELEMENT_TYPE_I4
#define ELEMENT_TYPE_SIZE ELEMENT_TYPE_U

HRESULT initTokens(const CComPtr<IMetaDataEmit> &metadataEmit, std::vector<mdSignature> &tokens) {
    mdSignature signatureToken;
    SIG_DEF(0x01, ELEMENT_TYPE_VOID, ELEMENT_TYPE_OFFSET)
    Track_Coverage_Sig = signatureToken;
    Branch_Addr_Sig = signatureToken;
    Track_Leave_Sig = signatureToken;
    Track_LeaveMain_Sig = signatureToken;
    Finalize_Call_Sig = signatureToken;
    SIG_DEF(0x02, ELEMENT_TYPE_VOID, ELEMENT_TYPE_TOKEN, ELEMENT_TYPE_U4)
    Track_EnterMain_Sig = signatureToken;
    SIG_DEF(0x03, ELEMENT_TYPE_VOID, ELEMENT_TYPE_TOKEN, ELEMENT_TYPE_U4, ELEMENT_TYPE_I1)
    Track_Enter_Sig = signatureToken;
    return S_OK;
}

Instrumenter::Instrumenter(ICorProfilerInfo8 &profilerInfo)
    : m_profilerInfo(profilerInfo)
    , m_moduleId(0)
    , m_signatureTokens(nullptr)
    , m_reJitInstrumentedStarted(false)
    , m_mainModuleName(nullptr)
    , m_mainModuleSize(0)
    , m_mainMethod(0)
    , m_mainReached(false)
{
}

Instrumenter::~Instrumenter()
{
    delete[] m_signatureTokens;
    delete[] m_mainModuleName;
}


bool Instrumenter::currentMethodIsMain(const WCHAR *moduleName, int moduleSize, mdMethodDef method) const {
    // NOTE: decrementing 'moduleSize', because of null terminator
    if (m_mainModuleSize != moduleSize - 1 || m_mainMethod != method)
        return false;
    for (int i = 0; i < m_mainModuleSize; i++)
        if (m_mainModuleName[i] != moduleName[i]) return false;
    return true;
}

HRESULT Instrumenter::startReJitSkipped() {
    LOG(tout << "ReJIT of skipped methods is started" << std::endl);
    ULONG count = skippedBeforeMain.size();
    auto *modules = new ModuleID[count];
    auto *methods = new mdMethodDef[count];
    int i = 0;
    for (const auto &it : skippedBeforeMain) {
        modules[i] = it.first;
        methods[i] = it.second;
        i++;
    }
    HRESULT hr = m_profilerInfo.RequestReJIT(count, modules, methods);
    skippedBeforeMain.clear();
    delete[] modules;
    delete[] methods;
    return hr;
}

HRESULT Instrumenter::doInstrumentation(ModuleID oldModuleId, const WCHAR *assemblyName, ULONG assemblyNameLength, const WCHAR *moduleName, ULONG moduleNameLength) {
    HRESULT hr;
    CComPtr<IMetaDataImport> metadataImport;
    CComPtr<IMetaDataEmit> metadataEmit;
    IfFailRet(m_profilerInfo.GetModuleMetaData(m_moduleId, ofRead | ofWrite, IID_IMetaDataImport, reinterpret_cast<IUnknown **>(&metadataImport)));
    IfFailRet(metadataImport->QueryInterface(IID_IMetaDataEmit, reinterpret_cast<void **>(&metadataEmit)));

    if (oldModuleId != m_moduleId) {
        delete[] m_signatureTokens;
        std::vector<mdSignature> tokens;
        initTokens(metadataEmit, tokens);
        m_signatureTokensLength = tokens.size() * sizeof(mdSignature);
        m_signatureTokens = new char[m_signatureTokensLength];
        memcpy(m_signatureTokens, (char *)&tokens[0], m_signatureTokensLength);
    }

    LOG(tout << "Instrumenting token " << HEX(m_jittedToken) << "..." << std::endl);

//    unsigned codeLength = codeSize();
//    char *bytes = new char[codeLength];
//    char *ehcs = new char[ehCount()];
//    memcpy(bytes, code(), codeLength);
//    memcpy(ehcs, ehs(), ehCount());
//    MethodInfo mi = MethodInfo{m_jittedToken, bytes, codeLength, maxStackSize(), ehcs, ehCount()};
//    instrumentedFunctions[{m_moduleId, m_jittedToken}] = mi;
//    char *bytecodeR; int lengthR; int maxStackSizeR; char *ehsR; int ehsLengthR;
//    LOG(tout << "Exporting " << lengthR << " IL bytes!");
//    IfFailRet(exportIL(bytecodeR, lengthR, maxStackSizeR, ehsR, ehsLengthR));

    RewriteIL(&m_profilerInfo, nullptr, m_moduleId, m_jittedToken, Track_Coverage_Addr, Track_Coverage_Sig);

    return S_OK;
}

HRESULT Instrumenter::instrument(FunctionID functionId, bool reJIT) {
    HRESULT hr = S_OK;
    ModuleID newModuleId;
    ClassID classId;
    IfFailRet(m_profilerInfo.GetFunctionInfo(functionId, &classId, &newModuleId, &m_jittedToken));
    assert((m_jittedToken & 0xFF000000L) == mdtMethodDef);

    LPCBYTE baseLoadAddress;
    ULONG moduleNameLength;
    AssemblyID assembly;
    IfFailRet(m_profilerInfo.GetModuleInfo(newModuleId, &baseLoadAddress, 0, &moduleNameLength, nullptr, &assembly));
    WCHAR *moduleName = new WCHAR[moduleNameLength];
    IfFailRet(m_profilerInfo.GetModuleInfo(newModuleId, &baseLoadAddress, moduleNameLength, &moduleNameLength, moduleName, &assembly));
    ULONG assemblyNameLength;
    AppDomainID appDomainId;
    ModuleID startModuleId;
    IfFailRet(m_profilerInfo.GetAssemblyInfo(assembly, 0, &assemblyNameLength, nullptr, &appDomainId, &startModuleId));
    WCHAR *assemblyName = new WCHAR[assemblyNameLength];
    IfFailRet(m_profilerInfo.GetAssemblyInfo(assembly, assemblyNameLength, &assemblyNameLength, assemblyName, &appDomainId, &startModuleId));

    bool shouldInstrument = true; // TODO: delete
//    if (!m_mainReached) {
//        if (currentMethodIsMain(moduleName, (int) moduleNameLength, m_jittedToken)) {
//            LOG(tout << "Main function reached!" << std::endl);
//            m_mainReached = true;
//            shouldInstrument = true;
//            IfFailRet(startReJitSkipped());
//        }
//    }

    if (shouldInstrument && instrumentingEnabled()) {
        ModuleID oldModuleId = m_moduleId;
        m_moduleId = newModuleId;
        hr = doInstrumentation(oldModuleId, assemblyName, assemblyNameLength, moduleName, moduleNameLength);
    } else {
        LOG(tout << "Instrumentation of token " << HEX(m_jittedToken) << " is skipped" << std::endl);
    }

    delete[] moduleName;
    delete[] assemblyName;

    return hr;
}

HRESULT Instrumenter::reInstrument(FunctionID functionId) {
    return S_OK; // instrument(functionId, true);
}
