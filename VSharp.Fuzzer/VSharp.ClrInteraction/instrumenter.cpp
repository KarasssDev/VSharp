#include "instrumenter.h"
#include "logging.h"
#include "cComPtr.h"
#include <vector>
#include "memory/memory.h"

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

void SetEntryMain(char* assemblyName, int assemblyNameLength, char* moduleName, int moduleNameLength, int methodToken) {
    mainAssemblyNameLength = assemblyNameLength;
    mainAssemblyName = new WCHAR[assemblyNameLength];
    memcpy(mainAssemblyName, assemblyName, assemblyNameLength * sizeof(WCHAR));

    mainModuleNameLength = moduleNameLength;
    mainModuleName = new WCHAR[moduleNameLength];
    memcpy(mainModuleName, moduleName, moduleNameLength * sizeof(WCHAR));

    mainToken = methodToken;

    tout << "received entry main" << std::endl;
}

void GetHistory(UINT_PTR size, UINT_PTR bytes) {
    LOG(tout << "GetHistory request received! serializing and writing the response");

    auto sizeBytes = sizeof(int);
    for (auto el : coverageHistory) {
        sizeBytes += el->size();
    }

    char *buffer = (char*)malloc(sizeBytes); // the buffer pointer moves further after each serialization
    auto beginning = buffer; // remembering the first point to check the sizes were counted correctly
    WRITE_BYTES(int, buffer, coverageHistory.size());
    for (auto el : coverageHistory) {
        el->serialize(buffer);
    }
    LOG(tout << buffer - beginning);
    LOG(tout << sizeBytes);
    assert(buffer - beginning == sizeBytes);
    *(ULONG*)size = sizeBytes;
    *(char**)bytes = beginning;
    coverageHistory.clear(); // freeing up the history
}

static std::set<std::pair<FunctionID, ModuleID>> vsharp::instrumentedMethods;

HRESULT initTokens(const CComPtr<IMetaDataEmit> &metadataEmit, std::vector<mdSignature> &tokens) {
    auto covProb = getProbes();
    mdSignature signatureToken;
    SIG_DEF(0x00, ELEMENT_TYPE_VOID)
    covProb->Track_Coverage_Sig.setSig(signatureToken);
    SIG_DEF(0x01, ELEMENT_TYPE_VOID, ELEMENT_TYPE_OFFSET)
    covProb->Finalize_Call_Sig.setSig(signatureToken);
    covProb->Track_Call_Sig.setSig(signatureToken);
    SIG_DEF(0x02, ELEMENT_TYPE_VOID, ELEMENT_TYPE_OFFSET, ELEMENT_TYPE_I4)
    covProb->Branch_Sig.setSig(signatureToken);
    covProb->Track_Leave_Sig.setSig(signatureToken);
    covProb->Track_Tailcall_Sig.setSig(signatureToken);
    covProb->Track_LeaveMain_Sig.setSig(signatureToken);
    SIG_DEF(0x03, ELEMENT_TYPE_VOID, ELEMENT_TYPE_OFFSET, ELEMENT_TYPE_I4, ELEMENT_TYPE_I4)
    covProb->Track_EnterMain_Sig.setSig(signatureToken);
    covProb->Track_Enter_Sig.setSig(signatureToken);
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
    if (mainModuleName == nullptr)
        return false;
    if (mainModuleNameLength != moduleSize - 1 || mainToken != method)
        return false;
    for (int i = 0; i < mainModuleNameLength; i++)
        if (mainModuleName[i] != moduleName[i]) return false;
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

HRESULT Instrumenter::doInstrumentation(ModuleID oldModuleId, int methodId, const WCHAR *moduleName, ULONG moduleNameLength) {
    HRESULT hr;
    CComPtr<IMetaDataImport> metadataImport;
    CComPtr<IMetaDataEmit> metadataEmit;
    IfFailRet(m_profilerInfo.GetModuleMetaData(m_moduleId, ofRead | ofWrite, IID_IMetaDataImport, reinterpret_cast<IUnknown **>(&metadataImport)));
    IfFailRet(metadataImport->QueryInterface(IID_IMetaDataEmit, reinterpret_cast<void **>(&metadataEmit)));

    bool firstTime = false;
    if (oldModuleId != m_moduleId || firstTime) {
        if (!firstTime) delete[] m_signatureTokens;
        std::vector<mdSignature> tokens;
        initTokens(metadataEmit, tokens);
        m_signatureTokensLength = tokens.size() * sizeof(mdSignature);
        m_signatureTokens = new char[m_signatureTokensLength];
        memcpy(m_signatureTokens, (char *)&tokens[0], m_signatureTokensLength);
    }

//    LOG(tout << "Instrumenting token " << HEX(m_jittedToken) << "..." << std::endl);

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

    RewriteIL(&m_profilerInfo, nullptr, m_moduleId, m_jittedToken, methodId, currentMethodIsMain(moduleName, moduleNameLength, m_jittedToken));

    return S_OK;
}

HRESULT Instrumenter::instrument(FunctionID functionId, bool reJIT) {
    HRESULT hr = S_OK;
    ModuleID newModuleId;
    ClassID classId;
    IfFailRet(m_profilerInfo.GetFunctionInfo(functionId, &classId, &newModuleId, &m_jittedToken));
    assert((m_jittedToken & 0xFF000000L) == mdtMethodDef);

    auto mp = std::make_pair(m_jittedToken, newModuleId);
    if (instrumentedMethods.find(mp) != instrumentedMethods.end()) {
        tout << "repeated JIT; skipped" << std::endl;
        return S_OK;
    }

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

//    if (!m_mainReached) {
//        if (currentMethodIsMain(moduleName, (int) moduleNameLength, m_jittedToken)) {
//            LOG(tout << "Main function reached!" << std::endl);
//            m_mainReached = true;
//            shouldInstrument = true;
//            IfFailRet(startReJitSkipped());
//        }
//    }

    getLock();
    int currentMethodId = collectedMethods.size();
    collectedMethods.push_back({m_jittedToken, assemblyNameLength, assemblyName, moduleNameLength, moduleName});
    instrumentedMethods.insert({m_jittedToken, newModuleId});
    freeLock();
    ModuleID oldModuleId = m_moduleId;
    m_moduleId = newModuleId;
    hr = doInstrumentation(oldModuleId, currentMethodId, moduleName, moduleNameLength);

//    delete[] moduleName;
//    delete[] assemblyName;

    return hr;
}

HRESULT Instrumenter::reInstrument(FunctionID functionId) {
    return S_OK; // instrument(functionId, true);
}
