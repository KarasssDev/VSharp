#include "protocol.h"
#include "../logging.h"
#include "../probes.h"

#include <cstring>
#include <iostream>

InstrumentType instrument = nullptr;

void SyncInfoGettersPointers(long instrumentPtr) {
    instrument = (InstrumentType) instrumentPtr;
    tout << "got pointer from f#: " << instrumentPtr << std::endl;
}

using namespace vsharp;

char *GetProbes(unsigned *bytesCount) {
    *bytesCount = ProbesAddresses.size() * sizeof(unsigned long long);
    return (char*)ProbesAddresses.data();
}

void Protocol::acceptEntryPoint(char *&entryPointBytes, int &length) {
    LOG(tout << "Entry point accepted" << std::endl);
    assert(length >= 0);
}

void Protocol::instrumentR(unsigned token, unsigned codeSize, unsigned assemblyNameLength, unsigned moduleNameLength, unsigned maxStackSize, unsigned ehsSize, unsigned signatureTokensLength, char *signatureTokensPtr,
    const WCHAR *assemblyNamePtr, const WCHAR *moduleNamePtr, char *byteCodePtr, char *ehsPtr,
    // result
    char **instrumentedBody, int *length, int *resultMaxStackSize, char **resultEhs, int *ehsLength)
{
    instrument(token, codeSize, assemblyNameLength, moduleNameLength, maxStackSize, ehsSize, signatureTokensLength,
               signatureTokensPtr, assemblyNamePtr, moduleNamePtr, byteCodePtr, ehsPtr, instrumentedBody, length,
               resultMaxStackSize, resultEhs, ehsLength);
}

void Protocol::sendTerminateByExceptionCommand() {
    // NOTE: sending command for SILI to terminate execution by exception
    terminateByException();
    LOG(tout << "Sending terminate by exception command" << std::endl);
}

bool Protocol::isInstrumenterAvailable() {
    return instrument != nullptr;
}
