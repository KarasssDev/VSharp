#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#ifdef IMAGEHANDLER_EXPORTS
#define IMAGEHANDLER_API __declspec(dllexport)
#else
#define IMAGEHANDLER_API __declspec(dllimport)
#endif

#include "../memory/memory.h"
#include "cor.h"
#include <vector>

#ifdef UNIX
#include "pal_mstypes.h"
#include "corhdr.h"
#endif

#ifdef WIN32
#include "../profiler_win.h"
#endif

typedef void (*InstrumentType)(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned, unsigned, char*,
        const WCHAR*, const WCHAR*, char*, char*,
        // result
        char**, int*, int*, char**, int*);

extern "C" IMAGEHANDLER_API void SyncInfoGettersPointers(long instrumentPtr);
extern "C" IMAGEHANDLER_API char *GetProbes(unsigned *bytesCount);

namespace vsharp {

class Protocol {
public:
    void acceptEntryPoint(char *&entryPointBytes, int &length);
    void instrumentR(unsigned token, unsigned codeSize, unsigned assemblyNameLength, unsigned moduleNameLength, unsigned maxStackSize, unsigned ehsSize, unsigned signatureTokensLength, char *signatureTokensPtr,
                    const WCHAR *assemblyNamePtr, const WCHAR *moduleNamePtr, char *byteCodePtr, char *ehsPtr,
                    // result
                    char **instrumentedBody, int *length, int *resultMaxStackSize, char **resultEhs, int *ehsLength);
    bool isInstrumenterAvailable();

    static void sendTerminateByExceptionCommand();
};

}

#endif // PROTOCOL_H_
