module internal VSharp.Fuzzer.Logger


let private communicationTraceTag = "Communication"
let private testGenerationTraceTag = "TestGeneration"
let private fuzzingTraceTag = "Fuzzing"
let traceCommunication msg = VSharp.Logger.traceWithTag communicationTraceTag msg
let traceFuzzing msg = VSharp.Logger.traceWithTag fuzzingTraceTag msg
let traceGeneration msg = VSharp.Logger.traceWithTag testGenerationTraceTag msg
let errorCommunication msg = VSharp.Logger.errorWithTag communicationTraceTag msg
let errorFuzzing msg = VSharp.Logger.errorWithTag fuzzingTraceTag msg


let setupLogger outputDir =
    #if DEBUG || DEBUGFUZZER
    let writer = new System.IO.StreamWriter (
        System.IO.File.OpenWrite $"{outputDir}{System.IO.Path.DirectorySeparatorChar}fuzzer.log"
    )
    VSharp.Logger.configureWriter writer
    VSharp.Logger.enableTag communicationTraceTag
    VSharp.Logger.enableTag fuzzingTraceTag
    VSharp.Logger.disableTag VSharp.Logger.defaultTag
    VSharp.Logger.currentLogLevel <- VSharp.Logger.Trace
    #endif
    ()