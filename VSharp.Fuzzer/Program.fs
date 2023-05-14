module VSharp.Fuzzer.Program


open System.Diagnostics
open VSharp.Fuzzer
open VSharp


let setupApplication (argv: string array) =
    if (argv.Length < 1) then
        internalfail "Missing log file folder path"
    let outputDir = argv[0]
    Fuzzer.Logger.setupLogger outputDir
    Application outputDir

[<EntryPoint>]
let main argv =
    #if DEBUGFUZZER
    while not Debugger.IsAttached do ()
    #endif

    try
        let app = setupApplication argv
        Fuzzer.Logger.logTrace "Application initialized"
        app.Start().Wait()
    with
        | e ->
            Fuzzer.Logger.logError $"Unhandled exception: {e.Message}"
            Fuzzer.Logger.logError $"Inner exception: {e.StackTrace}"
            Fuzzer.Logger.logError $"Inner exception: {e.InnerException.Message}"

    0
