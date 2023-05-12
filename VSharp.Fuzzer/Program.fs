module VSharp.Fuzzer.Program


open VSharp.Fuzzer
open VSharp



let setupApplication (argv: string array) =
    if (argv.Length < 1) then
        internalfail "Missing log file folder path"
    let outputDir = argv[0]
    Fuzzer.Logger.setupLogger outputDir
    if (argv.Length = 2) then
        match argv[1] with
        | "--debug-log-verbosity" -> Fuzzer.Logger.setDebugVerbosity ()
        | _ -> internalfail $"Unexpected second arg {argv[1]}"
    FuzzerApplication outputDir

[<EntryPoint>]
let main argv =
    //while not Debugger.IsAttached do ()
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
