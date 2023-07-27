open System
open System.Diagnostics
open System.Runtime.InteropServices
open VSharp
open VSharp.Fuzzer



let internal getOutputDir (argv: string array) =
    if (argv.Length < 1) then
        internalfail "Missing output directory path"
    argv[0]

[<EntryPoint>]
let main argv =
    #if DEBUG
    while not Debugger.IsAttached do ()
    #endif


    let outputDir = getOutputDir argv
    let app = Fuzzer.Application(outputDir)
    Logger.setupLogger outputDir
    let onError (e: exn) =
        Logger.errorFuzzing $"Unhandled exception: {e}"
        exit 1

    app.Start(onError).Wait()
    0
