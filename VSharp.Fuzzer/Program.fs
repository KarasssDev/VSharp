module VSharp.Fuzzer.Program

open System.Diagnostics
open System.IO
open System.IO.Pipes
open VSharp.Fuzzer
open VSharp
open VSharp.Interpreter.IL
open VSharp.Reflection


let setupApplication (argv: string array) =
    if (argv.Length < 1) then
        internalfail "Missing log file folder path"
    let outputDir = argv[0]
    Fuzzer.Logger.setupLogger outputDir
    if (argv.Length = 2) then
        match argv[1] with
        | "--debug" -> Fuzzer.Logger.setDebugVerbosity ()
        | _ -> internalfail $"Unexpected second arg {argv[1]}"
    FuzzerApplication outputDir

[<EntryPoint>]
let main argv =
    let app = setupApplication argv
    app.Start() |> Async.RunSynchronously
    0
