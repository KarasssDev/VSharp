module VSharp.Fuzzer.Program

open System.Diagnostics
open System.IO
open System.IO.Pipes
open VSharp.Fuzzer
open VSharp
open VSharp.Interpreter.IL
open VSharp.Reflection

[<EntryPoint>]
let main argv =
    //while Debugger.IsAttached |> not do ()
    if (argv.Length < 1) then
        internalfail "Missing log file folder path"
    let logFileFolderPath = argv[0]
    Logger.configureWriter <| new StreamWriter (File.OpenWrite $"{logFileFolderPath}{Path.DirectorySeparatorChar}fuzzer.log")
    Logger.error $"PID: {Process.GetCurrentProcess().Id}"
    Logger.error "Fuzzer started!"
    let app = FuzzerApplication ()
    Logger.error "App created"
    app.Start() |> Async.RunSynchronously
    0
