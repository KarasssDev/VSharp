module VSharp.Fuzzer.Program

open System.Diagnostics
open System.IO
open System.IO.Pipes
open VSharp.Fuzzer
open VSharp
open VSharp.Interpreter.IL
open VSharp.Reflection

[<EntryPoint>]
let main _ =
    //while Debugger.IsAttached |> not do ()

    Logger.error $"PID: {Process.GetCurrentProcess().Id}"
    Logger.error "Fuzzer started!"
    let app = FuzzerApplication ()
    Logger.error "App created"
    app.Start() |> Async.RunSynchronously
    0
