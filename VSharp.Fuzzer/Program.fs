module VSharp.Fuzzer.Program

open System.Diagnostics
open System.IO
open System.IO.Pipes
open VSharp.Fuzzer
open VSharp
open VSharp.Interpreter.IL
open VSharp.Reflection


let getAssembly argv =
    if Array.length argv < 1 then failwith "Unspecified path to assembly"
    let assemblyPath = argv[0]
    AssemblyManager.LoadFromAssemblyPath assemblyPath

let getOutputDir argv =
    if Array.length argv < 2 then failwith "Unspecified path to output directory"
    argv[1]


[<EntryPoint>]
let main argv =
    //while Debugger.IsAttached |> not do ()

    let assembly = getAssembly argv
    let outputDir = getOutputDir argv
    let log = new StreamWriter (File.OpenWrite $"{outputDir}{Path.DirectorySeparatorChar}fuzzer.log")
    Logger.configureWriter log
    Logger.error $"PID: {Process.GetCurrentProcess().Id}"
    Logger.error "Fuzzer started!"

    let app = FuzzerApplication (assembly, outputDir)
    Logger.error "App created"
    app.Start() |> Async.RunSynchronously
    0
