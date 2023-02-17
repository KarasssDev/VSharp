module VSharp.Fuzzer.Program

open System.Diagnostics
open System.IO
open System.IO.Pipes
open VSharp.Fuzzer
open VSharp
open VSharp.Interpreter.IL
open VSharp.Reflection
// open System.Runtime.InteropServices

// module InteropSyncCalls =
    // TODO: add GetHistory
    // [<DllImport("libvsharpConcolic", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    // extern byte* GetProbes(uint* byteCount)

let getAssembly argv =
    if Array.length argv < 1 then failwith "Unspecified path to assembly"
    let assemblyPath = argv[0]
    AssemblyManager.LoadFromAssemblyPath assemblyPath

let getOutputDir argv =
    if Array.length argv < 2 then failwith "Unspecified path to output directory"
    argv[1]

type FuzzerPipeServer () =
    let io = new NamedPipeServerStream("FuzzerPipe", PipeDirection.In)
    let reader = new StreamReader(io)

    do
        io.WaitForConnection()

    member this.ReadMessage () =
        async {
            let! str = reader.ReadLineAsync() |> Async.AwaitTask
            Logger.error $"Recived raw msg: {str}"
            return Message.deserialize str
        }

type FuzzerApplication (assembly, outputDir) =
    let fuzzer = Fuzzer ()
    let server = FuzzerPipeServer ()
    member this.Start () =
        let rec loop () =
            async {
                Logger.error $"Try to read message"
                let! command = server.ReadMessage()
                Logger.error $"Received {command}"
                match command with
                | Fuzz (moduleName, methodToken) ->
                    let methodBase = resolveMethodBaseFromAssembly assembly moduleName methodToken
                    let method = Application.getMethod methodBase
                    Logger.error "Try to fuzz"
                    let result = fuzzer.Fuzz method
                    Logger.error "Fuzzed"
                    result
                    |> Seq.map (fun x -> TestGenerator.state2test false method x "")
                    |> Seq.iteri (fun i x ->
                        Logger.error $"Saved to {outputDir}{Path.DirectorySeparatorChar}fuzzer_test{i}.vst"
                        x.Value.Serialize $"{outputDir}{Path.DirectorySeparatorChar}fuzzer_test{i}.vst"
                    )
                    do! loop ()
                | Kill -> ()
            }
        Logger.error "Loop started"
        loop()

[<EntryPoint>]
let main argv =
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
