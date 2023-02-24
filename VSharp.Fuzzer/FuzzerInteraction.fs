namespace VSharp.Fuzzer

open System
open System.Diagnostics
open System.IO
open System.IO.Pipes
open System.Runtime.InteropServices
open System.Threading
open VSharp
open VSharp.Fuzzer.Coverage
open VSharp.Interpreter.IL


type ClientMessage =
    | Kill
    | Fuzz of string * int

    static member serialize msg =
        match msg with
        | Kill -> "Kill"
        | Fuzz (moduleName, methodToken) -> $"Fuzz %s{moduleName} %d{methodToken}"

    static member deserialize (str: string) =
        let parts = str.Split ' '
        match parts[0] with
        | "Kill" -> Kill
        | "Fuzz" -> assert (parts.Length = 3); Fuzz (parts[1], int parts[2])
        | _ -> internalfail $"Unknown client message: {str}"

type ServerMessage =
    | Statistics of CoverageLocation array

    static member serialize msg =
        match msg with
        | Statistics arr ->
            let content = Array.map CoverageLocation.serialize arr |> String.concat ";"
            $"Statistics %s{content}"

    static member deserialize (str: string) =
        let parts = str.Split ' '
        match parts[0] with
        | "Statistics" ->
            assert (parts.Length = 2)
            let parts = parts[1].Split ';'
            let content = Array.map CoverageLocation.deserialize parts
            Statistics content
        | _  -> internalfail $"Unknown server message: {str}"

type FuzzerPipeServer () =
    let io = new NamedPipeServerStream("FuzzerPipe", PipeDirection.InOut)
    let reader = new StreamReader(io)
    let writer = new StreamWriter(io)

    do
        io.WaitForConnection()
        writer.AutoFlush <- true

    member this.ReadMessage () =
        async {
            let! str = reader.ReadLineAsync() |> Async.AwaitTask
            Logger.trace $"Received raw msg: {str}"
            return ClientMessage.deserialize str
        }

    member this.SendMessage msg =
        let msg = $"{ServerMessage.serialize msg}\n"
        Logger.error $"!!!!{msg}"
        msg |> writer.WriteAsync  |> Async.AwaitTask

type private FuzzerPipeClient () =
    let io = new NamedPipeClientStream(".", "FuzzerPipe", PipeDirection.InOut)
    let reader = new StreamReader(io)
    let writer = new StreamWriter(io)

    do
        io.Connect()
        writer.AutoFlush <- true

    member this.ReadMessage () =
        async {
            let! str = reader.ReadLineAsync() |> Async.AwaitTask
            Logger.trace $"Received raw msg: {str}"
            return ServerMessage.deserialize str
        }

    member this.SendMessage msg =
        writer.WriteAsync $"{ClientMessage.serialize msg}\n" |> Async.AwaitTask


type FuzzerApplication (assembly, outputDir) =
    let fuzzer = Fuzzer ()
    let server = FuzzerPipeServer ()

    let dummyStat = [| { assemblyName = "ass"; moduleName = "mmm"; methodToken = 1; offset = 1 }|]

    member this.Start () =
        let rec loop () =
            async {
                Logger.error "Try to read message"
                let! command = server.ReadMessage()
                Logger.error $"Received {command}"
                match command with
                | Fuzz (moduleName, methodToken) ->
                    let methodBase = Reflection.resolveMethodBaseFromAssembly assembly moduleName methodToken
                    let method = Application.getMethod methodBase

                    Logger.error $"Start fuzzing {moduleName} {methodToken}"
                    let result = fuzzer.Fuzz method
                    Logger.error $"Successfully fuzzed {moduleName} {methodToken}"

                    let states =
                        result
                        |> Array.ofSeq
                        |> Array.map (fun x -> TestGenerator.state2test false method x "")
                        |> Array.choose id

                    for i in 0..Array.length states do
                        let state = states[i]
                        let filePath = $"{outputDir}{Path.DirectorySeparatorChar}fuzzer_test{i}.vst"
                        Logger.trace $"Saved to {filePath}"
                        do! server.SendMessage (Statistics dummyStat)
                        state.Serialize filePath

                    do! loop ()
                | Kill -> ()
            }
        loop()

type FuzzerInteraction (pathToAssembly, outputDir, cancellationToken: CancellationToken) =
    // TODO: find correct path to the client
    let extension =
        if RuntimeInformation.IsOSPlatform(OSPlatform.Windows) then ".dll"
        elif RuntimeInformation.IsOSPlatform(OSPlatform.Linux) then ".so"
        elif RuntimeInformation.IsOSPlatform(OSPlatform.OSX) then ".dylib"
        else __notImplemented__()
    let pathToClient = $"libvsharpConcolic{extension}"
    let profiler = $"%s{Directory.GetCurrentDirectory()}%c{Path.DirectorySeparatorChar}%s{pathToClient}"

    let proc =
        let config =
            let info = ProcessStartInfo()
            info.EnvironmentVariables.["CORECLR_PROFILER"] <- "{2800fea6-9667-4b42-a2b6-45dc98e77e9e}"
            info.EnvironmentVariables.["CORECLR_ENABLE_PROFILING"] <- "1"
            info.EnvironmentVariables.["CORECLR_PROFILER_PATH"] <- profiler
            info.WorkingDirectory <- Directory.GetCurrentDirectory()
            info.FileName <- "dotnet"
            info.Arguments <- $"VSharp.Fuzzer.dll %s{pathToAssembly} %s{outputDir}"
            info.UseShellExecute <- false
            info.RedirectStandardInput <- false
            info.RedirectStandardOutput <- false
            info.RedirectStandardError <- false
            info
        Logger.trace "Fuzzer started"
        Process.Start(config)

    let client = FuzzerPipeClient()

    let killFuzzer () = Logger.trace "Fuzzer killed"; proc.Kill ()

    do
        cancellationToken.Register(killFuzzer)
        |> ignore


    let mutable fuzzedMethodsCount = 0

    let rec readLoop () =
        async {
            if fuzzedMethodsCount <> 0 then
                let! (Statistics x) = client.ReadMessage ()
                fuzzedMethodsCount <- fuzzedMethodsCount - 1
                do Logger.error $"{x}"
                do! readLoop ()
        }

    member this.Fuzz (moduleName: string, methodToken: int) =
        fuzzedMethodsCount <- fuzzedMethodsCount + 1
        client.SendMessage (Fuzz (moduleName, methodToken))

    member this.WaitStatistics () =
        async {
            do! client.SendMessage Kill
            Logger.error "Kill message sent to fuzzer"
            do! readLoop ()
            do! proc.WaitForExitAsync () |> Async.AwaitTask
            Logger.error "Fuzzer stopped"
        }

    member this.Kill = killFuzzer
