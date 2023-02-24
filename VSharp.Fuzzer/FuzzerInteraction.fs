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

type private FuzzerPipe<'a, 'b> (io: Stream, onStart, serialize: 'a -> string, deserialize: string -> 'b) =
    let reader = new StreamReader(io)
    let writer = new StreamWriter(io)

    do
        onStart ()
        writer.AutoFlush <- true

    member this.ReadMessage () =
        async {
            let! str = reader.ReadLineAsync() |> Async.AwaitTask
            Logger.trace $"Received raw msg: {str}"
            return deserialize str
        }

    member this.ReadAll onEach =
        async {
            let mutable completed = false
            while not completed do
                let! str = reader.ReadLineAsync() |> Async.AwaitTask
                if str = null then
                    completed <- true
                else
                    let! stop = deserialize str |> onEach
                    completed <- stop
        }

    member this.SendMessage msg =
        writer.WriteAsync $"{serialize msg}\n" |> Async.AwaitTask

    member this.SendEnd () =
        writer.Close ()

type FuzzerApplication (assembly, outputDir) =
    let fuzzer = Fuzzer ()
    let server =
        let io = new NamedPipeServerStream("FuzzerPipe", PipeDirection.InOut)
        FuzzerPipe (io, io.WaitForConnection, ServerMessage.serialize, ClientMessage.deserialize)

    let dummyStat = [| { assemblyName = "ass"; moduleName = "mmm"; methodToken = 1; offset = 1 }|]

    let mutable freeId = -1
    let nextId () =
        freeId <- freeId + 1
        freeId

    let handleRequest command =
        async {
            match command with
            | Fuzz (moduleName, methodToken) ->
                let methodBase = Reflection.resolveMethodBaseFromAssembly assembly moduleName methodToken
                let method = Application.getMethod methodBase

                Logger.error $"Start fuzzing {moduleName} {methodToken}"

                do! fuzzer.FuzzWithAction method (fun state -> async {
                    let test = TestGenerator.state2test false method state ""
                    match test with
                    | Some test ->
                        let filePath = $"{outputDir}{Path.DirectorySeparatorChar}fuzzer_test{nextId ()}.vst"
                        Logger.trace $"Saved to {filePath}"
                        do! server.SendMessage (Statistics dummyStat)
                        test.Serialize filePath
                    | None -> ()
                })

                Logger.error $"Successfully fuzzed {moduleName} {methodToken}"
                return false

            | Kill -> return true
        }

    member this.Start () = server.ReadAll handleRequest

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

    let client =
        let io = new NamedPipeClientStream(".", "FuzzerPipe", PipeDirection.InOut)
        FuzzerPipe(io, io.Connect, ClientMessage.serialize, ServerMessage.deserialize)

    let killFuzzer () = Logger.trace "Fuzzer killed"; proc.Kill ()

    let handleRequest msg = async { Logger.error "Msg received"; return false }
    do
        cancellationToken.Register(killFuzzer)
        |> ignore

    member this.Fuzz (moduleName: string, methodToken: int) = client.SendMessage (Fuzz (moduleName, methodToken))

    member this.WaitStatistics () =
        async {
            do! client.SendMessage Kill
            Logger.error "Kill message sent to fuzzer"
            do! client.ReadAll handleRequest
            do! proc.WaitForExitAsync () |> Async.AwaitTask
            Logger.error "Fuzzer stopped"
        }

    member this.Kill = killFuzzer
