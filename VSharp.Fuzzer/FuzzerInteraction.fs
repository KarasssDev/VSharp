namespace VSharp.Fuzzer

open System
open System.Diagnostics
open System.IO
open System.IO.Pipes
open System.Net.Sockets
open System.Runtime.InteropServices
open System.Text
open System.Threading
open Microsoft.FSharp.NativeInterop
open VSharp
open VSharp.Fuzzer.Coverage
open VSharp.Interpreter.IL


type ServerMessage =
    | Kill
    | Fuzz of string * int
    | Setup of string * string

    static member serialize msg =
        match msg with
        | Kill -> "Kill"
        | Fuzz (moduleName, methodToken) -> $"Fuzz %s{moduleName} %d{methodToken}"
        | Setup (assemblyPath, outputDir) -> $"Setup %s{assemblyPath} %s{outputDir}"

    static member deserialize (str: string) =
        let parts = str.Split ' '
        match parts[0] with
        | "Kill" -> Kill
        | "Fuzz" -> assert (parts.Length = 3); Fuzz (parts[1], int parts[2])
        | "Setup" -> assert (parts.Length = 3); Setup (parts[1], parts[2])
        | _ -> internalfail $"Unknown client message: {str}"

type ClientMessage =
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
        Logger.error "try to connect fuzzer"
        onStart ()
        Logger.error "fuzzer connected"
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

type FuzzerApplication () =
    let fuzzer = Fuzzer ()
    let client =
        let io = new NamedPipeClientStream(".", "FuzzerPipe", PipeDirection.InOut)
        FuzzerPipe(io, io.Connect, ClientMessage.serialize, ServerMessage.deserialize)
    let mutable assembly = Unchecked.defaultof<Reflection.Assembly>
    let mutable outputDir = ""

    let mutable freeId = -1
    let nextId () =
        freeId <- freeId + 1
        freeId

    let handleRequest command =
        async {
            match command with
            | Setup(assemblyPath, newOutputDir) ->
                assembly <- AssemblyManager.LoadFromAssemblyPath assemblyPath
                outputDir <- newOutputDir
                return false
            | Fuzz (moduleName, methodToken) ->
                let methodBase = Reflection.resolveMethodBaseFromAssembly assembly moduleName methodToken
                let method = Application.getMethod methodBase

                Interop.InstrumenterCalls.setEntryMain assembly moduleName methodToken

                Logger.error $"Start fuzzing {moduleName} {methodToken}"

                do! fuzzer.FuzzWithAction method (fun state -> async {
                    let test = TestGenerator.state2test false method state ""
                    match test with
                    | Some test ->
                        let filePath = $"{outputDir}{Path.DirectorySeparatorChar}fuzzer_test{nextId ()}.vst"
                        Logger.error $"Saved to {filePath}"
                        let hist = Interop.InstrumenterCalls.getHistory()
                        Logger.error $"count: {hist.Length}"
                        Logger.error $"size: {hist[0].Length}"
                        do! client.SendMessage (Statistics hist[0])
                        test.Serialize filePath
                    | None -> ()
                })

                Logger.error $"Successfully fuzzed {moduleName} {methodToken}"
                return false

            | Kill -> return true
        }

    member this.Start () = client.ReadAll handleRequest

type FuzzerInteraction (
    cancellationToken: CancellationToken,
    saveStatistic: codeLocation seq -> unit,
    dllsPath: string,
    outputPath: string
    ) =

    // let extension =
    //     if RuntimeInformation.IsOSPlatform(OSPlatform.Windows) then ".dll"
    //     elif RuntimeInformation.IsOSPlatform(OSPlatform.Linux) then ".so"
    //     elif RuntimeInformation.IsOSPlatform(OSPlatform.OSX) then ".dylib"
    //     else __notImplemented__()
    //
    // let pathToClient = $"libvsharpConcolic{extension}"
    // let profiler = $"%s{Directory.GetCurrentDirectory()}%c{Path.DirectorySeparatorChar}%s{pathToClient}"

    let fuzzerContainer = Docker.startFuzzer dllsPath outputPath

    let server =
        let io = new NamedPipeServerStream("FuzzerPipe", PipeDirection.InOut)
        FuzzerPipe (io, io.WaitForConnection, ServerMessage.serialize, ClientMessage.deserialize)

    let methods = System.Collections.Generic.Dictionary<int, Method>()
    let toSiliStatistic (loc: CoverageLocation seq) =

        let getMethod l =
            match methods.TryGetValue(l.methodToken) with
            | true, m -> m
            | false, _ ->
                let methodBase = Reflection.resolveMethodBase l.assemblyName l.moduleName l.methodToken
                let method = Application.getMethod methodBase
                methods.Add (l.methodToken, method)
                method

        let toCodeLocation l =
            {
                offset = LanguagePrimitives.Int32WithMeasure l.offset
                method = getMethod l
            }
            
        loc |> Seq.map toCodeLocation

    let handleRequest msg =
        async {
            match msg with
            | Statistics s -> toSiliStatistic s |> saveStatistic
            return false
        }

    do
        cancellationToken.Register(fun () -> fuzzerContainer.Kill ())
        |> ignore

    member this.Fuzz (moduleName: string, methodToken: int) =
        Logger.error $"Send to fuzz {methodToken}"
        server.SendMessage (Fuzz (moduleName, methodToken))

    member this.WaitStatistics ()  =
        async {
            do! server.SendMessage Kill
            Logger.error "Kill message sent to fuzzer"
            do! server.ReadAll handleRequest
            do! fuzzerContainer.WaitForExitAsync () |> Async.AwaitTask
            Logger.error "Fuzzer stopped"
        }

    member this.Setup (assemblyPath, outputDir) =  Setup (assemblyPath, outputDir) |> server.SendMessage

    // member this.Kill = killFuzzer
