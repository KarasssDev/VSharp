namespace VSharp.Fuzzer

open System
open System.Diagnostics
open System.IO
open System.IO.Pipes

open System.Net
open System.Net.Sockets
open System.Runtime.InteropServices
open System.Text
open System.Threading
open System.Threading.Tasks
open Microsoft.FSharp.Control
open Microsoft.FSharp.NativeInterop
open VSharp
open VSharp.Fuzzer.FuzzerMessage
open VSharp.Interpreter.IL

type private FuzzerCommunicator<'a, 'b> (
    init: unit -> Task<Stream>,
    serialize: 'a -> byte array,
    deserialize: Stream -> Async<'b option>
    ) =

    let mutable stream = Unchecked.defaultof<Stream>

    do
        Logger.error "try to connect"
        let ioTask = init()
        ioTask.Wait()
        stream <- ioTask.Result
        Logger.error "connected"


    member this.ReadMessage () = deserialize stream
    member this.SendMessage msg =
        async {
            let! result = stream.WriteAsync(serialize msg).AsTask() |> Async.AwaitTask
            do! stream.FlushAsync () |> Async.AwaitTask
            return result
        }

    member this.ReadAll onEach =
        async {
            let mutable completed = false
            while not completed do
                let! message = this.ReadMessage ()
                match message with
                | Some v -> 
                    let! stop = onEach v
                    completed <- stop
                | None -> completed <- true
        }
    member this.SendEnd () = stream.Close ()

type FuzzerApplication (outputDir) =
    let fuzzer = Fuzzer ()

    let server =
        let init () =
            task {
                let server = TcpListener(IPAddress.Any, Docker.fuzzerContainerPort)
                server.Start ()
                let! client = server.AcceptTcpClientAsync ()
                return client.GetStream () :> Stream
            }
        FuzzerCommunicator (init, ServerMessage.serialize, ClientMessage.deserialize)

    let mutable assembly = Unchecked.defaultof<Reflection.Assembly>

    let mutable freeId = -1
    let nextId () =
        freeId <- freeId + 1
        freeId

    let handleRequest command =
        async {
            match command with
            | Setup newAssembly ->
                assembly <- newAssembly
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
                        let hist = Interop.InstrumenterCalls.getRawHistory()
                        Logger.error $"count: {hist.Length}"
                        do! server.SendMessage (Statistics hist)
                        test.Serialize filePath
                    | None -> ()
                })

                Logger.error $"Successfully fuzzed {moduleName} {methodToken}"
                return false
            | ReturnAssembly _-> return false
            | Kill -> return true
        }

    member this.Start () = server.ReadAll handleRequest

type FuzzerInteraction (
    cancellationToken: CancellationToken,
    saveStatistic: codeLocation seq -> unit,
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

    let fuzzerContainer = Docker.startFuzzer outputPath

    let client =
        let rec connect (tcpClient: TcpClient) =
            task {
                try
                    tcpClient.Connect("localhost", Docker.fuzzerContainerPort)
                with
                    | _ ->
                        Thread.Sleep(50)
                        do! connect tcpClient
            }

        let init () =
            task {
                let tcpClient = new TcpClient()
                do! connect tcpClient
                return tcpClient.GetStream () :> Stream
            }
        FuzzerCommunicator(init, ClientMessage.serialize, ServerMessage.deserialize)


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
            | Statistics s -> (CoverageDeserializer.getHistory s)[0] |> toSiliStatistic |> saveStatistic
            | RequestAssembly -> ()
            return false
        }

    do
        cancellationToken.Register(fun () -> fuzzerContainer.Kill ())
        |> ignore

    member this.Fuzz (moduleName: string, methodToken: int) =
        Logger.error $"Send to fuzz {methodToken}"
        client.SendMessage (Fuzz (moduleName, methodToken))

    member this.WaitStatistics ()  =
        async {
            do! client.SendMessage Kill
            Logger.error "Kill message sent to fuzzer"
            do! client.ReadAll handleRequest
            do! fuzzerContainer.WaitForExitAsync () |> Async.AwaitTask
            Logger.error "Fuzzer stopped"
        }

    member this.Setup assembly = Setup assembly |> client.SendMessage


