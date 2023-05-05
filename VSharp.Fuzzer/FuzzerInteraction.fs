namespace VSharp.Fuzzer

open System
open System.IO
open System.Net
open System.Net.Sockets
open System.Threading
open System.Threading.Tasks
open Microsoft.FSharp.Control
open VSharp
open VSharp.Fuzzer.FuzzerMessage
open VSharp.Interpreter.IL

type private FuzzerCommunicator<'a, 'b> (
    init: unit -> NetworkStream,
    serialize: 'a -> byte array,
    deserialize: Stream -> Async<'b option>
    ) =

    let mutable stream = Unchecked.defaultof<NetworkStream>

    do
        stream <- init ()

    member this.ReadMessage () = deserialize (stream :> Stream)

    member this.SendMessage msg =
        async {
            do! stream.WriteAsync(serialize msg).AsTask() |> Async.AwaitTask
            do! stream.FlushAsync () |> Async.AwaitTask
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

type FuzzerApplication (outputDir: string) =
    let fuzzer = Fuzzer ()

    let server =
        let init () =
            let server = TcpListener(IPAddress.Any, Docker.fuzzerContainerPort)
            server.Start ()
            Fuzzer.Logger.logTrace "Wait connection"
            let client = server.AcceptTcpClient ()
            Fuzzer.Logger.logInfo "Client connected"
            client.GetStream()

        FuzzerCommunicator (init, ServerMessage.serialize, ClientMessage.deserialize)

    let mutable assembly = Unchecked.defaultof<Reflection.Assembly>

    let mutable freeId = -1
    let nextId () =
        freeId <- freeId + 1
        freeId

    let handleRequest command =
        async {
            match command with
            | Setup pathToTargetAssembly ->
                Fuzzer.Logger.logTrace $"Received: Setup {pathToTargetAssembly}"
                assembly <- AssemblyManager.LoadFromAssemblyPath pathToTargetAssembly
                Fuzzer.Logger.logTrace $"Target assembly was set to {assembly.FullName}"
                return false
            | Fuzz (moduleName, methodToken) ->
                Fuzzer.Logger.logTrace $"Received: Fuzz {moduleName} {methodToken}"
                let methodBase = Reflection.resolveMethodBaseFromAssembly assembly moduleName methodToken
                Fuzzer.Logger.logTrace $"Resolved MethodBase {methodToken}"
                let method = Application.getMethod methodBase
                Fuzzer.Logger.logTrace $"Resolved Method {methodToken}"
                Interop.InstrumenterCalls.setEntryMain assembly moduleName methodToken
                Fuzzer.Logger.logTrace $"Was set entry main {moduleName} {methodToken}"
                Fuzzer.Logger.logTrace $"Start fuzzing {moduleName} {methodToken}"

                do! fuzzer.FuzzWithAction method (fun state -> async {
                    let test = TestGenerator.state2test false method state ""
                    match test with
                    | Some test ->
                        let filePath = $"{outputDir}{Path.DirectorySeparatorChar}fuzzer_test{nextId ()}.vst"
                        let hist = Interop.InstrumenterCalls.getRawHistory()
                        Fuzzer.Logger.logTrace "Got raw history from instrumenter"
                        do! server.SendMessage (Statistics hist)
                        Fuzzer.Logger.logTrace "Sent raw history"
                        test.Serialize filePath
                        Fuzzer.Logger.logInfo $"Test saved to {filePath}"
                    | None -> ()
                })
                Fuzzer.Logger.logInfo $"Successfully fuzzed {moduleName} {methodToken}"
                return false
            | Kill ->
                Fuzzer.Logger.logTrace "Received: Kill"
                do! server.SendMessage End
                return true
        }

    member this.Start () = server.ReadAll handleRequest

type FuzzerInteraction (
    cancellationToken: CancellationToken,
    saveStatistic: codeLocation seq -> unit,
    dllPaths: string seq,
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

    let fuzzerContainer = Docker.startFuzzer outputPath dllPaths
    let killFuzzer () = fuzzerContainer.Kill ()
    let client =
        let rec connect (tcpClient: TcpClient) =
            try
                tcpClient.Connect("localhost", Docker.fuzzerContainerPort)
            with
                | _ ->
                    Thread.Sleep(10)
                    connect tcpClient

        let init () =
            let tcpClient = new TcpClient()
            connect tcpClient
            tcpClient.GetStream ()
            
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
            | Statistics s ->
                (CoverageDeserializer.getHistory s)[0] |> toSiliStatistic |> saveStatistic
                return false
            | End ->
                return true
        }

    do
        let innerTimeout =
            FuzzerInfo.defaultFuzzerConfig.MaxTest
            * FuzzerInfo.defaultFuzzerConfig.Timeout
            * 2
        let innerTimeoutCancellationToken =
            let tokSource = new CancellationTokenSource(innerTimeout)
            tokSource.Token
        let linkedCancellationToken =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, innerTimeoutCancellationToken).Token
        setupIOCancellationToken linkedCancellationToken
        linkedCancellationToken.Register(fun () ->
            killFuzzer ()
            Logger.warning "Fuzzer killed by timeout"
        ) |> ignore

    member this.Fuzz (moduleName: string, methodToken: int) =
        Logger.trace $"Send to fuzz {methodToken}"
        client.SendMessage (Fuzz (moduleName, methodToken))

    member this.WaitStatistics ()  =
        async {
            do! client.SendMessage Kill
            Logger.trace "Kill message sent to fuzzer"
            do! client.ReadAll handleRequest
            do! fuzzerContainer.WaitForExitAsync () |> Async.AwaitTask
            Logger.trace "Fuzzer stopped"
        }

    member this.Setup assembly = Setup assembly |> client.SendMessage


