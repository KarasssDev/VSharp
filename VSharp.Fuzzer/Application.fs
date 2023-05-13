namespace VSharp.Fuzzer

open System.IO
open System.Net
open System.Net.Sockets
open System.Reflection
open System.Threading
open VSharp
open VSharp.Fuzzer.Message
open VSharp.Interpreter.IL

type Application (outputDir: string) =
    let fuzzer = Fuzzer ()
    let ioTokenSource = new CancellationTokenSource()
    let ioToken = ioTokenSource.Token

    let server =

        let init =
            task {
                let server = TcpListener(IPAddress.Any, Docker.fuzzerContainerPort)
                server.Start ()
                Logger.logTrace "Wait connection"
                let! client = server.AcceptTcpClientAsync ioToken
                Logger.logInfo "Client connected"
                return client.GetStream()
            }

        let onIoFail _ =
            Logger.error "IO error"

        FuzzerCommunicator (
            init,
            ServerMessage.serialize,
            ClientMessage.deserialize,
            ioToken,
            onIoFail
        )

    let mutable assembly = Unchecked.defaultof<Assembly>

    let mutable freeId = -1
    let nextId () =
        freeId <- freeId + 1
        freeId

    let handleRequest command =
        task {
            match command with
            | Setup pathToTargetAssembly ->
                Logger.logTrace $"Received: Setup {pathToTargetAssembly}"
                assembly <- AssemblyManager.LoadFromAssemblyPath pathToTargetAssembly
                Logger.logTrace $"Target assembly was set to {assembly.FullName}"
                return false
            | Fuzz (moduleName, methodToken) ->
                Logger.logTrace $"Received: Fuzz {moduleName} {methodToken}"
                let methodBase = Reflection.resolveMethodBaseFromAssembly assembly moduleName methodToken
                Logger.logTrace $"Resolved MethodBase {methodToken}"
                let method = Application.getMethod methodBase
                Logger.logTrace $"Resolved Method {methodToken}"
                Interop.InstrumenterCalls.setEntryMain assembly moduleName methodToken
                Logger.logTrace $"Was set entry main {moduleName} {methodToken}"
                Logger.logTrace $"Start fuzzing {moduleName} {methodToken}"

                do! fuzzer.FuzzWithAction method (fun state -> task {
                    let test = TestGenerator.state2test false method state ""
                    match test with
                    | Some test ->
                        let filePath = $"{outputDir}{Path.DirectorySeparatorChar}fuzzer_test{nextId ()}.vst"
                        let hist = Interop.InstrumenterCalls.getRawHistory()
                        Logger.logTrace "Got raw history from instrumenter"
                        do! server.SendMessage (Statistics hist)
                        Logger.logTrace "Sent raw history"
                        test.Serialize filePath
                        Logger.logInfo $"Test saved to {filePath}"
                    | None -> ()
                })
                Logger.logInfo $"Successfully fuzzed {moduleName} {methodToken}"
                return false
            | Kill ->
                Logger.logTrace "Received: Kill"
                do! server.SendMessage End
                return true
        }

    member this.Start () =
        Logger.logTrace "Try start application"
        task {
            try
                do! server.ReadAll handleRequest
            with _ -> ioTokenSource.Cancel()
        }