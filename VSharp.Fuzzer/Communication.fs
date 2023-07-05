module internal VSharp.Fuzzer.Communication

open System
open System.IO
open System.Net
open System.Net.Sockets
open System.Threading
open System.Threading.Tasks
open VSharp
open Logger

type ClientMessage =
    | Kill
    | Fuzz of string * int
    | Setup of string

type ServerMessage =
    | Statistics of byte array
    | End

type ICommunicator<'a, 'b> =
    abstract member ReadMessages: ('b -> Task<bool>) -> Task<unit>
    abstract member SendMessage: 'a -> Task<unit>

module private MessageSerialization =
    type private DeserializerMonad<'a> = Stream -> CancellationToken -> Task<'a>
    let private runDeserializer (stream: Stream) (token: CancellationToken) (m: DeserializerMonad<'a>) = m stream token

    type private DeserializeBuilder () =
        member this.Bind (m: DeserializerMonad<'a>, k: 'a -> DeserializerMonad<'b>): DeserializerMonad<'b> =
            fun stream token ->
                task {
                    let! v = m stream token
                    let! result = k v stream token
                    return result
                }
        member this.Return (v: 'a): DeserializerMonad<'a> = fun _ _ -> task { return v }

    let private deserialize = DeserializeBuilder()

    let private readNBytes (n: int): DeserializerMonad<byte array> =
        fun stream token ->
            task {
                let buffer = Array.zeroCreate<byte> n
                let mutable alreadyReadCount = 0
                while alreadyReadCount <> n do
                    let! count = stream.ReadAsync (buffer, alreadyReadCount, n - alreadyReadCount, token)
                    alreadyReadCount <- alreadyReadCount + count
                return buffer
            }


    let private serializeInt (n: int) = BitConverter.GetBytes n

    let x: DeserializerMonad<byte array> = readNBytes 4

    let private deserializeInt () =
        deserialize {
            let! bytes = readNBytes 4
            return BitConverter.ToInt32 bytes
        }

    let serializeByteArray (bytes: byte array) =
        Array.concat [
            serializeInt bytes.Length
            bytes
        ]

    let deserializeByteArray ()  =
        deserialize {
            let! size = deserializeInt ()
            let! array = readNBytes size
            return array
        }

    let private serializeString (str: string) =
        System.Text.UTF32Encoding.UTF32.GetBytes str |> serializeByteArray

    let private deserializeString () =
        deserialize {
            let! bytes = deserializeByteArray ()
            return System.Text.UTF32Encoding.UTF32.GetString bytes
        }

    let private killByte = [| byte 1 |]
    let private fuzzByte = [| byte 2 |]
    let private setupTargetAssemblyByte = [| byte 3 |]

    let serializeClientMessage msg =
        match msg with
        | Kill -> killByte
        | Fuzz (moduleName, methodToken) ->
            Array.concat [
                fuzzByte
                serializeString moduleName
                serializeInt methodToken
            ]
        | Setup pathToTargetAssembly ->
            Array.concat [
                setupTargetAssemblyByte
                serializeString pathToTargetAssembly
            ]

    let deserializeClientMessage (stream: Stream) cancellationToken =
        deserialize {
            let! messageType = readNBytes 1
            if messageType = killByte then
                return Kill |> Some
            elif messageType = fuzzByte then
                let! moduleName = deserializeString ()
                let! methodToken = deserializeInt ()
                return Fuzz (moduleName, methodToken) |> Some
            elif messageType = setupTargetAssemblyByte then
                let! pathToTargetAssembly = deserializeString ()
                return Setup pathToTargetAssembly |> Some
            else
                return None
        }
        |> runDeserializer stream cancellationToken

    let private statisticsByte = [| byte 1 |]
    let private endByte = [| byte 2 |]

    let serializeServerMessage msg =
        match msg with
        | Statistics bytes ->
            Array.concat [
                statisticsByte
                serializeByteArray bytes
            ]
        | End -> endByte

    let deserializeServerMessage (stream: Stream) token =
        deserialize {
            let! messageType = readNBytes 1
            if messageType = statisticsByte then
                let! bytes = deserializeByteArray ()
                return Statistics bytes |> Some
            elif messageType = endByte then
                return Some End
            else
                return None
        } |> runDeserializer stream token



module TcpCommunicator =
    type private TcpCommunicator<'a, 'b> (
        init: Task<NetworkStream>,
        serialize: 'a -> byte array,
        deserialize: Stream -> CancellationToken -> Task<'b option>,
        cancellationToken: CancellationToken,
        onIoFail: exn -> unit
        ) =

        let tryIo io =
            task {
                try
                    do! io
                with
                    | :? SocketException
                    | :? IOException as e -> onIoFail e
            }

        let mutable stream = Unchecked.defaultof<NetworkStream>

        do
            init.Wait()
            if init.Exception = null then
                stream <- init.Result
                traceCommunication "Initialized communicator"
            else
                onIoFail init.Exception

        member private this.ReadMessage () =
            traceCommunication "Try read message"
            deserialize (stream :> Stream) cancellationToken

        interface ICommunicator<'a, 'b> with
            member this.SendMessage msg =
                traceCommunication $"Try send message: {msg}"
                task {
                    do! stream.WriteAsync(serialize msg, cancellationToken).AsTask()
                    do! stream.FlushAsync cancellationToken
                } |> tryIo

            member this.ReadMessages onEach =
                task {
                    let mutable completed = false
                    while not completed do
                        let! message = this.ReadMessage ()
                        match message with
                        | Some v ->
                            let! stop = onEach v
                            completed <- stop
                        | None -> completed <- true
                } |> tryIo

    let private tcpPort = 29172

    let createTcpClientCommunicator cancellationToken onIoFail =
        let connect (tcpClient: TcpClient) =
            task {
                let mutable connected = false
                while not connected do
                    try
                        do! tcpClient.ConnectAsync("localhost", tcpPort, cancellationToken)
                        connected <- true
                    with _ -> Thread.Sleep(100)
            }

        let init  =
            task {
                let tcpClient = new TcpClient()
                do! connect tcpClient
                return tcpClient.GetStream ()
            }

        TcpCommunicator(
            init,
            MessageSerialization.serializeClientMessage,
            MessageSerialization.deserializeServerMessage,
            cancellationToken,
            onIoFail
        ) :> ICommunicator<_, _>

    let createTcpServerCommunicator cancellationToken onIoFail =

        let init =
            task {
                let server = TcpListener(IPAddress.Any, tcpPort)
                server.Start ()
                let! client = server.AcceptTcpClientAsync cancellationToken
                return client.GetStream()
            }

        TcpCommunicator(
            init,
            MessageSerialization.serializeServerMessage,
            MessageSerialization.deserializeClientMessage,
            cancellationToken,
            onIoFail
        ) :> ICommunicator<_, _>
