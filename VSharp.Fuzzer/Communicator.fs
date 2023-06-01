namespace VSharp.Fuzzer

open System.IO
open System.Net.Sockets
open System.Threading
open System.Threading.Tasks
open VSharp

type internal FuzzerCommunicator<'a, 'b> (
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

    let traceInteraction (log: string) = Logger.traceWithTag Logger.fuzzerInteractionTraceTag $"{log}"

    let mutable stream = Unchecked.defaultof<NetworkStream>

    do
        #if DEBUGFUZZER || DEBUG
        Logger.enableTag Logger.fuzzerInteractionTraceTag
        #endif

        init.Wait()
        if init.Exception = null then
            stream <- init.Result
            traceInteraction "Initialized communicator"
        else
            onIoFail init.Exception

    member private this.ReadMessage () =
        traceInteraction "Try read message"
        deserialize (stream :> Stream) cancellationToken

    member this.SendMessage msg =
        traceInteraction $"Try send message: {msg}"
        task {
            do! stream.WriteAsync(serialize msg, cancellationToken).AsTask()
            do! stream.FlushAsync cancellationToken
        } |> tryIo

    member this.ReadAll onEach =
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
