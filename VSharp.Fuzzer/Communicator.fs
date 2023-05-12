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
            with e ->
                onIoFail e
        }


    let mutable stream = Unchecked.defaultof<NetworkStream>

    do
        init.Wait()
        if init.Exception = null then
            stream <- init.Result
            Fuzzer.Logger.logTrace "Initialized communicator"
        else
            onIoFail init.Exception

    member private this.ReadMessage () =
        Fuzzer.Logger.logTrace "Try read message"
        deserialize (stream :> Stream) cancellationToken

    member this.SendMessage msg =
        Fuzzer.Logger.logTrace "Try send message"
        task {
            do! stream.WriteAsync(serialize msg, cancellationToken).AsTask()
            do! stream.FlushAsync cancellationToken
        } |> tryIo

    member this.ReadAll onEach =
        Fuzzer.Logger.logTrace "Start start ReadAll"
        task {
            Fuzzer.Logger.logTrace "Start ReadAll"
            let mutable completed = false
            while not completed do
                let! message = this.ReadMessage ()
                match message with
                | Some v ->
                    let! stop = onEach v
                    completed <- stop
                | None -> completed <- true
        } |> tryIo
