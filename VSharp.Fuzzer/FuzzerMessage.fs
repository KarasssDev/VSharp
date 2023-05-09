module VSharp.Fuzzer.FuzzerMessage


open System
open System.IO
open System.Threading
open VSharp

let mutable private cancellationToken: CancellationToken option = None
let setupIOCancellationToken newToken = cancellationToken <- Some newToken 

let private readNBytes (stream: Stream) n =
    Fuzzer.Logger.logTrace $"Try read {n} bytes"
    async {
        let buffer = Array.zeroCreate<byte> n
        let mutable alreadyReadCount = 0
        while alreadyReadCount <> n do
            let! count =
                match cancellationToken with
                | Some tok -> stream.ReadAsync (buffer, alreadyReadCount, n - alreadyReadCount, tok) |> Async.AwaitTask
                | None -> stream.ReadAsync (buffer, alreadyReadCount, n - alreadyReadCount) |> Async.AwaitTask
            alreadyReadCount <- alreadyReadCount + count
        Fuzzer.Logger.logTrace $"Read {n} bytes"
        return buffer
    }
    

let private serializeInt (n: int) = BitConverter.GetBytes n
let private deserializeInt (stream: Stream) =
    async {
        let! bytes = readNBytes stream 4
        return BitConverter.ToInt32 bytes
    }
let serializeByteArray (bytes: byte array) =
    Array.concat [
        serializeInt bytes.Length
        bytes
    ]
let deserializeByteArray (stream: Stream) =
    async {
        let! size = deserializeInt stream
        return! readNBytes stream size
    }

let private serializeString (str: string) =
    System.Text.UTF32Encoding.UTF32.GetBytes str |> serializeByteArray

let private deserializeString (stream: Stream) =
    async {
        let! bytes = deserializeByteArray stream 
        return System.Text.UTF32Encoding.UTF32.GetString bytes
    }

let private killByte = [| byte 1 |]
let private fuzzByte = [| byte 2 |]
let private setupTargetAssemblyByte = [| byte 3 |]
type ClientMessage =
    | Kill
    | Fuzz of string * int
    | Setup of string

    static member serialize msg =
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


    static member deserialize (stream: Stream) =
        Fuzzer.Logger.logTrace "Try deserialize message"
        async {
            Fuzzer.Logger.logTrace "Try read message type"
            let! messageType = readNBytes stream 1

            let! result =
                async {
                    if messageType = killByte then
                        return Kill |> Some
                    elif messageType = fuzzByte then
                        let! moduleName = deserializeString stream
                        let! methodToken = deserializeInt stream
                        return Fuzz (moduleName, methodToken) |> Some
                    elif messageType = setupTargetAssemblyByte then
                        let! pathToTargetAssembly = deserializeString stream
                        return Setup pathToTargetAssembly |> Some
                    else
                        return None
                }

            if result.IsNone then
                let errorMessage = $"Unexpected message type byte {messageType[0]}"
                Fuzzer.Logger.logError $"{errorMessage}"
                internalfail $"{errorMessage}"

            return result
        }

let private statisticsByte = [| byte 1 |]
let private endByte = [| byte 2 |]
type ServerMessage =
    | Statistics of byte array
    | End

    static member serialize msg =
        match msg with
        | Statistics bytes ->
            Array.concat [
                statisticsByte
                serializeByteArray bytes
            ]
        | End -> endByte

    static member deserialize (stream: Stream) =
        async {
            let! messageType = readNBytes stream 1
            let! result =
                async {
                    if messageType = statisticsByte then
                        let! bytes = deserializeByteArray stream
                        return Statistics bytes |> Some
                    elif messageType = endByte then
                        return Some End
                    else
                        return None
                }

            if result.IsNone  then
                internalfail $"Unexpected message type byte {messageType[0]}"

            return result
        }