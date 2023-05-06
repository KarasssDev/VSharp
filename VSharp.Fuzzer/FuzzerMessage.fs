module VSharp.Fuzzer.FuzzerMessage


open System
open System.IO
open VSharp


let private readNBytes (stream: Stream) n =
    async {
        let buffer = Array.zeroCreate<byte> n
        let! _ = stream.ReadAsync (buffer, 0, n) |> Async.AwaitTask
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

let serializeAssembly (assembly: System.Reflection.Assembly) =
    File.ReadAllBytes assembly.Location |> serializeByteArray

let deserializeAssembly (stream: Stream) =
    async {
        let! bytes = deserializeByteArray stream 
        return System.Reflection.Assembly.Load bytes
    }

let private killByte = [| byte 1 |]
let private fuzzByte = [| byte 2 |]
let private setupOutputDirByte = [| byte 3 |]
let private returnAssemblyByte = [| byte 4 |]

type ClientMessage =
    | Kill
    | Fuzz of string * int
    | Setup of string * System.Reflection.Assembly
    | ReturnAssembly of System.Reflection.Assembly

    static member serialize msg =
        match msg with
        | Kill -> killByte
        | Fuzz (moduleName, methodToken) ->
            Array.concat [
                fuzzByte
                serializeString moduleName
                serializeInt methodToken
            ]
        | Setup (outputDir, assembly) ->
            Array.concat [
                setupOutputDirByte
                serializeString outputDir
                serializeAssembly assembly
            ]
        | ReturnAssembly assembly ->
            Array.concat [
                returnAssemblyByte
                serializeAssembly assembly
            ]

    static member deserialize (stream: Stream) =
        async {
            let! messageType = readNBytes stream 1

            let! result =
                async {
                    if messageType = killByte then
                        return Kill |> Some
                    elif messageType = fuzzByte then
                        let! moduleName = deserializeString stream
                        let! methodToken = deserializeInt stream
                        return Fuzz (moduleName, methodToken) |> Some
                    elif messageType = setupOutputDirByte then
                        let! outputDir = deserializeString stream
                        let! assembly = deserializeAssembly stream
                        return Setup (outputDir, assembly) |> Some
                    elif messageType = returnAssemblyByte then
                        let! assembly = deserializeAssembly stream
                        return ReturnAssembly assembly |> Some
                    else
                        return None
                }

            if result.IsNone && int messageType[0] <> 0 then
                internalfail $"Unexpected message type byte {messageType[0]}"

            return result
        }

let private statisticsByte = [| byte 1 |]
let private requestAssemblyByte = [| byte 2 |]

type ServerMessage =
    | Statistics of byte array
    | RequestAssembly

    static member serialize msg =
        match msg with
        | Statistics bytes ->
            Array.concat [
                statisticsByte
                serializeByteArray bytes
            ]
        | RequestAssembly -> requestAssemblyByte

    static member deserialize (stream: Stream) =
        async {
            let! messageType = readNBytes stream 1

            let! result =
                async {
                    if messageType = statisticsByte then
                        let! bytes = deserializeByteArray stream
                        return Statistics bytes |> Some
                    elif messageType = requestAssemblyByte then
                        return RequestAssembly |> Some
                    else
                        return None
                }

            if result.IsNone && int messageType[0] <> 0 then
                internalfail $"Unexpected message type byte {messageType[0]}"

            return result
        }