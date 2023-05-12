module VSharp.Fuzzer.FuzzerMessage


open System
open System.IO
open System.Threading
open System.Threading.Tasks
open VSharp

type private DeserializerMonad<'a> = Stream -> CancellationToken -> Task<'a>
let runDeserializer (stream: Stream) (token: CancellationToken) (m: DeserializerMonad<'a>) = m stream token

type DeserializeBuilder () =
    member this.Bind (m: DeserializerMonad<'a>, k: 'a -> DeserializerMonad<'b>): DeserializerMonad<'b> =
        fun stream token ->
            task {
                let! v = m stream token
                let! result = k v stream token
                return result
            }
    member this.Return (v: 'a): DeserializerMonad<'a> = fun _ _ -> task { return v }

let deserialize = DeserializeBuilder()

let private readNBytes (n: int): DeserializerMonad<byte array> =
    Fuzzer.Logger.logError $"Try read {n} bytes"
    fun stream token ->
        task {
            let buffer = Array.zeroCreate<byte> n
            let mutable alreadyReadCount = 0
            while alreadyReadCount <> n do
                let! count = stream.ReadAsync (buffer, alreadyReadCount, n - alreadyReadCount, token)
                alreadyReadCount <- alreadyReadCount + count
            Fuzzer.Logger.logError $"Read {n} bytes"
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


    static member deserialize (stream: Stream) cancellationToken =
        Fuzzer.Logger.logTrace "Try deserialize message"
        deserialize {
            Fuzzer.Logger.logTrace "Try read message type"
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

    static member deserialize (stream: Stream) token =
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
