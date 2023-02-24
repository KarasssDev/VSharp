module VSharp.Generator.PrimitiveGenerator

open System


open VSharp.Generator.Config
open VSharp



let private numericTypes = [
    typeof<int8>; typeof<int16>; typeof<int32>; typeof<int64>
    typeof<uint8>; typeof<uint16>; typeof<uint32>; typeof<uint64>
    typeof<float>; typeof<double>
    typeof<byte>
]

let private primitiveTypes = List.append numericTypes [typeof<char>; typeof<bool>; typeof<string>; typeof<decimal>]

let private numericCreators: (Type * int * (byte array -> obj)) list = [
    typeof<int8>, sizeof<int8>, BitConverter.ToInt16 >> box
    typeof<int16>, sizeof<int16>, BitConverter.ToInt16 >> box
    typeof<int32>, sizeof<int32>, BitConverter.ToInt32 >> box
    typeof<int64>, sizeof<int64>, BitConverter.ToInt64 >> box
    typeof<uint8>, sizeof<uint8>, BitConverter.ToUInt16 >> box
    typeof<uint16>, sizeof<uint16>, BitConverter.ToUInt16 >> box
    typeof<uint32>, sizeof<uint32>, BitConverter.ToUInt32 >> box
    typeof<uint64>, sizeof<uint64>, BitConverter.ToUInt64 >> box
    typeof<float32>, sizeof<float32>, BitConverter.ToSingle >> box
    typeof<double>, sizeof<double>, BitConverter.ToDouble >> box
    typeof<byte>, sizeof<byte>, (fun x -> x[0]) >> box
]

let (|Primitive|_|) t =
    if List.contains t primitiveTypes then Some Primitive else None

let (|Numeric|_|) t =
    if List.contains t numericTypes then Some Numeric else None

let generate (rnd: Random) (conf: GeneratorConfig) (t: Type) =

    let generateNumericType (t: Type) =
        let _, size, create = List.find ( fun (x, _, _) -> x = t) numericCreators
        let buffer = Array.create<byte> size 0uy
        rnd.NextBytes(buffer);
        create buffer

    let generateChar () =
        // ASCII
        rnd.Next(33, 126) |> char

    let generateString () =
        let size = rnd.Next (0, conf.StringMaxSize)
        Array.create size (char 0) |> Array.map (fun _ -> generateChar ())

    let generateBool () =
        rnd.Next(0, 2) = 1

    let generateDecimal () =
        let scale = rnd.Next(29) |> byte
        let sign = generateBool ()
        Decimal (rnd.Next(), rnd.Next(), rnd.Next(), sign, scale)

    match t with
    | Numeric -> generateNumericType t
    | _ when t = typeof<char> -> generateChar ()
    | _ when t = typeof<string> -> generateString ()
    | _ when t = typeof<bool> -> generateBool ()
    | _ when t = typeof<decimal> -> generateDecimal ()
    | _ -> internalfail $"unexpected type {t}"
