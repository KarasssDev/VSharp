module internal VSharp.Fuzzer.Generator

open System
open System.Reflection
open Microsoft.FSharp.NativeInterop
open VSharp
open VSharp.Core

let private instancesCache = System.Collections.Generic.Dictionary<Type, Type option>()
let mutable private allocatedObjects = System.Collections.Generic.HashSet<obj>()
let mutable private instantiatedMocks = System.Collections.Generic.Dictionary<obj, ITypeMock>()
let mutable private referencedObjects = System.Collections.Generic.HashSet<obj>()

let private setAllFields (t : Type) (setter: Type -> obj) =
    let isStatic = t.IsAbstract && t.IsSealed
    let fields = Reflection.fieldsOf isStatic t
    let instance = System.Runtime.Serialization.FormatterServices.GetUninitializedObject t
    for _, fieldInfo in fields do
        fieldInfo.SetValue(instance, setter fieldInfo.FieldType)
    instance

let private generateViaConstructor commonGenerator (t: Type) (rnd: Random) =
    let constructors = t.GetConstructors()
    if (constructors.Length = 0)
    then
        None
    else
        let constructor = constructors[rnd.NextInt64(0,  int64 constructors.Length) |> int32]
        let constructorArgsTypes = constructor.GetParameters() |> Array.map (fun p -> p.ParameterType)
        let constructorArgs = constructorArgsTypes |> Array.map (commonGenerator rnd)
        constructor.Invoke(constructorArgs) |> Some

let private getInstance (t: Type) (rnd: Random) commonGenerator =
    match instancesCache.TryGetValue t with
    | true, instance -> instance
    | false, _ ->
        let instances =
            t.Assembly.GetTypes()
            |> Array.filter (fun x -> x.IsClass && not x.IsAbstract && x.IsPublic && t.IsAssignableFrom(x))
        if instances.Length = 0 then instancesCache.Add(t, None)
        else instancesCache.Add(t, Some instances[rnd.NextInt64(0, instances.Length) |> int])
        instancesCache[t]

let inline private generateUnboxedChar (rnd: Random) =
    // Supports only ASCII for compatibility with test XML serializer
    rnd.Next(33, 126) |> char

let private builtinNumericTypes = [
    typeof<int8>; typeof<int16>; typeof<int32>; typeof<int64>
    typeof<uint8>; typeof<uint16>; typeof<uint32>; typeof<uint64>
    typeof<float>; typeof<double>
    typeof<byte>
]

let private generateUnboxedBool (rnd: Random) =
    rnd.Next(0, 2) = 1

// Generators
let private generateBuiltinNumeric _ (rnd: Random) (t: Type)  =
    let numericCreators: (Type * int * (byte array -> obj)) list = [
        typeof<int8>, sizeof<int8>, (fun x -> x[0]) >> box
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
    let _, size, create = List.find ( fun (x, _, _) -> x = t) numericCreators
    let buffer = Array.create<byte> size 0uy
    Logger.errorFuzzing $"{size}"
    Logger.errorFuzzing $"{buffer.Length}"
    rnd.NextBytes(buffer);
    create buffer

let private generateBool _ (rnd: Random) t =
    (generateUnboxedBool rnd) :> obj

let private generateDecimal _ (rnd: Random) t =
    let scale = rnd.Next(29) |> byte
    let sign = generateUnboxedBool rnd
    Decimal (rnd.Next(), rnd.Next(), rnd.Next(), sign, scale) :> obj

let private generateChar _ (rnd: Random) t =
    (generateUnboxedChar rnd) :> obj

let private generateString _ (rnd: Random) t =
    let size = rnd.Next (0, Options.options.StringMaxSize)
    String(Array.init size (fun _ -> generateUnboxedChar rnd)) :> obj

let private generateEnum _ (rnd: Random) (t: Type) =
    let values = Enum.GetValues(t)
    let index = rnd.NextInt64(0, int64 values.Length) |> int
    values.GetValue(index)

let private generateArray commonGenerator (rnd: Random) (t: Type) =
    if t.IsSZArray then
        let arraySize = rnd.NextInt64(0L, int64 Options.options.ArrayMaxSize) |> int
        let elementType = t.GetElementType()
        let array = Array.CreateInstance(elementType, arraySize)
        for i in 0 .. arraySize - 1 do
            array.SetValue(commonGenerator rnd elementType, i)
        array :> obj
    else
        // TODO: multidimensional arrays
        // TODO: LowerBound
        __notImplemented__ ()

let private generateAbstractClass commonGenerator (rnd: Random) (t: Type) =
    match getInstance t rnd commonGenerator with
    | Some instance -> commonGenerator rnd instance
    | None ->
        let mock, typ = TypeSolver.mockType t (commonGenerator rnd)
        let result = commonGenerator rnd typ
        instantiatedMocks.Add(result, mock)
        result

let private generateByRef commonGenerator (rnd: Random) (t: Type) =
    let referencedType = t.GetElementType()
    let object = commonGenerator rnd referencedType
    Logger.errorFuzzing $"Added to referenced objects: {object}"
    referencedObjects.Add(object) |> ignore
    object

let castToUnmanaged<'a when 'a: unmanaged> (v: obj)  = v :?> 'a

// let generatePointer commonGenerator (rnd: Random) (t: Type) =
//     let elementType = t.GetElementType()
//     let mutable result = commonGenerator rnd t |> unbox
//     Pointer.Box(&&result |> NativePtr.toVoidPtr, typeof<'a>)

let generateIntPointer () =
    let mutable result = 1
    Pointer.Box(&&result |> NativePtr.toVoidPtr, typeof<int>)

let private generatePointer (commonGenerator: Random -> Type -> obj) (rnd: Random) (t: Type) =
    let elementType = t.GetElementType()
    let object = commonGenerator rnd elementType
    let reference = ref object
    let pointer = System.Runtime.CompilerServices.Unsafe.AsPointer(reference)
    Pointer.Box(pointer, t)
    // Pointer.Box(&&object |> NativePtr.toVoidPtr, t)
    // // match elementType with
    // // | _ when elementType = typeof<int> -> generateIntPointer ()
    // // | _ -> failwith "unsupported"

let private generateDelegate commonGenerator (rnd: Random) (t: Type) =
    Prelude.__notImplemented__ ()

let private generateClass commonGenerator (rnd: Random) (t: Type) =
    match generateViaConstructor commonGenerator t rnd with
    | Some obj -> obj
    | None -> setAllFields t (commonGenerator rnd)

// Classification
let private (|ValueType|PointerType|ReferenceType|ByRefType|) (t: Type) =
    if t.IsValueType then ValueType
    elif t.IsPointer then PointerType
    elif t.IsByRef then ByRefType
    else ReferenceType

// Value types
let private (|Enum|BuiltinNumeric|Decimal|Boolean|Char|OtherStruct|) (t: Type) =
    if t.IsEnum then Enum
    elif List.contains t builtinNumericTypes then BuiltinNumeric
    elif t = typeof<Decimal> then Decimal
    elif t = typeof<bool> then Boolean
    elif t = typeof<char> then Char
    else OtherStruct

// Reference types
let private (|Array|Delegate|String|AbstractClass|OtherClass|) (t: Type) =
    if t.IsArray then Array
    elif t = typeof<string> then String
    elif t.IsSubclassOf typeof<System.Delegate> then Delegate
    elif t.IsAbstract || t.IsInterface then AbstractClass
    else OtherClass

let rec private commonGenerate (rnd: Random) (t: Type) =
    Logger.traceFuzzing $"Generate: {t.Name}"
    let concreteGenerate =
        match t with
        | ValueType ->
            match t with
            | Enum -> generateEnum
            | BuiltinNumeric -> generateBuiltinNumeric
            | Decimal -> generateDecimal
            | Boolean -> generateBool
            | Char -> generateChar
            // A structure does not differ from a class in terms of generation
            | OtherStruct -> generateClass
        | ReferenceType ->
            match t with
            | Array -> generateArray
            | Delegate -> generateDelegate
            | String -> generateString
            | AbstractClass -> generateAbstractClass
            | OtherClass -> generateClass
        | ByRefType -> generateByRef
        | PointerType -> generatePointer

    concreteGenerate commonGenerate rnd t

let generate = commonGenerate

let getInstantiatedMocks () =
    let result = instantiatedMocks
    instantiatedMocks <- System.Collections.Generic.Dictionary<obj, ITypeMock>()
    result

let getReferencedObjects () =
    let result = referencedObjects
    referencedObjects <- System.Collections.Generic.HashSet<obj>()
    result

let getAllocatedObjects () =
    let result = allocatedObjects
    allocatedObjects <- System.Collections.Generic.HashSet<obj>()
    result

// let getAllocatedObjects () =
//     let result = referencedObjects
//     referencedObjects <- System.Collections.Generic.Dictionary<obj, obj>()
//     result
