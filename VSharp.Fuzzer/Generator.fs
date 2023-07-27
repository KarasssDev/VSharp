module internal VSharp.Fuzzer.Generator

open System
open System.Reflection
open Microsoft.FSharp.NativeInterop
open VSharp
open VSharp.Core
open VSharp.Fuzzer.TypeSolver

type Generator(typeSolver: TypeSolver) =
    let instancesCache = System.Collections.Generic.Dictionary<Type, Type option>()
    let mutable allocatedObjects = System.Collections.Generic.HashSet<obj>()
    let mutable instantiatedMocks = System.Collections.Generic.Dictionary<obj, ITypeMock>()
    let mutable referencedObjects = System.Collections.Generic.HashSet<obj>()

    let setAllFields (t : Type) (setter: Type -> obj) =
        let isStatic = t.IsAbstract && t.IsSealed
        let fields = Reflection.fieldsOf isStatic t
        let instance = System.Runtime.Serialization.FormatterServices.GetUninitializedObject t
        for _, fieldInfo in fields do
            fieldInfo.SetValue(instance, setter fieldInfo.FieldType)
        instance

    let generateViaConstructor commonGenerator (t: Type) (rnd: Random) =
        let constructors = t.GetConstructors()
        if (constructors.Length = 0)
        then
            None
        else
            let constructor = constructors[rnd.NextInt64(0,  int64 constructors.Length) |> int32]
            let constructorArgsTypes = constructor.GetParameters() |> Array.map (fun p -> p.ParameterType)
            let constructorArgs = constructorArgsTypes |> Array.map (commonGenerator rnd)
            constructor.Invoke(constructorArgs) |> Some

    let getInstance (t: Type) (rnd: Random) commonGenerator =
        match instancesCache.TryGetValue t with
        | true, instance -> instance
        | false, _ ->
            let instances =
                t.Assembly.GetTypes()
                |> Array.filter (fun x -> x.IsClass && not x.IsAbstract && x.IsPublic && t.IsAssignableFrom(x))
            if instances.Length = 0 then instancesCache.Add(t, None)
            else instancesCache.Add(t, Some instances[rnd.NextInt64(0, instances.Length) |> int])
            instancesCache[t]

    let generateUnboxedChar (rnd: Random) =
        // Supports only ASCII for compatibility with test XML serializer
        rnd.Next(33, 126) |> char

    let builtinNumericTypes = [
        typeof<int8>; typeof<int16>; typeof<int32>; typeof<int64>
        typeof<uint8>; typeof<uint16>; typeof<uint32>; typeof<uint64>
        typeof<float>; typeof<double>
        typeof<byte>
    ]

    let generateUnboxedBool (rnd: Random) =
        rnd.Next(0, 2) = 1

    // Generators
    let generateBuiltinNumeric _ (rnd: Random) (t: Type)  =
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

    let generateBool _ (rnd: Random) t =
        (generateUnboxedBool rnd) :> obj

    let generateDecimal _ (rnd: Random) t =
        let scale = rnd.Next(29) |> byte
        let sign = generateUnboxedBool rnd
        Decimal (rnd.Next(), rnd.Next(), rnd.Next(), sign, scale) :> obj

    let generateChar _ (rnd: Random) t =
        (generateUnboxedChar rnd) :> obj

    let generateString _ (rnd: Random) t =
        let size = rnd.Next (0, Options.options.StringMaxSize)
        String(Array.init size (fun _ -> generateUnboxedChar rnd)) :> obj

    let generateEnum _ (rnd: Random) (t: Type) =
        let values = Enum.GetValues(t)
        let index = rnd.NextInt64(0, int64 values.Length) |> int
        values.GetValue(index)

    let generateArray commonGenerator (rnd: Random) (t: Type) =
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

    let generateAbstractClass commonGenerator (rnd: Random) (t: Type) =
        match getInstance t rnd commonGenerator with
        | Some instance -> commonGenerator rnd instance
        | None ->
            let mock, typ = typeSolver.MockType t (commonGenerator rnd)
            let result = commonGenerator rnd typ
            instantiatedMocks.Add(result, mock)
            result

    let generateByRef commonGenerator (rnd: Random) (t: Type) =
        let referencedType = t.GetElementType()
        let object = commonGenerator rnd referencedType
        Logger.errorFuzzing $"Added to referenced objects: {object}"
        referencedObjects.Add(object) |> ignore
        object

    let generatePointer (commonGenerator: Random -> Type -> obj) (rnd: Random) (t: Type) =
        let elementType = t.GetElementType()
        let object = commonGenerator rnd elementType
        let reference = ref object
        let pointer = System.Runtime.CompilerServices.Unsafe.AsPointer(reference)
        let result = Pointer.Box(pointer, t)
        allocatedObjects.Add result |> ignore
        result

    let generateDelegate commonGenerator (rnd: Random) (t: Type) =
        Prelude.__notImplemented__ ()

    let generateClass commonGenerator (rnd: Random) (t: Type) =
        match generateViaConstructor commonGenerator t rnd with
        | Some obj -> obj
        | None -> setAllFields t (commonGenerator rnd)

    // Classification
    let (|ValueType|PointerType|ReferenceType|ByRefType|) (t: Type) =
        if t.IsValueType then ValueType
        elif t.IsPointer then PointerType
        elif t.IsByRef then ByRefType
        else ReferenceType

    // Value types
    let (|Enum|BuiltinNumeric|Decimal|Boolean|Char|OtherStruct|) (t: Type) =
        if t.IsEnum then Enum
        elif List.contains t builtinNumericTypes then BuiltinNumeric
        elif t = typeof<Decimal> then Decimal
        elif t = typeof<bool> then Boolean
        elif t = typeof<char> then Char
        else OtherStruct

    // Reference types
    let (|Array|Delegate|String|AbstractClass|OtherClass|) (t: Type) =
        if t.IsArray then Array
        elif t = typeof<string> then String
        elif t.IsSubclassOf typeof<System.Delegate> then Delegate
        elif t.IsAbstract || t.IsInterface then AbstractClass
        else OtherClass

    let rec commonGenerate (rnd: Random) (t: Type) =
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
            | ByRefType -> __notImplemented__ ()
            | PointerType -> __notImplemented__ ()

        concreteGenerate commonGenerate rnd t

    member this.Generate rnd t =
        match t with
        | ByRefType -> generateByRef commonGenerate rnd t
        | PointerType -> generatePointer commonGenerate rnd t
        | _ -> commonGenerate rnd t

    member this.RefreshInstantiatedMocks () =
        let result = instantiatedMocks
        instantiatedMocks <- System.Collections.Generic.Dictionary<obj, ITypeMock>()
        result

    member this.RefreshReferencedObjects () =
        let result = referencedObjects
        referencedObjects <- System.Collections.Generic.HashSet<obj>()
        result

    member this.RefreshAllocatedObjects () =
        let result = allocatedObjects
        allocatedObjects <- System.Collections.Generic.HashSet<obj>()
        result
