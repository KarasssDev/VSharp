module VSharp.Generator.ClassGenerator

open System

open VSharp.Generator.Config
open VSharp.Generator.GeneratorInfo
open VSharp

let private setAllFields (t : Type) (setter: Type -> obj)=
    // Use Reflection.fieldsOf and Reflection
    let fields = t.GetFields()
    // Use Reflection.createObject
    let instance = Activator.CreateInstance(t)
    for field in fields do
        field.SetValue(instance, setter field.FieldType)
    instance

let private recognize (t: Type) = t.IsClass && not t.IsByRef && not t.IsArray && t <> typeof<Array>

let private generate (rnd: Random) (conf: GeneratorConfig) (t: Type) =
    assert (recognize t)
    let constructors = t.GetConstructors()
    if (constructors.Length = 0)
    then
        setAllFields t (commonGenerator rnd conf) |> Some
    else
        let constructor = constructors.[rnd.NextInt64(0,  int64 constructors.Length) |> int32]
        let constructorArgsTypes = constructor.GetParameters() |> Array.map (fun p -> p.ParameterType)
        let constructorArgs = constructorArgsTypes |> Array.map (commonGenerator rnd conf)
        constructor.Invoke(constructorArgs) |> Some

let classGenerator: Generator = mkGenerator recognize generate
