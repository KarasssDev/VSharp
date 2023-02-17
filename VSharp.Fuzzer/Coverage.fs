namespace VSharp.Interpreter.IL

open System.Reflection
open System.Runtime.InteropServices
open VSharp
open VSharp.Fuzzer

// Lightweight types for representing coverage information
[<Struct>]
[<type: StructLayout(LayoutKind.Sequential, Pack=1, CharSet=CharSet.Ansi)>]
type coverageLocation = {
    moduleToken : int
    methodToken : int
    offset : int
    threadToken : int
}
with
    override x.ToString() =
        sprintf "%x::%d" x.methodToken x.offset

module Coverage =

    let modules = System.Collections.Generic.List<Module>()

    // Represents code path in reverse order: adding new location into such path is constant-time by using List.cons
    type path = coverageLocation list

    let resolveModule moduleToken = modules.[moduleToken]
    let resolveMethod moduleToken methodToken =
        (resolveModule moduleToken).ResolveMethod methodToken

    let moduleToken (m : Module) =
    // TODO: this is slow!
        match Seq.tryFindIndex ((=)m) modules with
        | Some idx -> idx
        | None ->
            modules.Add m
            modules.Count - 1

    let empty = List.empty
    let dump (path : path) =
        path |> List.rev |> List.map toString |> join " => "
