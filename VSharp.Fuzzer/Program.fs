open System
open System.Diagnostics
open System.Runtime.InteropServices
open VSharp
open VSharp.Fuzzer



let internal getOutputDir (argv: string array) =
    if (argv.Length < 1) then
        internalfail "Missing output directory path"
    argv[0]

[<EntryPoint>]
let main argv =
    #if DEBUG
    //while not Debugger.IsAttached do ()
    #endif

    getOutputDir argv |> Interaction.startFuzzer
