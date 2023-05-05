module VSharp.Generator.DelegateGenerator

open System
open VSharp.Generator.Config

let (|Delegate|_|) (t: Type) = if t.IsSubclassOf (typeof<System.Delegate>) then Some Delegate else None

let generate commonGenerator (rnd: Random) (conf: GeneratorConfig) (t: Type)  =
    VSharp.Prelude.__notImplemented__()
