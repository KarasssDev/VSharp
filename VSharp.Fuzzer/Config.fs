module VSharp.Fuzzer.Config

open System.Reflection
open VSharp.Core

type GeneratorConfig = {
    ArrayMaxSize: int
    StringMaxSize: int
}

let defaultGeneratorConfig = {
    ArrayMaxSize = 10
    StringMaxSize = 10
}

let generateConfigForArg (_: state) (arg: ParameterInfo): GeneratorConfig =
    defaultGeneratorConfig

let generateConfigForType (_: state) (t: System.Type): GeneratorConfig =
    defaultGeneratorConfig


type FuzzerConfig = {
    MaxTest: int
    Timeout: int
    MaxClauses: int
}

let defaultFuzzerConfig = {
    MaxTest = 10
    Timeout = 1000
    MaxClauses = 10
}
