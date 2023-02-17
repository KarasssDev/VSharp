module VSharp.Fuzzer.FuzzerInfo

type FuzzerConfig = {
    MaxTest: int
    Timeout: int
}

let defaultFuzzerConfig = {
    MaxTest = 10
    Timeout = 5000
}
