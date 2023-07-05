namespace VSharp.Fuzzer

open System.Runtime.InteropServices

module private Fork =
    [<DllImport("libc")>]
    extern int private fork()

    exception FailedFork

    let forkProcess parentWork childWork =
        match fork() with
        | -1 -> raise FailedFork
        | 0 -> childWork ()
        | _ -> parentWork ()

