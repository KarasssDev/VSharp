module VSharp.Fuzzer.Docker

open System.Diagnostics
open System.IO
open System.Runtime.InteropServices
open System.Text
open VSharp


type private MountMode =
    | Readonly
    | ReadWrite

type private DockerRunOptions =
    | Mount of string * string * MountMode
    | EnvVar of string * string
    | User of uint * uint
    | Port of int * int
    | RemoveAfterStop
    | Name of string

type private DockerCommand =
    | Run of DockerRunOptions seq * string
    | Stop of string

let private buildRunOptions (options: DockerRunOptions seq) =
    let args = StringBuilder()
    for option in options do
        match option with
        | Mount (source, target, mountMode) ->
            match mountMode with
            | Readonly -> args.Append $" --mount type=bind,source={source},target={target}" |> ignore
            | ReadWrite -> args.Append $" --mount type=bind,source={source},target={target}" |> ignore
        | EnvVar (name, value) -> args.Append $""" -e {name}="{value}" """ |> ignore
        | User (uid, gid) -> args.Append $" --user {uid}:{gid}" |> ignore
        | Port(source, target) -> args.Append $" --publish {source}:{target}" |> ignore
        | RemoveAfterStop -> args.Append " --rm" |> ignore
        | Name containerName -> args.Append $" --name {containerName}" |> ignore

    args.ToString ()

let private runDockerProcess args  =
    Logger.error $"Args: {args}"
    let info = ProcessStartInfo()
    info.WorkingDirectory <- Directory.GetCurrentDirectory()
    info.FileName <- "docker"
    info.Arguments <- args
    info.UseShellExecute <- false
    info.RedirectStandardOutput <- true
    info.RedirectStandardError <- true
    Process.Start info

let private executeDockerCommand command =
    let args = 
        match command with
        | Run (runOptions, imageName) -> $"run {buildRunOptions runOptions} {imageName}"
        | Stop containerName -> $"stop {containerName}"
    runDockerProcess args

let private fuzzerImageName = "karasss/fuzzer:latest"
let private fuzzerContainerName = "vsharp-fuzzer"
let fuzzerContainerPort = 29172
let isSupportedArchForFuzzer () =
    let arch = Architecture ()
    match arch with
    | Architecture.X64
    | Architecture.X86 
    | Architecture.Arm 
    | Architecture.Arm64 -> true
    | Architecture.Wasm
    | Architecture.S390x -> false
    | _ -> __unreachable__ ()

let startFuzzer outputPath =

    let options =

        let baseOptions = [
            Mount(outputPath, outputPath, ReadWrite)

            EnvVar("CORECLR_PROFILER", "{2800fea6-9667-4b42-a2b6-45dc98e77e9e}")
            EnvVar("CORECLR_ENABLE_PROFILING", "1")
            EnvVar("CORECLR_PROFILER_PATH", "/app/libvsharpConcolic.so")

            Port(fuzzerContainerPort, fuzzerContainerPort)
            RemoveAfterStop
            Name fuzzerContainerName
        ]

        let linuxOptions = [
            Mount("/etc/passwd", "/etc/passwd", Readonly) 
            Mount("/etc/group", "/etc/group", Readonly)
            Interop.LinuxCalls.getCurrentUserInfo () |> User
        ]

        if (RuntimeInformation.IsOSPlatform OSPlatform.Linux) then List.concat [baseOptions; linuxOptions]
        else baseOptions

    Run (options, fuzzerImageName) |> executeDockerCommand

let stopFuzzer () = Stop fuzzerContainerName |> executeDockerCommand
