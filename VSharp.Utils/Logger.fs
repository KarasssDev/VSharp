namespace VSharp

open System.Text

module Logger =
    open System

    // Tag for state transitions info logs
    let stateTraceTag = "StateTrace"
    let fuzzerInteractionTraceTag = "FuzzerInteractionTrace"
    let fuzzerTraceTag = "FuzzerTrace"
    let noTag = ""

    let Quiet = 0
    let Critical = 1
    let Error = 2
    let Warning = 3
    let Info = 4
    let Trace = 5

    let mutable currentLogLevel = Error
    let mutable currentTextWriter = Console.Out
    let mutable writeTimestamps = true
    let private suppressedTags = System.Collections.Generic.HashSet<string>([
        stateTraceTag
        fuzzerInteractionTraceTag
        fuzzerTraceTag
    ])

    let tagFilter s = suppressedTags.Contains s |> not

    let public configureWriter writer = currentTextWriter <- writer
    let public enableTimestamps value = writeTimestamps <- value
    let public isTagEnabled tag = tagFilter tag
    let public enableTag tag = suppressedTags.Remove tag |> ignore
    let public suppressTag tag = suppressedTags.Add tag |> ignore

    let LevelToString = function
        | 1 -> "Critical"
        | 2 -> "Error"
        | 3 -> "Warning"
        | 4 -> "Info"
        | 5 -> "Trace"
        | _ -> "Unknown"

    let private writeLineString vLevel tag (message : string) =
        let builder = StringBuilder $"[{LevelToString vLevel}] "
        let builder = if writeTimestamps then builder.Append $"[%A{DateTime.Now}] " else builder
        let builder = if tag <> noTag then builder.Append $"[{tag}] " else builder
        let builder = builder.Append message
        currentTextWriter.WriteLine(builder.ToString())
        currentTextWriter.Flush()

    let public printLogString vLevel (message : string) =
        writeLineString vLevel noTag message

    let public printLogWithTag tag vLevel format =
        Printf.ksprintf (fun message -> if currentLogLevel >= vLevel && tagFilter tag then writeLineString vLevel tag message) format

    let public printLog vLevel format = printLogWithTag noTag vLevel format

    let public printLogLazyWithTag tag vLevel format (s : Lazy<_>) =
        if currentLogLevel >= vLevel && tagFilter tag then
            Printf.ksprintf (writeLineString vLevel tag) format (s.Force())

    let public printLogLazy vLevel format s = printLogLazyWithTag noTag vLevel format s

    let public error format = printLog Error format
    let public warning format = printLog Warning format
    let public info format = printLog Info format
    let public trace format = printLog Trace format

    let public errorWithTag tag format = printLogWithTag tag Error format
    let public warningWithTag tag format = printLogWithTag tag Warning format
    let public infoWithTag tag format = printLogWithTag tag Info format
    let public traceWithTag tag format = printLogWithTag tag Trace format
