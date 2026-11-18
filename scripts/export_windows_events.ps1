# Export existing Security records only; this script does not enable auditing.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][DateTimeOffset]$StartTime,
    [Parameter(Mandatory=$true)][DateTimeOffset]$EndTime,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [string]$EvtxPath
)
$ErrorActionPreference = 'Stop'
if ($EndTime -le $StartTime) { throw 'EndTime must be after StartTime. Use explicit UTC offsets.' }
if (Test-Path -LiteralPath $OutputPath) { throw 'Output already exists; choose a new filename.' }
$filter = @{
    Id = @(4624, 4625, 4698)
    StartTime = $StartTime.UtcDateTime
    EndTime = $EndTime.UtcDateTime
}
if ($EvtxPath) { $filter.Path = $EvtxPath } else { $filter.LogName = 'Security' }
try {
    $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
        $events = @()
    } else {
        throw "Cannot read requested logs. Check the path, Security log permissions and time interval. $($_.Exception.Message)"
    }
}
$settings = New-Object System.Xml.XmlWriterSettings
$settings.Encoding = New-Object System.Text.UTF8Encoding($false)
$settings.Indent = $true
$writer = $null
try {
    $writer = [System.Xml.XmlWriter]::Create($OutputPath, $settings)
    $writer.WriteStartDocument()
    $writer.WriteComment('Windows Security export; contains sensitive account and host information')
    $writer.WriteStartElement('Events')
    foreach ($event in ($events | Sort-Object TimeCreated, RecordId)) {
        $writer.WriteRaw($event.ToXml())
    }
    $writer.WriteEndElement()
    $writer.WriteEndDocument()
} finally {
    if ($writer) { $writer.Dispose() }
}
if ($events.Count -eq 0) {
    Write-Warning "No matching events. Wrote an empty Events document to $OutputPath."
} else {
    Write-Output "Exported $($events.Count) events to $OutputPath. Split large intervals to meet app import limits."
}
