<#
.SYNOPSIS
 
.NOTES
    Author: MDE OPS Team
    Date/Version: See $ScriptVer
#>
param (
	[string]$outputDir = $PSScriptRoot, 
	## To collect netsh traces -n 
	[Alias("n")][switch]$netTrace,
	[Alias("w", "wfp")][switch]$wfpTrace,
	##To collect Sense performance traces '-l' or '-h'
	[Alias("l")][switch]$wprpTraceL,
	[Alias("h")][switch]$wprpTraceH,
	##To collect Sense app compatibility traces '-c'
	[Alias("c")][switch]$AppCompatC,
	##To collect Sense dumps '-d'
	[Alias("d")][switch]$CrashDumpD,
	##To collect traces for isolation issues '-i'
	[Alias("i")][switch]$NetTraceI,
	##To collect boot traces issues at startup '-b'
	[Alias("b")][switch]$BootTraceB,
	##To collect traces for WD AntiVirus pref issues '-a'
	[Alias("a")][switch]$WDPerfTraceA,
	##To collect ETW traces for WD AntiVirus client (no performance) '-e' (subset of perf '-a')
	[Alias("e")][switch]$WDLiteTraceE,
	##To collect verbose traces for WD AntiVirus issues '-v'
	[Alias("v")][switch]$WDVerboseTraceV,
	##To collect verbose traces for DLP issues '-t'
	[Alias("t")][switch]$DlpT,
	##To collect quick DLP Diagnose run '-q'
	[Alias("q")][switch]$DlpQ,
	##To prepare the device for full dump collection '-z'
	[Alias("z")][switch]$FullCrashDumpZ,
	##To set the device for remote data collection '-r'
	[Alias("r")][switch]$RemoteRun,
	##To set the minutes to run for data collection '-m'
	[Alias("m")][int]$MinutesToRun = "5",
	##To crash the device and create a memory dump immediately '-k'
	[Alias("K")][switch]$NotMyFault,
	##To pass an onboarding script for use with connectivity checks
	[Alias("O")][string]$OnboardingScriptPath,
	##To pass a specific region use with connectivity checks
	[Alias("G", "Geo")][string]$GeoRegion,
	##To collect diagnostic data for CFA issues
	[Alias("CFA")][switch]$DoCfaDiagnostics
)

# Global variables
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8  # MDEClientAnalyzer.exe outputs UTF-8, so interpret its output as such
$ProcessWaitMin = 5	# wait max minutes to complete
$ToolsDir = Join-Path $outputDir "Tools"
$buildNumber = ([System.Environment]::OSVersion).Version.build
#Enforcing default PSModulePath to avoid getting unexpected modules to run instead of built-in modules
$env:PSModulePath = "C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules"

# Define outputs
$resultOutputDir = Join-Path $outputDir "MDEClientAnalyzerResult"
$SysLogs = Join-Path $resultOutputDir "SystemInfoLogs"
$psrFile = Join-Path $resultOutputDir "Psr.zip" 
$ProcMonlog = Join-Path $resultOutputDir "Procmonlog.pml"
$connectivityCheckFile = Join-Path $SysLogs "MDEClientAnalyzer.txt"
$connectivityCheckUserFile = Join-Path $SysLogs "MDEClientAnalyzer_User.txt"
$outputZipFile = Join-Path $outputDir "MDEClientAnalyzerResult.zip"
$WprpTraceFile = Join-Path  $resultOutputDir "FullSenseClient.etl"
$XmlLogFile = Join-Path $SysLogs "MDEClientAnalyzer.xml"
$XslFile = Join-Path $ToolsDir "MDEReport.xslt"
$RegionsJson = Join-Path $ToolsDir "RegionsURLs.json"
$EndpointList = Join-Path $ToolsDir "endpoints.txt"
$ResourcesJson = Join-Path $ToolsDir "Events.json"
$HtmOutputFile = Join-Path $resultOutputDir "MDEClientAnalyzer.htm"
$CertSignerResults = "$resultOutputDir\SystemInfoLogs\CertSigner.log"
$CertResults = "$resultOutputDir\SystemInfoLogs\CertValidate.log"
$netshlog = "$resultOutputDir\NetTraces\netsh.log"

$OSPreviousVersion = $false
$AVPassiveMode = $false
$ScriptVer = "08May2024"
$AllRegionsURLs = @{}

# function to read Registry Value
function Get-RegistryValue {
	param (
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$Path,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$Value
	)

	if (Test-Path -path $Path) {
		return Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction "SilentlyContinue"
	}
 else {
		return $false
	}
}

function Get-CertificateURL {
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )
$signature = @"
[DllImport("cryptnet.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern bool CryptGetObjectUrl(
    int pszUrlOid,
    IntPtr pvPara,
    int dwFlags,
    byte[] pUrlArray,
    ref int pcbUrlArray,
    IntPtr pUrlInfo,
    ref int pcbUrlInfo,
    int pvReserved
);
"@
    Add-Type -MemberDefinition $signature -Namespace PKI -Name Cryptnet
    function ConvertTo-DERString ([byte[]]$bytes) {
        $SB = New-Object System.Text.StringBuilder
        $bytes1 = $bytes | ForEach-Object{"{0:X2}" -f $_}
        for ($n = 0; $n -lt $bytes1.count; $n = $n + 2) {
            [void]$SB.Append([char](Invoke-Expression 0x$(($bytes1[$n+1]) + ($bytes1[$n]))))
        }
        $SB.ToString()
    }
    # create synthetic object to store resulting URLs
    $URLs = New-Object psobject -Property @{
        CDP = $null;
        AIA = $null;
        OCSP = $null;
    }
    $pvPara = $Cert.Handle
    # process only if Handle is not zero.
    if (!$Cert.Handle.Equals([IntPtr]::Zero)) {
        # loop over each URL type: AIA, CDP and OCSP
        foreach ($id in 1,2,13) {
            # initialize reference variables
            $pcbUrlArray = 0
            $pcbUrlInfo = 0
            # call CryptGetObjectUrl to get required buffer size. The function returns True if succeeds and False otherwise
            if ([PKI.Cryptnet]::CryptGetObjectUrl($id,$pvPara,2,$null,[ref]$pcbUrlArray,[IntPtr]::Zero,[ref]$pcbUrlInfo,$null)) {
                # create buffers to receive the data
                $pUrlArray = New-Object byte[] -ArgumentList $pcbUrlArray
                $pUrlInfo = [Runtime.InteropServices.Marshal]::AllocHGlobal($pcbUrlInfo)
                # call CryptGetObjectUrl to receive decoded URLs to the buffer.
                [void][PKI.Cryptnet]::CryptGetObjectUrl($id,$pvPara,2,$pUrlArray,[ref]$pcbUrlArray,$pUrlInfo,[ref]$pcbUrlInfo,$null)
                # convert byte array to a single string
                $URL = ConvertTo-DERString $pUrlArray
                # parse unicode string to remove extra insertions
                switch ($id) {
                    1 {
                        $URL = $URL.Split("`0",[StringSplitOptions]::RemoveEmptyEntries)
                        $URLs.AIA = $URL[4..($URL.Length - 1)]
                    }
                    2 {
                        $URL = $URL.Split("`0",[StringSplitOptions]::RemoveEmptyEntries)
                        $URLs.CDP = $URL[4..($URL.Length - 1)]
                    }
                    13 {
                        $URL = $URL -split "ocsp:"
                        $URLs.OCSP = $URL[1..($URL.Length - 1)] | ForEach-Object{$_ -replace [char]0}
                    }
                }
                # free unmanaged buffer
                [void][Runtime.InteropServices.Marshal]::FreeHGlobal($pUrlInfo)
            } else {Write-output "No Urls found"}
        }
        $URLs
    }
}

function Get-EndpointCertificate {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$true)] [System.Uri]
      $Uri,
    [Parameter()] [Switch]
      $UseProxy,   
    [Parameter(Mandatory=$false)]
      $ProxyAddress,
    [Parameter()] [Switch]
      $TrustAllCertificates
  )
  if ($request) {
      $request.Abort()
  }
  $request = [System.Net.WebRequest]::Create($Uri)
  if ($UseProxy) {
    if ($ProxyAddress) {
		$ProxyAddress = [system.net.webrequest]::DefaultWebProxy = new-object system.net.webproxy($ProxyAddress)
    } else {
		$ProxyAddress = [System.Net.WebRequest]::DefaultWebProxy	
	}
    $request.Proxy = $ProxyAddress
  }
  if ($uri -like "http:*") {
    $wc = New-Object System.Net.WebClient
    $wc.Proxy = $proxyAddress
    $wc.DownloadFile($Uri, "$outputdir\cert.crt")
    $crt = Get-ChildItem -Path "$outputdir\cert.crt" -ErrorAction SilentlyContinue
    if ($crt) {
        $CACert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($crt.FullName)
		Remove-Item -Path $crt
		return $CACert
    }
  }  
  if ($TrustAllCertificates) {
    # Create a compilation environment
    if ($provider) {
      $Provider.Dispose()
    }
    $Provider=New-Object Microsoft.CSharp.CSharpCodeProvider
    $Provider.CreateCompiler() | Out-Null
    $params=$null
    $Params=New-Object System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable=$False
    $Params.GenerateInMemory=$True
    $Params.IncludeDebugInformation=$False
    $Params.ReferencedAssemblies.Add("System.DLL") > $null
    $TASource=@'
      namespace Local.ToolkitExtensions.Net.CertificatePolicy {
        public class TrustAll : System.Net.ICertificatePolicy {
          public TrustAll() {
          }
          public bool CheckValidationResult(System.Net.ServicePoint sp,
            System.Security.Cryptography.X509Certificates.X509Certificate cert,
            System.Net.WebRequest req, int problem) {
            return true;
          }
        }
      }
'@
    $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
    $TAAssembly=$TAResults.CompiledAssembly
    $TrustAll=$TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
	[System.Net.ServicePointManager]::CertificatePolicy=$TrustAll
  }
  $request.GetResponse() | Out-Null
  $certhandle = [Security.Cryptography.X509Certificates.X509Certificate2]$request.ServicePoint.Certificate.Handle
  if ($certhandle.Length -gt 1) {
	$cert = $certhandle[-1]
  } else {
	  $cert = $certhandle
  }
  return $cert
}
<#
  .SYNOPSIS
    Retrieves the certificate used by a website.
  .PARAMETER  Uri
    The URL of the website. This should start with https.
  .PARAMETER  UseProxy
    Whether or not to use the proxy settings applied to MsSense.
  .PARAMETER  ProxyAddress
    Proxy address to use.
  .PARAMETER  TrustAllCertificates
    Ignore certificate errors for certificates that are expired, have a mismatched common name or are self signed.
  .INPUTS
    Does not accept pipeline input.
  .OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate
#>

# This telnet test does not support proxy as-is
Function TelnetTest($RemoteHost, $port) { 
	[int32]$TimeOutSeconds = 10000
	Try {
		$tcp = New-Object System.Net.Sockets.TcpClient
		$connection = $tcp.BeginConnect($RemoteHost, $Port, $null, $null)
		$connection.AsyncWaitHandle.WaitOne($TimeOutSeconds, $false)  | Out-Null 
		if ($tcp.Connected -eq $true) {
			$ConnectionResult = "Successfully connected to Host: $RemoteHost on Port: $Port"
		}
		else {
			$ConnectionResult = "Could not connect to Host: $RemoteHost on Port: $Port"
		}
	} 
	Catch {
		$ConnectionResult = "Unknown Error"
	}
	return $ConnectionResult
}


function Write-ReportEvent($severity, $id, $category, $check, $checkresult, $guidance) { 
	$checkresult_txtfile = [regex]::replace($checkresult, '<br>', '')
	$guidance_txtfile = [regex]::replace($guidance, '<br>', '')
	# Write Message to the screen
	$descLine = ((Get-Date).ToString("u") + " [$severity]" + " $check" + " $id" + ": " + $checkresult_txtfile + " " + $guidance_txtfile )
	if ($severity -eq "Error") {
		Write-Host -BackgroundColor Red -ForegroundColor Yellow $descLine
	}
 elseif ($severity -eq "Warning") {
		Write-Host -ForegroundColor Yellow $descLine
	}
 else {
		Write-Host $descLine
	}
	# Write message to the ConnectivityCheckFile
	$descLine | Out-File $connectivityCheckFile -append

	# Write Message to XML
	$subsectionNode = $script:xmlDoc.CreateNode("element", "event", "")
	$subsectionNode.SetAttribute("id", $id)

	$eventContext1 = $script:xmlDoc.CreateNode("element", "severity", "")
	$eventContext1.psbase.InnerText = $severity

	$eventContext2 = $script:xmlDoc.CreateNode("element", "category", "")
	$eventContext2.psbase.InnerText = $category

	$eventContext3 = $script:xmlDoc.CreateNode("element", "check", "")
	$eventContext3.psbase.InnerText = $check

	$eventContext4 = $script:xmlDoc.CreateNode("element", "checkresult", "")
	$eventContext4.psbase.InnerText = $checkresult

	$eventContext5 = $script:xmlDoc.CreateNode("element", "guidance", "")
	$eventContext5.psbase.InnerText = $guidance

	$subsectionNode.AppendChild($eventContext1) | out-Null
	$subsectionNode.AppendChild($eventContext2) | out-Null
	$subsectionNode.AppendChild($eventContext3) | out-Null
	$subsectionNode.AppendChild($eventContext4) | out-Null
	$subsectionNode.AppendChild($eventContext5) | out-Null
    
	$xmlRoot = $script:xmlDoc.SelectNodes("/MDEResults")
	$InputNode = $xmlRoot.SelectSingleNode("events")
	$InputNode.AppendChild($subsectionNode) | Out-Null
}


function Write-Report($section, $subsection, $displayName, $value, $alert) { 
	$subsectionNode = $script:xmlDoc.CreateNode("element", $subsection, "")    
	$subsectionNode.SetAttribute("displayName", $displayName)

	$eventContext1 = $script:xmlDoc.CreateNode("element", "value", "")
	$eventContext1.psbase.InnerText = $value
	$subsectionNode.AppendChild($eventContext1) | out-Null

	if ($value -eq "Running") {
		$alert = "None"
	} elseif (($value -eq "Stopped" -or $value -eq "StartPending")) {
		$alert = "High"
	}

	if ($alert) {
		$eventContext2 = $script:xmlDoc.CreateNode("element", "alert", "")
		$eventContext2.psbase.InnerText = $alert
		$subsectionNode.AppendChild($eventContext2) | out-Null
	}

	$checkresult = $DisplayName + ": " + $value
	# Write message to the ConnectivityCheckFile
	$checkresult | Out-File $connectivityCheckFile -append

	$xmlRoot = $script:xmlDoc.SelectNodes("/MDEResults")
	$InputNode = $xmlRoot.SelectSingleNode($section)
	$InputNode.AppendChild($subsectionNode) | Out-Null
}


# Initialize XML log - for consumption by external parser
function InitXmlLog {
	$script:xmlDoc = New-Object System.Xml.XmlDocument								 
	$script:xmlDoc = [xml]"<?xml version=""1.0"" encoding=""utf-8""?><MDEResults><general></general><devInfo></devInfo><EDRCompInfo></EDRCompInfo><MDEDevConfig></MDEDevConfig><AVCompInfo></AVCompInfo><events></events></MDEResults>"
}

function Format-XML ([xml]$xml) {
	$StringWriter = New-Object System.IO.StringWriter
	$XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
	$xmlWriter.Formatting = [System.Xml.Formatting]::Indented
	$xml.WriteContentTo($XmlWriter)
	Write-Output $StringWriter.ToString()
}

function ShowDlpPolicy($policyName) {
	$byteArray = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection' -Name $policyName
	$memoryStream = New-Object System.IO.MemoryStream(, $byteArray)
	$deflateStream = New-Object System.IO.Compression.DeflateStream($memoryStream, [System.IO.Compression.CompressionMode]::Decompress)
	$streamReader = New-Object System.IO.StreamReader($deflateStream, [System.Text.Encoding]::Unicode)
	$policyStr = $streamReader.ReadToEnd()
	$policy = $policyStr | ConvertFrom-Json
	$policyBodyCmd = ($policy.body | ConvertFrom-Json).cmd
	$policyBodyCmd | Format-List -Property hash, type, cmdtype, id, priority, timestamp, enforce | Out-File "$resultOutputDir\DLP\$policyName.txt"

	$timestamp = [datetime]$policyBodyCmd.timestamp
	"Timestamp: $($timestamp.ToString('u'))" | Out-File "$resultOutputDir\DLP\$policyName.txt" -Append

	# convert from/to json so it's JSON-formatted
	if ($policyBodyCmd.data) {
		$params = $policyBodyCmd.data | ConvertFrom-Json
	} elseif ($policyBodyCmd.paramsstr) {
		$params = $policyBodyCmd.paramsstr | ConvertFrom-Json
	}
	$params | ConvertTo-Json -Depth 20 > "$resultOutputDir\DLP\$policyName.json"

	if ($params.SensitiveInfoPolicy) {
		foreach ($SensitiveInfoPolicy in $params.SensitiveInfoPolicy) {
			$configStr = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($SensitiveInfoPolicy.Config))
			$config = [xml]$configStr
			Format-XML $config | Out-File "$resultOutputDir\DLP\rule_$($SensitiveInfoPolicy.RulePackageId).xml"
		}
	}
}

function PromptForDLPFile() {
	while ($true) {
		Write-Host -ForegroundColor Green "Please enter the full path to the document that was used during log collection. For example C:\Users\John Doe\Desktop\report.docx"
		[string]$DLPFilePath = (Read-Host)
		if ($DLPFilePath.Length -gt 0) {
			# Handle error cases
			try {
				if ((Test-Path -path ($DLPFilePath -Replace '"', "") -PathType leaf)) {
					return $DLPFilePath
				}
			}
			catch {
				Write-Host "Path is not pointing to a valid file. Exception: $_"
				return $DLPFilePath = $false
			}
		}
		else {
			Write-Host "Empty path was provided"
			return $DLPFilePath = $false
		}

	}
}

function Get-DLPEA {
	if ($DlpT) {
		New-Item -ItemType Directory -Path "$resultOutputDir\DLP" -ErrorAction SilentlyContinue | out-Null
		$DisplayEA = Join-Path $ToolsDir "DisplayExtendedAttribute.exe"
		Test-AuthenticodeSignature $DisplayEA
		$DLPFilePath = $false
		if (!($system -or $RemoteRun)) {
			do {
				$DLPFilePath = PromptForDLPFile
			} while ($DLPFilePath -eq $false)
			Write-Host "Checking Extended Attributes for $DLPFilePath..."
			"Extended attributes for: $DLPFilePath`n" | out-File -Encoding UTF8 "$resultOutputDir\DLP\FileEAs.txt"
			Test-AuthenticodeSignature $DisplayEA
			&$DisplayEA "$DLPFilePath" | out-File -encoding UTF8 -Append "$resultOutputDir\DLP\FileEAs.txt"
			if ($InteractiveAdmin) {
				# The output of this command will only be helpful if the user running the script is also the logged on user:
				$GetUserCmd = Join-Path $ToolsDir "GetAadUser.exe"
				Test-AuthenticodeSignature $GetUserCmd
				&$GetUserCmd | out-File -encoding UTF8 -Append "$resultOutputDir\DLP\AadUserInfo.txt"
			}
		}
	}
}

function Test-WPRError($ExitCode) {
	if (($ExitCode -eq "0") -or ($ExitCode -eq "-984076288")) {
		# -984076288 = There are no trace profiles running.
		return
	} elseif ($ExitCode -eq "-2147023446") {
		# 2147023446 = Insufficient system resources exist to complete the requested service.
		Test-CommandVerified "logman.exe"
		[int]$ETSCount = (&logman.exe query -ets).count | Out-File $connectivityCheckFile -Append
		[string]$ETSSessions = (&logman.exe query -ets) | Out-File $connectivityCheckFile -Append
		Write-error "Starting WPR trace has failed because too many trace sessions are already running on this system." | Out-File $connectivityCheckFile -Append
		Write-Warning "If this is the first time you are seeing this error, try restarting the machine and collecting traces from scratch."
		$ETSCount | Out-File $connectivityCheckFile -Append
		$ETSSessions | Out-File $connectivityCheckFile -Append
		Write-Host "Proceeding anyway without the collection of advanced traces..."
	} else {
		"Error $ExitCode occured when starting WPR trace." | Out-File $connectivityCheckFile -Append
	}
}

function Initialize-BootTrace {
	$ProcmonCommand = Join-Path $ToolsDir "Procmon.exe"
	Write-Host "Checking if WPR Boot trace is already running"
	$WptState = Test-WptState
	if ((!$OSPreviousVersion) -and ($WptState -eq "Ready")) {
		Test-CommandVerified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-boottrace -stopboot `"$WprpTraceFile`""
		Test-WPRError $StartWPRCommand.ExitCode
	}
	Write-Host "Saving any running ProcMon Boot trace"
	Test-AuthenticodeSignature $ProcmonCommand
	Start-Process -PassThru -wait $ProcmonCommand -ArgumentList "-AcceptEula -ConvertBootLog `"$ProcMonlog`"" | Out-Null
	$procmonlogs = Get-Item "$resultOutputDir\*.pml"
	if ($procmonlogs -eq $null) {
		Test-AuthenticodeSignature $ProcmonCommand
		& $ProcmonCommand -AcceptEula -EnableBootLogging -NoFilter -quiet -minimized
		if ((!$OSPreviousVersion) -and ($WptState -eq "Ready")) {
			Test-CommandVerified "wpr.exe"
			$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-boottrace -addboot `"$ToolsDir\Sense.wprp`" -filemode"
			Test-WPRError $StartWPRCommand.ExitCode
		}
		Write-Host "Boot logging ready"
		Write-Host -BackgroundColor Red -ForegroundColor Yellow "Please run the tool again with '-b' parameter when the device is back online" 
		if ($RemoteRun) {
			Write-Warning "Restarting remote device..."
		}
		else {
			Read-Host "Press ENTER when you are ready to restart..."
		}
		Restart-Computer -ComputerName . -Force
	}
	else {
		Write-Host "Boot logs were collected successfully"
	}
}

function Initialize-FullCrashDump {
	Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -name CrashDumpEnabled -Type DWord -Value "1"
	Write-Host "Registry settings for full dump collection have been configured"
}

function Initialize-CrashOnCtrlScroll {
	Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters' -name CrashOnCtrlScroll -Type DWord -Value "1"
	Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters' -name CrashOnCtrlScroll -Type DWord -Value "1"
	Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\hyperkbd\Parameters' -name CrashOnCtrlScroll -Type DWord -Value "1" -ErrorAction SilentlyContinue
	Write-Host "Registry settings for CrashOnCtrlScroll have been configured as per https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/forcing-a-system-crash-from-the-keyboard"
}

function Initialize-PSRRecording {
	if ($system -or $RemoteRun) {
		"`r`nSkipping PSR recording as it requires an interactive user session." | Out-File $connectivityCheckFile -Append
	} 
	else {
		Write-Host -ForegroundColor Yellow "Do you want to allow MDEClientAnalyzer to collect screen-captures while traces are running?"
		Write-Host -ForegroundColor Yellow "If yes, make sure you close any windows not related to the issue you are recording such as Outlook or Teams"
        [string]$ScreenCaptureEnabled = (Read-Host "Type 'Y' and press ENTER to allow Problem Steps Recorder to capture screenshots. Use any other key or ENTER to disable PSR.")
		if ($ScreenCaptureEnabled.Tolower() -eq "y") {
			Write-host -ForegroundColor Green "`r`nCapturing screenshots enabled with user approval"
			"`r`nCapturing screenshots enabled with user approval"  | Out-File $connectivityCheckFile -Append
			Test-CommandVerified "psr.exe"
			& psr.exe -stop
			Start-Sleep -Seconds 2
			Test-CommandVerified "psr.exe"
			& psr.exe -start -output "$psrFile" -gui 0 -maxsc 99 -sc 1
		} else {
			Write-Host -BackgroundColor Red -ForegroundColor Yellow "Capturing screenshots disabled by user request" 
			"`r`nCapturing screenshots disabled by user request"  | Out-File $connectivityCheckFile -Append
		}
	}
}

function Save-PSRRecording {
	if ($RemoteRun) {
		"`r`nSkipping PSR recording as it requires an interactive user session." | Out-File $connectivityCheckFile -Append
	} 
	else {
		Test-CommandVerified "psr.exe"
		& psr.exe -stop
	}
}

function Initialize-MDAVTrace {
	if ((!$OSPreviousVersion) -or ($MDfWS)) {
		if (($NetTraceI) -and (!$DlpT) -and (!$WDVerboseTraceV)) {
			Test-AuthenticodeSignature $MpCmdRunCommand
			Start-Process -WindowStyle minimized $MpCmdRunCommand -WorkingDirectory $CurrentMpCmdPath.ToString() -ArgumentList "-trace -grouping 0x1B -level 0x3F"
		}
		elseif ($DlpT) {
			Test-AuthenticodeSignature $MpCmdRunCommand
			Start-Process -WindowStyle minimized $MpCmdRunCommand -WorkingDirectory $CurrentMpCmdPath.ToString() -ArgumentList "-trace -grouping 0x30B -level 0x3F"
		}
		elseif ($WDVerboseTraceV) {
			Test-AuthenticodeSignature $MpCmdRunCommand
			Start-Process -WindowStyle minimized $MpCmdRunCommand -WorkingDirectory $CurrentMpCmdPath.ToString() -ArgumentList "-trace -grouping 0x1FF -level ff"
			&$MpCmdRunCommand -CaptureNetworkTrace -path C:\Users\Public\Downloads\Capture.npcap | Out-File $connectivityCheckFile -Append
			Initialize-WinEventDebug Microsoft-Windows-SmartScreen/Debug
		}
		if ($WDPerfTraceA -or $WDLiteTraceE) {
			$WPRP = Join-Path $ToolsDir "WD_Lite.WPRP"
			$WPRPSuffix = ""
			if ($WDPerfTraceA) { # Lite is a subset of perf, if perf is specified ignore lite
				$WPRP = Join-Path $ToolsDir "WD.WPRP"
				$WPRPSuffix = "!WD.Verbose"
				Write-Host "Starting WD perf trace"
			} else {
				Write-Host "Starting WD Lite trace"
			}

			Test-CommandVerified "wpr.exe"
			$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -WorkingDirectory $resultOutputDir -ArgumentList "-start `"$WPRP`"$WPRPSuffix -filemode -instancename AV"
			Test-WPRError $StartWPRCommand.ExitCode
		}
	} 
	#Downlevel machine with SCEP
	elseif (Test-Path -path "$env:ProgramFiles\Microsoft Security Client\MpCmdRun.exe") {
			Test-AuthenticodeSignature $MpCmdRunCommand
			Start-Process -WindowStyle minimized $MpCmdRunCommand -WorkingDirectory $CurrentMpCmdPath -ArgumentList "-trace -grouping ff -level ff"
	}
}

function Save-MDAVTrace {
	Write-Host "Stopping and merging Defender Antivirus traces if running"
	if ($WDVerboseTraceV) {
		&$MpCmdRunCommand -CaptureNetworkTrace | Out-File $connectivityCheckFile -Append
		Save-WinEventDebug Microsoft-Windows-SmartScreen/Debug
	}
	$MpCmdRunProcs = Get-Process | Where-Object { $_.MainWindowTitle -like "*MpCmdRun.ex*" }
	if ($MpCmdRunProcs) {
		foreach ($process in $MpCmdRunProcs) {
			[void][WindowFocus]::SetForeGroundWindow($process.MainWindowHandle) 
			[System.Windows.Forms.SendKeys]::SendWait("~")
		}
	}
	if ($WDPerfTraceA -or $WDLiteTraceE) {
		Test-CommandVerified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -WorkingDirectory $resultOutputDir -ArgumentList "-stop merged.etl -instancename AV"
		Test-WPRError $StartWPRCommand.ExitCode
	}
	if (Test-Path -Path  $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-SmartScreen%4Debug.evtx') {
		Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-SmartScreen%4Debug.evtx' -Destination $resultOutputDir\EventLogs\SmartScreen.evtx
	}
}

function Get-CrashDump {
	New-Item -ItemType Directory -Path "$resultOutputDir\CrashDumps" -ErrorAction SilentlyContinue | out-Null
	Write-Host "Attempting to collect user mode memory dumps"
	if ($ARM) {
		$ProcDumpCommand = Join-Path $ToolsDir "ProcDump64a.exe"
	}
 else {
		$ProcDumpCommand = Join-Path $ToolsDir "procdump.exe" 
	}
	Test-AuthenticodeSignature $ProcDumpCommand
	if ($OSPreviousVersion) {
		$processes = @(Get-Process -Name MsSenseS -ErrorAction SilentlyContinue) + @(Get-Process -Name MonitoringHost -ErrorAction SilentlyContinue)
		if ($processes -eq $null) {
			Write-Host "No running Sensor processes found"
		}
		else {
			foreach ($process in $processes) {
				Test-AuthenticodeSignature $ProcDumpCommand
				& $ProcDumpCommand -accepteula -ma -mk $process.Id "$resultOutputDir\CrashDumps\$($process.name)_$($process.Id).dmp"
			}
		}
	}
	elseif ($buildNumber -ge "15063") {
		$processes = @(Get-Process -Name SenseCE -ErrorAction SilentlyContinue) + @(Get-Process -Name SenseNDR -ErrorAction SilentlyContinue) + @(Get-Process -Name SenseTVM -ErrorAction SilentlyContinue)
		if ($processes -eq $null) {
			Write-Host "No running Sensor processes found"
		}
		else {
			foreach ($process in $processes) {
				Test-AuthenticodeSignature $ProcDumpCommand
				& $ProcDumpCommand -accepteula -ma -mk $process.Id "$resultOutputDir\CrashDumps\$($process.name)_$($process.Id).dmp"
			}
		}
	}
}

function Initialize-NetTrace {
	if ($NetTraceI) {
		New-Item -ItemType Directory -Path "$resultOutputDir\NetTraces" -ErrorAction SilentlyContinue | out-Null
		$traceFile = "$resultOutputDir\NetTraces\NetTrace.etl"
		Write-Host "Stopping any running network trace profiles"
		Test-CommandVerified "netsh.exe"
		Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "trace start capture=yes correlation=disabled report=no" | Out-Null
		start-sleep 1
		Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "trace stop" | Out-Null
		Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "wfp capture stop" | Out-Null
		start-sleep 1
		Test-CommandVerified "ipconfig.exe"
		Start-Process -PassThru -WindowStyle minimized ipconfig.exe -ArgumentList "/flushdns" | Out-Null
		Test-CommandVerified "netsh.exe"
		Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "interface ip delete arpcache" | Out-Null
		start-sleep 1
		# Terminating any lingering netsh processes just before starting fresh traces:
		$NetshProcess = Get-Process | Where-Object { $_.Name -eq "netsh" } -ErrorAction SilentlyContinue
		if ($NetshProcess -ne $null) {
			foreach ($process in $NetshProcess) { stop-Process $process -Force }
		}
		Write-Output "Starting netsh trace..." | Out-File $connectivityCheckFile -Append
		$NetshTraceKickOff = "{0:dd/MM/yyyy h:mm:ss tt zzz}" -f (get-date)
		Write-Output "Netsh trace start attempt at:" $NetshTraceKickOff | Out-File $connectivityCheckFile -Append
		if ($buildNumber -le 7601) {
			Test-CommandVerified "netsh.exe"
			$StartNetsh = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace start overwrite=yes capture=yes scenario=InternetClient report=yes maxSize=500 traceFile=`"$traceFile`" fileMode=circular"  -ErrorVariable NetshErr -RedirectStandardOutput $netshlog
		}
		else {
			Test-CommandVerified "netsh.exe"
			$StartNetsh = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace start overwrite=yes capture=yes scenario=InternetClient_dbg report=yes maxSize=500 traceFile=`"$traceFile`" fileMode=circular" -ErrorVariable NetshErr -RedirectStandardOutput $netshlog
		}
		if ($NetshErr -Or $StartNetsh.ExitCode) { 
			Write-Output "The exit code when attempting to start netsh trace was:" $StartNetsh.ExitCode | Out-File $connectivityCheckFile -Append
			Write-Output "Error variable contents:" $NetshErr | Out-File $connectivityCheckFile -Append
		}
		Test-CommandVerified "netsh.exe"
		Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging allowedconnections enable" | Out-Null  # enable firewall logging for allowed traffic
		Test-CommandVerified "netsh.exe"
		Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging droppedconnections enable"  | Out-Null  # enable firewall logging for dropped traffic
		Test-CommandVerified "netsh.exe"
		Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "wfp capture start file=wfpdiag.cab keywords=19"  | Out-Null # start capturing  WFP log
		Test-CommandVerified "netstat.exe"
		&netstat -anob | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStart.txt"
		"Netstat output above was taken at: " + (Get-Date) | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStart.txt" -Append
		if (($OSPreviousVersion) -and (!$MDfWS)) {
			$OMSPath = "$env:ProgramFiles\Microsoft Monitoring Agent\Agent\Tools"
			if (Test-Path -path $OMSPath) {
				Get-Service HealthService | Stop-Service -ErrorAction SilentlyContinue
				&$OMSPath\StopTracing.cmd | Out-Null
				&$OMSPath\StartTracing.cmd VER | Out-Null
				Get-Service HealthService | Start-Service -ErrorAction SilentlyContinue
			}
		}
	}
}

function Save-NetTrace {
	if ($NetTraceI) {
		Test-CommandVerified "netstat.exe"
		&netstat -anob | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStop.txt"
		"Netstat output above was taken at: " + (Get-Date) | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStop.txt" -Append
		Test-CommandVerified "netsh.exe"
		Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging allowedconnections disable" | Out-Null  # disable firewall logging for allowed traffic
		Test-CommandVerified "netsh.exe"
		Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging droppedconnections disable" | Out-Null  # disable firewall logging for dropped traffic
		Test-CommandVerified "netsh.exe"
		Start-Process -NoNewWindow netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "wfp capture stop"
		Test-CommandVerified "netsh.exe"
		Write-Host "Note: Stopping network and wfp traces may take a while..."
		Write-Output "Stopping netsh trace..." | Out-File $connectivityCheckFile -Append
		$NetshTraceStop = "{0:dd/MM/yyyy h:mm:ss tt zzz}" -f (get-date)
		Write-Output "Netsh trace stop attempt at:" $NetshTraceStop | Out-File $connectivityCheckFile -Append
		$StopNetsh = Start-Process -WindowStyle minimized netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace stop" -ErrorVariable StopErr -RedirectStandardOutput $netshlog
		if ($StopErr -Or $StopNetsh.ExitCode) { 
			Write-Output "The exit code when attempting to stop netsh trace was:" $StopNetsh.ExitCode | Out-File $connectivityCheckFile -Append
			Write-Output "Error variable contents:" $StopErr | Out-File $connectivityCheckFile -Append
		}
		Copy-Item $env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log -Destination "$resultOutputDir\NetTraces\" -ErrorAction SilentlyContinue
		if (($MMAPathExists) -and (!$MDfWS)) { 
			&$OMSPath\StopTracing.cmd | Out-Null
			Copy-Item $env:SystemRoot\Logs\OpsMgrTrace\* -Destination "$resultOutputDir\NetTraces\" -ErrorAction SilentlyContinue
		}	
		# Dump HOSTS file content to file
		Copy-Item $env:SystemRoot\System32\Drivers\etc\hosts -Destination "$resultOutputDir\SystemInfoLogs" -ErrorAction SilentlyContinue
		EndTimedoutProcess "netsh" 2
	}
}

# Define C# functions to extract info from Windows Security Center (WSC)
# WSC_SECURITY_PROVIDER as defined in Wscapi.h or http://msdn.microsoft.com/en-us/library/bb432509(v=vs.85).aspx
# And http://msdn.microsoft.com/en-us/library/bb432506(v=vs.85).aspx
$wscDefinition = @"
		[Flags]
        public enum WSC_SECURITY_PROVIDER : int
        {
            WSC_SECURITY_PROVIDER_FIREWALL = 1,				// The aggregation of all firewalls for this computer.
            WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS = 2,	// The automatic update settings for this computer.
            WSC_SECURITY_PROVIDER_ANTIVIRUS = 4,			// The aggregation of all antivirus products for this computer.
            WSC_SECURITY_PROVIDER_ANTISPYWARE = 8,			// The aggregation of all anti-spyware products for this computer.
            WSC_SECURITY_PROVIDER_INTERNET_SETTINGS = 16,	// The settings that restrict the access of web sites in each of the Internet zones for this computer.
            WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL = 32,	// The User Account Control (UAC) settings for this computer.
            WSC_SECURITY_PROVIDER_SERVICE = 64,				// The running state of the WSC service on this computer.
            WSC_SECURITY_PROVIDER_NONE = 0,					// None of the items that WSC monitors.
			
			// All of the items that the WSC monitors.
            WSC_SECURITY_PROVIDER_ALL = WSC_SECURITY_PROVIDER_FIREWALL | WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS | WSC_SECURITY_PROVIDER_ANTIVIRUS |
            WSC_SECURITY_PROVIDER_ANTISPYWARE | WSC_SECURITY_PROVIDER_INTERNET_SETTINGS | WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL |
            WSC_SECURITY_PROVIDER_SERVICE | WSC_SECURITY_PROVIDER_NONE
        }

        [Flags]
        public enum WSC_SECURITY_PROVIDER_HEALTH : int
        {
            WSC_SECURITY_PROVIDER_HEALTH_GOOD, 			// The status of the security provider category is good and does not need user attention.
            WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED,	// The status of the security provider category is not monitored by WSC. 
            WSC_SECURITY_PROVIDER_HEALTH_POOR, 			// The status of the security provider category is poor and the computer may be at risk.
            WSC_SECURITY_PROVIDER_HEALTH_SNOOZE, 		// The security provider category is in snooze state. Snooze indicates that WSC is not actively protecting the computer.
            WSC_SECURITY_PROVIDER_HEALTH_UNKNOWN
        }

		
        [DllImport("wscapi.dll")]
        private static extern int WscGetSecurityProviderHealth(int inValue, ref int outValue);

		// code to call interop function and return the relevant result
        public static WSC_SECURITY_PROVIDER_HEALTH GetSecurityProviderHealth(WSC_SECURITY_PROVIDER inputValue)
        {
            int inValue = (int)inputValue;
            int outValue = -1;

            int result = WscGetSecurityProviderHealth(inValue, ref outValue);

            foreach (WSC_SECURITY_PROVIDER_HEALTH wsph in Enum.GetValues(typeof(WSC_SECURITY_PROVIDER_HEALTH)))
                if ((int)wsph == outValue) return wsph;

            return WSC_SECURITY_PROVIDER_HEALTH.WSC_SECURITY_PROVIDER_HEALTH_UNKNOWN;
        }
"@

# Add-type to use SetForegroundWindow api https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setforegroundwindow
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
Add-Type @"
  using System;
  using System.Runtime.InteropServices;
  public class WindowFocus {
     [DllImport("user32.dll")]
     [return: MarshalAs(UnmanagedType.Bool)]
     public static extern bool SetForegroundWindow(IntPtr hWnd);
  }
"@

function Get-Log {
	New-Item -ItemType Directory -Path "$resultOutputDir\DefenderAV" -ErrorAction SilentlyContinue | out-Null	
	Test-CommandVerified "gpresult.exe"
	&gpresult /F /SCOPE COMPUTER /H "$env:windir\temp\GP.html"
	Move-Item -Path "$env:windir\temp\GP.html" -Destination "$resultOutputDir\SystemInfoLogs"
	if ($MpCmdRunCommand) {
		Write-Host "Running MpCmdRun -GetFiles..."
		Test-AuthenticodeSignature $MpCmdRunCommand
		&$MpCmdRunCommand -getfiles | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		Copy-Item -Path "$MpCmdResultPath\MpSupportFiles.cab" -Destination "$resultOutputDir\DefenderAV" -verbose -ErrorVariable GetFilesErr | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		$GetFilesErr | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		Copy-Item -path "C:\Users\Public\Downloads\Capture.npcap" -Destination "$resultOutputDir\DefenderAV" -ErrorAction SilentlyContinue -verbose -ErrorVariable CopyNpCap | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		$CopyNpCap | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		Copy-Item -path "C:\Users\Public\Downloads\Capture.npcap.injections" -Destination "$resultOutputDir\DefenderAV" -ErrorAction SilentlyContinue -verbose -ErrorVariable CopyNpCapInjections | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		$CopyNpCapInjections | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append		# Dump Defender related polices
		Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -recurse | Out-File "$resultOutputDir\DefenderAV\Policy-DefenderAV.txt"
		Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\" -recurse | Out-File "$resultOutputDir\DefenderAV\Policy-Firewall.txt"
		Get-ChildItem "HKU:\S-1-5-18\SOFTWARE\Microsoft\Windows Defender" -recurse -ErrorAction SilentlyContinue | Out-File "$resultOutputDir\DefenderAV\Policy-SystemService.txt"
		Get-ChildItem "HKU:\S-1-5-20\SOFTWARE\Microsoft\Windows Defender" -recurse -ErrorAction SilentlyContinue | Out-File "$resultOutputDir\DefenderAV\Policy-NetworkService.txt"

		Write-Host "Checking MpSupportFiles.cab for common issues"
		# Checking NetworkProtectionState.txt for common warning messages
		Start-Process -wait -WindowStyle minimized "expand" -ArgumentList "-I $resultOutputDir\DefenderAV\MPSupportFiles.cab -F:NetworkProtectionState.txt $resultOutputDir\DefenderAV"
	    if (-not(Test-Path -Path "$resultOutputDir\DefenderAV\NetworkProtectionState.txt" -PathType Leaf)) {
			Write-Host "Network Protection State unavailable - This may be expected on older Platform versions"
		}
		else {
			foreach ($NetworkProtectionState in Get-Content "$resultOutputDir\DefenderAV\NetworkProtectionState.txt") {
				if ($NetworkProtectionState.StartsWith("[WARNING]")) {
					WriteReport 121042 @() @(, @($NetworkProtectionState))
					$foundWarning = 1
				}
		
				if ($NetworkProtectionState -match "Network Protection is currently set in (?<mode>.*)") {
					$NetworkProtectionMode = (Get-Culture).TextInfo.ToTitleCase($Matches.mode)
				}
			}

			if ($NetworkProtectionMode) {
				if ($foundWarning) {
					# NetworkProtectionState contains the configured state, but if we hit a warning message then the feature is not really enabled
					$NetworkProtectionMode = $NetworkProtectionMode + " (Disabled)"
				}
				Write-Report -section "AVCompInfo" -subsection "NetworkProtectionState" -displayname "Defender Network Protection Mode" -value $NetworkProtectionMode
			}	
		}

		# Checking supportedUris to make sure it is being updated (if it exists).  This file contains URL Custom Indicators
		Start-Process -wait -WindowStyle minimized "expand" -ArgumentList "-I $resultOutputDir\DefenderAV\MPSupportFiles.cab -F:supportedUris $resultOutputDir\DefenderAV"
	    if (-not(Test-Path -Path "$resultOutputDir\DefenderAV\supportedUris" -PathType Leaf)) {
			Write-Host "No URL Custom Indicators received from Service - This may indicate connectivity issues if URL Custom Indicators are configured in portal"
		}
		else {
			$supportedUrisAge = (Get-ChildItem "$resultOutputDir\DefenderAV\supportedUris" | select-object LastWriteTime).LastWriteTime
		Write-Report -section "AVCompInfo" -subsection "NetworkProtectionState" -displayname "URL Custom Indicator Creation Date" -value $supportedUrisAge

			if (Test-Path -Path "$resultOutputDir\DefenderAV\supportedUris" -OlderThan (Get-Date).AddDays(-3))
			{
				WriteReport 141004 @() @()
			}
		}

		# run extra check for CFA if asked for:
		if ($DoCfaDiagnostics) {
			$CFAHelper = Join-Path $ToolsDir "MDEHelperCFA.psm1"
			# Test-AuthenticodeSignature $CFAHelper
			Import-Module $CFAHelper
			$cfaResults = Find-CfaDetections $resultOutputDir
			$filesToScan = $cfaResults[1]
			echo "MpCmdRunCommand: $MpCmdRunCommand"
			Test-ScanCfaReasons $filesToScan $MpCmdRunCommand $resultOutputDir
			# write the events
			$cfaDetections = $cfaResults[0]
			$cfaDetections | ForEach-Object {
				$_.DiagMessages | ForEach-Object {
					Write-ReportEvent -severity "Warning" -id 142010 -category "AV" -check "CFA" -checkresult $($_.description) -guidance $($_.guidance)
				}
			}
		}
	}

	Test-CommandVerified "fltmc.exe"
	&fltmc instances -v "$env:SystemDrive" > $resultOutputDir\SystemInfoLogs\filters.txt
	if ($OSProductName.tolower() -notlike ("*server*")) {
		Write-output "`r`n##################### Windows Security Center checks ######################" | Out-File $connectivityCheckFile -Append
		$wscType = Add-Type -memberDefinition $wscDefinition -name "wscType" -UsingNamespace "System.Reflection", "System.Diagnostics" -PassThru
 
		"            Firewall: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_FIREWALL) | Out-File $connectivityCheckFile -Append
		"         Auto-Update: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS) | Out-File $connectivityCheckFile -Append
		"          Anti-Virus: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_ANTIVIRUS) | Out-File $connectivityCheckFile -Append
		"        Anti-Spyware: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_ANTISPYWARE) | Out-File $connectivityCheckFile -Append
		"   Internet Settings: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_INTERNET_SETTINGS) | Out-File $connectivityCheckFile -Append
		"User Account Control: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL) | Out-File $connectivityCheckFile -Append
		"         WSC Service: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_SERVICE) | Out-File $connectivityCheckFile -Append

		if ($wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_FIREWALL) -eq $wscType[2]::WSC_SECURITY_PROVIDER_HEALTH_POOR) {
			Write-output "Windows Defender firewall settings not optimal" | Out-File $connectivityCheckFile -Append
		}
		if ($wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL) -eq $wscType[2]::WSC_SECURITY_PROVIDER_HEALTH_POOR) {
			Write-output "User Account Controller (UAC) is switched off" | Out-File $connectivityCheckFile -Append
		}
		if ($wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_ANTIVIRUS) -eq $wscType[2]::WSC_SECURITY_PROVIDER_HEALTH_GOOD) {
			Write-output "Windows Defender anti-virus is running and up-to-date" | Out-File $connectivityCheckFile -Append
		}
	}
}

function StartTimer {
	$TraceStartTime = "{0:dd/MM/yyyy h:mm:ss tt zzz}" -f (get-date)
	Write-Report -section "general" -subsection "traceStartTime" -displayname "Trace StartTime: " -value $TraceStartTime
	$timeout = New-TimeSpan -Minutes $MinutesToRun
	$sw = [diagnostics.stopwatch]::StartNew()
	Initialize-OnDemandStartEvent
	if ($RemoteRun) {
		Write-Warning "Trace started... Note that you can stop this non-interactive mode by running 'MDEClientAnalyzer.cmd' from another window or session"
		Wait-OnDemandStop
	} else {
		while ($sw.elapsed -lt $timeout) {
			Start-Sleep -Seconds 1
			$rem = $timeout.TotalSeconds - $sw.elapsed.TotalSeconds
			Write-Progress -Activity "Collecting traces, run your scenario now and press 'q' to stop data collection at any time" -Status "Progress:"  -SecondsRemaining $rem -PercentComplete (($sw.elapsed.Seconds / $timeout.TotalSeconds) * 100)
			if ([console]::KeyAvailable) {
				$key = [System.Console]::ReadKey() 
				if ( $key.key -eq 'q') {
					Write-Warning  "The trace collection action was ended by user exit command"
					break 
				}
			}
		}
	}
	$TraceStopTime = "{0:dd/MM/yyyy h:mm:ss tt zzz}" -f (get-date)
	Write-Report -section "general" -subsection "traceStopTime" -displayname "Trace StopTime: " -value $TraceStopTime 
}

function Get-MinutesValue {
	if ($RemoteRun) {
		"`r`nLog Collection was started from a remote device." | Out-File $connectivityCheckFile -Append
		return $MinutesToRun
	} 
	else {
		do {
			try {
				[int]$MinutesToRun = (Read-Host "Enter the number of minutes to collect traces")
				return $MinutesToRun
			}
			catch {
				Write-Warning  ($_.Exception.Message).split(':')[1]
				$MinutesToRun = $false
			}
		} while ($MinutesToRun -eq $false)
	}
}

function Test-WptState($command) {
	if (!$command) {
		$CheckCommand = (Get-Command "wpr.exe" -ErrorAction SilentlyContinue)
	} else {
		$CheckCommand = (Get-Command $command -ErrorAction SilentlyContinue)
	}
	# This line will reload the path so that a recent installation of wpr will take effect immediately:
	$env:path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
	$SenseWprp7 = Join-Path $ToolsDir "SenseW7.wprp"
	$SenseWprp10 = Join-Path $ToolsDir "SenseW10.wprp"
	$SenseWprp = Join-Path $ToolsDir "Sense.wprp"
	$DlZipFile = Join-Path $ToolsDir "WPT.cab"
	if (($CheckCommand -eq $null) -and ($InteractiveAdmin)) {
		Write-Warning "Performance Toolkit is not installed on this device. It is required for full traces to be collected."
		Write-host -ForegroundColor Green "Please wait while we download WPT installer files (~50Mb) to MDEClientAnalyzer directory. Refer to https://aka.ms/adk for more information about the 'Windows ADK'."
		$WPTURL = "https://aka.ms/MDATPWPT"
		Import-Module BitsTransfer
		$BitsResult = Start-BitsTransfer -Source $WPTURL -Destination "$DlZipFile" -TransferType Download -Asynchronous
		$DownloadComplete = $false
		if (!(Test-Path -path $DlZipFile)) {
			while ($DownloadComplete -ne $true) {
				start-Sleep 1
				$jobstate = $BitsResult.JobState;
				$percentComplete = ($BitsResult.BytesTransferred / $BitsResult.BytesTotal) * 100
				Write-Progress -Activity ('Downloading' + $result.FilesTotal + ' files') -Status "Progress:" -PercentComplete $percentComplete 
				if ($jobstate.ToString() -eq 'Transferred') {
					$DownloadComplete = $true
					Write-Progress -Activity ('Downloading' + $result.FilesTotal + ' files') -Completed close 
				}
				if ($jobstate.ToString() -eq 'TransientError') {
					$DownloadComplete = $true
					Write-host "Unable to download ADK installation package."
				}
			}
			$BitsResult | complete-BitsTransfer
		}
		if (Test-Path -path "$DlZipFile") {
			CheckHashFile "$DlZipFile" "6FE5F8CA7F864560B9715E0C18AA0D839416EDB0B68B4A314FC96DFAFA99733E"
			Test-CommandVerified "expand.exe"
			#Expand-Archive CMDlet or System.IO.Compression.ZipFile does not work with some older PowerShell/OS combinations so using the below for backwards compatbility 
			&expand.exe "$DlZipFile" "`"$($ToolsDir.TrimEnd('\'))`"" -F:*
			Write-host -ForegroundColor Green "Download complete. Starting installer..."
			start-Sleep 1
			Write-Host -BackgroundColor Red -ForegroundColor Yellow "Please click through the installer steps to deploy the Microsoft Windows Performance Toolkit (WPT) before proceeding"
			if ($buildNumber -eq 7601) {
				$AdkSetupPath = Join-Path $ToolsDir "8.0\adksetup.exe"
				Test-AuthenticodeSignature $AdkSetupPath
				Start-Process -wait -WindowStyle minimized "$AdkSetupPath" -ArgumentList "/ceip off /features OptionId.WindowsPerformanceToolkit"
				Read-Host "Press ENTER if intallation is complete and you are ready to resume..."	
			} elseif ($buildNumber -gt 7601) {
				$AdkSetupPath = Join-Path $ToolsDir "adksetup.exe"
				Test-AuthenticodeSignature $AdkSetupPath
				Start-Process -wait -WindowStyle minimized "$AdkSetupPath" -ArgumentList "/ceip off /features OptionId.WindowsPerformanceToolkit"
				Read-Host "Press ENTER if intallation is complete and you are ready to resume..."
			}
		} else {
			Write-host "Please download and install manually from https://aka.ms/adk" 
		}
		# If install is successful we need to refresh environemnt variable and check if command got installed
		$env:path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
		$CheckCommand = (Get-Command $command -ErrorAction SilentlyContinue)
		if ($CheckCommand -eq $null) {
			Write-Host -BackgroundColor Red -ForegroundColor Yellow "WPT was not installed. Only partial data will be collected"
			return
		} elseif ($buildNumber -eq 7601) {
			Write-Warning "Note: Windows7/2008R2 devices also require running 'wpr.exe -disablepagingexecutive on' and rebooting"
			Write-Warning "To disable, run 'wpr.exe -disablepagingexecutive off' once data collection is complete"
			Read-Host "Press ENTER to allow MDEClientAnalyzer to turn on 'disablepagingexecutive' and restart your device automatically"
			$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-disablepagingexecutive on"
			Test-WPRError $StartWPRCommand.ExitCode
			Restart-Computer -ComputerName .
		}
	} else {
		Write-Host "Stopping any running WPR trace profiles"
		Test-CommandVerified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe  -ArgumentList "-cancel"
		Test-WPRError $StartWPRCommand.ExitCode
	}
	if ($buildNumber -le 9600) {
		Copy-Item -path $SenseWprp7 -Destination $senseWprp -Force	
	} else {
		Copy-Item -path $SenseWprp10 -Destination $senseWprp -Force
	}
	$WptState = "Ready"
	return $WptState
}

function Initialize-Wpr {
	if ($WptState -eq "Ready") {
		Test-CommandVerified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-start `"$ToolsDir\Sense.wprp`" -filemode -instancename Sense"
		Test-WPRError $StartWPRCommand.ExitCode
	}
}

function Save-Wpr {
	if ($WptState -eq "Ready") {
		Test-CommandVerified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-stop `"$WprpTraceFile`" -instancename Sense"
		Test-WPRError $StartWPRCommand.ExitCode
	}
}

function Copy-RecentItem($ParentFolder, $DestFolderName) {
	$ParentFolder = (Get-ChildItem -Path $ParentFolder)
	$ParentFolder = ($ParentFolder | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-2) } -ErrorAction SilentlyContinue)
	if ($ParentFolder -ne $null) {
		foreach ($subfolder in $ParentFolder) {
			Copy-Item -Recurse -Path $subfolder.FullName -Destination $resultOutputDir\$DestFolderName\$subfolder -ErrorAction SilentlyContinue
		}
	}
}

function Initialize-WinEventDebug($DebugLogName) {
	$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $DebugLogName
	if ($log.IsEnabled -ne $true) {
		$log.IsEnabled = $true
		$log.SaveChanges()
	}
}

function Save-WinEventDebug($DebugLogName) {
	$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $DebugLogName
	$log.IsEnabled = $false
	$log.SaveChanges()
	$DebugLogPath = [System.Environment]::ExpandEnvironmentVariables($log.LogFilePath)
	Copy-Item -path "$DebugLogPath" -Destination "$resultOutputDir\EventLogs\"
}

function SetLocalDumps() {
	# If already implementing LocalDumps as per https://docs.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps, then backup the current config
	if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps") {
		Test-CommandVerified "reg.exe"
		&Reg export "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" "$ToolsDir\WerRegBackup.reg" /y 2>&1 | Out-Null
	}  
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Recurse -ErrorAction SilentlyContinue | out-Null
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "LocalDumps" -ErrorAction SilentlyContinue | out-Null
	New-Item -ItemType Directory -Path "$resultOutputDir\CrashDumps" -ErrorAction SilentlyContinue | out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpFolder" -Value "$resultOutputDir\CrashDumps" -PropertyType "ExpandString" -ErrorAction SilentlyContinue | out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpCount" -Value 5 -PropertyType DWord -ErrorAction SilentlyContinue | out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpType" -Value 2 -PropertyType DWord -ErrorAction SilentlyContinue | out-Null
}

function RestoreLocalDumps() {
	if (Test-Path "$ToolsDir\WerRegBackup.reg") {
		Test-CommandVerified "reg.exe"
		&reg.exe import "$ToolsDir\WerRegBackup.reg" 2>&1 | Out-Null
	}
 else {
		Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -ErrorAction SilentlyContinue | out-Null
	}
}

# function to download a given cab file and expand it
function Get-WebFile($webfile) {
	$DlZipFile = Join-Path $ToolsDir "webfile.cab"
	Write-host -ForegroundColor Green "Please wait while we download additional required files to MDEClientAnalyzer from: " $webfile
	Import-Module BitsTransfer
	Start-BitsTransfer -source $webfile -Destination "$DlZipFile" -Description "Downloading additional files" -RetryTimeout 60 -RetryInterval 60 -ErrorAction SilentlyContinue | Out-Null
}

function Initialize-AppCompatTrace() {
	if ($AppCompatC) {
		if ($ARM) {
			$ProcmonCommand = Join-Path $ToolsDir "Procmon64a.exe"
		}
		else {
			$ProcmonCommand = Join-Path $ToolsDir "Procmon.exe"
		}
		Test-AuthenticodeSignature $ProcmonCommand
		&$ProcmonCommand -AcceptEula -Terminate
		#Clearing out previus run lingering files and settings
		Remove-ItemProperty -Path "HKCU:\SOFTWARE\Sysinternals\Process Monitor" -Name "Logfile" -Force -ErrorAction SilentlyContinue
		Remove-Item $ToolsDir\*.pml -Force -ErrorAction SilentlyContinue
		Test-AuthenticodeSignature $ProcmonCommand
		&$ProcmonCommand -AcceptEula -BackingFile "$resultOutputDir\procmonlog.pml" -NoFilter -Quiet -Minimized 
		Initialize-WinEventDebug Microsoft-Windows-WMI-Activity/Debug
		SetLocalDumps
	}
}

function Save-AppCompatTrace() {
	if ($AppCompatC) {
		if ($ARM) {
			$ProcmonCommand = Join-Path $ToolsDir "Procmon64a.exe"
		}
		else {
			$ProcmonCommand = Join-Path $ToolsDir "Procmon.exe"
		}		
		Test-AuthenticodeSignature $ProcmonCommand
		Write-Host "Stopping procmon trace..."
		&$ProcmonCommand -AcceptEula -Terminate
		if (Test-Path -Path  $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider%4Admin.evtx') {
			Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider%4Admin.evtx' -Destination $resultOutputDir\EventLogs\MdmAdmin.evtx
			Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider%4Operational.evtx' -Destination $resultOutputDir\EventLogs\MdmOperational.evtx -ErrorAction SilentlyContinue
		}
		Save-WinEventDebug Microsoft-Windows-WMI-Activity/Debug
		Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx' -Destination $resultOutputDir\EventLogs\WMIActivityOperational.evtx
		Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\System.evtx' -Destination $resultOutputDir\EventLogs\System.evtx
		Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Application.evtx' -Destination $resultOutputDir\EventLogs\Application.evtx
		Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-PushNotification-Platform%4Operational.evtx' -Destination $resultOutputDir\EventLogs\PushNotification-Platform-Operational.evtx

		$DestFolderName = "WER"
		Copy-RecentItem $env:ProgramData\Microsoft\Windows\WER\ReportArchive $DestFolderName
		Copy-RecentItem $env:ProgramData\Microsoft\Windows\WER\ReportQueue $DestFolderName
		#Clearing out previus run lingering files and settings
		RestoreLocalDumps
		Remove-ItemProperty -Path "HKCU:\SOFTWARE\Sysinternals\Process Monitor" -Name "Logfile" -Force -ErrorAction SilentlyContinue
	}
}		

function Save-PerformanceCounter {
	param (
		$DataCollectorSet,
		$DataCollectorName
	)
	try {
		$DataCollectorSet.Query($DataCollectorName, $null)
		if ($DataCollectorSet.Status -ne 0) {
			$DataCollectorSet.stop($false)
			Start-Sleep 10
		}
           
		$DataCollectorSet.Delete()
	}
	catch [Exception] {
		$_.Exception.Message
	}
}

function Get-PerformanceCounter {
	param (
		[Alias("r")][switch]$RunCounter
	)

	$filePathToXml = "$ToolsDir\PerfCounter.xml"
	if ($RunCounter) {
		if (($buildNumber -eq 9600) -or ($buildNumber -eq 7601)) {
			Copy-Item  -path "$ToolsDir\PerfCounterW7.xml" -Destination  "$ToolsDir\PerfCounter.xml" -Force
		}
		else {
			Copy-Item  -path "$ToolsDir\PerfCounterW10.xml"  -Destination  "$ToolsDir\PerfCounter.xml" -Force
		}   
		$xmlContent = New-Object XML
		$xmlContent.Load($filePathToXml)
		$xmlContent.SelectNodes("//OutputLocation") | ForEach-Object { $_."#text" = $_."#text".Replace('c:\', $ToolsDir) }
		$xmlContent.SelectNodes("//RootPath") | ForEach-Object { $_."#text" = $_."#text".Replace('c:\', $ToolsDir) }
		$xmlContent.Save($filePathToXml)
	}

	$DataCollectorName = "MDE-Perf-Counter"
	$DataCollectorSet = New-Object -COM Pla.DataCollectorSet
	[string]$xml = Get-Content $filePathToXml
	$DataCollectorSet.SetXml($xml)
	Write-Host "Stopping any running perfmon trace profiles"
	Save-PerformanceCounter -DataCollectorSet  $DataCollectorSet -DataCollectorName $DataCollectorName >$null
	if ($RunCounter) {
		$DataCollectorSet.Commit("$DataCollectorName" , $null , 0x0003) | Out-Null
		$DataCollectorSet.Start($false)
	}
}

function Initialize-PerformanceTrace() {
	if ($wprpTraceL) {
		Get-PerformanceCounter -r
	}
}

function Save-PerformanceTrace() {
	if ($wprpTraceL) {
		Get-PerformanceCounter		
	}
	$Perfmonlogs = Get-Item $ToolsDir\*.blg
	if (($Perfmonlogs) -ne $null) {
		Move-Item -Path $Perfmonlogs -Destination $resultOutputDir
	} 
}

function GetOnboardingInfo {
	param (
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$onboardingScriptPath
	)
	$partnerGeoLocation = select-string -path $onboardingScriptPath -pattern "partnerGeoLocation\\+`":\\+`"([^\\]+)" | ForEach-Object{ $_.Matches[0].Groups[1].Value }
	$vortexGeoLocation = select-string -path $onboardingScriptPath -pattern "vortexGeoLocation\\+`":\\+`"([^\\]+)" | ForEach-Object{ $_.Matches[0].Groups[1].Value }
	$datacenter = select-string -path $onboardingScriptPath -pattern "datacenter\\+`":\\+`"([^\\]+)" | ForEach-Object{ $_.Matches[0].Groups[1].Value }
	return $partnerGeoLocation, $vortexGeoLocation, $datacenter
}

function SetUrlList {
	param (
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$OSPreviousVersion,
		[parameter(Mandatory = $false)]
		[string]$onboardingScriptPath,
		[parameter(Mandatory = $false)]
		[string]$geoRegion
	)
	$Urls = @{}
	
	$RegionsObj = (Get-Content $RegionsJson -raw) | ConvertFrom-Json
	if ((Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value OnboardedInfo) -or ($ASM) -or ($onboardingScriptPath)  -or ($geoRegion)) {
		Clear-Content -Path $EndpointList	

		if ($asm) {
			# Datacenter not relevant at this time
			$Region = "ASM"
		}
		Elseif ($onboardingScriptPath) {
			$partnerGeoLocation, $vortexGeoLocation, $datacenter = GetOnboardingInfo($onboardingScriptPath)
			$Region = $partnerGeoLocation
			if ($null -eq $Region) {
				$Region = $vortexGeoLocation
			}
			$Datacenter = $datacenter
		}
		Elseif ($geoRegion) {
			$Region = $geoRegion
		}
		Else {
			$OnboardedInfo = (((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\").OnboardedInfo | ConvertFrom-Json).body | ConvertFrom-Json)
			$Region = $OnboardedInfo.partnerGeoLocation
			if ($null -eq $Region) {
				$Region = $OnboardedInfo.vortexGeoLocation
			}
			$Datacenter = $OnboardedInfo.Datacenter
		}
		$regionURLs = ($RegionsObj | Where-Object { ($_.Region -eq $Region) -and ($Datacenter -like "$($_.datacenterprefix)*") })
		if ($null -ne $regionURLs) {
			Add-Content $EndpointList -value $regionURLs.CnCURLs
			Add-Content $EndpointList -value $regionURLs.CyberDataURLs
			Add-Content $EndpointList -value $regionURLs.AutoIRBlobs
			Add-Content $EndpointList -value $regionURLs.SampleUploadBlobs
			Add-Content $EndpointList -value $regionURLs.MdeConfigMgr
			Add-Content $EndpointList -value $regionURLs.OneDs

			$Urls['CnCURLs'] = $regionURLs.CnCURLs
			$Urls['CyberDataURLs'] = $regionURLs.CyberDataURLs
			$Urls['AutoIRBlobs'] = $regionURLs.AutoIRBlobs
			$Urls['SampleUploadBlobs'] = $regionURLs.SampleUploadBlobs
			$Urls['MdeConfigMgr'] = $regionURLs.MdeConfigMgr
			$Urls['OneDs'] = $regionURLs.OneDs
		}
		
		if (($Region) -notmatch 'FFL') {
			$regionAllURLs = ($RegionsObj | Where-Object { $_.Region -eq "ALL" });
			Add-Content $EndpointList -value $regionAllURLs.CTLDL
			Add-Content $EndpointList -value $regionAllURLs.Settings
			Add-Content $EndpointList -value $regionAllURLs.Events
			Add-Content $EndpointList -value $regionAllURLs.OneDs
		}
		$AllRegionsURLs['Region'] = $Region
		$AllRegionsURLs['Urls'] = $Urls
	} 
	elseif ($OSPreviousVersion) {
		Clear-Content -Path $EndpointList
		$Regions = ('US', 'UK', 'EU')
		foreach ($Region in $Regions) {
			Add-Content $EndpointList -value ($RegionsObj | Where-Object { $_.Region -eq $Region }).CnCURLs
			$Urls['CnCURLs'] = ($RegionsObj | Where-Object { $_.Region -eq $Region }).CnCURLs
			$AllRegionsURLs['Region'] = $Region
			$AllRegionsURLs['Urls'] = $Urls
		}
	}
}

function ValidateURLs {
	# Add warning to output if any EDR Cloud checks failed
	# Based on https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/configure-proxy-internet#verify-client-connectivity-to-microsoft-defender-atp-service-urls
	# "If at least one of the connectivity options returns a (200) status, then the Microsoft Defender for Endpoint client can communicate with the tested URL properly using this connectivity method."
	Write-output "`r`n#################### Defender for Endpoint cloud service check #####################" | Out-File $connectivityCheckFile -Append
	$Streamer = New-Object System.IO.StreamReader( $connectivityCheckFile)
	$SuccessCounter = -1

	$AllUrlsErrors = New-Object System.Collections.Generic.List[System.Object]
	while (($Line = $Streamer.ReadLine()) -ne $null) {
		If ($Line -like "*Testing URL :*") {
			$UrlToCheck = $Line.substring(14)
			$SuccessCounter = 0       
			For ($i = 0; $i -le 5; $i++) {
				$Line = $Streamer.ReadLine()
				If (($Line -like "*(200)*") -or ($Line -like "*(400)*") -or ($Line -like "*(404)*") -or ($Line -like "*Succeeded (405)*")) {
					$SuccessCounter += 1
				}
			}
			If ($SuccessCounter -eq 0) {
				 if (-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $UrlToCheck) {
						Add-Member -InputObject $AllUrlsErrors -MemberType NoteProperty -Name $currentSection -Value $UrlToCheck -ErrorAction SilentlyContinue
				   }
				[void]$AllUrlsErrors.Add($UrlToCheck)
			}
		}
	}
	$Streamer.Dispose()
	if ($SuccessCounter -eq -1) {
		WriteReport 131001 @() @()
	}
	else {
		#Urls connectivity checks by region
		if ($AllRegionsURLs.Region -eq 'ASM') {
			CheckCnCURLs $AllRegionsURLs $AllUrlsErrors
		}
		else {
			CheckCnCURLs $AllRegionsURLs $AllUrlsErrors
			CheckCyberURLs $AllRegionsURLs $AllUrlsErrors
			CheckAutoIR $AllRegionsURLs $AllUrlsErrors
			CheckSampleUpload $AllRegionsURLs $AllUrlsErrors
			CheckMdeConfigMgr $AllRegionsURLs $AllUrlsErrors
		}
	}
}

function CountErrors($AllUrlsErrors, $AllConnectivity, $ConnectivityCheck) {
	$CheckURLs = $AllConnectivity.$ConnectivityCheck
	$CountErrors = 0
	$Errors = New-Object System.Collections.Generic.List[System.Object]
	If ($AllUrlsErrors.Count -gt 0 -and $CheckURLs.Count -gt 0) {
		foreach ($url in $CheckURLs) {
			If ($AllUrlsErrors.Contains($url)) {
				$CountErrors += 1
				[void]$Errors.Add($url)
			}
		}
	}
	$ParsedErrors = @()
	foreach ($Error in $Errors) {
		$ParsedErrors += "<a href='" + $Error + "'>" + $Error + "</a>"
	}
	return $CountErrors, $ParsedErrors
}

function CheckCnCURLs($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$CncErrorCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'CnCURLs'

	If ($CncErrorCnt -gt 1) {
		WriteReport 132021 @(, @($Errors)) @()
	}
	elseif ($CncErrorCnt -eq 0) {
		WriteReport 130017 @() @()
	}
	else {
		WriteReport 131013 @(, @($Errors)) @()
	}
}

function CheckCyberURLs($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$CyberErrorCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'CyberDataURLs'

	If ($CyberErrorCnt -gt 1) {
		WriteReport 132022 @(, @($Errors)) @()
	}
	elseif ($CyberErrorCnt -eq 0) {
		WriteReport 130018 @() @()
	}
	else {
		WriteReport 131014 @(, @($Errors)) @()
	}
}

function CheckAutoIR($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$AutoIRCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'AutoIRBlobs'

	If ($AutoIRCnt -gt 1) {
		WriteReport 132023 @(, @($Errors)) @()
	}
	elseif ($AutoIRCnt -eq 0) {
		WriteReport 130019  @() @()
	}
	else {
		WriteReport 131015 @(, @($Errors)) @()
	}
}

function CheckSampleUpload($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$SampleUploadCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'SampleUploadBlobs'

	If ($SampleUploadCnt -gt 1) {
		WriteReport 132024 @(, @($Errors)) @()
	}
	elseif ($SampleUploadCnt -eq 0) {
		WriteReport 130020 @() @()
	}
	else {
		WriteReport 131016 @(, @($Errors)) @()
	}
}

function CheckMdeConfigMgr($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$MdeConfigMgrCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'MdeConfigMgr'

	If ($MdeConfigMgrCnt -gt 1) {
		WriteReport 132025 @(, @($Errors)) @()
	}
	elseif ($MdeConfigMgrCnt -eq 0) {
		WriteReport 130021 @() @()
	}
	else {
		WriteReport 131017 @(, @($Errors)) @()
	}
}

function Enter-CheckURL() {
	$PSExecCommand = Join-Path $ToolsDir "PsExec.exe"
	$MDEClientAnalyzerCommand = Join-Path $ToolsDir "MDEClientAnalyzer.exe"
	$URLCheckLog = Join-Path $ToolsDir "URLCheckLog.txt"
	$psexeclog = Join-Path $ToolsDir "psexeclog.txt"
	if (test-Path -path $PSExecCommand) {
		Test-AuthenticodeSignature $PSExecCommand
		Test-AuthenticodeSignature $MDEClientAnalyzerCommand
		Start-Process `
			-WorkingDirectory $ToolsDir `
			-FilePath $PSExecCommand `
			-WindowStyle Hidden `
			-RedirectStandardOutput $URLCheckLog `
			-RedirectStandardError $psexeclog `
			-ArgumentList "$ARMcommand -accepteula -nobanner -s -w `"$ToolsDir`" `"$MDEClientAnalyzerCommand`""
	}
}

function CheckConnectivity {
 param (
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$OSPreviousVersion,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$connectivityCheckFile,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$connectivityCheckUserFile,
		[parameter(Mandatory = $false)]
		[string]$onboardingScriptPath,
		[parameter(Mandatory = $false)]
		[string]$geoRegion
	)

	[version]$mindotNet = "4.0.30319"
	$PSExecCommand = Join-Path $ToolsDir "PsExec.exe"
	if (test-Path -path $PSExecCommand) {
		Test-AuthenticodeSignature $PSExecCommand
	}
	$MDEClientAnalyzerCommand = Join-Path $ToolsDir "MDEClientAnalyzer.exe"
	Test-AuthenticodeSignature $MDEClientAnalyzerCommand
	$MDEClientAnalyzerPreviousVersionCommand = Join-Path $ToolsDir "MDEClientAnalyzerPreviousVersion.exe"
	$URLCheckLog = Join-Path $ToolsDir "URLCheckLog.txt"
	$psexeclog = Join-Path $ToolsDir "psexeclog.txt"

	SetUrlList -OSPreviousVersion $OSPreviousVersion -onboardingScriptPath $onboardingScriptPath -geoRegion $geoRegion

	if ((Get-RegistryValue -Path  "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client" -Value Version)) {
		[version]$dotNet = Get-RegistryValue -Path  "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client" -Value Version
	}
 	else {
		[version]$dotNet = "0.0.0000"
	}
	
	if ((!$OSPreviousVersion) -or ($MDfWS)) {		        
		"`r`nImportant notes:" | Out-File $connectivityCheckFile -Append
		"1. If at least one of the connectivity options returns status (200), then Defender for Endpoint sensor can properly communicate with the tested URL using this connectivity method." | Out-File $connectivityCheckFile -Append
		"2. For *.blob.core.*.net URLs, return status (400) is expected. However, the basic connectivity test on Azure blob URLs cannot detect SSL inspection scenarios as it is performed without certificate pinning." | Out-File $connectivityCheckFile -Append
		"However, please refer to section 'MDE certificate chain validation' at the bottom of this file for certificate pinning check that can detect SSL inspection scenarios." | Out-File $connectivityCheckFile -Append
		
		
		
		"For more information on certificate pinning, please refer to: https://docs.microsoft.com/en-us/windows/security/identity-protection/enterprise-certificate-pinning" | Out-File $connectivityCheckFile -Append
		# check if running with system context (i.e. script was most likely run remotely via "psexec.exe -s \\device command" or Live Response)
		if ($system) {
			"`r`nConnectivity output, running as System:" | Out-File $connectivityCheckFile -Append
			Set-Location -Path $ToolsDir
			Test-AuthenticodeSignature $MDEClientAnalyzerCommand
			&$MDEClientAnalyzerCommand >> $connectivityCheckFile
			Set-Location -Path $outputDir
		}
		elseif ($eulaAccepted -eq "Yes") {
			"`r`nConnectivity output, using psexec -s:" | Out-File $connectivityCheckFile -Append
			Write-Host "The tool checks connectivity to Microsoft Defender for Endpoint service URLs. This may take longer to run if URLs are blocked."
			Enter-CheckURL
			# Run the tool as interactive user (for authenticated proxy scenario)
			# Start-Process -wait -WindowStyle minimized $MDEClientAnalyzerCommand -WorkingDirectory $ToolsDir -RedirectStandardOutput $connectivityCheckUserFile
		}
		start-sleep 10
		EndTimedoutProcess "MDEClientAnalyzer" 2 
		if (test-path $URLCheckLog) {
			Get-Content -Path $URLCheckLog | Out-File $connectivityCheckFile -Append
			Get-Content -Path $psexeclog | Out-File $connectivityCheckFile -Append
		}
		ValidateURLs
	}
	elseif ($dotNet -ge $mindotNet) {
		Write-Host "The tool checks connectivity to Microsoft Defender for Endpoint service URLs. This may take longer to run if URLs are blocked."
		Test-AuthenticodeSignature $MDEClientAnalyzerPreviousVersionCommand
		# check if running with system context (i.e. script was most likely run remotely via "psexec.exe -s \\device command")
		if ($system) {
			Set-Location -Path $ToolsDir
			Test-AuthenticodeSignature $MDEClientAnalyzerPreviousVersionCommand
			&$MDEClientAnalyzerPreviousVersionCommand
			Set-Location -Path $outputDir
		}
		elseif ($eulaAccepted -eq "Yes") {
			if (test-Path -path $PSExecCommand) {
				Test-AuthenticodeSignature $PSExecCommand
			}
			(& $PSExecCommand -accepteula -s -nobanner -w "`"$($ToolsDir.TrimEnd('\'))`"" "$MDEClientAnalyzerPreviousVersionCommand" )
			# Run the tool as interactive user (for authenticated proxy scenario)
			Start-Process -wait -WindowStyle minimized $MDEClientAnalyzerPreviousVersionCommand -WorkingDirectory $ToolsDir -RedirectStandardOutput $connectivityCheckUserFile
		}
            
		#Run MMA Connectivity tool
		$MMATestProcess = "$env:ProgramFiles\Microsoft Monitoring Agent\Agent\TestCloudConnection.exe"
		if (Test-Path -path $MMATestProcess) {
			Test-AuthenticodeSignature $MMATestProcess
			&$MMATestProcess
		}
	} else {
		Write-Host -BackgroundColor Red -ForegroundColor Yellow "To run URI validation tool please install .NET framework 4.0  or higher"
		"To run URI validation tool please install .NET framework 4.0 or higher" | Out-File $connectivityCheckFile -Append
	}

	if ($OSPreviousVersion) {
		$HealthServiceDll = "$env:ProgramFiles\Microsoft Monitoring Agent\Agent\HealthService.dll"
		if (Test-Path -path $HealthServiceDll) {
			$healthserviceprops = @{
				Message = ""
				Valid   = $true
				Version = [string]((Get-ItemProperty -Path "$HealthServiceDll").VersionInfo).ProductMajorPart + '.' + [string]((Get-ItemProperty -Path "$HealthServiceDll").VersionInfo).ProductMinorPart + '.' + [string]((Get-ItemProperty -Path "$HealthServiceDll").VersionInfo).ProductBuildPart + '.' + [string]((Get-ItemProperty -Path "$HealthServiceDll").VersionInfo).FilePrivatePart
			}
			$Global:healthservicedll = new-object psobject -Property $healthserviceprops

			If ($OSBuild -eq "7601") {
				<#
				Supported versions for Windows Server 2008 R2 / 2008 / Windows 7
				x64 - 10.20.18029,  10.20.18038, 10.20.18040
				x86 - 10.20.18049
				#>
				if ($arch -like "*64*") {
					[version]$HealthServiceSupportedVersion = '10.20.18029'
				}
				else {
					[version]$HealthServiceSupportedVersion = '10.20.18049'
				}

				If ([version]$Global:healthservicedll.version -lt $HealthServiceSupportedVersion) {
					$Global:healthservicedll.Valid = $false
					$Global:healthservicedll.Message = "The Log Analytics Agent version installed on this device (" + $Global:healthservicedll.version + ") is deprecated as it does not support SHA2 for code signing.`r`n" `
						+ "Note that the older versions of the Log Analytics will no longer be supported and will stop sending data in a future timeframe. More information: https://aka.ms/LAAgentSHA2 `r`n" `
						+ "Please upgrade to the latest version:`r`n" `
						+ "- Windows 64-bit agent - https://go.microsoft.com/fwlink/?LinkId=828603 `r`n"`
						+ "- Windows 32-bit agent - https://go.microsoft.com/fwlink/?LinkId=828604"
				}
				else {
					$Global:healthservicedll.Message = "The version " + $Global:healthservicedll.version + " of HealthService.dll is supported"
				}
			}
		}
	}
	
	if ('$env:SystemRoot\\System32\wintrust.dll') {
		[version]$wintrustMinimumFileVersion = '6.1.7601.23971'
		$wintrustprops = @{
			Message = ""
			Valid   = $true
			Version = [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\wintrust.dll).VersionInfo).ProductMajorPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\wintrust.dll).VersionInfo).ProductMinorPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\wintrust.dll).VersionInfo).ProductBuildPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\wintrust.dll).VersionInfo).FilePrivatePart
		}
		$Global:wintrustdll = new-object psobject -Property $wintrustprops

		if (([version]$Global:wintrustdll.version -lt $wintrustMinimumFileVersion) ) {
			$Global:wintrustdll.Valid = $false
			$Global:wintrustdll.Message = "Environment is not supported: " + [System.Environment]::OSVersion.VersionString + "`r`nMDE can't start - it requires wintrust.dll version $wintrustMinimumFileVersion or higher, while this device has version " + $wintrustdll.version + ". `r`n" `
				+ "You should install one of the following updates:`r`n" `
				+ "* KB4057400 - 2018-01-19 preview of monthly rollup.`r`n" `
				+ "* KB4074598 - 2018-02-13 monthly rollup.`r`n" `
				+ "* A later monthly rollup that supersedes them.`r`n"
		}
		else {
			$Global:wintrustdll.Message = "The version " + $Global:wintrustdll.version + " of wintrust.dll is supported"
		}
	}

	if (('$env:SystemRoot\\System32\tdh.dll')) {
		$tdhprops = @{
			Message = ""
			Valid   = $true
			Version = [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\tdh.dll).VersionInfo).ProductMajorPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\tdh.dll).VersionInfo).ProductMinorPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\tdh.dll).VersionInfo).ProductBuildPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\tdh.dll).VersionInfo).FilePrivatePart
		}
		$Global:tdhdll = new-object psobject -Property $tdhprops
		
		if ($OSBuild -eq "9600") {
			[version]$gdrTdhMinimumFileVersion = '6.3.9600.17958'
		}
		else {
			[version]$gdrTdhMinimumFileVersion = '6.1.7601.18939'
			[version]$ldrMinimumFileVersion = '6.1.7601.22000'
			[version]$ldrTdhMinimumFileVersion = '6.1.7601.23142'
		}
	
		if ([version]$Global:tdhdll.Version -lt $gdrTdhMinimumFileVersion) {
			$Global:tdhdll.Valid = $false
			$Global:tdhdll.Message = "Environment is not supported: " + [System.Environment]::OSVersion.VersionString + "`r`nMDE can't start - it requires tdh.dll version $gdrTdhMinimumFileVersion or higher, while this device has version " + $tdhdll.version + ". `r`n" `
				+ "You should install the following update:`r`n" `
				+ "* KB3080149 - Update for customer experience and diagnostic telemetry.`r`n"
		}
		elseif ($OSBuild -eq "7601" -and [version]$Global:tdhdll.Version -ge $ldrMinimumFileVersion -and [version]$tdhdll.Version -lt $ldrTdhMinimumFileVersion) {
			$Global:tdhdll.Valid = $false
			$Global:tdhdll.Message = "Environment is not supported: " + [System.Environment]::OSVersion.VersionString + "`r`nMDE can't start - it requires tdh.dll version $ldrTdhMinimumFileVersion or higher, while this device has version " + $tdhdll.version + ". `r`n" `
				+ "You should install the following update:`r`n" `
				+ "* KB3080149 - Update for customer experience and diagnostic telemetry.`r`n"
		}
		else {
			$Global:tdhdll.Message = "The version " + $Global:tdhdll.version + " of tdh.dll is supported"
		}
	}

	$protocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072)
	[string]$global:SSLProtocol = $null
	try {
		[System.Net.ServicePointManager]::SecurityProtocol = $protocol
	}
 	catch [System.Management.Automation.SetValueInvocationException] {
		$global:SSLProtocol = "`r`nEnvironment is not supported , the missing KB must be installed`r`n"`
			+ "" + [System.Environment]::OSVersion.VersionString + ", MDE requires TLS 1.2 support in .NET framework 3.5.1, exception " + $_.Exception.Message + " . You should install the following updates:`n" `
			+ "* KB3154518 - Support for TLS System Default Versions included in the .NET Framework 3.5.1 on Windows 7 SP1 and Server 2008 R2 SP1`n"`
			+ "* .NET framework 4.0 or later.`n"`
			+ "########################################################################################################################" 
	}
 	Catch [Exception] {
		$global:SSLProtocol = $_.Exception.Message
	}
}

function TestASRRules() {
	#Taken from: https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-process-creations-originating-from-psexec-and-wmi-commands
	$ASRRuleBlockPsExec = "d1e49aac-8f56-4280-b9ba-993a6d77406c"

	$ASRRules = (Get-MpPreference).AttackSurfaceReductionRules_Ids
	$ASRActions = (Get-MpPreference).AttackSurfaceReductionRules_Actions
	if (($ASRRules) -and ($ASRActions) -and (!$system)) {
		Write-output "############################ ASR rule check ###############################" | Out-File $connectivityCheckFile -Append
		# Check for existance of 'Block' mode ASR rule that can block PsExec from running
		$RuleIndex = $ASRRules::indexof($ASRRules, $ASRRuleBlockPsExec)
		if (($RuleIndex -ne -1) -and ($ASRActions[$RuleIndex] -eq 1)) {
			# Check if exclusions on script path are set
			$ASRRulesExclusions = (Get-MpPreference).AttackSurfaceReductionOnlyExclusions
			if (($ASRRulesExclusions) -and (($ASRRulesExclusions -contains $PSScriptRoot + '\') -or ($ASRRulesExclusions -contains $PSScriptRoot))) {
				"ASR rule 'Block process creations originating from PSExec and WMI commands' exists in block mode, but script path is excluded as needed" | Out-File $connectivityCheckFile -Append
				Write-Host -BackgroundColor Green -ForegroundColor black "Script path is excluded from ASR rules so URL checks can run as expected."
			} 
			else {
				"ASR rule 'Block process creations originating from PSExec and WMI commands' exists on the device and is in Block mode" | Out-File $connectivityCheckFile -Append
				Write-Host -BackgroundColor Red -ForegroundColor Yellow "Please note that ASR rule 'Block process creations originating from PSExec and WMI commands' is enabled and can block this tool from performing network validation if no exclusion is set" 			
			}
		}
	}
}

#This function expects to receive the EventProvider, EventId and Error string and returns the error event if found
function Get-MatchingEvent($EventProvider, $EventID, $ErrorString) {
	$EventResult = Get-WinEvent -ProviderName $EventProvider -MaxEvents 1000 -ErrorAction SilentlyContinue `
	| Where-Object -Property Id -eq $EventID `
	| Where-Object { $_.Properties.Value -like "*$ErrorString*" } `
	| Sort-Object -Property TimeCreated -Unique `
	| Select-Object -L 1
	
	return $EventResult
}

function CheckProxySettings() {		
	$RegPathHKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
	$RegPathHKU = "HKU:\S-1-5-18\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
	$RegPathHKCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
	$RegPathDefault = "HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"

	if (Get-RegistryValue -Path $RegPathHKLM -Value "ProxyServer") {
		"Proxy settings in device level were detected" | Out-File $connectivityCheckFile -append
		"The detected Proxy settings in device path (HKLM) are :  " + (Get-RegistryValue -Path $RegPathHKLM -Value "ProxyServer" ) | Out-File $connectivityCheckFile -append
		"ProxyEnable is set to :  " + (Get-RegistryValue -Path $RegPathHKLM -Value "ProxyEnable" ) | Out-File $connectivityCheckFile -append
	} 
	
	if (Get-RegistryValue -Path $RegPathHKU -Value "ProxyServer") {
		"Proxy settings in SYSTEM SID level were detected" | Out-File $connectivityCheckFile -append
		"The detected proxy settings in SYSTEM HKU path (S-1-5-18) are :  " + (Get-RegistryValue -Path $RegPathHKU -Value "ProxyServer" ) | Out-File $connectivityCheckFile -append
		"ProxyEnable is set to :  " + (Get-RegistryValue -Path $RegPathHKU -Value "ProxyEnable" ) | Out-File $connectivityCheckFile -append
	} 

	if (Get-RegistryValue -Path $RegPathHKCU -Value "ProxyServer") {
		"Proxy setting in current user level were detected" | Out-File $connectivityCheckFile -append
		"The detected proxy settings in current user path (HKCU) are :  " + (Get-RegistryValue -Path $RegPathHKCU -Value "ProxyServer" ) | Out-File $connectivityCheckFile -append
		"ProxyEnable is set to :  " + (Get-RegistryValue -Path $RegPathHKCU -Value "ProxyEnable" ) | Out-File $connectivityCheckFile -append
	}
	if (Get-RegistryValue -Path $RegPathDefault -Value "ProxyServer") {
		"Proxy setting in DEFAULT user level were detected" | Out-File $connectivityCheckFile -append
		"The detected proxy settings in the default user path (.DEFAULT) are :  " + (Get-RegistryValue -Path $RegPathDefault -Value "ProxyServer" ) | Out-File $connectivityCheckFile -append
		"ProxyEnable is set to :  " + (Get-RegistryValue -Path $RegPathDefault -Value "ProxyEnable" ) | Out-File $connectivityCheckFile -append
	}
	Test-CommandVerified "bitsadmin.exe"
	"Proxy setting detected via bitsadmin: " + (&bitsadmin.exe /Util /GETIEPROXY LOCALSYSTEM) | Out-File $connectivityCheckFile -append

	# Check additional proxy variables for devices running Unified Agent based on CURL
	if ($MDfWS) {
		if ($env:HTTPS_PROXY) {
			"Proxy settings discovered in HTTPS_PROXY variable" | Out-File $connectivityCheckFile -append
			"The detected proxy settings point to :  " + $env:HTTPS_PROXY | Out-File $connectivityCheckFile -append
			Write-Report -section "devInfo" -subsection "CurlProxy" -displayname "Curl HTTPS proxy" -value $env:HTTPS_PROXY
		}
		if ($env:HTTP_PROXY) {
			"Proxy settings discovered in HTTP_PROXY variable" | Out-File $connectivityCheckFile -append
			"The detected proxy settings point to :  " + $env:HTTP_PROXY | Out-File $connectivityCheckFile -append
			Write-Report -section "devInfo" -subsection "CurlProxy" -displayname "Curl HTTP proxy" -value $env:HTTP_PROXY
		} 	
		if ($env:NO_PROXY) {
			"Proxy settings discovered in NO_PROXY variable" | Out-File $connectivityCheckFile -append
			"The detected proxy settings point to :  " + $env:HTTPS_PROXY | Out-File $connectivityCheckFile -append
			Write-Report -section "devInfo" -subsection "CurlProxy" -displayname "Curl NO proxy override" -value $env:NO_PROXY
		} 
		if ($env:ALL_PROXY) {
			"Proxy settings discovered in NO_PROXY variable" | Out-File $connectivityCheckFile -append
			"The detected proxy settings point to :  " + $env:ALL_PROXY | Out-File $connectivityCheckFile -append
			Write-Report -section "devInfo" -subsection "CurlProxy" -displayname "Curl ALL proxy" -value $env:ALL_PROXY
		} 
	}
}
function GetAddRemovePrograms($regpath) {
	$programsArray = $regpath | ForEach-Object { New-Object PSObject -Property @{
			DisplayName     = $_.GetValue("DisplayName")
			DisplayVersion  = $_.GetValue("DisplayVersion")
			InstallLocation = $_.GetValue("InstallLocation")
			Publisher       = $_.GetValue("Publisher")
		} }
	$ProgramsArray | Where-Object { $_.DisplayName }
}

function FormatTimestamp($TimeStamp) {
	if ($TimeStamp) {
		return ([DateTime]::FromFiletime([Int64]::Parse($TimeStamp))).ToString("U")
	} 
	else {
		return "Unknown"
	}
}

function Get-ConnectionStatus {
	"Last SevilleDiagTrack LastNormalUploadTime TimeStamp: " + (FormatTimestamp($LastCYBERConnected)) | Out-File $connectivityCheckFile -append
	"Last SevilleDiagTrack LastRealTimeUploadTime TimeStamp: " + (FormatTimestamp($LastCYBERRTConnected)) | Out-File $connectivityCheckFile -append
	"Last SevilleDiagTrack LastInvalidHttpCode: " + $LastInvalidHTTPcode | Out-File $connectivityCheckFile -append
}

function IsAzureVm(){
	# BIOS Asset Tag check - Azure and Azure Stack VM has predefined Asset Tag for the private use.
	$SystemEnclosureObject = Get-WmiObject -class Win32_SystemEnclosure -namespace "root\CIMV2"
	$IsAzureAssetTag = ($SystemEnclosureObject.SMBIOSAssetTag -eq "7783-7084-3265-9085-8269-3286-77") -OR ($SystemEnclosureObject.SMBIOSAssetTag -eq "7783-7084-3265-9085-8269-3283-84")

	$vmIdRegResult =  (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Azure" -Value "VmId")

	return ($IsAzureAssetTag -AND $vmIdRegResult)
}

function Get-DeviceInfo {
	Write-Report -section "devInfo" -subsection "deviceName" -displayname "Device name" -value $env:computername 
	Write-Report -section "devInfo" -subsection "OSName" -displayname "Device Operating System" -value $OSProductName 
	Write-Report -section "devInfo" -subsection "OSBuild" -displayname "OS build number" -value (([System.Environment]::OSVersion.VersionString) + "." + $MinorBuild)
	Write-Report -section "devInfo" -subsection "Edition" -displayname "OS Edition" -value $OSEditionName
	Write-Report -section "devInfo" -subsection "Architecture" -displayname "OS Architecture" -value $arch
	Write-Report -section "devInfo" -subsection "SystemBootTime" -displayname "SystemBootTime" -value $LastSystemBootTime
}

function Get-RegValue {
	[string]$SQMMachineId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SQMClient" -Value "MachineId")
	[string]$SenseId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\Windows Advanced Threat Protection" -Value "SenseId")
	[string]$DeviceTag = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging" -Value "Group")
	[string]$GroupIds = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Value "GroupIds") 
	[string]$PreferStaticProxyForHttpRequest = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Value PreferStaticProxyForHttpRequest)

	if ($SQMMachineId) {
		"SQM Machine Identifier from registry is:  " + $SQMMachineId | Out-File $connectivityCheckFile -append
	} else {
		"SQM Machine Identifier was not found in 'HKLM\SOFTWARE\Microsoft\SQMClient' key" | Out-File $connectivityCheckFile -append
	}

	if ($OSPreviousVersion) {
		$sensepr = Get-ChildItem -Path "C:\Program Files\Microsoft Monitoring Agent\Agent\Health Service State\Monitoring Host Temporary File*" -Filter mssenses.exe -Recurse -ErrorAction SilentlyContinue | Sort-Object -Property TimeCreated -Unique
	}
	elseif ($MDfWS) {
		$InstallPath = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value "InstallLocation")
		$sensepr = Join-Path $InstallPath "MsSense.exe"
	} else {
		$sensepr = (Get-item -Path "C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe" -ErrorAction SilentlyContinue)
	}

	Get-DeviceInfo
	if (!$SenseId) {
		# Option to get SenseID from event log as some older OS versions only post Sense Id to log
		$SenseId = (Get-WinEvent -ProviderName Microsoft-Windows-SENSE -ErrorAction SilentlyContinue | Where-Object -Property Id -eq 13 | Sort-Object -Property TimeCreated | Select-Object -L 1).Message			
	}
	if ($SenseId) {
		Write-Report -section "EDRCompInfo" -subsection "DeviceId" -displayname "Device ID" -value $SenseId 		

		$OrgId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\Status" -Value "OrgID")
		Write-Report -section "EDRCompInfo" -subsection "OrgId" -displayname "Organization Id" -value $OrgId

		if ($sensepr) {
			[version]$Global:SenseVer = ([string](([System.IO.FileInfo]$sensepr).VersionInfo).ProductMajorPart + '.' + [string](([System.IO.FileInfo]$sensepr).VersionInfo).ProductMinorPart + '.' + [string](([System.IO.FileInfo]$sensepr).VersionInfo).ProductBuildPart + '.' + [string](([System.IO.FileInfo]$sensepr).VersionInfo).FilePrivatePart)
			Write-Report -section "EDRCompInfo" -subsection "SenseVersion" -displayname "Sense version" -value $Global:SenseVer 
		}
		$SenseConfigVer = (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\Status" -Value "ConfigurationVersion" ) 
		if ($SenseConfigVer -like "*-*") {
			$SenseConfigVer = $SenseConfigVer.split('-')[0] 
		}
		Write-Report -section "EDRCompInfo" -subsection "SenseConfigVersion" -displayname "Sense Configuration version" -value $SenseConfigVer 

		"Sense GUID is: " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection" -Value "senseGuid") | Out-File $connectivityCheckFile -append
		"AadAccountCache is: " + (Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status\AadAccountCache" -Recurse  -ErrorAction SilentlyContinue | Out-String) | Out-File $connectivityCheckFile -append
		if ($DeviceTag -ne $False) {
			"Optional Sense DeviceTag is: " + $DeviceTag | Out-File $connectivityCheckFile -append
		}		
		if ($GroupIds) {
			Write-Report -section "EDRCompInfo" -subsection "SenseGroupIds" -displayname "Sense GroupIds" -value $GroupIds 
		}
		if ($PreferStaticProxyForHttpRequest) {
			"Optional PreferStaticProxyForHttpRequest setting is: " + $PreferStaticProxyForHttpRequest | Out-File $connectivityCheckFile -append
		}
		if (($LastCnCConnected) -and (!$ASM)) {
			"Last Sense Seen TimeStamp is: " + (FormatTimestamp($LastCnCConnected)) | Out-File $connectivityCheckFile -append
		}
	}
	if (!$IsOnboarded) {
		"Device is: not onboarded" | Out-File $connectivityCheckFile -append
	}
}

Function Get-MSInfo ([boolean]$NFO = $true, [boolean]$TXT = $true, [string]$OutputLocation = $PWD.Path, [string]$Suffix = '') {
	$Process = "msinfo32.exe"
	
	if (test-path (join-path ([Environment]::GetFolderPath("System")) $Process)) {
		$ProcessPath = (join-path ([Environment]::GetFolderPath("System")) $Process)
	}
 elseif (test-path (join-path ([Environment]::GetFolderPath("CommonProgramFiles")) "Microsoft Shared\MSInfo\$Process")) {
		$ProcessPath = (join-path ([Environment]::GetFolderPath("CommonProgramFiles")) "Microsoft Shared\MSInfo\$Process")
	}
 else {
		Test-CommandVerified "cmd.exe"
		$ProcessPath = "cmd.exe /c start /wait $Process"
	}
	if ($TXT) {
		$InfoFile = Join-Path -Path $OutputLocation -ChildPath ("msinfo32" + $Suffix + ".txt")
		Test-AuthenticodeSignature $ProcessPath
		&$ProcessPath /report "$InfoFile"
	}
	if ($NFO) {
		$InfoFile = Join-Path -Path $OutputLocation -ChildPath ("msinfo32" + $Suffix + ".nfo")
		Test-AuthenticodeSignature $ProcessPath
		&$ProcessPath /nfo "$InfoFile"
	}
}

function EndTimedoutProcess ($process, $ProcessWaitMin) {
	$proc = Get-Process $process -EA SilentlyContinue
	if ($proc) {
		Write-Host "Waiting max $ProcessWaitMin minutes on $process processes to complete "
		Wait-Process -InputObject $proc -Timeout ($ProcessWaitMin * 60) -EA SilentlyContinue
		$ProcessToEnd = Get-Process | Where-Object { $_.Name -eq "$process" } -EA SilentlyContinue
		if ($ProcessToEnd -ne $null) {
			Write-Host "timeout reached ..."
			foreach ($prc in $ProcessToEnd) { Stop-Process $prc -Force -EA SilentlyContinue }
		}
	}
}

function Initialize-XSLT {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$XmlPath, 
		[Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$XslPath,
		[Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$HtmlOutput )

	Try {
		If ((Test-path($XmlPath)) -and (Test-path($XslPath))) {
			$myXslCompiledTransfrom = new-object System.Xml.Xsl.XslCompiledTransform
			$xsltArgList = New-Object System.Xml.Xsl.XsltArgumentList

			$myXslCompiledTransfrom.Load($XslPath)
			$xmlWriter = [System.Xml.XmlWriter]::Create($HtmlOutput)
		
			$myXslCompiledTransfrom.Transform($XmlPath, $xsltArgList, $xmlWriter)
	
			$xmlWriter.Flush()
			$xmlWriter.Close()

			return $True
		} 
	}
 Catch {
		return $False
	}
}

function GenerateHealthCheckReport() {
	# Save XML log file
	$script:xmlDoc.Save($XmlLogFile)

	CheckHashFile "$XslFile" "7F801B73C2E0D1A43EF9915328881A85D1EE7ADDBC31273CCD72D1C81CB2B258"
	# Transform XML to HTML based using XSLT
	$Result = Initialize-XSLT -XmlPath $XmlLogFile -XslPath $XslFile -HtmlOutput $HtmOutputfile
	If (!$Result) {
		"Unable to generate HTML file" | Out-File $connectivityCheckFile -append
	}
}

function WriteReport($id, $CheckresultInsertions, $GuidanceRInsertions) {
	$CurrEvent = $ResourcesOfEvents.$id.PSObject.Copy()
	$i = 1
	$CurrEvent, $i = UpdateInsertion $CurrEvent $CheckresultInsertions $i "checkresult"
	$CurrEvent, $i = UpdateInsertion $CurrEvent $GuidanceRInsertions $i "guidance"
	$CurrEvent.checkresult = [regex]::replace($CurrEvent.checkresult, '\n', '<br>')
	$CurrEvent.guidance = [regex]::replace($CurrEvent.guidance, '\n', '<br>')
	Write-ReportEvent -section "events" -severity $CurrEvent.severity -category $CurrEvent.category -check $CurrEvent.check -id $id -checkresult $CurrEvent.checkresult -guidance $CurrEvent.guidance
}

function UpdateInsertion($CurrEvent, $Insertions, $i, $id) {
	If ($Insertions.Count -gt 0) {
		Foreach ($insert in $Insertions) {
			$ind = '%' + "$i"
			$CurrEvent.$id = [regex]::replace($CurrEvent.$id, $ind, $insert)
			$i += 1
		}	
	}
	return $CurrEvent, $i
}

function CheckExpirationCertUtil($IsDisabled, $TestName, $RootToCheck) {
	Test-CommandVerified "certutil.exe"
	$CertResults = &certutil -verifyctl $TestName $RootToCheck | findstr /i SignerExpiration
	"`n`nCommand:`n`tcertutil -verifyctl $TestName | findstr /i SignerExpiration `nResults:`n`t" + $CertResults | Out-File $CertSignerResults -append

	#Get the number of days from $CertResults: 'SignerExpiration = "12/2/2021 11:25 PM", "273.5 Days"'
	$ExpirationTime = $CertResults.split('"')[3].split(" ")[0]
	#Case there is ',' instead '.'
	$ExpirationTime = [double]($ExpirationTime.replace(',', '.'))
	If ($ExpirationTime -le 0) {
		#$days = [string]($ExpirationTime * (-1))
		If ($IsDisabled) {
			#WriteReport 121013 @(@($days, $CertSignerResults)) @()
		}
		else {
			#WriteReport 121014 @(@($days, $CertSignerResults)) @()
		}
	}
}

function Test-AuthenticodeSignature($pathToCheck) {
	if (test-path $resultOutputDir -ErrorAction SilentlyContinue) {
		$issuerInfo = "$resultOutputDir\issuerInfo.txt"
	} else {
		$issuerInfo = "$outputDir\issuerInfo.txt"
	}
	if ($pathToCheck) {
		if (Test-Path -path $pathToCheck -ErrorAction SilentlyContinue) {
			$AuthenticodeSig = (Get-AuthenticodeSignature -FilePath $pathToCheck)
			$cert = $AuthenticodeSig.SignerCertificate
			$FileInfo = (get-command $pathToCheck).FileVersionInfo			
			$issuer = $cert.Issuer
			#OS is older than 2016 and some built-in processes will not be signed
			if (($OSBuild -lt 14393) -and (!$AuthenticodeSig.SignerCertificate)) {
				if (($FileInfo.CompanyName -eq "Microsoft Corporation")) {
					return
				}
				else {
					Write-Error "Script execution terminated because a process or script that does not have any signature was detected" | Out-File $issuerInfo -append
					$pathToCheck | Out-File $issuerInfo -append
					$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
					$cert | Format-List * | Out-File $issuerInfo -append
					[Environment]::Exit(1)
				}
			}
			#check if valid
			if ($AuthenticodeSig.Status -ne "Valid") {
				Write-Error "Script execution terminated because a process or script that does not have a valid Signature was detected" | Out-File $issuerInfo -append
				$pathToCheck | Out-File $issuerInfo -append
				$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
				$cert | Format-List * | Out-File $issuerInfo -append
				[Environment]::Exit(1)
			}
			#check issuer
			if (($issuer -ne "CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Code Signing PCA, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Code Signing PCA 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Development PCA 2014, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")) {
				Write-Error "Script execution terminated because a process or script that is not Microsoft signed was detected" | Out-File $issuerInfo -append
				$pathToCheck | Out-File $issuerInfo -append
				$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
				$cert | Format-List * | Out-File $issuerInfo -append
				[Environment]::Exit(1)
			}	
			if ($AuthenticodeSig.IsOSBinary -ne "True") {
				#If revocation is offline then test below will fail
				if (!$LegacyOS) {
					$IsOnline = (Get-NetConnectionProfile).IPv4Connectivity -like "*Internet*"
				}
				$EKUArray = @('1.3.6.1.5.5.7.3.3', '1.3.6.1.4.1.311.76.47.1')
				if ($IsOnline) {
					$IsWindowsSystemComponent = (Test-Certificate -Cert $cert -EKU "1.3.6.1.4.1.311.10.3.6" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable OsCertWarnVar -ErrorVariable OsCertErrVar)
					$IsMicrosoftPublisher = (Test-Certificate -Cert $cert -EKU "1.3.6.1.4.1.311.76.8.1" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable MsPublisherWarnVar -ErrorVariable MsPublisherErrVar)
					$TrustedEKU = (Test-Certificate -Cert $cert -EKU $EKUArray -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable EKUWarnVar -ErrorVariable EKUErrVar)
					if (($IsWindowsSystemComponent -eq $False) -and ($IsMicrosoftPublisher -eq $False) -and ($TrustedEKU -eq $False)) {
						#Defender AV and some OS processes will have an old signature if older version is installed
						#Ignore if cert is OK and only signature is old
						if (($OsCertWarnVar -like "*CERT_TRUST_IS_NOT_TIME_VALID*") -or ($MsPublisherWarnVar -like "*CERT_TRUST_IS_NOT_TIME_VALID*") -or ($OsCertWarnVar -like "*CERT_TRUST_IS_OFFLINE_REVOCATION*") -or ($MsPublisherWarnVar -like "CERT_TRUST_IS_OFFLINE_REVOCATION")) {
							return
						}
						Write-Error "Script execution terminated because the process or script certificate failed trust check" | Out-File $issuerInfo -append
						$pathToCheck | Out-File $issuerInfo -append
						$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
						$cert | Format-List * | Out-File $issuerInfo -append
						[Environment]::Exit(1)
					}
				}
			}
		}
	 else {
			Write-Error ("Path " + $pathToCheck + " was not found") | Out-File $issuerInfo -append
		}
	}
}

function CheckHashFile($filePath, $hash) {
if (test-path $filePath) {
		$fileHash = Get-FileHash -Path $filePath
		if ($fileHash.Hash -ne $hash) {
			Write-Error "Script execution terminated because hash did not match expected value. Expected value: $hash"
			[Environment]::Exit(1)
		}
	}
}

function NTFSSecurityAccess($resultOutputDir) {
	Test-CommandVerified "takeown.exe"
	#take ownership
	Start-Process -wait -WindowStyle minimized Takeown.exe -ArgumentList "/f `"$resultOutputDir`" /r /d y"
	Test-CommandVerified "icacls.exe"
	#Prevent inheritance
	Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /inheritance:r"
	Test-CommandVerified "icacls.exe"
	#Allow Access to Administrators
	Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /grant `"Administrators`":(OI)(CI)F /t /q"
	Test-CommandVerified "icacls.exe"
	#Allow Access to Creator owner 
	Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /grant `"Creator Owner`":(OI)(CI)F /t /q"
	Test-CommandVerified "icacls.exe"
	#Allow Access to SYSTEM
	Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /grant `"NT AUTHORITY\SYSTEM`":(OI)(CI)F /t /q"
	Test-CommandVerified "icacls.exe"
	if (!$System) {
		#Allow curent user access
		Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /grant `"$context`":(OI)(CI)F /t /q"
	}
	
}

#gets path of command and check signature
function Test-CommandVerified($checkCommand) {
	$command = Get-Command $CheckCommand -ErrorAction SilentlyContinue
	Test-AuthenticodeSignature $command.path
}

function get-MdeConfigMgrLog() {
	# folder for SIMA logs and info
	New-Item -ItemType Directory -Path "$resultOutputDir\MdeConfigMgrLogs" -ErrorAction SilentlyContinue | out-Null
	$MdeConfigMgrRegInfo = "$resultOutputDir\MdeConfigMgrLogs\MdeConfigMgrRegInfo.txt"
	# reg info collections
	"please find reg info for MdeConfigMgr flow On : " + $ScriptRunTime + "`n" | Out-File $MdeConfigMgrRegInfo
	"EnrollmentStatus : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value EnrollmentStatus) | Out-File $MdeConfigMgrRegInfo -Append
	"TenantId : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value TenantId) | Out-File $MdeConfigMgrRegInfo -Append
	"DeviceId : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value DeviceId) | Out-File $MdeConfigMgrRegInfo -Append
	"EnrollmentPayload : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value EnrollmentPayload) | Out-File $MdeConfigMgrRegInfo -Append
	"MemConfiguration : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value MemConfiguration) | Out-File $MdeConfigMgrRegInfo -Append
	"LastCheckinAttempt : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value LastCheckinAttempt) | Out-File $MdeConfigMgrRegInfo -Append
	"LastCheckinSuccess : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value LastCheckinAttempt) | Out-File $MdeConfigMgrRegInfo -Append
	"SystemManufacturer : " + (Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation\" -Value SystemManufacturer) | Out-File $MdeConfigMgrRegInfo -Append
	"SystemProductName : " + (Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation\" -Value SystemProductName) | Out-File $MdeConfigMgrRegInfo -Append
	"ProductName : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Value ProductName) | Out-File $MdeConfigMgrRegInfo -Append
	"UBR : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Value UBR) | Out-File $MdeConfigMgrRegInfo -Append
	"OnboardedInfo : " | Out-File $MdeConfigMgrRegInfo -Append
	(Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value OnboardedInfo) |  ConvertFrom-Json | Select-Object body | Out-File $MdeConfigMgrRegInfo -Append
	"SenseCmConfiguration : " | Out-File $MdeConfigMgrRegInfo -Append
	(Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value SenseCmConfiguration) |  ConvertFrom-Json | Out-File $MdeConfigMgrRegInfo -Append
	"NextVersion : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value NextVersion) | Out-File $MdeConfigMgrRegInfo -Append
	"InvalidVersion : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value InvalidVersion) | Out-File $MdeConfigMgrRegInfo -Append
	"SwitchStatus : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value SwitchStatus) | Out-File $MdeConfigMgrRegInfo -Append
	"InstallLocation : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value InstallLocation) | Out-File $MdeConfigMgrRegInfo -Append
	"NewPlatform : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\" -Value NewPlatform) | Out-File $MdeConfigMgrRegInfo -Append
	"MsSensePath : " + (Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\sense" -Value ImagePath) | Out-File $MdeConfigMgrRegInfo -Append
	"MsSecFltPath : " + (Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MsSecFlt" -Value ImagePath) | Out-File $MdeConfigMgrRegInfo -Append

	# collect event logs
	if (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-AADRT%4Admin.evtx') {
		Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-AADRT%4Admin.evtx -Destination $resultOutputDir\EventLogs\AADRT-Admin.evtx
	}

	if (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-AAD%4Operational.evtx') {
		Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-AAD%4Operational.evtx -Destination $resultOutputDir\EventLogs\AAD-Operational.evtx
	}

	# collect additional files
	if (test-path -Path $env:SystemRoot\Temp\MpSigStub.log) {
		Copy-Item -path $env:SystemRoot\Temp\MpSigStub.log -Destination $resultOutputDir\EventLogs\MpSigStub.log
	}

	#collect sense CM data folder
	if (($eulaAccepted -eq "Yes") -and (!$system)) {
		$PSExecCommand = Join-Path $ToolsDir "PsExec.exe"
		if (test-Path -path $PSExecCommand) {
			Test-AuthenticodeSignature $PSExecCommand
		}
		Test-CommandVerified "Robocopy.exe"
		Start-Process -PassThru -wait -WindowStyle minimized $PSExecCommand -ArgumentList "-accepteula -nobanner -s robocopy.exe `"$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\SenseCM`" `"$resultOutputDir\MdeConfigMgrLogs`" /E /ZB /w:1 /r:1  /log:`"$resultOutputDir\MdeConfigMgrLogs\copy.log`"" | Out-Null
	}
 elseif ($system) {
		Test-CommandVerified "Robocopy.exe"
		Start-Process -PassThru -wait -WindowStyle minimized Robocopy.exe -ArgumentList "`"$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\SenseCM`" `"$resultOutputDir\MdeConfigMgrLogs`" /E /ZB /w:1 /r:1  /log:`"$resultOutputDir\MdeConfigMgrLogs\copy.log`""  | Out-Null
	}
}

# Return the information about Sense Configuration Manager a PSObject.
Function Get-SenseCMInfo () {
	$SenseCMInfoObj = New-Object -TypeName PSObject

	$SenseCMRegPath = "HKLM:\SOFTWARE\Microsoft\SenseCM\"
	
	# Check the device's enrollment status
	$EnrollmentStatusId = (Get-RegistryValue -Path $SenseCMRegPath -Value "EnrollmentStatus" -ErrorAction SilentlyContinue)
	if ($EnrollmentStatusId) {
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "EnrollmentStatusId" -Value $EnrollmentStatusId -ErrorAction SilentlyContinue
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "EnrollmentStatusReportId" -Value "" -ErrorAction SilentlyContinue
		switch ($EnrollmentStatusId) {
			1 {$EnrollmentStatusText = "Device is enrolled to AAD and MEM"}
			2 {$EnrollmentStatusText = "Device is not enrolled and has never been enrolled"}
			{(($_ -eq 3) -or ($_ -eq 21))} {$EnrollmentStatusText = "Device is managed by MDM Agent"}
			{(($_ -eq 4) -or ($_ -eq 22))} {$EnrollmentStatusText = "Device is managed by SCCM Agent"}

			{(($_ -ge 5) -and ($_ -le 7)) -or ($_ -eq 9) -or (($_ -ge 11) -and ($_ -le 12))} {$EnrollmentStatusText = "General error";$SenseCMInfoObj.EnrollmentStatusReportId = "122022"}
			{(($_ -eq 8) -or ($_ -eq 44))} {$EnrollmentStatusText = "Microsoft Endpoint Manager Configuration issue"; $SenseCMInfoObj.EnrollmentStatusReportId = "122023"}  
			{(($_ -ge 13) -and ($_ -le 14)) -or ($_ -eq 24) -or ($_ -eq 25)} {$EnrollmentStatusText = "Connectivity issue";$SenseCMInfoObj.EnrollmentStatusReportId = "122024"}
			{(($_ -eq 19) -or ($_ -eq 20))} {$EnrollmentStatusText = "Microsoft Endpoint Manager Configuration issue"; $SenseCMInfoObj.EnrollmentStatusReportId = "122032"}  
			
			23 {$EnrollmentStatusText = "Device was enrolled and is now unenrolled"; $SenseCMInfoObj.EnrollmentStatusReportId = "120032"}  
			32 {$EnrollmentStatusText = "Device is pending unenrollment"; $SenseCMInfoObj.EnrollmentStatusReportId = "122033"}  
			34 {$EnrollmentStatusText = "Polices assignment failure"; $SenseCMInfoObj.EnrollmentStatusReportId = "122034"}  
			35 {$EnrollmentStatusText = "Polices report failure"; $SenseCMInfoObj.EnrollmentStatusReportId = "122035"}  
		
			{(($_ -eq 10) -or ($_ -eq 42))} {$EnrollmentStatusText = "General Hybrid join failure"; $SenseCMInfoObj.EnrollmentStatusReportId = "122025"}  
			15 {$EnrollmentStatusText = "Tenant mismatch"; $SenseCMInfoObj.EnrollmentStatusReportId = "122026"}
			{(($_ -eq 16) -or ($_ -eq 17))} {$EnrollmentStatusText = "Hybrid error - Service Connection Point"; $SenseCMInfoObj.EnrollmentStatusReportId = "122027"}  
			18 {$EnrollmentStatusText = "Certificate error"; $SenseCMInfoObj.EnrollmentStatusReportId = "122028"}
			{(($_ -eq 36) -or ($_ -eq 37))} {$EnrollmentStatusText = "AAD Connect misconfiguration"; $SenseCMInfoObj.EnrollmentStatusReportId = "122029"}  
			{(($_ -eq 38) -or ($_ -eq 41))} {$EnrollmentStatusText = "DNS error"; $SenseCMInfoObj.EnrollmentStatusReportId = "122030"}  
			40 {$EnrollmentStatusText = "Clock sync issue"; $SenseCMInfoObj.EnrollmentStatusReportId = "122031"}
			43 {$EnrollmentStatusText = "MDE and ConfigMgr"; $SenseCMInfoObj.EnrollmentStatusReportId = "120031"}
			default {
				$EnrollmentStatusText = "Unknown State"
			}
		}

		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "EnrollmentStatusText" -Value ($EnrollmentStatusText+" ("+$EnrollmentStatusId+")") -ErrorAction SilentlyContinue
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "SwitchMode" -Value ((Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value SenseCmConfiguration -ErrorAction SilentlyContinue) |  ConvertFrom-Json).SenseCmModeSwitch

		$AADDeviceId =  (Get-RegistryValue -Path $SenseCMRegPath -Value DeviceId -ErrorAction SilentlyContinue)
		if ($AADDeviceId) {$AADDeviceId = $AADDeviceId.Tolower()}
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "AADDeviceId" -Value $AADDeviceId -ErrorAction SilentlyContinue

		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "TenantId" -Value (Get-RegistryValue -Path $SenseCMRegPath -Value TenantId) -ErrorAction SilentlyContinue
		
		$IntuneDeviceID = ((Get-RegistryValue -Path $SenseCMRegPath -Value EnrollmentPayload -ErrorAction SilentlyContinue) |  ConvertFrom-Json -ErrorAction SilentlyContinue).intuneDeviceId
		if ($IntuneDeviceID) {$IntuneDeviceID = $IntuneDeviceID.Tolower()}
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "IntuneDeviceID" -Value $IntuneDeviceID -ErrorAction SilentlyContinue
	}

	return $SenseCMInfoObj
}


# Return the output of dsregcmd /status as a PSObject.
Function Get-DsRegStatus () {
	if (test-path -path $env:windir\system32\dsregcmd.exe) {
		Test-CommandVerified "dsregcmd.exe"
		$dsregcmd = &dsregcmd /status
		
		# Dump dsregcmd info to results
		$dsregcmd  | Out-File "$resultOutputDir\SystemInfoLogs\dsregcmd.txt"
	
		 $o = New-Object -TypeName PSObject
		 foreach($line in $dsregcmd) {
			  if ($line -like "| *") {
				   if (-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $so) {
						Add-Member -InputObject $o -MemberType NoteProperty -Name $currentSection -Value $so -ErrorAction SilentlyContinue
				   }
				   $currentSection = $line.Replace("|","").Replace(" ","").Trim()
				   $so = New-Object -TypeName PSObject
			  } elseif ($line -match " *[A-z]+ : [A-z0-9\{\}]+ *") {
				   Add-Member -InputObject $so -MemberType NoteProperty -Name (([String]$line).Trim() -split " : ")[0] -Value (([String]$line).Trim() -split " : ")[1] -ErrorAction SilentlyContinue
			  }
		 }
		 if (-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $so) {
			  Add-Member -InputObject $o -MemberType NoteProperty -Name $currentSection -Value $so -ErrorAction SilentlyContinue
		 }
		return $o
	}
}

# Get Windows 10 MDM Enrollment Status.
function Get-MDMEnrollmentStatus {
	#Locate correct Enrollment Key
	$EnrollmentKey = Get-Item -Path HKLM:\SOFTWARE\Microsoft\Enrollments\* | Get-ItemProperty | Where-Object -FilterScript {$null -ne $_.UPN}
	
	if ($EnrollmentKey) {
		# Translate the MDM Enrollment Type in a readable string.
		Switch ($EnrollmentKey.EnrollmentType) {
		0 {$EnrollmentTypeText = "Enrollment was not started"}
		6 {$EnrollmentTypeText = "MDM enrolled"}
		13 {$EnrollmentTypeText = "Azure AD joined"}
		}
		Add-Member -InputObject $EnrollmentKey -MemberType NoteProperty -Name EnrollmentTypeText -Value $EnrollmentTypeText
	} else {
		# Write-Error "Device is not enrolled to MDM."
		$EnrollmentKey = New-Object -TypeName PSObject
		Add-Member -InputObject $EnrollmentKey -MemberType NoteProperty -Name EnrollmentTypeText -Value "Not enrolled"
	}

	# Return 'Not enrolled' if Device is not enrolled to an MDM.
	return $EnrollmentKey
}

# TODO: Report the connectivity failure
function CheckDCConnecvitiy {
	$ErrorActionPreference = "SilentlyContinue"

    $DCName = ""
	Test-CommandVerified "nltest.exe"
    $DCTest = nltest /dsgetdc:
    $DCName = $DCTest | Select-String DC | Select-Object -first 1
    $DCName = ($DCName.tostring() -split "DC: \\")[1].trim()

    if (($DCName.length) -eq 0) {
		return $False		
	} else {
		return $True		
	}
}

function Get-SCPConfiguration {
	$SCPConfiguration = New-Object -TypeName PSObject
	Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name ResultID -Value "" -ErrorAction SilentlyContinue

	$CDJReg = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD -ErrorAction SilentlyContinue
	if (((($CDJReg.TenantId).Length) -eq 0) -AND ((($CDJReg.TenantName).Length) -eq 0)) {
		# No client-side registry setting were found for SCP, checking against DC
		if (CheckDCConnecvitiy) {
			$Root = [ADSI]"LDAP://RootDSE"
			$ConfigurationName = $Root.rootDomainNamingContext
			if (($ConfigurationName.length) -eq 0) {
				$SCPConfiguration.ResultID = 121016
			} else {
				$scp = New-Object System.DirectoryServices.DirectoryEntry;
				$scp.Path = "LDAP://CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,CN=Configuration," + $ConfigurationName;
				if ($scp.Keywords -ne $null){
					Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name ConfigType -Value "Domain" -ErrorAction SilentlyContinue
					if ($scp.Keywords -like ("*enterpriseDrsName*")) {
						# Enterprise DRS was found
						$SCPConfiguration.ResultID = 121017
						$SCPConfiguration.TenantName = $scp.Keywords.ToString()
					} else {
						Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name TenantName -Value (($scp.Keywords[0].tostring() -split ":")[1].trim()) -ErrorAction SilentlyContinue
						Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name TenantId -Value (($scp.Keywords[1].tostring() -split ":")[1].trim()) -ErrorAction SilentlyContinue
					}
				} Else {
					$SCPConfiguration.ResultID = 121018
				}
			}
		} Else {
			$SCPConfiguration.ResultID = 121019
		}
	} else {
		# Client-side registry setting were found for SCP
		Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name ConfigType -Value "Client" -ErrorAction SilentlyContinue
		Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name TenantName -Value ($CDJReg.TenantName) -ErrorAction SilentlyContinue
		Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name TenantId -Value ($CDJReg.TenantId) -ErrorAction SilentlyContinue
	}

	return $SCPConfiguration
}
# TODO: Connectivity checks to DRS 


function ConnecttoAzureAD {
    Write-Host ''
    Write-Host "Checking if there is a valid Access Token..." -ForegroundColor Yellow
    Write-Log -Message "Checking if there is a valid Access Token..."
    $headers = @{ 
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $global:accesstoken"
                }
    $GraphLink = "https://graph.microsoft.com/v1.0/domains"
    $GraphResult=""
    $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json

    if ($GraphResult.value.Count)
    {
            $headers = @{ 
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $global:accesstoken"
            }
            $GraphLink = "https://graph.microsoft.com/v1.0/me"
            $GraphResult=""
            $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json
            $User_DisplayName=$GraphResult.displayName
            $User_UPN=$GraphResult.userPrincipalName
            Write-Host "There is a valid Access Token for user: $User_DisplayName, UPN: $User_UPN" -ForegroundColor Green
            $msg="There is a valid Access Token for user: $User_DisplayName, UPN: $User_UPN" 
            Write-Log -Message $msg

    } else {
        Write-Host "There no valid Access Token, please sign-in to get an Access Token" -ForegroundColor Yellow
        Write-Log -Message "There no valid Access Token, please sign-in to get an Access Token"
        $global:accesstoken = Connect-AzureDevicelogin
        ''
        if ($global:accesstoken.Length -ge 1){
            $headers = @{ 
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $global:accesstoken"
            }
            $GraphLink = "https://graph.microsoft.com/v1.0/me"
            $GraphResult=""
            $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json
            $User_DisplayName=$GraphResult.displayName
            $User_UPN=$GraphResult.userPrincipalName
            Write-Host "You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN" -ForegroundColor Green
            $msg="You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN" 
            Write-Log -Message $msg
        }
    }
}

function CheckAzureADDeviceHealth ($DeviceID) {
	ConnecttoAzureAD

	$DeviceHealth = New-Object -TypeName PSObject

    $headers = @{ 
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $global:accesstoken"
                }

    $GraphLink = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$DeviceID'"
    try {
        $GraphResult = Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json"
        $AADDevice = $GraphResult.Content | ConvertFrom-Json

        if ($AADDevice.value.Count -ge 1) {
			# Device was found    
			Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceExists -Value $True -ErrorAction SilentlyContinue
			Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceEnabled -Value $AADDevice.value.accountEnabled -ErrorAction SilentlyContinue

			# Check if device in Stale state
			$LastLogonTimestamp = $AADDevice.value.approximateLastSignInDateTime
			Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name LastLogonTimestamp -Value $LastLogonTimestamp -ErrorAction SilentlyContinue
	
			$CurrentDate = Get-Date 
			$Diff = New-TimeSpan -Start $LastLogonTimestamp -End $CurrentDate
			$diffDays = $Diff.Days
			if (($diffDays -ge 21) -or ($diffDays.length -eq 0)) {
				Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceStale -Value $True -ErrorAction SilentlyContinue
			} else {
				Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceStale -Value $False -ErrorAction SilentlyContinue
			}

			# Check if device in Pending State
			$Cert = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($AADDevice.value.alternativeSecurityIds.key))
            $AltSec = $Cert -replace $cert[1]

            if (-not ($AltSec.StartsWith("X509:"))) {
                $devicePending=$true
            } else {
                $devicePending=$false
            }
			Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DevicePending -Value $devicePending -ErrorAction SilentlyContinue
        } else {
            # Device was not found
            Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceExists -Value $False -ErrorAction SilentlyContinue
        }
	} catch {
        Write-Host ''
        Write-Host "Operation aborted. Unable to connect to Azure AD, please check you entered a correct credentials and you have the needed permissions" -ForegroundColor red
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Host ''
        Write-Host ''
        exit
    }

	return $DeviceHealth
}


function Wait-OnDemandStop {
	$LogName = "Application"
	$Log = [System.Diagnostics.EventLog]$LogName
	$Action = {
		$entry = $event.SourceEventArgs.Entry
		if ($entry.EventId -eq 2 -and $entry.Source -eq "MDEClientAnalyzer")
		{
			Write-Host "Stop event was triggered!" -ForegroundColor Green
			Unregister-Event -SourceIdentifier MDEClientAnalyzer
			Remove-Job -Name MDEClientAnalyzer
		}
	}
	Register-ObjectEvent -InputObject $log -EventName EntryWritten -SourceIdentifier "MDEClientAnalyzer" -Action $Action | Out-Null
	$timeout = New-TimeSpan -Minutes $MinutesToRun
	$sw = [diagnostics.stopwatch]::StartNew()
	try {
		do {
			Wait-Event -SourceIdentifier MDEClientAnalyzer -Timeout 1
			[int]$rem = $timeout.TotalSeconds - $sw.elapsed.TotalSeconds
			Write-Host "Remaining seconds: " ([math]::Round($rem))
		} while ((Get-Job -Name MDEClientAnalyzer -ErrorAction SilentlyContinue) -xor ([int]$rem -lt 1))
	} finally {
		 Unregister-Event -SourceIdentifier MDEClientAnalyzer -ErrorAction SilentlyContinue
		 Remove-Job -Name MDEClientAnalyzer -ErrorAction SilentlyContinue
	}
}

function Initialize-OnDemandStopEvent {
	Write-host "Another non-interactive trace is already running... stopping log collection and exiting."
	Write-EventLog -LogName "Application" -Source "MDEClientAnalyzer" -EventID 2 -EntryType Information -Message "MDEClientAnalyzer is stopping a running log set" -Category 1
	[Environment]::Exit(1)
}

function Initialize-OnDemandStartEvent {
	Write-EventLog -LogName "Application" -Source "MDEClientAnalyzer" -EventID 1 -EntryType Information -Message "MDEClientAnalyzer is starting OnDemand traces" -Category 1	
}

function Test-StreamlinedConnectivity {
	$hasMinimalAvSignatureVersion = [version]$AVSignatureVersion -ge [version]"1.391.345.0"
	$hasMinimalAvEngineVersion = [version]$AVEngineVersion -ge [version]"1.1.19900.2"
	$hasMinimalPlatformVersion = [version]$Platform -ge [version]"4.18.2211.5"
	$hasMinimalSenseVersion = [version]$Global:SenseVer -gt [version]"10.8041.0.0"

	if ($hasMinimalAvSignatureVersion -and $hasMinimalAvEngineVersion -and $hasMinimalPlatformVersion -and $hasMinimalSenseVersion) {
		Write-Report -section "devInfo" -subsection "SimplifiedConnectivity" -displayname "Streamlined Connectivity Readiness (Preview)" -value "READY" -alert 'None'
	}
	elseif (($OSPreviousVersion) -and (!$MDfWS)) {		
		Write-Report -section "devInfo" -subsection "SimplifiedConnectivity" -displayname "Streamlined Connectivity Readiness (Preview)" -value "Streamlined connectivity requires MDE Unified Agent"
		WriteReport 131018 @() @()
	}
	elseif ($OSBuild -lt 17763) {
		Write-Report -section "devInfo" -subsection "SimplifiedConnectivity" -displayname "Streamlined Connectivity Readiness (Preview)" -value "Streamlined connectivity is partially supported on this OS version."
		WriteReport 131019 @() @()
	}
	else {
		$missingComponents = @()
		if (-not $hasMinimalAvSignatureVersion) {
			$missingComponents += "Defender AV Security Intelligence"
		}
		if (-not $hasMinimalAvEngineVersion) {
			$missingComponents += "Defender AV Engine"
		}
		if (-not $hasMinimalPlatformVersion) {
			$missingComponents += "Defender AV Platform"
		}
		if (-not $hasMinimalSenseVersion) {
			$missingComponents += "EDR Sense"
		}

		$Msg = "This device is not ready for streamlined connectivity. Please update the following components: " + ($missingComponents -join ", ")
		Write-Report -section "devInfo" -subsection "SimplifiedConnectivity" -displayname "Streamlined Connectivity Readiness" -value $Msg
		WriteReport 131020 @(, @($missingComponents -join ", ")) @()
	}
}


#Main
Get-Module | ForEach-Object { Remove-Module -Name $_.Name -Force }
$PSModuleAutoloadingPreference = 'none'
Import-Module Microsoft.PowerShell.Utility
[int]$OSBuild = [system.environment]::OSVersion.Version.Build
if ($OSBuild -le "7601") {
	$LegacyOS = "True"
}
Test-AuthenticodeSignature $MyInvocation.MyCommand.Path
[bool]$system = ([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)
[string]$context = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
[string]$LoggedOnUsers = (Get-Process -Name "Explorer" -IncludeUserName -ErrorAction SilentlyContinue).UserName | Sort-Object UserName -Unique
if (!$system) {
	if ($LoggedOnUsers -contains $context) {
	# This means the user context running the script is also interactively logged on
	$InteractiveAdmin = $true
	}
}

$EULA = Join-Path $ToolsDir "EULA.ps1"
Test-AuthenticodeSignature $EULA
Import-module $EULA

if ($system -or $RemoteRun) {
	# Running in non-interactive mode. I.e. assume EULA accepted by admin who is initiating advanced data collection 
	$eulaAccepted = ShowEULAIfNeeded "MDEClientAnalyzer" 2
} else {
	$eulaAccepted = ShowEULAIfNeeded "MDEClientAnalyzer" 0
}

if ($eulaAccepted -ne "Yes") {
    write-error "MDEClientAnalyzer EULA Declined"
    [Environment]::Exit(1)
}
write-host "MDEClientAnalyzer EULA Accepted"

if ($PSMode -eq "ConstrainedLanguage") {
	Write-Warning "PowerShell is set with 'Constrained Language' mode hardening which can affect script execution and capabilities. To avoid issues while troubleshooting with the analyzer, please temporarly remove the ConstrainedLanguage mode in your policy."
	Write-Host "For more information, refer to: https://docs.microsoft.com/powershell/module/microsoft.powershell.core/about/about_language_modes"
	if (!($system -or $RemoteRun)) {
		Read-Host "Press ENTER to continue anyway..."
	}
}

New-EventLog –LogName Application –Source "MDEClientAnalyzer" -ErrorAction SilentlyContinue
[array]$RunningPS = Get-WmiObject Win32_Process | Where-Object {$_.name -eq 'powershell.exe'}
foreach ($PS in $RunningPS) {
	If ($PID -ne ($PS.ProcessId)) {
		$StringRunningPS = ([string]$PS.CommandLine).ToLower()
		if (($StringRunningPS).contains(" -r") -and (($StringRunningPS).contains("mdeclientanalyzer.ps1'"))) { 
			# This means we have a previous trace already kicked off and running, so signal to stop log collection and exit.
			Initialize-OnDemandStopEvent
		}
	} 
}

InitXmlLog
[string]$PSMode = ($ExecutionContext.SessionState.LanguageMode)

$OSInfoObj = (Get-WmiObject Caption, OSArchitecture, ProductType, LastBootUpTime -Class Win32_OperatingSystem)
$ComSysObj = (Get-WmiObject DomainRole, PartOfDomain -Class Win32_ComputerSystem)

[int]$MinorBuild = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Value "UBR" )
[string]$OSEditionID = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value EditionID
[string]$OSProductName = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value ProductName
if (($OSProductName -like "Windows 10*") -And ($OSBuild -ge 22000)) {
	[string]$OSProductName = $OSInfoObj.Caption
}
[string]$OSEditionName = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value InstallationType
[string]$IsOnboarded = Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\Windows Advanced Threat Protection\Status" -Value OnboardingState 
[int]$PsMjVer = $PSVersionTable.PSVersion.Major
# Below is using WMI instead of $env:PROCESSOR_ARCHITECTURE to avoid getting the PS env instead of the actual OS archecture
[string]$arch = $OSInfoObj.OSArchitecture
[string]$MDfWS = GetAddRemovePrograms (Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall) | Where-Object {$_.DisplayName -like "Microsoft Defender for *"}
[string]$LastSystemBootTime = ($OSInfoObj | select-object @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}).LastBootUpTime
[bool]$DomainJoined = $ComSysObj.PartOfDomain
[bool]$IsDC = ($OSInfoObj.ProductType -eq 2)


if ($arch -like "ARM*") {
	$ARM = $true
	$ARMcommand = "-ARM"
}

if (Get-Process WDATPLauncher -EA silentlycontinue) {
	$SignerInfo = ((Get-AuthenticodeSignature (Get-Process WDATPLauncher).Path).SignerCertificate).Subject
	if ($SignerInfo -like "*Microsoft Corporation*") {
		$ASM = $true
	}
}

# Storing HKU reg path for later use
New-PSDrive HKU Registry HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

if (($OSBuild -le 7601) -And ($PsMjVer -le 2)) { 
	Write-Host -ForegroundColor Yellow "We recommend installing at least 'Windows Management Framework 3.0' (KB2506143) or later for optimal script results: `r`nhttps://www.microsoft.com/en-us/download/details.aspx?id=34595"
}

if ((Test-Path -Path $ToolsDir) -eq $False) {
	Write-Host -ForegroundColor Yellow "Missing 'Tools' directory. Exiting script."
	[Environment]::Exit(1)
}

# Delete previous output if exists
if (Test-Path $resultOutputDir) {
	Remove-Item -Recurse -Force $resultOutputDir -ErrorVariable FileInUse;
	while ($FileInUse) {
		Write-Warning "Please close any opened log files from previous MDEClientAnalyzer run and then try again."
		Read-Host "Press ENTER once you've closed all open files."
		Remove-Item -Recurse -Force $resultOutputDir -ErrorVariable FileInUse
	}
}
if (Test-Path $outputZipFile) {
	Remove-Item -Recurse -Force  $outputZipFile
}

#Check if Evens.Json File not exist
if (-not (Test-Path $ResourcesJson)) {
	Write-Error 'The Events.jsonfile does not exist' -ErrorAction Stop
}
CheckHashFile "$ResourcesJson" "0BD95ADDCF4A35DF4AD2FF49DD3B550C45C11851B4059E04B6EB1532AF8BF6CD" #Must be changed whenever new event is added to events JSON file
CheckHashFile "$RegionsJson" "F1AA9286B533AC62E6C79F4D1E421157299E9706C7C03CB31BCC57A7C560F60A" #Must be changed whenever CnC region is added to regions JSON file
$ResourcesOfEvents = (Get-Content $ResourcesJson -raw) | ConvertFrom-Json

# Create output folders
New-Item -ItemType directory -Path $resultOutputDir | Out-Null
NTFSSecurityAccess $resultOutputDir

New-Item -ItemType Directory -Path "$resultOutputDir\EventLogs" | out-Null
New-Item -ItemType Directory -Path "$resultOutputDir\SystemInfoLogs" | out-Null

#Store paths for MpCmdRun.exe usage
if (((Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Value ImagePath) -and ($OSBuild -ge 14393)) -or ($MDfWS)) {
	$MsMpEngPath = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Value ImagePath
	[System.IO.DirectoryInfo]$CurrentMpCmdPath = $MsMpEngPath -replace "MsMpEng.exe" -replace """"
	$MpCmdRunCommand = Join-Path $CurrentMpCmdPath "MpCmdRun.exe"
	$MpCmdResultPath = "$env:ProgramData\Microsoft\Windows Defender\Support"
}
elseif (Test-Path -path "$env:ProgramFiles\Microsoft Security Client\MpCmdRun.exe") {
	$CurrentMpCmdPath = "$env:ProgramFiles\Microsoft Security Client\"
	$MpCmdRunCommand = "$env:ProgramFiles\Microsoft Security Client\MpCmdRun.exe"
	$MpCmdResultPath = "$env:ProgramData\Microsoft\Microsoft Antimalware\Support"
}

 if ($BootTraceB) {
	$AdvancedFlag = $True
	Initialize-BootTrace
}

Write-Report -section "general" -subsection "PSlanguageMode" -displayname "PowerShell Language mode: " -value $PSMode
Write-Report -section "general" -subsection "scriptVersion" -displayname "Script Version: " -value $ScriptVer
$ScriptRunTime = "{0:dd/MM/yyyy h:mm:ss tt zzz}" -f (get-date)
Write-Report -section "general" -subsection "scriptRunTime" -displayname "Script RunTime: " -value $ScriptRunTime 

Write-output "######################## device Info summary #############################" | Out-File $connectivityCheckFile -append
#if ((($OSBuild -ge 7601 -and $OSBuild -le 14393) -and ($OSProductName -notmatch 'Windows 10')) -and (($OSEditionID -match 'Enterprise') -or ($OSEditionID -match 'Pro') -or ($OSEditionID -match 'Ultimate') -or ($OSEditionID -match 'Server'))) {

if ($OSProductName -like "Hyper-V Server*") {
	[bool]$HyperVOS = $True
	WriteReport 112006 @(, @($OSProductName)) @()
}

if ((!(Get-Service -Name Sense -ErrorAction SilentlyContinue)) -And (!$HyperVOS)) {
	$OSPreviousVersion = $true
	$global:SenseVer=""
	Get-RegValue
	CheckConnectivity -OSPreviousVersion $OSPreviousVersion -connectivityCheckFile $connectivityCheckFile -connectivityCheckUserFile $connectivityCheckUserFile
      
	if ($Global:tdhdll.Valid -and $Global:wintrustdll.Valid -and !($global:SSLProtocol)) {
		"OS Environment is  supported: " + [System.Environment]::OSVersion.VersionString | Out-File $connectivityCheckFile -append
	}
	else {
		"OS Environment is not  supported: " + [System.Environment]::OSVersion.VersionString + " More information below" | Out-File $connectivityCheckFile -append
	}

	if ($Global:connectivityresult -match "failed" ) {
		"Command and Control channel as System Account : Some of the MDE APIs failed , see details below" | Out-File $connectivityCheckFile -append
	}
	elseif (!$Global:connectivityresult) {
		"Command and Control channel as System Account: Not tested" | Out-File $connectivityCheckFile -append 
	}
	else {
		"Command and Control channel as System Account: Passed validation" | Out-File $connectivityCheckFile -append 
	}

	if ($Global:connectivityresultUser -match "failed" ) {
		"Command and Control channel as User Account : Some of the MDE APIs failed , see details below" | Out-File $connectivityCheckFile -append
	}
	elseif (!$Global:connectivityresultUser) {
		"Command and Control channel as User Account: Not tested" | Out-File $connectivityCheckFile -append 
	}
	else {
		"Command and Control channel as User Account: Passed validation" | Out-File $connectivityCheckFile -append 
	}

	if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\services\HealthService\Parameters") {
		Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\services\HealthService\Parameters -recurse | Format-table -AutoSize | Out-File "$resultOutputDir\SystemInfoLogs\HealthServiceReg.txt"
		# Test if multiple MMA workspaces are configured
		$AgentCfg = New-Object -ComObject AgentConfigManager.MgmtSvcCfg
		$workspaces = $AgentCfg.GetCloudWorkspaces()
		if ($workspaces.Item(1)) {
			Write-output "`r`n############################ Multiple workspaces check ###############################" | Out-File $connectivityCheckFile -Append
			WriteReport 121001 @() @()
		}
	}
} 

if ((!$OSPreviousVersion) -or ($MDfWS)) {
	if ($IsOnboarded) {
		Get-RegValue		
		$UTCServiceStatus = (Get-Service -Name DiagTrack).Status
		$DefenderServiceStatus = (Get-Service -Name WinDefend).Status
        [string]$DefenderAVProxy = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Value ProxyServer
		[string]$SSLOptions = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Value SSLOptions
		Write-Report -section "EDRCompInfo" -subsection "UTCServiceStatus" -displayname "DiagTrack (UTC) Service Status" -value $UTCServiceStatus
		Write-Report -section "AVCompInfo" -subsection "DefenderServiceStatus" -displayname "Defender AV Service Status" -value $DefenderServiceStatus
		if (Get-Service -name wscsvc -ErrorAction SilentlyContinue) {
			$WindowsSecurityCenter = (Get-Service -Name wscsvc).Status
			Write-Report -section "AVCompInfo" -subsection "WindowsSecurityCenter" -displayname "Windows Security Center Service Status" -value $WindowsSecurityCenter
		}
		if (Get-Service -name SecurityHealthService -ErrorAction SilentlyContinue) {
			$SecurityHealthService = (Get-Service -Name SecurityHealthService).Status
			Write-Report -section "AVCompInfo" -subsection "SecurityHealthService" -displayname "Windows Security Health Service Status" -value $SecurityHealthService
		}

		if (($OSEditionName -notlike "*core") -and (!$MDfWS)) {
			#"Microsoft Account Sign-in Assistant service start type is: " + (Get-Service -Name wlidsvc).StartType | Out-File $connectivityCheckFile -append
			$WLIDServiceStartType = (Get-Service -Name wlidsvc -ErrorAction SilentlyContinue).StartType
			Write-Report -section "EDRCompInfo" -subsection "WLIDServiceStartType" -displayname "Microsoft Account Sign-in Assistant Start Type" -value $WLIDServiceStartType
		}
		If ($DefenderServiceStatus -eq "Running") {
            if ($DefenderAVProxy) {
                Write-Report -section "AVCompInfo" -subsection "DefenderAVProxy" -displayname "Defender AV proxy configuration" -value $DefenderAVProxy
            }
            if ($SSLOptions) {
                Write-Report -section "AVCompInfo" -subsection "SSLOptions" -displayname "Defender AV SSLOptions configuration" -value $SSLOptions
            }
			if (($OSEditionID -match 'Server') -and (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Value "ForcePassiveMode")) {
				$AVPassiveMode = $true
				Write-Report -section "AVCompInfo" -subsection "DefenderState" -displayname "Defender AV mode" -value "Passive (Forced)"
			} elseif (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Value "PassiveMode") {
				$AVPassiveMode = $true
				Write-Report -section "AVCompInfo" -subsection "DefenderState" -displayname "Defender AV mode" -value "Passive"
			} else {
				Write-Report -section "AVCompInfo" -subsection "DefenderState" -displayname "Defender AV mode" -value "Active" -alert "None"
			}

			# If Defender is running, check if Network Protection Service and Driver are running
			if (Get-Service -name WdNisSvc -ErrorAction SilentlyContinue) {
				$DefenderNetworkProtectionSvc = (Get-Service -Name WdNisSvc).Status
				Write-Report -section "AVCompInfo" -subsection "NetworkProtectionState" -displayname "Defender Network Inspection Service" -value $DefenderNetworkProtectionSvc
			}
		
			if (Get-Service -name WdNisDrv -ErrorAction SilentlyContinue) {
				$DefenderNetworkProtectionDrv = (Get-Service -Name WdNisDrv).Status
				Write-Report -section "AVCompInfo" -subsection "NetworkProtectionState" -displayname "Defender Network Inspection Driver" -value $DefenderNetworkProtectionDrv
			}
		} else {
			$DefenderStartType = (Get-Service -Name Windefend).StartType
			Write-Report -section "AVCompInfo" -subsection "DefenderServiceStartType" -displayname "Defender AV StartType" -value $DefenderStartType
		}

		if (!$ASM) {
			$LastCnCConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Value LastConnected)
			if ($OSBuild -eq 14393) {
				$LastCYBERConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SevilleSettings" -Value LastNormalUploadTime)
				$LastCYBERRTConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SevilleSettings" -Value LastRealTimeUploadTime)
				$LastInvalidHTTPcode = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\HeartBeats\Seville" -Value LastInvalidHttpCode)
				Get-ConnectionStatus 
			} elseif ($OSBuild -le 17134) {
				$LastCYBERConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Tenants\P-WDATP" -Value LastNormalUploadTime)
				$LastCYBERRTConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Tenants\P-WDATP" -Value LastRealTimeUploadTime)
				$LastInvalidHTTPcode = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\HeartBeats\Seville" -Value LastInvalidHttpCode)
				Get-ConnectionStatus
			} elseif ($OSBuild -ge 17763) {
				$LastCYBERConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\TelLib" -Value LastSuccessfulNormalUploadTime)
				$LastCYBERRTConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\TelLib" -Value LastSuccessfulRealtimeUploadTime)
				$LastInvalidHTTPcode = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\TelLib\HeartBeats\Seville" -Value LastInvalidHttpCode)
				Get-ConnectionStatus
			}
		}

		if ((Get-Process -Name MsSense -ErrorAction SilentlyContinue) -And ($OSProductName -notlike "*LTSB")) {
			[version]$minVer = "10.8210.17763.3650"
			if ([version]$Global:SenseVer -gt [version]$minVer) {
				[string]$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\48A68F11-7A16-4180-B32C-7F974C7BD783"
				[string]$RegPathCmd = "HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\48A68F11-7A16-4180-B32C-7F974C7BD783"
			} else {
				[string]$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection"
				[string]$RegPathCmd = "HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection"
			}
			if ($system) {				
				[string]$StateReg = (Get-RegistryValue -Path $RegPath -Value "7DC0B629-D7F6-4DB3-9BF7-64D5AAF50F1A" -ErrorAction "SilentlyContinue")
				[string]$RegisteredId = (Get-RegistryValue -Path $RegPath -Value "C9D38BBB-E9DD-4B27-8E6F-7DE97E68DAB9" -ErrorAction "SilentlyContinue")
			} else {
				$PSExecCommand = Join-Path $ToolsDir "PsExec.exe"
				Test-CommandVerified $PSExecCommand
				Test-CommandVerified "reg.exe"
				&$PSExecCommand -accepteula -s -nobanner reg.exe query `"$RegPathCmd`" /v 7DC0B629-D7F6-4DB3-9BF7-64D5AAF50F1A 2>$null > "$ToolsDir\StateReg.log"
				&$PSExecCommand -accepteula -s -nobanner reg.exe query `"$RegPathCmd`" /v C9D38BBB-E9DD-4B27-8E6F-7DE97E68DAB9 2>$null > "$ToolsDir\RegisteredId.log"
				[string]$StateReg = (Get-Content "$ToolsDir\StateReg.log")
				[string]$RegisteredId = (Get-Content "$ToolsDir\RegisteredId.log")
				if ($StateReg) {
					$position = $StateReg.IndexOf("REG_SZ    ")
					[string]$StateReg = $StateReg.Substring($position+10)
				}
				if ($RegisteredId) {
					$position = $RegisteredId.IndexOf("REG_SZ    ")
					[string]$RegisteredId = $RegisteredId.Substring($position+10)
				}
			}
			if ($StateReg) {
				Write-Report -section "EDRCompInfo" -subsection "AFState" -displayname "Anti-Spoofing capability deployed" -value "YES"
				if ($StateReg -match "66748D4C-F662-482E-8EAE-F8D73CD9AFED") {
					[string]$SenseId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value "SenseId")
					if ($RegisteredId -match $SenseId) {
						WriteReport 120037 @() @()
					# VDI has special Anti-Spoofing handling in cloud so only throw this warning if not running a VDI machine
					} elseif (!$IsVDI) {
						WriteReport 121036 @() @()
						$UnstableAntiSpoof = $true
					}
				} else {
					WriteReport 121040 @() @()
				}
			} else {
				[string]$RegisteredId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value "C9D38BBB-E9DD-4B27-8E6F-7DE97E68DAB9")
				[string]$StateReg = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value "7DC0B629-D7F6-4DB3-9BF7-64D5AAF50F1A")		
				if (!$StateReg) {
					if ([version]$Global:SenseVer -lt [version]$minVer) {
						Write-Report -section "EDRCompInfo" -subsection "AFState" -displayname "Anti-Spoofing capability deployed" -value "NO"
						WriteReport 121035 @() @()
					}			
				}
			}
			if ($RegisteredId) {
				Write-Report -section "EDRCompInfo" -subsection "MachineAuthId" -displayname "MachineAuth ID" -value $RegisteredId
			}
			if ($StateReg) {
				Write-Report -section "EDRCompInfo" -subsection "StateReg" -displayname "Anti-Spoofing State GUID" -value $StateReg 
			}
		}

		# Test for events indicating expired OrgID in Sense event logs
		Write-output "`r`n############################ OrgID error check ###############################" | Out-File $connectivityCheckFile -Append
		if ((Get-Service -Name "SENSE").Status -eq "Running") {
			$OrgId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Value "OrgID" )
			$EventError = (Get-MatchingEvent Microsoft-Windows-SENSE 67 "400")
			if (!$EventError) {
				$EventError = (Get-MatchingEvent Microsoft-Windows-SENSE 5 "400")
			}
			$EventOk = (Get-MatchingEvent Microsoft-Windows-SENSE 50 "*10.*")
			if (!$EventError) {
				"Based on SENSE log, no OrgId mismatch errors were found in events" | Out-File $connectivityCheckFile -Append
			} 		
			if (($EventOk) -and ($EventError)) {
				if ((Get-Date $EventOk.TimeCreated) -gt (Get-Date $EventError.TimeCreated)) {
					"Based on SENSE log, the device is linked to an active Organization ID: $orgID`r`n" | Out-File $connectivityCheckFile -Append
				} 
			}
			# Ignore the error if the AntiSpoofing component is unstable as it can also cause error 400
			elseif (($EventError) -and (!$UnstableAntiSpoof)) {
				Write-output "Event Log error information:" | Out-File $connectivityCheckFile -Append
				$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
				WriteReport 122005 @(, @($OrgId)) @()
			}
		}
	} 

	# Dump Registry OnboardingInfo and OffboardingInfo if exists
	$RegOnboardingInfo = Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\" -Value OnboardingInfo 
	$RegOnboardedInfo = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value OnboardedInfo 
	$RegOffboardingInfo = Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\" -Value 696C1FA1-4030-4FA4-8713-FAF9B2EA7C0A 
	($RegOnboardingInfo | ConvertFrom-Json).body | Out-File "$resultOutputDir\SystemInfoLogs\RegOnboardingInfoPolicy.Json"
	($RegOnboardedInfo | ConvertFrom-Json).body | Out-File "$resultOutputDir\SystemInfoLogs\RegOnboardedInfoCurrent.Json"
	($RegOffboardingInfo | ConvertFrom-Json).body | Out-File "$resultOutputDir\SystemInfoLogs\RegOffboardingInfo.Json"
	if (($RegOnboardingInfo -eq $False) -or ($RegOnboardingInfo -eq $null)) {
		Get-deviceInfo
		"`r`Note: OnboardingInfo could not be found in the registry. This can be expected if device was offboarded or onboarding was not yet executed." | Out-File $connectivityCheckFile -Append
	}
	Write-Output "CheckConnectivity -OSPreviousVersion $OSPreviousVersion -connectivityCheckFile $connectivityCheckFile -connectivityCheckUserFile $connectivityCheckUserFile -onboardingScriptPath $OnboardingScriptPath -geoRegion $GeoRegion " | Out-File $connectivityCheckFile -append  
	CheckConnectivity -OSPreviousVersion $OSPreviousVersion -connectivityCheckFile $connectivityCheckFile -connectivityCheckUserFile $connectivityCheckUserFile -onboardingScriptPath $OnboardingScriptPath -geoRegion $GeoRegion
}

#Fetching configured proxy
$ConOutput = (Get-Content $connectivityCheckFile)
[string]$SenseProxyOutput = ($ConOutput | Select-String -pattern "Proxy config: Method")
if ($SenseProxyOutput) {
	Write-Report -section "EDRCompInfo" -subsection "SenseProxyConfig" -displayname "Sense Service Discovered Proxy" -value $SenseProxyOutput
}
$TelemetryProxyServer = Get-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Value "TelemetryProxyServer"
#Setting proxy from discovered MDE proxy
if ($TelemetryProxyServer) {
	$Proxy = $TelemetryProxyServer
} elseif ($SenseProxyOutput) {
	$position = $SenseProxyOutput.IndexOf("address=")
	if (($position) -And (!$SenseProxyOutput.Substring($position+8).endswith("="))) {
		$Proxy = $SenseProxyOutput.Substring($position+8)
	}
}

# Check if MDE for down-level server is installed on 2012R2/2016
if (($OSEditionID -match 'Server') -and ($OSBuild -gt 7601 -and $OSBuild -le 14393)) {
	if ($MDfWS) {
		Write-Report -section "EDRCompInfo" -subsection "MDfWSState" -displayname "Unified agent for downlevel servers installed" -value "YES" 
		[version]$minVer = "10.8049.22439.1084"
		if ([version]$Global:SenseVer -lt [version]$minVer) {
			WriteReport 122038 @() @()
		}
	} else {
		Write-Report -section "EDRCompInfo" -subsection "MDfWSState" -displayname "Unified agent for downlevel servers installed" -value "NO"
		WriteReport 121020 @() @()
	}
}

If ($CurrentMpCmdPath) {
	    $AVSignatureVersion = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates" -Value "AVSignatureVersion" ) 
		$AVEngineVersion = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates" -Value "EngineVersion" ) 
		$AVPlatformVersion = $CurrentMpCmdPath.Name
			
		#Check AV component versions to ensure they are up-to-date and report to Result
		$FilePathEPPversions = Join-Path $ToolsDir "EPPversions.xml"
		CheckHashFile $FilePathEPPversions "9038FA111718D7CED9BEE745D0684B68DBE166E62059DCAA265BD871FFEA6ACB"
		$CheckAV = Join-Path $ToolsDir "MDE.psm1"
		Test-AuthenticodeSignature $CheckAV
		Import-Module $CheckAV
		$CheckAVHelper = Join-Path $ToolsDir "MDEHelper.psd1"
		Test-AuthenticodeSignature $CheckAVHelper
		Import-Module $CheckAVHelper
		if ($Proxy) {
			$ProxyAddress = [system.net.webrequest]::DefaultWebProxy = new-object system.net.webproxy($Proxy)
		}
		$WebRequestAV = [net.WebRequest]::Create("https://www.microsoft.com/security/encyclopedia/adlpackages.aspx?action=info")
		$WebRequestAV.Proxy = $proxyAddress
		try {
			Write-Host "Checking latest AV versions from cloud: " $WebRequestAV.GetResponse().StatusCode
		}
		catch [System.Net.WebException] {
			$ErrorMessage = $Error[0].Exception.ErrorRecord.Exception.Message;
		}
		$WebRequestAV.Close
		if ($AVPlatformVersion -like "*-*") {
				[string]$Platform = $AVPlatformVersion.split('-')[0]
		} else {
			[string]$Platform = $AVPlatformVersion
		}
		$MoCAMPAlert = "None"; $EngineAlert = "None"; $SigsAlert = "None"; 
		if ($ErrorMessage -eq $null) {
			if ((checkeppversion -component MoCAMP -version $Platform -proxy $ProxyAddress) -or ($Platform -eq "Windows Defender")) {
				$MoCAMPAlert = "High"
				WriteReport 122010 @() @()
			} 
			if (checkeppversion -component Engine -version $AVEngineVersion -proxy $ProxyAddress) {
				$EngineAlert = "High"
				WriteReport 122011 @() @()
			} 
			if (checkeppversion -component Sigs -version $AVSignatureVersion -proxy $ProxyAddress) {
				$SigsAlert = "Medium"
				WriteReport 121012 @() @()
			} 
		} else {
			[XML]$EPPversions = Get-Content $FilePathEPPversions
			#Option to check the AV state using the included EPPversions.xml ($FilePathEPPversions)
			if ((checkeppversion -component MoCAMP -version $Platform -xml $EPPversions) -or ($Platform -eq "Windows Defender")) {
				$MoCAMPAlert = "High"
				WriteReport 122010 @() @()
			} 
			if (checkeppversion -component Engine -version $AVEngineVersion -xml $EPPversions) {
				$EngineAlert = "High"
				WriteReport 122011 @() @()
			} 
			if (checkeppversion -component Sigs -version $AVSignatureVersion -xml $EPPversions) {
				$SigsAlert = "Medium"
				WriteReport 121012 @() @()
			} 
		}	
		Write-Report -section "AVCompInfo" -subsection "AVPlatformVersion" -displayname "Defender AV Platform Version" -value $Platform -alert $MoCAMPAlert
		Write-Report -section "AVCompInfo" -subsection "AVSignatureVersion" -displayname "Defender AV Security Intelligence Version" -value $AVSignatureVersion -alert $SigsAlert
		Write-Report -section "AVCompInfo" -subsection "AVEngineVersion" -displayname "Defender AV engine Version" -value $AVEngineVersion -alert $EngineAlert

		# Report Is Tamper Protected, Tamper Protection Source, and IsTpExclusionsEnabled
		$IsTp = (Get-MpComputerStatus).IsTamperProtected
		if ($null -ne $IsTp) {
			Write-Report -section "AVCompInfo" -subsection "DefenderState" -displayname "Defender Is Tamper Protected" -value $IsTp
			$TpSource = (Get-MpComputerStatus).TamperProtectionSource
			if ($null -ne $TpSource) {
				Write-Report -section "AVCompInfo" -subsection "DefenderState" -displayname "Defender Tamper Protection Source" -value $TpSource
			}
			# Currently no mpclient api, if there ever is one we should switch
			[int]$TpExclusions = (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Value "TPExclusions")
			if ($null -ne $TpExclusions) {
				$TpExclusionEnabled = $TpExclusions -gt 0
				Write-Report -section "AVCompInfo" -subsection "DefenderState" -displayname "Defender Is Tamper Protection Exclusions Enabled" -value $TpExclusionEnabled
			}
		}
}

# Check if agent versions match minimum for Simplified Connectivity
Test-StreamlinedConnectivity
if ($RegOnboardedInfo) {
	[string]$Region = (($RegOnboardedInfo | ConvertFrom-Json).body | ConvertFrom-Json).vortexGeoLocation
	if ($Region) {
		Write-Report -section "EDRCompInfo" -subsection "Location" -displayname "Device Datacenter Location" -value $Region
	}
	if ((($RegOnboardedInfo | ConvertFrom-Json).body | ConvertFrom-Json).partnerGeoLocation -like "GW_*") {
		Write-Report -section "EDRCompInfo" -subsection "SimplifiedConnectivity" -displayname "Device Onboarded via Streamlined Connectivity" -value "YES"
	} else {
		Write-Report -section "EDRCompInfo" -subsection "SimplifiedConnectivity" -displayname "Device Onboarded via Streamlined Connectivity" -value "NO"
	}
}

[int]$PreventPlatformUpdate = (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows Defender\Miscellaneous Configuration" -Value "PreventPlatformUpdate")
if ($PreventPlatformUpdate) {
	$Msg = "To enable platform update, please delete the registry value HKLM\SOFTWARE\Microsoft\Windows Defender\Miscellaneous Configuration\PreventPlatformUpdate"
	Write-Report -section "AVCompInfo" -subsection "PlatformUpdate" -displayname "PreventPlatformUpdate is set in Registry" -value $Msg
}

[string]$SharedSignatureRoot = (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates" -Value "SharedSignatureRoot")
if ($SharedSignatureRoot) {
	$Msg = "SharedSignatureRoot is set, any update schedule / interval will thus be short circuited. "
	Write-Report -section "AVCompInfo" -subsection "SignatureUpdates" -displayname "SharedSignatureRoot is set in Registry" -value $Msg
}

[int]$OobeEnableRtpAndSigUpdate = (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Value "OobeEnableRtpAndSigUpdate")
if ($OobeEnableRtpAndSigUpdate) {
	$Msg = "Enabled. Registry value HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\OobeEnableRtpAndSigUpdate=$OobeEnableRtpAndSigUpdate"
	Write-Report -section "AVCompInfo" -subsection "OobeEnableRtpAndSigUpdate" -displayname "OobeEnableRtpAndSigUpdate is set in Registry" -value $Msg
}

if ((($OSBuild -ge 7601 -and $OSBuild -le 14393) -and ($OSProductName -notmatch 'Windows 10')) -and (($OSEditionID -match 'Enterprise') -or ($OSEditionID -match 'Pro') -or ($OSEditionID -match 'Ultimate') -or ($OSEditionID -match 'Server'))) {
	"`r`n###################### OMS validation details  ###########################" | Out-File $connectivityCheckFile -append
	if ($Global:TestOMSResult -match "Connection failed" -or $Global:TestOMSResult -match "Blocked Host") {
		"OMS channel: Some of the OMS APIs failed , see details below" | Out-File $connectivityCheckFile -append
	}
 elseif (!$Global:TestOMSResult) {
		"OMS channel: Not tested" | Out-File $connectivityCheckFile -append 
	}
 elseif (!$MDfWS) {
		"OMS channel: Passed validation" | Out-File $connectivityCheckFile -append 
		"Service Microsoft Monitoring Agent is " + (Get-Service -Name HealthService -ErrorAction SilentlyContinue).Status | Out-File $connectivityCheckFile -append
		"Health Service DLL version is: " + $Global:healthservicedll.version | Out-File $connectivityCheckFile -append
		If (!$Global:healthservicedll.Valid) {
			"`n" | Out-File $connectivityCheckFile -append
			WriteReport 122002 @(, @($Global:healthservicedll.Message)) @()
		}
	} 
	"`r`n###################### OS validation details  ###########################" | Out-File $connectivityCheckFile -append
	$Global:tdhdll.Message  | Out-File $connectivityCheckFile -append
	$Global:wintrustdll.Message  | Out-File $connectivityCheckFile -append
	$global:SSLProtocol | Out-File $connectivityCheckFile -append
	Write-output "##########################################################################`n" | Out-File $connectivityCheckFile -append  
	"######## Connectivity details for Command and Control  validation  #######" | Out-File $connectivityCheckFile -append
	$connectivityresult | Out-File $connectivityCheckFile -append
	Write-output "##########################################################################`n" | Out-File $connectivityCheckFile -append  
	"################# Connectivity details for OMS  validation  #########" | Out-File $connectivityCheckFile -append
	$Global:TestOMSResult | Out-File $connectivityCheckFile -append
	Write-output "##########################################################################`n" | Out-File $connectivityCheckFile -append  
}

# Checks for MDE Device Configuration
if ((($osbuild -gt 9600) -or (($osbuild -eq 9600) -and ($OSEditionID -match 'Server'))) -and ($IsOnboarded)) {
	Write-output "`r`n################# Device Registration and Enrollment ##################" | Out-File $connectivityCheckFile -Append	

	$SenseCMConfig = Get-SenseCMInfo

	# Check applicability for MDEAttach v2
	$hasMinimalSenseVersion = $false
	If ($MDfWS) {
		$hasMinimalSenseVersion = [version]$Global:SenseVer -ge [version]"10.8295.22621.1023"
	} else {
		$hasMinimalSenseVersion = [version]$Global:SenseVer -ge [version]"10.8040.0.0"
	}

	If (!$hasMinimalSenseVersion) {
		WriteReport 111021 @(, @("$Global:SenseVer")) @()
	} else {
		If ($SenseCMConfig.SwitchMode -eq "2") {
			Write-Report -section "MDEDevConfig" -subsection "SwitchMode" -displayname "Version" -value  $SenseCMConfig.SwitchMode
		}
	}
	
	# Check SenseCM enrollment Status
	if ($SenseCMConfig.EnrollmentStatusId) {
		$EnrollmentStatusAlert = ""

		If ($SenseCMConfig.EnrollmentStatusReportId) {
			$EnrollmentStatusAlert = "High"
			WriteReport $SenseCMConfig.EnrollmentStatusReportId @() @()
		} 

		If ($SenseCMConfig.EnrollmentStatusId -eq "1" -or $SenseCMConfig.EnrollmentStatusId -eq "43") { $EnrollmentStatusAlert = "None" }
		Write-Report -section "MDEDevConfig" -subsection "SenseCMEnrollmentStatus" -displayname "Enrollment Status" -value $SenseCMConfig.EnrollmentStatusText -alert $EnrollmentStatusAlert

		if ($SenseCMConfig.AADDeviceId) { Write-Report -section "MDEDevConfig" -subsection "AADDeviceID" -displayname "Azure AD Device ID" -value $SenseCMConfig.AADDeviceId }
		if ($SenseCMConfig.IntuneDeviceID) { Write-Report -section "MDEDevConfig" -subsection "IntuneDeviceID" -displayname "Intune Device ID" -value $SenseCMConfig.IntuneDeviceID }
		if ($SenseCMConfig.TenantId) { Write-Report -section "MDEDevConfig" -subsection "AADTenantId" -displayname "Azure AD Tenant ID" -value $SenseCMConfig.TenantId }
		}
	}

	if ($DomainJoined) {
		Write-Report -section "MDEDevConfig" -subsection "DomainJoined" -displayname "Domain Joined" -value "YES"
		if ($IsDC) {
			WriteReport 111022 @() @()
		}
	} else {
		Write-Report -section "MDEDevConfig" -subsection "DomainJoined" -displayname "Domain Joined" -value "NO"
	}

	# Collect information about up-level OS
	if ($osbuild -gt "9600") {
		# Collect Information from DSREGCMD 
		$DSRegState = Get-DsRegStatus		
		Write-Report -section "MDEDevConfig" -subsection "AzureADJoined" -displayname "Azure AD Joined" -value $DSRegState.DeviceState.AzureAdJoined
		Write-Report -section "MDEDevConfig" -subsection "WorkplaceJoined" -displayname "Workplace Joined" -value $DSRegState.UserState.WorkplaceJoined
		if ((!$SenseCMConfig.AADDeviceId) -and ($DSRegState.DeviceDetails.DeviceID)) {
			Write-Report -section "MDEDevConfig" -subsection "AADDeviceID" -displayname "Azure AD Device ID" -value $DSRegState.DeviceDetails.DeviceID 
			
			$MDMEnrollmentState = Get-MDMEnrollmentStatus
			Write-Report -section "MDEDevConfig" -subsection "MDMEnrollmentState" -displayname "MDM Enrollment state" -value $MDMEnrollmentState.EnrollmentTypeText
		}

		# Dump DFSS Settings
		$DFSS_Setttings = "$resultOutputDir\SystemInfoLogs\DFSS_Settings.txt"
		Get-ChildItem "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Quota System" -Recurse -ErrorAction silentlycontinue | Out-File $DFSS_Setttings -append
		Get-ChildItem "HKLM:SOFTWARE\Policies\Microsoft\Windows\Session Manager\Quota System" -Recurse -ErrorAction silentlycontinue | Out-File $DFSS_Setttings -append
	}

	# Checks are only relevant for MDEAttach v1
	If (!$hasMinimalSenseVersion -and $DomainJoined) {
		$SCPConfiguration = Get-SCPConfiguration
		if ($SCPConfiguration.ResultID -eq "") {
			Write-Report -section "MDEDevConfig" -subsection "SCPClientSide" -displayname "SCP Configuration Type" -value $SCPConfiguration.ConfigType
			Write-Report -section "MDEDevConfig" -subsection "SCPTenantName" -displayname "SCP Tenant Name" -value $SCPConfiguration.TenantName
			Write-Report -section "MDEDevConfig" -subsection "SCPTenantID" -displayname "SCP Tenant ID" -value $SCPConfiguration.TenantId
				
			if ((!$SenseCMConfig.TenantId) -xor (!$SCPConfiguration.TenantId)) {
					WriteReport 120021 @() @()
			} elseif ((((!$SenseCMConfig.TenantId) -and (!$SCPConfiguration.TenantId)) -and ($SenseCMConfig.TenantId -notmatch $SCPConfiguration.TenantId)) -or ($SenseCMConfig.EnrollmentStatusId -eq 15)) {
				WriteReport 121022 @() @()
			} elseif (($SCPConfiguration.ResultID -eq 121017) -or ($SenseCMConfig.EnrollmentStatusId -eq 15)) {
				WriteReport $SCPConfiguration.ResultID @(, @($SCPConfiguration.TenantName)) @()
			} else {
				WriteReport $SCPConfiguration.ResultID  @() @()
			}
	}	
}

if ((!$OSPreviousVersion) -or ($MDfWS)) {
	Write-output "`r`n################# Defender AntiVirus cloud service check ##################" | Out-File $connectivityCheckFile -Append
	if ($MpCmdRunCommand) {
		Test-AuthenticodeSignature $MpCmdRunCommand
		$MAPSCheck = &$MpCmdRunCommand -ValidateMapsConnection
		$MAPSErr = $MAPSCheck | Select-String -pattern "ValidateMapsConnection failed"
		if ($MAPSErr) { 
			WriteReport 131007 @(, @($MAPSErr)) @()
		}
		else {
			$MAPSOK = $MAPSCheck | Select-String -pattern "ValidateMapsConnection successfully"
			if ($MAPSOK) {
				WriteReport 130011 @() @()
			}
		}
	}
	Write-output "`r`n############################ Metered Network Check ############################" | Out-File $connectivityCheckFile -Append
	[void][Windows.Networking.Connectivity.NetworkInformation, Windows, ContentType = WindowsRuntime]
	$connectionProfile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()

	if ($connectionProfile) {
		$cost = $connectionProfile.GetConnectionCost()
		$isMetered = $cost.ApproachingDataLimit -or $cost.OverDataLimit -or $cost.Roaming -or $cost.BackgroundDataUsageRestricted -or (($cost.NetworkCostType -ne "Unrestricted") -and ($cost.NetworkCostType -ne "Unknown"))
		if ($isMetered) {
			$ApproachingDatalimit = $cost.ApproachingDataLimit
			$OverDataLimit = $cost.OverDataLimit
			$Roaming = $cost.Roaming
			$BackgroundDataUsageRestricted = $cost.BackgroundDataUsageRestricted
			$NetworkCostType = $cost.NetworkCostType
			$ResultStr = "`nApproachingDataLimit: $ApproachingDataLimit`n OverDataLimit: $OverDataLimit`n Roaming: $Roaming`n BackgroundDataUsageRestricted: $BackgroundDataUsageRestricted`n NetworkCostType: $NetworkCostType."
			WriteReport 131008 @(, @($ResultStr)) @()
		} else {
			WriteReport 130012 @() @()
		}
	}
}

# Dump installed hotfix list via WMI call
$Computer = "LocalHost"
$Namespace = "root\CIMV2"
$InstalledUpdates = Get-WmiObject -class Win32_QuickFixEngineering -computername $Computer -namespace $Namespace -ErrorAction SilentlyContinue
If ($InstalledUpdates) {
	$InstalledUpdates | Out-File "$resultOutputDir\SystemInfoLogs\InstalledUpdates.txt"
}

# Dump Device Guard Settings
$Namespace = "root\Microsoft\Windows\DeviceGuard"
$DeviceGuardSettings = Get-WmiObject -Class Win32_DeviceGuard -Namespace $Namespace -ErrorAction SilentlyContinue
If ($DeviceGuardSettings) {
	$DeviceGuardSettings | Out-File "$resultOutputDir\SystemInfoLogs\DeviceGuardSettings.txt"
}

<#Collect advanced traces if flagged
1. Start timer
2. Call the relevant function to start traces for various scenarios
3. When timer expires or manually stopped call the functions to stop traces for various scenarios
4. Gather logs common to all scenarios and finish
#>

if ($DlpQ -or $DlpT) {
	$DLPHealthCheck = Join-Path $ToolsDir "DLPDiagnose.ps1"
	Test-AuthenticodeSignature $DLPHealthCheck
	Test-CommandVerified "powershell.exe"
	&Powershell.exe -NoProfile "$DLPHealthCheck"
}

# Dump DLP related policy information from registry
if (($DlpT) -or ($AppCompatC) -or ($DlpQ) -or ($AdvancedFlag)) {
	if ((!$OSPreviousVersion) -and ($OSBuild -ge 17763)) {
		New-Item -ItemType Directory -Path "$resultOutputDir\DLP" | out-Null
		<# 
		# The below captures the local AD user UPN. We should also fetch UPN in case of Azure AD
		if ($InteractiveAdmin) {
			[string]$UserUPN = ([ADSI]"LDAP://<SID=$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)>").UserPrincipalName
			$UserUPN | Out-File "$resultOutputDir\DLP\dlpPolicy.txt" -Append
		}
		#>
		if (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value dlpPolicy) {
			ShowDlpPolicy dlpPolicy
			ShowDlpPolicy dlpSensitiveInfoTypesPolicy
			if (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value dlpActionsOverridePolicy) {
				ShowDlpPolicy dlpActionsOverridePolicy
			}
			if (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value dlpWebSitesPolicy) {
				ShowDlpPolicy dlpWebSitesPolicy
                $Rules = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows Defender\DLP Websites" -ErrorAction SilentlyContinue
                if ($Rules[0].ValueCount -ge 1) {
					$Sids = $Rules.Property
                    foreach ($SID in $Sids) {
			        [Array]$ByteArray = (Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows Defender\DLP Websites\Rules" -name $SID)
                    $ByteArray = $ByteArray.Where({ $_ -ne "" })
                    $Enc = [System.Text.Encoding]::ASCII
                    $Converted = $enc.GetString($ByteArray)
                    $Converted | ConvertTo-Json -Depth 20 > "$resultOutputDir\DLP\WebRules_$SID.json"
                    }
                } else {
					Write-output "No DLP website rules found in the registry of this device" | Out-File "$resultOutputDir\DLP\NoDlp.txt" -append
				}
			}
			$DLPlogs = Get-Item "$env:SystemDrive\DLPDiagnoseLogs\*.log" -ErrorAction SilentlyContinue
			if ($DLPlogs) {
				Move-Item -Path $DLPlogs -Destination "$resultOutputDir\DLP\"
			}
		}
		else {
			Write-output "No DLP polices found in the registry of this device" | Out-File "$resultOutputDir\DLP\NoDlp.txt" -append
		}
	}
}

if ($wprpTraceL -or $wprpTraceH -or $AppCompatC -or $NetTraceI -or $WDPerfTraceA -or $WDLiteTraceE -or $WDVerboseTraceV -or $DlpT) {
	$AdvancedFlag = $True
	if ($wprpTraceH) {
		$WDPerfTraceA = $true
	}
	Initialize-PSRRecording
	$WPtState = Test-WptState
	$MinutesToRun = Get-MinutesValue
	Initialize-Wpr
	Initialize-PerformanceTrace
	Initialize-AppCompatTrace
	Initialize-MDAVTrace
	Initialize-NetTrace
	StartTimer
	Get-MSInfo -NFO $true -TXT $false -OutputLocation "$resultOutputDir\SystemInfoLogs"
	Save-Wpr
	Save-PerformanceTrace
	Save-AppCompatTrace
	Save-MDAVTrace
	Save-NetTrace
	Get-DLPEA
	Save-PSRRecording
}

#Moved SENSE service check to end of trace and adding also start state
if ((!$OSPreviousVersion) -or ($MDfWS)) {
	$SenseServiceStatus = (Get-Service -Name Sense).Status
	$SenseStartType = (Get-Service -Name Sense).StartType
	Write-Report -section "EDRCompInfo" -subsection "SenseServiceStatus" -displayname "Sense service Status" -value $SenseServiceStatus
	Write-Report -section "EDRCompInfo" -subsection "SenseStartType" -displayname "Sense service StartType" -value $SenseStartType
}

#Always run GetFiles collection regardless of what sceanrio flag was used
Get-Log

if ($CrashDumpD) {
	Get-CrashDump
}

if ($FullCrashDumpZ) {
	Initialize-CrashOnCtrlScroll
	Initialize-FullCrashDump
	Write-Host -BackgroundColor Red -ForegroundColor Yellow "Please reboot the device for the change in settings to apply" 
	Write-Host -ForegroundColor Green "To force the system to crash for memory dump collection, hold down the RIGHT CTRL key while pressing the SCROLL LOCK key twice"
	Write-Host "Note: This is not expected to work during Remote Desktop Protocol (RDP). For RDP please use the script with -k parameter instead"
}

if ($notmyfault) {
	Initialize-FullCrashDump
	if (!$RemoteRun) {
		[string]$notmyfault = (Read-Host "Type 'crashnow' and press ENTER to crash the device and create a full device dump now")
	}
	if (($notmyfault -eq "crashnow") -or ($RemoteRun)) {
		if ([Environment]::Is64BitOperatingSystem) {
			$NotMyFaultCommand = Join-Path $ToolsDir "NotMyFaultc64.exe"
		}
		else {
			$NotMyFaultCommand = Join-Path $ToolsDir "NotMyFaultc.exe"
		}
		Test-AuthenticodeSignature $NotMyFaultCommand
		& $NotMyFaultCommand /accepteula /Crash 1
	}
}

if (Test-Path -Path  $env:SystemRoot\System32\'Winevt\Logs\Operations Manager.evtx') {
	Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Operations Manager.evtx' -Destination $resultOutputDir\EventLogs\OperationsManager.evtx
}

if (Test-Path -Path  $env:SystemRoot\System32\'Winevt\Logs\OMS Gateway Log.evtx') {
	Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\OMS Gateway Log.evtx' -Destination $resultOutputDir\EventLogs\OMSGatewayLog.evtx
}

if (test-path -Path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-UniversalTelemetryClient%4Operational.evtx') {
	Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-UniversalTelemetryClient%4Operational.evtx -Destination $resultOutputDir\EventLogs\utc.evtx
}

if (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-SENSE%4Operational.evtx') {
	Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-SENSE%4Operational.evtx -Destination $resultOutputDir\EventLogs\sense.evtx
	Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-SenseIR%4Operational.evtx -Destination $resultOutputDir\EventLogs\senseIR.evtx -ErrorAction SilentlyContinue
}

if (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-WindowsUpdateClient%4Operational.evtx') {
	Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-WindowsUpdateClient%4Operational.evtx -Destination $resultOutputDir\EventLogs\Microsoft-Windows-WindowsUpdateClient%4Operational.evtx
}

# Test for ASR rule blocking PsExec
if ((!$OSPreviousVersion) -and (!$AVPassiveMode)) {
	TestASRRules    
}

# Check if automatic update of Trusted Root Certificates is blocked
$AuthRootLocal = get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot" -ErrorAction SilentlyContinue
$AuthRootGPO = get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" -ErrorAction SilentlyContinue
if (($AuthRootLocal.DisableRootAutoUpdate -eq "1") -or ($AuthRootGPO.DisableRootAutoUpdate -eq "1")) {
	Write-output "`r`n######################## Auth Root Policies #########################" | Out-File $connectivityCheckFile -Append
	WriteReport 130009 @(@($AuthRootLocal), @($AuthRootGPO)) @()
	if ($OSPreviousVersion) {
		$EventError = Get-MatchingEvent HealthService 2132 "12175L"
	}
 else {
		$EventError = Get-MatchingEvent Microsoft-Windows-SENSE 5 "12175"
	}
	if ($EventError) {
		WriteReport 132012 @() @()
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
	} 
}

if (!$TelemetryProxyServer) {
	"############## Connectivity Check for ctldl.windowsupdate.com #############" | Out-File $connectivityCheckFile -append
	$urlctldl = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab"
	$webRequest = [net.WebRequest]::Create("$urlctldl")
	try {
		"StatusCode for " + $urlctldl + " IS : " + $webRequest.GetResponse().StatusCode | Out-File $connectivityCheckFile -append
	}
	catch [System.Net.WebException] {
		$ErrorMessage = $Error[0].Exception.ErrorRecord.Exception.Message;
		"Exception occurred for " + $urlctldl + " :" + $ErrorMessage | Out-File $connectivityCheckFile -append
		$Error[0].Exception.InnerException.Response | Out-File $connectivityCheckFile -append		
		# WriteReport 131003 @() @()
	}
	$webRequest.Close
}

"############## CertSigner Results #############" | Out-File $CertSignerResults
$RootAutoUpdateDisabled = (($AuthRootLocal.DisableRootAutoUpdate -eq "1") -or ($AuthRootGPO.DisableRootAutoUpdate -eq "1"))
if (!$LegacyOS) {
	CheckExpirationCertUtil $RootAutoUpdateDisabled "authroot" "$ToolsDir\MsPublicRootCA.cer"
	CheckExpirationCertUtil $RootAutoUpdateDisabled "disallowed"
}

# Check if only domain based trusted publishers are allowed
$AuthenticodeFlagsLocal = get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SystemCertificates\TrustedPublisher\Safer" -ErrorAction SilentlyContinue
$AuthenticodeFlagsGPO = get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Safer" -ErrorAction SilentlyContinue
if (($AuthenticodeFlagsLocal.AuthenticodeFlags -eq "2") -or ($AuthenticodeFlagsGPO.AuthenticodeFlags -eq "2")) {
	Write-output "`r`n######################## Trusted Publishers Policy #########################" | Out-File $connectivityCheckFile -Append
	WriteReport 121009 @() @(@($AuthenticodeFlagsLocal), @($AuthenticodeFlagsGPO))
}

# Validate certificate revocation
# public .cer file was fetched from the https://winatp-gw-cus.microsoft.com/test this needs to be updated if certificate changes
if (!$OSPreviousVersion) {
	"`r`n##################### certificate validation check ########################" | Out-File $connectivityCheckFile -Append	
	# Try to get the cert of the first URL to test
	$Cert = Get-EndpointCertificate (Get-Content $EndpointList)[0]
	$CertAsBytes = ([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert).Export("Cert")
	if ($CertAsBytes) {
		Set-Content -Path "$ToolsDir\winatp.cer" -Value $CertAsBytes -Encoding Byte
	}
	if (Test-Path -Path "$ToolsDir\winatp.cer")	{
		$certutilcommand = Join-Path $ToolsDir "PsExec.exe"
		if (test-Path -path $certutilcommand) {
			Test-AuthenticodeSignature $certutilcommand
		}
		if (!$system) {
			Test-CommandVerified "certutil.exe"
			&$certutilcommand -accepteula -s -nobanner certutil.exe -verify -urlfetch "$ToolsDir\winatp.cer" 2>> $connectivityCheckFile | Out-File $CertResults
		} elseif ($system) {
			Test-CommandVerified "certutil.exe"
			&certutil.exe -verify -urlfetch "$ToolsDir\winatp.cer" | Out-File $CertResults
		}
		$Certlog = (Get-Content $CertResults)

		if (!$Certlog) {
			WriteReport 131004 @() @()
		} else {
			if (($Certlog -like "*Element.dwErrorStatus*") -or ($Certlog -like "*0x8007*")) {
				if ((($osbuild -eq "17763") -and ([int]$MinorBuild -lt 1911)) -or (($osbuild -eq "18363") -and ([int]$MinorBuild -lt 1411)) -or (($osbuild -eq "19041") -and ([int]$MinorBuild -lt 844)) -or (($osbuild -eq "19042") -and ([int]$MinorBuild -lt 964))) {
					WriteReport 131005 @() @(, @($CertResults))
				} 
			} else {
				WriteReport 130010 @() @()
			}
		}
	}
}

Write-Host "Evaluating sensor condition..."
"########################### PROXY SETTINGS ################################" | Out-File $connectivityCheckFile -append
CheckProxySettings
Test-CommandVerified "netsh.exe"
[array]$netshproxyoutput = (netsh.exe winhttp show proxy)
$netshproxyoutput | Out-File $connectivityCheckFile -append
if ($netshproxyoutput[3]) {
	Write-Report -section "devInfo" -subsection "SystemWideProxy" -displayname "System-wide WinHTTP proxy" -value $netshproxyoutput[3]
}

if ($TelemetryProxyServer) {
	if ($TelemetryProxyServer.contains(" ")) {
		WriteReport 131002 @() @()
	}

	$PreferStaticProxyForHttpRequest = Get-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows Advanced Threat Protection" -Value "PreferStaticProxyForHttpRequest"
	If ($PreferStaticProxyForHttpRequest -eq "1") {
		Write-Report -section "EDRCompInfo" -subsection "SenseProxyConfig" -displayname "Preferred Telemetry Proxy Server enabled" -value "YES"
	} else {
		Write-Report -section "EDRCompInfo" -subsection "SenseProxyConfig" -displayname "Preferred Telemetry Proxy Server enabled" -value "NO"
	}
}

# Check if device was onboarded using VDI script and dump relevant information
If (Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging" -Value "VDI") {
	$IsVDI = $true
	Write-output "`r`n######################## VDI Information #########################" | Out-File $connectivityCheckFile -Append
	$StartupFolder = (get-ChildItem -Recurse -path $env:SystemRoot\system32\GroupPolicy\Machine\Scripts\Startup) 
	WriteReport 110003 @() @(, @($StartupFolder))
}

If (!$OSPreviousVersion) {
	# Test for DiagTrack listener on RS4 and earlier Win10 builds or SenseOms for Down-level OS, and export network proxy Registry settings
	Write-output "`r`n#################### Data Collection Registry setting #####################" | Out-File $connectivityCheckFile -Append

	$DiagTrackSvcStartType = (get-service -name diagtrack).StartType 
	If ($DiagTrackSvcStartType -eq "Disabled") {
		WriteReport 141001 @() @()
	}
	Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -ErrorAction SilentlyContinue | Out-File $connectivityCheckFile -Append
}
if ((!$OSPreviousVersion) -and ($buildNumber -le "17134") -and ($OSEditionName -eq "Client")) {
	Write-output "`r`n######################## DiagTrack Listener check #########################" | Out-File $connectivityCheckFile -Append
	Test-CommandVerified "logman.exe"
	$DiagTrackListener = &logman Diagtrack-Seville-Listener -ets
	$DiagTrackListener > "$resultOutputDir\SystemInfoLogs\DiagTrackListener.txt"
	$SevilleProv = $DiagTrackListener | Select-String "CB2FF72D-D4E4-585D-33F9-F3A395C40BE7"
	if ($SevilleProv -eq $null) {
		WriteReport 141002 @() @()
	}
	else {
		WriteReport 140004 @() @()
	}	
}
elseif (($OSPreviousVersion) -and (!$ASM)) {
	Write-output "`r`n######################## SenseOms Listener check #########################" | Out-File $connectivityCheckFile -Append
	Test-CommandVerified "logman.exe"
	$SenseOmsListener = &logman SenseOms -ets
	$SenseOmsListener > "$resultOutputDir\SystemInfoLogs\SenseOmsListener.txt"
	$OmsProv = $SenseOmsListener | Select-String "CB2FF72D-D4E4-585D-33F9-F3A395C40BE7"
	if ($OmsProv -eq $null) {
		WriteReport 141003 @() @()
	}
	else {
		WriteReport 140006 @() @()
	}	
}

if (!$OSPreviousVersion) {
	"################ Connectivity Check for Live Response URL ################" | Out-File $connectivityCheckFile -append
	$TestLR1 = TelnetTest "global.notify.windows.com" 443
	$TestLR2 = TelnetTest "client.wns.windows.com" 443
	$TestLR1 | Out-File $connectivityCheckFile -append
	$TestLR2 | Out-File $connectivityCheckFile -append
	# the abvoe test does not support proxy configuration as-is
	#if (($TestLR1 -notlike "Successfully connected*") -Or ($TestLR2 -notlike "Successfully connected*")) {
	#	Write-ReportEvent -section "events" -severity "Warning" -check "LRcheckFail" -id XXXXX -checkresult ( `
	#	"Failed to reach Windows Notification Service URLs required for Live Response.`r`n" `
	#	+ "Please ensure Live Response URLs are not blocked.`r`n" `
	#	+ "For more information, see: https://docs.microsoft.com/en-us/windows/uwp/design/shell/tiles-and-notifications/firewall-allowlist-config")
	#} elseif (($TestLR1 -like "Successfully connected*") -and ($TestLR2 -like "Successfully connected*")) {
	#	Write-ReportEvent -section "events" -severity "Informational" -check "LRcheckOK" -id XXXXX -checkresult ( `
	#	"Windows Notification Service URLs required for Live Response are reachable.`r`n")
	#}
}

# Test for existence of unsupported ProcessMitigationOptions and dump IFEO
# Reference https://docs.microsoft.com/en-us/windows/security/threat-protection/override-mitigation-options-for-app-related-security-policies
Get-childItem -Recurse "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue | Out-File "$resultOutputDir\SystemInfoLogs\IFEO.txt"
Get-Item "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\kernel" | Out-File "$resultOutputDir\SystemInfoLogs\SessionManager.txt"
if ((!$OSPreviousVersion) -and ($buildNumber -le "17134") -and ((Get-Service DiagTrack).Status -eq "StartPending")) {
	If (Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Value "MitigationOptions") {
		Write-output "`r`n######################## ProcessMitigations check #########################" | Out-File $connectivityCheckFile -Append
		WriteReport 142007 @() @()
		Test-CommandVerified "reg.exe"
		&Reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "$resultOutputDir\SystemInfoLogs\KernelProcessMitigation.reg" /y 2>&1 | Out-Null
		Test-CommandVerified "reg.exe"
		&Reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" "$resultOutputDir\SystemInfoLogs\SvchostProcessMitigation.reg" /y 2>&1 | Out-Null
	}	
}

# Test for existence of faulty EccCurves SSL settings and gather additional useful reg keys for troubleshooting
# Refernce https://docs.microsoft.com/en-us/windows-server/security/tls/manage-tls
$SSLSettings = "$resultOutputDir\SystemInfoLogs\SSL_00010002.txt"
$SCHANNEL = "$resultOutputDir\SystemInfoLogs\SCHANNEL.txt"
Get-ChildItem "HKLM:SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL" -Recurse -ErrorAction silentlycontinue | Out-File $SSLSettings
Get-ChildItem "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Recurse -ErrorAction silentlycontinue | Out-File $SCHANNEL
if ((Get-Content $SSLSettings) -like "*EccCurves : {}*") {
	WriteReport 132006 @() @()
} 

# Test if running on unsupported Windows 10 or 2012 RTM OS or Windows Server 2008 R2 and not on Azure
if ((($OSProductName -match 'Windows 10') -and ($OSBuild -lt "14393")) -or ($OSBuild -eq "9200") -or ((($OSBuild -eq 7601) -and ($OSEditionID -match 'Server')) -and (-not (IsAzureVm)))) {
	Write-output "`r`n######################## Unsupported Win OS check #########################" | Out-File $connectivityCheckFile -Append
	WriteReport 112002 @(, @($OSBuild)) @()
}

#Push Azure resource string to results file if exists:
$AzureResourceId = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging" -Value AzureResourceId
if ($AzureResourceId) { 
	Write-Report -section "devInfo" -subsection "AzureResourceId" -displayname "Azure Resource Id" -value $AzureResourceId
}
#Collect MDC Logs
if (Test-Path $env:windir\Packages\Plugins\Microsoft.Azure.AzureDefenderForServers.MDE.Windows) {
	New-Item -ItemType Directory -Path "$resultOutputDir\MDC" -ErrorAction SilentlyContinue | out-Null
	# Test if MDC ARC agent exists and collect related logs:
	$azcmagentCmd = Join-Path "$env:ProgramFiles\AzureConnectedMachineAgent" "azcmagent.exe"
	if (Test-Path -Path "$azcmagentCmd") {
		$MDCLog = Join-Path "$resultOutputDir\MDC" "ArcLogs.zip"
		Test-AuthenticodeSignature "$azcmagentCmd"
		&$azcmagentCmd logs -o "$MDCLog"
	}
	# Test if MDC ARM JSON exists and collect related logs:
	$MDCJSON = (Get-Item C:\Packages\Plugins\Microsoft.Azure.AzureDefenderForServers.MDE.Windows\*\HandlerEnvironment.json -ErrorAction SilentlyContinue)
	if (test-path $MDCJSON.FullName -pathtype leaf) {
		$MDCJSONData = (Get-Content $MDCJSON -raw) | ConvertFrom-Json
		$MDClogFolder = $MDCJSONData.handlerEnvironment.logFolder
		Copy-Item -Path "$MDClogFolder\*" -Destination "$resultOutputDir\MDC" -Recurse -Exclude @('*.msi') -ErrorAction SilentlyContinue
	}
	Copy-Item -Path (Get-Item C:\Packages\Plugins\Microsoft.Azure.AzureDefenderForServers.MDE.Windows\*\Status) -Destination "$resultOutputDir\MDC\Status" -Recurse -Exclude @('*.msi') -ErrorAction SilentlyContinue
	Copy-Item -Path (Get-Item C:\Packages\Plugins\Microsoft.Azure.AzureDefenderForServers.MDE.Windows\*\Install-*) -Destination "$resultOutputDir\MDC\" -Exclude @('*.msi') -ErrorAction SilentlyContinue
}

# Test for WSAEPROVIDERFAILEDINIT event related to LSP in netsh winsock catalog
if (!$OSPreviousVersion) {
	$EventError = Get-MatchingEvent Microsoft-Windows-UniversalTelemetryClient 29 "2147952506"
	if ($EventError) {
		Write-output "`r`n############################ Winsock error check ###############################" | Out-File $connectivityCheckFile -Append
		if ((Get-ProcessMitigation -Name MsSense.exe).ExtensionPoint.DisableExtensionPoints -eq "ON") {
			WriteReport 140005 @() @()
			"This disables various extensibility mechanisms that allow DLL injection. No further action required." | Out-File $connectivityCheckFile -Append
		}
  else {
			WriteReport 142008 @() @()
			$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
			Test-CommandVerified "netsh.exe"
			$Winsock = &netsh winsock show catalog
			$winsock | Out-File $resultOutputDir\SystemInfoLogs\winsock_catalog.txt
			if ($winsock -like "*FwcWsp64.dll*") {
				WriteReport 142009 @() @()
			}
		}
	}
}

# Dump FSUTIL USN queryjournal output to log
$DriveLetters = (Get-PSDrive -PSProvider FileSystem) | Where-Object { $_.Free -ne $null } | ForEach-Object { $_.Name }
Write-output "`r`n######################## FSUTIL USN journal query #########################" | Out-File $connectivityCheckFile -Append
foreach ($DriveLetter in $DriveLetters) {
	Write-output "USN query journal output for Drive: " $DriveLetter | Out-File $connectivityCheckFile -Append
	Test-CommandVerified "fsutil.exe"
	&fsutil usn queryjournal ("$DriveLetter" + ":") |  Out-File $connectivityCheckFile -Append
}

# Dump AddRemovePrograms to file
$uninstallKeys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
$dstfile = "$resultOutputDir\SystemInfoLogs\AddRemovePrograms.csv"
GetAddRemovePrograms $uninstallKeys | Export-Csv -Path $dstfile -NoTypeInformation -Encoding UTF8
$uninstallKeysWOW64 = Get-ChildItem HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue
$dstfileWOW64 = "$resultOutputDir\SystemInfoLogs\AddRemoveProgramsWOW64.csv"
if ($uninstallKeysWOW64) {
	GetAddRemovePrograms $uninstallKeysWOW64 | Export-Csv -Path $dstfileWOW64 -NoTypeInformation -Encoding UTF8
}

# Check for issues with certificate store or time skew
if (($OSPreviousVersion) -and (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Operations Manager.evtx')) {
	$EventError = Get-MatchingEvent "Service Connector" 3009 "80090016"
	if ($EventError) {
		Write-output "`r`n###################### MMA certificate error check #########################" | Out-File $connectivityCheckFile -Append
		WriteReport 122006 @() @()
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
	}
	$EventError = Get-MatchingEvent "Service Connector" 4002 "ClockSkew"
	if ($EventError) {
		Write-output "`r`n######################### Client TimeSkew check ############################" | Out-File $connectivityCheckFile -Append	
		WriteReport 122007 @() @()
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
	}
}

# Check for issues with Default paths or reg keys
# Taken from amcore/wcd/Source/Setup/Manifest/Windows-SenseClient-Service.man
$DefaultPaths = 
@{
	Name = "Default MDE Policies key"
	Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection"
},
@{
	Name = "Default MDE Sensor Service key"
	Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Sense"
},
@{
	Name = "Default MDE directory path"
	Path = "$env:ProgramFiles\Windows Defender Advanced Threat Protection"
},
@{
	Name = "Default MDE ProgramData directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection"
},
@{
	Name = "Default MDE Cache directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Cache"
},
@{
	Name = "Default MDE Cyber directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Cyber"
},
@{
	Name = "Default MDE Temp directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Temp"
},
@{
	Name = "Defalt MDE Trace directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Trace"
}

if ((!$OSPreviousVersion) -and (!$ARM) -and ($buildNumber -ge "15063")) {
	foreach ($item in $DefaultPaths) {
		if (!(Test-Path $item.Path)) {
			$MissingDefaultPath += $("`r`n" + $item.Name)
			$MissingDefaultPath += $("`r`n" + $item.Path + "`n")
		}
	}
	if ($MissingDefaultPath) {
		Write-Host -BackgroundColor Red -ForegroundColor Yellow "Default paths are missing. Please ensure the missing path(s) exist and have not been renamed:"
		Write-Host $MissingDefaultPath
		Write-output "`r`n###################### Missing default path check #########################" | Out-File $connectivityCheckFile -Append
		WriteReport 122003 @(, @($MissingDefaultPath)) @(, @($DefaultPaths[5].Path))
	}
}

# Check if SENSE cannot be started due to crash
if ((!$OSPreviousVersion) -or ($MDfWS)) {
	$EventError = (Get-MatchingEvent "Application Error" 1000 "TelLib.dll")
	if ($EventError) {
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
		$Exception = ($EventError.message -split '\n')[2]
		[DateTime]$Timeframe = ($EventError.TimeCreated)
        [DateTime]$DaysAgo = (Get-Date).AddDays(-2)
        if (($DaysAgo -gt $Timeframe) -and ((Get-Service SENSE).Status -eq "Running")) {
			Write-output "`r`n Crash Event was detected but it is older than 2 days while SENSE service is running as expected now" | Out-File $connectivityCheckFile -Append
        } else {
            WriteReport 122039 @(, @($Exception)) @()
        }
	}
	# Check for PPL protection 
	Test-CommandVerified "sc.exe"
	#Checking only for ": WINDOWS" string as a quick fix for this test on non-English OSes
	$qprotection = (&sc.exe qprotection sense)
	if ($qprotection[1].contains(": WINDOWS")) {
		WriteReport 110005 @() @()
	} elseif (($qprotection[1].contains(": ANTIMALWARE")) -And ($buildNumber -eq "14393") -And ($OSEditionName -match "Client")) {
		WriteReport 110005 @() @()
	} else {
		WriteReport 112004 @(, @($qprotection[1])) @()
	}
}

# Check if onboarding failed with Access denied due to tampering with registry permissions
if ((Test-Path -Path "$env:ProgramFiles\Windows Defender Advanced Threat Protection\MsSense.exe") -and !(Get-Process -Name MsSense -ErrorAction silentlycontinue)) {
	$EventError = (Get-MatchingEvent Microsoft-Windows-SENSE 43 "80070005")
	if ($EventError) {
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
		$SenseRegAclList = (Get-Acl -Path HKLM:\System\CurrentControlSet\Services\Sense | Select-Object -ExpandProperty Access) 
		$SenseRegAclSystem = $SenseRegAclList | Where-Object identityreference -eq "NT AUTHORITY\SYSTEM" 
		if (($SenseRegAclSystem.RegistryRights -ne "FullControl") -or ($SenseRegAclSystem.AccessControlType -ne "Allow")) {
			[string]$cleanAclOutput = $SenseRegAclSystem | Out-String -Width 250
			WriteReport 122015 @() @(, @($cleanAclOutput))	
		}
	}
} 

# Check if onboarding via SCCM failed due to registry issues
if (test-path -path $env:windir\ccm\logs\DcmWmiProvider.log) {
	$SCCMErr = Select-String -Path $env:windir\ccm\logs\DcmWmiProvider.log -Pattern 'Unable to update WATP onboarding' | Sort-Object CreationTime -Unique
	if ($SCCMErr) { 
		Write-output "`r`n############################ SCCM onboarding check ###############################" | Out-File $connectivityCheckFile -Append
		Copy-Item -path $env:windir\ccm\logs\DcmWmiProvider.log -Destination "$resultOutputDir\EventLogs\DcmWmiProvider.log"
		WriteReport 122004 @() @(, @($SCCMErr))
	}
}

# Check if onboarding via MMA failed due to unsupported OS env
if (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Operations Manager.evtx') {
	$EventError = Get-MatchingEvent "HealthService" 4509 "NotSupportedException"
	if (($EventError) -And (!$IsOnboarded)) {
		Write-output "`r`n########################## MMA unsupported OS check ##########################" | Out-File $connectivityCheckFile -Append
		WriteReport 112020 @() @()
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
	}
}

# Check if running latest SCEP edition for downlevel OS
$ImageState = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" -Value "ImageState")
$EventError = Get-MatchingEvent Microsoft-Windows-SENSE 19 "OOBE"
if (($ImageState -ne "IMAGE_STATE_COMPLETE") -and $EventError) {	
	Write-output "`r`n############################ ImageState check ###############################" | Out-File $connectivityCheckFile -Append	
	$ImageState | Out-File $connectivityCheckFile -Append
	$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
	WriteReport 122041 @(, @($ImageState)) @()
}

# Check if ImageState in registry is unhealthy and event log shows OOBE issues blocking onboarding
$SCEP = GetAddRemovePrograms $uninstallKeys | Where-Object { $_.DisplayName -like "*Endpoint Protection" }
if ($SCEP -And ("$env:ProgramFiles\Microsoft Security Client\")) {	
	if ([version](($SCEP).DisplayVersion) -lt [version]"4.10.209.0") {
		Write-output "`r`n############################ SCEP Client check ###############################" | Out-File $connectivityCheckFile -Append	
		WriteReport 122008 @(, @($SCEP)) @()
	}
}

# Check if ImagePath has been tampered with prior to onboarding and this is blocking onboarding
if ((Get-Service -Name sense -ErrorAction SilentlyContinue).Status -eq "Stopped") {
	$ImagePath = (Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" -Value "ImagePath")
	$EventError2 = Get-MatchingEvent WDATPOnboarding 15 "System error 2 has occurred"
	$EventError577 = Get-MatchingEvent WDATPOnboarding 15 "System error 577 has occurred"
	if ($EventError2 -Or $EventError577) {	
		Write-output "`r`n############################ ImagePath check ###############################" | Out-File $connectivityCheckFile -Append	
		Write-output "`r`n ImagePath value in registry may have been tampered prior to onboarding:" | Out-File $connectivityCheckFile -Append
		$ImagePath | Out-File $connectivityCheckFile -Append
		$EventError2 | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
		$EventError577 | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
		WriteReport 122043 @(, @($ImagePath)) @()
	}
}

# Detect Secure Channel misconfigurations
$CiphersLog = "$resultOutputDir\SystemInfoLogs\EnabledCiphers.txt"
$TLSEnabled = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Value Enabled
$ECDHEnabled = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" -Value Enabled
$Ciphers = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Value Functions
if ($Ciphers) {
	[Array]$CipherArray = $Ciphers.Split(",")
	$CipherArray | Out-File $CiphersLog
	[Array]$MinCiphers = @('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384','TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256','TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256','TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384','TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256')
	#$ComparedCiphers = Compare-Object -IncludeEqual -ExcludeDifferent $MinCiphers $CipherArray
    foreach($Cipher in $CipherArray){
      foreach($MinCipher in $MinCiphers){
       if($Cipher -match $MinCipher){
        "match found: $minCipher" | Out-File $CiphersLog -append
       }
      }
    }
	if (($Ciphers) -And !((Get-content $CiphersLog) -like "match found*")) {
        WriteReport 122044 @() @()
	}
}
If (!($TLSEnabled -eq $null) -and $TLSEnabled -eq "0") {
    WriteReport 122045 @() @()
}
If (!($ECDHEnabled -eq $null) -and ($ECDHEnabled -eq "0")) {
    WriteReport 122046 @() @()
}

Write-Host "Evaluating certificate pinning for MDE URLs. This may take longer to run if URLs are blocked..."
Write-output "`r`n################## MDE certificate chain validation  ####################"  | Out-File $connectivityCheckFile -Append 
# List of certificate Roots expected in the chain
[string]$ExpectedMSRoot = "CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
[string]$ExpectedDCRootG2 = "CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US"
[string]$ExpectedDCRootCA = "CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US"
[string]$ExpectedBCRoot = "CN=Baltimore CyberTrust Root, OU=CyberTrust, O=Baltimore, C=IE"
Foreach ($endpoint in ((Get-Content $EndpointList) -like "https://*")) {
    $URL =  ($endpoint -Replace 'NoPinning', "").Trim()
    $cert = (Get-EndpointCertificate $URL -UseProxy -ProxyAddress $Proxy -TrustAllCertificates -ErrorAction SilentlyContinue)
	if ($cert) {
		# Build the certificate chain from the file certificate
        [string]$Issuer = $cert.Issuer
		$chain = $null
		$chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain -ErrorAction SilentlyContinue
		$chain.ChainPolicy.RevocationMode="NoCheck"
		$BuildChain = $chain.Build($cert)
		if (!$BuildChain) {
			$AIA = (Get-CertificateURL $cert).AIA
			if ($AIA) {
				$CACert = (Get-EndpointCertificate "$AIA" -UseProxy -ProxyAddress $Proxy -ErrorAction SilentlyContinue)
			}
			If ($CACert) {
				$chain.Dispose()
				$chain.ChainPolicy.ExtraStore.Add($CACert) > $null
				Write-output "Note: Intermediate CA was fetched $AIA as initial build chain failed" | Out-File $connectivityCheckFile -Append
				$BuildChain = $chain.Build($cert)
			}
		}
		if ($chain.ChainElements.Count -gt 2) {
			[string]$root = $chain.ChainElements[2].Certificate.Issuer
		} else {
			[string]$root = $chain.ChainElements[1].Certificate.Issuer
		}
		$BuildChain = $null
		$chain.Dispose()
    }
	# Write warning if cert root is not the expected Root or CA issuer
    if ($issuer) {
	    Write-output "`r`nThe cert issuer for $URL is :" $Issuer | Out-File $connectivityCheckFile -Append
    }
	if (!$root) {
			Write-output "The root issuer for $URL was not detected" | Out-File $connectivityCheckFile -Append
			if ($Issuer) {
				Write-output "Failed to fetch root CA chain for $URL the CA issuer that was detected is:" $Issuer  | Out-File $connectivityCheckFile -Append
				WriteReport 131028 @(@($URL, $Issuer)) @()
			} else {
				Write-output "Failed to check certificate issuer for $URL " | Out-File $connectivityCheckFile -Append
			}
		} else {
			Write-output "The root issuer for $URL is :" $root  | Out-File $connectivityCheckFile -Append
			if ($Issuer -like "CN=Microsoft Secure Server CA*") {
				if (($root) -ne $ExpectedMSRoot) {    
					Write-output "The root issuer for $URL is :" $root  | Out-File $connectivityCheckFile -Append
					WriteReport 132026 @(@($URL, $root)) @()
				}
			} elseif ($Issuer -like "CN=Microsoft Azure*") {
				if (($root) -ne $ExpectedDCRootG2) {        
					Write-output "The root issuer for $URL is :" $root  | Out-File $connectivityCheckFile -Append
					WriteReport 132026 @(@($URL, $root)) @()
				}
			} elseif ($Issuer -like "CN=DigiCert SHA2*") {
				if (($root) -ne $ExpectedDCRootCA) {        
					Write-output "The root issuer for $URL is :" $root  | Out-File $connectivityCheckFile -Append
					WriteReport 132026 @(@($URL, $root)) @()
				}
			} elseif ($Issuer -like "CN=Microsoft RSA*") {
				if (($root) -ne $ExpectedBCRoot) {        
					Write-output "The root issuer for $URL is :" $root  | Out-File $connectivityCheckFile -Append
					WriteReport 132026 @(@($URL, $root)) @()
				}
			} else {
				Write-output "The issuer for $URL was fetched but was not expected :" $Issuer  | Out-File $connectivityCheckFile -Append
				WriteReport 132027 @(@($URL, $Issuer)) @()
			}
		}
}

Write-output "`r`n################## MDE CommandLine usage information ####################"  | Out-File $connectivityCheckFile -Append 
[environment]::GetCommandLineArgs() | Out-File $connectivityCheckFile -Append

#Dump MDM related logs and data to results
if (Get-Command  $env:windir\system32\MdmDiagnosticsTool.exe -ErrorAction SilentlyContinue) {
	New-Item -ItemType Directory -Path "$resultOutputDir\MDM" -ErrorAction SilentlyContinue | out-Null
	$MDMLogs = Join-Path "$resultOutputDir\MDM" "MDMLogs.zip"
	Test-AuthenticodeSignature $env:windir\system32\MdmDiagnosticsTool.exe
	Start-Process -NoNewWindow -wait $env:windir\system32\MdmDiagnosticsTool.exe -ArgumentList "-area `DeviceEnrollment;DeviceProvisioning;Autopilot` -zip `"$MDMLogs`""
}

Write-Host "Generating HealthCheck report..."
GenerateHealthCheckReport

# collect Mde Configuration Manager logs reg and Events
if ((!$OSPreviousVersion) -or ($MDfWS)) {
	get-MdeConfigMgrLog
}

# Generate AV perf report if relevant ETL exists and device supports perf reporting
$AVTrace = "$resultOutputDir\merged.etl"
if (((Test-Path -Path "$AVTrace" -ErrorAction SilentlyContinue) -And (Get-Command Get-MpPerformanceReport -ErrorAction SilentlyContinue)) -And $WDPerfTraceA) {
    Write-Host "Generating Antivirus performance report..."
	Get-MpPerformanceReport -Path "$AVTrace" -TopPaths:10 -TopFiles:10 -TopProcesses:10 -TopScans:10 -TopProcessesPerFile:3 -TopScansPerProcessPerFile:3 -TopPathsDepth:3 -TopScansPerPath:3 | Out-File "$resultOutputDir\DefenderAV\PerfReport.txt"
}

# Collect base address for PPL processes to allow stack analysis
[Array]$AVDlls = @('MpRtp.dll','mpengine.dll','MpCommu.dll','MsClient.dll','MpDlp.dll','MpOAV.dll','MpSvc.dll','MpSenseComm.dll','MpCommon.dll',"MpClient.dll")
if ([Environment]::Is64BitOperatingSystem) {
	$ModuleFinder = Join-Path $ToolsDir "LoadedModuleFinderX64.exe"
}
else {
	$ModuleFinder = Join-Path $ToolsDir "LoadedModuleFinderX86.exe"
}
$MsSenseProc = (Get-Process -Name MsSense -ErrorAction SilentlyContinue)
$MsMpEngProc = (Get-Process -Name MsMpEng -ErrorAction SilentlyContinue)
$ResultJson = "$resultOutputDir\SystemInfoLogs\ModuleInfo.Json"
$ModuleFinderLog = "$OutputDir\ModuleFinderLog.txt"
$json = @()
if ($MsSenseProc) {
	$ID = $MsSenseProc.Id
	Test-AuthenticodeSignature $ModuleFinder
	Start-Process -WindowStyle minimized -PassThru -wait $ModuleFinder -ArgumentList "$ID MsSense.dll" -RedirectStandardOutput $ModuleFinderLog | Out-Null
	[string]$LogOutput = (Get-Content $ModuleFinderLog -raw)
	if ($LogOutput -notlike "*Failed*") {
        $json += (ConvertFrom-Json $LogOutput)
	}
}
if ($MsMpEngProc) {
	$ID = $MsMpEngProc.Id
	foreach ($AVDll in $AVDlls) {
		Test-AuthenticodeSignature $ModuleFinder
		Start-Process -WindowStyle minimized -PassThru -wait $ModuleFinder -ArgumentList "$ID $AVDll" -RedirectStandardOutput $ModuleFinderLog | Out-Null
		[string]$LogOutput = (Get-Content $ModuleFinderLog -raw)
		if ($LogOutput -notlike "*Failed*") {
            $json += (ConvertFrom-Json $LogOutput)
		}
	}
}
$json | ConvertTo-Json | Out-File -FilePath $ResultJson -Encoding utf8

# Check if MSinfo is still running and allow to run until timeout is reached
EndTimedoutProcess "msinfo32" 2

[version]$PSMinVer = '2.0.1.1'
if ( $PSVersionTable.PSVersion -gt $PSMinVer) {
	Write-Host "Compressing results directory..."
	Add-Type -Assembly "System.IO.Compression.FileSystem";
	[System.IO.Compression.ZipFile]::CreateFromDirectory($resultOutputDir, $outputZipFile)
	if ([System.IO.File]::Exists($outputZipFile)) {
		if (!($system -or $RemoteRun)) {
			[string]$ZipDate = (Get-Date -Format "yyddMMhhmm")
			$TimeStampZip = "MDEClientAnalyzerResult_$ZipDate.zip"
			Rename-Item -Path "$outputZipFile" -NewName $TimeStampZip
			Write-Host "Result is available at: " $TimeStampZip
		} else {
			Write-Host "Result is available at: " $outputZipFile
		}
	}
}
else {
	Write-Host "Result is available at: " $resultOutputDir
}

# Open HTML result file if running with interactive session
if (!($system -or $RemoteRun) -and ($HtmOutputFile)) {
	try {
		Start-Process -FilePath $HtmOutputFile -ErrorAction SilentlyContinue -ErrorVariable OpenErrVar
		If (!$OpenErrVar) {
			Write-Host -ForegroundColor Green "Client analysis results opened in browser"
		}
	} catch {
		Write-Host "Please open $HtmOutputFile from a device with a web browser for a quick overview of the device health"
	}
}
# SIG # Begin signature block
# MIIn4AYJKoZIhvcNAQcCoIIn0TCCJ80CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAO2cCeWrv5niM+
# eBrBkAkuETkzy34kAO/vK2sDWzkHD6CCDZcwggYVMIID/aADAgECAhMzAAADz7d0
# vUQxddCTAAAAAAPPMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjQwMjIyMTkwNzUzWhcNMjUwMjE5MTkwNzUzWjCBlDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE+MDwGA1UEAxM1TWlj
# cm9zb2Z0IFdpbmRvd3MgRGVmZW5kZXIgQWR2YW5jZWQgVGhyZWF0IFByb3RlY3Rp
# b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDwAPmxMmR9a92NX/Lv
# 2PmaySDZqZUANxu28n+GqAuhMRrC8/v5HrKeebKt+6wqnp28fO1jvJ5OlBIrirN7
# KUiSUH86mvByCFnIwIkKcusZbgEF+v15S0jRExa5C9lC+kDVYtlSCnPEdx/tkKLN
# QQMmSroC3baj7y0WIvBfZ1l4x2qyDhFC/5plmMfD8TSfl3sN4twBiXAcpJ/SES50
# QbLahl/MTsVA2UEo7ygPJIrmci8wvD0Kt1pfkwbB3eiK4Vatr0VoJujRucjGT322
# m/9vH6p4Y5suUJMo9196/ze8hA8bqH+5NdU+DeRLrV/UzVat1Xs/Wm6kPK8GgTPL
# H+M9AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBggrBgEFBQcDAwYKKwYBBAGCN0wv
# ATAdBgNVHQ4EFgQU10vjUl0bvgJvpCFtGT8ECb23+CAwRQYDVR0RBD4wPKQ6MDgx
# HjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEWMBQGA1UEBRMNNDUxODk0
# KzUwMjA2OTAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8E
# TTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9N
# aWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBR
# BggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAw
# DQYJKoZIhvcNAQELBQADggIBAHcmfqgz/boPmZhEOAtYI5wj3mRicbSQwDQcGZfK
# 8I1WdILE80dhNGqgtVvxO5v5/PyjBJY5HV9HxxCzdVVj60PYAwzoyfTIZF+0hPrh
# l6JkjfckCiy9qsONVkL6SDJH6a+Xf4penA2ge9WM3XLR5BUQH538wx4w+VswV1QX
# hKsAMGAvxBG8EzIFTMRXMoKy/RYZ1FSig96mdJRb9Zh4o37XcyAgSxlbiv50vu3X
# MGNXRZJY0/PdB6Du55mI0WfJDaKBJuDShBMLOjDRX8UEWjy3rqGTjVVLYhK4mWq6
# I/1bIZlgkKBFnUMFbVvtSWDP13FgyGIVDk5YB5s2XmSC6hTfXAHakSpLfFeZ1VK5
# /pRMdhxEenleDdsgksd9idt+U7YxgjZ6gfdGuWgj9ZNi8Ef4ILoA5fkUGIIP14a7
# j2SUsaYvJKw/5aiVHRza+Q9gbDpNcsR5WbhhcSAnkFmi7ZkmJKHVlkUqAUDbP8WB
# yz/bq6m/HCHELfFfsG4HMvOfLSTVhKfXPptRzN4N5m2AZX423KM2zhqzPjCWNWce
# /jqhUKtbyMuPPqqo+eaoYi+ZzaEqirxAmPF6Nz3VIncZppzm451L2Uu05NwN1T5m
# ZbiGW2WW1Iz50ofUKACCqThHMtSh4fOdq0OiKaqQz3S5BGdoXdPPOKgXxOtfaMpr
# C3SrMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWlj
# cm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4
# MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBD
# QSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3Y
# bqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUB
# FDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnbo
# MlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT
# +OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuy
# e4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEh
# NSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2
# z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3
# s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78Ic
# V9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E
# 11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5P
# M4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcV
# AQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBL
# hklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggr
# BgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNS
# b29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsG
# AQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwA
# ZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0G
# CSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDB
# ZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc
# 8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYq
# wooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu
# 5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWI
# UUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXh
# j38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yH
# PgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtI
# EJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4Guzq
# N5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgR
# MiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQ
# zTGCGZ8wghmbAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEC
# EzMAAAPPt3S9RDF10JMAAAAAA88wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcN
# AQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUw
# LwYJKoZIhvcNAQkEMSIEIP6cXofHNaEj82va4w6rVLzUHAXYLe5E8lupxsDiwRQV
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEA4PPyhmSuoVKm
# bwjG0YHcnyONzVXXuAOlcH712GRlyLusFAc9fdILfr7X9DFqex3A/m+82HN8War8
# CjoRV1Xi5cuqQ2I5DD6PSIQAhtzYyMsrvEsPlqXzu0e+DgnpoxBblWEEPacvFkUR
# UNQ/y9P8nofyIqvEsmjZFcJSNg011ec8PIultluCmWz+LW+jjFLJNzL3NPehD7pj
# xp5xAYRPgTB5Oimd00nLM5dn5lFX1s3TUZmUTKTzpx7CR58NQq5l4nsBYR9sK40p
# TLrV0TtvDFXtHHaRaUBK/Dh4NxU8perfsHqSqVlv66kIvLuB9SHMqC4i2BHYPIKi
# +l8xpHnO9qGCFykwghclBgorBgEEAYI3AwMBMYIXFTCCFxEGCSqGSIb3DQEHAqCC
# FwIwghb+AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgE
# ggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCCLZ/FY9vEG
# SfnkDwOpuW9g2af6QJjaraGs+Tp6q1zctQIGZjOs1lb8GBMyMDI0MDUxMjExMDcz
# NC4wMTRaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25z
# IExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQwODItNEJGRC1FRUJB
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIReDCCBycw
# ggUPoAMCAQICEzMAAAHcweCMwl9YXo4AAQAAAdwwDQYJKoZIhvcNAQELBQAwfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjMxMDEyMTkwNzA2WhcNMjUw
# MTEwMTkwNzA2WjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVk
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpEMDgyLTRCRkQtRUVCQTElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAIvIsyA1sjg9kSKJzelrUWF5ShqYWL83amn3SE5JyIVP
# UC7F6qTcLphhHZ9idf21f0RaGrU8EHydF8NxPMR2KVNiAtCGPJa8kV1CGvn3beGB
# 2m2ltmqJanG71mAywrkKATYniwKLPQLJ00EkXw5TSwfmJXbdgQLFlHyfA5Kg+pUs
# JXzqumkIvEr0DXPvptAGqkdFLKwo4BTlEgnvzeTfXukzX8vQtTALfVJuTUgRU7zo
# P/RFWt3WagahZ6UloI0FC8XlBQDVDX5JeMEsx7jgJDdEnK44Y8gHuEWRDq+SG9Xo
# 0GIOjiuTWD5uv3vlEmIAyR/7rSFvcLnwAqMdqcy/iqQPMlDOcd0AbniP8ia1BQEU
# nfZT3UxyK9rLB/SRiKPyHDlg8oWwXyiv3+bGB6dmdM61ur6nUtfDf51lPcKhK4Vo
# 83pOE1/niWlVnEHQV9NJ5/DbUSqW2RqTUa2O2KuvsyRGMEgjGJA12/SqrRqlvE2f
# iN5ZmZVtqSPWaIasx7a0GB+fdTw+geRn6Mo2S6+/bZEwS/0IJ5gcKGinNbfyQ1xr
# vWXPtXzKOfjkh75iRuXourGVPRqkmz5UYz+R5ybMJWj+mfcGqz2hXV8iZnCZDBrr
# nZivnErCMh5Flfg8496pT0phjUTH2GChHIvE4SDSk2hwWP/uHB9gEs8p/9Pe/mt9
# AgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQU6HPSBd0OfEX3uNWsdkSraUGe3dswHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMC
# B4AwDQYJKoZIhvcNAQELBQADggIBANnrb8Ewr8eX/H1sKt3rnwTDx4AqgHbkMNQo
# +kUGwCINXS3y1GUcdqsK/R1g6Tf7tNx1q0NpKk1JTupUJfHdExKtkuhHA+82lT7y
# ISp/Y74dqJ03RCT4Q+8ooQXTMzxiewfErVLt8WefebncST0i6ypKv87pCYkxM24b
# bqbM/V+M5VBppCUs7R+cETiz/zEA1AbZL/viXtHmryA0CGd+Pt9c+adsYfm7qe5U
# MnS0f/YJmEEMkEqGXCzyLK+dh+UsFi0d4lkdcE+Zq5JNjIHesX1wztGVAtvX0DYD
# ZdN2WZ1kk+hOMblUV/L8n1YWzhP/5XQnYl03AfXErn+1Eatylifzd3ChJ1xuGG76
# YbWgiRXnDvCiwDqvUJevVRY1qy4y4vlVKaShtbdfgPyGeeJ/YcSBONOc0DNTWbjM
# bL50qeIEC0lHSpL2rRYNVu3hsHzG8n5u5CQajPwx9PzpsZIeFTNHyVF6kujI4Vo9
# NvO/zF8Ot44IMj4M7UX9Za4QwGf5B71x57OjaX53gxT4vzoHvEBXF9qCmHRgXBLb
# RomJfDn60alzv7dpCVQIuQ062nyIZKnsXxzuKFb0TjXWw6OFpG1bsjXpOo5DMHky
# sribxHor4Yz5dZjVyHANyKo0bSrAlVeihcaG5F74SZT8FtyHAW6IgLc5w/3D+R1o
# bDhKZ21WMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG
# 9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEy
# MDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIw
# MTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az
# /1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V2
# 9YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oa
# ezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkN
# yjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7K
# MtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRf
# NN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SU
# HDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoY
# WmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5
# C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8
# FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TAS
# BgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1
# Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUw
# UzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIB
# hjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fO
# mhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9w
# a2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggr
# BgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3
# DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEz
# tTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJW
# AAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G
# 82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/Aye
# ixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI9
# 5ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1j
# dEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZ
# KCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xB
# Zj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuP
# Ntq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvp
# e784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtQw
# ggI9AgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBM
# aW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpEMDgyLTRCRkQtRUVCQTEl
# MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsO
# AwIaAxUAHDn/cz+3yRkIUCJfSbL3djnQEqaggYMwgYCkfjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOnqsKkwIhgPMjAyNDA1
# MTIxMTA2MTdaGA8yMDI0MDUxMzExMDYxN1owdDA6BgorBgEEAYRZCgQBMSwwKjAK
# AgUA6eqwqQIBADAHAgEAAgIPzjAHAgEAAgIRwzAKAgUA6ewCKQIBADA2BgorBgEE
# AYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYag
# MA0GCSqGSIb3DQEBBQUAA4GBABMlsp2QN0gu+tlC3JCy6YIPb438LlQxC6+nNmBV
# tRjDsLOB8ATpb1dKM5uEB6DTYxMAGA/pIpOSnP7L9EHAxy18XkgURSCUYWiPt2VD
# r3FiMPifbOB7qX86bsyMK8VUMyFeLXy/NOcJePfmC6fxmyur36+jhg9fYPkJ+GSA
# oxJfMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAC
# EzMAAAHcweCMwl9YXo4AAQAAAdwwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3
# DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQguZvq+rH7kp753jHs
# uyMheC2VQeBfMj+qcEhHs33S4K8wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9
# BCBTpxeKatlEP4y8qZzjuWL0Ou0IqxELDhX2TLylxIINNzCBmDCBgKR+MHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB3MHgjMJfWF6OAAEAAAHcMCIE
# IC8ey+c2UU1u8F/rB7MdSxl1O3O9ax5gc6ZIV+rcEO92MA0GCSqGSIb3DQEBCwUA
# BIICADwwKs4eadONjJbEQJ9rQlKTOIonzMmHQhVNpfIj73IosKDqPlQE+BEbV46K
# yV2p96OpavtylZQtFtOF42ID+lIcWsLBwUAT0b9XT7i7nFhmAD/TWOgg5DXVuCIz
# UUhz965nqMvgNjy0NgB/2skt6HD7uVxVrM51PNkAgIY7k98aGoycyjj6EwZw9Aqo
# GBKTsfY77qgfFg71Dx9SlGXQwFotyWNRsMy0JhMEUYC6xEVo1GAFCePCUC4aoPp7
# Y05IDa7cheouBLaft9HAPIcxf0MsIvcbK0coRDyX4usaZ59G5cGbDjfHqvKLFJdr
# OuO3pCXuMv5lMOuvXqw8ClRr3S2hJE3nZTixXch2JMoRonIM9W6WtlJbQ7kdZJ7E
# kew8lRYKaVlxeCBkOFaNSiN9aD0I3aIGBmWWYlKSI+MQppLUYL1lY5tsV2NV0VPL
# VqBv5vnORw8kxaYI+A3Rx4sKzaT7ewVLZt3GnAHDfqAi3gWdDrbNpm63vcV4z/d1
# 0M8M9cPXqWB1FqLD12QXPF35UTtASjBsD/Z3nGvIGvzEP7bP9c4u15cHHB/veEq9
# 3hQ3dXXZkbOdZH9qW/60oKby8inr5wBmkI0fXhgYhhFN8pj+Jhj+dXIq3leWlmji
# +nFBa2HhFSFycXNx4jghZfzQ2GhZvWYuXDk66l5eL04t4KnS
# SIG # End signature block
