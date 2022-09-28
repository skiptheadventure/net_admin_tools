class IPAddress {
	[string]
	$InterfaceAlias
	[string]
	$IPAddress
	[byte]
	$PrefixLength
	[string]
	$MacAddress
	[string]
	$InterfaceAdminStatus
	[string]
	$InterfaceMediaConnectionState
	[string]
	$InterfaceStatus
	[string]
	$InterfaceLinkSpeed
	hidden
	$FullDuplex

	hidden $_InterfaceDuplex = $($this | Add-Member ScriptProperty 'InterfaceDuplex' `
		{
			# get
			switch ($this.FullDuplex) {
				$true {"Full"}
				$false {"Half"}
				default {""}
			}
		}
	)
}

function ConvertFrom-F5Cookie {
	Param(
		$Cookie
	)
	
	$IPArray=('{0:X}' -f [int]($Cookie.Split("."))[0]) -split '([A-Z0-9]{2})' | Where-Object{$_ -ne ""}| ForEach-Object{[uint32]"0x$_"}
	[array]::Reverse($IPArray)
	$IP = $IPArray -join "."
	$PortArray = ('{0:X}' -f [int]($Cookie.Split("."))[1]).ToCharArray()
	[array]::Reverse($PortArray)
	$PortHex = $PortArray -join ""
	$Port = [uint32]"0x$PortHex"
	$Server = "$IP`:$Port"
	return $Server
}
function ConvertFrom-F5Config {
	[CmdletBinding()]
	Param (
		[parameter(
			Mandatory         = $false,
			ValueFromPipeline = $true,
			ParameterSetName = 'Direct')]
		$Text,
		[parameter(
			Mandatory         = $false,
			ValueFromPipeline = $true,
			ParameterSetName = 'File')]
		$Path,
		[parameter(
			Mandatory         = $false,
			ParameterSetName = 'Direct')]
		[parameter(
			ParameterSetName = 'File')]
		$FilterParameter,
		[parameter(
			Mandatory         = $false,
			ParameterSetName = 'Direct')]
		[parameter(
			ParameterSetName = 'File')]
		$FilterValue
	)
	
	$ltms = @()
	$Groups = @()
	$Properties = @()
	
	if ($Path -ne '' -and $null -ne $Path) {
		try {
			$Text = Get-Content -Path $Path -Raw -Encoding UTF8
		}
		catch {
			Write-Error "Unable to read file."
		}
	}
	
	$Text -split '(?m)(?<=^\})' | ForEach-Object { $Groups += $_}
	$i = 0
	
	foreach ($Group in $Groups) {
		$i++
		$ltm = $null
		$Props = @()
		$re = [regex]::new('(?sm)^(?<module>\w+)\s(?<component>\w+)\s(?(?=\b[\w\-]+\b\s\b.+?\b)(?<subcomponent>[\w\-]+)\s(?<name>[^\s].+?)|(?<name>[^\s].+?))\s\{')
		if (($re.matches($Group) | Measure-Object).Count -eq 0) {
			Write-Verbose "$($i): No top level match found. $($Group[1])"
			continue
		}
		
		$re.matches($Group) | Foreach-Object {
			if (($_.Groups).Name -contains 'subcomponent') {
				$module, $component, $subcomponent, $name = $_.Groups['module','component','subcomponent','name'].Value
			}
			else {
				$module, $component, $name = $_.Groups['module','component','name'].Value
				$subcomponent = ''
			}
			
			$ltm = [PSCustomObject]@{
				'Module' = $module
				'Component' = $component
				'Subcomponent' = $subcomponent
				'Name' = $name
			}
		}
				
		$PropsRE = [regex]::new('(?m)^\s{4}(?<property>[\w\-]+)\s(?<value>[^{}]+?)$')
		$PropsRE.Matches($Group) | ForEach-Object {
			$property, $value = $_.Groups['property','value'].Value
			$property = $property.Trim()
			$value = $value.Trim()
			$Props += $property
			
			$ltm | Add-Member -MemberType NoteProperty -Name $($property) -Value $($value)
		}
		
		$PropsRE = [regex]::new('(?sm)^\s{4}(?<property>[\w\-]+)\s\{\s{8,}(?<value>.*?)^\s{4}\}')
		$PropsRE.Matches($Group) | ForEach-Object {
			$property, $value = $_.Groups['property','value'].Value
			$value = (($value -replace '(?sm)(?<=})\s{8,}',',') -replace '(?sm)(?<={)\s{8,}(?=\w)|(?<=\w)\s{1,}(?=})|^\s{1,}(?=\w)','').Trim()
			$property = $property.Trim()
			$Props += $property
			
			$ltm | Add-Member -NotePropertyName $($property) -NotePropertyValue $($value)
		}
		
		If ($FilterParameter -ne '' -and $null -ne $FilterParameter) {
			$ParameterValue = $($ltm.$($FilterParameter))
			Write-Verbose "$($i) Parameter Value $ParameterValue"
			if ($FilterValue.Trim() -ne $ParameterValue.Trim()){
				Write-Verbose "$($i) Parameter Not Matched"
				continue
			}
		}
		
		Write-Verbose "$($i) Continuing on."
		
		$ltms+=$ltm
		$Props | ForEach-Object { $Properties += $_ }
	}
	
	$Properties = $Properties | Sort-Object -Unique
	
	foreach ($ltm in $ltms) {
		$LtmProperties = $ltm.PSobject.Properties.name
		Compare-Object -ReferenceObject $LtmProperties -DifferenceObject $Properties | Where-Object {$_.SideIndicator -eq "=>"} | Foreach-Object { $ltm | Add-Member -NotePropertyName $_.InputObject -NotePropertyValue $null }
	}

	return $ltms
}
function Get-PublicIP {
	$RE = [regex]::new("(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}")
	$URI = "http://ifconfig.io/ip"
	$Response = Invoke-WebRequest -UseBasicParsing -URI $URI -ErrorAction SilentlyContinue
	
	if ($Response.StatusCode -eq "200") {
		$IP = $RE.Matches($Response.Content).Value
	} else {
		$IP = 0
	}
	
	return $IP
}
function Get-IP {
	$IPAddresses = @()
	$NetAddresses = Get-NetIPAddress
	$NetAdapters = Get-NetAdapter

	foreach ($NetAddress in $NetAddresses) {
		if ($NetAdapters.ifIndex -contains $NetAddress.InterfaceIndex) {
			$IPAddress = [IPAddress]::new()
			$NetAdapter = $NetAdapters | Where-Object {$_.ifIndex -eq $NetAddress.InterfaceIndex}
			$IPAddress.InterfaceAlias = $NetAddress.InterfaceAlias
			$IPAddress.IPAddress = $NetAddress.IPAddress
			$IPAddress.PrefixLength = $NetAddress.PrefixLength
			$IPAddress.MacAddress = $NetAdapter.MacAddress.ToString()
			$IPAddress.InterfaceAdminStatus = $NetAdapter.AdminStatus.ToString()
			$IPAddress.InterfaceMediaConnectionState = $NetAdapter.MediaConnectionState.ToString()
			$IPAddress.InterfaceStatus = $NetAdapter.Status.ToString()
			$IPAddress.InterfaceLinkSpeed = $NetAdapter.LinkSpeed.ToString()
			$IPAddress.FullDuplex = $NetAdapter.FullDuplex
			$IPAddresses += $IPAddress
		}
	}

	$PublicIP = [IPAddress]::new()
	$PublicIP.InterfaceAlias = 'public'
	$PublicIP.IPAddress = Get-PublicIP
	$PublicIP.PrefixLength = '32'
	
	$IPAddresses += $PublicIP
    return $IPAddresses
}
function Test-Port {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, HelpMessage = 'Could be suffixed by :Port')]
        [String[]]$ComputerName,

        [Parameter(HelpMessage = 'Will be ignored if the port is given in the param ComputerName')]
        [array]$Port = @(),

        [Parameter(HelpMessage = 'Timeout in millisecond. Increase the value if you want to test Internet resources.')]
        [Int]$Timeout = 1000
    )

    begin {
        $result = [System.Collections.ArrayList]::new()
    }

    process {
        foreach ($originalComputerName in $ComputerName) {
		
			$ping = (Test-Connection -ComputerName $originalComputerName.. -Count 4  | measure-Object -Property ResponseTime -Average).average
			if ($ping) {
				[int]$Timeout = $ping
				$Timeout = $Timeout + 10
				Write-Host $Timeout
			}
			
			$remoteInfo = $originalComputerName.Split(":")
			if ($remoteInfo.count -eq 1) {
				# In case $ComputerName in the form of 'host'
				$remoteHostname = $originalComputerName
				$remotePorts = $Port
			} elseif ($remoteInfo.count -eq 2) {
				# In case $ComputerName in the form of 'host:port',
				# we often get host and port to check in this form.
				$remoteHostname = $remoteInfo[0]
				$remotePorts = $remoteInfo[1]
			} else {
				$msg = "Got unknown format for the parameter ComputerName: " `
					+ "[$originalComputerName]. " `
					+ "The allowed formats is [hostname] or [hostname:port]."
				Write-Error $msg
				return
			}
			
			$countPorts = $remotePorts.count
			$currentPort = 1
			
			foreach ($remotePort in $remotePorts) {
				Write-Progress -Id 2 -Activity "Scanning Network Ports" -Status "Scanning Port $remotePort. $currentPort of $countPorts" -PercentComplete ($currentPort / $countPorts * 100)
				$tcpClient = New-Object System.Net.Sockets.TcpClient
				
				$portOpened = $tcpClient.ConnectAsync($remoteHostname, $remotePort).Wait($Timeout)

				$null = $result.Add([PSCustomObject]@{
					RemoteHostname       = $remoteHostname
					RemotePort           = $remotePort
					PortOpened           = $portOpened
					TimeoutInMillisecond = $Timeout
					SourceHostname       = $env:COMPUTERNAME
					OriginalComputerName = $originalComputerName
					})
			}
        }
    }

    end {
        return $result
    }
}
function Get-HostIPAddresses {
	Param (
		[array]$Hostnames
	)
	
	$Results = @()
	foreach ($hostname in $Hostnames){
		$IP = ([System.Net.Dns]::GetHostAddresses($hostname)).IPAddressToString
		$Result = [pscustomobject]@{
			"Host" = $hostname
			"IP" = $IP
		}
		$Results += $Result
	}
	
	return $Results
	
}

function ConvertFrom-CIDR {
	Param (
		[string]$CIDR
	)
	
	# Make a string of bits (24 to 11111111111111111111111100000000)
	$CIDR_Bits = ('1' * $CIDR).PadRight(32, "0")
	
	# Split into groups of 8 bits, convert to Ints, join up into a string
	$Octets = $CIDR_Bits -split '(.{8})' -ne ''
	$Mask = ($Octets | ForEach-Object -Process {[Convert]::ToInt32($_, 2) }) -join '.'
	return $Mask
}
function Get-COMPorts {
	Param (
		[switch]$Name
	)
	
	$COMPorts = Get-WmiObject -query "SELECT * FROM Win32_PnPEntity" | Where-Object {$_.Name -Match "COM\d+"}
	
	if ($Name) {
		return $COMPorts.Name
	}
	else {
		return $COMPorts
	}
}

function Connect-COMPort {
	Param (
		$Port,
		[int]$Speed = '9600'
	)
	function Select-Port {
		$RE = [regex]::new('COM\d+')
		$COMPorts = Get-COMPorts -Name
		$SelectedPort = Invoke-Menu -Items $COMPorts

		if ($SelectedPort -ne $false) {
			$Port = ($RE.Matches($SelectedPort)).Value
		} else {
			break
		}
		return $Port
	}

	if (!($Port)) {
		$Port = Select-Port
	} else {
		$Port = "COM$($Port)"
		$SelectedPort = Get-COMPorts -Name | Where-Object {$_ -match "`($($Port)`)"}
		if (($SelectedPort | Measure-Object).Count -eq 0) {
			$Prompt = "$($PortName) is not a valid port. Would you like to select from a list?"
			if (Read-Prompt -Prompt $Prompt) {
				$Port = Select-Port
			} else {
				return
			}
		}
	}
	
	Clear-Host
	Write-Host "Connecting to $($Port) at BAUD $($Speed)..."
	Start-Sleep -Seconds 5
	Clear-Host
	plink.exe $($Port) -serial -sercfg $Speed
}