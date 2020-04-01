param (
	[Parameter(Mandatory=$true,Position=1)][string]$XMLfile,
	[Parameter(Mandatory=$true,Position=2)][string]$CSVfile
)

# Checking pre-reqs
Write-Host -foregroundcolor Green [+] Checking pre-reqs
If (!(($XMLfile) -and ($CSVfile))) {
	Write-Host [!] Missing parameter. Usage:
	Write-Host " "
	Write-Host pwsh nmap-xml2csv.ps1 -XMLfile ./tcp_100.xml -CSVfile ./tcp_100.csv
	Write-Host " "
	Exit
} Elseif (!(Test-Path -Path $XMLfile)) {
	Write-Host -foregroundcolor Red [!] XMLfile arg is not a valid file path. Exiting.
	Exit
} Elseif (Test-Path -Path $CSVfile) {
	Write-Host -foregroundcolor Yellow [!] CSVfile already exists and will be overwritten. Press CTRL+C to exit, otherwise
	Pause
}

# Import Nmap XML file
Write-Host -foregroundcolor Green [+] Loading XML file contents into posh XML object
$XML = New-Object -TypeName Xml
$XML.Load((Convert-Path $XMLfile))

# Array to store results objects
$Results = @()
# Loop through all host nodes in XML
Write-Host -foregroundcolor Green -Nonewline [+] Extracting data from XML nodes
Foreach ($target in $XML.nmaprun.host) {
	Write-Host -foregroundcolor Green -Nonewline " ."
	$IP = $target.address.addr
	# Loop through all port nodes in XML under this host node
	Foreach ($portscan in $target.ports.port) {
		# Extract the scan result information
		$Protocol = $portscan.protocol
		$Port = $portscan.portid
		$State = $portscan.state.state
		$Service = $portscan.service.name
		
		# Create new object to store extracted information RE this host/ports
		$Result = New-Object -TypeName PSObject
		Add-Member -InputObject $Result -MemberType NoteProperty -Name "IP" -Value $IP
		Add-Member -InputObject $Result -MemberType NoteProperty -Name "Protocol" -Value $Protocol
		Add-Member -InputObject $Result -MemberType NoteProperty -Name "Port" -Value $Port
		Add-Member -InputObject $Result -MemberType NoteProperty -Name "State" -Value $State
		Add-Member -InputObject $Result -MemberType NoteProperty -Name "Service" -Value $Service
		
		# Add result object to results array
		$Results += $Result
	}
}

# Output results array to CSV file
Write-Host " "
Write-Host -foregroundcolor Green [+] Exporting to CSV file
$Results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $CSVfile
Write-Host -foregroundcolor Green -Nonewline [+] Done!
