<#
.SYNOPSIS
   Replaces RDP certificate on remote computers

.DESCRIPTION
   The Install-RDPCert function is used to replace the RDP certificate on computers, including multiple remote computers.

.PARAMETER ComputerName
   Optional - One or more computers that the certificate should be installed to. Can accept pipeline input. If not specified, the local computer will be used.

.PARAMETER FilePath
   Mandatory - Path to a certificate in PFX format.

.PARAMETER Password
   Mandatory - Password used to unlock the certificate PFX.

.PARAMETER ListenerName
   Optional - Specify an optional listener name in case your organization customizes the name. Default is "RDP-tcp".

.EXAMPLE
   Install-RDPCert -ComputerName RDSHServer1 -FilePath D:\WildcardCert.pfx -Password P4$$w0rd9

   This example shows how to push a certificate located on the local machine to a remote computer.

.EXAMPLE
   Install-RDPCert -ComputerName RDSHServer1,RDSHServer2,RDSHServer3 -FilePath D:\WildcardCert.pfx -Password P4$$w0rd9

   This example shows how to push a certificated located on the local machine to multiple remote computers.

.EXAMPLE
   Get-RDServer -Role RDS-RD-SERVER | Install-RDPCert -FilePath D:\WildcardCert.pfx -Password P4$$w0rd9

   This example uses the Get-RDServer cmdlet to get a list of all RD Session Host servers in an RDS deployment, and then apply a certificate to them.

.NOTES
   Created by Tom Murphy
   1/30/2015
   http://blog.tmurphy.org

   Inspired by Ryan Mangan's RDS 2012 Session Host Certificate Configuration script.
   https://gallery.technet.microsoft.com/RDS-2012-Session-Host-fbb54ff9

.LINK
   http://blog.tmurphy.org
#>
function Install-RDPCert
{
    [CmdletBinding(DefaultParameterSetName='ParamSet1')]
    [OutputType([String])]
    Param
    (
        ## ComputerName
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='ParamSet1')]
        [ValidateNotNullOrEmpty()]
        [Alias("Computer")]
        [Alias("Server")]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        ## FilePath of the certificate
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   ValueFromRemainingArguments=$false,
                   Position=1,
                   ParameterSetName='ParamSet1')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
                if ($_ -like "*.pfx"){
                    $true
                } else {
                    Throw "Certificate must be in *.PFX format!"
                }})]
        [Alias("CertificatePath")]
        [Alias("PFX")]
        [string]$FilePath,

        ## Password
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   ValueFromRemainingArguments=$false,
                   Position=2,
                   ParameterSetName='ParamSet1')]
        [ValidateNotNullOrEmpty()]
        [String]$Password,

        ## ListenerName
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$false,
                   ValueFromRemainingArguments=$false,
                   Position=3,
                   ParameterSetName='ParamSet1')]
        [ValidateNotNullOrEmpty()]
        [String]$ListenerName = "RDP-tcp"
    )

    Begin
    {
        ## Check to ensure certificate exists at target path
        if (-not (Test-Path $FilePath)){
            ## File does not exist
            throw "Certificate not found at target location $FilePath"
        }

        ## Convert password to secure string
        $SecurePass = ConvertTo-SecureString $Password -AsPlainText -Force
        
        ## Get the thumbprint from the certificate
        try{
            $Thumbprint = (Get-PfxData -FilePath $FilePath -Password $SecurePass -ErrorVariable CertError).EndEntityCertificates.Thumbprint
            Write-Verbose "Certificate thumbprint: $Thumbprint"
        } catch {
            ## Unable to get thumbprint from certificate file
            throw "Unable to get thumbprint from certificate. Error details: $($CertError.Message)"
        }

        ## Create array to hold output object
        $Output = @()
    }
    Process
    {
        foreach($Computer in $ComputerName){
            ## Ensure target computer can be reached
            if (-not (Test-Connection $Computer -Count 1 -Quiet)){
                ## Computer cannot be pinged
                Write-Warning "Cannot ping target computer: $Computer"
                Continue
            }

            ## Create hashtable to hold output object properties and add default properties
            $hashtable = @{}
            $hashtable.ComputerName = $Computer

            ## Get WMI object of Win32_TSGeneralSetting
            try{
                $WMIObject = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='$ListenerName'" -ComputerName $Computer -Authentication 6
                if ($WMIObject){
                    if ($WMIObject.SSLCertificateSHA1Hash -eq $Thumbprint){
                        ## Thumbprint already matches, no need to continue
                        Write-Verbose "The certificate thumbprint for computer $Computer already matches the new certificate"
                        Continue
                    }
                } else {
                    ## WMI query did not return any results
                    Write-Warning "No results returned when querying WMI class Win32_TSGeneralSetting with filter TerminalName='$ListenerName' on computer $Computer"
                    Continue
                }
            } catch {
                ## Error connecting to WMI
                Write-Warning "Unable to connect to WMI on computer $Computer`: $Error[0]"
                Continue
            }
            Write-Verbose "Original thumbprint for $Computer`: $($WMIObject.SSLCertificateSHA1Hash)"
            $hashtable.OriginalThumbprint = $WMIObject.SSLCertificateSHA1Hash

            ## Get $env:SystemRoot path from remote computer and build remote path variables
            $RemoteSystemRoot = Invoke-Command -ComputerName $Computer -ScriptBlock {$env:SystemRoot.replace(":","$")}
            $RemoteFilePath = "\\" + $Computer + "\" + $RemoteSystemRoot + "\Temp"
            $RemoteCert = ($RemoteSystemRoot.replace("$",":")) + "\Temp\" + (Split-Path $FilePath -Leaf)
        
            ## Push certificate to computer
            Write-Verbose "Pushing certificate to $Computer"
            Copy-Item -Path $FilePath -Destination $RemoteFilePath
        
            ## Import certificate on remote machine
            Write-Verbose "Importing certificate to $Computer LocalMachine store"
            try{
                $SessionOptions = New-PSSessionOption -OperationTimeout 60000 -IdleTimeout 60000 -OpenTimeout 60000
                Invoke-Command -ComputerName $Computer -ScriptBlock {param($FilePath,$SecurePass) Import-PfxCertificate -FilePath $FilePath -Password $SecurePass -CertStoreLocation Cert:\LocalMachine\My} -ArgumentList $RemoteCert,$SecurePass -SessionOption $SessionOptions | Out-Null
            } catch {
                ## Unable to import the certificate
                Write-Warning "Unable to import certificate into store on computer $Computer`: $Error[0]"
                Continue
            }

            ## Set the certificate
            Write-Verbose "Applying the certificate to computer $Computer"
            try{
                $WMIObject.SSLCertificateSHA1Hash = $Thumbprint
                $WMIObject.Put() | Out-Null
            } catch {
                ## Unable to apply the certificate
                Write-Warning "Unable to apply certificate on computer $Computer`: $Error[0]"
                Continue
            }
            Write-Verbose "Certificate applied successfully to computer $Computer"

            ## Everything was successful, add properties to hashtable
            $hashtable.NewThumbprint = $Thumbprint

            ## Create new object and add to object array
            $Object = New-Object -TypeName psobject -Property $hashtable
            $Output += $Object
        }
    }
    End
    {
        ## Write output object to the pipeline
        Write-Output $Output | Select-Object ComputerName, OriginalThumbprint, NewThumbprint
    }
}