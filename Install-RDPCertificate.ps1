<#
.SYNOPSIS
   Replaces RDP certificate on local or remote computers

.DESCRIPTION
   This function replaces the certificate used by Remote Desktop Protocol on computers, including remote computers.

.PARAMETER ComputerName
   One or more computers that the certificate should be installed to. Can accept pipeline input.

.PARAMETER FilePath
   Mandatory - Path to a certificate in PFX format.

.PARAMETER Password
   Mandatory - Password used to unlock the certificate PFX.

.EXAMPLE
   Install-RDPCertificate -ComputerName RDSHServer1 -FilePath D:\WildcardCert.pfx -Password P4$$w0rd9

   This example shows how to push a certificate located on the local machine to a remote computer.

.EXAMPLE
   Install-RDPCertificate -ComputerName RDSHServer1,RDSHServer2,RDSHServer3 -FilePath D:\WildcardCert.pfx -Password P4$$w0rd9

   This example shows how to push a certificated located on the local machine to multiple remote computers.

.EXAMPLE
   Get-RDServer -Role RDS-RD-SERVER | Install-RDPCertificate -FilePath D:\WildcardCert.pfx -Password P4$$w0rd9

   This example uses the Get-RDServer cmdlet to get a list of all RD Session Host servers in an RDS deployment, and then apply a certificate to them.

.NOTES
   Inspired by Ryan Mangan's RDS 2012 Session Host Certificate Configuration script.
   https://gallery.technet.microsoft.com/RDS-2012-Session-Host-fbb54ff9

.LINK
   Link to 
#>
function Install-RDPCertificate
{
    [CmdletBinding(DefaultParameterSetName='ParamSet1', 
                  SupportsShouldProcess=$true)]
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
        [String]$Password
    )

    Begin
    {
        ## Check to ensure certificate exists at target path
        if (-not (Test-Path $FilePath)){
            ## File does not exist
            Write-Error "Certificate not found at target location $FilePath"
            break
        }

        ## Convert password to secure string
        $SecurePass = ConvertTo-SecureString $Password -AsPlainText -Force
        
        ## Get the thumbprint from the certificate
        $Thumbprint = (Get-PfxData -FilePath $FilePath -Password $SecurePass).EndEntityCertificates.Thumbprint
        Write-Verbose "Certificate thumbprint: $Thumbprint"

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
                $WMIObject = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'" -ComputerName $Computer -Authentication 6
                if ($WMIObject){
                    if ($WMIObject.SSLCertificateSHA1Hash -eq $Thumbprint){
                        ## Thumbprint already matches, no need to continue
                        Write-Verbose "The certificate thumbprint for computer $Computer already matches the new certificate"
                        Continue
                    }
                } else {
                    ## WMI query did not return any results
                    Write-Warning "Could not query WMI class Win32_TSGeneralSetting on $Computer"
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

            ## Set the certificate and permissions
            Write-Verbose "Applying the certificate to computer $Computer"
            try{
                # Apply the certificate to WMI
                $WMIObject.SSLCertificateSHA1Hash = $Thumbprint
                $WMIObject.Put() | Out-Null
                
                # Set the appropriate permissions to the private key so RDP may access it
                $ScriptBlock = {
                    $FilePath = "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys"
                    $File = Get-ChildItem $FilePath | sort LastWriteTime -Descending | select -First 1
                    # Specify account
                    $Account = "NT AUTHORITY\NETWORK SERVICE"
                    # Get current ACL on the private key
                    $ACL = Get-Acl -Path $File.FullName
                    # Set new rule
                    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Account", "Read", "Allow")
                    # Add rule to the ACL
                    $ACL.AddAccessRule($rule)
                    # Set new ACL to the private key
                    Set-Acl -Path $File.FullName -AclObject $ACL
                }
                Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock -ArgumentList $FilePath -SessionOption $SessionOptions
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