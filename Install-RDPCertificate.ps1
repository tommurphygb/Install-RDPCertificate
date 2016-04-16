#Requires -Version 4.0
#Requires -Modules PKI

<#
.SYNOPSIS
   Replaces RDP certificate on local or remote computers

.DESCRIPTION
   This function replaces the certificate used by Remote Desktop Protocol on computers, including remote computers.

.EXAMPLE
   $SecurePass = ConvertTo-SecureString -String "P4$$w0rd9" -AsPlainText -Force
   Install-RDPCertificate -ComputerName RDSHServer1 -FilePath D:\WildcardCert.pfx -Password $SecurePass

   This example shows how to push a certificate located on the local machine to a remote computer.

.EXAMPLE
   $SecurePass = ConvertTo-SecureString -String "P4$$w0rd9" -AsPlainText -Force
   Install-RDPCertificate -ComputerName RDSHServer1,RDSHServer2,RDSHServer3 -FilePath D:\WildcardCert.pfx -Password $SecurePass

   This example shows how to push a certificated located on the local machine to multiple remote computers.

.EXAMPLE
   $SecurePass = ConvertTo-SecureString -String "P4$$w0rd9" -AsPlainText -Force
   Get-RDServer -Role RDS-RD-SERVER | Install-RDPCertificate -FilePath D:\WildcardCert.pfx -Password $SecurePass

   This example uses the Get-RDServer cmdlet to get a list of all RD Session Host servers in an RDS deployment, and then apply a certificate to them.

.NOTES
   Created by Tom Murphy 
   Last modified 4/15/2016 
   http://blog.tmurphy.org
 
   Inspired by Ryan Mangan's RDS 2012 Session Host Certificate Configuration script. 
   https://gallery.technet.microsoft.com/RDS-2012-Session-Host-fbb54ff9 
 
.LINK 
   http://blog.tmurphy.org
#>
function Install-RDPCertificate
{
    [CmdletBinding(
        SupportsShouldProcess=$true,
        ConfirmImpact="Medium"
    )]
    
    Param
    (
        # One or more computers that the certificate should be installed to. Can accept pipeline input.
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

        # Path to a certificate exported in PFX format. The exported certificate must be secured with a password.
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

        # Password used to unlock the certificate PFX. Must be formatted as a SecureString.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   ValueFromRemainingArguments=$false,
                   Position=2,
                   ParameterSetName='ParamSet1')]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]$Password
    ) # end param block

    Begin
    {
        # Import modules
        Import-Module PKI -Verbose:$false

        # Check to ensure certificate exists at target path
        if (-not (Test-Path $FilePath)){
            # File does not exist
            throw "Certificate not found at target location $FilePath"
        } # end if

        # Get the thumbprint from the certificate
        try
        {
            $Thumbprint = (Get-PfxData -FilePath $FilePath -Password $Password).EndEntityCertificates.Thumbprint
            Write-Verbose "Certificate thumbprint: $Thumbprint"
        }
        catch [System.Exception]
        {
            # Cannot get thumbprint from certificate, password is likely invalid
            throw "Access denied to certificate - ensure the password is correct"
        } # end try/catch

        # Create array to hold output object
        $Output = @()
    } # end Begin block
    Process
    {
        foreach($Computer in $ComputerName){
            # Set -WhatIf information
            if($PSCmdlet.ShouldProcess("$Computer","Apply certificate '$(Split-Path -Path $FilePath -Leaf)' to RDP listener")){
                # Ensure target computer can be reached
                if (-not (Test-Connection $Computer -Count 1 -Quiet)){
                    # Computer cannot be pinged
                    Write-Warning "[$Computer] - Cannot ping target computer"
                    Continue
                } # end if

                # Create hashtable to hold output object properties and add default properties
                $hashtable = @{}
                $hashtable.ComputerName = $Computer

                # Get WMI object of Win32_TSGeneralSetting
                try
                {
                    $WMIObject = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'" -ComputerName $Computer -Authentication 6
                    if ($WMIObject){
                        if ($WMIObject.SSLCertificateSHA1Hash -eq $Thumbprint){
                            # Thumbprint already matches, no need to continue
                            Write-Verbose "[$Computer] - The certificate thumbprint already matches the new certificate"
                            Continue
                        } # end if
                    } else {
                        # WMI query did not return any results
                        Write-Warning "[$Computer] - Could not query WMI class Win32_TSGeneralSetting"
                        Continue
                    } # end if
                }
                catch
                {
                    # Error connecting to WMI
                    Write-Warning "[$Computer] - Unable to connect to WMI`: $($Error[0])"
                    Continue
                } # end try/catch

                Write-Verbose "[$Computer] - Original thumbprint`: $($WMIObject.SSLCertificateSHA1Hash)"
                $hashtable.OriginalThumbprint = $WMIObject.SSLCertificateSHA1Hash

                # Get $env:SystemRoot path from remote computer and build remote path variables
                $RemoteSystemRoot = Invoke-Command -ComputerName $Computer -ScriptBlock {$env:SystemRoot.replace(":","$")}
                $RemoteFilePath = "\\" + $Computer + "\" + $RemoteSystemRoot + "\Temp"
                $RemoteCert = ($RemoteSystemRoot.replace("$",":")) + "\Temp\" + (Split-Path $FilePath -Leaf)
        
                # Push certificate to computer
                Write-Verbose "[$Computer] - Pushing certificate to $RemoteCert"
                Copy-Item -Path $FilePath -Destination $RemoteFilePath
        
                # Import certificate on remote machine
                Write-Verbose "[$Computer] - Importing certificate to LocalMachine store"
                try
                {
                    $SessionOptions = New-PSSessionOption -OperationTimeout 60000 -IdleTimeout 60000 -OpenTimeout 60000
                    Invoke-Command -ComputerName $Computer -ScriptBlock {param($FilePath,$Password) Import-PfxCertificate -FilePath $FilePath -Password $Password -CertStoreLocation Cert:\LocalMachine\My} -ArgumentList $RemoteCert,$Password -SessionOption $SessionOptions -ErrorAction Continue | Out-Null
                    Write-Verbose "[$Computer] - Import successful"
                }
                catch
                {
                    # Unable to import the certificate
                    Write-Warning "[$Computer] - Unable to import certificate into store`: $($Error[0])"
                    Continue
                } # end try/catch

                # Set the certificate and permissions
                Write-Verbose "[$Computer] - Applying the certificate to computer"
                try
                {
                    # Apply the certificate to WMI
                    $WMIObject.SSLCertificateSHA1Hash = $Thumbprint
                    $WMIObject.Put() | Out-Null
                    Write-Verbose "[$Computer] - Certificate applied successfully"
                
                    # Set the appropriate permissions to the private key so RDP may access it
                    $ScriptBlock = {
                        $FilePath = "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys"
                        $File = Get-ChildItem $FilePath | Sort-Object LastWriteTime -Descending | Select-Object -First 1
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
                    } # end $ScriptBlock
                    Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock -ArgumentList $FilePath -SessionOption $SessionOptions
                    Write-Verbose "[$Computer] - Set private key permissions successfully"
                }
                catch
                {
                    # Unable to apply the certificate
                    Write-Warning "[$Computer] - Unable to apply certificate`: $($Error[0])"
                    Continue
                } # end try/catch
                Write-Verbose "[$Computer] - Certificate applied successfully"

                # Delete pfx certificate file from remote machine
                try
                {
                    Remove-Item -Path ($RemoteFilePath + '\' + (Split-Path $FilePath -Leaf)) -Force
                    Write-Verbose "[$Computer] - Deleted certificate file successfully"
                }
                catch
                {
                    Write-Warning "[$Computer] - Unable to delete PFX file from remote machine"
                } # end try/catch

                # Everything was successful, add properties to hashtable
                $hashtable.NewThumbprint = $Thumbprint

                # Create new object and add to object array
                $Object = New-Object -TypeName psobject -Property $hashtable
                $Output += $Object
            } # end $PSCmdlet.ShouldProcess
        } # end foreach
    } # end Process block
    End
    {
        # Write output object to the pipeline
        Write-Output $Output | Select-Object ComputerName, OriginalThumbprint, NewThumbprint
    } # end End block
} #end function