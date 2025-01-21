Function Get-RpcSessionInfo {
    <#
    .SYNOPSIS
        Returns details of the current connected Windows settion including Authentication type, Groups tokens and logon type
        Useful for debuging session issues
 
    .PARAMETER AsJson
        Return results as Json string
    .OUTPUTS
        Custom object or json string with the session details
 
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [Switch]
        $AsJson
    )
    $rtn = [PSCustomObject]@{status=0;cmdOut=$Null;errOut=$Null}
    try {
        $winId = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]$winId
        $tokenGroups = $winId.Groups | Foreach-Object {$_.Translate([System.Security.Principal.NTAccount]).toString()}
        $isAdmin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $PCInfo = Get-CimInstance -Class Win32_ComputerSystem
        $rtn.cmdOut = [PSCustomObject]@{
            userId=$winId.Name;
            computerName=[Environment]::MachineName;
            manufacturer = $PCInfo.manufacturer;
            model = $PCInfo.model;
            domainName = $PCInfo.Domain;
            domainJoined = $PCInfo.PartOfDomain;
            authenticationType=$winId.AuthenticationType;
            impersonation = $winId.ImpersonationLevel.ToString();
            isAdmin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            localProfile=[Environment]::GetEnvironmentVariable("LOCALAPPDATA");
            tokenGroups=$tokenGroups;
            isSystem=$winId.isSystem;
            isService=$tokenGroups -contains "NT AUTHORITY\SERVICE";
            isNetwork=$tokenGroups -contains "NT AUTHORITY\NETWORK";
            isBatch=$tokenGroups -contains "NT AUTHORITY\BATCH";
            isInteractive=$tokenGroups -contains "NT AUTHORITY\INTERACTIVE";
            isNtlmToken=$tokenGroups -contains "NT AUTHORITY\NTLM Authentication";
            osVersion = [Environment]::OSVersion.VersionString;
            systemDrive = [Environment]::GetEnvironmentVariable("SystemDrive");
            psVersion=$PSVersionTable.PSVersion.ToString();
            psEdition=$PSVersionTable.PSEdition;
            psExePath=(Get-Process -Id $Pid).Path
        }
    }
    catch {
        $rtn.status=1
        $rtn.errOut = [PSCustomObject]@{message="Error while querying session details. Exception: {0}" -F $_.Exception.Message}
    }
    if ($AsJson) {
        return $rtn | ConvertTo-Json -Depth 3
    } else {
        return $rtn
    }
}
 
 
Get-RpcSessionInfo -AsJson