###############################################################################################################
# Language     :  PowerShell 5.0
# Filename     :  Get-TroubleshootingADUser.ps1
# Author       :  chaiem (https://github.com/chaiem/)
# Description  :  Checking the most common issues of an AD-User Account
# Repository   :  https://github.com/chaiem/PowerShell_Helpdesk
# Date         :  19.01.2021
###############################################################################################################

<#
    .SYNOPSIS
    Checking the most common issues of an AD-User Account.
    
    .DESCRIPTION
    Checking the most common issues of an AD-User Account.
    
    .EXAMPLE
    Get-TroubleshootingADUser -Identity samaccountname
    
    .LINK
    
#>


Function Get-TroubleshootingADUser
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$true,
            Position=0,
            HelpMessage="Use sAMAccountName")]
        [ValidateScript({
            if([bool](Get-ADUser -Filter {sAMAccountName -eq $_})){
                return $true
            }
            else{
                throw "sAMAccountName $_ does not exist"
            }
        })]
        [string]$Identity
    )

    Begin{
        $UserProperties = 0
        $Date = [datetime](Get-Date).AddDays(-180)
        $Today = [datetime](Get-Date)
    }

    Process{
        $UserProperties = Get-ADUser -Identity $Identity -Properties *
        $UserGroups = Get-ADPrincipalGroupMembership -Identity $Identity | Sort-Object Name | ft Name, DistinguishedName
    }

    End{
        Clear-Host
        Write-Host "##################################" -ForegroundColor Yellow
        Write-Host "##### Basic User Information #####" -ForegroundColor Yellow
        Write-Host "##################################" -ForegroundColor Yellow
        Write-Host "Name:                   " $UserProperties.GivenName $UserProperties.Surname
        Write-Host "sAMAccountName:         " $UserProperties.sAMAccountName
        Write-Host "UserPrincipalName:      " $UserProperties.UserPrincipalName
        Write-Host "DistinguishedName:      " $UserProperties.DistinguishedName "`n"
        Write-Host "Enabled:                 " -NoNewline; Write-Host $UserProperties.Enabled -ForegroundColor $(if($UserProperties.Enabled -eq $True) {'White'} else {'Red'})
        Write-Host "WhenCreated:            " $UserProperties.WhenCreated
        Write-Host "AccountExpirationDate:   " -NoNewline; Write-Host $UserProperties.AccountExpirationDate -ForegroundColor $(if($UserProperties.AccountExpirationDate -le $Today) {'Red'} else {'White'})

        Write-Host "##################################" -ForegroundColor Yellow
        Write-Host "###### Password Information ######" -ForegroundColor Yellow
        Write-Host "##################################" -ForegroundColor Yellow
        Write-Host "PasswordExpired:         " -NoNewline; Write-Host $UserProperties.PasswordExpired -ForegroundColor $(if ($UserProperties.PasswordExpired -eq $False) {'White'} else {'Red'})
        Write-Host "PasswordNeverExpires:    " -NoNewline; Write-Host $UserProperties.PasswordNeverExpires -ForegroundColor $(if ($UserProperties.PasswordNeverExpires -eq $False) {'White'} else {'Red'})
        Write-Host "PasswordNotRequired:     " -NoNewline; Write-Host $UserProperties.PasswordNotRequired -ForegroundColor $(if ($UserProperties.PasswordNotRequired -eq $False) {'White'} else {'Red'})
        Write-Host "PasswordLastSet:         " -NoNewLine; Write-Host $UserProperties.PasswordLastSet -ForegroundColor $(if ($UserProperties.PasswordLastSet -gt $Date) {'White'} else {'Red'})

        Write-Host "##################################" -ForegroundColor Yellow
        Write-Host "####### Logon Information ########" -ForegroundColor Yellow
        Write-Host "##################################" -ForegroundColor Yellow
        Write-Host "LockedOut:               " -NoNewline; Write-Host $UserProperties.LockedOut -ForegroundColor $(if ($UserProperties.LockedOut -eq $False) {'White'} else {'Red'})
        Write-Host "LogonCount:             " $UserProperties.logonCount 
        Write-Host "LastLogon:              " ([datetime]::FromFileTime($UserProperties.lastlogon))
        Write-Host "LastBadPasswordAttempt: " $UserProperties.LastBadPasswordAttempt

        Write-Host "##################################" -ForegroundColor Yellow
        Write-Host "######## Group Membership ########" -ForegroundColor Yellow
        Write-Host "##################################" -ForegroundColor Yellow
        $UserGroups
    }
}
