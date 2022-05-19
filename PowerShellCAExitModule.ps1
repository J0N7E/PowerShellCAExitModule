<#
 .SYNOPSIS
    PowerShell CA ExitModule

 .DESCRIPTION
    Export certificate requests to SQL

 .NOTES
    Register task in powershell with:

    @{
        TaskName    = "PowerShell CA ExitModule"
        Description = 'Triggers on Security event 4870, 4887, 4888 & 4889'
        TaskPath    = '\'
        Action      =
        @{
            WorkingDirectory = "$PWD"
            Execute  = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe'
            Argument = '-NoProfile -File .\PowerShellCAExitModule.ps1 -RequestId "$(RequestId)" -SerialNumber "$(SerialNumber)"'
        } | ForEach-Object {
            New-ScheduledTaskAction @_
        }
        Trigger     =
        @(
            @{
                Enabled = $true
                Subscription =
@"
<QueryList>
    <Query Id="0" Path="Security">
        <Select Path="Security">
            *[System[EventID=4870]] or
            *[System[EventID=4887]] or
            *[System[EventID=4888]] or
            *[System[EventID=4889]]
        </Select>
    </Query>
</QueryList>
"@
                ValueQueries =
                @{
                    RequestId = 'Event/EventData/Data[@Name="RequestId"]'
                    SerialNumber = 'Event/EventData/Data[@Name="CertificateSerialNumber"]'
                }.GetEnumerator() | ForEach-Object { $_2 = $_;
                    New-CimInstance -CimClass (
                        Get-CimClass -ClassName MSFT_TaskNamedValue `
                                     -Namespace Root/Microsoft/Windows/TaskScheduler
                    ) -ClientOnly | ForEach-Object {
                        $_.Name  = $_2.Name
                        $_.Value = $_2.Value
                        return $_
                    }
                }
            }
        ) | ForEach-Object { $_2 = $_;
            New-CimInstance -CimClass (
                Get-CimClass -ClassName MSFT_TaskEventTrigger `
                             -Namespace Root/Microsoft/Windows/TaskScheduler
            ) -ClientOnly | ForEach-Object {
                $_.Enabled      = $_2.Enabled
                $_.Subscription = $_2.Subscription
                $_.ValueQueries = $_2.ValueQueries
                return $_
            }
        }
        Principal   = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount
        Settings    = New-ScheduledTaskSettingsSet
    } | ForEach-Object {
        Register-ScheduledTask @_
    }

 .NOTES
    Register event source with:

    foreach ($EventSource in @('PowerShell CA ExitModule'))
    {
        New-EventLog -LogName Application -Source $EventSource
    }

 .NOTES
    Debug:

    foreach ($EventSource in @('PowerShell CA ExitModule'))
    {
        #Check registered event source exist with:
        [System.Diagnostics.EventLog]::SourceExists($EventSource)

        #Check which log registered event source is registered under
        [System.Diagnostics.EventLog]::LogNameFromSourceName($EventSource,'.')

        #Remove registered event with:
        #[System.Diagnostics.EventLog]::DeleteEventSource($EventSource)
    }

 .NOTES
    AUTHOR Jonas Henriksson

 .LINK
    https://github.com/J0N7E
#>

param
(
    [String]$RequestId,
    [String]$SerialNumber
)

try
{
    ############
    # Configure
    ############

    $SQLConnectionString = 'Server=localhost;Database=ExitModule;Trusted_Connection=True;'
    $RequestsTableName   = 'dbo.CertificateRequests'
    $ExtensionsTableName = 'dbo.CertificateExtensions'

    #############
    # Get-CaView
    # https://github.com/J0N7E/PowerShellCAFunctions/blob/master/f_GetCAView.ps1
    #############

    Invoke-Command -ScriptBlock `
    {
        try
        {
            . $PSScriptRoot\f_GetCAView.ps1
        }
        catch [Exception]
        {
            throw $_
        }

    } -NoNewScope

    ############
    # Functions
    ############

    function Get-SQLProperties
    {
        param
        (
            $Request
        )

        # Initialize hash
        $Properties = @{}

        # Get object members
        $RequestMembers = Get-Member -Type Properties -InputObject $Request

        # Itterate members
        foreach ($Member in $RequestMembers)
        {
            # Check if not empty
            if ($Request.($Member.Name))
            {
                # Get value
                $Value = $Request.($Member.Name)

                # Check member type
                switch ($Request.($Member.Name).GetType())
                {
                    # Set string or datetime property, add pem tags or trim end
                    {$_ -in @([System.String],
                              [System.DateTime])}
                    {
                        if ($Member.Name -eq 'RawRequest')
                        {
                            $Value = "-----BEGIN CERTIFICATE REQUEST-----`n$Value-----END CERTIFICATE REQUEST-----"
                        }
                        elseif ($Member.Name -eq 'RawCertificate')
                        {
                            $Value = "-----BEGIN CERTIFICATE-----`n$Value-----END CERTIFICATE-----"
                        }
                        elseif ($Member.Name -eq 'RawPublicKey')
                        {
                            $Value = "-----BEGIN PUBLIC KEY-----`n$Value-----END PUBLIC KEY-----"
                        }
                        elseif  ($Member.Name -match 'Raw')
                        {
                            $Value = $Value.TrimEnd()
                        }

                        $Properties += @{ $Member.Name = "'$Value'" }
                    }

                    # Set integer property
                    {$_ -eq [System.Int32]}
                    {
                        $Properties += @{ $Member.Name = $Value }
                    }
                }
            }
        }

        Write-Output -InputObject $Properties
    }

    function Build-SQLUpsertQuery
    {
        param
        (
            [Parameter(ParameterSetName='Requests', Mandatory=$true)]
            [Switch]$RequestsTable,

            [Parameter(ParameterSetName='Extensions', Mandatory=$true)]
            [Switch]$ExtensionsTable,

            [Parameter(ParameterSetName='Requests', Mandatory=$true)]
            [Parameter(ParameterSetName='Extensions', Mandatory=$true)]
            $TableName,

            [Parameter(ParameterSetName='Requests')]
            [Parameter(ParameterSetName='Extensions', Mandatory=$true)]
            $RequestId,

            [Parameter(ParameterSetName='Requests')]
            $SerialNumber,

            [Parameter(ParameterSetName='Requests', Mandatory=$true)]
            [Parameter(ParameterSetName='Extensions', Mandatory=$true)]
            $Properties
        )

        ###################
        # Check properties
        ###################

        if ($ExtensionsTable.IsPresent -and
            -not $Properties.ExtensionName)
        {
            throw "ExtensionName property missing from 'Properties'."
        }

        ###########
        # Check Id
        ###########

        if ($RequestId)
        {
            $Id = $RequestId

            if ($RequestsTable.IsPresent)
            {
                $IdName = 'RequestId'
            }
            elseif ($ExtensionsTable.IsPresent)
            {
                $IdName = 'ExtensionRequestId'
            }
        }
        elseif ($SerialNumber)
        {
            $Id = $SerialNumber
            $IdName = 'SerialNumber'
        }
        else
        {
            throw "Cannot validate arguments on parameter 'RequestId' and 'SerialNumber'. Both arguments is null or empty."
        }

        ###################
        # Check table type
        ###################

        if ($RequestsTable.IsPresent)
        {
                $WhereClause =
@"

WHERE $IdName = $Id;
"@
        }
        elseif ($ExtensionsTable.IsPresent)
        {
                $WhereClause =
@"

WHERE $IdName = $Id
AND ExtensionName = $($Properties.ExtensionName);
"@
        }

        ##############
        # Build query
        ##############

        # Setting start of query
        $Query =
@"
BEGIN TRANSACTION;

UPDATE $TableName WITH (UPDLOCK, SERIALIZABLE)
SET
"@
        # Set item counter
        $i = 0

        # Add name/value pairs to set in update query
        foreach ($Property in $Properties.GetEnumerator())
        {
            $Query += "`n   $($Property.Name) = $($Property.Value)"

            # Check if not last item
            if ($i -lt $Properties.Count -1)
            {
                $Query += ','
            }

            # Increase item count
            $i++
        }

        # Add where clause depending on tabletype
        $Query += $WhereClause

        # Continue building query
        $Query +=
@"


IF @@ROWCOUNT = 0
BEGIN
  INSERT $TableName
  (
"@

        # Set item counter
        $i = 0

        # Add column names for insert query
        foreach ($Property in $Properties.GetEnumerator())
        {
            $Query += "`n   $($Property.Name)"

            # Check if not last item
            if ($i -lt $Properties.Count -1)
            {
                $Query += ','
            }

            # Increase item count
            $i++
        }

        # Continue building query
        $Query +=
@"

  )
  VALUES
  (
"@
        # Set item counter
        $i = 0

        # Add values for insert query
        foreach ($Property in $Properties.GetEnumerator())
        {
            $Query += "`n   $($Property.Value)"

            # Check if not last item
            if ($i -lt $Properties.Count -1)
            {
                $Query += ','
            }

            # Increase item count
            $i++
        }

        # Adding end of query
        $Query +=
@"

  );
END

COMMIT TRANSACTION;
"@
        Write-Output -InputObject $Query
    }

    ###########
    # Requests
    ###########

    if ($RequestId)
    {
        # Get request from RequestId
        $Request = Get-CAView -Requests -Properties * -RequestId $RequestId
    }

    elseif ($SerialNumber)
    {
        # Get request from SerialNumber
        $Request = Get-CAView -Requests -Properties * -SerialNumber $SerialNumber
    }
    else
    {
        throw "Cannot validate arguments on parameter 'RequestId' and 'SerialNumber'. Both arguments is null or empty."
    }

    # Check if to return
    if (-not $Request)
    {
        return
    }

    # Get properties
    $Properties = Get-SQLProperties -Request $Request

    # Connect to SQL server
    $Connection = New-Object System.Data.SqlClient.SQLConnection($SQLConnectionString)
    $Connection.Open()

    # Execute query
    $Adapter =  New-Object System.Data.SqlClient.SqlDataAdapter(
                    New-Object System.Data.SqlClient.SqlCommand((
                        Build-SQLUpsertQuery -RequestsTable `
                                             -TableName  $RequestsTableName `
                                             -RequestId  $Properties.RequestID `
                                             -Properties $Properties
                        ),
                        $Connection
                    )
                )

    $Adapter.Fill((New-Object System.Data.DataSet)) > $null

    #############
    # Extensions
    #############

    # Itterate issued extensions from database
    foreach ($Extension in (Get-CAView -Extensions -RequestId $Properties.RequestId))
    {
        # Get properties
        $Properties = Get-SQLProperties -Request $Extension

        # Execute query
        $Adapter =  New-Object System.Data.SqlClient.SqlDataAdapter(
                        New-Object System.Data.SqlClient.SqlCommand((
                            Build-SQLUpsertQuery -ExtensionsTable `
                                                 -TableName  $ExtensionsTableName `
                                                 -RequestId  $Properties.ExtensionRequestId `
                                                 -Properties $Properties
                            ),
                            $Connection
                        )
                    )

        $Adapter.Fill((New-Object System.Data.DataSet)) > $null
    }

    #############
    # Disconnect
    #############

    $Connection.Close()
}
catch [Exception]
{
    Write-EventLog -LogName Application `
                   -Source "PowerShell CA ExitModule" `
                   -EntryType Error `
                   -EventId 1234 `
                   -Message $_ `
                   -Category 0
    throw $_
}


# SIG # Begin signature block
# MIIZBgYJKoZIhvcNAQcCoIIY9zCCGPMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUhkvPyfnhmzfQNbLo9Qp+9DZV
# IkWgghKHMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
# AQsFADAQMQ4wDAYDVQQDDAVKME43RTAeFw0yMTA2MDcxMjUwMzZaFw0yMzA2MDcx
# MzAwMzNaMBAxDjAMBgNVBAMMBUowTjdFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzdFz3tD9N0VebymwxbB7s+YMLFKK9LlPcOyyFbAoRnYKVuF7Q6Zi
# fFMWIopnRRq/YtahEtmakyLP1AmOtesOSL0NRE5DQNFyyk6D02/HFhpM0Hbg9qKp
# v/e3DD36uqv6DmwVyk0Ui9TCYZQbMDhha/SvT+IS4PBDwd3RTG6VH70jG/7lawAh
# mAE7/gj3Bd5pi7jMnaPaRHskogbAH/vRGzW+oueG3XV9E5PWWeRqg1bTXoIhBG1R
# oSWCXEpcHekFVSnatE1FGwoZHTDYcqNnUOQFx1GugZE7pmrZsdLvo/1gUCSdMFvT
# oU+UeurZI9SlfhPd6a1jYT/BcgsZdghWUO2M8SCuQ/S/NuotAZ3kZI/3y3T5JQnN
# 9l9wMUaoIoEMxNK6BmsSFgEkiQeQeU6I0YT5qhDukAZDoEEEHKl17x0Q6vxmiFr0
# 451UPxWZ19nPLccS3i3/kEQjVXc89j2vXnIW1r5UHGUB4NUdktaQ25hxc6c+/Tsx
# 968S+McqxF9RmRMp4g0kAFhBHKj7WhUVt2Z/bULSyb72OF4BC54CCSt1Q4eElh0C
# 1AudkZgj9CQKFIyveTBFsi+i2g6D5cIpl5fyQQnqDh/j+hN5QuI8D7poLe3MPNA5
# r5W1c60B8ngrDsJd7XnJrX6GdJd2wIPh1RmzDlmoUxVXrgnFtgzeTUUCAwEAAaNd
# MFswDgYDVR0PAQH/BAQDAgWgMCoGA1UdJQQjMCEGCCsGAQUFBwMDBgkrBgEEAYI3
# UAEGCisGAQQBgjcKAwQwHQYDVR0OBBYEFEPCLoNYgwyQVHRrBSI9l0nSMwnLMA0G
# CSqGSIb3DQEBCwUAA4ICAQBiMW8cSS4L1OVu4cRiaPriaqQdUukgkcT8iWGWrAHL
# TFPzivIPI5+7qKwzIJbagOM3fJjG0e6tghaSCPfVU+sPWvXIKF3ro5XLUfJut6j5
# qUqoQt/zNuWpI12D1gs1NROWnJgqe1ddmvoAOn5pZyFqooC4SnD1fT7Srs+G8Hs7
# Qd2j/1XYAphZfLXoiOFs7uzkQLJbhmikhEJQKzKE4i8dcsoucNhe2lvNDftJqaGl
# oALzu04y1LcpgCDRbvjU0YDStZwKSEj9jvz89xpl5tMrgGWIK8ghjRzGf0iPhqb/
# xFOFcKP2k43X/wXWa9W7PlO+NhIlZmTM/W+wlgrRfgkawy2WLpO8Vop+tvVwLdyp
# 5n4UxRDXBhYd78Jfscb0fwpsU+DzONLrJEwXjdj3W+vdEZs7YIwAnsCGf8NznXWp
# N9D7OzqV0PT2Szkao5hEp3nS6dOedw/0uKAz+l5s7WJOTLtFjDhUk62g5vIZvVK2
# E9TWAuViPmUkVugnu4kV4c870i5YgRZz9l4ih5vL9XMoc4/6gohLtUgT4FD0xKXn
# bwtl/LczkzDO9vKLbx93ICmNJuzLj+K8S4AAo8q6PTgLZyGlozmTWRa3SmGVqTNE
# suZR41hGNpjtNtIIiwdZ4QuP8cj64TikUIoGVNbCZgcPDHrrz84ZjAFlm7H9SfTK
# 8jCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290
# IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBU
# cnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh
# 1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+Feo
# An39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1
# decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxnd
# X7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6
# Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPj
# Q2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlREr
# WHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JM
# q++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh
# 3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8j
# u2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnS
# DmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud
# DgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# dwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
# dC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAG
# A1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOC
# AgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp
# /GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40B
# IiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2d
# fNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibB
# t94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7
# T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZA
# myEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdB
# eHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnK
# cPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/
# pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yY
# lvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbGMIIErqADAgEC
# AhAKekqInsmZQpAGYzhNhpedMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1
# c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwMzI5
# MDAwMDAwWhcNMzMwMzE0MjM1OTU5WjBMMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xJDAiBgNVBAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIy
# IC0gMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALkqliOmXLxf1knw
# FYIY9DPuzFxs4+AlLtIx5DxArvurxON4XX5cNur1JY1Do4HrOGP5PIhp3jzSMFEN
# MQe6Rm7po0tI6IlBfw2y1vmE8Zg+C78KhBJxbKFiJgHTzsNs/aw7ftwqHKm9MMYW
# 2Nq867Lxg9GfzQnFuUFqRUIjQVr4YNNlLD5+Xr2Wp/D8sfT0KM9CeR87x5MHaGjl
# RDRSXw9Q3tRZLER0wDJHGVvimC6P0Mo//8ZnzzyTlU6E6XYYmJkRFMUrDKAz200k
# heiClOEvA+5/hQLJhuHVGBS3BEXz4Di9or16cZjsFef9LuzSmwCKrB2NO4Bo/tBZ
# mCbO4O2ufyguwp7gC0vICNEyu4P6IzzZ/9KMu/dDI9/nw1oFYn5wLOUrsj1j6siu
# gSBrQ4nIfl+wGt0ZvZ90QQqvuY4J03ShL7BUdsGQT5TshmH/2xEvkgMwzjC3iw9d
# RLNDHSNQzZHXL537/M2xwafEDsTvQD4ZOgLUMalpoEn5deGb6GjkagyP6+SxIXuG
# Z1h+fx/oK+QUshbWgaHK2jCQa+5vdcCwNiayCDv/vb5/bBMY38ZtpHlJrYt/YYcF
# aPfUcONCleieu5tLsuK2QT3nr6caKMmtYbCgQRgZTu1Hm2GV7T4LYVrqPnqYklHN
# P8lE54CLKUJy93my3YTqJ+7+fXprAgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMC
# B4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAE
# GTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3Mp
# dpovdYxqII+eyG8wHQYDVR0OBBYEFI1kt4kh/lZYRIRhp+pvHDaP3a8NMFoGA1Ud
# HwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUF
# BwEBBIGDMIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# WAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZI
# hvcNAQELBQADggIBAA0tI3Sm0fX46kuZPwHk9gzkrxad2bOMl4IpnENvAS2rOLVw
# Eb+EGYs/XeWGT76TOt4qOVo5TtiEWaW8G5iq6Gzv0UhpGThbz4k5HXBw2U7fIyJs
# 1d/2WcuhwupMdsqh3KErlribVakaa33R9QIJT4LWpXOIxJiA3+5JlbezzMWn7g7h
# 7x44ip/vEckxSli23zh8y/pc9+RTv24KfH7X3pjVKWWJD6KcwGX0ASJlx+pedKZb
# NZJQfPQXpodkTz5GiRZjIGvL8nvQNeNKcEiptucdYL0EIhUlcAZyqUQ7aUcR0+7p
# x6A+TxC5MDbk86ppCaiLfmSiZZQR+24y8fW7OK3NwJMR1TJ4Sks3KkzzXNy2hcC7
# cDBVeNaY/lRtf3GpSBp43UZ3Lht6wDOK+EoojBKoc88t+dMj8p4Z4A2UKKDr2xpR
# oJWCjihrpM6ddt6pc6pIallDrl/q+A8GQp3fBmiW/iqgdFtjZt5rLLh4qk1wbfAs
# 8QcVfjW05rUMopml1xVrNQ6F1uAszOAMJLh8UgsemXzvyMjFjFhpr6s94c/MfRWu
# FL+Kcd/Kl7HYR+ocheBFThIcFClYzG/Tf8u+wQ5KbyCcrtlzMlkI5y2SoRoR/jKY
# pl0rl+CL05zMbbUNrkdjOEcXW28T2moQbh9Jt0RbtAgKh1pZBHYRoad3AhMcMYIF
# 6TCCBeUCAQEwJDAQMQ4wDAYDVQQDDAVKME43RQIQJTSMe3EEUZZAAWO1zNUfWTAJ
# BgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAj
# BgkqhkiG9w0BCQQxFgQUWccxN61pz/uHmBvY0SiI2+l/seUwDQYJKoZIhvcNAQEB
# BQAEggIAUKy9aC3z2IJ3USu+g0zGkbKuXFw8bP+WRGAI3McreUUnOchutKIqgIbT
# St29Zb4cqUujp5fn2bxTwZIvj5M3JbnpAK/3FL2c9lONpQeB4aPTc7D9zNTVxQhq
# tNx9E9zJTLK5nIGYn4hBnJR2VlDTxluhOIMTYKhNtAxcjvGk04GpSleYG3MTOHJ1
# xjBktaa5wHqrn/IKazKlEdJBavFFXKQdZERnln/bG2+gSvtdcz0n+ylO2Lqg2Szs
# x2OjevK6AY7vi5TfGRlZ+Y4kES0f1PmqZzIuO74Aiskwj5pzAojyP6B4LpP6nWgY
# hDgvXH/8m6O+l2DfGuzeMFwa6a8IC9bZk2o2JwS2wJP9cOQ0NejDdfwBIfB68idz
# PrGMZjCmoovNutYCsM8ykehsw5+n73MQfCzj3Uq7MIbgXSTZzKyVXtBxwS1n+ULa
# qxn1+bnjYwyv9LxWj8tUl0jI2vx12Nu+2R3Qxc4yY1Xmw394SySOsQgXTWlR40aT
# 5GmR2tNEEAePYjax9BkpG2RWDyOC5uE/kDgeQR42WEySbya5WMNaIwzJF6pGhsKN
# llwnFqART32O04SMolVMDp7ltZ21xM4Hd5UKx5qCXcHx3cFwHBCg43sni/p7Idbi
# DNiSahRu6pYpUxecCvBEXiwCQflwlWxesowYUWixdzhrSeY7MY6hggMgMIIDHAYJ
# KoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNB
# NDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAKekqInsmZQpAGYzhNhpedMA0G
# CWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG
# 9w0BCQUxDxcNMjIwNTE5MTcwMDA0WjAvBgkqhkiG9w0BCQQxIgQgI4GeiQ9+m1Id
# 0MjqbtdyYV2WYdpbEERXLPx00iBnG8UwDQYJKoZIhvcNAQEBBQAEggIATsjXBBXl
# ygk13UXmoHBcEWbu93+WC1Ga1iSkqdgTBTeWrKRRrFq1X0TTNBAYT3Br82oSXHx/
# AY8FhNv+rvlOUBilAWX2xK1hQjn4heCCM0UQCd2oUdOT1JHzIfP0NJEs5+NCQ6ef
# 1fvBwRTySK6ZttYB6g2vQoNAW5EblRZ/venYdpprjFLcgg+mrdbIc3t6o51ulC+e
# eljrGiyW7Ij6FKJxjfIgWho3OeuxKGmeXU4sLIFwR1CvRieJNx40B5nKD0um2iqO
# eZ/CAKbfikV78hhVZ0ltUgW0knCuDmCKQIXRIyTf+oH0UgVHCNQbb2RWFZ1g3w+J
# 3zL1K6aPTaktbXEuD6yv+OJ1uqPbfsRS1HhCc0DQ3JAANifXm2HWjXkUc2KZ3vUx
# vAQYKbK4qFUB6HxhHFM2aG0tYjBp+hs9JcQmk08d2jlpmQvgHLUIX5GkCub22YBG
# spRjIPj5b2zyqkpExrx4nglCP3Oa7jKfJLLYuxdTGE6NjuOHZ8rJRtCJzfuJMRRN
# A32uAQXOd4rqmCKKmc4hLi82jfCUjuXpT5IvrLKPbR9JgMIjLN+XWN2JoxxGNVWb
# UVA1X12zVGUMcmMK7LLj1XR8dwXLQdgUYzA19x4uv+7J/pDAUPkb8E2Gn3RYX8+t
# LmCSKrERyS4fBdMRGdIxMnPFYZV4q2sTckQ=
# SIG # End signature block
