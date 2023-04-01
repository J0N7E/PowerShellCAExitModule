<#
 .SYNOPSIS
    PowerShell CA ExitModule

 .DESCRIPTION
    Export certificate requests to SQL

 .NOTES
    AUTHOR Jonas Henriksson

 .LINK
    https://github.com/J0N7E

 .NOTES
    Register task in powershell with:

    @{
        TaskName    = "PowerShell CA ExitModule"
        Description = 'Triggers on Security event 4870, 4887, 4888 & 4889'
        TaskPath    = '\'
        Action      =
        @{
            Execute          = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe'
            Argument         = '-ExecutionPolicy RemoteSigned -NoProfile -File .\PowerShellCAExitModule.ps1 -RequestId "$(RequestId)" -SerialNumber "$(SerialNumber)"'
            WorkingDirectory = "$($PWD.Path)"
        } | ForEach-Object {
            New-ScheduledTaskAction @_
        }
        Trigger     =
        @(
            @{
                Enabled = $true
                Subscription = @('<QueryList>',
                                 '  <Query Id="0" Path="Security">',
                                 '        <Select Path="Security">',
                                 '            *[System[EventID=4870]] or',
                                 '            *[System[EventID=4887]] or',
                                 '            *[System[EventID=4888]] or',
                                 '            *[System[EventID=4889]]',
                                 '        </Select>',
                                 '    </Query>',
                                 '</QueryList>') -join "`n"
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
        Settings    = New-ScheduledTaskSettingsSet -MultipleInstances Parallel `
                                                   -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
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
    Debug event source:

    foreach ($EventSource in @('PowerShell CA ExitModule'))
    {
        #Check registered event source exist with:
        [System.Diagnostics.EventLog]::SourceExists($EventSource)

        #Check which log registered event source is registered under
        [System.Diagnostics.EventLog]::LogNameFromSourceName($EventSource,'.')

        #Remove registered event with:
        #[System.Diagnostics.EventLog]::DeleteEventSource($EventSource)
    }
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
                   -Source 'PowerShell CA ExitModule' `
                   -EntryType Error `
                   -EventId 1234 `
                   -Message "$_`n`nRequestId: $($Properties.RequestID)" `
                   -Category 0
    throw $_
}


# SIG # Begin signature block
# MIIekQYJKoZIhvcNAQcCoIIegjCCHn4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUk0GccxWR/r1wp/LVFW4wQChi
# 83WgghgSMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
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
# 8jCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAw
# ZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBS
# b290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUu
# ySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8
# Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0M
# G+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldX
# n1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVq
# GDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFE
# mjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6
# SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXf
# SwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b23
# 5kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ
# 6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRp
# L5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
# BBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1R
# i6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADAN
# BgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVe
# qRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3vot
# Vs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum
# 6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJ
# aISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/
# ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBq4wggSWoAMCAQIC
# EAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAw
# MDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQw
# OTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2
# EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuA
# hIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQ
# h0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7Le
# Sn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw5
# 4qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP2
# 9p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjF
# KfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHt
# Qr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpY
# PtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4J
# duyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGj
# ggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2
# mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBp
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUH
# MAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRS
# b290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EM
# AQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIB
# fmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb
# 122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+r
# T4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQ
# sl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsK
# RcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKn
# N36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSe
# reU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no
# 8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcW
# oWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInw
# AM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7
# qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbAMIIEqKADAgECAhAMTWlyS5T6PCpKPSkH
# gD1aMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwOTIxMDAwMDAwWhcNMzMxMTIx
# MjM1OTU5WjBGMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxJDAiBgNV
# BAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAM/spSY6xqnya7uNwQ2a26HoFIV0MxomrNAcVR4eNm28
# klUMYfSdCXc9FZYIL2tkpP0GgxbXkZI4HDEClvtysZc6Va8z7GGK6aYo25BjXL2J
# U+A6LYyHQq4mpOS7eHi5ehbhVsbAumRTuyoW51BIu4hpDIjG8b7gL307scpTjUCD
# HufLckkoHkyAHoVW54Xt8mG8qjoHffarbuVm3eJc9S/tjdRNlYRo44DLannR0hCR
# RinrPibytIzNTLlmyLuqUDgN5YyUXRlav/V7QG5vFqianJVHhoV5PgxeZowaCiS+
# nKrSnLb3T254xCg/oxwPUAY3ugjZNaa1Htp4WB056PhMkRCWfk3h3cKtpX74LRsf
# 7CtGGKMZ9jn39cFPcS6JAxGiS7uYv/pP5Hs27wZE5FX/NurlfDHn88JSxOYWe1p+
# pSVz28BqmSEtY+VZ9U0vkB8nt9KrFOU4ZodRCGv7U0M50GT6Vs/g9ArmFG1keLuY
# /ZTDcyHzL8IuINeBrNPxB9ThvdldS24xlCmL5kGkZZTAWOXlLimQprdhZPrZIGwY
# UWC6poEPCSVT8b876asHDmoHOWIZydaFfxPZjXnPYsXs4Xu5zGcTB5rBeO3GiMiw
# bjJ5xwtZg43G7vUsfHuOy2SJ8bHEuOdTXl9V0n0ZKVkDTvpd6kVzHIR+187i1Dp3
# AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgB
# hv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYE
# FGKK3tBh/I8xFO2XC809KpQU31KcMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9j
# cmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZU
# aW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEy
# NTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAFWqKhrzRvN4
# Vzcw/HXjT9aFI/H8+ZU5myXm93KKmMN31GT8Ffs2wklRLHiIY1UJRjkA/GnUypsp
# +6M/wMkAmxMdsJiJ3HjyzXyFzVOdr2LiYWajFCpFh0qYQitQ/Bu1nggwCfrkLdcJ
# iXn5CeaIzn0buGqim8FTYAnoo7id160fHLjsmEHw9g6A++T/350Qp+sAul9Kjxo6
# UrTqvwlJFTU2WZoPVNKyG39+XgmtdlSKdG3K0gVnK3br/5iyJpU4GYhEFOUKWaJr
# 5yI+RCHSPxzAm+18SLLYkgyRTzxmlK9dAlPrnuKe5NMfhgFknADC6Vp0dQ094XmI
# vxwBl8kZI4DXNlpflhaxYwzGRkA7zl011Fk+Q5oYrsPJy8P7mxNfarXH4PMFw1nf
# J2Ir3kHJU7n/NBBn9iYymHv+XEKUgZSCnawKi8ZLFUrTmJBFYDOA4CPe+AOk9kVH
# 5c64A0JH6EE2cXet/aLol3ROLtoeHYxayB6a1cLwxiKoT5u92ByaUcQvmvZfpyeX
# upYuhVfAYOd4Vn9q78KVmksRAsiCnMkaBXy6cbVOepls9Oie1FqYyJ+/jbsYXEP1
# 0Cro4mLueATbvdH7WwqocH7wl4R44wgDXUcsY6glOJcB0j862uXl9uab3H4szP8X
# TE0AotjWAQ64i+7m4HJViSwnGWH2dwGMMYIF6TCCBeUCAQEwJDAQMQ4wDAYDVQQD
# DAVKME43RQIQJTSMe3EEUZZAAWO1zNUfWTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGC
# NwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU6KShG95O
# XdgT3jpElKvdSYXUGzEwDQYJKoZIhvcNAQEBBQAEggIAh7S8S57PbdfJIZTJej52
# LIDTR4MnF29zD4HVCN+MESJp5bY2T5HC2zt5kwhuuFPY3vLWig8Eo1vm431/Jq05
# NOEb7mi9XQm+dstKp0L5dx6M0bXOC9dHy1/p7Wfg2p1tzYgLoFhQdwF0RzK7dJ1M
# 0LI59J55skw0RcnkZ9KCAQ3uFioVWq9B01yGRxtTjJtrqlJaL8LfMq3/r9NpK0rE
# taFhRuX2OQ/Koer63j11oYv/teRUToB91TTIkcTcSSPF4rY5a8knlTo+PlbBUSQl
# eZb01XjwSGPVdKUp4WEm26TIIHyJH4uR1GWgKQahMUgK7QDc6aJz1MEFKkK7+eHn
# R4OBh0pJR+p17pJCmjtL8UA3McAylMu420viidyGk4piL1EvD/89lenooYQ5cWR1
# OmWKlsoc5LZYKxTfj/CXyfCEZ200MUPAtSoebD84P5V/b8dRlC1jsJTXDYh+DRxg
# c25EUiR+8mZeoPK4uruc3BcygJz4cQi1H9GguILuSCkIYgBPAeWcsgrnirdjbd76
# iyDDZEU+wlCCrkvKbEt3GeM5KFD9VEKhQsPmpIunqA9YQptXgpgevjhVcau7bVUw
# 57qQZ/OUfEO3vRxoTTcaVRDPe4q3RQ9vn43ie+UyQj+yW+vOV0Pdzot1j8impx2e
# M9/cDtFByaLQGSVT5ZiBP1uhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEw
# dzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNV
# BAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1w
# aW5nIENBAhAMTWlyS5T6PCpKPSkHgD1aMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMwNDAxMTEwMDA0
# WjAvBgkqhkiG9w0BCQQxIgQgxvYlHLO33H/2Cbf8OEFrIPM/yHp4/r8oO90mpYtD
# MLkwDQYJKoZIhvcNAQEBBQAEggIAhTBxYJI1H5/YudumA4PnfmvS7AGB7/xm59qM
# pJ+k6NFFBt3EZPSA2g+aVvpEEE9/BMkldy1su5oPAAQ2e+jjJaxEpaOlJT61D87o
# yHAXAMO3C8OsNr5THKiAHcRLnQfCMlgRoeC7OiCmPFJNKXLajtxHpf26/LbhQp/k
# jrFTk+a7l+8s2UYi4ouEaAwqM2qVeUZveOfPC6s7N/xOlhFGpyVAcLbmMuBwelRh
# /npp7oAmntewGLJtIbVJKgRETYOD1K3LSZmLvYDZcBA70LKIgzYunV5O/2mlG9B+
# pcQL+2y5hFWABiX3rWxL9mGwibh5+JE2Pl+0TQlfsTHzZ5ITSpgHS5ELfdblWHL/
# P3bB5U6uc/mpdijrjZ1I5fojrKMaHBbPxn+gR/r+Z3NV2fRNIFvpIfPuRq74sDjb
# HC54bdnqkgK7NoDXoSaWo3bC0EEIsmf/xeZof6fUaZLX9gUUII25E63ePs0bUnyD
# NSJ4Hayb/dHi3UEbj9xbODgYKehxj5YbX7dRejmZU+BkjX1GxLevnWtEAhwPGIRO
# qFyuvwvZAgRJrwXQeuN5xD4Gawheg4mR9p5k7johmxqMpcoSEQgVRBnZChgVgr/F
# N895W4OqYeH9dRLzUkziIYQHWopTr0y3U2Ttm4SksD0ssaKonHZgRK7dmGO442vk
# MeCcinU=
# SIG # End signature block
