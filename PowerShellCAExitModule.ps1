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
# MIIekwYJKoZIhvcNAQcCoIIehDCCHoACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUk0GccxWR/r1wp/LVFW4wQChi
# 83WgghgUMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
# AQsFADAQMQ4wDAYDVQQDDAVKME43RTAeFw0yMzA5MDcxODU5NDVaFw0yODA5MDcx
# OTA5NDRaMBAxDjAMBgNVBAMMBUowTjdFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA0cNYCTtcJ6XUSG6laNYH7JzFfJMTiQafxQ1dV8cjdJ4ysJXAOs8r
# nYot9wKl2FlKI6eMT6F8wRpFbqKqmTpElxzM+fzknD933uEBLSAul/b0kLlr6PY2
# oodJC20VBAUxthFUYh7Fcni0dwz4EjXJGxieeDDLZYRT3IR6PzewaWhq1LXY3fhe
# fYQ1Q2nqHulVWD1WgucgIFEfUJCWcOvfmJBE+EvkNPVoKAqFxJ61Z54z8y6tIjdK
# 3Ujq4bgROQqLsFMK+mII1OqcLRKMgWkVIS9nHfFFy81VIMvfgaOpoSVLatboxAnO
# mn8dusJA2DMH6OL03SIBb/FwE7671sjtGuGRp+nlPnkvoVqFET9olZWDxlGOeeRd
# Tc3jlcEPb9XLpiGjlQfMfk4ycSwraJqn1cYDvSXh3K6lv0OeSLa/VQRlEpOmttKB
# EI/eFMK76DZpGxFvv1xOg1ph3+01hCboOXePu9qSNk5hnIrBEb9eqks3r5ZDfrlE
# wjFUhd9kLe2UKEaHK7HI9+3x1WhTgNRKWzKzqUcF9aVlpDQRplqbUMJEzMxzRUIk
# 01NDqw46gjUYet6VnIPqnQAe2bLWqDMeL3X6P7cAHxw05yONN51MqyBFdYC1MieY
# uU4MOoIfIN6M6vEGn7avjw9a4Xpfgchtty2eNgIRg+KuJ3Xxtd1RDjUCAwEAAaNd
# MFswDgYDVR0PAQH/BAQDAgWgMCoGA1UdJQQjMCEGCCsGAQUFBwMDBgkrBgEEAYI3
# UAEGCisGAQQBgjcKAwQwHQYDVR0OBBYEFFjQBHg94o+OtZeRxQoH0mKFzMApMA0G
# CSqGSIb3DQEBCwUAA4ICAQBSglLs0PCn7g36iGRvqXng/fq+6nL3ZSLeLUXSDoFX
# KhJ3K6wFSiHBJtBYtWc7OnHIbIg1FFFAi5GIP56MMwmN4NoY0DrBN0Glh4Jq/lhu
# iah5zs/9v/aUvtwvBD4NVX0G/wJuRuX697UQZrtkWninB46BMPU+gEg1ctn0V4zQ
# 3fazrcmJqD9xIwKlOXsvxOAO5OJ51ucdsubD6QkJa++4bGd5HhoC8/O18mxz6YYa
# gOnXWJObybkwdkDC9MUjy5wZNAv48DkUM+OArbfM3ZpfcAVTnDrfuzpoOKTkcdgb
# N+4VXJC/ly1D98f+IpEOw1UItX8Hg67WfU9sXcIY+fghzHPHF864vp2F/G75i02M
# oqeRpeO3guwum3DbKCkKts5S1QXnE7pmeqe4U595jCVhELeB6ifrvj0ulSlOU5GE
# twNY5VL0T3cHegBmtQXFfQoT6vboF6m9I7kVlKGT4WI8M/UQYCQ2ZP3HTjdSHt9U
# cJslGMqDxhbkGLH49ESP5ghbRddll24dsw0dF96lOIEmhB01UNIz40TonraK3cku
# Jdnrh/2fHYbycGHjkowiMUJQaihbZBRKvBHhrM7OuQ96M9g8Gk2RCIqdX0lO8n2y
# S8fnzEoWe8FVwE5bgA5Nwl6iYdoszubYgh+siVMe2EFaUh0DXXpbQ3JxjMGe5qVK
# 1zCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAw
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
# qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbCMIIEqqADAgECAhAFRK/zlJ0IOaa/2z9f
# 5WEWMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjMwNzE0MDAwMDAwWhcNMzQxMDEz
# MjM1OTU5WjBIMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# IDAeBgNVBAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIzMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAo1NFhx2DjlusPlSzI+DPn9fl0uddoQ4J3C9Io5d6
# OyqcZ9xiFVjBqZMRp82qsmrdECmKHmJjadNYnDVxvzqX65RQjxwg6seaOy+WZuNp
# 52n+W8PWKyAcwZeUtKVQgfLPywemMGjKg0La/H8JJJSkghraarrYO8pd3hkYhftF
# 6g1hbJ3+cV7EBpo88MUueQ8bZlLjyNY+X9pD04T10Mf2SC1eRXWWdf7dEKEbg8G4
# 5lKVtUfXeCk5a+B4WZfjRCtK1ZXO7wgX6oJkTf8j48qG7rSkIWRw69XloNpjsy7p
# Be6q9iT1HbybHLK3X9/w7nZ9MZllR1WdSiQvrCuXvp/k/XtzPjLuUjT71Lvr1KAs
# NJvj3m5kGQc3AZEPHLVRzapMZoOIaGK7vEEbeBlt5NkP4FhB+9ixLOFRr7StFQYU
# 6mIIE9NpHnxkTZ0P387RXoyqq1AVybPKvNfEO2hEo6U7Qv1zfe7dCv95NBB+plwK
# WEwAPoVpdceDZNZ1zY8SdlalJPrXxGshuugfNJgvOuprAbD3+yqG7HtSOKmYCaFx
# smxxrz64b5bV4RAT/mFHCoz+8LbH1cfebCTwv0KCyqBxPZySkwS0aXAnDU+3tTbR
# yV8IpHCj7ArxES5k4MsiK8rxKBMhSVF+BmbTO77665E42FEHypS34lCh8zrTioPL
# QHsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYG
# A1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCG
# SAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4E
# FgQUpbbvE+fvzdBkodVWqWUxo97V40kwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1
# NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNI
# QTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAgRrW3qCp
# tZgXvHCNT4o8aJzYJf/LLOTN6l0ikuyMIgKpuM+AqNnn48XtJoKKcS8Y3U623mzX
# 4WCcK+3tPUiOuGu6fF29wmE3aEl3o+uQqhLXJ4Xzjh6S2sJAOJ9dyKAuJXglnSoF
# eoQpmLZXeY/bJlYrsPOnvTcM2Jh2T1a5UsK2nTipgedtQVyMadG5K8TGe8+c+nji
# kxp2oml101DkRBK+IA2eqUTQ+OVJdwhaIcW0z5iVGlS6ubzBaRm6zxbygzc0brBB
# Jt3eWpdPM43UjXd9dUWhpVgmagNF3tlQtVCMr1a9TMXhRsUo063nQwBw3syYnhmJ
# A+rUkTfvTVLzyWAhxFZH7doRS4wyw4jmWOK22z75X7BC1o/jF5HRqsBV44a/rCcs
# QdCaM0qoNtS5cpZ+l3k4SF/Kwtw9Mt911jZnWon49qfH5U81PAC9vpwqbHkB3NpE
# 5jreODsHXjlY9HxzMVWggBHLFAx+rrz+pOt5Zapo1iLKO+uagjVXKBbLafIymrLS
# 2Dq4sUaGa7oX/cR3bBVsrquvczroSUa31X/MtjjA2Owc9bahuEMs305MfR5ocMB3
# CtQC4Fxguyj/OOVSWtasFyIjTvTs0xf7UGv/B3cfcZdEQcm4RtNsMnxYL2dHZeUb
# c7aZ+WssBkbvQR7w8F/g29mtkIBEr4AQQYoxggXpMIIF5QIBATAkMBAxDjAMBgNV
# BAMMBUowTjdFAhB0XMs0val9mEnBo5ekK6KYMAkGBSsOAwIaBQCgeDAYBgorBgEE
# AYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTopKEb
# 3k5d2BPeOkSUq91JhdQbMTANBgkqhkiG9w0BAQEFAASCAgCoPkba2JxQWHGubJcS
# w5RhSEdJsuPjyfPTqPq/Qf/aH9HgApMuAF7hIBaJzSNs4u2xdcmYfb4/w6c66oaB
# nZzKQ6bRl9sEEQxj9vVNDhnVj4ePm286OM+63LGWHkkKpF5xwK/299NhBPeFAKcn
# d1ZFf/z3jmry0uwBUOBf7ek6npogrNLKymsbaS/OF1ohcQh50a9qIbwp4u+mBVaX
# mB6FPErkQnClJ877M14alJSsXzJOkde3Ee8aeFXhFGZVPH3O3qEmCbeQkjo8RM/z
# z6Z43t4VJbLCxJvUKm1GqAKR4BPiYmQYm9ArvV88lM/SASsXit8ZS0AePSx1nXQI
# aOrytwCV8aklq74PVdATIwD9PiBj/y9uHXmqgclde7aQ7tmuPuVw7wFEyScdHARE
# 3yWGEYi7P0GlSL8px+GR4mVKGlikhLzQ8bKKGNbrEZVOz29kbO7ntG2qbnqMbF//
# gJ+CzJ8jhnkucC6VVBbqTKSMdVJAndPvvz0rTAM2YUABCxj18P+JUUx0IpNCW7c0
# TWl/7UG0i1Xhqt8icUChZY/l0XB9GuRZASB2QRVcnF2KK6Q6fyKQ86eQF2au1WBs
# c8BzEGWwowbi91Q4JRCvzuPh1GU/0M+Xh2VrSys4k+9HqDnAPhkL36ts43sC6HND
# 7Tg7YVTurN2zR0HNFj+ETes44KGCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIB
# ATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzA5MDcxOTU5
# NThaMC8GCSqGSIb3DQEJBDEiBCBGOxOsUmxfX5n4SkCOTXFB2EkH9vfeQSVtQa9h
# ZNz7QTANBgkqhkiG9w0BAQEFAASCAgBbUc4Yq3LwR/kfQnHXPYWhMsG/swCICvps
# l4IvkMFJMNy9MUDE7iBuhudDBfx1nDVX71y9mElr/HoOf03qdn/8lATevqBrkOcA
# MU/aPvXJaJDWFlKcmqDQ2K5w0b1kci7KcPJQ5p7X/cnmUAdUCpgSCEOTJDLMh3B6
# kANb3CAdPQIhLwlyi95MzHe6QLr3J+K52kNxtNbT6xnHVGZ8GY7Fcti9FloM/WnH
# ptN4aks50rX7a6IXrsC9gONmltHHVz7PiQm9kPr5PIeoLvuVBnb4e7W4iE3HaR39
# B8QkdwvZJakAD0KZG0GjwbDBC247Mkn6NGtHqs/2Xp9wX5Ro3DAjx1QvUrGLMecC
# p1Ln+Z+2EPUBH8ABh9E6XUOXFi3tSH5gkt5Sb5WsoGDkJ3YD5pgpYMuxS28vKc6N
# tnA9SOqffh7azPpeGeqU7JNxScDxfuKmFcZJiOCiCOOtI2dCOJ2X5qGTwfWcpeRZ
# tDxTF1JvZ0hGZUcd5SrwrGX3e344+JLAWSuqhUBltFM0jFJcPgTQqSdCRb2i+RbL
# MttcU7vVjBysFlFX2E8RGYdfkisspBMMNOGnZPIzohb+M03LBLT7Rdl+fJuVtNve
# jYQpaCqiD+70pdirNEgo5dHtFR02zlLBpAcogirqUVe4sDga9pKotkkenJIbMpCl
# +hQ6euio9w==
# SIG # End signature block
