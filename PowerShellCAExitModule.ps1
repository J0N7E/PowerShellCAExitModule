<#
 .SYNOPSIS
    PowerShell CA ExitModule

 .DESCRIPTION
    Export certificate requests to SQL

 .NOTES
    Register task in powershell with:

    @{
        TaskName    = "PowerShell CA ExitModule"
        Description = 'Triggers on Security event 4870, 4887 & 4889'
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
