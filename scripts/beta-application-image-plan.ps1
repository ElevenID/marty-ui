# Pure projections of the runner's already-validated release inputs. Keep Docker,
# environment reads, builds and artifact writes in the calling runner.
function New-BetaApplicationImagePlan {
    param(
        [Parameter(Mandatory = $true)][string[]]$Services,
        [Parameter(Mandatory = $true)][string]$ReleaseVersion,
        [Parameter(Mandatory = $true)][bool]$OfficialStackRelease,
        [string]$ServicesReference = "",
        [string]$ServicesDigest = ""
    )

    foreach ($service in $Services) {
        $selectorPresent = $OfficialStackRelease
        $imageExpression = if ($OfficialStackRelease) { '${MARTY_SERVICES_IMAGE}' }
            else { "elevenid-local/${service}:${ReleaseVersion}" }
        $effectiveReference = if ($OfficialStackRelease) { $ServicesReference }
            else { $imageExpression }
        $knownDigest = if ($OfficialStackRelease) {
            $ServicesDigest
        } else { $null }
        [pscustomobject][ordered]@{
            service = $service
            image_expression = $imageExpression
            effective_reference = $effectiveReference
            artifact_role = if ($OfficialStackRelease) { "services" } else { "local" }
            selector_present = $selectorPresent
            selector = if ($selectorPresent) {
                if ($service -eq "issuance") { "issuance_native" }
                else { $service -replace '-', '_' }
            } else { $null }
            build_eligible = -not $OfficialStackRelease
            known_digest = $knownDigest
        }
    }
}

function ConvertTo-BetaApplicationImageLines {
    param([Parameter(Mandatory = $true)][object[]]$Plan)

    "services:"
    foreach ($entry in $Plan) {
        "  $($entry.service):"
        "    image: $($entry.image_expression)"
        if ($entry.selector_present -or $entry.service -eq "issuance") {
            "    environment:"
            if ($entry.service -eq "issuance") { "      SERVICE_NAME: issuance_native" }
            else { "      SERVICE_NAME: $($entry.selector)" }
            if ($entry.service -eq "issuance") {
                "      MARTY_SCHEMA_STARTUP_MODE: validate"
                "      CANVAS_MIRROR_WORKER_ENABLED: 'false'"
            }
        }
        if ($entry.service -eq "issuance") {
            if ($entry.build_eligible) {
                "    build:"
                "      context: ."
                "      dockerfile: services/Dockerfile"
                "      args:"
                "        SERVICE_NAME: issuance-native"
            } else {
                "    build: !reset null"
            }
            "    entrypoint: [/usr/local/bin/marty-issuance-service]"
            "    command: []"
        }
    }
    $issuance = @($Plan | Where-Object { $_.service -eq "issuance" })
    if ($issuance.Count -gt 1) { throw "Issuance image plan is ambiguous" }
    if ($issuance.Count -eq 1) {
        "  issuance-migrations:"
        "    image: $($issuance[0].image_expression)"
        "    build: !reset null"
        "    entrypoint: [/usr/local/bin/marty-issuance-service]"
        "    command: [migrate]"
        "    environment:"
        "      SERVICE_NAME: issuance_native"
        '      DATABASE_URL: postgresql://marty:${MARTY_DB_PASSWORD:-marty_dev_password}@postgres:5432/marty'
        "    depends_on:"
        "      organization: {condition: service_healthy}"
        "      credential-template: {condition: service_healthy}"
    }
}

function Set-BetaApplicationVerificationImage {
    param(
        [Parameter(Mandatory = $true)][object[]]$Plan,
        [Parameter(Mandatory = $true)][string]$ImageId
    )

    if ($ImageId -notmatch '^sha256:[0-9a-f]{64}$') {
        throw "Could not pin the local verification runtime image before rehearsal"
    }
    $verification = @($Plan | Where-Object { $_.service -eq "verification" })
    if ($verification.Count -ne 1 -or $verification[0].artifact_role -ne "local") {
        throw "Verification image pin requires exactly one local verification plan entry"
    }
    foreach ($entry in $Plan) {
        # Return fresh records: the pre-build plan remains an independent value.
        $copy = [ordered]@{}
        foreach ($property in $entry.PSObject.Properties) {
            $copy[$property.Name] = $property.Value
        }
        if ($entry.service -eq "verification") {
            $copy.image_expression = $ImageId
            $copy.effective_reference = $ImageId
            $copy.known_digest = $ImageId
        }
        [pscustomobject]$copy
    }
}

function Get-BetaApplicationImageEvidence {
    param([Parameter(Mandatory = $true)][object[]]$Plan)

    foreach ($entry in $Plan) {
        [pscustomobject][ordered]@{
            service = $entry.service
            digest = $entry.known_digest
            inspect_reference = if ($null -eq $entry.known_digest) { $entry.effective_reference } else { $null }
        }
    }
}
