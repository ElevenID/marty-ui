# Pure projections of the runner's already-validated release inputs. Keep Docker,
# environment reads, builds and artifact writes in the calling runner.
function New-BetaApplicationImagePlan {
    param(
        [Parameter(Mandatory = $true)][string[]]$Services,
        [Parameter(Mandatory = $true)][string]$ReleaseVersion,
        [Parameter(Mandatory = $true)][bool]$OfficialStackRelease,
        [Parameter(Mandatory = $true)][string]$IssuanceReference,
        [Parameter(Mandatory = $true)][string]$IssuanceDigest,
        [string]$ServicesReference = "",
        [string]$ServicesDigest = ""
    )

    foreach ($service in $Services) {
        $externalIssuance = $service -eq "issuance"
        $selectorPresent = $OfficialStackRelease -and -not $externalIssuance
        $imageExpression = if ($externalIssuance) { '${MARTY_ISSUANCE_IMAGE}' }
            elseif ($OfficialStackRelease) { '${MARTY_SERVICES_IMAGE}' }
            else { "elevenid-local/${service}:${ReleaseVersion}" }
        $effectiveReference = if ($externalIssuance) { $IssuanceReference }
            elseif ($OfficialStackRelease) { $ServicesReference }
            else { $imageExpression }
        $knownDigest = if ($OfficialStackRelease) {
            if ($externalIssuance) { $IssuanceDigest } else { $ServicesDigest }
        } else { $null }
        [pscustomobject][ordered]@{
            service = $service
            image_expression = $imageExpression
            effective_reference = $effectiveReference
            artifact_role = if ($externalIssuance) { "issuance" } elseif ($OfficialStackRelease) { "services" } else { "local" }
            selector_present = $selectorPresent
            selector = if ($selectorPresent) { $service -replace '-', '_' } else { $null }
            build_eligible = -not $OfficialStackRelease -and -not $externalIssuance
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
        if ($entry.selector_present) {
            "    environment:"
            "      SERVICE_NAME: $($entry.selector)"
        }
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
