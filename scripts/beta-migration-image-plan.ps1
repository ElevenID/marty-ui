# Use the same native artifacts for rehearsal and live migration; ordinary
# database maintenance never receives the one-time KMS initialization credential.
function ConvertTo-BetaMigrationImageLines {
    param([Parameter(Mandatory = $true)][string]$MigrationImage,
          [Parameter(Mandatory = $true)][string]$IssuanceImage,
          [Parameter(Mandatory = $true)][string]$RevocationImage)
    foreach ($image in @($MigrationImage, $IssuanceImage, $RevocationImage)) {
        if ($image -cnotmatch '^sha256:[0-9a-f]{64}$') { throw 'Migration jobs require immutable image IDs' }
    }
    'services:'
    foreach ($entry in @(@('db-migrate', $MigrationImage), @('issuance-migrations', $IssuanceImage),
                         @('revocation-profile-migrate', $RevocationImage))) {
        "  $($entry[0]):"
        "    image: $($entry[1])"
        '    build: !reset null'
        if ($entry[0] -eq 'db-migrate') {
            '    environment:'
            "      MARTY_KMS_BOOTSTRAP_ENABLED: 'false'"
            '      BAO_CACERT: /bao/public-ca/ca.crt'
            '      NOTIFICATION_OPENBAO_CA_CERT_FILE: /bao/public-ca/ca.crt'
            foreach ($key in @('BAO_TOKEN', 'BAO_TOKEN_FILE', 'OPENBAO_SERVICE_TOKEN', 'OPENBAO_SERVICE_TOKEN_FILE')) {
                "      ${key}: ''"
            }
            '    volumes: !override'
            foreach ($mount in @(@('openbao_public_ca', '/bao/public-ca'), @('openbao_notification', '/bao/notification'))) {
                '      - type: volume'
                "        source: $($mount[0])"
                "        target: $($mount[1])"
                '        read_only: true'
            }
        }
    }
}
