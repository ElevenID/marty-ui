param(
  [int]$BrowserProcessId,
  [string]$BrowserExecutable,
  [switch]$ProbeRuntimeProperties
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$automationType = [System.Windows.Automation.AutomationElement]
$ariaField = $automationType.GetField('AriaRoleProperty')
$ariaProperty = $automationType.GetProperty('AriaRoleProperty')
$ariaRole = $null
if ($ariaField) { $ariaRole = $ariaField.GetValue($null) }
elseif ($ariaProperty) { $ariaRole = $ariaProperty.GetValue($null, $null) }
if ($ProbeRuntimeProperties) {
  # Reflection only: never enumerate windows or invoke any control in this mode.
  @{state='RUNTIME_PROPERTIES_CHECKED'; aria_role_available=($null -ne $ariaRole);
    control_type_available=($null -ne $automationType.GetField('ControlTypeProperty'));
    localized_control_type_available=($null -ne $automationType.GetField('LocalizedControlTypeProperty'));
    class_name_available=($null -ne $automationType.GetField('ClassNameProperty'))} | ConvertTo-Json -Compress
  exit 0
}
if ($BrowserProcessId -le 0 -or [string]::IsNullOrWhiteSpace($BrowserExecutable)) { throw 'Owned browser identity is required' }
$process = Get-Process -Id $BrowserProcessId
if ($process.ProcessName -ne 'chrome' -or $process.Path -ne $BrowserExecutable) { throw 'Owned Chrome process identity mismatch' }
$root = [System.Windows.Automation.AutomationElement]::RootElement
$pidCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $BrowserProcessId)
$windows = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $pidCondition)
$cancelCandidates = New-Object System.Collections.Generic.List[object]
$walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
foreach ($window in $windows) {
  if ($window.Current.ClassName -ne 'Chrome_WidgetWin_1') { continue }
  $buttons = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants,
    (New-Object System.Windows.Automation.AndCondition(
      (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)),
      (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, 'Cancel')))))
  foreach ($button in $buttons) {
    if ($button.Current.IsOffscreen -or -not $button.Current.IsEnabled) { continue }
    $current = $walker.GetParent($button); $dialog = $null; $documentAncestor = $false
    for ($depth=0; $current -and $depth -lt 30; $depth++) {
      if ($current.Current.ControlType -eq [System.Windows.Automation.ControlType]::Document) { $documentAncestor=$true; break }
      $role = $null
      if ($null -ne $ariaRole) { $role = $current.GetCurrentPropertyValue($ariaRole, $true) }
      # Older installed .NET UIAutomationClient lacks AriaRoleProperty. Its
      # supported native LocalizedControlType still identifies dialog controls.
      if (-not $dialog -and ($role -match '^(alert)?dialog$' -or $current.Current.LocalizedControlType -match '^(alert )?dialog$')) { $dialog=$current }
      if ([System.Windows.Automation.Automation]::Compare($current,$window)) { break }
      $current=$walker.GetParent($current)
    }
    if ($documentAncestor -or -not $dialog) { continue }
    $elements = $dialog.FindAll([System.Windows.Automation.TreeScope]::Subtree, [System.Windows.Automation.Condition]::TrueCondition)
    $credentialDialog = $false
    foreach ($element in $elements) {
      if ($element.Current.Name -match '(?i)credential|identity|bluetooth|phone|QR code|another device|wallet') { $credentialDialog=$true; break }
    }
    if ($credentialDialog) { $cancelCandidates.Add(@{ button=$button; dialog=$dialog }) }
  }
}
if ($cancelCandidates.Count -ne 1) {
  @{state='NO_UNAMBIGUOUS_NATIVE_CHOOSER'; native_cancel_candidates=$cancelCandidates.Count; owned_chrome_windows=$windows.Count} | ConvertTo-Json -Compress
  exit 2
}
$selected=$cancelCandidates[0]
$nameBytes=[Text.Encoding]::UTF8.GetBytes($selected.dialog.Current.Name)
$sha=[Security.Cryptography.SHA256]::Create()
$dialogHash=([BitConverter]::ToString($sha.ComputeHash($nameBytes))).Replace('-','').ToLowerInvariant()
$pattern=$selected.button.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
if (-not $pattern) { throw 'Native Cancel button has no InvokePattern' }
$pattern.Invoke()
@{state='NATIVE_CANCEL_INVOKED'; browser_process_id=$BrowserProcessId; dialog_name_sha256=$dialogHash;
  cancel_control='Cancel'; mechanism='Windows UIAutomation InvokePattern on browser-owned non-document dialog';
  observed_at=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Compress

