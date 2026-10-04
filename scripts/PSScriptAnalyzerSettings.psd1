# PSScriptAnalyzer settings for Warden's PowerShell scripts.
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # install.ps1 is an interactive installer: Write-Host is the right tool
        # for coloured progress output that must not pollute the pipeline.
        'PSAvoidUsingWriteHost',
        # Private helper functions in a one-shot installer; -WhatIf plumbing
        # would add surface without adding safety.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
