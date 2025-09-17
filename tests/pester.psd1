@{
    Run        = @{
        Path = @('./tests')
    }
    Output     = @{
        Verbosity = 'Normal'
    }
    TestResult = @{
        Enabled      = $true
        OutputPath   = './TestResults/Pester-TestResults.xml'
        OutputFormat = 'NUnitXml'
    }
}