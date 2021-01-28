module Program =
    let [<EntryPoint>] main _ =
        let testContainer = KeyVaultSignTests.TestClass()
        testContainer.keyvault <- "isaac-hsm"
        testContainer.certificateName <- "loantest"

        testContainer.``KeyVault sign test``()
        testContainer.``KeyVault sign and verify test``()
        0
