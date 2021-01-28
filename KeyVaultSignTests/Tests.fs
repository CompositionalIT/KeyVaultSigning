namespace KeyVaultSignTests

open System
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type TestClass () =

    member val keyvault = "isaac-hsm" with get, set
    member val certificateName = "loantest" with get, set

    [<TestMethod>]
    member this.``KeyVault sign test``() =

        //KeyVault.configureAlgorithm <- KeyVault.Algorithms.SHA384
        //KeyVault.configureEncoding <- System.Text.Encoding.Unicode

        let signature = KeyVault.sign this.keyvault this.certificateName "Here's a message"
        // signature |> printfn "%A"
        Assert.IsNotNull(signature);

    [<TestMethod>]
    member this.``KeyVault sign async test``() =

        let signature = KeyVault.signAsync this.keyvault this.certificateName "Here's a message" |> Async.RunSynchronously
        // signature |> printfn "%A"
        Assert.IsNotNull(signature);

    [<TestMethod>]
    member this.``KeyVault sign and verify test``() =

        let msg = "Here's a message"
        let signatureResult = KeyVault.sign this.keyvault this.certificateName msg

        let res = KeyVault.verify this.keyvault this.certificateName msg signatureResult.Signature
        // res |> printfn "%A"
        Assert.IsNotNull(res);
