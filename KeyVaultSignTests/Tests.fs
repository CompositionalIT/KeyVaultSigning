namespace KeyVaultSignTests

open System
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type TestClass () =

    //// You can change the Azure credential funci
    //let changeDefaultCredentials =
    //    KeyVault.configureAzureCredentials <- fun() ->
    //        Azure.Identity.DefaultAzureCredential (
    //            Azure.Identity.DefaultAzureCredentialOptions (
    //                    //ExcludeEnvironmentCredential = true
    //                    //,ExcludeManagedIdentityCredential = true
    //                    ExcludeSharedTokenCacheCredential = true
    //                    ,ExcludeVisualStudioCredential = true
    //                    //,ExcludeVisualStudioCodeCredential = true
    //                    //,ExcludeAzureCliCredential = true
    //                    //,ExcludeInteractiveBrowserCredential = true
    //                ))

    member val keyvault = "isaac-hsm" with get, set
    member val certificateName = "loantest" with get, set

    [<TestMethod>]
    member this.``KeyVault sign test``() =

        //KeyVault.configureAlgorithm <- KeyVault.Algorithms.SHA384
        //KeyVault.configureEncoding <- System.Text.Encoding.Unicode

        let signature = KeyVault.sign this.keyvault this.certificateName "Here's a message"
        // signature |> printfn "%A"
        Assert.IsNotNull(signature);
        Assert.AreEqual(256, signature.Signature.Length)
        Assert.IsTrue (signature.KeyId.Contains this.keyvault)
        Assert.IsTrue (signature.KeyId.Contains this.certificateName)

    [<TestMethod>]
    member this.``KeyVault sign async test``() =

        let signature = KeyVault.signAsync this.keyvault this.certificateName "Here's a message" |> Async.AwaitTask |> Async.RunSynchronously
        // signature |> printfn "%A"
        Assert.IsNotNull(signature);
        Assert.AreEqual(256, signature.Signature.Length)
        Assert.IsTrue (signature.KeyId.Contains this.keyvault)
        Assert.IsTrue (signature.KeyId.Contains this.certificateName)

    [<TestMethod>]
    member this.``KeyVault sign and verify test``() =

        let msg = "Here's a message"
        let signatureResult = KeyVault.sign this.keyvault this.certificateName msg

        let res = KeyVault.verify this.keyvault this.certificateName msg signatureResult.Signature
        // res |> printfn "%A"
        Assert.IsNotNull(res);
        Assert.IsTrue res.IsValid

    [<TestMethod>]
    member this.``KeyVault sign and verify test async``() =
        task {
            let msg = "Here's a message"
            let! signatureResult = KeyVault.signAsync this.keyvault this.certificateName msg

            let! res = KeyVault.verifyAsync this.keyvault this.certificateName msg signatureResult.Signature
            // res |> printfn "%A"
            Assert.IsNotNull(res);
            Assert.IsTrue res.IsValid
        }:> System.Threading.Tasks.Task

    [<TestMethod>]
    member this.``KeyVault sign test2``() =

        //KeyVault.configureAlgorithm <- KeyVault.Algorithms.SHA384
        //KeyVault.configureEncoding <- System.Text.Encoding.Unicode

        let signature1 = KeyVault.sign this.keyvault this.certificateName "Here's a message2"

        let signature2 = KeyVault.sign this.keyvault this.certificateName "Here's a message2"

        let b1, b2 = signature1.Signature |> Convert.ToBase64String, signature2.Signature |> Convert.ToBase64String

        // signature |> printfn "%A"
        Assert.IsNotNull(signature2);
        Assert.AreEqual(256, signature2.Signature.Length)
        Assert.IsTrue (signature2.KeyId.Contains this.keyvault)
        Assert.IsTrue (signature2.KeyId.Contains this.certificateName)
        Assert.AreEqual(b1, b2)

    [<TestMethod>]
    member this.``KeyVault sign async test2``() =

        task {
            let! signature1 = KeyVault.signAsync this.keyvault this.certificateName "Here's a message3" 
            let! signature2 = KeyVault.signAsync this.keyvault this.certificateName "Here's a message3"

            let b1, b2 = signature1.Signature |> Convert.ToBase64String, signature2.Signature |> Convert.ToBase64String

            // signature |> printfn "%A"
            Assert.IsNotNull(signature2);
            Assert.AreEqual(256, signature2.Signature.Length)
            Assert.IsTrue (signature2.KeyId.Contains this.keyvault)
            Assert.IsTrue (signature2.KeyId.Contains this.certificateName)
            Assert.AreEqual(b1, b2)
        } :> System.Threading.Tasks.Task
