namespace KeyVaultSignTests

open System
open Microsoft.VisualStudio.TestTools.UnitTesting
open System.Text

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
    member this.``KeyVault sign and verifyPublic test``() =

        let msg = """{"Type":"FITestEvent","Version":1,"Payload":"test","Nonce":1583990063}"""

        let msgBytes = msg |> Encoding.UTF8.GetBytes
        let signature = "vqOPgJiOAP6Bl9vIGK9mW6jj9HBt+4LGV79Bjf7djPNlGrpw6JS2lQnW/xw2BfUAXmiPcxi8kllK9NVAEDESum8kt78D+J5/HWX9jOWO4Tgu6LT27J6u6aWgnkIR6/rHtVJlzMeWiKLMp8hTmArM4cZWEg5tVfLS3OlZd2Fcvrj4lqDYj2oikZ6i8glym3EXqrURkj+1Z6M2ZLxs5MWU5gW8D3X653MyUBB5Zm5YxhUiAUhnKqripDKFcBS2weIWH6i02risc3UtDqqVb668qi7Ykwf6p+ZQFZUPZalVOdU46yWZMM1jI3jmAjnLTjuZ5MNg69F1U+JeRzJW04pQe28tK2ZjkUxdIasOVpzmJmtHoAvTdCbpppFcGTomWDu8acFx8ax+9qjqFnhE97vg/W/kWKlzDhSXbUev/x6MT12WYD7/z9iSZ18WoTaEUXWWu84g0q2nQke+iVi8tjJArLF4YlJgOuFqJMGscMIYOf/0KvCSh0R40ASsjp2EQKXJEXxGUvSRoq1ilKKHadxy9nY+iLbVdOapngz1dBpm7CkkjC4jgQMqI4jdf7uI+CqZRczjL/F4/onP3DO92oeXAFUDn9gF8Wqiqt4ZoH/UxAjrE+JdIfaxHt8pYJOVxiSjAUpDCHjdJsEEZkBXXl75aETUh/vZ2uh9RQV9i3GAEBA="//let signatureResult = KeyVault.sign this.keyvault this.certificateName msg
        let signBytes = signature |> System.Convert.FromBase64String

        let publicKeyXml = "<RSAKeyValue><Modulus>v71mKsJJhpfBPluwl2+1ZfGLNtE2EZWyf2UkwF/QGJddycsFoKVpKZZP+LLmrNLZXKJWd7k2tcj/jwKZEbIjpBOMzCTLmiTXNr8aBwgb7FhUX9AQ62jDKvRW7jUTFPkzDTOuLto02iDSUCLGSGpico1MM0uS0NgY9oy9pMZGISBulOXAZ/aFABqpzRsId+JGgHCCPJm/HF6uAp/rbF78VHnzA2GvNUrUXBm0vGiX/JPIc/xhItRpT7IcAM7/RAy6e7kKxak60FK7rQkXTrcXlD/u34644Tuip3Th+9IzALIUahijWJOnO5bSo5CG4jk/qke2m8egkj1ojDO4gxS54JWIdL1SpB6adFoyDYD5FNrnwMmRklSel/sb1hjHPkU+zex8t+i//meC8kOXPh/R65xbOXZlPIEqFz4+M6QSAGQCtAa5GRqiz2vAkcxHQHW07VLYRFUbRYlw4ju4w2PRM7ur+X0iMqdJiBQX6hMJIhiDMWXZvL3XwOooz7D4bk99vIliJ1mB821uER2oRV5FBJhdDq5VfAfXRrZwCrbo8HacTMw9NrN32vN9HGJi7bfm/y8FD9TQnsSV01dfMKayO3K1GbIx54bTy5wufv/n3kd4c2hkga9jRfa2HEFTSkLPkPoHLD8/NRs5j6a5Ua8/qXRJbFQIXhYAme9THhSiUcs=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"

        let res = KeyVault.verifyPublic publicKeyXml signBytes msgBytes
        // res |> printfn "%A"
        Assert.IsNotNull(res);
        Assert.IsTrue res

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
