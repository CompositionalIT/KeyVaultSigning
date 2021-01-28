//#r "nuget:Azure.Security.KeyVault.Keys"
//#r "nuget:Azure.Identity"
// --- or ---
//#r "bin/Debug/net472/Azure.Core.dll"
//#r "bin/Debug/net472/Azure.Identity.dll"
//#r "bin/Debug/net472/Azure.Security.KeyVault.Keys.dll"

open Azure.Security.KeyVault.Keys.Cryptography

module KeyVault =
    open Azure.Identity
    open Azure.Security.KeyVault.Keys
    open System
    open System.Security.Cryptography
    open System.Text

    /// Create credentials using commonly-used auth methods including your current identity.
    let azureCredentials = 
        // powershell Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; rm .\AzureCLI.msi
        // On development machine, may need: az login
        DefaultAzureCredential ()

    /// Gets a client that can sign hashes for a specific key vault and client that is already installed inside.
    let getSigningClient keyVaultName certName =
        let keyClient = KeyClient (Uri $"https://%s{keyVaultName}.vault.azure.net/", azureCredentials)
        let key = keyClient.GetKey(certName).Value
        CryptographyClient (key.Id, azureCredentials)

    /// Creates a hash (digest) for a given string
    let createDigest : string -> _ =
        let hasher = new SHA256Managed()
        Encoding.UTF8.GetBytes >> hasher.ComputeHash

let signingClient = KeyVault.getSigningClient "isaac-hsm" "loantest"
let digest = KeyVault.createDigest "Here's a message"

// Sign the hash
let signingResult = signingClient.Sign(SignatureAlgorithm.RS384, digest)
signingResult |> printfn "%A"

// Verify it was signed correctly
signingClient.Verify(SignatureAlgorithm.RS384, digest, signingResult.Signature)
|> printfn "%A"

// Changing the signature will fail
signingResult.Signature.[0] <- 43uy
signingClient.Verify(SignatureAlgorithm.RS384, digest, signingResult.Signature)
|> printfn "%A"
