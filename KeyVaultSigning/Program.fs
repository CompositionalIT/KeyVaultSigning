//#r "nuget:Azure.Security.KeyVault.Keys"
//#r "nuget:Azure.Identity"
// --- or ---
//#r "bin/Debug/net472/Azure.Core.dll"
//#r "bin/Debug/net472/Azure.Identity.dll"
//#r "bin/Debug/net472/Azure.Security.KeyVault.Keys.dll"

module KeyVault

    open System.Text
    open Azure.Identity
    open Azure.Security.KeyVault.Keys.Cryptography

    type Algorithms =
    | SHA256
    | SHA384

    /// You can change the algorithm: KeyVault.configureAlgorithm <- KeyVault.Algorithms.SHA384
    /// Default is SHA256.
    let mutable configureAlgorithm = Algorithms.SHA256

    /// You can change the encoding KeyVault.configureEncoding <- System.Text.Encoding.Unicode
    // Default is System.Text.Encoding.UTF8
    let mutable configureEncoding = Encoding.UTF8

    /// Create credentials using commonly-used auth methods including your current identity.
    let mutable configureAzureCredentials = fun () ->
        // Install Azure CLI:
        // powershell Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; rm .\AzureCLI.msi

        // On development machine, may need: az login
        DefaultAzureCredential (
            DefaultAzureCredentialOptions (
                    //ExcludeEnvironmentCredential = true
                    //,ExcludeManagedIdentityCredential = true
                    //,ExcludeSharedTokenCacheCredential = true
                    //,ExcludeVisualStudioCredential = true
                    //,ExcludeVisualStudioCodeCredential = true
                    //,ExcludeAzureCliCredential = true
                    //,ExcludeInteractiveBrowserCredential = true
                ))


    module internal KeyVaultInternal =

        open Azure.Security.KeyVault.Keys
        open System
        open System.Security.Cryptography


        /// Gets a client that can sign hashes for a specific key vault and client that is already installed inside.
        let getSigningClient keyVaultName certName =
            let credentials = configureAzureCredentials()
            let keyClient = KeyClient (Uri $"https://%s{keyVaultName}.vault.azure.net/", credentials)
            let key = keyClient.GetKey(certName).Value
            CryptographyClient (key.Id, credentials)

        /// Creates a hash (digest) for a given string
        let createDigest : string -> _ =
            let hasher =
                match configureAlgorithm with
                | SHA256 -> new SHA256Managed() :> HashAlgorithm
                | SHA384 -> new SHA384CryptoServiceProvider() :> HashAlgorithm
            configureEncoding.GetBytes >> hasher.ComputeHash

    /// Sign
    let sign keyVaultName certName payload =

        let signingClient = KeyVaultInternal.getSigningClient keyVaultName certName
        let digest = KeyVaultInternal.createDigest payload

        // Sign the hash
        signingClient.Sign(
            match configureAlgorithm with
            | SHA256 -> SignatureAlgorithm.RS256
            | SHA384 -> SignatureAlgorithm.RS384
            , digest)

    /// Sign
    let signAsync keyVaultName certName payload =
        async {
            let signingClient = KeyVaultInternal.getSigningClient keyVaultName certName
            let digest = KeyVaultInternal.createDigest payload

            // Sign the hash
            let! res = signingClient.SignAsync(
                            match configureAlgorithm with
                            | SHA256 -> SignatureAlgorithm.RS256
                            | SHA384 -> SignatureAlgorithm.RS384
                            , digest) |> Async.AwaitTask
            return res
        }

    /// Verify
    let verify keyVaultName certName payload signature =

        let signingClient = KeyVaultInternal.getSigningClient keyVaultName certName
        let digest = KeyVaultInternal.createDigest payload

        // Verify it was signed correctly
        signingClient.Verify(
            match configureAlgorithm with
            | SHA256 -> SignatureAlgorithm.RS256
            | SHA384 -> SignatureAlgorithm.RS384
            , digest, signature)

