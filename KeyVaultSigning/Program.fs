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
        open Azure.Security.KeyVault.Secrets
        open System
        open System.Security.Cryptography

        let cache =
            System.Collections.Concurrent.ConcurrentDictionary<Tuple<string, string>, Tuple<CryptographyClient, DateTime>>()

        let mutable cacheMinutes = 5.0
        
        /// Gets a client that can sign hashes for a specific key vault and client that is already installed inside.
        let getSigningClient keyVaultName certName =
            let cacheFunc() =
                try
                    cache.GetOrAdd((keyVaultName,certName), 
                        fun (keyVaultName,certName) ->
                            let credentials = configureAzureCredentials()
                            let keyClient = KeyClient (Uri $"https://%s{keyVaultName}.vault.azure.net/", credentials)
                            let key = keyClient.GetKey(certName).Value
                            CryptographyClient (key.Id, credentials), DateTime.UtcNow
                    )
                with
                | e ->
                    try
                        cache.TryRemove((keyVaultName,certName)) |> ignore
                    with | e2 -> ()
                    reraise()

            let cryptoClient, creationTime = cacheFunc()
            if creationTime < DateTime.UtcNow.AddMinutes(-1. * cacheMinutes) then
                cache.TryRemove((keyVaultName,certName)) |> ignore
                cacheFunc() |> fst
            else 
                cryptoClient

        /// Gets a client that can sign hashes for a specific key vault and client that is already installed inside.
        let getSigningClientAsync keyVaultName certName =
            task {
                // Accept the imperfectness of async locking
                let validItem = 
                    if cache.ContainsKey (keyVaultName,certName) then
                        let itmOpt =
                            try
                                Some cache.[(keyVaultName,certName)]
                            with | e -> None

                        match itmOpt with
                        | Some (itm, creationTime) when creationTime < DateTime.UtcNow.AddMinutes(-1. * cacheMinutes) -> Some itm
                        | _ -> None
                    else None

                match validItem with
                | Some x -> return x
                | None ->
                    let credentials = configureAzureCredentials()
                    let keyClient = KeyClient (Uri $"https://%s{keyVaultName}.vault.azure.net/", credentials)
                    let! key = keyClient.GetKeyAsync(certName)
                    let cli = CryptographyClient (key.Value.Id, credentials)
                    cache.TryAdd((keyVaultName,certName), (cli, DateTime.UtcNow)) |> ignore
                    return cli
            }

        /// Creates a hash (digest) for a given string
        let createDigest : string -> _ =
            let hasher =
                match configureAlgorithm with
                | SHA256 -> new SHA256Managed() :> HashAlgorithm
                | SHA384 -> new SHA384CryptoServiceProvider() :> HashAlgorithm
            configureEncoding.GetBytes >> hasher.ComputeHash

        let secretCache =
            System.Collections.Concurrent.ConcurrentDictionary<Tuple<string, string>, Tuple<KeyVaultSecret, DateTime>>()

        let getSecret keyVaultName secretName =
            let cacheFunc() =
                try
                    secretCache.GetOrAdd((keyVaultName,secretName), 
                        fun (keyVaultName,secretName) ->
                            let credentials = configureAzureCredentials()
                            let secretClient = SecretClient (Uri $"https://%s{keyVaultName}.vault.azure.net/", credentials)
                            let secret = secretClient.GetSecret(secretName).Value
                            secret, DateTime.UtcNow
                    )
                with
                | e ->
                    try
                        secretCache.TryRemove((keyVaultName,secretName)) |> ignore
                    with | e2 -> ()
                    reraise()

            let secret, creationTime = cacheFunc()
            if creationTime < DateTime.UtcNow.AddMinutes(-1. * cacheMinutes) then
                secretCache.TryRemove((keyVaultName,secretName)) |> ignore
                cacheFunc() |> fst
            else 
                secret

        let getSecretAsync keyVaultName secretName =
            task {
                // Accept the imperfectness of async locking
                let validItem = 
                    if secretCache.ContainsKey (keyVaultName,secretName) then
                        let itmOpt =
                            try
                                Some secretCache.[(keyVaultName,secretName)]
                            with | e -> None

                        match itmOpt with
                        | Some (itm, creationTime) when creationTime < DateTime.UtcNow.AddMinutes(-1. * cacheMinutes) -> Some itm
                        | _ -> None
                    else None

                match validItem with
                | Some x -> return x
                | None ->
                    let credentials = configureAzureCredentials()
                    let secretClient = SecretClient (Uri $"https://%s{keyVaultName}.vault.azure.net/", credentials)
                    let! key = secretClient.GetSecretAsync(secretName)
                    let secret = key.Value
                    secretCache.TryAdd((keyVaultName,secretName), (secret, DateTime.UtcNow)) |> ignore
                    return secret
            }

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
        task {
            let! signingClient = KeyVaultInternal.getSigningClientAsync keyVaultName certName
            let digest = KeyVaultInternal.createDigest payload

            // Sign the hash
            let! res = signingClient.SignAsync(
                            match configureAlgorithm with
                            | SHA256 -> SignatureAlgorithm.RS256
                            | SHA384 -> SignatureAlgorithm.RS384
                            , digest)
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

    /// Verify
    let verifyAsync keyVaultName certName payload signature =
        task {

            let! signingClient = KeyVaultInternal.getSigningClientAsync keyVaultName certName
            let digest = KeyVaultInternal.createDigest payload

            // Verify it was signed correctly
            let! res = signingClient.VerifyAsync(
                            match configureAlgorithm with
                            | SHA256 -> SignatureAlgorithm.RS256
                            | SHA384 -> SignatureAlgorithm.RS384
                            , digest, signature) |> Async.AwaitTask

            return res
        }

    /// Verify
    let verifyFromSecret keyVaultName certName payload secretName =
        let secret = KeyVaultInternal.getSecret keyVaultName secretName
        let secretBytes = secret.Value |> Encoding.ASCII.GetBytes
        verify keyVaultName certName payload secretBytes

    /// Verify
    let verifyFromSecretAsync keyVaultName certName payload secretName =
        task {
            let! secret = KeyVaultInternal.getSecretAsync keyVaultName secretName
            let secretBytes = secret.Value |> Encoding.ASCII.GetBytes
            return! verifyAsync keyVaultName certName payload secretBytes
        }
