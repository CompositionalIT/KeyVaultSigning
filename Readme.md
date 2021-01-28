# Azure KeyVault signing #

This component will calculate SHA-hash for your message and then sign that with Azure KeyVault.

Pre-conditions:

- Install Azure CLI: 

```
 powershell Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; rm .\AzureCLI.msi
```

- Create an Azure Key Vault: https://azure.microsoft.com/en-gb/services/key-vault/
- Add a certificate in the Certificates-tab of the key vault.
- From Access policies -tab, add a user. Add permissions to Sign -operation. Add permissions to Verify-operation.
- The code is using just `DefaultAzureCredential()`, so you have to have your environmentconfiguration for that correct. In development you may haveto do `az login`. See: https://docs.microsoft.com/en-us/dotnet/api/overview/azure/identity-readme#defaultazurecredential

Then just reference this library and call:

```fsharp
KeyVault.sign "keyvault" "certificateName" "Hello world!"
```

By default the library uses SHA256 and UTF8, but you can modify that:

```fsharp
KeyVault.configureAlgorithm <- KeyVault.Algorithms.SHA384
KeyVault.configureEncoding <- System.Text.Encoding.Unicode
```
