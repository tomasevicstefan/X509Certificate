dotnet
{
    assembly("System")
    {
        Version = '4.0.0.0';
        Culture = 'neutral';
        PublicKeyToken = 'b77a5c561934e089';

        type("System.Security.Cryptography.X509Certificates.X509Certificate2Collection"; "X509Certificate2Collection") { }
        type("System.Security.Cryptography.X509Certificates.X509Store"; "X509Store") { }
        type("System.Security.Cryptography.X509Certificates.StoreName"; "StoreName") { }
        type("System.Security.Cryptography.X509Certificates.StoreLocation"; "StoreLocation") { }
        type("System.Security.Cryptography.X509Certificates.OpenFlags"; "OpenFlags") { }
    }
}