codeunit 50100 "X509 Certificate Mgt."
{
    trigger OnRun()
    begin
    end;

    var
        CertFileNameTxt: Label 'Certificate.cer', Locked = true;
        ImportErr: Label 'Unable to import certificate!';

    procedure ImportCertificate(ContentType: Text) CertBase64Value: Text
    var
        TempBlobApi: Codeunit "Temp Blob";
        FileManagement: Codeunit "File Management";
        PasswordDialog: Page "Password Dialog";
        X509Certificate2: DotNet X509Certificate2;
        X509ContentType: DotNet X509ContentType;
    begin
        if not TryParseEnum(X509ContentType, GetDotNetType(X509ContentType), ContentType) then
            X509ContentType := X509ContentType.Pkcs12;

        if FileManagement.BLOBImport(TempBlobApi, CertFileNameTxt) = '' then
            Error('');

        CertBase64Value := ReadCertFromBlob(TempBlobApi);

        if not TryImportCertificate(CertBase64Value, '', X509Certificate2) then begin
            PasswordDialog.DisablePasswordConfirmation();
            if PasswordDialog.RunModal() <> Action::OK then exit;
            if not TryImportCertificate(CertBase64Value, PasswordDialog.GetPasswordValue(), X509Certificate2) then
                Error(ImportErr);
        end;

        if not TryExportToBase64String(X509Certificate2, X509ContentType, CertBase64Value) then
            Error(GetLastErrorText());
    end;

    procedure GetCertificateDetails(CertBase64Value: Text; var FriendlyName: Text; var Thumbprint: Text; var Issuer: Text; var Expiration: DateTime)
    var
        TypeHelper: Codeunit "Type Helper";
        X509Certificate2: DotNet X509Certificate2;
        DateTimeVar: Variant;
    begin
        CreateCertificate(CertBase64Value, X509Certificate2);
        FriendlyName := X509Certificate2.FriendlyName();
        Thumbprint := X509Certificate2.Thumbprint();
        Issuer := X509Certificate2.Issuer();
        DateTimeVar := Expiration;
        if not Evaluate(Expiration, X509Certificate2.GetExpirationDateString()) then
            if TypeHelper.Evaluate(DateTimeVar, X509Certificate2.GetExpirationDateString(), '', 'en-US') then
                Expiration := DateTimeVar;
    end;

    procedure GetCertificatePropertiesAsJson(CertBase64Value: Text): Text
    var
        X509Certificate2: DotNet X509Certificate2;
    begin
        CreateCertificate(CertBase64Value, X509Certificate2);
        exit(CreateCertificatePropertyJson(X509Certificate2));
    end;

    procedure GetCertificateCollectionPropertiesAsJson(FromX509StoreLocation: Text): Text
    var
        JSONManagement: Codeunit "JSON Management";
        JObject: DotNet JObject;
        X509Certificate2Collection: DotNet X509Certificate2Collection;
        X509Certificate2: DotNet X509Certificate2;
        X509ContentType: DotNet X509ContentType;
        CertBase64Value: Text;
    begin
        GetStoreCollections(FromX509StoreLocation, X509Certificate2Collection);
        JSONManagement.InitializeEmptyCollection();
        foreach X509Certificate2 in X509Certificate2Collection do begin
            JSONManagement.InitializeObject(CreateCertificatePropertyJson(X509Certificate2));
            JSONManagement.GetJSONObject(JObject);
            if TryExportToBase64String(X509Certificate2, X509ContentType.Pkcs12, CertBase64Value) then
                JSONManagement.AddJPropertyToJObject(JObject, 'CertBase64Value', CertBase64Value);
            JSONManagement.AddJObjectToCollection(JObject);
        end;
        exit(JSONManagement.WriteCollectionToString());
    end;

    local procedure ReadCertFromBlob(TempBlob: Codeunit "Temp Blob"): Text
    var
        InStr: InStream;
        Convert: Codeunit "Base64 Convert";
    begin
        TempBlob.CreateInStream(InStr);
        exit(Convert.ToBase64(InStr));
    end;

    [TryFunction]
    local procedure TryImportCertificate(CertBase64Value: Text; Password: Text; var X509Certificate2: DotNet X509Certificate2)
    var
        X509KeyStorageFlags: DotNet X509KeyStorageFlags;
        Convert: DotNet Convert;
    begin
        X509Certificate2 := X509Certificate2.X509Certificate2(Convert.FromBase64String(CertBase64Value), Password, X509KeyStorageFlags.Exportable);
        if IsNull(X509Certificate2) then
            Error('');
    end;

    [TryFunction]
    local procedure TryExportToBase64String(X509Certificate2: DotNet X509Certificate2; X509ContentType: DotNet X509ContentType; var CertBase64Value: Text)
    var
        Convert: DotNet Convert;
    begin
        CertBase64Value := Convert.ToBase64String(X509Certificate2.Export(X509ContentType));
    end;

    [TryFunction]
    local procedure TryParseEnum(var Class: DotNet Object; EnumType: DotNet Type; EnumValue: Text)
    var
        Enum: DotNet Enum;
    begin
        Class := Enum.Parse(EnumType, EnumValue);
    end;

    local procedure CreateCertificate(CertBase64Value: Text; var X509Certificate2: DotNet X509Certificate2)
    var
        Convert: DotNet Convert;
    begin
        X509Certificate2 := X509Certificate2.X509Certificate2(Convert.FromBase64String(CertBase64Value));
    end;

    local procedure GetStoreCollections(FromX509StoreLocation: Text; var X509Certificate2Collection: DotNet X509Certificate2Collection)
    var
        X509Store: DotNet X509Store;
        X509StoreName: DotNet StoreName;
        X509StoreLocation: DotNet StoreLocation;
        X509StoreOpenFlags: DotNet OpenFlags;
    begin
        if not TryParseEnum(X509StoreLocation, GetDotNetType(X509StoreLocation), FromX509StoreLocation) then
            X509StoreLocation := X509StoreLocation.LocalMachine;

        X509Store := X509Store.X509Store(X509StoreName.My, X509StoreLocation);
        X509Store.Open(X509StoreOpenFlags.ReadOnly);
        X509Certificate2Collection := X509Store.Certificates();
        X509Store.Close();
    end;

    local procedure CreateCertificatePropertyJson(X509Certificate2: DotNet X509Certificate2): Text
    var
        JSONManagement: Codeunit "JSON Management";
        JObject: DotNet JObject;
        PropertyInfo: DotNet PropertyInfo;
    begin
        JSONManagement.InitializeEmptyObject();
        JSONManagement.GetJSONObject(JObject);

        foreach PropertyInfo in X509Certificate2.GetType().GetProperties() do
            if PropertyInfo.PropertyType().ToString() in ['System.Boolean', 'System.String', 'System.DateTime', 'System.Int32'] then
                JSONManagement.AddJPropertyToJObject(JObject, PropertyInfo.Name(), Format(PropertyInfo.GetValue(X509Certificate2), 0, 9));
        exit(JSONManagement.WriteObjectToString());
    end;
}