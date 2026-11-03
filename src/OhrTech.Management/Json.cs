using System.Text.Json.Serialization.Metadata;

namespace OhrTech.Management
{
    public partial class OhrManagementClient
    {
        // Every request and response type has source-generated metadata (OhrManagementJsonContext,
        // written by generate.sh), so the client needs no reflection: it works in .NET 10 file-based
        // apps (dotnet run app.cs), trimmed and native AOT apps. generate.sh points the generated
        // calls at these two helpers.
        static partial void UpdateJsonSerializerSettings(System.Text.Json.JsonSerializerOptions settings)
        {
            settings.TypeInfoResolver = OhrManagementJsonContext.Default;
        }

        private static JsonTypeInfo<T> TypeInfo<T>() =>
            (JsonTypeInfo<T>) (OhrManagementJsonContext.Default.GetTypeInfo(typeof(T))
                               ?? throw new System.NotSupportedException($"{typeof(T)} is not an API type."));

        private static byte[] SerializeBody<T>(T body) => System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(body, TypeInfo<T>());
    }
}
