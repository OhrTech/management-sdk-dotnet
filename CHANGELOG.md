# Changelog

## 1.0.1

- Works where reflection-based JSON is off: .NET 10 file-based apps (`dotnet run app.cs`), trimmed
  and native AOT apps. 1.0.0 failed there on the first call with "Reflection-based serialization
  has been disabled". The client now uses source-generated JSON metadata and is marked AOT compatible.

## 1.0.0

First release, for Management API v1.
