#!/bin/sh
# Regenerates src/OhrTech.Management/Generated/OhrManagementClient.g.cs from openapi.json.
#   ./generate.sh                use the committed openapi.json
#   ./generate.sh <url|file>     update openapi.json first, e.g. from the spec repo:
#       ./generate.sh https://raw.githubusercontent.com/OhrTech/management-api/main/openapi.json
#     or from the running API: ./generate.sh https://api.ohrtech.net/v1/openapi.json
#     (review the diff: within v1 the API only ever adds)
set -eu
cd "$(dirname "$0")"
if [ $# -gt 0 ]; then
    case "$1" in
        http://*|https://*) curl -fsS "$1" > openapi.json.new ;;
        *) cp "$1" openapi.json.new ;;
    esac
    python3 -m json.tool --indent 2 openapi.json.new > openapi.json
    rm openapi.json.new
fi
dotnet tool restore >/dev/null
dotnet tool run nswag openapi2csclient \
    /input:openapi.json \
    /output:src/OhrTech.Management/Generated/OhrManagementClient.g.cs \
    /namespace:OhrTech.Management \
    /className:OhrManagementClient \
    /operationGenerationMode:SingleClientFromOperationId \
    /generateClientInterfaces:true \
    /injectHttpClient:true \
    /useBaseUrl:false \
    /jsonLibrary:SystemTextJson \
    /generateNullableReferenceTypes:true \
    /generateOptionalPropertiesAsNullable:true \
    /generateDataAnnotations:false \
    /classStyle:Poco \
    /anyType:System.Text.Json.Nodes.JsonNode \
    /dateTimeType:System.DateTimeOffset \
    /arrayType:System.Collections.Generic.List \
    /arrayInstanceType:System.Collections.Generic.List \
    /dictionaryType:System.Collections.Generic.Dictionary \
    /dictionaryInstanceType:System.Collections.Generic.Dictionary \
    /responseArrayType:System.Collections.Generic.List \
    /responseDictionaryType:System.Collections.Generic.Dictionary \
    /exceptionClass:OhrApiException \
    /generateOptionalParameters:true \
    /parameterArrayType:System.Collections.Generic.IEnumerable
