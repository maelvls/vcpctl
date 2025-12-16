//go:generate go run .
//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest --config=oapi-codegen.yaml -include-tags "Service Accounts,Issuer Configurations,Issuer Sub CA Providers,Workload Issuance Policies" openapi.json
//  go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest --config=oapi-codegen.yaml -include-tags "Service Accounts,Issuer Configurations,Issuer Sub CA Providers,Workload Issuance Policies" openapi.json

package main
