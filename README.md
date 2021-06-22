# graphql-authz

[![Coverage Status](https://coveralls.io/repos/github/casbin/graphql-authz/badge.svg?branch=master)](https://coveralls.io/github/casbin/graphql-authz?branch=master)[![Go](https://github.com/casbin/graphql-authz/actions/workflows/ci.yml/badge.svg)](https://github.com/casbin/graphql-authz/actions/workflows/ci.yml)[![Release](https://img.shields.io/github/release/casbin/graphql-authz.svg)](https://github.com/casbin/graphql-authz/releases/latest)[![Go Report Card](https://goreportcard.com/badge/github.com/casbin/graphql-authz)](https://goreportcard.com/report/github.com/casbin/graphql-authz)

graphql-authz is a casbin binding of graphql, something like restful api. There're actions, like `enforce`, `getPolicies`, `addPolicy`, `removePolicy`, `updatePolicy`.

## Install

```bash
go get -u github.com/casbin/graphql-authz
```

## Usage

Enforce Example:

```go
e, _ := casbin.NewEnforcer("./examples/model.conf", "./examples/policy.csv")
schema := authz.InitType(e)
result := authz.Execute(`{enforce(sub:"alice" obj:"data1" act:"read"){sub obj act ok}}`, schema)
```

More info, please refer to [graphql](https://github.com/graphql/graphql-js) and [basic usage](./authz_test.go)