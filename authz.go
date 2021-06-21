//package graphql_authz
package authz

import (
	"github.com/casbin/casbin/v2"
	"github.com/graphql-go/graphql"
)

type Request struct {
	Sub string `json:"sub"`
	Obj string `json:"obj"`
	Act string `json:"act"`
	OK  bool   `json:"ok"`
}

type UpdatePolicy struct {
	Sub string `json:"sub"`
	Obj string `json:"obj"`
	Act string `json:"act"`

	OldSub string `json:"osub"`
	OldObj string `json:"oobj"`
	OldAct string `json:"oact"`
	Ok     bool   `json:"ok"`
}

type Policy struct {
	Sub string `json:"sub"`
	Obj string `json:"obj"`
	Act string `json:"act"`
}

func StringArrToPolicy(arr []string) Policy {
	return Policy{
		Sub: arr[0],
		Obj: arr[1],
		Act: arr[2],
	}
}

func InitType(e *casbin.Enforcer) graphql.Schema {
	var requestType = graphql.NewObject(
		graphql.ObjectConfig{
			Name: "Request",
			Fields: graphql.Fields{
				"sub": &graphql.Field{
					Type: graphql.String,
				},
				"obj": &graphql.Field{
					Type: graphql.String,
				},
				"act": &graphql.Field{
					Type: graphql.String,
				},
				"ok": &graphql.Field{
					Type: graphql.Boolean,
				},
			},
		},
	)

	var policyType = graphql.NewObject(
		graphql.ObjectConfig{
			Name: "Policy",
			Fields: graphql.Fields{
				"sub": &graphql.Field{
					Type: graphql.String,
				},
				"obj": &graphql.Field{
					Type: graphql.String,
				},
				"act": &graphql.Field{
					Type: graphql.String,
				},
			},
		},
	)

	var updatePolicyType = graphql.NewObject(
		graphql.ObjectConfig{
			Name: "UpdatePolicy",
			Fields: graphql.Fields{
				"sub": &graphql.Field{
					Type: graphql.String,
				},
				"obj": &graphql.Field{
					Type: graphql.String,
				},
				"act": &graphql.Field{
					Type: graphql.String,
				},
				"osub": &graphql.Field{
					Type: graphql.String,
				},
				"oobj": &graphql.Field{
					Type: graphql.String,
				},
				"oact": &graphql.Field{
					Type: graphql.String,
				},
				"ok": &graphql.Field{
					Type: graphql.Boolean,
				},
			},
		},
	)

	var queryType = graphql.NewObject(
		graphql.ObjectConfig{
			Name: "Query",
			Fields: graphql.Fields{
				"enforce": &graphql.Field{
					Type: requestType,
					Args: graphql.FieldConfigArgument{
						"sub": &graphql.ArgumentConfig{
							Type: graphql.String,
						},
						"obj": &graphql.ArgumentConfig{
							Type: graphql.String,
						},
						"act": &graphql.ArgumentConfig{
							Type: graphql.String,
						},
					},
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						sub := p.Args["sub"].(string)
						obj := p.Args["obj"].(string)
						act := p.Args["act"].(string)
						res, err := e.Enforce(sub, obj, act)
						if err != nil {
							return nil, err
						}
						return Request{sub, obj, act, res}, nil
					},
				},
				"policy": &graphql.Field{
					Type:        graphql.NewList(policyType),
					Description: "Get all policy",
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						policies := e.GetPolicy()
						result := make([]Policy, 0)
						for _, policy := range policies {
							result = append(result, StringArrToPolicy(policy))
						}
						return result, nil
					},
				},
			},
		})

	var mutaionType = graphql.NewObject(graphql.ObjectConfig{
		Name: "Mutation",
		Fields: graphql.Fields{
			"add": &graphql.Field{
				Type:        requestType,
				Description: "Add a policy",
				Args: graphql.FieldConfigArgument{
					"sub": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"obj": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"act": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					sub, obj, act := p.Args["sub"].(string), p.Args["obj"].(string), p.Args["act"].(string)
					ok, err := e.AddPolicy(sub, obj, act)
					if err != nil {
						return nil, err
					}
					return Request{sub, obj, act, ok}, nil
				},
			},
			"delete": &graphql.Field{
				Type:        requestType,
				Description: "Delete a policy",
				Args: graphql.FieldConfigArgument{
					"sub": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"obj": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"act": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					sub, obj, act := p.Args["sub"].(string), p.Args["obj"].(string), p.Args["act"].(string)
					ok, err := e.RemovePolicy(sub, obj, act)
					if err != nil {
						return nil, err
					}
					return Request{sub, obj, act, ok}, nil
				},
			},
			"update": &graphql.Field{
				Type:        updatePolicyType,
				Description: "Update a policy",
				Args: graphql.FieldConfigArgument{
					"sub": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"obj": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"act": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"osub": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"oobj": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"oact": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					sub, obj, act := p.Args["sub"].(string), p.Args["obj"].(string), p.Args["act"].(string)
					osub, oobj, oact := p.Args["osub"].(string), p.Args["oobj"].(string), p.Args["oact"].(string)
					res, err := e.UpdatePolicy([]string{osub, oobj, oact}, []string{sub, obj, act})
					if err != nil {
						return nil, err
					}
					return UpdatePolicy{sub, obj, act, osub, oobj, oact, res}, nil
				},
			},
		},
	})

	var schema, _ = graphql.NewSchema(
		graphql.SchemaConfig{
			Query:    queryType,
			Mutation: mutaionType,
		},
	)
	return schema
}

func Execute(query string, schema graphql.Schema) *graphql.Result {
	result := graphql.Do(graphql.Params{
		Schema:        schema,
		RequestString: query,
	})
	return result
}
