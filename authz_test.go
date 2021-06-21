package authz_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/casbin/casbin/v2"
	authz "github.com/casbin/graphql-authz"
	"github.com/graphql-go/graphql"
)

func getSchema() graphql.Schema {
	e, _ := casbin.NewEnforcer("./examples/model.conf", "./examples/policy.csv")
	schema := authz.InitType(e)
	return schema
}

func newServer() *httptest.Server {
	schema := getSchema()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := authz.Execute(r.URL.Query().Get("query"), schema)
		json.NewEncoder(w).Encode(result)
	}))
	return server
}

func unmarshalFromResp(t *testing.T, resp *http.Response) map[string]interface{} {
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("read from response body failed: %v", err)
	}
	result := make(map[string]interface{})
	if err := json.Unmarshal(bytes, &result); err != nil {
		if err != nil {
			t.Errorf("Unmarshal from bytes failed: %v", err)
		}
	}
	return result
}

func TestPolicyByHttp(t *testing.T) {
	expectedResult := []map[string]interface{}{
		{"sub": "alice", "obj": "data1", "act": "read"},
		{"sub": "bob", "obj": "data2", "act": "write"},
		{"sub": "data2_admin", "obj": "data2", "act": "read"},
		{"sub": "data2_admin", "obj": "data2", "act": "write"},
	}
	server := newServer()
	defer server.Close()

	resp, err := http.Get(fmt.Sprintf("http://%s/?query={policy{sub,obj,act}}", server.Listener.Addr().String()))
	if err != nil {
		t.Errorf("http get request occurred an error: %v", err)
	}
	result := unmarshalFromResp(t, resp)
	r := result["data"].(map[string]interface{})["policy"].([]interface{})
	for i, policy := range r {
		if !reflect.DeepEqual(policy.(map[string]interface{}), expectedResult[i]) {
			t.Errorf("got value %v, but expected to be: %v", policy, expectedResult[i])
		}
	}
}

func TestPolicy(t *testing.T) {
	expectedResult := []map[string]interface{}{
		{"sub": "alice", "obj": "data1", "act": "read"},
		{"sub": "bob", "obj": "data2", "act": "write"},
		{"sub": "data2_admin", "obj": "data2", "act": "read"},
		{"sub": "data2_admin", "obj": "data2", "act": "write"},
	}

	schema := getSchema()
	result := authz.Execute("{policy{sub,obj,act}}", schema)
	if len(result.Errors) != 0 {
		t.Errorf("graphql executing occurred errors: %v", result.Errors)
	}
	policies := result.Data.(map[string]interface{})["policy"].([]interface{})
	for i, policy := range policies {
		if !reflect.DeepEqual(policy.(map[string]interface{}), expectedResult[i]) {
			t.Errorf("got value %v, but expected to be: %v", policy, expectedResult[i])
		}
	}
}

func testEnforce(t *testing.T, schema graphql.Schema, requests [][]interface{}) {
	for _, request := range requests {
		result := authz.Execute(fmt.Sprintf(`{enforce(sub:"%s" obj:"%s" act:"%s"){sub obj act ok}}`, request[0], request[1], request[2]), schema)
		if len(result.Errors) != 0 {
			t.Errorf("graphql executing occurred errors: %v", result.Errors)
		}
		policy := result.Data.(map[string]interface{})["enforce"].(map[string]interface{})
		if policy["ok"] != request[3] {
			t.Errorf("policy sub: %s, obj: %s, act: %s got result: %v, but expected to be: %v",
				request[0], request[1], request[2], policy["ok"], request[3])
		}
	}
}

func TestEnforce(t *testing.T) {
	requests := [][]interface{}{
		{"alice", "data1", "read", true},
		{"bob", "data2", "write", true},
		{"data2_admin", "data2", "read", true},
		{"data2_admin", "data2", "write", true},
		{"alice", "data2", "write", true},
		{"alice", "data2", "read", true},
		{"alice", "data1", "write", false},
	}
	schema := getSchema()
	testEnforce(t, schema, requests)
}

func TestAddPolicy(t *testing.T) {
	schema := getSchema()
	policies := [][]string{
		{"bob", "data1", "read"},
		{"alice", "data1", "read"},
	}
	expected := []bool{true, false}
	for i, policy := range policies {
		result := authz.Execute(fmt.Sprintf(`mutation {add(sub:"%s", obj:"%s", act:"%s"){ sub obj act ok }}`, policy[0], policy[1], policy[2]), schema)
		if len(result.Errors) != 0 {
			t.Errorf("graphql executing occurred errors: %v", result.Errors)
		}
		r := result.Data.(map[string]interface{})["add"].(map[string]interface{})
		if r["ok"] != expected[i] {
			t.Errorf("add policy sub: %s, obj: %s, act: %s got result: %v, but expected to be: %v",
				policy[0], policy[1], policy[2], r["ok"], expected[i])
		}
	}
	testEnforce(t, schema, [][]interface{}{
		{"bob", "data1", "read", true},
		{"alice", "data1", "read", true},
	})
}

func TestDeletePolicy(t *testing.T) {
	schema := getSchema()
	policies := [][]string{
		{"bob", "data1", "read"},
		{"alice", "data1", "read"},
	}
	expected := []bool{false, true}
	for i, policy := range policies {
		result := authz.Execute(fmt.Sprintf(`mutation {delete(sub:"%s", obj:"%s", act:"%s"){ sub obj act ok }}`, policy[0], policy[1], policy[2]), schema)
		if len(result.Errors) != 0 {
			t.Errorf("graphql executing occurred errors: %v", result.Errors)
		}
		r := result.Data.(map[string]interface{})["delete"].(map[string]interface{})
		if r["ok"] != expected[i] {
			t.Errorf("delete policy sub: %s, obj: %s, act: %s got result: %v, but expected to be: %v",
				policy[0], policy[1], policy[2], r["ok"], expected[i])
		}
	}
	testEnforce(t, schema, [][]interface{}{
		{"bob", "data1", "read", false},
		{"alice", "data1", "read", false},
	})
}

func TestUpdatePolicy(t *testing.T) {
	schema := getSchema()
	policies := [][]string{
		{"alice", "data1", "write", "alice", "data1", "read"},
		{"alice", "data1", "wrtie", "alice", "data1", "read"},
		{"data2_admin", "data3", "read", "data2_admin", "data2", "read"},
	}
	expected := []bool{true, false, true}
	for i, policy := range policies {
		result := authz.Execute(fmt.Sprintf(`mutation {update(sub:"%s", obj:"%s", act:"%s",osub:"%s", oobj:"%s", oact:"%s"){ sub obj act osub oobj oact ok }}`,
			policy[0], policy[1], policy[2], policy[3], policy[4], policy[5]), schema)
		if len(result.Errors) != 0 {
			t.Errorf("graphql executing occurred errors: %v", result.Errors)
		}
		r := result.Data.(map[string]interface{})["update"].(map[string]interface{})
		if r["ok"] != expected[i] {
			t.Errorf("update policy sub: %s, obj: %s, act: %s ,osub: %s, oobj: %s, oact: %s got result: %v, but expected to be: %v",
				policy[0], policy[1], policy[2], policy[3], policy[4], policy[5], r["ok"], expected[i])
		}
	}
	testEnforce(t, schema, [][]interface{}{
		{"alice", "data1", "read", false},
		{"alice", "data1", "write", true},
		{"alice", "data3", "read", true},
		{"alice", "data2", "read", false},
		{"data2_admin", "data2", "read", false},
	})
}
