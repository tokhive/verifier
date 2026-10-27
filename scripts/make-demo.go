//go:build ignore

// Generate rejection-only fixtures; these must never pass hardware attestation.
package main

import (
	"fmt"
	"github.com/tokhive/verifier/internal/testfixture"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: go run scripts/make-demo.go <output-directory>")
	}
	f, err := testfixture.New(time.Now())
	if err != nil {
		panic(err)
	}
	if err = f.WriteFiles(os.Args[1]); err != nil {
		panic(err)
	}
	fmt.Println("Created software-signed rejection demo; hardware verification must fail.")
}
