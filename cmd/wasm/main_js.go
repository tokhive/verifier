//go:build js && wasm

package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/tokhive/verifier"
)

func main() {
	fn := js.FuncOf(func(_ js.Value, args []js.Value) (result any) {
		defer func() {
			if recovered := recover(); recovered != nil {
				b, _ := json.Marshal(map[string]string{"engine_error": fmt.Sprint(recovered)})
				result = string(b)
			}
		}()
		if len(args) != 6 {
			return `{"engine_error":"Expected options, receipt, evidence, response, specification and request"}`
		}
		var opts verifier.Options
		if err := json.Unmarshal([]byte(args[0].String()), &opts); err != nil {
			return `{"engine_error":"Invalid verification options"}`
		}
		in := verifier.Input{Options: opts}
		copyBytes := func(v js.Value, limit int) []byte {
			if v.IsNull() || v.IsUndefined() {
				return nil
			}
			n := v.Get("byteLength").Int()
			if n > limit {
				panic("File exceeds size limit")
			}
			b := make([]byte, n)
			js.CopyBytesToGo(b, v)
			return b
		}
		in.Receipt = copyBytes(args[1], verifier.MaxReceiptBytes)
		in.Evidence = copyBytes(args[2], verifier.MaxEvidenceBytes)
		in.ResponseProvided = !args[3].IsNull() && !args[3].IsUndefined()
		in.Response = copyBytes(args[3], verifier.MaxResponseBytes)
		in.JobSpec = copyBytes(args[4], verifier.MaxJobSpecBytes)
		in.RequestProvided = !args[5].IsNull() && !args[5].IsUndefined()
		in.Request = copyBytes(args[5], verifier.MaxRequestBytes)
		b, err := json.Marshal(verifier.Verify(in))
		if err != nil {
			return `{"engine_error":"Cannot encode verification report"}`
		}
		return string(b)
	})
	js.Global().Set("tokhiveVerify", fn)
	select {}
}
