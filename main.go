package main

import (
	"encoding/pem"
	"syscall/js"

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
)

// ----------------------
// SPHINCS+ WASM 接口
// ----------------------

// GenerateSphincsKeyPairJS 返回 {privateKey: string, publicKey: Uint8Array}
func GenerateSphincsKeyPairJS(this js.Value, args []js.Value) interface{} {
	params := parameters.MakeSphincsPlusSHA256256fRobust(true)
	sk, pk := sphincs.Spx_keygen(params)

	skBytes, err := sk.SerializeSK()
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}

	pkBytes, err := pk.SerializePK()
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "SPHINCS+ PRIVATE KEY",
		Bytes: skBytes,
	})

	pkJS := js.Global().Get("Uint8Array").New(len(pkBytes))
	js.CopyBytesToJS(pkJS, pkBytes)

	return js.ValueOf(map[string]interface{}{
		"privateKey": string(privPEM), // string, not []byte
		"publicKey":  pkJS,            // Uint8Array
	})
}

// SignMessageJS (privKeyPEM Uint8Array, message Uint8Array)
func SignMessageJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return js.ValueOf(map[string]interface{}{"error": "expected 2 arguments"})
	}
	privKey := args[0]
	message := args[1]

	privBytes := make([]byte, privKey.Get("length").Int())
	js.CopyBytesToGo(privBytes, privKey)

	messageBytes := make([]byte, message.Get("length").Int())
	js.CopyBytesToGo(messageBytes, message)

	block, _ := pem.Decode(privBytes)
	if block == nil || block.Type != "SPHINCS+ PRIVATE KEY" {
		return js.ValueOf(map[string]interface{}{"error": "invalid private key PEM"})
	}

	params := parameters.MakeSphincsPlusSHA256256fRobust(true)
	sk, err := sphincs.DeserializeSK(params, block.Bytes)
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}

	sigStruct := sphincs.Spx_sign(params, messageBytes, sk)
	sigBytes, err := sigStruct.SerializeSignature()
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}

	sigJS := js.Global().Get("Uint8Array").New(len(sigBytes))
	js.CopyBytesToJS(sigJS, sigBytes)

	return sigJS
}

// ----------------------
// 主函数，注册 JS 导出
// ----------------------
var genFunc js.Func
var signFunc js.Func

func main() {
	c := make(chan struct{})

	genFunc = js.FuncOf(GenerateSphincsKeyPairJS)
	signFunc = js.FuncOf(SignMessageJS)

	js.Global().Set("GenerateSphincsKeyPair", genFunc)
	js.Global().Set("SignMessage", signFunc)

	<-c
}
