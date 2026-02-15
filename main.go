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

// GenerateSphincsKeyPair 返回 [privateKeyPEM, publicKeyBytes]
func GenerateSphincsKeyPairJS(this js.Value, args []js.Value) interface{} {
	params := parameters.MakeSphincsPlusSHA256256fRobust(true)
	sk, pk := sphincs.Spx_keygen(params)

	// serialize private key
	skBytes, err := sk.SerializeSK()
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}

	// serialize public key
	pkBytes, err := pk.SerializePK()
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "SPHINCS+ PRIVATE KEY",
		Bytes: skBytes,
	})

	return js.ValueOf(map[string]interface{}{
		"privateKey": privPEM,
		"publicKey":  pkBytes,
	})
}

// SignMessage(privKeyPEM Uint8Array, message Uint8Array)
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
func main() {
	c := make(chan struct{})

	js.Global().Set("GenerateSphincsKeyPair", js.FuncOf(GenerateSphincsKeyPairJS))
	js.Global().Set("SignMessage", js.FuncOf(SignMessageJS))

	<-c // 阻塞，保持 Go runtime 在 WASM 里运行
}

/*
<script src="wasm_exec.js"></script>
<script>
const go = new Go();
WebAssembly.instantiateStreaming(fetch("sphincs.wasm"), go.importObject).then(result => {
  go.run(result.instance);

  // 调用生成密钥
  const kp = GenerateSphincsKeyPair();
  console.log(kp.privateKey, kp.publicKey);

  // 调用签名
  const msg = new TextEncoder().encode("hello world");
  const sig = SignMessage(kp.privateKey, msg);
  console.log(sig);
});
</script>
*/
