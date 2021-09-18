package eth_proxy

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"
)

func TestProxy(t *testing.T) {
	type Params struct {
		Data string
	}
	data := struct {
		JSONRPC string
		Method  string
		Params  string
	}{
		JSONRPC: "2.0",
		Method:  "eth_sendRawTransaction",
		Params:  "0xf867808082520894f97798df751deb4b6e39d4cf998ee7cd4dcb9acc880de0b6b3a76400008025a0f0d2396973296cd6a71141c974d4a851f5eae8f08a8fba2dc36a0fef9bd6440ca0171995aa750d3f9f8e4d0eac93ff67634274f3c5acf422723f49ff09a6885422",
	}
	datas, err := json.Marshal(data)
	if err != nil {
		{
			t.Error(err)
		}
	}
	r := bytes.NewReader(datas)
	req, err := http.NewRequest("POST", "http://127.0.0.1:8545", r)
	if err != nil {
		t.Error(err)
		return
	}
	req.Header.Add("Content-Type", "application/json")
	//headers := http.Header{
	//	"Content-Type": []string{":application/json"},
	//}
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	resp1, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(resp.Status)
	t.Log("resp:", string(resp1))
}
