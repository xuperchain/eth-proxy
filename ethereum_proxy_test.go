package xuperproxy

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
		Params  Params
	}{
		JSONRPC: "2.0",
		Method:  "eth_sendTransaction",
		Params: Params{
			Data: "0xa46a766ce422e1e1a9827efe6989eeacc82a2352765287fe557497465751d9ab",
		},
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
