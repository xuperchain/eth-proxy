/*
 * Copyright (c) 2021. Baidu Inc. All Rights Reserved.
 */

package eth_proxy

import (
	"encoding/hex"
	"net/http"
)

const NetworkID = "1337"

// NetService returns data about the network the client is connected
// to.
type NetService struct {
}

// Version takes no parameters and returns the network identifier.
//
// https://github.com/ethereum/wiki/wiki/JSON-RPC#net_version
func (s *NetService) Version(r *http.Request, _ *interface{}, reply *string) error {
	*reply = hex.EncodeToString([]byte(NetworkID))
	return nil
}

func (s *NetService) Listening(r *http.Request, _ *interface{}, reply *bool) error {
	*reply = true
	return nil
}
