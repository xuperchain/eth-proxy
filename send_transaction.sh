#!/usr/bin/env bash
# old for execution test
#curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_sendTransaction","params": [{"type":"0","nonce":"0","gasPrice":"9184e72a000","maxPriorityFeePerGas":null,"maxFeePerGas":null,"gas":"76c0","value":"9184e72a","input":"ae896c870000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000678636861696e0000000000000000000000000000000000000000000000000000","v":"2d","r":"9910f8e6fc72f08b0caddf1b1135ed4e4dbee034849fab65eed88003e76ac087",
#"s":"4bf09c57e9af2829a39859ba93525fd21da489abf78d0e4fe613d5411090a82","to":"313131312d2d2d2d2d2d2d2d2d636f756e746572","hash":"549e6094d23179b5d0e092ee32621cf79d3bb35855043d713ca86fbd096a4639"}],"id":1}' 127.0.0.1:8545


# see https://learnblockchain.cn/books/geth/part1/transaction.html for more information

curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_sendTransaction","params": [{"nonce":"0x16","gasPrice":"0x2","gas":"0x1","to":"0x0100000000000000000000000000000000000000","value":"0x0","input":"0x616263646566","v":"0x25","r":"0x3c46a1ff9d0dd2129a7f8fbc3e45256d85890d9d63919b42dac1eb8dfa443a32","s":"0x6b2be3f225ae31f7ca18efc08fa403eb73b848359a63cd9fdeb61e1b83407690","hash":"0xb848eb905affc383b4f431f8f9d3676733ea96bcae65638c0ada6e45038fb3a6"}],"id":1}' 127.0.0.1:8545

