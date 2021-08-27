package xuperproxy

import "testing"

func TestSendRawTransaction(t *testing.T) {
	service, err := NewEthService1()
	if err != nil {
		t.Error(err)
		return
	}
	t.Run("TestSendTransaction", func(t *testing.T) {

	})
	t.Run("TestSendRawTransaction", func(t *testing.T) {
		tx := "0xf867808082520894f97798df751deb4b6e39d4cf998ee7cd4dcb9acc880de0b6b3a76400008025a0f0d2396973296cd6a71141c974d4a851f5eae8f08a8fba2dc36a0fef9bd6440ca0171995aa750d3f9f8e4d0eac93ff67634274f3c5acf422723f49ff09a6885422"
		if err := service.SendRawTransaction(nil, &tx, nil); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("GetTransactionReceipt", func(t *testing.T) {
		txHash := "0f756f59c8997a09c3efce102a6c1dfaf0459fd808d418d91853048a47cc00a8"
		if err := service.GetTransactionReceipt(nil, &txHash, nil); err != nil {
			t.Error(err)
			return

		}

	})

	t.Run("TestContractCall", func(t *testing.T) {
		if err := service.Call(nil, nil, nil); err != nil {
			t.Error(err)
			return
		}
	})
}
