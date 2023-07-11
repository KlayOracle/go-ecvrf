package solidity_vrf

import (
	"context"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/klayoracle/go-ecvrf"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

// Generate proof in go and verify with solidity
func Test_Verify_Proof_GoVRF_Vs_SolidityVRF(t *testing.T) {

	chainId := big.NewInt(1337)
	chainRPC := "http://127.0.0.1:8545" //Ganache RPC Listening on

	client, err := ethclient.Dial(chainRPC)
	if err != nil {
		t.Errorf("start up Ganache client, to connect with client: %s", err)
	}

	privateKey, err := crypto.HexToECDSA("46dbea7b5d1b58285aa09e10aabf32a99a344385579c0bd1432f7d6ead2c8dd4") //Use account 1 provided by Ganache client
	if err != nil {
		t.Errorf("error with node signing key: %s", err)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		t.Errorf("error getting gas price: %s", err)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainId)
	if err != nil {
		t.Errorf("%s", err)
	}
	auth.Value = big.NewInt(0)      // in wei
	auth.GasLimit = uint64(9000000) // in units
	auth.GasPrice = gasPrice

	_, _, instance, err := DeployVerifyVRF(auth, client)
	if err != nil {
		t.Errorf("%v", err)
	}

	alpha, _ := hex.DecodeString("73616d706c65")

	vrf := ecvrf.Secp256k1Sha256Tai

	_, pi, err := vrf.ProveSecp256k1(privateKey, alpha)

	d, err := instance.DecodeProof(&bind.CallOpts{}, pi)

	valid, err := instance.Verify(&bind.CallOpts{}, [2]*big.Int{privateKey.X, privateKey.Y}, d, alpha)
	if err != nil {
		t.Errorf("%v", err)
	}

	assert.True(t, valid)
}
