```shell
solc --abi contract/VerifyVRF.sol -o ./build --bin --overwrite

abigen --bin=build/VerifyVRF.bin --abi=build/VerifyVRF.abi --pkg solidity_vrf --type VerifyVRF -out verify.go
```