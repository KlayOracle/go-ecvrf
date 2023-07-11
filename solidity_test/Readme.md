## Testing

### Step 1

Install and start ganache cli.

```shell
 npm install ganache --global
 
 ganache
```

### Step 2

Copy one of the private key and replace in the `verify_test.go` on line **26** without the `0x` prefix of the private key.

### Step 3

Run from this directory root on terminal.

```shell
go test
```

Proof will be generated in golang and verified with solidity.