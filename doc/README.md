## Developer guides

### Local build

```
$ go build -o sbom2vans ./cmd/sbom2vans
```

### Testing command

```bash
$ ./sbom2vans -u "國家資通安全研究院" --oid "88385753" \
-i ./test/spdx.json \
--vans-key "wU......u0" \
--nvd-key "65d12345-abcd-xxxx-xxxx-654321d00e31" \
--vans-url "http://staging-nics-external-561465956.ap-northeast-1.elb.amazonaws.com" --debug
```
