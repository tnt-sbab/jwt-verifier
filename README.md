# JWT Verifier
JWT Verifier is a Traefik middleware that verifies the Authorization Bearer JWT header RS512 signature, iss, nbf and exp.

### Generate public and private RS512 keys for test on macOS
`ssh-keygen -t rsa -b 4096 -E SHA512 -f jwtRS512.key -m PEM`
`openssl rsa -in jwtRS512.key -pubout -outform PEM -out jwtRS512.key.pub`