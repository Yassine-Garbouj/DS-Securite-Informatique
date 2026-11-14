#!/usr/bin/env bash
# Démonstration PKI avec OpenSSL : AC locale, certificat valide, expiré et d'une AC inconnue.
# Usage : bash pki/openssl_demo.sh   (les fichiers sont créés dans pki/demo/)
set -euo pipefail
cd "$(dirname "$0")"
rm -rf demo && mkdir -p demo/ca/newcerts demo/rogue && cd demo
touch ca/index.txt && echo 1000 > ca/serial

cat > ca/openssl.cnf <<CNF
[ca]
default_ca = CA_default
[CA_default]
dir = ./ca
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
serial = \$dir/serial
default_md = sha256
policy = policy_any
unique_subject = no
copy_extensions = none
[policy_any]
commonName = supplied
[req]
distinguished_name = dn
prompt = no
[dn]
CN = x
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
[v3_user]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,nonRepudiation
CNF

echo "1) AC racine : clé P-256 protégée par passphrase + certificat auto-signé (10 ans)"
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -v2 aes-256-cbc \
    -passout pass:ca-passphrase -out ca/ca.key
openssl req -x509 -new -key ca/ca.key -passin pass:ca-passphrase -sha256 -days 3650 \
    -subj "/CN=SecureShare Local CA" -extensions v3_ca -config ca/openssl.cnf -out ca/ca.crt

echo "2) Certificat valide pour alice (CSR puis signature par l'AC)"
openssl ecparam -name prime256v1 -genkey -noout -out alice.key
openssl req -new -key alice.key -subj "/CN=alice" -out alice.csr
openssl ca -batch -config ca/openssl.cnf -cert ca/ca.crt -keyfile ca/ca.key -passin pass:ca-passphrase \
    -extensions v3_user -days 365 -in alice.csr -out alice.crt -notext 2>/dev/null
openssl verify -CAfile ca/ca.crt alice.crt

echo "3) Certificat EXPIRÉ pour bob (validité passée)"
openssl ecparam -name prime256v1 -genkey -noout -out bob.key
openssl req -new -key bob.key -subj "/CN=bob" -out bob.csr
openssl ca -batch -config ca/openssl.cnf -cert ca/ca.crt -keyfile ca/ca.key -passin pass:ca-passphrase \
    -extensions v3_user -startdate 20240101000000Z -enddate 20240102000000Z \
    -in bob.csr -out bob.crt -notext 2>/dev/null
openssl verify -CAfile ca/ca.crt bob.crt || echo "=> refusé : certificat expiré (attendu)"

echo "4) Certificat signé par une AC INCONNUE (fausse AC)"
openssl ecparam -name prime256v1 -genkey -noout -out rogue/rogue.key
openssl req -x509 -new -key rogue/rogue.key -sha256 -days 365 -subj "/CN=Fausse AC" \
    -extensions v3_ca -config ca/openssl.cnf -out rogue/rogue.crt
openssl x509 -req -in alice.csr -CA rogue/rogue.crt -CAkey rogue/rogue.key -CAcreateserial \
    -days 365 -out alice_fake.crt 2>/dev/null
openssl verify -CAfile ca/ca.crt alice_fake.crt || echo "=> refusé : AC inconnue (attendu)"

echo "5) Contenu du certificat d'alice"
openssl x509 -in alice.crt -noout -subject -issuer -dates -ext keyUsage
