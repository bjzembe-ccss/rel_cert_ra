# related-certs-ca

This README describes the steps necessary to generate the RA key material and CSRs using OQS-openssl.

* start\_[proto]\_server.bs. This file starts a simple [proto] server on port 8000 from the certs directory
* test\_asn1.cnf. Tbh I don't remember what this file was for, but it looks like I was trying to make something important work...
* gen\_rel\_cert\_config.py: This script accepts a filepath to a previously issued certificate, as well as a server uri, and generates an openssl config file in the `./config/` directory. The resulting file contains all necessary config parameters for the related-certs extension, and uses the file `config/rel_cert_base.cnf` as a base. 
* reqs/: This directory is for storing Certificate Signing Requests.
* keys/: Thid directory is for storying private (or public) keys.
* config/: This directory holds config files, which are passed along with CSRs to openssl to provide extension parameters.
  - config/base.cnf: This file holds basic required parameters like dname, basicConstraints, etc. This file is used as a baseline for generating other config files.
  - config/rel\_cert\_base.cnf: This is a config file which imports all the same parameters as in base.cnf, but includes an additional rel\_cert\_ext section. This file is used as a template for generating config files for CSRs which use the related certificate extension.
  - config/hybrid\_signed\_rsa4096.cnf: This file is a sample config file for a CSR which uses the related certificate extension. It has a rel\_cert section which contains the fields necessary for the related certificate extension. The key attributes are certID, requestTime, locationInfo (which contains accessMethod and accessLocation), and signature. This file was automatically generated by the gen rel cert config python script.


## Generate Prerequisite Material

First, we want to generate private/public key pairs and certificate signing requests for the RA.

### RSA

#### Generate private key and certificate signing request

```
apps/openssl req -newkey rsa:4096 -keyout ./keys/rsa4096.priv -out rsa4096.csr -nodes -config ./config/base.cnf
```

#### Derive public key from private key

```
apps/openssl pkey -in ./keys/rsa4096.priv -pubout -out ./keys/rsa4096.pub
```

### EC secp521r1

#### Generate private key and certificate signing request

```
apps/openssl req -newkey ec:<(oqs ecparam -name secp521r1) -keyout ./keys/secp521r1.priv -out secp521r1.csr -nodes -config ./config/base.cnf
```

#### Derive public key from private key

```
apps/openssl pkey -in ./keys/secp521r1.priv -pubout -out ./keys/secp521r1.pub
```

### dilithium lvl 5

#### Generate private key and certificate signing request

```
apps/openssl req -newkey dilithium5 -keyout ./keys/dilithium5.priv -out dilithium5.csr -nodes -config ./config/base.cnf
```

#### Derive public key from private key

```
apps/openssl pkey -in ./keys/dilithium5.priv -pubout -out ./keys/dilithium5.pub
```

## Use the CA to sign the "previously issued" cert

In the related certs draft, either a PQ-signed cert can reference a previously issued Classically signed cert, or a Classically signed cert can reference a previously issued PQ-signed cert. We will assume the former. In this step we will generate the "previously issued" cert; in this case, one which was signed using our rsa:4096 key.

Assuming that both 'related-certs-ca' and 'related-certs-ra' are cloned locally on the same machine (for testing purposes), the command to do so is as follows;

```
apps/openssl x509 -req -in ~/ra/related-certs-ra/reqs/rsa4096.csr -out ~/ra/related-certs-ra/certs/signed_rsa4096.crt -CA ~/ca/related-certs-ca/rsa4096_root.crt -CAkey ~/ca/related-certs-ca/rsa4096_root.priv -CAcreateserial -days 3650
```

## Create related-certs config file

We want to extract the information from the "previously issued" rsa4096 cert so that we can reference this cert in a CSR which implements the related-certs extension. This can be accomplished using the `gen_rel_cert_config.py` script.

### gen\_rel\_cert\_config.py

The `gen_rel_cert_config.py` script accepts a filepath to a previously issued certificate, as well as a server uri, and generates an openssl config file in the `./config/` directory. The resulting file contains all necessary config parameters for the related-certs extension, and uses the file `config/rel_cert_base.cnf` as a base. The usage of this script is as follows;

```
python3 gen_rel_cert_config.py FILEPATH SERVER_URI [-v|--verbose]
```

Unfortunately I couldn't figure out how to get python to read from the `~/.bash_aliases` file lol. In order to get the script to function properly, you will need to modify the `OQS_CMD` variable at the top of the script to be the global filepath to the OQS `apps/openssl` executable.

The `SERVER_URI` parameter represents the an http or ftp URI from which the CA can access teh previously issued certificate for validation. A simple server can be started using the `start_server.bs` script. This script starts an http server in the `certs/` directory. For testing purposes where the CA and RA are located on the same machine, the `SERVER_URI` parameter can be set to `http://0.0.0.0`.

We can therefore create a related-certs config file using our previously issued rsa4096 cert by executing the following;

```
python3 gen_rel_cert_config.py ./certs/signed_rsa4096.crt http://0.0.0.0
```

## Create hybrid certificate

We will want to use the hybrid rsa4096 config file with the dilithium5 CSR to create a signed hybrid certificate. This can be accomplished with the following command;

```
apps/openssl x509 -req -in ~/ra/related-certs-ra/reqs/dil5.csr -days 3650 -CA ~/ca/related-certs-ca/dilithium5_root.crt -CAkey ~/ca/dilithium5_root.priv -CAcreateserial -out ~/ra/related-certs-ra/certs/dil5_rsa4096_hybrid.crt -extensions rel_cert_ext -extfile ~/ra/related-certs-ra/config/hybrid_signed_rsa4096.cnf
```

The implementation of this command is still a work in progress.

