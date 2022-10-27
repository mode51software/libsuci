# libsuci

5G deconcealment library that [decrypts the SUCI to a SUPI](https://www.mpirical.com/blog/5g-anonymity-and-the-suci) (IMSI). 

Supports ECIES profile B as specified in [TS 33.501](https://www.etsi.org/deliver/etsi_ts/133500_133599/133501/16.12.00_60/ts_133501v161200p.pdf). 
The test data in section C.4.4 is used here. The res/ec-priv-hnkey.der key is the Home Network Private key.

Implements [OpenSSLv3 Elliptic Curve Diffie Hellman key exchange](https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman).

Compatible with [Open5GS](https://github.com/open5gs/open5gs).

## Build

### Build Env
Built using Ubuntu 22:
- gcc 11.3.0
- cmake 3.22.1
- openssl v3 - libcrypto.so.3

### Build Selection

In CMakeLists.txt configure either:
- command line test client
```
set(CMDLINE_TEST 1)
```

or
- libsuci.so

```
set(CMDLINE_TEST 0)
```


### Build

```
mkdir bin
cd bin
cmake ..
make
```
# Changelog
v1.0.3 - 27 Oct 2022

initial release with ECIES profile B support

# License

libsuci files are made available under the terms of the GNU Affero General Public License ([GNU AGPL v3.0](https://www.gnu.org/licenses/agpl-3.0.html)).

Commercial support including HSM and enclave integration is available from [https://mode51.software](https://mode51.software).

ETH 0xfE29b9d1462Dc203F5BA64d64F3B054EaBb64F52
