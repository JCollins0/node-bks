# NODE-BKS

## Definitions

| Term | Definition             |
| ---- | ---------------------- |
| BKS  | Bouncy Castle Keystore |
| JKS  | Java Key store         |

## Use

This Library provides the capability to read BKS Files

### API

```javascript
import { readBKSFile } from "node-bks";

const keyStore = readBKSFile("keystore.bks", "password");
```

## Commands to generate various files

Generate self signed certificate and private key

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
```

Generate BKS file from self signed cert

```bash
keytool -importcert -v -trustcacerts -file cert.pem -alias <ALIAS> -keystore keystore.bks -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath <PATH_TO_BC_PROV.jar> -storetype BKS -storepass <PASSWORD>
```

List contents of bks file

```bash
keytool -list -v -keystore keystore.bks -storepass mypassword -storetype BKS -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath <PATH_TO_BC_PROV.jar>
```
