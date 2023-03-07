# 2FA-API
[![Documentation Status](https://readthedocs.org/projects/2fa-api/badge/?version=latest)](https://2fa-api.readthedocs.io/en/latest/?badge=latest)
[![](https://jitpack.io/v/TominoLP/2FA-API.svg)](https://jitpack.io/#TominoLP/2FA-API)

## Introduction
The 2FA-API is a Java library for generating QR codes and validating codes for Two-factor authentication. The library supports both the TOTP (Time-based One-Time Password) algorithm and SHA1 hashing. The library generates a secret key that can be stored securely on the client-side and a QR code that can be displayed to the user.


---

## Usage

You can use the TWOFA-API library in your Java application by following these steps:

1. Generate a secret key:
```java
String secretKey = AuthSys.generateSecretKey();
```

2. Generate a QR code image or bufferd image:
```java
BufferedImage qrCodeImage = AuthSys.generateQrCodeData(secretKey, "YourApp", "username");
```

```java
Image qrCodeImage = AuthSys.generateQrCode(secretKey, "YourApp", "username");
```
you can also use the method `generateLink` to get the link to the QR code image:
```java
String link = AuthSys.generateLink(secretKey, "YourApp", "username");
```




3. Display the QR code to the user, so they can scan it with their authenticator app,
such as Google Authenticator
        

4. Validate the code entered by the user:
```java
boolean isValid = AuthSys.validateCode(secretKey, userEnteredCode);
```
if you wish to save the QR code image to a file, you can use the method `saveQrCode`:
```java
AuthSys.saveQrCode(qrCodeImage, fileformat ,"path/to/file");
```

That's it! You can now use the TWOFA-API library to add Two-factor authentication to your Java application.
 


### NEW!

you can now also generate TOTP codes with the method `generateCode`:
```java
HashMap<String, String> secretKeys = TOTP.generateCode(timeInSecondsAsInt)
```
the method returns a HashMap with the secret key as key and the code as value. 

now you can send the code to the user via email or something else. 

that you can validate the code with the method `validateTOTPCode`:
```java
boolean isValid = AuthSys.validateTOTPCode(secretKey, code);
```

you can also get the ExpirationDate of the code with the method `getExpirationDate`:
```java
Date expirationDate = TOTP.getExpirationDate(secretKey);
```

---
## Example

```java
import java.awt.*;
import java.awt.image.BufferedImage;

public class Example {
    public static void main(String[] args) {
        String secretKey = AuthSys.generateSecretKey();
        String issuer = "Example Company";
        String account = "john@example.com";

        // Generate the QR code as a BufferedImage
        Image qrCodeImage = AuthSys.generateQrCode(secretKey, issuer, account);

        // Display the QR code image or save it to a file

        // Validate a code
        String code = "123456"; // The code entered by the user
        boolean isValid = AuthSys.validateCode(secretKey, code);
        if (isValid) {
            System.out.println("Code is valid!");
        } else {
            System.out.println("Code is not valid.");
        }
    }
}
```

---

## Installation

You can install the TWOFA-API library via [jitpack](https://jitpack.io/#TominoLP/2FA-API) by adding the following to your Maven pom.xml file:

#### Maven

```xml
<repository>
    <id>jitpack.io</id>
    <url>https://jitpack.io</url>
</repository>

<dependency>
    <groupId>com.github.TominoLP</groupId>
    <artifactId>2FA-API</artifactId>
    <version>1.1</version>
</dependency>
```

#### Gradle

Or, if you're using Gradle, add the following to your build.gradle file:

```kotlin
repositories {
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'com.github.TominoLP:2FA-API:1.1'
}
```

---

## License
This API is licensed under the Apache License 2.0. click [here](http://www.apache.org/licenses/LICENSE-2.0) to read the full license.

---

## Support
**add me on discord:** _Tomino#0101_\
**or:** [Send an email](mailto:Kontakt@TomWerth.de)


---

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
