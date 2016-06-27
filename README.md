
![MotoLOGIC Logo](https://www.motologic.com/assets/logo-d2c564e3062680706e506d3ba8171aba.png)


# Partner Site Authentication

MotoLOGIC allows users of a partner site to seamlessly authenticate and navigate the Repair and Diagnostics web app via a special request from the partner site.  

At a high level, this is done via a HTTPS request that includes a few special parameters that:

- Allow MotoLOGIC to authenticate the request as being from a specific trusted partner site.
- Include basic user information for the MotoLOGIC session (e.g. to display their information on the UI, for example).

A secondary function of the request is to allow the partner site to provide ACES car fields in the query string, which can then be used as a whole to navigate the user to the equivalent MotoLOGIC car, optionally including a keyword search and service info type selection.

Once the request is completed, the partner site user will have established a session on the MotoLOGIC site.

## Request Details

The request URL takes the form:

`https://www.motologic.com/aces-car?partner_site_id={partner_site_id}&token={auth_token}&keywords={keywords}&sit={sit}&{aces-car-field_1}={value_1}&{aces-car-field_n}={value_n}`

Where:

- `{keywords}` = search keywords.

- `{sit}` = service information type to be selected in the MotoLOGIC search results page UI (located on the right side).  Valid values are:
    * /sit/all
    * /sit/bulletins
    * /sit/diagnostics
    * /sit/diagrams
    * /sit/locators
    * /sit/maintenance
    * /sit/repair
    * /sit/specifications
    * /sit/labor
    * /sit/om  (owner's manual)
    
  These values should be URL encoded.

  For example, to perform a request to search for “brakes” and select the “repair” sit:
  
  * The “repair” service info type has the path: `/sit/repair`.

  Thus, the query string, which must have its values URL encoded, would be:

  `?keywords=brakes&sit=%2Fsit%2Frepair`

  The list of the possible sit values may change from time to time.  Please contact MotoLOGIC if you are running into problems with them.  (Last updated on June 6, 2016.)

- `{aces-car-field_1}..{aces-car-field_n}` = a set of “aces labels” and respective values which are used to map an aces car to a MotoLOGIC car. MotoLOGIC cares about only a subset of all possible “aces labels”.  Also note that, with the exception of YearID, we mean aces labels, as in "ModelName", not aces IDs (e.g. "ModelID").  The list of required aces labels is outlined below, with some sample values:

  | Label | Sample Value |
|----------- | -----------|
| AspirationName | Naturally Aspirated |
| BlockType | L |
| BodyTypeName |  
| CylinderHeadTypeName | DOHC |
| Cylinders | 4 |
| DriveTypeName | FWD |
| EngineDesignationName |  
| EngineVersion |  
| EngineVINName |  
| FuelTypeName | GAS |
| MfrBodyCodeName |  
| Liter | 2.0L |
| MakeName | Dodge |
| ModelName | Neon |
| SubmodelName |  
| TransmissionTypeName 
| TransmissionNumSpeeds   
| TransmissionControlTypeName | Automatic |
| TransmissionMfrCode |  
| VehicleTypeName |  
| VersionDate |  
| YearID | 2005 |

  There is not a hard requirement that all the above field values are present.  However, the fields above are the minimum needed to avoid resulting in more than one matching MotoLOGIC car.

The auth params included with the above request URL look like:

```
partner_site_id={auth-partner}&token={encrypted-token}
```

Where:

- `{auth-partner}` = a unique identifier for the partner.  This value will be provided by MotoLOGIC.
- `{encrypted-token}` = an encrypted token.  See the "Authentication Token" section below.


Finally, the URL must use the HTTPS protocol, not HTTP.  HTTP requests will be redirected to HTTPS equivalents.

### Example

GET Request URL:

```
https://www.motologic.com/aces-car?AspirationName=Naturally%20Aspirated&BlockType=L&BodyTypeName=&CylinderHeadTypeName=DOHC&Cylinders=4&DriveTypeName=FWD&EngineDesignationName=&EngineVINName=&EngineVersion=&FuelTypeName=GAS&Liter=2.0L&MakeName=Dodge&MfrBodyCodeName=&ModelName=Neon&SubmodelName=&TransmissionControlTypeName=Automatic&TransmissionMfrCode=&TransmissionNumSpeeds=&TransmissionTypeName=&VehicleTypeName=&VersionDate=&YearID=2005&keywords=foo&sit=%2Fsit%2Frepair&partner_site_id=magic_garage&token=TN%2FUEzg0uaVTN17uJbHNERblHKIN8xqI117LO%2BRxNTzVHrf3JeZdL8G4xweIHKl1ALwBTvqs4SYFOjEM7Di5xPbHK0gsT9jwcZbDVdItu6sWeW8gUUyfuztNEuCpLWpVQN4fTzCj1uCVODN8DK0Srg%3D%3D
```

## Authentication Token

The partner site's authentication token is an encrypted token which contains a few details about the partner site user that is to navigate the MotoLOGIC site.

As a pre-requisite, both parties will have a shared key for the symmetric encryption of the token (it will be provided by MotoLOGIC as part of the setup).  Each party **must** keep this key private (e.g. it should not be hanging out on the client/browser side).  Exposing of this key by either party would result in arbitrary users having the ability to add themselves to and freely access the MotoLOGIC site!

### Creating The Token

The token payload is a simple JSON structure with the partner site user's username, email (or both--**at least one is required)**, and a timestamp in [ISO-8601](https://en.wikipedia.org/wiki/ISO_8601) format, indicating the token creation time:

  ```json
  {
    "username":"jsmith3",
    "email":"",
    "created":"2015-08-18T06:36:40+00:00"
  }
  ```

### Encrypting The Token

The token is encrypted with the following parameters:

  - AES-256-CBC cipher with [PKCS7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7) padding
  - [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) key derivation function with a SHA1-based HMAC
  - 16-byte salt and 16-byte IV lengths
  - Strict Base64 encoding of a byte array consisting of the concactenated generated salt byte array and encrypted output byte array

#### Ruby OpenSSL Example

1. Generate a random 16-byte salt:

  ```
    salt = OpenSSL::Random.random_bytes(16)
  ```
2. Generate a key and an IV (initalization vector).  A shared secret should not be used as-is to encrypt or decrypt.  It must be hashed or otherwise manipulated before it is passed on to the encrypt/decrypt functions.  One way to do this is by use of a *key derivation function*.  (A "key" is what the shared secret becomes after such processing.)  

  A popular function is "PBKDF2", which is standard across several platforms (Ruby and C# to name a few, as well as any package that uses a recent OpenSSL.) and is what will be used for this scheme.  
  
  The function takes the shared secret, a salt value, a number of iterations, and the total length of resulting bytes, and generates an array of bytes.  Calling the function with the same shared secret, salt, iterations, and length should yield the same resulting bytes, thus agreeing on these parameters allows both parties to do the encryption/decryption successfully.  In our case, the parameters **required** to be agreed upon are:

  - 32-byte key length (dictated by use of AES-256 cipher)
  - 16-byte salt length
  - 16-byte IV length
  - 10,000 iterations for the "PBKDF2" function

  Here is the Ruby function call (assume the `shared_secret` variable has been set at some point):

  ```
    key_and_iv = OpenSSL::PKCS5.pbkdf2_hmac_sha1(shared_secret, salt, 10000, 48)
  ```
  Because the function is static, we must call it a single time and generate 48 bytes (32 for the key, and 16 for the IV).  Do not make two separate calls for the key and IV, as you will end up with the same first 16 bytes for both items!

3. Configure the cipher:

  ```
    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.encrypt
    cipher.key = key_and_iv[0, 32] # 32 byte key
    cipher.iv = key_and_iv[32, 48] # 16-byte IV
  ```

  Note that the code above splits the `key_and_iv` bytes into the respective `cipher.key` and `cipher.iv` parameters.
  
4. Encrypt the JSON value:

   ```
     cipher_text = cipher.update(json_value) + cipher.final
   ```

5. Encode the Cipher Text:  the `cipher_text` value from the previous step is a byte array.  Since the token will need to be sent as a url parameter, we need to encode the byte array into a string.  However, we also want to send the "salt" value generated in step 1, so that the receiving party can use it and the shared secret to re-generate the same key and IV values.  Thus, we will take the salt byte array, append the cipher text byte array, and then base64 encode the combined byte array:

  ```
    encoded_token = Base64.strict_encode64(salt + cipher_text)
  ```

6. Lastly, we need to escape the encoded string for use in URLs. In ruby, this looks like: 

  ```
    CGI::escape(encoded_token)
  ```

#### Microsoft .NET C# Example

The C# equivalent of Ruby's `OpenSSL::PKCS5.pbkdf2_hmac_sha1` function is [Rfc2898DeriveBytes.GetBytes](https://msdn.microsoft.com/en-us/library/system.security.cryptography.rfc2898derivebytes(v=vs.110).aspx).  Unlike the Ruby counterpart, the C# class can be instantiated, and subsequent `GetBytes` calls can be made, so there is no need to do byte array splitting in C#.

```
// You will want to URL encode the resulting token string (e.g. HttpUtility.UrlEncode(x)), as sometimes 
// Base64 encoding can result in special query string parameter characters (such as "+").

public static string TestEncryption(string mySharedSecret, int iterations, string myJson)
{
  // Generate a random 16-byte salt
  var mySalt = new byte[16];
  using (var rnd = RandomNumberGenerator.Create())
  {
    rnd.GetBytes(mySalt);
  }

  // Generate key and IV using PBKDF2
  var deriveBytes = new Rfc2898DeriveBytes(mySharedSecret, mySalt, iterations);
  var key = deriveBytes.GetBytes(32);
  var iv = deriveBytes.GetBytes(16);

  var plainTextBytes = Encoding.UTF8.GetBytes(myJson);

  var transform = new RijndaelManaged();
  byte[] saltAndCipherBytes;

  using (var ms = new MemoryStream())
  {
    using (var cryptoStream = new CryptoStream(ms, transform.CreateEncryptor(key, iv), CryptoStreamMode.Write))
    {   
      cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Count());
    }   

    var cipherTextBytes = ms.ToArray();

    // Concatenate salt and cypher text bytes
    saltAndCipherBytes = new byte[cipherTextBytes.Length + mySalt.Length];
    Buffer.BlockCopy(mySalt, 0, saltAndCipherBytes, 0, mySalt.Length);
    Buffer.BlockCopy(cipherTextBytes, 0, saltAndCipherBytes, mySalt.Length, cipherTextBytes.Length);
  }

  return Convert.ToBase64String(saltAndCipherBytes);
}
```
