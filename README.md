# XAdES Signer
  
XAdES Signer is project for sign XML Document with Certificate. 

## Prerequisites
- NET Framework 3.5
- Visual Studio 2019 

## Library Dependencies
- BouncyCastle 1.8.9

## Getting started
### Quick Usage
`XAdESSigner.exe -signType "multiple" -inputFolder "xml" -outputFolder "signed_xml" -outputSuffix "_signed" -selfSelectCert "TRUE" -signLevel "BES" -timeStampingType "COMPUTER_CLOCK" -digestAlgorithm "SHA256"
`

### Command Line Parameter
-`-signType "single | multiple"` Single or Multiple sign.
-`-signLevel "BES | T"` XAdES' Level
-`-inputFile "<PATH_TO_FILE>"`  Input file path.
-`-outputFile "<PATH_TO_FILE>"` Output file path
-`-inputFolder "<PATH_TO_FOLDER>"`  Input folder.
-`-outputFolder ""<PATH_TO_FOLDER>"` Output folder.
-`-selfSelectCert "TRUE"` Use Self Select Certificate.
-`-pkcs11TokenName "<NAME>"` PKCS11 Token's name
-`-pkcs11LibraryPath "<PATH_TO_FILE>"` PKCS11 Token's library path. 
-`-pkcs11Pin "<PASSWORD>"` Token's password
-`-pkcs11KeyStorePassword "<PASSWORD>"` Keystore's password
-`-pkcs11SeachKeyword "<ANY_TEXT>"` Certificate Search for pkcs11 Token
-`-pkcs12FilePath "<PATH_TO_FILE>"` Path for P12, PFX file.
-`-pkcs12Password "<PASSWORD>"` Password for P12, PFX file.
-`-timeStampType "TSA | COMPUTER_CLOCK"`  Timestamp Type
-`-tsaURL "<URL>"` TSA's URL.
-`-tsaAuthenticationType "<NO_AUTHENTICATION | USERNAME_PASSWORD | CERTIFICATE>"` TSA's authenticate type.
-`-tsaUsername "<USERNAME>"` TSA's username.
-`-tsaPassword "<PASSWORD>"` TSA's password.
-`-digestAlgorithm "<SHA256 | SHA384 | SHA512>"` Hash Algorithm for digest


## More Detail
- การใช้งาน XAdES Signer สามารถศึกษาได้จากไฟล์คู่มีอการใช้งานดังนี้ /XAdESSigner/Manual/04_Manual_XAdESSigner (.NET).docx 

    
    

    
 
