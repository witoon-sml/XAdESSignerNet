# XAdES Signer

XAdES Signer is project for sign XML Document with Certificate.

## Prerequisites

- NET Framework 3.5
- Visual Studio 2019

## Library Dependencies

- BouncyCastle 1.8.9

## Getting started

### Quick Usage

`XAdESSigner.exe -signType "multiple" -inputFolder "xml" -outputFolder "signed_xml" -outputSuffix "_signed" -selfSelectCert "TRUE" -signLevel "BES" -timeStampingType "COMPUTER_CLOCK" -digestAlgorithm "SHA256" `

### Command Line Parameter

_`-signType "single | multiple"` Single or Multiple sign.
_`-signLevel "BES | T"` XAdES' Level
_`-inputFile "<PATH_TO_FILE>"` Input file path.
_`-outputFile "<PATH_TO_FILE>"` Output file path
_`-inputFolder "<PATH_TO_FOLDER>"` Input folder.
_`-outputFolder ""<PATH_TO_FOLDER>"` Output folder.
_`-selfSelectCert "TRUE"` Use Self Select Certificate.
_`-pkcs11TokenName "<NAME>"` PKCS11 Token's name
_`-pkcs11LibraryPath "<PATH_TO_FILE>"` PKCS11 Token's library path.
_`-pkcs11Pin "<PASSWORD>"` Token's password
_`-pkcs11KeyStorePassword "<PASSWORD>"` Keystore's password
_`-pkcs11SeachKeyword "<ANY_TEXT>"` Certificate Search for pkcs11 Token
_`-pkcs12FilePath "<PATH_TO_FILE>"` Path for P12, PFX file.
_`-pkcs12Password "<PASSWORD>"` Password for P12, PFX file.
_`-timeStampType "TSA | COMPUTER_CLOCK"` Timestamp Type
_`-tsaURL "<URL>"` TSA's URL.
_`-tsaAuthenticationType "<NO_AUTHENTICATION | USERNAME_PASSWORD | CERTIFICATE>"` TSA's authenticate type.
_`-tsaUsername "<USERNAME>"` TSA's username.
_`-tsaPassword "<PASSWORD>"` TSA's password.
_`-digestAlgorithm "<SHA256 | SHA384 | SHA512>"` Hash Algorithm for digest

## More Detail

- การใช้งาน XAdES Signer สามารถศึกษาได้จากไฟล์คู่มีอการใช้งานดังนี้ /XAdESSigner/Manual/04_Manual_XAdESSigner (.NET).docx
