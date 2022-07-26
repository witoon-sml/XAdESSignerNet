using FirmaXadesNet.Crypto;
using FirmaXadesNet.Signature.Parameters;
using pkcs;
using System;
using timestamp;
using System.IO;
using utility;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using FirmaXadesNet.Upgraders.Parameters;
using System.Security;
using System.Security.Cryptography;
using System.Threading;

namespace sign
{
    class XAdESSigner
    {
        /**
         * Sign single XML file in Baseline-B Conformance
         * 
         * @param inputFilePath The input XML path
         * @param outputFilePath The output XML path
         * @param pKCSInstance The Public key cryptography instance
         * @param digestAlgorithm The digest algorithm, supports SHA-256 and SHA-512
         * @param signaturePackaging The signature packaging, how signature will be store
         * @param externalSignatureFilePath The XML path for external signature
         */
        public void SignBESOnce(string inputFilePath, string outputFilePath, IPKCSInstance pKCSInstance, DigestAlgorithm digestAlgorithm, 
            SignaturePackaging signaturePackaging, string externalSignatureFilePath)
        {
            // Compose SignatureParameters
            SignatureParameters signatureParameter = GetSignatureParameter(digestAlgorithm, signaturePackaging, 
                externalSignatureFilePath, pKCSInstance);
            
            // Call to generate signature and save output file
            (new SignController()).SignBES(inputFilePath, outputFilePath, signatureParameter);
        }

        /**
         * Sign multiple XML file in Baseline-B Conformance
         * 
         * @param inputFolderPath The input XML path
         * @param outputFolderPath The output XML path
         * @param outputSuffix The suffix for output XML path
         * @param pKCSInstance The Public key cryptography instance
         * @param digestAlgorithm The digest algorithm, supports SHA-256 and SHA-512
         * @param signaturePackaging The signature packaging, how signature will be store
         * @param externalSignatureFilePath The XML path for external signature
         */
        public void SignBESMultiple(string inputFolderPath, string outputFolderPath, string outputSuffix, IPKCSInstance pKCSInstance, 
            DigestAlgorithm digestAlgorithm, SignaturePackaging signaturePackaging, string externalSignatureFilePath)
        {
            // Get all XML file from specific folder
            List<FileSpecification> fileSpecList = GetFileFromFolder(inputFolderPath);

            // Compose SignatureParameters
            SignatureParameters signatureParameter = GetSignatureParameter(digestAlgorithm, signaturePackaging, externalSignatureFilePath, pKCSInstance);
            
            // Loop sign each file in folder
            foreach (FileSpecification fileSpec in fileSpecList)
            {
                // Compose input and output file name
                string inputFilePath = fileSpec.FullFilePath;
                string outputFilePath = null;
                if (outputSuffix != null)
                {
                    outputFilePath = outputFolderPath + "/" + fileSpec.FileNameWithoutExtension + outputSuffix + fileSpec.FileExtension;
                }
                else
                {
                    outputFilePath = outputFolderPath + "/" + fileSpec.FileNameWithoutExtension + fileSpec.FileExtension;
                }

                // Call to generate signature and save output file
                (new SignController()).SignBES(inputFilePath, outputFilePath, signatureParameter);
            }

        }

        /**
         * Sign single XML file in Baseline-T Conformance
         * 
         * @param inputFilePath The input XML path
         * @param outputFilePath The output XML path
         * @param pKCSInstance The Public key cryptography instance
         * @param digestAlgorithm The digest algorithm, supports SHA-256 and SHA-512
         * @param signaturePackaging The signature packaging, how signature will be store
         * @param externalSignatureFilePath The XML path for external signature
         * @param timeStamp TimeStamp instance (XAdES-T allow only TSA timestamp)
         */
        public void SignTOnce(string inputFilePath, string outputFilePath, IPKCSInstance pKCSInstance, DigestAlgorithm digestAlgorithm,
            SignaturePackaging signaturePackaging, string externalSignatureFilePath, TimeStamp timeStamp)
        {
            // Compose SignatureParameters
            SignatureParameters signatureParameter = GetSignatureParameter(digestAlgorithm, signaturePackaging,
                externalSignatureFilePath, pKCSInstance);
            UpgradeParameters upgradeParameters = GetUpgradeParameters(timeStamp);

            // Call to generate signature and save output file
            (new SignController()).SignT(inputFilePath, outputFilePath, signatureParameter, upgradeParameters);
        }

        /**
         * Sign single XML file in Baseline-T Conformance
         * 
         * @param inputFolderPath The input XML path
         * @param outputFolderPath The output XML path
         * @param outputSuffix The suffix for output XML path
         * @param pKCSInstance The Public key cryptography instance
         * @param digestAlgorithm The digest algorithm, supports SHA-256 and SHA-512
         * @param signaturePackaging The signature packaging, how signature will be store
         * @param externalSignatureFilePath The XML path for external signature
         * @param timeStamp TimeStamp instance (XAdES-T allow only TSA timestamp)
         */
        public void SignTMultiple(string inputFolderPath, string outputFolderPath, string outputSuffix, IPKCSInstance pKCSInstance, DigestAlgorithm digestAlgorithm,
            SignaturePackaging signaturePackaging, string externalSignatureFilePath, TimeStamp timeStamp)
        {
            // Get all XML file from specific folder
            List<FileSpecification> fileSpecList = GetFileFromFolder(inputFolderPath);

            // Compose SignatureParameters
            SignatureParameters signatureParameter = GetSignatureParameter(digestAlgorithm, signaturePackaging,
                externalSignatureFilePath, pKCSInstance);
            UpgradeParameters upgradeParameters = GetUpgradeParameters(timeStamp);

            // Loop sign each file in folder
            foreach (FileSpecification fileSpec in fileSpecList)
            {
                // Compose input and output file name
                string inputFilePath = fileSpec.FullFilePath;
                string outputFilePath = null;
                if (outputSuffix != null)
                {
                    outputFilePath = outputFolderPath + "/" + fileSpec.FileNameWithoutExtension + outputSuffix + fileSpec.FileExtension;
                }
                else
                {
                    outputFilePath = outputFolderPath + "/" + fileSpec.FileNameWithoutExtension + fileSpec.FileExtension;
                }

                // Call to generate signature and save output file
                (new SignController()).SignT(inputFilePath, outputFilePath, signatureParameter, upgradeParameters);

                Console.WriteLine("\tWait 5 seconds...");
                Thread.Sleep(5000);
            }
        }

        /**
         * GetSignatureParameter
         * @param digestAlgorithm The digest algorithm, supports SHA-256 and SHA-512
         * @param signaturePackaging The signature packaging, how signature will be store
         * @param externalSignatureFilePath The XML path for external signature
         * @param pKCSInstance The Public key cryptography instance
         * 
         * @return SignatureParameters
         */
        private SignatureParameters GetSignatureParameter(DigestAlgorithm digestAlgorithm, SignaturePackaging signaturePackaging, string externalSignatureFilePath, IPKCSInstance pKCSInstance)
        {
            SignatureParameters signatureParameter = new SignatureParameters();

            // Set sign date => Now
            signatureParameter.SigningDate = DateTime.Now;

            // Set hash algorithm
            switch (digestAlgorithm)
            {
                // SHA-256
                case DigestAlgorithm.SHA256:
                    signatureParameter.SignatureMethod = SignatureMethod.RSAwithSHA256;
                    break;
                // SHA-364 -> Not natively support by firmaxades, now avalilable by modify original firmaxades
                case DigestAlgorithm.SHA384:
                    signatureParameter.SignatureMethod = SignatureMethod.RSAwithSHA384;
                    break;
                // SHA-512
                case DigestAlgorithm.SHA512:
                    signatureParameter.SignatureMethod = SignatureMethod.RSAwithSHA512;
                    break;
                // Default : SHA-256
                default:
                    signatureParameter.SignatureMethod = SignatureMethod.RSAwithSHA256;
                    break;
            }

            //Set signature package
            switch (signaturePackaging)
            {
                // ENVELOPED signature
                case SignaturePackaging.ENVELOPED:
                    signatureParameter.SignaturePackaging = FirmaXadesNet.Signature.Parameters.SignaturePackaging.ENVELOPED;
                    break;
                // ENVELOPING signature
                case SignaturePackaging.ENVELOPING:
                    signatureParameter.SignaturePackaging = FirmaXadesNet.Signature.Parameters.SignaturePackaging.ENVELOPING;
                    break;
                // EXTERNALLY_DETACHED signature
                case SignaturePackaging.EXTERNALLY_DETACHED:
                    if (externalSignatureFilePath == null)
                        throw new Exception("For EXTERNALLY_DETACHED method, external signature file must be input");
                    if (Path.GetExtension(externalSignatureFilePath).Equals("xml", StringComparison.InvariantCultureIgnoreCase))
                        throw new Exception("External signature file must be XML");
                    signatureParameter.SignaturePackaging = FirmaXadesNet.Signature.Parameters.SignaturePackaging.EXTERNALLY_DETACHED;
                    break;
                // INTERNALLY_DETACHED
                case SignaturePackaging.INTERNALLY_DETACHED:
                    signatureParameter.SignaturePolicyInfo = new SignaturePolicyInfo() { PolicyIdentifier = "", PolicyHash = "" };
                    signatureParameter.SignaturePackaging = FirmaXadesNet.Signature.Parameters.SignaturePackaging.INTERNALLY_DETACHED;
                    signatureParameter.DataFormat = new DataFormat();
                    signatureParameter.DataFormat.MimeType = "text/xml";
                    break;
                // Unknown SignaturePackaging input, included null
                default:
                    throw new Exception("Unrecognized signature packaging");
            }

            // Set PKCS12 instance
            if (pKCSInstance is PKCS12Instance)
            {
                signatureParameter.Signer = new Signer(
                   new X509Certificate2(
                       ((PKCS12Instance)pKCSInstance).FilePath,
                       ((PKCS12Instance)pKCSInstance).KeyStorePassword)
                   );
            }
            // Set PKCS11 instance
            else if (pKCSInstance is PKCS11Instance)
            {
                // Open PKCS11 Store
                X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.MaxAllowed);

                // Set up input as X500DistinguishedName
                var name = new X500DistinguishedName(((PKCS11Instance)pKCSInstance).SearchPhase, X500DistinguishedNameFlags.None).Format(false);
                var certificateList = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, name, false);
                var certificate = certificateList[0];

                // Close PKCS11 Store
                store.Close();

                // Certificate not found
                if (certificate == null)
                {
                    throw new Exception("KeyStore not found");
                }

                // Pass certificate into FirmaXAdES
                var pass = new SecureString();
                char[] array = ((PKCS11Instance)pKCSInstance).Pin.ToCharArray();
                foreach (char ch in array)
                {
                    pass.AppendChar(ch);
                }
                var privateKey = certificate.PrivateKey as RSACryptoServiceProvider;
                CspParameters cspParameters = new CspParameters(
                    privateKey.CspKeyContainerInfo.ProviderType,
                    privateKey.CspKeyContainerInfo.ProviderName,
                    privateKey.CspKeyContainerInfo.KeyContainerName,
                    new System.Security.AccessControl.CryptoKeySecurity(),
                    pass);

                var rsaCsp = new RSACryptoServiceProvider(cspParameters);
                certificate.PrivateKey = rsaCsp;
                signatureParameter.Signer = new Signer(certificate);
            }else if (pKCSInstance == null)
            {
                signatureParameter.Signer = new Signer(FirmaXadesNet.Utils.CertUtil.SelectCertificate());
            }
            // Unknown PKCS instance
            else
            {
                throw new Exception("Unrecognized PKCS instance");
            }
            return signatureParameter;
        }

        /**
         * GetUpgradeParameters
         * 
         * @param timeStamp TimeStamp instance (XAdES-T allow only TSA timestamp)
         * 
         * @return UpgradeParameters
         */
        private UpgradeParameters GetUpgradeParameters(TimeStamp timeStamp)
        {
            UpgradeParameters upgradeParameters = new UpgradeParameters();

            if (timeStamp.TimeStampType != TimeStampType.TSA)
            {
                throw new Exception("XAdES-T can only use timestamp from TSA");
            } 
            else
            {
                switch(timeStamp.TSAAuthenticationType)
                {
                    // NO Authentication
                    case TSAAuthenticationType.NO_AUTHENTICATION:
                        // Check input
                        if (timeStamp.URL == null)
                        {
                            throw new NullReferenceException("Timestamp URL cannot be null");
                        }
                        else if (timeStamp.URL.Trim().Equals(""))
                        {
                            throw new NullReferenceException("Timestamp URL cannot be blank");
                        }
                        // Create timestamp client
                        upgradeParameters.TimeStampClient = new FirmaXadesNet.Clients.TimeStampClient(timeStamp.URL);
                        break;
                    // Username & Password
                    case TSAAuthenticationType.USERNAME_PASSWORD:
                        // Check input
                        if (timeStamp.URL == null || timeStamp.Username == null || timeStamp.Password == null)
                        {
                            throw new NullReferenceException("Timestamp URL/Username/Password cannot be null");
                        }
                        else if (timeStamp.URL.Trim().Equals("") || timeStamp.Username.Trim().Equals("") || timeStamp.Password.Trim().Equals(""))
                        {
                            throw new NullReferenceException("Timestamp URL/Username/Password cannot be blank");
                        }
                        // Create timestamp client
                        upgradeParameters.TimeStampClient = new FirmaXadesNet.Clients.TimeStampClient(
                            timeStamp.URL, timeStamp.Username, timeStamp.Password);
                        break;
                    case TSAAuthenticationType.CERTIFICATE:
                        // Check input
                        if (timeStamp.URL == null || timeStamp.CertificatePath == null || timeStamp.Password == null)
                        {
                            throw new NullReferenceException("Timestamp URL/Certificate path/Password cannot be null");
                        }
                        else if (timeStamp.URL.Trim().Equals("") || timeStamp.CertificatePath.Trim().Equals("") || timeStamp.Password.Trim().Equals(""))
                        {
                            throw new NullReferenceException("Timestamp URL/Certificate path/Password cannot be blank");
                        }
                        // Create timestamp client
                        upgradeParameters.TimeStampClient = new FirmaXadesNet.Clients.TimeStampClient(
                            timeStamp.URL, timeStamp.CertificatePath, timeStamp.Password, true);
                        break;
                    default:
                        throw new Exception("Unrecognized TSA authentication");
                }
            }

            upgradeParameters.DigestMethod = DigestMethod.SHA256;

            return upgradeParameters;
        }


        /**
		 * Get all file in specific folder
		 * @param folderPath
		 * @return List<FileSpecification>
		 */
        private List<FileSpecification> GetFileFromFolder(string folderPath)
        {
            List<FileSpecification> fileSpecList = new List<FileSpecification>();
            foreach (string file in Directory.GetFiles(folderPath, "*.xml", SearchOption.AllDirectories))
            {
                //Console.WriteLine(file);
                FileSpecification fileSpecification = new FileSpecification();
                fileSpecification.FullFilePath = Path.GetFullPath(file);
                fileSpecification.FileNameWithExtension = Path.GetFileName(file);
                fileSpecification.FileNameWithoutExtension = Path.GetFileNameWithoutExtension(file);
                fileSpecification.FileExtension = Path.GetExtension(file);
                fileSpecList.Add(fileSpecification);
            }
            return fileSpecList;
        }
    }
}
