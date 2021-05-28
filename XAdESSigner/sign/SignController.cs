using FirmaXadesNet;
using FirmaXadesNet.Crypto;
using FirmaXadesNet.Signature;
using FirmaXadesNet.Signature.Parameters;
using FirmaXadesNet.Upgraders;
using FirmaXadesNet.Upgraders.Parameters;
using pkcs;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace sign
{
    class SignController
    {

        public SignController()
        {

        }
        public void SignBES(string inputFilePath, string outputFilePath, SignatureParameters signatureParameters)
        {
            Console.WriteLine("\tSining file: " + inputFilePath);

            XadesService xadesService = new XadesService();
            SignatureDocument signatureDocument;

            if (signatureParameters.SignaturePackaging == FirmaXadesNet.Signature.Parameters.SignaturePackaging.EXTERNALLY_DETACHED)
            {
                FileStream fileInputStream = new FileStream(inputFilePath, FileMode.Open);
                signatureDocument = xadesService.Sign(fileInputStream, signatureParameters);
            }
            else
            {
                FileStream fileInputStream = new FileStream(inputFilePath, FileMode.Open);
                signatureDocument = xadesService.Sign(fileInputStream, signatureParameters);
            }
            signatureDocument.Save(outputFilePath);
        }

        public void SignT(string inputFilePath, string outputFilePath, SignatureParameters signatureParameters, UpgradeParameters upgradeParameters)
        {
            Console.WriteLine("\tSining file: " + inputFilePath);

            // XAdES-BES routine
            XadesService xadesService = new XadesService();
            SignatureDocument signatureDocument;

            if (signatureParameters.SignaturePackaging == FirmaXadesNet.Signature.Parameters.SignaturePackaging.EXTERNALLY_DETACHED)
            {
                FileStream fileInputStream = new FileStream(inputFilePath, FileMode.Open);
                signatureDocument = xadesService.Sign(fileInputStream, signatureParameters);
            }
            else
            {
                FileStream fileInputStream = new FileStream(inputFilePath, FileMode.Open);
                signatureDocument = xadesService.Sign(fileInputStream, signatureParameters);
            }

            //XAdES-T routine
            XadesUpgraderService upgrader = new XadesUpgraderService();
            upgrader.Upgrade(signatureDocument, SignatureFormat.XAdES_T, upgradeParameters);
            signatureDocument.Save(outputFilePath);
        }
    }
}

