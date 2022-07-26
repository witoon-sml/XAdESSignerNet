using pkcs;
using sign;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using timestamp;
using utility;

namespace Controller
{
    class Runnable
    {
        public static void Main(string[] args)
        {
            try
            {
				RunWithExternalInput(args);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                Console.Error.WriteLine(ex.StackTrace);
            }
            finally
            {
                Console.WriteLine("Finish library");
                Console.Read();
            }
        }

		public static void RunWithExternalInput(string[] args)
		{
			ParameterController paramCtrl = new ParameterController(args);

			// Input-Output
			string signType = paramCtrl.getParameterValue("-signType");
			string inputFile = paramCtrl.getParameterValue("-inputFile");
			string outputFile = paramCtrl.getParameterValue("-outputFile");
			string inputFolder = paramCtrl.getParameterValue("-inputFolder");
			string outputFolder = paramCtrl.getParameterValue("-outputFolder");
			string outputSuffix = paramCtrl.getParameterValue("-outputSuffix");

			//Self-Select Certificate
			string selfSelectCert = paramCtrl.getParameterValue("-selfSelectCert");

			//PKCS12 Parameter
			string pkcs12FilePath = paramCtrl.getParameterValue("-pkcs12FilePath");
			string pkcs12Password = paramCtrl.getParameterValue("-pkcs12Password");

			//PKCS11 Parameter
			string pkcs11TokenName = paramCtrl.getParameterValue("-pkcs11TokenName");
			string pkcs11LibraryPath = paramCtrl.getParameterValue("-pkcs11LibraryPath");
			string pkcs11TokenPin = paramCtrl.getParameterValue("-pkcs11Pin");
			string pkcs11KeyStorePassword = paramCtrl.getParameterValue("-pkcs11KeyStorePassword");
			string pkcs11SearchKeyword = paramCtrl.getParameterValue("-pkcs11SearchKeyword");

			//TimeStamp URL
			TimeStampType timeStampingType;
			if (paramCtrl.getParameterValue("-timeStampType") != null)
            {
				timeStampingType = (TimeStampType)Enum.Parse(typeof(TimeStampType), paramCtrl.getParameterValue("-timeStampType"));
			} else
            {
				// If timestamp type was not input then set to COMPUTER_CLOCK
				timeStampingType = TimeStampType.COMPUTER_CLOCK;
			}

			TSAAuthenticationType tsaAuthenticationType = TSAAuthenticationType.NO_AUTHENTICATION;
			if (paramCtrl.getParameterValue("-tsaAuthenticationType") != null)
			{
				switch (paramCtrl.getParameterValue("-tsaAuthenticationType"))
				{
					case "NO_AUTHENTICATION":
						tsaAuthenticationType = TSAAuthenticationType.NO_AUTHENTICATION;
						break;
					case "USERNAME_PASSWORD":
						tsaAuthenticationType = TSAAuthenticationType.USERNAME_PASSWORD;
						break;
					case "CERTIFICATE":
						tsaAuthenticationType = TSAAuthenticationType.CERTIFICATE;
						break;
				}
			}
			//TSAAuthenticationType tsaAuthenticationType = (TSAAuthenticationType)(paramCtrl.getParameterValue("-tsaAuthenticationType") != null ? Enum.Parse(typeof(TSAAuthenticationType), paramCtrl.getParameterValue("-tsaAuthenticationType")) : null);
			string tsaURL = paramCtrl.getParameterValue("-tsaURL");
			string tsaUsername = paramCtrl.getParameterValue("-tsaUsername");
			string tsaPassword = paramCtrl.getParameterValue("-tsaPassword");
			string tsaPKCS12File = paramCtrl.getParameterValue("-tsaPKCS12File");
			string tsaPKCS12Password = paramCtrl.getParameterValue("-tsaPKCS12Password");
			TimeStamp timeStamping;
			if (timeStampingType == TimeStampType.TSA)
			{
				switch (tsaAuthenticationType)
				{
					case TSAAuthenticationType.NO_AUTHENTICATION:
						timeStamping = new TimeStamp()
						{
							TimeStampType = timeStampingType,
							URL = tsaURL,
							TSAAuthenticationType = tsaAuthenticationType
						};
						break;
					case TSAAuthenticationType.USERNAME_PASSWORD:
						timeStamping = new TimeStamp()
						{
							TimeStampType = timeStampingType,
							URL = tsaURL,
							TSAAuthenticationType = tsaAuthenticationType,
							Username = tsaUsername,
							Password = tsaPassword
						};
						break;
					case TSAAuthenticationType.CERTIFICATE:
						timeStamping = new TimeStamp()
						{
							TimeStampType = timeStampingType,
							URL = tsaURL,
							TSAAuthenticationType = tsaAuthenticationType,
							CertificatePath = tsaPKCS12File,
							Password = tsaPKCS12Password
						};
						break;
					default:
						throw new Exception("TSA authentication must be input");
				}
			}
			else if (timeStampingType == TimeStampType.COMPUTER_CLOCK)
			{
				timeStamping = new TimeStamp()
				{
					TimeStampType = timeStampingType
				};
			}
			else
			{
				timeStamping = new TimeStamp()
				{
					TimeStampType = timeStampingType
				};
			}

			//Other sign parameter
			DigestAlgorithm digestAlgorithm = (DigestAlgorithm)(paramCtrl.getParameterValue("-digestAlgorithm") != null ? Enum.Parse(typeof(DigestAlgorithm), paramCtrl.getParameterValue("-digestAlgorithm")) : null);
			string signLevel = paramCtrl.getParameterValue("-signLevel");

			//PKCS
			PKCS12Instance pkcs12 = null;
			PKCS11Instance pkcs11 = null;

			if (pkcs12FilePath != null && pkcs12Password != null)
			{
				pkcs12 = new PKCS12Instance()
				{
					FilePath = pkcs12FilePath,
					KeyStorePassword = pkcs12Password
				};
			}
			//else if (pkcs11TokenName != null && pkcs11LibraryPath != null && pkcs11TokenPin != null && pkcs11KeyStorePassword != null && pkcs11SearchKeyword != null)
			else if (pkcs11TokenPin != null && pkcs11KeyStorePassword != null && pkcs11SearchKeyword != null)
			{
				pkcs11 = new PKCS11Instance()
				{
					TokenName = pkcs11TokenName,
					Pin = pkcs11TokenPin,
					KeyStorePassword = pkcs11KeyStorePassword,
					SearchPhase = pkcs11SearchKeyword
				};
            }
            else if (selfSelectCert != null && selfSelectCert.Equals("TRUE", StringComparison.InvariantCultureIgnoreCase))
            {

            }
            else
			{
				throw new Exception("Incomplete certificate input");
			}

			//Let's sign
			XAdESSigner padesSigner = new XAdESSigner();
			if (signType.Equals("single", StringComparison.InvariantCultureIgnoreCase))
			{
				if (pkcs12 != null)
				{
					if (signLevel.Equals("BES", StringComparison.InvariantCultureIgnoreCase))
                    {
						(new XAdESSigner()).SignBESOnce(inputFile, outputFile, pkcs12,
							digestAlgorithm, SignaturePackaging.ENVELOPED, null);
					} 
					else if (signLevel.Equals("T", StringComparison.InvariantCultureIgnoreCase))
                    {
						(new XAdESSigner()).SignTOnce(inputFile, outputFile, pkcs12,
							digestAlgorithm, SignaturePackaging.ENVELOPED, null, timeStamping);
					}
				}
				else if ((pkcs11 != null))
				{
					if (signLevel.Equals("BES", StringComparison.InvariantCultureIgnoreCase))
					{
						(new XAdESSigner()).SignBESOnce(inputFile, outputFile, pkcs11,
							digestAlgorithm, SignaturePackaging.ENVELOPED, null);
					}
					else if (signLevel.Equals("T", StringComparison.InvariantCultureIgnoreCase))
					{
						(new XAdESSigner()).SignTOnce(inputFile, outputFile, pkcs11,
							digestAlgorithm, SignaturePackaging.ENVELOPED, null, timeStamping);
					}
				}else
				{
					if (signLevel.Equals("BES", StringComparison.InvariantCultureIgnoreCase))
					{
						(new XAdESSigner()).SignBESOnce(inputFile, outputFile, null,
							digestAlgorithm, SignaturePackaging.ENVELOPED, null);
					}
					else if (signLevel.Equals("T", StringComparison.InvariantCultureIgnoreCase))
					{
						(new XAdESSigner()).SignTOnce(inputFile, outputFile, null,
							digestAlgorithm, SignaturePackaging.ENVELOPED, null, timeStamping);
					}
				}
			}
			else if (signType.Equals("multiple", StringComparison.InvariantCultureIgnoreCase))
			{
				if (pkcs12 != null)
				{
					if (signLevel.Equals("BES", StringComparison.InvariantCultureIgnoreCase))
					{
						(new XAdESSigner()).SignBESMultiple(inputFolder, outputFolder, outputSuffix, pkcs12,
							digestAlgorithm, SignaturePackaging.ENVELOPED, null);
					}
					else if (signLevel.Equals("T", StringComparison.InvariantCultureIgnoreCase))
					{
						(new XAdESSigner()).SignTMultiple(inputFolder, outputFolder, outputSuffix, pkcs12,
							digestAlgorithm, SignaturePackaging.ENVELOPED, null, timeStamping);
					}
				}
				else if ((pkcs11 != null))
				{
					if (signLevel.Equals("BES", StringComparison.InvariantCultureIgnoreCase))
					{
						(new XAdESSigner()).SignBESMultiple(inputFolder, outputFolder, outputSuffix, pkcs11,
							digestAlgorithm, SignaturePackaging.ENVELOPED, null);
					}
					else if (signLevel.Equals("T", StringComparison.InvariantCultureIgnoreCase))
					{
						(new XAdESSigner()).SignTMultiple(inputFolder, outputFolder, outputSuffix, pkcs11,
							digestAlgorithm, SignaturePackaging.ENVELOPED, null, timeStamping);
					}
                }
                else
				{
					if (signLevel.Equals("BES", StringComparison.InvariantCultureIgnoreCase))
					{
						(new XAdESSigner()).SignBESMultiple(inputFolder, outputFolder, outputSuffix, null,
							digestAlgorithm, SignaturePackaging.ENVELOPED, null);
					}
					else if (signLevel.Equals("T", StringComparison.InvariantCultureIgnoreCase))
					{
						(new XAdESSigner()).SignTMultiple(inputFolder, outputFolder, outputSuffix, null,
							digestAlgorithm, SignaturePackaging.ENVELOPED, null, timeStamping);
					}
				}
			}
			else
			{
				throw new Exception("Sign type must be 'single' or 'multiple only'");
			}

			Console.WriteLine("Complete");
		}
	}
}
