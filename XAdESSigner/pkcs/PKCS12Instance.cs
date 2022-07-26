namespace pkcs
{
	class PKCS12Instance : IPKCSInstance
	{
		public string FilePath { get; set; }
		public string KeyStorePassword { get; set; }
	}
}
