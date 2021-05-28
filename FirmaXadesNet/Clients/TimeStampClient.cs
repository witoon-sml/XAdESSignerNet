// --------------------------------------------------------------------------------------------------------------------
// TimeStampClient.cs
//
// FirmaXadesNet - Librería para la generación de firmas XADES
// Copyright (C) 2016 Dpto. de Nuevas Tecnologías de la Dirección General de Urbanismo del Ayto. de Cartagena
//
// This program is free software: you can redistribute it and/or modify
// it under the +terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/. 
//
// E-Mail: informatica@gemuc.es
// 
// --------------------------------------------------------------------------------------------------------------------

using FirmaXadesNet.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FirmaXadesNet.Clients
{
    public class TimeStampClient : ITimeStampClient
    {
        #region Private variables
        private string _url;
        private string _user;
        private string _password;
        private string _certificatefile;
        private string _certificatepass;
        private bool _tsawithcer;

        #endregion

        #region Constructors

        public TimeStampClient()
        {

        }

        public TimeStampClient(string url)
        {
            _url = url;
        }

        public TimeStampClient(string url, string user, string password)
            : this(url)
        {
            _user = user;
            _password = password;
        }

        public TimeStampClient(string url, string certificatefile, string certificatepass, bool tsawithcer)
            : this(url)
        {
            _certificatefile = certificatefile;
            _certificatepass = certificatepass;
            _tsawithcer = tsawithcer;

        }


        #endregion

        #region Public methods

        /// <summary>
        /// Realiza la petición de sellado del hash que se pasa como parametro y devuelve la
        /// respuesta del servidor.
        /// </summary>
        /// <param name="hash"></param>
        /// <param name="digestMethod"></param>
        /// <param name="certReq"></param>
        /// <returns></returns>
        public byte[] GetTimeStamp(byte[] hash, DigestMethod digestMethod, bool certReq)
        {
            
            TimeStampRequestGenerator tsrq = new TimeStampRequestGenerator();
            tsrq.SetCertReq(certReq);

            BigInteger nonce = BigInteger.ValueOf(DateTime.Now.Ticks);

            TimeStampRequest tsr = tsrq.Generate(digestMethod.Oid, hash, nonce);
            byte[] requestBytes = tsr.GetEncoded();

            HttpWebRequest con = (HttpWebRequest)WebRequest.Create(_url);
            con.Method = "POST";
            con.ContentType = "application/timestamp-query";
            con.ContentLength = requestBytes.Length;

            if (!string.IsNullOrEmpty(_user) && !string.IsNullOrEmpty(_password))
            {
                string auth = string.Format("{0}:{1}", _user, _password);
                con.Headers["Authorization"] = "Basic " + Convert.ToBase64String(Encoding.Default.GetBytes(auth), Base64FormattingOptions.None);
            }
            else if ((_certificatefile != null) && !_certificatefile.Equals(""))
            {
                X509Certificate2Collection certificates = new X509Certificate2Collection();
                certificates.Import(_certificatefile, _certificatepass, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
                con.ClientCertificates = certificates;
                con.ContentLength = requestBytes.Length;
            }

            Stream outp = con.GetRequestStream();
            outp.Write(requestBytes, 0, requestBytes.Length);
            outp.Close();
            HttpWebResponse response = (HttpWebResponse)con.GetResponse();
            if (response.StatusCode != HttpStatusCode.OK)
                throw new IOException();
            Stream inp = response.GetResponseStream();

            MemoryStream baos = new MemoryStream();
            byte[] buffer = new byte[1024];
            int bytesRead = 0;
            while ((bytesRead = inp.Read(buffer, 0, buffer.Length)) > 0)


            {

                baos.Write(buffer, 0, bytesRead);
            }
            inp.Close();
            response.Close();
            byte[] respBytes = baos.ToArray();

            String encoding = response.ContentEncoding;
            if (encoding != null)
            {
                try
                {
                    byte[] test = Convert.FromBase64String(encoding);
                    //respBytes = Convert.FromBase64String(Encoding.ASCII.GetString(respBytes));
                }
                catch (Exception)
                {
                    
                }
            }
            return respBytes;
            
        }

        #endregion
            
    }
}
