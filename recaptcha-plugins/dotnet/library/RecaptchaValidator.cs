// Copyright (c) 2007 Adrian Godong, Ben Maurer
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web;
using System.Web.Script.Serialization;
using System.Collections.Generic;
using System.Collections;

namespace Recaptcha
{
    /// <summary>
    /// Calls the reCAPTCHA server to validate the answer to a reCAPTCHA challenge. Normally,
    /// you will use the RecaptchaControl class to insert a web control on your page. However
    /// </summary>
    public class RecaptchaValidator
    {

        // https://developers.google.com/recaptcha/docs/verify
        private const string VerifyUrl = "https://www.google.com/recaptcha/api/siteverify";
        // Recaptcha response properties
        private const string Success = "success";
        private const string ChallengeTimeStamp = "challenge_ts";
        private const string Hostname = "hostname";
        private const string ErrorCodes = "error-codes";

        private string privateKey;
        private string remoteIp;

        private string response;

        private IWebProxy proxy;

        public string PrivateKey
        {
            get { return this.privateKey; }
            set { this.privateKey = value; }
        }

        public string RemoteIP
        {
            get
            {
                return this.remoteIp;
            }

            set
            {
                IPAddress ip = IPAddress.Parse(value);

                if (ip == null ||
                    (ip.AddressFamily != AddressFamily.InterNetwork &&
                    ip.AddressFamily != AddressFamily.InterNetworkV6))
                {
                    throw new ArgumentException("Expecting an IP address, got " + ip);
                }

                this.remoteIp = ip.ToString();
            }
        }

        public string Response
        {
            get { return this.response; }
            set { this.response = value; }
        }

        public IWebProxy Proxy
        {
            get { return this.proxy; }
            set { this.proxy = value; }
        }

        private void CheckNotNull(object obj, string name)
        {
            if (obj == null)
            {
                throw new ArgumentNullException(name);
            }
        }

        public RecaptchaResponse Validate()
        {
            this.CheckNotNull(this.PrivateKey, "PrivateKey");
            this.CheckNotNull(this.RemoteIP, "RemoteIp");
            this.CheckNotNull(this.Response, "Response");

            if (this.response == string.Empty)
            {
                return RecaptchaResponse.InvalidSolution;
            }

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(VerifyUrl);
            request.ProtocolVersion = HttpVersion.Version10;
            request.Timeout = 30 * 1000 /* 30 seconds */;
            request.Method = "POST";
            request.UserAgent = "reCAPTCHA/ASP.NET";
            if (this.proxy != null)
            {
                request.Proxy = this.proxy;
            }

            request.ContentType = "application/x-www-form-urlencoded";

            string formdata = String.Format(
                "secret={0}&response={1}&remoteip={2}",
                                    HttpUtility.UrlEncode(this.PrivateKey),
                                    HttpUtility.UrlEncode(this.Response),
                                    HttpUtility.UrlEncode(this.RemoteIP));

            byte[] formbytes = Encoding.ASCII.GetBytes(formdata);

            using (Stream requestStream = request.GetRequestStream())
            {
                requestStream.Write(formbytes, 0, formbytes.Length);
            }

            Dictionary<String, Object> results = null;

            try
            {
                using (WebResponse httpResponse = request.GetResponse())
                {
                    using (TextReader readStream = new StreamReader(httpResponse.GetResponseStream(), Encoding.UTF8))
                    {
                        String jsonResult = readStream.ReadToEnd();
                        JavaScriptSerializer JavaScriptSerializer = new JavaScriptSerializer();
                        results = JavaScriptSerializer.Deserialize<Dictionary<String, Object>>(jsonResult);
                    }
                }
            }
            catch (WebException ex)
            {
                EventLog.WriteEntry("Application", ex.Message, EventLogEntryType.Error);
                return RecaptchaResponse.RecaptchaNotReachable;
            }
            // TODO: Handle stream exceptions or deserialize exceptions

            RecaptchaResponse result = null;
            // Assuming there was no exception above - results should be a valid Dictionary (not null)
            if (results != null) {
                // The dictionary should always contain a Success property.
                if (results.ContainsKey(Success)) {
                    Object objSuccess = results[Success];
                    if (objSuccess is Boolean) {
                        Boolean success = (Boolean) objSuccess;
                        if (success) {
                            result = RecaptchaResponse.Valid;
                        }
                    }
                }
                // If there was no success field, or it wasn't a boolean, or it was false - extract the ErrorCodes (assuming they exist)
                if (result == null && results.ContainsKey(ErrorCodes)) {
                    Object objErrorCodes = results[ErrorCodes];
                    if (objErrorCodes is ArrayList) {
                        ArrayList errorCodes = (ArrayList)objErrorCodes;
                        if (errorCodes.Count > 0) {
                            String firstErrorCode = (String)errorCodes[0];
                            result = new RecaptchaResponse(false, firstErrorCode);
                        }
                    }
                }
            }
            
            // At this point, result should either refer to a valid response, or an invalid one with an error code.
            // Anything else (other than server being unreachable) is completely unexpected (and an exception is warranted).
            if (result == null)
            {
                    throw new InvalidProgramException("Unknown status response.");
            }

            return result;
        }
    }
}
