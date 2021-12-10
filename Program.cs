using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using java.security;
using java.io;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Threading.Tasks;
using java.util;
using RestSharp;
using System.Web.Script.Serialization;
using Newtonsoft.Json;

namespace KCBfIleencryption
{
    
        class Program
        {
            static string KCBRESPONSE = null;
            static string CheckSumResponse = null;
            static void Main(string[] args)
            {

                string fileName = @"C:\Users\Administrator\Downloads\krcsconstitution.pdf";
                var fileStream = new FileStream(fileName, FileMode.OpenOrCreate, FileAccess.Read);
                var systemCode = "REDCROSS";
                var conversationId = "REDCROSS12";
                var serviceId = "REDCROSS";
                string dataString = GetChecksumBuffered(fileStream);
                try
                {
                    // Create a UnicodeEncoder to convert between byte array and string.
                    ASCIIEncoding ByteConverter = new ASCIIEncoding();
                    byte[] originalData = ByteConverter.GetBytes(dataString);
                    byte[] signedData;
                    RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
                    RSAParameters Key = RSAalg.ExportParameters(true);
                    RSAParameters PublicKey = RSAalg.ExportParameters(false);

                    // Hash and sign the data.
                    signedData = HashAndSignBytes(originalData, Key);
                    string base64 = Convert.ToBase64String(signedData, 0, signedData.Length);

                    //coverting private key to string
                    string privKey;
                    {
                        //we need some buffer
                        var sw = new System.IO.StringWriter();
                        //we need a serializer
                        var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                        //serialize the key into the stream
                        xs.Serialize(sw, Key);
                        //get the string from the stream
                        privKey = sw.ToString();
                    }
                    string pubKey;
                    {
                        //we need some buffer
                        var sw = new System.IO.StringWriter();
                        //we need a serializer
                        var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                        //serialize the key into the stream
                        xs.Serialize(sw, PublicKey);
                        //get the string from the stream
                        pubKey = sw.ToString();
                    }
                    string checksum = Encoding.Default.GetString(originalData);

                    var sender = SendChecksum(checksum, base64, serviceId, systemCode, conversationId, fileName);

                    //Gpg gpg = new Gpg();

                    //gpg.Recipient = "myfriend@domain.com";
                    FileStream sourceFile = new FileStream(@"c:\temp\source.txt", FileMode.Open);
                    FileStream outputFile = new FileStream(@"c:\temp\output.txt", FileMode.Create);

                    // encrypt the data using IO Streams 




                    // Verify the data and display the result to the console.
                    if (VerifySignedHash(originalData, signedData, Key))
                    {
                        //System.Console.WriteLine("Original Data: " + Encoding.Default.GetString(originalData));
                        //System.Console.WriteLine("Private Key: " + privKey);
                        //System.Console.WriteLine("Public Key: " + pubKey);
                        //System.Console.WriteLine("Signed data: " + Encoding.Default.GetString(signedData));
                        //System.Console.WriteLine("Signed data: " + base64);
                        //System.Console.WriteLine("The data was verified.");
                        System.Console.ReadLine();
                    }

                    else
                    {
                        System.Console.WriteLine("The data does not match the signature.");
                        System.Console.ReadLine();
                    }
                }
                catch (ArgumentNullException)
                {
                    System.Console.WriteLine("The data was not signed or verified");
                    System.Console.ReadLine();
                }


            }
            public static byte[] HashAndSignBytes(byte[] DataToSign, RSAParameters Key)

            {
                try
                {
                    RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                    RSAalg.ImportParameters(Key);

                    // Hash and sign the data. Pass a new instance of SHA256 to specify the hashing algorithm.
                    return RSAalg.SignData(DataToSign, SHA256.Create());
                }
                catch (CryptographicException e)
                {
                    System.Console.WriteLine(e.Message);

                    return null;
                }
            }
            public static bool VerifySignedHash(byte[] DataToVerify, byte[] SignedData, RSAParameters Key)
            {
                try
                {
                    // Create a new instance of RSACryptoServiceProvider using the key from RSAParameters.
                    RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                    RSAalg.ImportParameters(Key);

                    // Verify the data using the signature.  Pass a new instance of SHA256
                    // to specify the hashing algorithm.
                    return RSAalg.VerifyData(DataToVerify, SHA256.Create(), SignedData);
                }
                catch (CryptographicException e)
                {
                    //Console..WriteLine(e.Message);

                    return false;
                }
            }
            private static string GetChecksumBuffered(Stream stream)
            {
                using (var bufferedStream = new BufferedStream(stream, 1024 * 32))
                {
                    var sha = new SHA256Managed();
                    byte[] checksum = sha.ComputeHash(bufferedStream);
                    return BitConverter.ToString(checksum).Replace("-", String.Empty);

                }
            }
            //Get token from KCB
            public static string Gettoken()
            {
                string Username = "REDCROSS101";
                string Password = "1520Suspect6?";
                string svcCredentials = Convert.ToBase64String(ASCIIEncoding.ASCII.GetBytes(Username + ":" + Password));
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                string auth = "Basic " + svcCredentials;

                var client = new RestClient("https://196.216.223.2:4450/kcb/payments/auth/v1");
                client.Timeout = -1;
                var request = new RestRequest(Method.POST);
                request.AddHeader("Content-Type", "application/json");
                request.AddHeader("Authorization", "Basic UkVEQ1JPU1MxMDE6MTUyMFN1c3BlY3Q2Pw==");
                IRestResponse response = client.Execute(request);
                KCBRESPONSE = response.Content;
            System.Console.WriteLine(response.Content);

                TokenResponse AccessTokenRequestResponse = JsonConvert.DeserializeObject<TokenResponse>(KCBRESPONSE);
                var Accesstoken = AccessTokenRequestResponse.access_token;

                return Accesstoken;
            }
            // send Signed Check sum
            public static string SendChecksum(string checksum, string signature, string serviceId, string systemCode, string conversationId, string fileName)
            {

                string token = Gettoken();
                token = "Bearer " + token;

                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                var bodyRequest = new Sendchecksum
                {
                    header = new Header
                    {
                        conversationId = conversationId,
                        serviceId = serviceId,
                        systemCode = systemCode
                    },
                    payload = new Payload
                    {
                        fileName = fileName,
                        checksum = checksum,
                        signature = signature

                    }

                };

                JavaScriptSerializer js = new JavaScriptSerializer();
                string body = js.Serialize(bodyRequest);

                var client = new RestClient("https://196.216.223.2:4450/kcb/payments/validation/v1");
                client.Timeout = -1;
                var request = new RestRequest(Method.POST);
                request.AddHeader("Accept", "application/json");
                request.AddHeader("Content-Type", "application/json");
                request.AddHeader("Authorization", token);
                //request.AddHeader("Authorization", "Bearer RVhsYXh6d3RtYUlTZnd6bnNrc2M9PVFRV3BDRWI2SzZXMzBMK294RFZIZTFlYjlwZndPb2hZelRBcXUvK05nNzhQQ24wMXVxU3pPNFBSQlRTdFhVdGJZeW01STRIQUlKb0MxazlPRjZUQ1Z2YVByZlRUYU9aaVh4anZ4bmROU3o");           
                request.AddParameter("application/json", body, ParameterType.RequestBody);
                IRestResponse response = client.Execute(request);
                CheckSumResponse = response.Content;
            System.Console.WriteLine(response.Content);

                checksumresponseBody RequestResponse = JsonConvert.DeserializeObject<checksumresponseBody>(CheckSumResponse);
                var status = RequestResponse.status;
                var description = RequestResponse.description;
                var ConversationId = RequestResponse.conversationId;
                var FileName = RequestResponse.fileName;
                var originatorConversationId = RequestResponse.originatorConversationId;
                var Status = RequestResponse.status;
                var submissionDate = RequestResponse.submissionDate;
                var totalFailed = RequestResponse.totalFailed;
                var totalNumberInFile = RequestResponse.totalNumberInFile;
                var totalSuccess = RequestResponse.totalSuccess;
                var transactionDate = RequestResponse.transactionDate;

                return description;
            }
        }
        public class TokenResponse
        {
            public string access_token { get; set; }
            public string expires_in { get; set; }
            public string refresh_token { get; set; }
            public string token_type { get; set; }
            public string scope { get; set; }
        }
        public class checksumresponseBody
        {
            public int status { get; set; }
            public string description { get; set; }
            public string conversationId { get; set; }
            public string originatorConversationId { get; set; }
            public string fileName { get; set; }
            public DateTime transactionDate { get; set; }
            public DateTime submissionDate { get; set; }
            public int totalNumberInFile { get; set; }
            public int totalSuccess { get; set; }
            public int totalFailed { get; set; }

        }
        public class Sendchecksum
        {
            public Header header { get; set; }
            public Payload payload { get; set; }
        }
        public class Header
        {
            public string conversationId { get; set; }
            public string serviceId { get; set; }
            public string systemCode { get; set; }


        }
        public class Payload
        {
            public string checksum { get; set; }
            public string signature { get; set; }
            public string fileName { get; set; }


        }
    
}
