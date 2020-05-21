/*
 * Name: Harsh Tagotra 
 * Email: hxt1965@rit.edu
 * Date: 4/17/20
 */

using System;
using System.Numerics;
using System.IO;
using System.Threading;
using System.Text;
using System.Threading.Tasks;
using BigIntegerExtension;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Diagnostics;
using Newtonsoft.Json.Linq;
using System.Collections;
using Newtonsoft.Json;

namespace Messenger
{
    class MessengerMain
    {
        private static MessengerOptions msgOptions = new MessengerOptions();
        private static HttpClient client = new HttpClient();
        private static MessengerMain mainObj = new MessengerMain();
        //private string serverLink = "kayrun.cs.rit.edu";
        //private int port = 5000;
        
        /// <summary>
        /// Parsing arguments in this function and calling functions according to the
        /// arguments passed in command line 
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        public static async Task Main(string[] args)
        {
            
            if (args.Length < 2)
            {
                Console.WriteLine("Invalid Input! Format is...\ndotnet run <option> <other arguments>");
                mainObj.showHelp();
                return;
            }
            if(string.Equals(args[0], "keyGen"))
            {
                try
                {
                    var keySize = args[1];
                    mainObj.KeyGen(Int32.Parse(keySize));
                } catch (FormatException )
                {
                    Console.WriteLine("Invalid keysize!");
                    mainObj.showHelp();
                }
            } 
            else if(string.Equals("sendKey", args[0]))
            {
                
                await mainObj.SendKey(args[1], client);
                
            }
            else if (string.Equals("getKey", args[0]))
            {
                
                await mainObj.GetKey(args[1], client);
                
            }
            else if (string.Equals("sendMsg", args[0]))
            {
                try
                {
                    await mainObj.SendMsg(args[1], args[2]);
                }
                catch (IndexOutOfRangeException)
                {
                    Console.WriteLine("Plaintext message is missing!");
                }
            }
            else if (string.Equals("getMsg", args[0]))
            {
                await mainObj.GetMsg(args[1], client);
            }
        }

        /// <summary>
        /// Helper function to display valid command line arguments 
        /// </summary>
        private void showHelp()
        {
            Console.WriteLine("\nValid arguments and options are:-");
            Console.WriteLine("\nkeyGen <keysize>");
            Console.WriteLine("sendKey <email>");
            Console.WriteLine("getKey <email>");
            Console.WriteLine("sendMsg <email> <plaintext>");
            Console.WriteLine("getMsg <email>");
        }

        /// <summary>
        ///  
        /// Checks the server for a public key that it can later use for decryption.
        /// This key is specific to a user who has posted it online. 
        /// 
        /// </summary>
        /// <param name="email">User from whom to get the key</param>
        /// <param name="httpClient">HttpClient object to facilitate connections</param>
        /// <returns></returns>
        private async Task GetKey(string email, HttpClient httpClient)
        {
            
            string responseBody = "";
            try
            {
                // GET request, returns a JSON object containing an email address and an encoded key
                var response = await httpClient.GetAsync("http://kayrun.cs.rit.edu:5000/Key/"+email);
                responseBody = await response.Content.ReadAsStringAsync();
                JObject jsonKey = JObject.Parse(responseBody);
                
                //extract Key from JSON object and convert into byte array
                var keyEncoded = (string) jsonKey["key"];
                byte[] keyBytes = Convert.FromBase64String(keyEncoded);

                //The next part follows the RSA Key format to extract values of e, E, n and N
                var eSize = new byte[4];
                for(var i = 0; i<4; i++)
                    eSize[i] = keyBytes[i];

                if (BitConverter.IsLittleEndian)
                    Array.Reverse(eSize);
                var e = BitConverter.ToInt32(eSize, 0);
                
                var bytes = new byte[e];
                for (var i = 4; i<(4 + e); i++)
                    bytes[i-4] = keyBytes[i];
                BigInteger E = new BigInteger(bytes);
                
                var nSize = new byte[4];
                for (var i = 4 + e; i < 4 + e + 4; i++)
                {
                    //Console.WriteLine(keyBytes[i]);
                    nSize[i - 4 - e] = keyBytes[i];
                }

                if (BitConverter.IsLittleEndian)
                    Array.Reverse(nSize);
                var n = BitConverter.ToInt32(nSize, 0);
                var nBytes = new byte[n];
                for (var i = 0; i < n; i++)
                    nBytes[i] = keyBytes[i + 4 + e + 4];
                BigInteger N = new BigInteger(nBytes);
                

                //Now that the key has been received, combine all byte arrays and 
                // store it in a file after Base64Encoding it.
                var publicKeyList = new List<byte[]>();
                publicKeyList.Add(eSize);
                publicKeyList.Add(bytes);
                publicKeyList.Add(nSize);
                publicKeyList.Add(nBytes);
                var publicKeyArray = publicKeyList.SelectMany(a => a).ToArray();
                var publicKey = Convert.ToBase64String(publicKeyArray);
                
                var filename = email + ".key";
                var pos = Directory.GetCurrentDirectory().LastIndexOf("\\");
                var path = Directory.GetCurrentDirectory().Substring(0, pos) +"\\"+filename;
                File.WriteAllText(path, publicKey);
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine(e.Message);
            }
        }

        /// <summary>
        /// This function generates a pair of public and private keys by following the 
        /// steps to come up with values for p, q, N, r, E and D and combining them to 
        /// make the respective keys. 
        /// </summary>
        /// <param name="keySize">Bit size of keys to be generated </param>
        private void KeyGen(int keySize)
        {
            
            BigInteger p = msgOptions.Generate(keySize, 1);
            BigInteger q = msgOptions.Generate(1024 - keySize, 1);
            BigInteger N = BigInteger.Multiply(p, q);
            BigInteger r = BigInteger.Multiply(BigInteger.Subtract
                (p, 1), BigInteger.Subtract(q, 1));
            BigInteger E = 65537;
            BigInteger D = PrimeCheckExtension.modInverse(E, r);

            var eBytes = E.ToByteArray();
            var nBytes = N.ToByteArray();
            var dBytes = D.ToByteArray();

            var eByteLength = eBytes.Length;
            var nByteLength = nBytes.Length;
            var dByteLength = dBytes.Length;
            var eByteSize = BitConverter.GetBytes(eByteLength);
            var nByteSize = BitConverter.GetBytes(nByteLength);
            var dByteSize = BitConverter.GetBytes(dByteLength);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(eByteSize);
                Array.Reverse(nByteSize);
                Array.Reverse(dByteSize);
            }

            var publicKeyList = new List<byte[]>();
            var privateKeyList = new List<byte[]>();

            publicKeyList.Add(eByteSize);
            publicKeyList.Add(eBytes);
            publicKeyList.Add(nByteSize);
            publicKeyList.Add(nBytes);

            privateKeyList.Add(dByteSize);
            privateKeyList.Add(dBytes);
            privateKeyList.Add(nByteSize);
            privateKeyList.Add(nBytes);

            var publicKeyArray = publicKeyList.SelectMany(a => a).ToArray();
            var privateKeyArray = privateKeyList.SelectMany(a => a).ToArray();

            var privateKey = Convert.ToBase64String(privateKeyArray);
            var publicKey = Convert.ToBase64String(publicKeyArray);


            //Write these Base64 encoded files to disk 
            var pos = Directory.GetCurrentDirectory().LastIndexOf("\\");
            var pvtPath = Directory.GetCurrentDirectory().Substring(0, pos)+"\\private.key";
            var pubPath = Directory.GetCurrentDirectory().Substring(0, pos)+"\\public.key";
            var pvtPathJson = Directory.GetCurrentDirectory().Substring(0, pos) + "\\private.txt";
            var pubPathJson = Directory.GetCurrentDirectory().Substring(0, pos) + "\\public.txt";
            //Console.WriteLine(pvtPath);

            KeyMessage pvtKeyObj = new KeyMessage();
            KeyMessage pubKeyObj = new KeyMessage();
            pvtKeyObj.email = new List<string>();
            pubKeyObj.email = new List<string>();
            pvtKeyObj.key = privateKey;
            pubKeyObj.key = publicKey;
            var pvtJsonObj = JObject.FromObject(pvtKeyObj);
            var pubJsonObj = JObject.FromObject(pubKeyObj);

            //Console.WriteLine("Generating public key...\n" + pubJsonObj.ToString());
            //Console.WriteLine("Generating private key ... \n" + pvtJsonObj.ToString());
            File.WriteAllText(pvtPath, privateKey);
            File.WriteAllText(pubPath, publicKey);
            File.WriteAllText(pvtPathJson, pvtJsonObj.ToString());
            File.WriteAllText(pubPathJson, pubJsonObj.ToString());
        }
        

        /// <summary>
        /// Sends the public key to the servers for others to access 
        /// </summary>
        /// <param name="email">Email of user</param>
        /// <param name="client">HttpClient object </param>
        /// <returns></returns>
        private async Task SendKey(string email, HttpClient client)
        {
            try
            {
                //Read key from local file
                var pos = Directory.GetCurrentDirectory().LastIndexOf("\\");
                var jsonTxt = File.ReadAllText(Directory.GetCurrentDirectory().Substring(0, pos)+"\\public.txt");
                var pvtJsonTxt = File.ReadAllText(Directory.GetCurrentDirectory().Substring(0, pos) + "\\private.txt");
                
                
                var keyObj = JsonConvert.DeserializeObject<KeyMessage>(pvtJsonTxt);
                keyObj.email.Add(email);
                var jsonObj = JObject.FromObject(keyObj);
                File.WriteAllText(Directory.GetCurrentDirectory().Substring(0, pos) + "\\private.txt", jsonObj.ToString());

                //Create a KeyMessage JSON Object 
                var pubKeyObj = JsonConvert.DeserializeObject<KeyMessage>(jsonTxt);
                var sendKey = new PutKeyMessage();
                sendKey.email = email;
                sendKey.key = pubKeyObj.key;
                var sendKeyObj = JObject.FromObject(sendKey);

                //PUT request 
                var content = new StringContent(sendKeyObj.ToString(), Encoding.UTF8, "application/json");
                var response = await client.PutAsync("http://kayrun.cs.rit.edu:5000/Key/" + email, content);
                if (response.IsSuccessStatusCode)
                    Console.WriteLine("Key Saved");
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("Exception!\n" + e.Message);
            }
            catch(FileNotFoundException)
            {
                Console.WriteLine("Key does not exist!");
            }

        }

        /// <summary>
        /// Sends a message to a specific user on the server 
        /// </summary>
        /// <param name="email">Email of user </param>
        /// <param name="plaintext">Text message to be sent </param>
        /// <returns></returns>
        private async Task SendMsg(string email, string plaintext)
        {
            try
            {
                //Check if we have the public key on our disk
                var pos = Directory.GetCurrentDirectory().LastIndexOf("\\");
                var filename = Directory.GetCurrentDirectory().Substring(0, pos) + "\\"+email + ".key";
                if (!File.Exists(filename))
                    Console.WriteLine("Key does not exist for " + email + "\n");
                else
                {
                    //encide text message and decrypt using RSA formula 
                    var textBytes = Encoding.ASCII.GetBytes(plaintext);
                    var bigInt = new BigInteger(textBytes);
                    var key = File.ReadAllText(filename);
                    
                    //e, E, n, N extraction 
                    byte[] keyBytes = Convert.FromBase64String(key);
                    var eSize = new byte[4];
                    for (var i = 0; i < 4; i++)
                        eSize[i] = keyBytes[i];
                    //if (BitConverter.IsLittleEndian)
                    //    Array.Reverse(eSize);
                    var e = BitConverter.ToInt32(eSize, 0);
                    var bytes = new byte[e];
                    for (var i = 4; i < (4 + e); i++)
                        bytes[i - 4] = keyBytes[i];
                    BigInteger E = new BigInteger(bytes);
                    var nSize = new byte[4];
                    for (var i = 4 + e; i < 4 + e + 4; i++)
                        nSize[i - 4 - e] = keyBytes[i];
                    //if (BitConverter.IsLittleEndian)
                    //    Array.Reverse(nSize);
                    var n = BitConverter.ToInt32(nSize, 0);
                    var nBytes = new byte[n];
                    for (var i = 0; i < n; i++)
                        nBytes[i] = keyBytes[i + 4 + e + 4];
                    BigInteger N = new BigInteger(nBytes);

                    //Final decryption of text 
                    var cipher = BigInteger.ModPow(bigInt, E, N);
                    var cipherArray = cipher.ToByteArray();
                    var message = Convert.ToBase64String(cipherArray);
                    var textObj = new TextMessage();
                    textObj.email = email;
                    textObj.content = message;
                    var jsonText = JObject.FromObject(textObj);

                    //PUT request sends a JSON object 
                    var content = new StringContent(jsonText.ToString(), Encoding.UTF8, "application/json");
                    var response = await client.PutAsync("http://kayrun.cs.rit.edu:5000/Message/" + email, content);
                    if (!response.IsSuccessStatusCode)
                        Console.WriteLine("Unable to send Message");
                    else
                        Console.WriteLine("Message written");
                }
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("exception!\n" + e.Message);
            }
        }

        /// <summary>
        /// This method attempts to receive and decrypt a message from a specific 
        /// user from the server 
        /// </summary>
        /// <param name="email">Email of the user sending the message</param>
        /// <param name="client">HTTPClient object </param>
        /// <returns></returns>
        private async Task GetMsg(string email, HttpClient client)
        {
            try
            {
                //Extract private key from local file 
                var pos = Directory.GetCurrentDirectory().LastIndexOf("\\");
                var filename = Directory.GetCurrentDirectory().Substring(0, pos) +"\\"+"private.key";
                var jsonTxt = File.ReadAllText(filename);
                
                var key = jsonTxt;
                var response = await client.GetAsync("http://kayrun.cs.rit.edu:5000/Message/" + email);
                string responseBody = await response.Content.ReadAsStringAsync();
                JObject jsonKey = JObject.Parse(responseBody);
                
                //After receiving encoded message, attempt to decrypt by extracting 
                // values of C, D and N 
                var msgEncoded = (string)jsonKey["content"];
                byte[] msgBytes = Encoding.UTF8.GetBytes(msgEncoded);
                BigInteger C = new BigInteger(msgBytes);

                byte[] keyBytes = Convert.FromBase64String(key);
                var dSize = new byte[4];
                for (var i = 0; i < 4; i++)
                    dSize[i] = keyBytes[i];
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(dSize);
                var d = BitConverter.ToInt32(dSize, 0);
                var bytes = new byte[d];
                for (var i = 4; i < (4 + d); i++)
                {
                    //Console.WriteLine(i);
                    bytes[i - 4] = keyBytes[i];
                }
                BigInteger D = new BigInteger(bytes);
                var nSize = new byte[4];
                for (var i = 4 + d; i < 4 + d + 4; i++)
                    nSize[i - 4 - d] = keyBytes[i];
               if (BitConverter.IsLittleEndian)
                    Array.Reverse(nSize);
                var n = BitConverter.ToInt32(nSize, 0);
                var nBytes = new byte[n];
                for (var i = 0; i < n; i++)
                    nBytes[i] = keyBytes[i + 4 + d + 4];
                BigInteger N = new BigInteger(nBytes);

                BigInteger Pl = BigInteger.ModPow(C, D, N);
                var plainBytes = Pl.ToByteArray();
                var plainText = Convert.ToBase64String(plainBytes) ;
                Console.WriteLine(plainText);
                
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("exception!\n" + e.Message);
            }
        }
    }

    //JSON Objects declared for Serializing and Deserializng 
    public class KeyMessage
    {
        public List<string> email { get; set;  }
        public string key { get; set; }
    }

    public class PutKeyMessage
    {
        public string email { get; set; }
        public string key { get; set; }
    }

    public class TextMessage
    {
        
        public string email { get; set;  }
        public string content { get; set; }
    }
}
