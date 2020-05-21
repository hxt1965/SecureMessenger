/**
 * Name: Harsh Tagotra (hxt1965)
 */

using System;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using BigIntegerExtension;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Diagnostics;

namespace Messenger
{
    class MessengerOptions
    {
        private static object myLock = new object();


        public BigInteger KeyGen(int keySize)
        {
            return 0;
        }

        public void SendKey(string email)
        {

        }

        public void SendMsg(string email, string plaintext)
        {

        }

        public string GetMsg(string email)
        {
            return null;
        }

        

        /// <summary>
        /// A parallel foreach loop instantiates a BigInteger using the RNGCryptoServiceProvider. 
        /// This function also uses the isProbablyPrime() function from the PrimeCheckExtension class. 
        /// Parallel options has been used to modify how the ForEach loop runs and doesnt crash due to running 
        /// out of memory. For every BigInteger, it is checked for prime and once the number of primes found is 
        /// equal to the required number (count), the process is terminated.
        /// </summary>
        /// <param name="bits">BitLength of the numbers to be checked</param>
        /// <param name="count">The number of prime numbers to be generated</param>
        public BigInteger Generate(int bits, int count)
        {
            CancellationTokenSource cts = new CancellationTokenSource();
            ParallelOptions po = new ParallelOptions();

            // to avoid running out of memory 
            po.MaxDegreeOfParallelism = 20;
            // to facilitate termination of all threads if the condition (required number of primes)
            // has been met 
            po.CancellationToken = cts.Token;
            BigInteger primeNum = 0;
            //counter for number of primes found. Will be compared to [count] to check if requirement has been met 
            var cnt = 0;

            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();

            // to run maximum number of threads possible. The code crashes (runs out of memory)
            // in the case of 
            List<int> thread_ids = Enumerable.Range(1, Int16.MaxValue).ToList();
            try
            {
                Parallel.ForEach(thread_ids, po, (id, state) =>
                {
                    //instantiation of BigInteger 
                    var byteArray = new byte[(bits / 8)];
                    provider.GetBytes(byteArray);
                    BigInteger bigNum = new BigInteger(byteArray);

                    // if bigInteger generated is negative 
                    if (bigNum < 0)
                        bigNum *= -1;

                    var isPrime = PrimeCheckExtension.IsProbablyPrime(bigNum);


                    //Making updation of counter and printing thread safe 
                    lock (myLock)
                    {
                        if (isPrime)
                        {
                            primeNum = bigNum;
                            cnt = cnt + 1;
                            //To terminate all OTHER threads if the required number of threads has been reached  
                            cts.Token.ThrowIfCancellationRequested();

                            //Printing prime numbers as they are found
                            //Console.WriteLine("\n{0}: {1}", cnt, bigNum);



                            if (cnt == count)
                                cts.Cancel();
                        }
                    }


                });
            }
            catch (OperationCanceledException)
            {
                //Console.WriteLine("Wooho ");
                //return 0;
                return primeNum;
            }
            return primeNum;
        }
    }
}
