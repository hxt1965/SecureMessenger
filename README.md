# SecureMessenger

A secure message generator that uses the RSA encryption and decryption algorithm the encode and decode messages and send them over a server.

The general algorithm is described as follows :

```
N = p * q
r = (p - 1) * (q - 1) 
E = a prime number
D = modInverse(E, r)
```

Where p and q are prime numbers whose bit sizes add up to 1024 (for example 508 and 516). 

These large prime numbers are generated through parallel computing for efficiency, and the C# class **BigInteger** is used for further computation. 
For a Plain text message converted to a BitArray, the Ciphertext (encoded message can be obtained by)
**C = P^e mod N**

See the [writeup](https://github.com/hxt1965/SecureMessenger/blob/master/Secure_Messaging%20(2).pdf) for more details on how to run this project 
