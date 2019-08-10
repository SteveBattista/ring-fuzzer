[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
<BR>
Built with:<BR>
Built with untrusted = "0.6.2"  - Using "0.7.0" causes errors<BR>
Built with ring = "0.16.5"<BR>


Not testing:<BR>
1. The writing of PKS8 files to disk. Just keeping them in memory.<BR>
2. Does not test nonce advance as we want to try an unlimited number of attempts. Uses less_safe_key in aead.<BR>

3. RSA signatures: Ring does not have a rust function to generate primes. This is because there is a lot of risk in picking improper primes. For more information read this blog post https://blog.trailofbits.com/2019/07/08/fuck-rsa/ <BR>

4. When performing hashes (digest), we used the two step method of adding context.update(data)

Might Impact Outcome:<BR>
In aead nonce is first 12 bytes of the key.<BR>

zero length in random1 or random2 can cause crashes. (PBKDF2 needs non zero values). <BR>
