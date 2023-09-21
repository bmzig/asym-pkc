# Rivest-Shamir-Aldeman (RSA) Cryptography
[RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) is the first modern cryptographic scheme. Being the first modern cryptographic scheme, it suffers many potential weaknesses. In this implementation, I require you to choose your own prime numbers, as I only verify that they are in fact prime, as well as your own public-key exponent. Given the difficult nature of generating secure RSA keys, I have opted to move those algorithms to later on the to-do list. As with the other encryption schemes in this repository, this is a barebones implementation meant for unimportant message transmission (although you could technically use it properly for secure data transfers). The production-quality schemes will be in their own dedicated repository. 

# Important Algorithms

Obviously, I require that the user simply types in two primes instead of the program generating cryptographically secure keys. This is because it is much more difficult to actually verify the "difficulty" of cracking a given product of two primes. I do, however, plan on implmenenting [Pollard's Algorithm](https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm) and some checks from [Fermat's Little Theorem](https://en.wikipedia.org/wiki/Fermat%27s_little_theorem) eventually. 

As for making your own primes, I'd suggest getting familiar with the [Sieve of Eratosthenes](https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes) and reading [A Tale of Two Sieves](https://www.ams.org/notices/199612/pomerance.pdf) by Pomerance. Basically, use a quadratic sieve or a number field sieve to ensure that your secret keys p and q's respective (p-1) and (q-1) cannot be sieved into small prime factors. 

It would also be nice to make an algorithm which calculates whether a not a number is B-smooth given an input and a target B, but these are currently TODO. 
