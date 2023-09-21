# Elgamal Digital Signature Algorithm 

This implementation is evidently similar to the original Elgamal code. Digital Signatures are arguably just as (if not more) important than message encryption. We can utilize the hash (such as sha256 or md5) of a file to digitally "sign" it with our private key, all while making it very difficult to figure out what the private key actually is. Pretty cool, huh?

You use this program by taking the hash of a specific document and generating a private key (just a number) between 1 and 2^252 + 27742317777372353535851937790883648493 (a variety of options thanks to ed25519). You first derive a public key, then you sign your document with the private key, then you can publish your signatures on the internet and everybody will know that the owner of your public key (whoever that might be, anon!) has verified the authenticity of the document.
