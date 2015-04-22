# crypto-assignment1 / Kryptographische Protokolle / Tag 1:
==============================================================

Die Aufgabenstellung für den ersten Tag war folgende Funktionen zu implementieren.

  - RSA Ver-/Entschlüsselung sowie Schlüsselgenerierung
  - ECC skalare Multiplikation
  - DSA Signaturgenerierung/-verifizierung
  - Hashen von beliebigen Texten mit beliebigen Funktionen
  - X.509v3 Zertifikate lesen/generieren/verifizieren
  - Client/Server Architektur

Dafür wurde ein Java-Programm Namens Crypto geschrieben, dass die geforderten Funktionen erfüllt. Nachfolgend ist aufgelistet, wie das Programm zu benutzen ist:


```
Usage: crypto command [sub-command] [args]                  
                                                            
Command may be one of the following:                        
 hash, ecc, cert, rsa, dsa, network                         
                                                            
Complete list of commands, sub-commands and options:        
  hash:                                                     
     [function] [input-text]                                
       - function can any function that is supported by Java (ex. MD5, SHA-1, SHA-256)
                                                            
  rsa:                                                      
     generate-keys [key-prefix]                             
       - generates rsa keys and saves them in files named prefix.*.key
     encrypt [key-prefix] [input]                           
       - encrypts the given input using the keys specified by key-prefix (you must run generate-keys first)
     decrypt [key-prefix] [input]                           
       - decrypts the given input using the keys specified by key-prefix (you must run generate-keys first)
                                                            
  cert:                                                     
     read [cert-file]                                       
       - reads a certificate and prints some information    
     verify [ca-file] [cert-file]                           
       - verifies if the certificate is derived from the specified CA certificate
                                                            
  dsa:                                                      
     generate-keys [key-prefix]                             
       - generates dsa keys and save them in files named dsa.prefix.*.key
     sign [key-prefix] [input]                              
       - signs the input message with the keys specified by input
     verify [key-prefix] [r] [s] [input]                    
       - verifies that the signature specified by r and s matches to the input message
                                                            
  network:                                                  
     server [port]                                          
       - starts a network hashing service; hashes incoming hashes and sends them back 
     client [address] [port]                                
       - client for the hashing service                     
                                                            
  ecc:                                                      
     p192 [k]                                               
       - calculates point R on the NIST Curve P192          

```

Nachfolgend sind einige Aufrufe exemplarisch gelistet:

 - um die Hash-Funktion aufzurufen: # java crypto.Crypto hash SHA-1 FH-Campus-Wien-ITS16  

 - um den Server zu starten:        # java crypto.Crypto network server 1234 

 - um den Cient zu starten:         # java crypto.Crypto network client localhost 1234  


