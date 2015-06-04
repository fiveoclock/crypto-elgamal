# crypto-assignment / Kryptographische Protokolle / Tag 4 / Elgamal:
==============================================================

Die Aufgabenstellung war das Elgamal Signaturverfahren zu implementieren. Folgende Funktionen wurden implementiert:

  - Schlüsselgenerierung
  - Ver-/Entschlüsselung
  - Signierung von Nachrichten
  - Verifizierung von Signaturen

Darauf aufbauend wurden folgende Anwendungen mittels Elgamal implementiert:
  - Challenge/Response Authentifizierungsverfahren
  - Telnet Service, das Signieren und Verifizieren von Nachrichten ermöglicht


Das Programm wurde in Java geschrieben. Nachfolgend ist aufgelistet, wie das Programm zu benutzen ist:


```
# java crypto.Crypto     
Usage: crypto command [sub-command] [args]                  
                                                            
  elgamal:                                                  
     generate-keys [key-prefix]                             
       - generates elgamal keys and saves them in files named elgamal.[prefix].key
                                                            
     sign [key-prefix] [input]                              
       - signs the input message with the keys specified by input 
     verify [key-prefix] [r] [s] [input]                    
       - verifies that the signature specified by r and s matches to the input message
                                                            
     auth-server [port]                                     
       - starts a challenge/response server for authenticating users 
     auth-client [host] [port] [username]                   
       - starts a challenge/response client that authenticates against the server 
                                                            
     telnet-server [key-prefix] [port]                      
       - starts a server that allows signing of messages and verification of signatures
     telnet-client [host] [port] [message]                    
       - starts an automated telnet client that signes the specified message and verifies the resulting signature
                                                            
     encrypt [key-prefix] [input]                           
       - encrypts the given input using the keys specified by key-prefix
     decrypt [key-prefix] [input]                           
       - decrypts the given input using the keys specified by key-prefix

```

Nachfolgend sind einige Aufrufe exemplarisch gelistet:

 - um eine Nachricht zu signieren:  # java crypto.Crypto elgamal sign campus "hallo hallo"

 - um den Auth-Server zu starten:   # java crypto.Crypto elgamal auth-server 1234

 - um den Auth-Cient zu starten:    # java crypto.Crypto elgamal auth-client localhost 1234 campus


