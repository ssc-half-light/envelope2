# envelope2 ![tests](https://github.com/ssc-hermes/envelope/actions/workflows/nodejs.yml/badge.svg)

Private messages that hide the identity of the sender.

-------

Alice wants to send a message to Bob.

Bob has already given Alice a *send certificate* or *envelope*, which is a message signed by Bob that includes a single-use keypair.

In order to send Bob a message, the message must be signed by the private side of the keypair in Bob's send certificate.

Any nodes that relay a message to Bob will look at the envelope carrying the message, and check that it is signed by a keypair that Bob created. How do they know that the keypair was created by Bob? Because the *public* side of the keypair is visible publicly on the envelope. The *private* side of the keypair must be given secretly to people who Bob wants to hear from.

The envelope is signed by Bob also, so we are able to verify that Bob created the envelope, and the keypair contained within.

In practical terms, that means that the *private* side would be encrypted *to* Alice. Alice then decrypts the *private* key, and uses it to sign the envelope. Anyone who receives the envelope is then able to check that the signature & public key are valid together.

-------

This hides the information of *who is talking to whom*. A relaying node would be able to see that a message is for Bob, but the *sender* of the message could be encrypted within the message content, so the relay is not able to see *who* is sending the message to Bob.
