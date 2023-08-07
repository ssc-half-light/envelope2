# envelope2 ![tests](https://github.com/ssc-hermes/envelope/actions/workflows/nodejs.yml/badge.svg)

Private messages that hide the identity of the sender, but leave the recipient of the message visible. That way the messages do not reveal metadata of who is talking to whom, but the recipient is still visible, which allows us to index messages by recipient. That way Alice can write a query like *show me any private messages addressed to Alice*.

Message content is e2e encrypted thanks to a [keystore](https://github.com/fission-codes/keystore-idb) module that lets us store non-extractable keys on the client machines.

-------

__the idea__
Create an 'envelope' that is certified by the adressee.

Alice wants to send a message to Bob.

Bob has already given Alice a *send certificate*, or *envelope*, which is a message signed by Bob that includes a single-use keypair.

In order to send Bob a message, the message must be signed by the private side of the keypair in Bob's send certificate.

Any nodes that relay a message to Bob will look at the envelope carrying the message, and check that it is signed by a keypair that Bob created. How do they know that the keypair was created by Bob? Because the *public* side of the keypair is visible publicly on the envelope, and the envelope is signed by Bob. The *private* side of the keypair must be given secretly to people who Bob wants to hear from.

In practical terms, that means that the *private* side could be encrypted *to* Alice. Alice then decrypts the *private* key, and uses it to sign the envelope. Anyone who receives the envelope is then able to check that the signature & public key are valid together.

-------

This hides information of *who is talking to whom*. A relaying node would be able to see that a message is for Bob, but the *sender* of the message could be encrypted within the message content, so the relay is not able to see *who* is sending the message to Bob.

-------

A nice thing is that anyone can validate an envelope. You don't need to know anything about who created the message or envelope, you can still check that the signature matches the public key in the envelope.

```js
import { checkEnvelope } from '@ssc-hermes/envelope2'

test('envelope.checkEnvelope', async t => {
    const isOk = await checkEnvelope(envelopedMsg)
    t.equal(isOk, true, 'should validate a valid envelop')
})
```
