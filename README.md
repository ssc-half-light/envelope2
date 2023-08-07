# envelope2 ![tests](https://github.com/ssc-hermes/envelope/actions/workflows/nodejs.yml/badge.svg)

Private messages that hide the identity of the sender, but leave the recipient of the message visible. That way the messages do not reveal metadata of who is talking to whom, but the recipient is still visible, which allows us to index messages by recipient. That way Alice can write a query like *show me any private messages addressed to Alice*.

Message content is e2e encrypted thanks to a [keystore](https://github.com/fission-codes/keystore-idb) module that lets us store non-extractable keys on the client machines.

-------

## the idea
Create an 'envelope' that is certified by the addressee.

Alice wants to send a message to Bob.

Bob has already given Alice a *send certificate*, or *envelope*, which is a message signed by Bob that includes a single-use keypair.

In order to send Bob a message, the message must be signed by the private side of the keypair in Bob's send certificate.

Any nodes that relay a message to Bob will look at the envelope carrying the message, and check that it is signed by a keypair that Bob created. How do they know that the keypair was created by Bob? Because the *public* side of the keypair is visible publicly on the envelope, and the envelope is signed by Bob. The *private* side of the keypair must be given secretly to people who Bob wants to hear from.

In practical terms, that means that the *private* side could be encrypted *to* Alice. Alice then decrypts the *private* key, and uses it to sign the envelope. Anyone who receives the envelope is then able to check that the signature & public key are valid together.

Thinking about a social network, this means that a server would be able to see that Alice has gotten a message from someone they gave out an envelope to, nothing else. The server can not even determine the *set* of people that Alice has given envelopes to, because Alice could give out envelopes by a variety of means, like on their website, or via text message.

### keypair vs signature
This decoupling of messages from our application is made possilbe by including a single-use keypair in the envelope. For a different version, see [@ssc-hermes/envelope](https://github.com/ssc-hermes/envelope). There the envelope is just a signed certificate, which means that Alice would need to know ahead of time *who* they are expecting to receive messages from. Meaning you would only give out envelopes to people with a pre-existing account in the network.

In this version, Alice doesn't need to know who they gave out an envelope to, but they can be sure that the message is legitimate. So, for example, Alice could give out an envelope to someone who doesn't yet have an account, then get a message after the new person has created an account.

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
