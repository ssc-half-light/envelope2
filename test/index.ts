import { test } from '@socketsupply/tapzero'
import { create as createId, Identity } from '@ssc-hermes/identity'
import { createCryptoComponent } from '@ssc-hermes/node-components'
import * as ed from '@noble/ed25519'
import serialize from 'json-canon'
import { fromString } from 'uint8arrays'
import { Crypto } from '@oddjs/odd'
import {
    create as createEnvelope,
    Envelope,
    // wrapMessage,
    arrFromString,
    sealEnvelope,
    EncryptedContent,
    decryptMessage,
    EnvelopedMessage
} from '../dist/index.js'
import { create as createMsg } from '@ssc-hermes/message'

let alicesEnvelope:Envelope
let alice:Identity
let alicesCrypto:Crypto.Implementation
// let bob:Identity
// let bobsCrypto
const bobsCrypto = await createCryptoComponent()
const bob = await createId(bobsCrypto, { humanName: 'bob' })

test('create an envelope to alice', async t => {
    alicesCrypto = await createCryptoComponent()
    alice = await createId(alicesCrypto, { humanName: 'alice' })
    alicesEnvelope = await createEnvelope(alicesCrypto, {
        envelopeUser: bob,
        username: alice.username,
        seq: 0
    })

    t.ok(alicesEnvelope.signature, 'should create an envelope')
    t.equal(alicesEnvelope.recipient, alice.username,
        "alice's username should be on the envelope")
})

// let alicesKeys:Record<string, string>
let msgContent:EncryptedContent
let envelopedMsg:EnvelopedMessage
// let bob:Identity

test('bob puts a message in the envelope to alice', async t => {
    // bobsCrypto = await createCryptoComponent()
    // bob = await createId(bobsCrypto, { humanName: 'bob' })

    const content = await createMsg(bobsCrypto, {
        from: { username: bob.username },
        text: 'hello'
    })

    // console.log('***content***', content)

    // const [
    //     { envelope: returnedEnvelope, message },  // the encrypted message content
    //     keys  // map of sender's device name to encrypted key string
    // ] = await wrapMessage(bob, alice, alicesEnvelope, content)

    envelopedMsg = await sealEnvelope(bob, alice, alicesEnvelope, content, {
        crypto: bobsCrypto
    })

    const { message } = envelopedMsg
    msgContent = message

    t.ok(envelopedMsg, 'should return the envelope')
    t.ok(envelopedMsg.signature, 'should have a signature on the envelope')
    // t.equal(envelopedMsg.signature, alicesEnvelope.signature,
    //     'the envelope we get back shoud be equal to what was passed in')
    // t.ok(message, 'should return the encrypted content')
    // t.ok(keys, 'should return keys')

    // console.log('**msg**', message)
})

test('an anonymous node can verify the message is ok', async t => {
    const msg = fromString(serialize(msgContent), 'utf8')
    const sig = fromString(envelopedMsg.signature, 'base64pad')
    const pubKey = arrFromString(envelopedMsg.envelopeKey)
    // const isValid = await ed.verifyAsync(signature, message, pubKey);
    const isOk = await ed.verifyAsync(sig, msg, pubKey)
    t.equal(isOk, true, 'should verify a valid envelope')
})

test('alice can decrypt a message addressed to alice', async t => {
    const decrypted = await decryptMessage(alicesCrypto, msgContent)
    console.log('***decrypted***', decrypted)
    t.equal(decrypted.from.username, bob.username,
        "should have bob's username in decrypted message")
    t.equal(decrypted.text, 'hello', 'should have the original text of the message')
})

test("carol cannot read alice's message", async t => {
    const carolsCrypto = await createCryptoComponent()
    try {
        await decryptMessage(carolsCrypto, msgContent)
        t.fail('should throw with the wrong keys')
    } catch (err) {
        t.ok(err, 'should throw if we use the wrong keys')
    }
})
