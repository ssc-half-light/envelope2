import { create as createMsg, SignedRequest } from '@ssc-hermes/message'
import { fromString, toString } from 'uint8arrays'
import { Crypto } from '@oddjs/odd'
import { SymmAlg } from 'keystore-idb/types.js'
import { writeKeyToDid } from '@ssc-hermes/util'
import * as ed from '@noble/ed25519'
import {
    aesGenKey,
    aesEncrypt,
    aesDecrypt,
} from '@oddjs/odd/components/crypto/implementation/browser'
import { Identity, encryptKey, createDeviceName } from '@ssc-hermes/identity'
import serialize from 'json-canon'

// map of device name to encrypted key string
type Keys = Record<string, string>

// {
//     seq: 0,
//     expiration: '456',
//     recipient: 'my-identity',
//     signature: '123abc',
//     author: 'did:key:abc'
// }

export const ALGORITHM = SymmAlg.AES_GCM

interface UnsignedEnvelope {
    seq:number,
    expiration:number,
    publicKey:string,  // ed25519 public key, encoded as base64pad
    recipient:string,  // the recipient's username (the person creating the envelope)
    encrypted?:{ key:Keys, content:string }  /* can include a private key,
        encrypted to someone. `content` is the encrypted private key */
}

/**
 * An 'envelope'
 * Can include an 'encrypted' portion, which would include the private side
 *   of the given public key. In this case, the envelope would be for a specific
 *   person who is able to decrypt it.
 */
export type Envelope = SignedRequest<UnsignedEnvelope>

type Content = SignedRequest<{
    from:{ username:string },
    text:string,
    mentions?:string[],
}>

export interface EncryptedContent {
    key:Record<string, string>,  // { deviceName: 'encrypted-key' }
    content:string
}

export interface EnvelopedMessage {
    message:EncryptedContent,
    signature:string,
    envelopeKey:string
}

/**
 * Put a message into the envelope. This means use the corresponding private key
 *   to sign the given message.
 *
 * You must get the private key somehow. One option is to pass in the envelope
 * user when you create the envelope. In which case the corresponding private
 * key will be encrypted to the envelope user and embedded with the envelope.
 * @param me Your identity
 * @param recipient The recipient, because we need to encrypt data *to* them.
 * @param envelope The envelope you are putting a message into
 * @param content The content you are putting into the envelope
 * @param {{ crypto?, privKey? }} opts A crypto or private key to use to sign
 * the envelope. If `privKey` is omitted, then you must pass a `crypto` instance,
 * so you can decrypt the embedded private key
 * @returns {{ message, signature, envelopeKey }} The sealed envelope is the
 * message along with a signature produced by the envelope's private key. You
 * would verify the return signature is ok with the `envelopeKey` and the
 * `message`.
 */
export async function sealEnvelope (
    recipient:Identity,
    envelope:Envelope,
    content:Content,
    { crypto, privKey }:{ crypto?:Crypto.Implementation, privKey?:string }
):Promise<EnvelopedMessage> {
    const key = await aesGenKey(ALGORITHM)
    const encryptedContent = await encryptContent(key, serialize(content),
        recipient)

    const contentForSigning:Uint8Array = fromString(serialize(encryptedContent),
        'utf8')

    let _privKey

    // if not passed in, the priv key should be embedded in the envelope
    if (!privKey) {
        if (!crypto) throw new Error('not crypto and not privKey')
        if (!envelope.encrypted) throw new Error('not privKey and not encrypted')
        _privKey = await getKeyFromEnvelope(crypto, envelope.encrypted)
    }

    const signature = await ed.signAsync(
        contentForSigning,
        (privKey ? arrFromString(privKey) : _privKey)
    )

    return {
        message: encryptedContent,
        signature: toString(signature, 'base64pad'),
        envelopeKey: envelope.publicKey
    }
}

export async function checkEnvelope (envelopedMsg:EnvelopedMessage)
:Promise<boolean> {
    const { message } = envelopedMsg
    const msg = fromString(serialize(message), 'utf8')
    const sig = fromString(envelopedMsg.signature, 'base64pad')
    const pubKey = arrFromString(envelopedMsg.envelopeKey)

    return ed.verifyAsync(sig, msg, pubKey)
}

// /**
//  * Encrypt a string and put it into an envelope. The envelope tells us who the
//  * recipient of the message is; the message sender is hidden.
//  * @param me Your Identity.
//  * @param recipient The identity of the recipient, because we need to encrypt
//  * the message to the recipient.
//  * @param envelope The envelope we are putting it in
//  * @param content The content that will be encrypted to the recipient
//  * @returns [message, <sender's keys>]
//  * Return an array of [message, keys], where keys is a map of the sender's devices
//  * to the symmetric key encrypted to that device. This is returned as a seperate
//  * object because we *don't* want the sender device names to be in the message.
//  */
// export async function wrapMessage (
//     me:Identity,
//     recipient:Identity,  // because we need to encrypt the message to the recipient
//     envelope:Envelope,
//     content:Content
// ):Promise<[{
//     envelope:Envelope,
//     message:EncryptedContent
// }, Keys]> {
//     // encrypt the content *to* the recipient,

//     // create a key
//     const key = await aesGenKey(ALGORITHM)
//     // encrypt the key to the recipient,
//     // also encrypt the content with the key
//     const encryptedContent = await encryptContent(key, serialize(content),
//         recipient)

//     return [
//         {
//             envelope,
//             message: encryptedContent,
//         },
//         await encryptKeys(me, key)]
// }

/**
 * Get a private key that is embedded in the envelope. That means this envelope
 * was created specifically for you.
 * @param crypto
 * @param param1
 * @returns {Promise<Uint8Array>}
 */
async function getKeyFromEnvelope (
    crypto:Crypto.Implementation,
    { key, content }:{ key:Keys, content:string }  // <- envelope.encrypted
):Promise<Uint8Array> {
    const did = await writeKeyToDid(crypto)
    const deviceName = await createDeviceName(did)
    const encryptedKey = key[deviceName]
    const decryptedKey = await crypto.keystore.decrypt(
        fromString(encryptedKey, 'base64pad')
    )

    const decrypted = await aesDecrypt(
        fromString(content, 'base64pad'),
        decryptedKey,
        ALGORITHM
    )

    const { privateKey } = (JSON.parse(new TextDecoder().decode(decrypted)))
    return arrFromString(privateKey)
}

export async function decryptMessage (
    crypto:Crypto.Implementation,
    msg:EncryptedContent
):Promise<Content> {
    const did = await writeKeyToDid(crypto)
    const deviceName = await createDeviceName(did)
    const encryptedKey = msg.key[deviceName]
    const decryptedKey = await crypto.keystore.decrypt(
        fromString(encryptedKey, 'base64pad')
    )

    const decrypted = await aesDecrypt(
        fromString(msg.content, 'base64pad'),
        decryptedKey,
        ALGORITHM
    )

    return (JSON.parse(new TextDecoder().decode(decrypted)))
}

/**
 * Create an envelope -- a certificate. Return a signed certificate object
 * @param crypto odd crypto object
 * @param {{ username:string, seq:number, expiration?:number }} opts
 *   username: your username (the recipient)
 *   seq: an always incrementing integer
 *   expiration: timestamp to expire, default is 1 year from now
 * the sequence number to use for this envelope
 * @returns {Promise<Envelope>} A serializable certificate
 */
export async function create (crypto:Crypto.Implementation, {
    envelopeUser,  // who will be using this envelope
    username,
    seq,
    // expire 1 year from now by default
    expiration = new Date().setFullYear(new Date().getFullYear() + 1)
}:{
    envelopeUser?:Identity,
    username:string,
    seq:number,
    expiration?:number
}):Promise<Envelope> {
    const privKey = ed.utils.randomPrivateKey()
    const pubKey = await ed.getPublicKeyAsync(privKey)
    const pubKeyStr = toString(pubKey, 'base64pad')

    const preEnvelope:UnsignedEnvelope = {
        seq,
        expiration,
        publicKey: pubKeyStr,
        recipient: username  // our username goes on the envelope
    }
    if (envelopeUser) {
        // if we know who will be using this envelope,
        // then encrypt the corresponding private key to them
        const aesKey = await aesGenKey(ALGORITHM)
        preEnvelope.encrypted = await encryptContent(aesKey, serialize({
            privateKey: toString(privKey, 'base64pad')
        }), envelopeUser)
    }

    const envelope = await createMsg(crypto, preEnvelope)
    return envelope
}

/**
 * Take data in string format, and encrypt it with the given symmetric key.
 * @param key The symmetric key used to encrypt/decrypt
 * @param data The text to encrypt
 * @param recipient The `Identity` redord for the recipient.
 * @returns {Promise<{ key:Keys, content:string }>}
 */
export async function encryptContent (
    key:CryptoKey,
    data:string,
    recipient:Identity
):Promise<{ key:Keys, content:string }> {
    const encrypted = arrToString(await aesEncrypt(
        new TextEncoder().encode(data.normalize()),
        key,
        ALGORITHM
    ))

    const encryptedKeys = await encryptKeys(recipient, key)

    return {
        key: encryptedKeys,
        content: encrypted
    }
}

/**
 * Take a given AES key and encrypt it to all the devices in the given identity.
 * @param id The identity we are encrypting to
 * @param key The AES key we are encrypting
 * @returns {Record<string, string>}
 */
async function encryptKeys (id:Identity, key:CryptoKey):
Promise<Keys> {
    const encryptedKeys = {}
    for await (const deviceName of Object.keys(id.devices)) {
        const exchange = id.devices[deviceName].exchange
        encryptedKeys[deviceName] = await encryptKey(key, arrFromString(exchange))
    }

    return encryptedKeys
}

export function arrFromString (str:string) {
    return fromString(str, 'base64pad')
}

export function arrToString (arr:Uint8Array) {
    return toString(arr, 'base64pad')
}
