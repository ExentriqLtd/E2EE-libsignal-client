//Necessario compilare i file ts in js e utilizzare le classi per restituire su talk le varie chiavi 
/** source/server.ts */
import http from 'http';
import express, { Express } from 'express';
import morgan from 'morgan';
import routes from './routes/api';

const router: Express = express();

/** Logging */
router.use(morgan('dev'));
/** Parse the request */
router.use(express.urlencoded({ extended: false }));
/** Takes care of JSON data */
router.use(express.json());

/** RULES OF OUR API */
router.use((req, res, next) => {
    // set the CORS policy
    res.header('Access-Control-Allow-Origin', '*');
    // set the CORS headers
    res.header('Access-Control-Allow-Headers', 'origin, X-Requested-With,Content-Type,Accept, Authorization');
    // set the CORS method headers
    if (req.method === 'OPTIONS') {
        res.header('Access-Control-Allow-Methods', 'GET PATCH DELETE POST');
        return res.status(200).json({});
    }
    next();
});

/** Routes */
router.use('/', routes);

/** Error handling */
router.use((req, res, next) => {
    const error = new Error('not found');
    return res.status(404).json({
        message: error.message
    });
});

/** Server */
const httpServer = http.createServer(router);
const PORT: any = process.env.PORT ?? 6060;
httpServer.listen(PORT, () => console.log(`The server is running on port ${PORT}`));

// Importazione di PublicAPI

//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, use } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as SignalClient from '../index';

use(chaiAsPromised);


SignalClient.initLogger(
    SignalClient.LogLevel.Trace,
    (level, target, fileOrNull, lineOrNull, message) => {
        const targetPrefix = target ? '[' + target + '] ' : '';
        const file = fileOrNull ?? '<unknown>';
        const line = lineOrNull ?? 0;
        // eslint-disable-next-line no-console
        console.log(targetPrefix + file + ':' + line + ': ' + message);
    }
);

class InMemorySessionStore extends SignalClient.SessionStore {
    private state = new Map<string, Buffer>();
    async saveSession(
        name: SignalClient.ProtocolAddress,
        record: SignalClient.SessionRecord
    ): Promise<void> {
        const idx = name.name() + '::' + name.deviceId();
        Promise.resolve(this.state.set(idx, record.serialize()));
    }
    async getSession(
        name: SignalClient.ProtocolAddress
    ): Promise<SignalClient.SessionRecord | null> {
        const idx = name.name() + '::' + name.deviceId();
        const serialized = this.state.get(idx);
        if (serialized) {
            return Promise.resolve(
                SignalClient.SessionRecord.deserialize(serialized)
            );
        } else {
            return Promise.resolve(null);
        }
    }
    async getExistingSessions(
        addresses: SignalClient.ProtocolAddress[]
    ): Promise<SignalClient.SessionRecord[]> {
        return addresses.map(address => {
            const idx = address.name() + '::' + address.deviceId();
            const serialized = this.state.get(idx);
            if (!serialized) {
                throw 'no session for ' + idx;
            }
            return SignalClient.SessionRecord.deserialize(serialized);
        });
    }
}

class InMemoryIdentityKeyStore extends SignalClient.IdentityKeyStore {
    private idKeys = new Map();
    private localRegistrationId: number;
    private identityKey: SignalClient.PrivateKey;

    constructor() {
        super();
        this.identityKey = SignalClient.PrivateKey.generate(); 
        this.localRegistrationId = 5; //Verrà generato random con la libreria crypto
    }

    async getIdentityKey(): Promise<SignalClient.PrivateKey> {
        return Promise.resolve(this.identityKey);
    }
    async getLocalRegistrationId(): Promise<number> {
        return Promise.resolve(this.localRegistrationId);
    }

    async isTrustedIdentity(
        name: SignalClient.ProtocolAddress,
        key: SignalClient.PublicKey,
        _direction: SignalClient.Direction
    ): Promise<boolean> {
        const idx = name.name() + '::' + name.deviceId();
        if (this.idKeys.has(idx)) {
            const currentKey = this.idKeys.get(idx);
            return Promise.resolve(currentKey.compare(key) == 0);
        } else {
            return Promise.resolve(true);
        }
    }

    async saveIdentity(
        name: SignalClient.ProtocolAddress,
        key: SignalClient.PublicKey
    ): Promise<boolean> {
        const idx = name.name() + '::' + name.deviceId();
        const seen = this.idKeys.has(idx);
        if (seen) {
            const currentKey = this.idKeys.get(idx);
            const changed = currentKey.compare(key) != 0;
            this.idKeys.set(idx, key);
            return Promise.resolve(changed);
        }

        this.idKeys.set(idx, key);
        return Promise.resolve(false);
    }
    async getIdentity(
        name: SignalClient.ProtocolAddress
    ): Promise<SignalClient.PublicKey | null> {
        const idx = name.name() + '::' + name.deviceId();
        if (this.idKeys.has(idx)) {
            return Promise.resolve(this.idKeys.get(idx));
        } else {
            return Promise.resolve(null);
        }
    }
}

class InMemoryPreKeyStore extends SignalClient.PreKeyStore {
    private state = new Map();
    async savePreKey(
        id: number,
        record: SignalClient.PreKeyRecord
    ): Promise<void> {
        Promise.resolve(this.state.set(id, record.serialize()));
    }
    async getPreKey(id: number): Promise<SignalClient.PreKeyRecord> {
        return Promise.resolve(
            SignalClient.PreKeyRecord.deserialize(this.state.get(id))
        );
    }
    async removePreKey(id: number): Promise<void> {
        this.state.delete(id);
        return Promise.resolve();
    }
}

class InMemorySignedPreKeyStore extends SignalClient.SignedPreKeyStore {
    private state = new Map();
    async saveSignedPreKey(
        id: number,
        record: SignalClient.SignedPreKeyRecord
    ): Promise<void> {
        Promise.resolve(this.state.set(id, record.serialize()));
    }
    async getSignedPreKey(id: number): Promise<SignalClient.SignedPreKeyRecord> {
        return Promise.resolve(
            SignalClient.SignedPreKeyRecord.deserialize(this.state.get(id))
        );
    }
}

class InMemorySenderKeyStore extends SignalClient.SenderKeyStore {
    private state = new Map();
    async saveSenderKey(
        sender: SignalClient.ProtocolAddress,
        distributionId: SignalClient.Uuid,
        record: SignalClient.SenderKeyRecord
    ): Promise<void> {
        const idx =
            distributionId + '::' + sender.name() + '::' + sender.deviceId();
        Promise.resolve(this.state.set(idx, record));
    }
    async getSenderKey(
        sender: SignalClient.ProtocolAddress,
        distributionId: SignalClient.Uuid
    ): Promise<SignalClient.SenderKeyRecord | null> {
        const idx =
            distributionId + '::' + sender.name() + '::' + sender.deviceId();
        if (this.state.has(idx)) {
            return Promise.resolve(this.state.get(idx));
        } else {
            return Promise.resolve(null);
        }
    }
}


// Request GET 
console.log("---PROTOCOL ADDRESS---");
const addr = SignalClient.ProtocolAddress.new('name', 42); //42 è il device id
// Il codice per prendere il device ID viene spiegato qui: https://aboutreact.com/react-native-get-unique-id-of-device/
// assert.deepEqual è una verifica tra due valori. In questo caso è come se fosse una if con ==
assert.deepEqual(addr.name(), 'name'); // Username della persona proprietaria del dispositivo
assert.deepEqual(addr.deviceId(), 42);
console.log(addr.deviceId());
console.log("----------------------");

// PACCHETTO PUBLIC KEY
console.log("---PUBLIC KEY BUNDLE---");

const registrationId = 5; // ID del dispositivo nel server generato dopo l'inizializzazione del device ID
const deviceId = addr.deviceId(); //Device id passato da sopra
const prekeyId = 42; // ID del Prekey packet
const prekey = SignalClient.PrivateKey.generate().getPublicKey(); // Public Key (Prekey packet)
const signedPrekeyId = 2300; // (ID della Signed prekey packet che verà firmata)
const signedPrekey = SignalClient.PrivateKey.generate().getPublicKey(); // Public Key che verrà firmata (Signed prekey packet)
const signedPrekeySignature = SignalClient.PrivateKey.generate().sign( // Signature
    Buffer.from('010203', 'hex')
);
const identityKey = SignalClient.PrivateKey.generate().getPublicKey(); // Identity Key (Chiave "privata" per ogni dispositivo)

console.log("DeviceID: ", deviceId);
console.log("PrekeyID (ID Prekey Packet): ", prekeyId);
console.log("Identity Key Packet: ", identityKey);
console.log("Prekey (Prekey packet, public key): ", prekey);
console.log("signedPrekeyId (ID Signed prekey packet firmata): ", signedPrekeyId);
console.log("signedPrekey (Public key generata e firmata): ", signedPrekey);
console.log("signedPrekeySignature (Firma digitale della public key): ", signedPrekeySignature);
console.log("---------------------");

const pkb = SignalClient.PreKeyBundle.new(
    registrationId,
    deviceId,
    prekeyId,
    prekey,
    signedPrekeyId,
    signedPrekey,
    signedPrekeySignature,
    identityKey
);

assert.deepEqual(pkb.registrationId(), registrationId);
assert.deepEqual(pkb.deviceId(), deviceId);
assert.deepEqual(pkb.preKeyId(), prekeyId);
assert.deepEqual(pkb.preKeyPublic(), prekey);
assert.deepEqual(pkb.signedPreKeyId(), signedPrekeyId);
assert.deepEqual(pkb.signedPreKeyPublic(), signedPrekey);
assert.deepEqual(pkb.signedPreKeySignature(), signedPrekeySignature);
assert.deepEqual(pkb.identityKey(), identityKey);
console.log("DeviceID: ", deviceId);
console.log("PrekeyID: ", prekeyId);
console.log("Prekey: ", prekey);
console.log("signedPrekeyId: ", signedPrekeyId);
console.log("signedPrekey: ", signedPrekey);
console.log("signedPrekeySignature: ", signedPrekeySignature);
console.log("---------------------");


// CODICE PER CRIPTARE I MESSAGGI 1-1

console.log("-------------CRYPT CODE 1-1-------------");
const sync = async () => {
    const aKeys = new InMemoryIdentityKeyStore(); // Questo oggetto conterrà l'Identity Key Packet ed il Registration ID
    const bKeys = new InMemoryIdentityKeyStore();
    console.log("<----Chiavi---->");
    console.log("Oggetto chiavi A:", aKeys);
    console.log("Oggetto chiavi B:", bKeys);
    console.log("<-------------->");
    const aSess = new InMemorySessionStore();
    const bSess = new InMemorySessionStore();
    console.log("<--Sessione--->");
    console.log("Oggetto sessione A:", aSess);
    console.log("Oggetto sessione B:", bSess);
    console.log("<------------->");

    const bPreK = new InMemoryPreKeyStore();
    const bSPreK = new InMemorySignedPreKeyStore();
    console.log("<----Prekey--->");
    console.log("Prekey B:", bPreK);
    console.log("Prekey B con signature:", bSPreK);
    console.log("<------------->");

    const bPreKey = SignalClient.PrivateKey.generate();
    const bSPreKey = SignalClient.PrivateKey.generate();

    const aIdentityKey = await aKeys.getIdentityKey();
    const bIdentityKey = await bKeys.getIdentityKey();
    console.log("<----ID Key--->");
    console.log("ID Key A:", aIdentityKey);
    console.log("ID Key B:", bIdentityKey);
    console.log("<------------->");

    const aE164 = '+14151111111';
    const bE164 = '+19192222222';

    const aDeviceId = 1;
    const bDeviceId = 3;

    const aUuid = '9d0652a3-dcc3-4d11-975f-74d61598733f';
    const bUuid = '796abedb-ca4e-4f18-8803-1fde5b921f9f';

    const trustRoot = SignalClient.PrivateKey.generate();
    const serverKey = SignalClient.PrivateKey.generate();

    const serverCert = SignalClient.ServerCertificate.new(
        1,
        serverKey.getPublicKey(),
        trustRoot
    );

    const expires = 1605722925;
    const senderCert = SignalClient.SenderCertificate.new(
        aUuid,
        aE164,
        aDeviceId,
        aIdentityKey.getPublicKey(),
        expires,
        serverCert,
        serverKey
    );

    const bRegistrationId = await bKeys.getLocalRegistrationId();
    const bPreKeyId = 31337;
    const bSignedPreKeyId = 22;

    const bSignedPreKeySig = bIdentityKey.sign(
        bSPreKey.getPublicKey().serialize()
    );

    const bPreKeyBundle = SignalClient.PreKeyBundle.new(
        bRegistrationId,
        bDeviceId,
        bPreKeyId,
        bPreKey.getPublicKey(),
        bSignedPreKeyId,
        bSPreKey.getPublicKey(),
        bSignedPreKeySig,
        bIdentityKey.getPublicKey()
    );

    const bPreKeyRecord = SignalClient.PreKeyRecord.new(
        bPreKeyId,
        bPreKey.getPublicKey(),
        bPreKey
    );
    bPreK.savePreKey(bPreKeyId, bPreKeyRecord);

    const bSPreKeyRecord = SignalClient.SignedPreKeyRecord.new(
        bSignedPreKeyId,
        42, // timestamp
        bSPreKey.getPublicKey(),
        bSPreKey,
        bSignedPreKeySig
    );
    bSPreK.saveSignedPreKey(bSignedPreKeyId, bSPreKeyRecord);

    const bAddress = SignalClient.ProtocolAddress.new(bUuid, bDeviceId);
    await SignalClient.processPreKeyBundle(
        bPreKeyBundle,
        bAddress,
        aSess,
        aKeys
    );

    const aPlaintext = Buffer.from('hi there', 'utf8');

    const aCiphertext = await SignalClient.sealedSenderEncryptMessage(
        aPlaintext,
        bAddress,
        senderCert,
        aSess,
        aKeys
    );

    const bPlaintext = await SignalClient.sealedSenderDecryptMessage(
        aCiphertext,
        trustRoot.getPublicKey(),
        43, // timestamp,
        bE164,
        bUuid,
        bDeviceId,
        bSess,
        bKeys,
        bPreK,
        bSPreK
    );

    assert(bPlaintext != null);

    if (bPlaintext != null) {
        assert.deepEqual(bPlaintext.message(), aPlaintext);
        assert.deepEqual(bPlaintext.senderE164(), aE164);
        assert.deepEqual(bPlaintext.senderUuid(), aUuid);
        assert.deepEqual(bPlaintext.deviceId(), aDeviceId);
    }

    const innerMessage = await SignalClient.signalEncrypt(
        aPlaintext,
        bAddress,
        aSess,
        aKeys
    );

    for (const hint of [
        200,
        SignalClient.ContentHint.Default,
        SignalClient.ContentHint.Resendable,
        SignalClient.ContentHint.Implicit,
    ]) {
        const content = SignalClient.UnidentifiedSenderMessageContent.new(
            innerMessage,
            senderCert,
            hint,
            null
        );
        const ciphertext = await SignalClient.sealedSenderEncrypt(
            content,
            bAddress,
            aKeys
        );
        const decryptedContent = await SignalClient.sealedSenderDecryptToUsmc(
            ciphertext,
            bKeys
        );
        assert.deepEqual(decryptedContent.contentHint(), hint);
    }
}
sync();
console.log("----------------------------------------");

console.log("------------------PREKEY MESSAGING BASIC----------------------");
it('test01', async () => { 
    console.log("Funzione partita");
    // Prende le chiavi generate e immagazzinate nello store
    const aKeys = new InMemoryIdentityKeyStore();
    const bKeys = new InMemoryIdentityKeyStore();

    // Inizializza la sessione
    const aSess = new InMemorySessionStore();
    const bSess = new InMemorySessionStore();

    // Prende le prekey e le signed prekey immagazzinate nello store
    const bPreK = new InMemoryPreKeyStore();
    const bSPreK = new InMemorySignedPreKeyStore();


    const bPreKey = SignalClient.PrivateKey.generate();
    const bSPreKey = SignalClient.PrivateKey.generate();
    console.log("Qui si blocca");

    const bIdentityKey = await bKeys.getIdentityKey();
    console.log("testprint:::::::::::::")
    const bSignedPreKeySig = bIdentityKey.sign(
      bSPreKey.getPublicKey().serialize()
    );
        
    const aAddress = SignalClient.ProtocolAddress.new('+14151111111', 1);
    const bAddress = SignalClient.ProtocolAddress.new('+19192222222', 1);

    const bRegistrationId = await bKeys.getLocalRegistrationId();
    const bPreKeyId = 31337;
    const bSignedPreKeyId = 22;

    const bPreKeyBundle = SignalClient.PreKeyBundle.new(
      bRegistrationId,
      bAddress.deviceId(),
      bPreKeyId,
      bPreKey.getPublicKey(),
      bSignedPreKeyId,
      bSPreKey.getPublicKey(),
      bSignedPreKeySig,
      bIdentityKey.getPublicKey()
    );

    const bPreKeyRecord = SignalClient.PreKeyRecord.new(
      bPreKeyId,
      bPreKey.getPublicKey(),
      bPreKey
    );
    bPreK.savePreKey(bPreKeyId, bPreKeyRecord);

    const bSPreKeyRecord = SignalClient.SignedPreKeyRecord.new(
      bSignedPreKeyId,
      42, // timestamp
      bSPreKey.getPublicKey(),
      bSPreKey,
      bSignedPreKeySig
    );
    bSPreK.saveSignedPreKey(bSignedPreKeyId, bSPreKeyRecord);

    await SignalClient.processPreKeyBundle(
      bPreKeyBundle,
      bAddress,
      aSess,
      aKeys
    );
    const aMessage = Buffer.from('Greetings hoo-man', 'utf8');
    console.log("Messaggio in uscita:", aMessage);

    const aCiphertext = await SignalClient.signalEncrypt(
      aMessage,
      bAddress,
      aSess,
      aKeys
    );
    console.log("Messaggio in uscita criptato:", aCiphertext);

    assert.deepEqual(
      aCiphertext.type(),
      SignalClient.CiphertextMessageType.PreKey
    );

    const aCiphertextR = SignalClient.PreKeySignalMessage.deserialize(
      aCiphertext.serialize()
    );

    const bDPlaintext = await SignalClient.signalDecryptPreKey(
      aCiphertextR,
      aAddress,
      bSess,
      bKeys,
      bPreK,
      bSPreK
    );
    assert.deepEqual(bDPlaintext, aMessage);

    const bMessage = Buffer.from(
      'Sometimes the only thing more dangerous than a question is an answer.',
      'utf8'
    );

    const bCiphertext = await SignalClient.signalEncrypt(
      bMessage,
      aAddress,
      bSess,
      bKeys
    );

    assert.deepEqual(
      bCiphertext.type(),
      SignalClient.CiphertextMessageType.Whisper
    );

    const bCiphertextR = SignalClient.SignalMessage.deserialize(
      bCiphertext.serialize()
    );

    const aDPlaintext = await SignalClient.signalDecrypt(
      bCiphertextR,
      bAddress,
      aSess,
      aKeys
    );
    console.log("Messaggio decriptato::::::::::::::", aDPlaintext);

    assert.deepEqual(aDPlaintext, bMessage);

    const session = await bSess.getSession(aAddress);

    if (session != null) {
      assert(session.serialize().length > 0);
      assert.deepEqual(session.localRegistrationId(), 5);
      assert.deepEqual(session.remoteRegistrationId(), 5);
      assert(session.hasCurrentState());
      assert(
        !session.currentRatchetKeyMatches(
          SignalClient.PrivateKey.generate().getPublicKey()
        )
      );

      session.archiveCurrentState();
      assert(!session.hasCurrentState());
      assert(
        !session.currentRatchetKeyMatches(
          SignalClient.PrivateKey.generate().getPublicKey()
        )
      );
    } else {
      assert.fail('no session found');
    }
});

console.log("--------------------------------------------------------------");
