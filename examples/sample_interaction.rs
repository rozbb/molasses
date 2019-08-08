// This file is going to implement the following MLS interaction:
//
// Alice creates a Group.
// Alice receives a UserInitKey from Bob.
// Alice adds Bob
// Alice sends an application message
// Bob sends an application message
// Alice receives a UserInitKey from Carol
// Alice sends an application message
// Alice adds Carol
// Carol sends an application message

use molasses::{
    application::{decrypt_application_message, encrypt_application_message, ApplicationMessage},
    credential::{BasicCredential, Credential, Identity},
    crypto::{
        ciphersuite::{CipherSuite, X25519_SHA256_AES128GCM},
        sig::{SigPublicKey, SigSecretKey, SignatureScheme, ED25519_IMPL},
    },
    group_state::{GroupState, Welcome},
    handshake::{Handshake, ProtocolVersion, UserInitKey, MLS_DUMMY_VERSION},
    tls_de::TlsDeserializer,
    tls_ser::TlsSerializer,
    upcast::{CryptoCtx, CryptoUpcast},
};

use std::thread;

use crossbeam::channel;
use rand;
use rot13::rot13;
use serde::de::Deserialize;
use serde::ser::Serialize;

static COMMON_CIPHER_SUITE: &'static CipherSuite = &X25519_SHA256_AES128GCM;
static COMMON_SIG_SCHEME: &'static SignatureScheme = &ED25519_IMPL;
static COMMON_PROTOCOL_VERSION: ProtocolVersion = MLS_DUMMY_VERSION;

// Pauses the main thread until the user presses Enter
fn pause_for_effect() {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
}

// Deserializes and upcasts MLS data structures
pub fn deserialize<'de, T: Deserialize<'de> + CryptoUpcast>(bytes: &[u8]) -> T {
    // Deserialize
    let mut cursor = bytes;
    let mut deserializer = TlsDeserializer::from_reader(&mut cursor);
    let mut val = <T as Deserialize>::deserialize(&mut deserializer).unwrap();

    // Punt on negotiating ciphersuites and signature schemes. I don't wanna deal with that
    let ctx = CryptoCtx::new()
        .set_cipher_suite(COMMON_CIPHER_SUITE)
        .set_signature_scheme(COMMON_SIG_SCHEME);

    // Make everything nice and typesafe
    val.upcast_crypto_values(&ctx).unwrap();

    val
}

// Serializes MLS data structures
fn serialize<T: Serialize>(value: &T) -> Vec<u8> {
    let mut serializer = TlsSerializer::new();
    value.serialize(&mut serializer).unwrap();
    serializer.into_vec()
}

// Turns a byte sequence into a String and ROT13s it
fn bytes_to_str(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    rot13(&s)
}

// The purpose of the delivery service is to read messages from members and distribute them to
// every other member. In this case, we decide that members don't get copies of the messages that
// they send. This is just for convenience.
fn delivery_service(
    ds_to_alice_tx: channel::Sender<Vec<u8>>,
    ds_to_bob_tx: channel::Sender<Vec<u8>>,
    ds_to_carol_tx: channel::Sender<Vec<u8>>,
    alice_to_ds_rx: channel::Receiver<Vec<u8>>,
    bob_to_ds_rx: channel::Receiver<Vec<u8>>,
    carol_to_ds_rx: channel::Receiver<Vec<u8>>,
) {
    // Select lets us wait for activity on any of the incoming channels
    let mut sel = channel::Select::new();
    sel.recv(&alice_to_ds_rx);
    sel.recv(&bob_to_ds_rx);
    sel.recv(&carol_to_ds_rx);

    let mut passthrough = || {
        // When something happens, figure out which channel it was
        let oper = sel.select();
        let idx = oper.index();

        // Receive a message from the appropriate channel
        let msg = match idx {
            0 => oper.recv(&alice_to_ds_rx).unwrap(),
            1 => oper.recv(&bob_to_ds_rx).unwrap(),
            2 => oper.recv(&carol_to_ds_rx).unwrap(),
            _ => panic!("out of bounds operation index"),
        };

        // Send the message to everyone but the original sender
        match idx {
            0 => {
                ds_to_bob_tx.send(msg.clone()).unwrap();
                ds_to_carol_tx.send(msg.clone()).unwrap();
            }
            1 => {
                ds_to_alice_tx.send(msg.clone()).unwrap();
                ds_to_carol_tx.send(msg.clone()).unwrap();
            }
            2 => {
                ds_to_alice_tx.send(msg.clone()).unwrap();
                ds_to_bob_tx.send(msg.clone()).unwrap();
            }
            _ => panic!("out of bounds operation index"),
        }
    };

    // Bob --UserInitKey--> Alice
    pause_for_effect();
    passthrough();

    // Alice --Welcome--> Bob
    pause_for_effect();
    passthrough();

    // Alice --Add--> Bob
    pause_for_effect();
    passthrough();

    // Alice --ApplicationMessage--> Bob
    pause_for_effect();
    passthrough();

    // Alice <--ApplicationMessage-- Bob
    pause_for_effect();
    passthrough();

    // Alice --ApplicationMessage--> Bob
    pause_for_effect();
    passthrough();

    // Carol --UserInitKey--> Alice
    // Carol <--Welcome-- Alice
    // Carol <--Add-- Alice
    pause_for_effect();
    passthrough();
    passthrough();
    passthrough();

    // Carol yells
    pause_for_effect();
    passthrough();

    pause_for_effect();
}

fn alice(tx: channel::Sender<Vec<u8>>, rx: channel::Receiver<Vec<u8>>) {
    let mut rng = rand::thread_rng();

    // First order of business, make a GroupState
    // Make up an identity key
    let identity_secret_key = SigSecretKey::new_from_random(COMMON_SIG_SCHEME, &mut rng).unwrap();
    let identity_public_key =
        SigPublicKey::new_from_secret_key(COMMON_SIG_SCHEME, &identity_secret_key);

    // Make up a group ID
    let group_id = b"suspicions_rising".to_vec();

    // Make up a credential
    let credential = {
        let identity = Identity::from_bytes(b"alice".to_vec());
        let basic_cred = BasicCredential::new(identity, COMMON_SIG_SCHEME, identity_public_key);
        Credential::Basic(basic_cred)
    };
    let group_state = GroupState::new_singleton_group(
        COMMON_CIPHER_SUITE,
        COMMON_PROTOCOL_VERSION,
        identity_secret_key,
        group_id,
        credential,
        &mut rng,
    )
    .unwrap();

    // Get Bob's UserInitKey
    let bob_user_init_key: UserInitKey = deserialize(&rx.recv().unwrap());

    // Add Bob to the Group
    // First, make and send a Welcome
    let (welcome, welcome_info_hash) =
        Welcome::from_group_state(&group_state, &bob_user_init_key, &mut rng).unwrap();
    tx.send(serialize(&welcome)).unwrap();
    println!("ALICE SEND Welcome");

    // Then make an Add Handshake, letting the resulting group state be the new group state.
    // Bob will have roster index 1. Recall Alice is at roster index 0.
    let bob_roster_idx = 1;
    let (add_handshake, group_state, mut app_key_chain) = group_state
        .create_and_apply_add_handshake(bob_roster_idx, bob_user_init_key, &welcome_info_hash)
        .unwrap();
    tx.send(serialize(&add_handshake)).unwrap();
    println!("ALICE SEND Add");

    // Now time for Alice's first message
    let msg = b"Lbh fnvq ab zber pybja fpubby";
    let app_msg =
        encrypt_application_message(msg.to_vec(), &group_state, &mut app_key_chain).unwrap();
    tx.send(serialize(&app_msg)).unwrap();
    println!("ALICE SEND ApplicationMessage");

    // Receive Bob's response
    let app_msg: ApplicationMessage = deserialize(&rx.recv().unwrap());
    let plaintext = decrypt_application_message(app_msg, &group_state, &mut app_key_chain).unwrap();
    println!(r#"ALICE RECV ApplicationMessage "{}""#, bytes_to_str(&plaintext));

    // Alice's response
    let msg =
        b"Gura jul gur uryy unf Pneby orra pnyyvat gur ynaqyvar, thfuvat nobhg lbhe cebterff?";
    let app_msg =
        encrypt_application_message(msg.to_vec(), &group_state, &mut app_key_chain).unwrap();
    tx.send(serialize(&app_msg)).unwrap();
    println!("ALICE SEND ApplicationMessage");

    // Get Carol's UserInitKey
    let carol_user_init_key: UserInitKey = deserialize(&rx.recv().unwrap());
    println!("ALICE RECV UserInitKey");

    // Add Carol to the Group:
    // First, make and send a Welcome
    let (welcome, welcome_info_hash) =
        Welcome::from_group_state(&group_state, &carol_user_init_key, &mut rng).unwrap();
    tx.send(serialize(&welcome)).unwrap();
    println!("ALICE SEND Welcome");

    // Then make an Add Handshake, letting the resulting group state be the new group state.
    let carol_roster_idx = 2;
    let (add_handshake, group_state, mut app_key_chain) = group_state
        .create_and_apply_add_handshake(carol_roster_idx, carol_user_init_key, &welcome_info_hash)
        .unwrap();
    tx.send(serialize(&add_handshake)).unwrap();
    println!("ALICE SEND Add");

    // Receive Carol's message
    let app_msg: ApplicationMessage = deserialize(&rx.recv().unwrap());
    let plaintext = decrypt_application_message(app_msg, &group_state, &mut app_key_chain).unwrap();
    println!(r#"ALICE RECV ApplicationMessage "{}""#, bytes_to_str(&plaintext));
}

fn bob(tx: channel::Sender<Vec<u8>>, rx: channel::Receiver<Vec<u8>>) {
    let mut rng = rand::thread_rng();

    // Make an identity
    let identity_secret_key = SigSecretKey::new_from_random(COMMON_SIG_SCHEME, &mut rng).unwrap();
    let identity_public_key =
        SigPublicKey::new_from_secret_key(COMMON_SIG_SCHEME, &identity_secret_key);

    // Make up a credential
    let credential = {
        let identity = Identity::from_bytes(b"bob".to_vec());
        let basic_cred = BasicCredential::new(identity, COMMON_SIG_SCHEME, identity_public_key);
        Credential::Basic(basic_cred)
    };
    // Make a UserInitKey
    let user_init_key_id = b"bob_user_init_key".to_vec();
    let cipher_suites = vec![COMMON_CIPHER_SUITE];
    let supported_versions = vec![COMMON_PROTOCOL_VERSION];
    let user_init_key = UserInitKey::new_from_random(
        &identity_secret_key,
        user_init_key_id,
        credential,
        cipher_suites,
        supported_versions,
        &mut rng,
    )
    .unwrap();

    // Send the UserInitKey
    tx.send(serialize(&user_init_key)).unwrap();
    println!("BOB   SEND UserInitKey");

    // Receive the Welcome message
    let welcome: Welcome = deserialize(&rx.recv().unwrap());
    println!("BOB   RECV Welcome");
    // Make a preliminary GroupState out of it
    let group_state =
        GroupState::from_welcome(welcome, identity_secret_key, user_init_key).unwrap();

    // Now receive the Add and process the Handshake
    let add_handshake: Handshake = deserialize(&rx.recv().unwrap());
    println!("BOB   RECV Add");
    let (group_state, mut app_key_chain) = group_state.process_handshake(&add_handshake).unwrap();

    // Time to receive the first ApplicationMessage
    let app_msg: ApplicationMessage = deserialize(&rx.recv().unwrap());
    let plaintext = decrypt_application_message(app_msg, &group_state, &mut app_key_chain).unwrap();
    println!(r#"BOB   RECV ApplicationMessage "{}""#, bytes_to_str(&plaintext));

    // Respond
    let msg = b"V qvq, naq V'ir fgbccrq. Pbyq ghexrl fvapr Sroehnel";
    let app_msg =
        encrypt_application_message(msg.to_vec(), &group_state, &mut app_key_chain).unwrap();
    tx.send(serialize(&app_msg)).unwrap();
    println!("BOB   SEND ApplicationMessage");

    // Get rebuked by Alice
    let app_msg: ApplicationMessage = deserialize(&rx.recv().unwrap());
    let plaintext = decrypt_application_message(app_msg, &group_state, &mut app_key_chain).unwrap();
    println!(r#"BOB   RECV ApplicationMessage "{}""#, bytes_to_str(&plaintext));

    // Silently ignore Carol's UserInitKey
    rx.recv().unwrap();
    // Silently ignore Alice's Welcome
    rx.recv().unwrap();

    // Process Carol's addition to the group
    let add_handshake: Handshake = deserialize(&rx.recv().unwrap());
    println!("BOB   RECV Add");
    let (group_state, mut app_key_chain) = group_state.process_handshake(&add_handshake).unwrap();

    // Get Carol's first message
    let app_msg: ApplicationMessage = deserialize(&rx.recv().unwrap());
    let plaintext = decrypt_application_message(app_msg, &group_state, &mut app_key_chain).unwrap();
    println!(r#"BOB   RECV ApplicationMessage "{}""#, bytes_to_str(&plaintext));
}

fn carol(tx: channel::Sender<Vec<u8>>, rx: channel::Receiver<Vec<u8>>) {
    let mut rng = rand::thread_rng();

    // Even though Carol is added to the convo later, she's still connected to the Delivery
    // Service. So ignore all the things sent before it's Carol's time to shine.
    rx.recv().unwrap();
    rx.recv().unwrap();
    rx.recv().unwrap();
    rx.recv().unwrap();
    rx.recv().unwrap();
    rx.recv().unwrap();

    // Make an identity
    let identity_secret_key = SigSecretKey::new_from_random(COMMON_SIG_SCHEME, &mut rng).unwrap();
    let identity_public_key =
        SigPublicKey::new_from_secret_key(COMMON_SIG_SCHEME, &identity_secret_key);

    // Make up a credential
    let credential = {
        let identity = Identity::from_bytes(b"bob".to_vec());
        let basic_cred = BasicCredential::new(identity, COMMON_SIG_SCHEME, identity_public_key);
        Credential::Basic(basic_cred)
    };
    // Make a UserInitKey
    let user_init_key_id = b"carol_user_init_key".to_vec();
    let cipher_suites = vec![COMMON_CIPHER_SUITE];
    let supported_versions = vec![COMMON_PROTOCOL_VERSION];
    let user_init_key = UserInitKey::new_from_random(
        &identity_secret_key,
        user_init_key_id,
        credential,
        cipher_suites,
        supported_versions,
        &mut rng,
    )
    .unwrap();

    // Send the UserInitKey
    tx.send(serialize(&user_init_key)).unwrap();
    println!("CAROL SEND UserInitKey");

    // Receive the Welcome message
    let welcome: Welcome = deserialize(&rx.recv().unwrap());
    println!("CAROL RECV Welcome");
    // Make a preliminary GroupState out of it
    let group_state =
        GroupState::from_welcome(welcome, identity_secret_key, user_init_key).unwrap();

    // Now receive the Add and process the Handshake
    let add_handshake: Handshake = deserialize(&rx.recv().unwrap());
    println!("CAROL RECV Add");
    let (group_state, mut app_key_chain) = group_state.process_handshake(&add_handshake).unwrap();

    // Carol's first message
    let msg = b"Uv rirelbar V'z whfg ernyyl tynq gb or urer.";
    let app_msg =
        encrypt_application_message(msg.to_vec(), &group_state, &mut app_key_chain).unwrap();
    tx.send(serialize(&app_msg)).unwrap();
    println!("CAROL SEND ApplicationMessage");
}

fn main() {
    // We need six unidirectional channels:
    //
    //     Delivery Service
    //      ^      ^     ^
    //      |      |     |
    //      |      |     |
    //      v      v     v
    //    Alice   Bob  Carol

    let (alice_to_ds_tx, alice_to_ds_rx) = channel::bounded(0);
    let (bob_to_ds_tx, bob_to_ds_rx) = channel::bounded(0);
    let (carol_to_ds_tx, carol_to_ds_rx) = channel::bounded(0);

    let (ds_to_alice_tx, ds_to_alice_rx) = channel::bounded(0);
    let (ds_to_bob_tx, ds_to_bob_rx) = channel::bounded(0);
    let (ds_to_carol_tx, ds_to_carol_rx) = channel::bounded(0);

    // Make a thread for each actor
    thread::spawn(move || alice(alice_to_ds_tx, ds_to_alice_rx));
    thread::spawn(move || bob(bob_to_ds_tx, ds_to_bob_rx));
    thread::spawn(move || carol(carol_to_ds_tx, ds_to_carol_rx));

    // Let the delivery service control the flow of the program
    delivery_service(
        ds_to_alice_tx,
        ds_to_bob_tx,
        ds_to_carol_tx,
        alice_to_ds_rx,
        bob_to_ds_rx,
        carol_to_ds_rx,
    );
}
