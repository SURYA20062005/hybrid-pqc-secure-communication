/*
  ============================================================
  ALICE ESP32
  Hybrid ML-KEM-512 + HKDF-SHA256 + AES-256-GCM
  ESP-NOW communication

  Serial commands:
    GEN_KEY
    SEND_PUBLIC_K
    CHECK_CIPHERTEXT
    DECAPSULATE
    DERIVE_AES
    ESTABLISH
    SEND_MESSAGE:<message>
    RESET

  Alice MAC:
    8C:94:DF:52:11:9C

  Bob MAC:
    8C:94:DF:57:45:E8

  WiFi Channel:
    1
  ============================================================
*/

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_system.h>
#include <PQCMicro.h>

#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"

#include <string.h>

// ============================================================
// CONFIGURATION
// ============================================================

#define WIFI_CHANNEL 1

#define PUBLIC_KEY_SIZE       800
#define CIPHERTEXT_SIZE       768
#define SHARED_SECRET_SIZE     32

#define AES_KEY_SIZE           32
#define NONCE_SIZE             12
#define TAG_SIZE               16

#define CHUNK_SIZE             200
#define MAX_MESSAGE_SIZE       180

#define PQC_HEADER_SIZE        5

#define TYPE_PUBLIC_KEY        0x01
#define TYPE_KYBER_CT          0x02
#define TYPE_AES_DATA          0x20

// ============================================================
// BOB MAC ADDRESS
// ============================================================

uint8_t BOB_MAC[] = {
  0x8C,
  0x94,
  0xDF,
  0x57,
  0x45,
  0xE8
};

// ============================================================
// PQC OBJECT
// ============================================================

PQCKyber alice;

// ============================================================
// STATE
// ============================================================

bool keyGenerated       = false;
bool publicKeySent      = false;
bool ciphertextReceived = false;
bool decapsulationDone  = false;
bool aesReady           = false;
bool channelEstablished = false;

// ============================================================
// RECEIVED KYBER CIPHERTEXT
// ============================================================

uint8_t receivedCiphertext[
  CIPHERTEXT_SIZE
];

bool ciphertextChunks[
  (CIPHERTEXT_SIZE / CHUNK_SIZE) + 2
];

int receivedCiphertextBytes = 0;
int expectedCiphertextChunks = 0;

// ============================================================
// AES KEY
// ============================================================

uint8_t aesKey[
  AES_KEY_SIZE
];

// ============================================================
// PQC PACKET
// ============================================================
//
// IMPORTANT:
// packed ensures:
//
// type   = offset 0
// index  = offset 1
// total  = offset 2
// length = offset 3
// data   = offset 5
//
// Header = exactly 5 bytes.
//
// ============================================================

struct __attribute__((packed)) PQCPacket {

  uint8_t  type;
  uint8_t  index;
  uint8_t  total;
  uint16_t length;

  uint8_t data[
    CHUNK_SIZE
  ];
};

// ============================================================
// RX BUFFER
// ============================================================

volatile bool newPacketAvailable = false;

PQCPacket rxPacket;

portMUX_TYPE mux =
  portMUX_INITIALIZER_UNLOCKED;

// ============================================================
// HEX PRINT
// ============================================================

void printHex(
  const uint8_t *data,
  size_t len
) {

  for (
    size_t i = 0;
    i < len;
    i++
  ) {

    if (data[i] < 16) {
      Serial.print("0");
    }

    Serial.print(
      data[i],
      HEX
    );

    if (i < len - 1) {
      Serial.print(":");
    }
  }

  Serial.println();
}

// ============================================================
// WIFI
// ============================================================

void setWiFiChannel() {

  WiFi.mode(
    WIFI_STA
  );

  delay(100);

  esp_err_t result =
    esp_wifi_set_channel(
      WIFI_CHANNEL,
      WIFI_SECOND_CHAN_NONE
    );

  if (result != ESP_OK) {

    Serial.print(
      "ERROR:WIFI_CHANNEL_SET_FAILED:"
    );

    Serial.println(
      result
    );
  }

  Serial.print(
    "MAC: "
  );

  Serial.println(
    WiFi.macAddress()
  );

  Serial.print(
    "WiFi Channel: "
  );

  Serial.println(
    WIFI_CHANNEL
  );
}

// ============================================================
// SEND PQC CHUNK
// ============================================================

bool sendPQCChunk(
  uint8_t type,
  uint8_t index,
  uint8_t total,
  const uint8_t *data,
  uint16_t len
) {

  if (len > CHUNK_SIZE) {

    Serial.println(
      "ERROR:PQC_CHUNK_TOO_LARGE"
    );

    return false;
  }

  PQCPacket packet;

  memset(
    &packet,
    0,
    sizeof(packet)
  );

  packet.type =
    type;

  packet.index =
    index;

  packet.total =
    total;

  packet.length =
    len;

  memcpy(
    packet.data,
    data,
    len
  );

  size_t packetLength =
    PQC_HEADER_SIZE + len;

  esp_err_t result =
    esp_now_send(
      BOB_MAC,
      (uint8_t *)&packet,
      packetLength
    );

  if (result == ESP_OK) {

    Serial.println(
      "SEND_STATUS:SUCCESS"
    );

    return true;

  } else {

    Serial.print(
      "SEND_STATUS:FAILED:"
    );

    Serial.println(
      result
    );

    return false;
  }
}

// ============================================================
// STEP 2 - SEND PUBLIC KEY
// ============================================================

bool sendPublicKey() {

  if (!keyGenerated) {

    Serial.println(
      "ERROR:KEY_NOT_GENERATED"
    );

    return false;
  }

  const uint8_t *publicKey =
    alice.getPublicKey();

  int total =
    (
      PUBLIC_KEY_SIZE +
      CHUNK_SIZE -
      1
    ) /
    CHUNK_SIZE;

  Serial.println();

  Serial.println(
    "[Step 2] Sending Alice's Kyber Public Key..."
  );

  Serial.print(
    "PUBLIC_KEY_SIZE:"
  );

  Serial.println(
    PUBLIC_KEY_SIZE
  );

  Serial.print(
    "PUBLIC_KEY_CHUNKS:"
  );

  Serial.println(
    total
  );

  for (
    int i = 0;
    i < total;
    i++
  ) {

    int offset =
      i * CHUNK_SIZE;

    int remaining =
      PUBLIC_KEY_SIZE -
      offset;

    int len =
      remaining > CHUNK_SIZE
      ?
      CHUNK_SIZE
      :
      remaining;

    Serial.print(
      "TX_PUBLIC_KEY_CHUNK:"
    );

    Serial.print(
      i + 1
    );

    Serial.print(
      "/"
    );

    Serial.println(
      total
    );

    if (!sendPQCChunk(
      TYPE_PUBLIC_KEY,
      i,
      total,
      publicKey + offset,
      len
    )) {

      Serial.println(
        "ERROR:PUBLIC_KEY_SEND_FAILED"
      );

      return false;
    }

    delay(50);
  }

  publicKeySent =
    true;

  Serial.println(
    "EVENT:PUBLIC_KEY_SENT"
  );

  return true;
}

// ============================================================
// ESP-NOW RECEIVE CALLBACK
// ============================================================

void onDataRecv(
  const esp_now_recv_info_t *info,
  const uint8_t *data,
  int len
) {

  if (len < PQC_HEADER_SIZE) {
    return;
  }

  if (
    len >
    (int)sizeof(PQCPacket)
  ) {
    return;
  }

  PQCPacket temp;

  memset(
    &temp,
    0,
    sizeof(temp)
  );

  memcpy(
    &temp,
    data,
    len
  );

  portENTER_CRITICAL_ISR(
    &mux
  );

  memcpy(
    &rxPacket,
    &temp,
    sizeof(PQCPacket)
  );

  newPacketAvailable =
    true;

  portEXIT_CRITICAL_ISR(
    &mux
  );
}

// ============================================================
// PROCESS KYBER CIPHERTEXT
// ============================================================

void processCiphertextChunk() {

  if (
    rxPacket.type !=
    TYPE_KYBER_CT
  ) {
    return;
  }

  if (
    rxPacket.total == 0
  ) {
    return;
  }

  if (
    rxPacket.index >=
    rxPacket.total
  ) {

    Serial.println(
      "ERROR:CIPHERTEXT_BAD_INDEX"
    );

    return;
  }

  if (
    rxPacket.length == 0 ||
    rxPacket.length > CHUNK_SIZE
  ) {

    Serial.println(
      "ERROR:CIPHERTEXT_BAD_LENGTH"
    );

    return;
  }

  int offset =
    rxPacket.index *
    CHUNK_SIZE;

  if (
    offset +
    rxPacket.length >
    CIPHERTEXT_SIZE
  ) {

    Serial.println(
      "ERROR:CIPHERTEXT_SIZE"
    );

    return;
  }

  memcpy(
    receivedCiphertext + offset,
    rxPacket.data,
    rxPacket.length
  );

  ciphertextChunks[
    rxPacket.index
  ] = true;

  expectedCiphertextChunks =
    rxPacket.total;

  Serial.print(
    "RX_CIPHERTEXT_CHUNK:"
  );

  Serial.print(
    rxPacket.index + 1
  );

  Serial.print(
    "/"
  );

  Serial.println(
    rxPacket.total
  );

  bool complete =
    true;

  for (
    int i = 0;
    i < rxPacket.total;
    i++
  ) {

    if (
      !ciphertextChunks[i]
    ) {

      complete =
        false;

      break;
    }
  }

  if (complete) {

    ciphertextReceived =
      true;

    receivedCiphertextBytes =
      CIPHERTEXT_SIZE;

    Serial.println();

    Serial.println(
      "[Step 7] Kyber ciphertext completely received."
    );

    Serial.print(
      "CIPHERTEXT_SIZE:"
    );

    Serial.println(
      CIPHERTEXT_SIZE
    );

    Serial.println(
      "EVENT:CIPHERTEXT_RECEIVED"
    );

    Serial.print(
      "DEBUG_RX_CIPHERTEXT:"
    );

    printHex(
      receivedCiphertext,
      CIPHERTEXT_SIZE
    );
  }
}

// ============================================================
// STEP 8 - DECAPSULATE
// ============================================================

bool doDecapsulate() {

  if (!ciphertextReceived) {

    Serial.println(
      "ERROR:CIPHERTEXT_NOT_RECEIVED"
    );

    return false;
  }

  Serial.println();

  Serial.println(
    "[Step 8] Alice decapsulating Kyber ciphertext..."
  );

  bool result =
    alice.decapsulate(
      receivedCiphertext
    );

  if (!result) {

    Serial.println(
      "ERROR:DECAPSULATION_FAILED"
    );

    return false;
  }

  decapsulationDone =
    true;

  Serial.println(
    "EVENT:DECAPSULATION_SUCCESS"
  );

  const uint8_t *ss =
    alice.getSharedSecret();

  Serial.print(
    "DEBUG_SHARED_SECRET:"
  );

  printHex(
    ss,
    SHARED_SECRET_SIZE
  );

  return true;
}

// ============================================================
// STEP 9 - HKDF
// ============================================================

bool deriveAESKey() {

  if (!decapsulationDone) {

    Serial.println(
      "ERROR:PQC_SECRET_NOT_READY"
    );

    return false;
  }

  Serial.println();

  Serial.println(
    "[Step 9] Deriving AES-256 key using HKDF..."
  );

  const uint8_t *ss =
    alice.getSharedSecret();

  const mbedtls_md_info_t *md =
    mbedtls_md_info_from_type(
      MBEDTLS_MD_SHA256
    );

  int result =
    mbedtls_hkdf(
      md,

      NULL,
      0,

      ss,
      SHARED_SECRET_SIZE,

      (const unsigned char *)
        "AES-256-GCM",

      strlen(
        "AES-256-GCM"
      ),

      aesKey,
      AES_KEY_SIZE
    );

  if (result != 0) {

    Serial.println(
      "ERROR:HKDF_FAILED"
    );

    return false;
  }

  aesReady =
    true;

  Serial.print(
    "DEBUG_AES_KEY:"
  );

  printHex(
    aesKey,
    AES_KEY_SIZE
  );

  Serial.println(
    "EVENT:AES_KEY_READY"
  );

  return true;
}

// ============================================================
// STEP 10
// ============================================================

void establishChannel() {

  if (!aesReady) {

    Serial.println(
      "ERROR:AES_KEY_NOT_READY"
    );

    return;
  }

  channelEstablished =
    true;

  Serial.println();

  Serial.println(
    "[Step 10] PQC key establishment complete."
  );

  Serial.println(
    "EVENT:PQC_READY"
  );

  Serial.println(
    "READY_FOR_MESSAGE"
  );
}

// ============================================================
// STEP 11 + 12
// AES-256-GCM ENCRYPTION
// ============================================================

bool encryptAndSend(
  String message
) {

  if (!channelEstablished) {

    Serial.println(
      "ERROR:PQC_NOT_READY"
    );

    return false;
  }

  if (
    message.length() == 0
  ) {

    Serial.println(
      "ERROR:EMPTY_MESSAGE"
    );

    return false;
  }

  if (
    message.length() >
    MAX_MESSAGE_SIZE
  ) {

    Serial.println(
      "ERROR:MESSAGE_TOO_LONG"
    );

    return false;
  }

  Serial.println();

  Serial.println(
    "[Step 11] Encrypting message using AES-256-GCM..."
  );

  Serial.print(
    "PLAINTEXT:"
  );

  Serial.println(
    message
  );

  // ----------------------------------------------------------
  // Nonce
  // ----------------------------------------------------------

  uint8_t nonce[
    NONCE_SIZE
  ];

  esp_fill_random(
    nonce,
    NONCE_SIZE
  );

  // ----------------------------------------------------------
  // Sequence
  // ----------------------------------------------------------

  uint64_t sequence =
    1;

  // ----------------------------------------------------------
  // Ciphertext + tag
  // ----------------------------------------------------------

  uint8_t ciphertext[
    MAX_MESSAGE_SIZE
  ];

  uint8_t tag[
    TAG_SIZE
  ];

  // ----------------------------------------------------------
  // AES GCM
  // ----------------------------------------------------------

  mbedtls_gcm_context gcm;

  mbedtls_gcm_init(
    &gcm
  );

  int result =
    mbedtls_gcm_setkey(
      &gcm,
      MBEDTLS_CIPHER_ID_AES,
      aesKey,
      256
    );

  if (result != 0) {

    Serial.println(
      "ERROR:AES_SETKEY_FAILED"
    );

    mbedtls_gcm_free(
      &gcm
    );

    return false;
  }

  result =
    mbedtls_gcm_crypt_and_tag(
      &gcm,

      MBEDTLS_GCM_ENCRYPT,

      message.length(),

      nonce,
      NONCE_SIZE,

      (const unsigned char *)
        &sequence,

      sizeof(sequence),

      (const unsigned char *)
        message.c_str(),

      ciphertext,

      TAG_SIZE,
      tag
    );

  mbedtls_gcm_free(
    &gcm
  );

  if (result != 0) {

    Serial.println(
      "ERROR:AES_ENCRYPT_FAILED"
    );

    return false;
  }

  // ----------------------------------------------------------
  // Debug values
  // ----------------------------------------------------------

  Serial.print(
    "DEBUG_NONCE:"
  );

  printHex(
    nonce,
    NONCE_SIZE
  );

  Serial.print(
    "DEBUG_CIPHERTEXT:"
  );

  printHex(
    ciphertext,
    message.length()
  );

  Serial.print(
    "DEBUG_TAG:"
  );

  printHex(
    tag,
    TAG_SIZE
  );

  Serial.print(
    "SEQUENCE:"
  );

  Serial.println(
    (unsigned long)sequence
  );

  // ==========================================================
  // MANUAL AES WIRE SERIALIZATION
  // ==========================================================
  //
  // Wire format:
  //
  // [1 byte]  TYPE
  // [8 byte]  SEQUENCE
  // [12 byte] NONCE
  // [2 byte]  CIPHERTEXT LENGTH
  // [N byte]  CIPHERTEXT
  // [16 byte] GCM TAG
  //
  // For "gotham":
  //
  // 1 + 8 + 12 + 2 + 6 + 16 = 45 bytes
  //
  // ==========================================================

  uint8_t buffer[
    1 +
    sizeof(uint64_t) +
    NONCE_SIZE +
    sizeof(uint16_t) +
    MAX_MESSAGE_SIZE +
    TAG_SIZE
  ];

  size_t offset =
    0;

  // TYPE
  buffer[offset++] =
    TYPE_AES_DATA;

  // SEQUENCE
  memcpy(
    buffer + offset,
    &sequence,
    sizeof(sequence)
  );

  offset +=
    sizeof(sequence);

  // NONCE
  memcpy(
    buffer + offset,
    nonce,
    NONCE_SIZE
  );

  offset +=
    NONCE_SIZE;

  // CIPHERTEXT LENGTH
  uint16_t ctLen =
    (uint16_t)message.length();

  memcpy(
    buffer + offset,
    &ctLen,
    sizeof(ctLen)
  );

  offset +=
    sizeof(ctLen);

  // CIPHERTEXT
  memcpy(
    buffer + offset,
    ciphertext,
    ctLen
  );

  offset +=
    ctLen;

  // TAG
  memcpy(
    buffer + offset,
    tag,
    TAG_SIZE
  );

  offset +=
    TAG_SIZE;

  size_t packetLength =
    offset;

  Serial.print(
    "AES_PACKET_SIZE:"
  );

  Serial.println(
    packetLength
  );

  // ----------------------------------------------------------
  // Step 12
  // ----------------------------------------------------------

  Serial.println();

  Serial.println(
    "[Step 12] Sending AES-256-GCM encrypted message..."
  );

  esp_err_t sendResult =
    esp_now_send(
      BOB_MAC,
      buffer,
      packetLength
    );

  if (
    sendResult != ESP_OK
  ) {

    Serial.print(
      "ERROR:AES_SEND_FAILED:"
    );

    Serial.println(
      sendResult
    );

    return false;
  }

  Serial.println(
    "SEND_STATUS:SUCCESS"
  );

  Serial.println(
    "EVENT:AES_MESSAGE_SENT"
  );

  Serial.print(
    "SENT_MESSAGE:"
  );

  Serial.println(
    message
  );

  return true;
}

// ============================================================
// SERIAL COMMANDS
// ============================================================

void processCommand(
  String command
) {

  command.trim();

  // ----------------------------------------------------------
  // STEP 1
  // ----------------------------------------------------------

  if (
    command ==
    "GEN_KEY"
  ) {

    Serial.println();

    Serial.println(
      "[Step 1] Generating Alice's Kyber-512 key pair..."
    );

    unsigned long start =
      millis();

    bool result =
      alice.generateKeys();

    if (!result) {

      Serial.println(
        "ERROR:KEY_GENERATION_FAILED"
      );

      return;
    }

    keyGenerated =
      true;

    publicKeySent =
      false;

    Serial.print(
      "KEYGEN_TIME:"
    );

    Serial.print(
      millis() - start
    );

    Serial.println(
      " ms"
    );

    Serial.println(
      "EVENT:KYBER_KEY_READY"
    );

    Serial.print(
      "PUBLIC_KEY_SIZE:"
    );

    Serial.println(
      PUBLIC_KEY_SIZE
    );

    Serial.print(
      "DEBUG_PUBLIC_KEY:"
    );

    printHex(
      alice.getPublicKey(),
      PUBLIC_KEY_SIZE
    );
  }

  // ----------------------------------------------------------
  // STEP 2
  // ----------------------------------------------------------

  else if (
    command ==
    "SEND_PUBLIC_KEY"
  ) {

    sendPublicKey();
  }

  // ----------------------------------------------------------
  // STEP 7
  // ----------------------------------------------------------

  else if (
    command ==
    "CHECK_CIPHERTEXT"
  ) {

    if (ciphertextReceived) {

      Serial.println(
        "EVENT:CIPHERTEXT_RX_CONFIRMED"
      );

    } else {

      Serial.println(
        "EVENT:WAITING_FOR_CIPHERTEXT"
      );
    }
  }

  // ----------------------------------------------------------
  // STEP 8
  // ----------------------------------------------------------

  else if (
    command ==
    "DECAPSULATE"
  ) {

    doDecapsulate();
  }

  // ----------------------------------------------------------
  // STEP 9
  // ----------------------------------------------------------

  else if (
    command ==
    "DERIVE_AES"
  ) {

    deriveAESKey();
  }

  // ----------------------------------------------------------
  // STEP 10
  // ----------------------------------------------------------

  else if (
    command ==
    "ESTABLISH"
  ) {

    establishChannel();
  }

  // ----------------------------------------------------------
  // STEP 11/12
  // ----------------------------------------------------------

  else if (
    command.startsWith(
      "SEND_MESSAGE:"
    )
  ) {

    String message =
      command.substring(
        strlen("SEND_MESSAGE:")
      );

    encryptAndSend(
      message
    );
  }

  // ----------------------------------------------------------
  // RESET
  // ----------------------------------------------------------

  else if (
    command ==
    "RESET"
  ) {

    Serial.println(
      "RESETTING_ALICE"
    );

    delay(100);

    ESP.restart();
  }

  // ----------------------------------------------------------
  // UNKNOWN
  // ----------------------------------------------------------

  else {

    Serial.print(
      "ERROR:UNKNOWN_COMMAND:"
    );

    Serial.println(
      command
    );
  }
}

// ============================================================
// SETUP
// ============================================================

void setup() {

  Serial.begin(
    115200
  );

  delay(2000);

  Serial.println();

  Serial.println(
    "========================================"
  );

  Serial.println(
    "ALICE ESP32"
  );

  Serial.println(
    "ML-KEM-512 + HKDF-SHA256 + AES-256-GCM"
  );

  Serial.println(
    "========================================"
  );

  setWiFiChannel();

  // ----------------------------------------------------------
  // ESP-NOW
  // ----------------------------------------------------------

  if (
    esp_now_init() != ESP_OK
  ) {

    Serial.println(
      "ERROR:ESP_NOW_INIT_FAILED"
    );

    return;
  }

  esp_now_register_recv_cb(
    onDataRecv
  );

  // ----------------------------------------------------------
  // Add Bob
  // ----------------------------------------------------------

  esp_now_peer_info_t peerInfo;

  memset(
    &peerInfo,
    0,
    sizeof(peerInfo)
  );

  memcpy(
    peerInfo.peer_addr,
    BOB_MAC,
    6
  );

  peerInfo.channel =
    WIFI_CHANNEL;

  peerInfo.encrypt =
    false;

  if (
    esp_now_add_peer(
      &peerInfo
    ) != ESP_OK
  ) {

    Serial.println(
      "ERROR:ADD_BOB_PEER_FAILED"
    );

  } else {

    Serial.println(
      "EVENT:BOB_PEER_ADDED"
    );
  }

  Serial.println();

  Serial.println(
    "Alice waiting for Flask commands."
  );
}

// ============================================================
// LOOP
// ============================================================

void loop() {

  // ----------------------------------------------------------
  // Process received PQC packets
  // ----------------------------------------------------------

  if (
    newPacketAvailable
  ) {

    PQCPacket packet;

    portENTER_CRITICAL(
      &mux
    );

    memcpy(
      &packet,
      &rxPacket,
      sizeof(PQCPacket)
    );

    newPacketAvailable =
      false;

    portEXIT_CRITICAL(
      &mux
    );

    if (
      packet.type ==
      TYPE_KYBER_CT
    ) {

      rxPacket =
        packet;

      processCiphertextChunk();
    }
  }

  // ----------------------------------------------------------
  // Flask command
  // ----------------------------------------------------------

  if (
    Serial.available()
  ) {

    String command =
      Serial.readStringUntil(
        '\n'
      );

    processCommand(
      command
    );
  }

  delay(1);
}








