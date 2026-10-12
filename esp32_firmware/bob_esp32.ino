/*
  ============================================================
  BOB ESP32
  Hybrid ML-KEM-512 + HKDF-SHA256 + AES-256-GCM
  ESP-NOW communication

  Serial commands:
    CHECK_PUBLIC_KEY
    VERIFY_PUBLIC_KEY
    ENCAPSULATE
    SEND_CIPHERTEXT
    DERIVE_AES
    ESTABLISH
    RESET

  Bob MAC:
    8C:94:DF:57:45:E8

  Alice MAC:
    8C:94:DF:52:11:9C

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
// ALICE MAC ADDRESS
// ============================================================

uint8_t ALICE_MAC[] = {
  0x8C,
  0x94,
  0xDF,
  0x52,
  0x11,
  0x9C
};

// ============================================================
// PQC
// ============================================================

PQCKyber bob;

// ============================================================
// STATE
// ============================================================

bool publicKeyReceived  = false;
bool publicKeyVerified  = false;
bool encapsulationDone  = false;
bool ciphertextSent     = false;
bool aesReady           = false;
bool channelEstablished = false;

// ============================================================
// RECEIVED PUBLIC KEY
// ============================================================

uint8_t receivedPublicKey[
  PUBLIC_KEY_SIZE
];

bool publicKeyChunks[
  (PUBLIC_KEY_SIZE / CHUNK_SIZE) + 2
];

int expectedPublicKeyChunks = 0;

// ============================================================
// BOB CIPHERTEXT
// ============================================================

uint8_t bobCiphertextCopy[
  CIPHERTEXT_SIZE
];

// ============================================================
// AES KEY
// ============================================================

uint8_t aesKey[
  AES_KEY_SIZE
];

// ============================================================
// PQC PACKET
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
// RAW ESP-NOW RX BUFFER
// ============================================================

volatile bool newPacketAvailable =
  false;

uint8_t rxRaw[
  250
];

int rxRawLength =
  0;

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
// ESP-NOW RECEIVE CALLBACK
// ============================================================

void onDataRecv(
  const esp_now_recv_info_t *info,
  const uint8_t *data,
  int len
) {

  if (
    len <= 0
  ) {
    return;
  }

  if (
    len > 250
  ) {
    return;
  }

  portENTER_CRITICAL_ISR(
    &mux
  );

  memcpy(
    rxRaw,
    data,
    len
  );

  rxRawLength =
    len;

  newPacketAvailable =
    true;

  portEXIT_CRITICAL_ISR(
    &mux
  );
}

// ============================================================
// PROCESS PUBLIC KEY
// ============================================================

void processPublicKey(
  const uint8_t *data,
  int len
) {

  if (
    len <
    PQC_HEADER_SIZE
  ) {
    return;
  }

  if (
    len >
    (int)sizeof(PQCPacket)
  ) {
    return;
  }

  PQCPacket packet;

  memset(
    &packet,
    0,
    sizeof(packet)
  );

  memcpy(
    &packet,
    data,
    len
  );

  if (
    packet.type !=
    TYPE_PUBLIC_KEY
  ) {
    return;
  }

  if (
    packet.total == 0
  ) {

    Serial.println(
      "ERROR:PUBLIC_KEY_BAD_TOTAL"
    );

    return;
  }

  if (
    packet.index >=
    packet.total
  ) {

    Serial.println(
      "ERROR:PUBLIC_KEY_BAD_INDEX"
    );

    return;
  }

  if (
    packet.length == 0 ||
    packet.length > CHUNK_SIZE
  ) {

    Serial.println(
      "ERROR:PUBLIC_KEY_BAD_LENGTH"
    );

    return;
  }

  int offset =
    packet.index *
    CHUNK_SIZE;

  if (
    offset +
    packet.length >
    PUBLIC_KEY_SIZE
  ) {

    Serial.println(
      "ERROR:PUBLIC_KEY_SIZE"
    );

    return;
  }

  memcpy(
    receivedPublicKey + offset,
    packet.data,
    packet.length
  );

  publicKeyChunks[
    packet.index
  ] = true;

  expectedPublicKeyChunks =
    packet.total;

  Serial.print(
    "RX_PUBLIC_KEY_CHUNK:"
  );

  Serial.print(
    packet.index + 1
  );

  Serial.print(
    "/"
  );

  Serial.println(
    packet.total
  );

  bool complete =
    true;

  for (
    int i = 0;
    i < packet.total;
    i++
  ) {

    if (
      !publicKeyChunks[i]
    ) {

      complete =
        false;

      break;
    }
  }

  if (complete) {

    publicKeyReceived =
      true;

    Serial.println();

    Serial.println(
      "[Step 3] Alice's Kyber Public Key completely received."
    );

    Serial.print(
      "PUBLIC_KEY_SIZE:"
    );

    Serial.println(
      PUBLIC_KEY_SIZE
    );

    Serial.println(
      "EVENT:PUBLIC_KEY_RECEIVED"
    );

    Serial.print(
      "DEBUG_RX_PUBLIC_KEY:"
    );

    printHex(
      receivedPublicKey,
      PUBLIC_KEY_SIZE
    );
  }
}

// ============================================================
// STEP 4 - VERIFY PUBLIC KEY
// ============================================================

bool verifyPublicKey() {

  if (!publicKeyReceived) {

    Serial.println(
      "ERROR:PUBLIC_KEY_NOT_RECEIVED"
    );

    return false;
  }

  Serial.println();

  Serial.println(
    "[Step 4] Verifying Alice's Kyber Public Key..."
  );

  bool nonZero =
    false;

  for (
    int i = 0;
    i < PUBLIC_KEY_SIZE;
    i++
  ) {

    if (
      receivedPublicKey[i] != 0
    ) {

      nonZero =
        true;

      break;
    }
  }

  if (!nonZero) {

    Serial.println(
      "EVENT:PUBLIC_KEY_VERIFICATION_FAILED"
    );

    return false;
  }

  publicKeyVerified =
    true;

  Serial.println(
    "PUBLIC_KEY_VERIFICATION:SUCCESS"
  );

  Serial.println(
    "EVENT:PUBLIC_KEY_VERIFIED"
  );

  return true;
}

// ============================================================
// STEP 5 - ENCAPSULATION
// ============================================================

bool doEncapsulate() {

  if (!publicKeyVerified) {

    Serial.println(
      "ERROR:PUBLIC_KEY_NOT_VERIFIED"
    );

    return false;
  }

  Serial.println();

  Serial.println(
    "[Step 5] Bob encapsulating using Alice's Public Key..."
  );

  bool result =
    bob.encapsulate(
      receivedPublicKey
    );

  if (!result) {

    Serial.println(
      "ERROR:ENCAPSULATION_FAILED"
    );

    return false;
  }

  encapsulationDone =
    true;

  const uint8_t *ct =
    bob.getCiphertext();

  // Make our own stable copy
  memcpy(
    bobCiphertextCopy,
    ct,
    CIPHERTEXT_SIZE
  );

  Serial.print(
    "CIPHERTEXT_SIZE:"
  );

  Serial.println(
    CIPHERTEXT_SIZE
  );

  Serial.print(
    "DEBUG_CIPHERTEXT:"
  );

  printHex(
    bobCiphertextCopy,
    CIPHERTEXT_SIZE
  );

  const uint8_t *ss =
    bob.getSharedSecret();

  Serial.print(
    "DEBUG_SHARED_SECRET:"
  );

  printHex(
    ss,
    SHARED_SECRET_SIZE
  );

  Serial.println(
    "EVENT:ENCAPSULATION_SUCCESS"
  );

  return true;
}

// ============================================================
// STEP 6 - SEND KYBER CIPHERTEXT
// ============================================================

bool sendCiphertext() {

  if (!encapsulationDone) {

    Serial.println(
      "ERROR:ENCAPSULATION_NOT_DONE"
    );

    return false;
  }

  Serial.println();

  Serial.println(
    "[Step 6] Bob sending Kyber ciphertext to Alice..."
  );

  int total =
    (
      CIPHERTEXT_SIZE +
      CHUNK_SIZE -
      1
    ) /
    CHUNK_SIZE;

  for (
    int i = 0;
    i < total;
    i++
  ) {

    int offset =
      i *
      CHUNK_SIZE;

    int remaining =
      CIPHERTEXT_SIZE -
      offset;

    int len =
      remaining > CHUNK_SIZE
      ?
      CHUNK_SIZE
      :
      remaining;

    PQCPacket packet;

    memset(
      &packet,
      0,
      sizeof(packet)
    );

    packet.type =
      TYPE_KYBER_CT;

    packet.index =
      i;

    packet.total =
      total;

    packet.length =
      len;

    memcpy(
      packet.data,
      bobCiphertextCopy + offset,
      len
    );

    size_t packetLength =
      PQC_HEADER_SIZE + len;

    esp_err_t result =
      esp_now_send(
        ALICE_MAC,
        (uint8_t *)&packet,
        packetLength
      );

    if (
      result != ESP_OK
    ) {

      Serial.print(
        "SEND_STATUS:FAILED:"
      );

      Serial.println(
        result
      );

      return false;
    }

    Serial.println(
      "SEND_STATUS:SUCCESS"
    );

    Serial.print(
      "TX_CIPHERTEXT_CHUNK:"
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

    delay(50);
  }

  ciphertextSent =
    true;

  Serial.println(
    "EVENT:CIPHERTEXT_SENT"
  );

  return true;
}

// ============================================================
// STEP 9 - DERIVE AES KEY
// ============================================================

bool deriveAESKey() {

  if (!encapsulationDone) {

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
    bob.getSharedSecret();

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
    "READY_FOR_AES_MESSAGE"
  );
}

// ============================================================
// STEP 12 + 13
// MANUAL AES PACKET PARSING
// ============================================================

void processAESMessage(
  const uint8_t *data,
  int len
) {

  if (!channelEstablished) {

    Serial.println(
      "ERROR:PQC_NOT_READY"
    );

    return;
  }

  // ----------------------------------------------------------
  // Minimum packet:
  //
  // type        1
  // sequence    8
  // nonce       12
  // ct length   2
  // tag         16
  //
  // Total = 39 bytes
  // ----------------------------------------------------------

  const size_t MIN_PACKET_SIZE =
    1 +
    sizeof(uint64_t) +
    NONCE_SIZE +
    sizeof(uint16_t) +
    TAG_SIZE;

  if (
    len <
    (int)MIN_PACKET_SIZE
  ) {

    Serial.println(
      "ERROR:AES_PACKET_TOO_SMALL"
    );

    return;
  }

  // ----------------------------------------------------------
  // MANUAL PARSING
  // ----------------------------------------------------------

  size_t offset =
    0;

  // TYPE
  uint8_t type =
    data[offset++];

  if (
    type != TYPE_AES_DATA
  ) {
    return;
  }

  // ----------------------------------------------------------
  // SEQUENCE
  // ----------------------------------------------------------

  uint64_t sequence;

  memcpy(
    &sequence,
    data + offset,
    sizeof(sequence)
  );

  offset +=
    sizeof(sequence);

  // ----------------------------------------------------------
  // NONCE
  // ----------------------------------------------------------

  uint8_t nonce[
    NONCE_SIZE
  ];

  memcpy(
    nonce,
    data + offset,
    NONCE_SIZE
  );

  offset +=
    NONCE_SIZE;

  // ----------------------------------------------------------
  // CIPHERTEXT LENGTH
  // ----------------------------------------------------------

  uint16_t ciphertextLength;

  memcpy(
    &ciphertextLength,
    data + offset,
    sizeof(ciphertextLength)
  );

  offset +=
    sizeof(ciphertextLength);

  if (
    ciphertextLength == 0 ||
    ciphertextLength >
      MAX_MESSAGE_SIZE
  ) {

    Serial.println(
      "ERROR:INVALID_CIPHERTEXT_LENGTH"
    );

    return;
  }

  // ----------------------------------------------------------
  // CHECK EXPECTED PACKET SIZE
  // ----------------------------------------------------------

  size_t expectedLength =
    offset +
    ciphertextLength +
    TAG_SIZE;

  if (
    len !=
    (int)expectedLength
  ) {

    Serial.print(
      "ERROR:AES_PACKET_LENGTH_MISMATCH:"
    );

    Serial.print(
      len
    );

    Serial.print(
      "/EXPECTED:"
    );

    Serial.println(
      expectedLength
    );

    return;
  }

  // ----------------------------------------------------------
  // CIPHERTEXT
  // ----------------------------------------------------------

  uint8_t ciphertext[
    MAX_MESSAGE_SIZE
  ];

  memcpy(
    ciphertext,
    data + offset,
    ciphertextLength
  );

  offset +=
    ciphertextLength;

  // ----------------------------------------------------------
  // TAG
  // ----------------------------------------------------------

  uint8_t tag[
    TAG_SIZE
  ];

  memcpy(
    tag,
    data + offset,
    TAG_SIZE
  );

  // ==========================================================
  // DEBUG
  // ==========================================================

  Serial.println();

  Serial.println(
    "[Step 12] AES-256-GCM encrypted message received."
  );

  Serial.print(
    "RX_SEQUENCE:"
  );

  Serial.println(
    (unsigned long)sequence
  );

  Serial.print(
    "DEBUG_RX_NONCE:"
  );

  printHex(
    nonce,
    NONCE_SIZE
  );

  Serial.print(
    "DEBUG_RX_CIPHERTEXT:"
  );

  printHex(
    ciphertext,
    ciphertextLength
  );

  Serial.print(
    "DEBUG_RX_TAG:"
  );

  printHex(
    tag,
    TAG_SIZE
  );

  Serial.print(
    "RX_AES_PACKET_SIZE:"
  );

  Serial.println(
    len
  );

  // ==========================================================
  // STEP 13 - AES-GCM AUTHENTICATION
  // ==========================================================

  Serial.println();

  Serial.println(
    "[Step 13] Bob decrypting and authenticating..."
  );

  uint8_t plaintext[
    MAX_MESSAGE_SIZE + 1
  ];

  memset(
    plaintext,
    0,
    sizeof(plaintext)
  );

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

  if (
    result != 0
  ) {

    Serial.println(
      "EVENT:AUTH_FAILED"
    );

    Serial.println(
      "ERROR:AES_SETKEY_FAILED"
    );

    mbedtls_gcm_free(
      &gcm
    );

    return;
  }

  result =
    mbedtls_gcm_auth_decrypt(

      &gcm,

      ciphertextLength,

      nonce,

      NONCE_SIZE,

      (const unsigned char *)
        &sequence,

      sizeof(sequence),

      tag,

      TAG_SIZE,

      ciphertext,

      plaintext
    );

  mbedtls_gcm_free(
    &gcm
  );

  // ==========================================================
  // AUTHENTICATION RESULT
  // ==========================================================

  if (
    result != 0
  ) {

    Serial.println();

    Serial.println(
      "EVENT:AUTH_FAILED"
    );

    Serial.println(
      "AES-GCM authentication FAILED."
    );

    return;
  }

  plaintext[
    ciphertextLength
  ] = '\0';

  Serial.println();

  Serial.println(
    "EVENT:AUTH_SUCCESS"
  );

  Serial.println(
    "AES-GCM authentication SUCCESS."
  );

  Serial.print(
    "RECEIVED_MESSAGE:"
  );

  Serial.println(
    (char *)plaintext
  );

  Serial.println();

  Serial.println(
    "========================================"
  );

  Serial.println(
    "MESSAGE_RECEIVED_SUCCESSFULLY"
  );

  Serial.println(
    "========================================"
  );
}

// ============================================================
// SERIAL COMMANDS
// ============================================================

void processCommand(
  String command
) {

  command.trim();

  // ----------------------------------------------------------
  // STEP 3
  // ----------------------------------------------------------

  if (
    command ==
    "CHECK_PUBLIC_KEY"
  ) {

    if (publicKeyReceived) {

      Serial.println(
        "EVENT:PUBLIC_KEY_RX_CONFIRMED"
      );

    } else {

      Serial.println(
        "EVENT:WAITING_FOR_PUBLIC_KEY"
      );
    }
  }

  // ----------------------------------------------------------
  // STEP 4
  // ----------------------------------------------------------

  else if (
    command ==
    "VERIFY_PUBLIC_KEY"
  ) {

    verifyPublicKey();
  }

  // ----------------------------------------------------------
  // STEP 5
  // ----------------------------------------------------------

  else if (
    command ==
    "ENCAPSULATE"
  ) {

    doEncapsulate();
  }

  // ----------------------------------------------------------
  // STEP 6
  // ----------------------------------------------------------

  else if (
    command ==
    "SEND_CIPHERTEXT"
  ) {

    sendCiphertext();
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
  // RESET
  // ----------------------------------------------------------

  else if (
    command ==
    "RESET"
  ) {

    Serial.println(
      "RESETTING_BOB"
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
    "BOB ESP32"
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
  // Add Alice
  // ----------------------------------------------------------

  esp_now_peer_info_t peerInfo;

  memset(
    &peerInfo,
    0,
    sizeof(peerInfo)
  );

  memcpy(
    peerInfo.peer_addr,
    ALICE_MAC,
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
      "ERROR:ADD_ALICE_PEER_FAILED"
    );

  } else {

    Serial.println(
      "EVENT:ALICE_PEER_ADDED"
    );
  }

  Serial.println();

  Serial.println(
    "Bob waiting for Flask commands."
  );
}

// ============================================================
// LOOP
// ============================================================

void loop() {

  // ----------------------------------------------------------
  // Process received packets
  // ----------------------------------------------------------

  if (
    newPacketAvailable
  ) {

    uint8_t packet[
      250
    ];

    int len;

    portENTER_CRITICAL(
      &mux
    );

    memcpy(
      packet,
      rxRaw,
      rxRawLength
    );

    len =
      rxRawLength;

    newPacketAvailable =
      false;

    portEXIT_CRITICAL(
      &mux
    );

    if (
      len >= 1
    ) {

      uint8_t type =
        packet[0];

      // ------------------------------------------------------
      // Public key
      // ------------------------------------------------------

      if (
        type ==
        TYPE_PUBLIC_KEY
      ) {

        processPublicKey(
          packet,
          len
        );
      }

      // ------------------------------------------------------
      // AES packet
      // ------------------------------------------------------

      else if (
        type ==
        TYPE_AES_DATA
      ) {

        processAESMessage(
          packet,
          len
        );
      }
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
