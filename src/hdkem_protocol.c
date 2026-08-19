#include "hdkem_protocol.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ===== CRC Utilities ===== */

uint16_t calculate_crc16(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 0x0001) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}

uint16_t calculate_crc_ccitt(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

/* ===== Connection Management ===== */

int hdkem_connection_init(hdkem_connection_t *conn, uint8_t is_server) {
    if (!conn) return HDKEM_ERROR_INVALID_PARAM;
    
    memset(conn, 0, sizeof(hdkem_connection_t));
    conn->state = STATE_INIT;
    conn->is_server = is_server;
    conn->sequence_number = 0;
    
    return HDKEM_SUCCESS;
}

void hdkem_connection_cleanup(hdkem_connection_t *conn) {
    if (conn) {
        hdkem_secure_memzero(&conn->session, sizeof(hdkem_session_t));
        memset(conn, 0, sizeof(hdkem_connection_t));
    }
}

/* ===== Server-Side Implementation ===== */

int hdkem_server_send_hello(hdkem_connection_t *conn,
                            const hdkem_server_keys_t *keys,
                            const uint8_t *client_gandalf_pk,
                            uint8_t *buffer,
                            size_t *buffer_len) {
    if (!conn || !keys || !client_gandalf_pk || !buffer || !buffer_len) {
        return HDKEM_ERROR_INVALID_PARAM;
    }

    if (conn->state != STATE_INIT) {
        return HDKEM_ERROR_INVALID_PARAM;
    }

    hdkem_server_hello_t hello;
    int result = hdkem_server_create_hello(keys, client_gandalf_pk, &hello);
    if (result != HDKEM_SUCCESS) {
        return result;
    }
    
    /* Serialize to wire format */
    wire_server_hello_t *wire = (wire_server_hello_t *)buffer;
    wire->message_type = 0x01;
    
    memcpy(wire->mlkem_public_key, hello.mlkem_public_key, MLKEM_PUBLIC_KEY_SIZE);
    memcpy(wire->x25519_public_key, hello.x25519_public_key, X25519_PUBLIC_KEY_SIZE);
    memcpy(wire->server_id, hello.server_id, hello.server_id_len);
    wire->server_id_len_low = (uint8_t)(hello.server_id_len & 0xFF);
    wire->server_id_len_high = (uint8_t)((hello.server_id_len >> 8) & 0xFF);
    
    /* Copy signature (size depends on Gandalf output) */
    memcpy(wire->signature, hello.signature, GANDALF_SIGNATURE_SIZE);
    wire->signature_len_low = (uint8_t)(GANDALF_SIGNATURE_SIZE & 0xFF);
    wire->signature_len_high = (uint8_t)((GANDALF_SIGNATURE_SIZE >> 8) & 0xFF);
    
    *buffer_len = sizeof(wire_server_hello_t);
    
    conn->state = STATE_SERVER_HELLO_SENT;
    
    return HDKEM_SUCCESS;
}

int hdkem_server_process_client_hello_wire(hdkem_connection_t *conn,
                                           const hdkem_server_keys_t *server_keys,
                                           const uint8_t *client_gandalf_pk,
                                           const uint8_t *k3_qkd,
                                           const uint8_t *buffer,
                                           size_t buffer_len) {
    if (!conn || !server_keys || !client_gandalf_pk || !k3_qkd || !buffer) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    if (conn->state != STATE_QKD_ESTABLISH && conn->state != STATE_SERVER_HELLO_SENT) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    const wire_client_hello_t *wire = (const wire_client_hello_t *)buffer;
    
    if (wire->message_type != 0x02) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    /* Convert wire format to internal structure */
    hdkem_client_hello_t client_hello;
    memcpy(client_hello.mlkem_ciphertext, wire->mlkem_ciphertext, MLKEM_CIPHERTEXT_SIZE);
    memcpy(client_hello.x25519_public_key, wire->x25519_public_key, X25519_PUBLIC_KEY_SIZE);
    uint16_t client_id_len = (uint16_t)wire->client_id_len_low | ((uint16_t)wire->client_id_len_high << 8);
    uint16_t signature_len = (uint16_t)wire->signature_len_low | ((uint16_t)wire->signature_len_high << 8);
    memcpy(client_hello.client_id, wire->client_id, client_id_len);
    client_hello.client_id_len = client_id_len;
    memcpy(client_hello.signature, wire->signature, signature_len);
    
    /* Call the original hdkem.c function */
    int result = hdkem_server_process_client_hello(server_keys, &client_hello,
                                                   client_gandalf_pk, k3_qkd,
                                                   &conn->session);
    
    if (result == HDKEM_SUCCESS) {
        conn->state = STATE_SESSION_ESTABLISHED;
    }
    
    return result;
}

int hdkem_server_send_finished(hdkem_connection_t *conn,
                               const uint8_t *server_id,
                               size_t server_id_len,
                               uint8_t *buffer,
                               size_t *buffer_len) {
    if (!conn || !server_id || !buffer || !buffer_len) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    if (conn->state != STATE_SESSION_ESTABLISHED) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    /* Create "Server_Finished" message */
    uint8_t plaintext[256];
    size_t pt_len = 0;
    
    memcpy(plaintext, "Server_Finished", 15);
    pt_len += 15;
    memcpy(plaintext + pt_len, server_id, server_id_len);
    pt_len += server_id_len;
    
    /* Encrypt with session key */
    hdkem_encrypted_msg_t encrypted;
    int result = hdkem_encrypt_message(&conn->session, plaintext, pt_len, &encrypted);
    if (result != HDKEM_SUCCESS) {
        return result;
    }
    
    /* Serialize to wire format */
    wire_server_finished_t *wire = (wire_server_finished_t *)buffer;
    wire->message_type = 0x03;
    memcpy(wire->nonce, encrypted.nonce, ASCON_NONCE_SIZE);
    memcpy(wire->encrypted_finish, encrypted.ciphertext, encrypted.ciphertext_len);
    wire->encrypted_len_low = (uint8_t)(encrypted.ciphertext_len & 0xFF);
    wire->encrypted_len_high = (uint8_t)((encrypted.ciphertext_len >> 8) & 0xFF);
    
    *buffer_len = sizeof(wire_server_finished_t);
    
    return HDKEM_SUCCESS;
}

/* ===== Client-Side Implementation ===== */

int hdkem_client_process_server_hello_wire(hdkem_connection_t *conn,
                                          hdkem_client_keys_t *client_keys,
                                          const uint8_t *server_gandalf_pk,
                                          const uint8_t *k3_qkd,
                                          const uint8_t *buffer,
                                          size_t buffer_len,
                                          uint8_t *response,
                                          size_t *response_len) {
    if (!conn || !client_keys || !server_gandalf_pk || !k3_qkd || 
        !buffer || !response || !response_len) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    if (conn->state != STATE_INIT && conn->state != STATE_QKD_ESTABLISH) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    const wire_server_hello_t *wire = (const wire_server_hello_t *)buffer;
    
    if (wire->message_type != 0x01) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    /* Convert wire format to internal structure */
    hdkem_server_hello_t server_hello;
    memcpy(server_hello.mlkem_public_key, wire->mlkem_public_key, MLKEM_PUBLIC_KEY_SIZE);
    memcpy(server_hello.x25519_public_key, wire->x25519_public_key, X25519_PUBLIC_KEY_SIZE);
    uint16_t server_id_len = (uint16_t)wire->server_id_len_low | ((uint16_t)wire->server_id_len_high << 8);
    uint16_t sig_len = (uint16_t)wire->signature_len_low | ((uint16_t)wire->signature_len_high << 8);
    memcpy(server_hello.server_id, wire->server_id, server_id_len);
    server_hello.server_id_len = server_id_len;
    memcpy(server_hello.signature, wire->signature, sig_len);
    
    /* Process server hello and generate client hello using original API */
    hdkem_client_hello_t client_hello;
    int result = hdkem_client_process_server_hello(client_keys, &server_hello,
                                                   server_gandalf_pk, k3_qkd,
                                                   &client_hello, &conn->session);
    
    if (result != HDKEM_SUCCESS) {
        return result;
    }
    
    /* Serialize client hello to wire format */
    wire_client_hello_t *wire_resp = (wire_client_hello_t *)response;
    wire_resp->message_type = 0x02;
    memcpy(wire_resp->mlkem_ciphertext, client_hello.mlkem_ciphertext, MLKEM_CIPHERTEXT_SIZE);
    memcpy(wire_resp->x25519_public_key, client_hello.x25519_public_key, X25519_PUBLIC_KEY_SIZE);
    memcpy(wire_resp->client_id, client_hello.client_id, client_hello.client_id_len);
    wire_resp->client_id_len_low = (uint8_t)(client_hello.client_id_len & 0xFF);
    wire_resp->client_id_len_high = (uint8_t)((client_hello.client_id_len >> 8) & 0xFF);
    wire_resp->signature_len_low = (uint8_t)(1356 & 0xFF);
    wire_resp->signature_len_high = (uint8_t)((1356 >> 8) & 0xFF);
    memcpy(wire_resp->signature, client_hello.signature, 1356);
    
    *response_len = sizeof(wire_client_hello_t);
    
    conn->state = STATE_SESSION_ESTABLISHED;
    
    return HDKEM_SUCCESS;
}

int hdkem_client_process_server_finished(hdkem_connection_t *conn,
                                         const uint8_t *buffer,
                                         size_t buffer_len) {
    if (!conn || !buffer) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    if (conn->state != STATE_SESSION_ESTABLISHED) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    const wire_server_finished_t *wire = (const wire_server_finished_t *)buffer;
    
    if (wire->message_type != 0x03) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    /* Decrypt server finished message */
    hdkem_encrypted_msg_t encrypted;
    memcpy(encrypted.nonce, wire->nonce, ASCON_NONCE_SIZE);
    uint16_t encrypted_len = (uint16_t)wire->encrypted_len_low | ((uint16_t)wire->encrypted_len_high << 8);
    memcpy(encrypted.ciphertext, wire->encrypted_finish, encrypted_len);
    encrypted.ciphertext_len = encrypted_len;
    
    uint8_t plaintext[256];
    size_t plaintext_len;
    
    int result = hdkem_decrypt_message(&conn->session, &encrypted, 
                                      plaintext, &plaintext_len);
    
    if (result != HDKEM_SUCCESS) {
        return result;
    }
    
    /* Verify "Server_Finished" prefix */
    if (plaintext_len < 15 || memcmp(plaintext, "Server_Finished", 15) != 0) {
        return HDKEM_ERROR_VERIFICATION;
    }
    
    return HDKEM_SUCCESS;
}

int hdkem_client_send_finished(hdkem_connection_t *conn,
                               const uint8_t *client_id,
                               size_t client_id_len,
                               uint8_t *buffer,
                               size_t *buffer_len) {
    if (!conn || !client_id || !buffer || !buffer_len) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    if (conn->state != STATE_SESSION_ESTABLISHED) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    /* Create "Client_Finished" message */
    uint8_t plaintext[256];
    size_t pt_len = 0;
    
    memcpy(plaintext, "Client_Finished", 15);
    pt_len += 15;
    memcpy(plaintext + pt_len, client_id, client_id_len);
    pt_len += client_id_len;
    
    /* Encrypt with session key */
    hdkem_encrypted_msg_t encrypted;
    int result = hdkem_encrypt_message(&conn->session, plaintext, pt_len, &encrypted);
    if (result != HDKEM_SUCCESS) {
        return result;
    }
    
    /* Serialize to wire format */
    wire_client_finished_t *wire = (wire_client_finished_t *)buffer;
    wire->message_type = 0x04;
    memcpy(wire->nonce, encrypted.nonce, ASCON_NONCE_SIZE);
    memcpy(wire->encrypted_finish, encrypted.ciphertext, encrypted.ciphertext_len);
    wire->encrypted_len_low = (uint8_t)(encrypted.ciphertext_len & 0xFF);
    wire->encrypted_len_high = (uint8_t)((encrypted.ciphertext_len >> 8) & 0xFF);
    
    *buffer_len = sizeof(wire_client_finished_t);
    
    return HDKEM_SUCCESS;
}

/* ===== Application Data Exchange ===== */

int hdkem_send_protocol_data(hdkem_connection_t *conn,
                             const protocol_msg_t *msg,
                             uint8_t *buffer,
                             size_t *buffer_len) {
    if (!conn || !msg || !buffer || !buffer_len) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    if (conn->state != STATE_SESSION_ESTABLISHED) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    /* Serialize protocol-specific message */
    uint8_t plaintext[8192];
    size_t plaintext_len = 0;
    int result;
    
    switch (msg->protocol) {
        case PROTOCOL_ANSI_C12_22:
            result = serialize_c1222_message(&msg->msg.c1222, plaintext, &plaintext_len);
            break;
        case PROTOCOL_DNP3:
            result = serialize_dnp3_message(&msg->msg.dnp3, plaintext, &plaintext_len);
            break;
        case PROTOCOL_IEC61850:
            result = serialize_iec61850_message(&msg->msg.iec61850, plaintext, &plaintext_len);
            break;
        case PROTOCOL_IEEE_C37_118:
            result = serialize_c37118_message(&msg->msg.c37118, plaintext, &plaintext_len);
            break;
        default:
            return HDKEM_ERROR_INVALID_PARAM;
    }
    
    if (result != HDKEM_SUCCESS) {
        return result;
    }
    
    /* Encrypt the payload */
    hdkem_encrypted_msg_t encrypted;
    result = hdkem_encrypt_message(&conn->session, plaintext, plaintext_len, &encrypted);
    if (result != HDKEM_SUCCESS) {
        return result;
    }
    
    /* Create wire format */
    wire_app_data_t *wire = (wire_app_data_t *)buffer;
    wire->message_type = 0x05;
    wire->protocol_type = msg->protocol;
    wire->sequence_number[0] = (uint8_t)(conn->sequence_number & 0xFF);
    wire->sequence_number[1] = (uint8_t)((conn->sequence_number >> 8) & 0xFF);
    wire->sequence_number[2] = (uint8_t)((conn->sequence_number >> 16) & 0xFF);
    wire->sequence_number[3] = (uint8_t)((conn->sequence_number >> 24) & 0xFF);
    conn->sequence_number++;
    memcpy(wire->nonce, encrypted.nonce, ASCON_NONCE_SIZE);
    memcpy(wire->encrypted_data, encrypted.ciphertext, encrypted.ciphertext_len);
    wire->encrypted_len_low = (uint8_t)(encrypted.ciphertext_len & 0xFF);
    wire->encrypted_len_high = (uint8_t)((encrypted.ciphertext_len >> 8) & 0xFF);
    
    *buffer_len = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t) + 
                  ASCON_NONCE_SIZE + sizeof(uint16_t) + encrypted.ciphertext_len;
    
    return HDKEM_SUCCESS;
}

int hdkem_receive_protocol_data(hdkem_connection_t *conn,
                                const uint8_t *buffer,
                                size_t buffer_len,
                                protocol_msg_t *msg) {
    if (!conn || !buffer || !msg) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    if (conn->state != STATE_SESSION_ESTABLISHED) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    const wire_app_data_t *wire = (const wire_app_data_t *)buffer;
    
    if (wire->message_type != 0x05) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    /* Decrypt the payload */
    hdkem_encrypted_msg_t encrypted;
    memcpy(encrypted.nonce, wire->nonce, ASCON_NONCE_SIZE);
    uint16_t encrypted_len = (uint16_t)wire->encrypted_len_low | ((uint16_t)wire->encrypted_len_high << 8);
    memcpy(encrypted.ciphertext, wire->encrypted_data, encrypted_len);
    encrypted.ciphertext_len = encrypted_len;
    
    uint8_t plaintext[8192];
    size_t plaintext_len;
    
    int result = hdkem_decrypt_message(&conn->session, &encrypted, 
                                      plaintext, &plaintext_len);
    if (result != HDKEM_SUCCESS) {
        return result;
    }
    
    /* Deserialize protocol-specific message */
    msg->protocol = (protocol_type_t)wire->protocol_type;
    
    switch (msg->protocol) {
        case PROTOCOL_ANSI_C12_22:
            result = deserialize_c1222_message(plaintext, plaintext_len, &msg->msg.c1222);
            break;
        case PROTOCOL_DNP3:
            result = deserialize_dnp3_message(plaintext, plaintext_len, &msg->msg.dnp3);
            break;
        case PROTOCOL_IEC61850:
            result = deserialize_iec61850_message(plaintext, plaintext_len, &msg->msg.iec61850);
            break;
        case PROTOCOL_IEEE_C37_118:
            result = deserialize_c37118_message(plaintext, plaintext_len, &msg->msg.c37118);
            break;
        default:
            return HDKEM_ERROR_INVALID_PARAM;
    }
    
    return result;
}

/* Protocol serialization implementations in next file... */
