#include "hdkem_protocol.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>

/* ===== ANSI C12.22 Serialization ===== */

int serialize_c1222_message(const ansi_c1222_msg_t *msg, uint8_t *buffer, size_t *len) {
    if (!msg || !buffer || !len) return HDKEM_ERROR_INVALID_PARAM;
    
    size_t offset = 0;
    
    /* Calling AP-Title (20 bytes) */
    memcpy(buffer + offset, msg->calling_aptitle, 20);
    offset += 20;
    
    /* Called AP-Title (20 bytes) */
    memcpy(buffer + offset, msg->called_aptitle, 20);
    offset += 20;
    
    /* EPSEM Control byte */
    buffer[offset++] = msg->epsem_ctrl;
    
    /* Data length (2 bytes, big-endian) */
    uint16_t data_len = htons(msg->data_len);
    memcpy(buffer + offset, &data_len, 2);
    offset += 2;
    
    /* Application data */
    if (msg->data && msg->data_len > 0) {
        memcpy(buffer + offset, msg->data, msg->data_len);
        offset += msg->data_len;
    }
    
    /* CRC16 */
    uint16_t crc = calculate_crc16(buffer, offset);
    crc = htons(crc);
    memcpy(buffer + offset, &crc, 2);
    offset += 2;
    
    *len = offset;
    return HDKEM_SUCCESS;
}

int deserialize_c1222_message(const uint8_t *buffer, size_t len, ansi_c1222_msg_t *msg) {
    if (!buffer || !msg || len < 45) return HDKEM_ERROR_INVALID_PARAM;
    
    size_t offset = 0;
    
    /* Calling AP-Title */
    memcpy(msg->calling_aptitle, buffer + offset, 20);
    offset += 20;
    
    /* Called AP-Title */
    memcpy(msg->called_aptitle, buffer + offset, 20);
    offset += 20;
    
    /* EPSEM Control */
    msg->epsem_ctrl = buffer[offset++];
    
    /* Data length */
    uint16_t data_len;
    memcpy(&data_len, buffer + offset, 2);
    msg->data_len = ntohs(data_len);
    offset += 2;
    
    /* Verify sufficient buffer */
    if (offset + msg->data_len + 2 > len) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    /* Application data */
    msg->data = malloc(msg->data_len);
    if (!msg->data) return HDKEM_ERROR_INVALID_PARAM;
    memcpy(msg->data, buffer + offset, msg->data_len);
    offset += msg->data_len;
    
    /* Verify CRC */
    uint16_t received_crc;
    memcpy(&received_crc, buffer + offset, 2);
    received_crc = ntohs(received_crc);
    
    uint16_t computed_crc = calculate_crc16(buffer, offset);
    if (received_crc != computed_crc) {
        free(msg->data);
        return HDKEM_ERROR_VERIFICATION;
    }
    
    msg->crc = received_crc;
    
    return HDKEM_SUCCESS;
}

/* ===== DNP3 Serialization ===== */

int serialize_dnp3_message(const dnp3_msg_t *msg, uint8_t *buffer, size_t *len) {
    if (!msg || !buffer || !len) return HDKEM_ERROR_INVALID_PARAM;
    
    size_t offset = 0;
    
    /* Start bytes (0x05 0x64) */
    buffer[offset++] = 0x05;
    buffer[offset++] = 0x64;
    
    /* Length */
    buffer[offset++] = msg->length;
    
    /* Control */
    buffer[offset++] = msg->control;
    
    /* Destination address (2 bytes, little-endian) */
    uint16_t dest = msg->dest_addr;
    memcpy(buffer + offset, &dest, 2);
    offset += 2;
    
    /* Source address (2 bytes, little-endian) */
    uint16_t src = msg->src_addr;
    memcpy(buffer + offset, &src, 2);
    offset += 2;
    
    /* Header CRC */
    uint16_t header_crc = calculate_crc16(buffer + 2, 6);
    memcpy(buffer + offset, &header_crc, 2);
    offset += 2;
    
    /* Function code */
    buffer[offset++] = msg->function_code;
    
    /* Application data */
    if (msg->data && msg->data_len > 0) {
        memcpy(buffer + offset, msg->data, msg->data_len);
        offset += msg->data_len;
        
        /* Data CRC */
        uint16_t data_crc = calculate_crc16(buffer + 11, msg->data_len + 1);
        memcpy(buffer + offset, &data_crc, 2);
        offset += 2;
    }
    
    *len = offset;
    return HDKEM_SUCCESS;
}

int deserialize_dnp3_message(const uint8_t *buffer, size_t len, dnp3_msg_t *msg) {
    if (!buffer || !msg || len < 11) return HDKEM_ERROR_INVALID_PARAM;
    
    size_t offset = 0;
    
    /* Verify start bytes */
    if (buffer[offset++] != 0x05 || buffer[offset++] != 0x64) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    msg->start_bytes[0] = 0x05;
    msg->start_bytes[1] = 0x64;
    
    /* Length */
    msg->length = buffer[offset++];
    
    /* Control */
    msg->control = buffer[offset++];
    
    /* Addresses */
    memcpy(&msg->dest_addr, buffer + offset, 2);
    offset += 2;
    memcpy(&msg->src_addr, buffer + offset, 2);
    offset += 2;
    
    /* Verify header CRC */
    uint16_t received_crc;
    memcpy(&received_crc, buffer + offset, 2);
    offset += 2;
    
    uint16_t computed_crc = calculate_crc16(buffer + 2, 6);
    if (received_crc != computed_crc) {
        return HDKEM_ERROR_VERIFICATION;
    }
    msg->crc = received_crc;
    
    /* Function code */
    msg->function_code = buffer[offset++];
    
    /* Application data */
    if (offset < len - 2) {
        msg->data_len = len - offset - 2;
        msg->data = malloc(msg->data_len);
        if (!msg->data) return HDKEM_ERROR_INVALID_PARAM;
        memcpy(msg->data, buffer + offset, msg->data_len);
        offset += msg->data_len;
        
        /* Verify data CRC */
        memcpy(&received_crc, buffer + offset, 2);
        computed_crc = calculate_crc16(buffer + 11, msg->data_len + 1);
        if (received_crc != computed_crc) {
            free(msg->data);
            return HDKEM_ERROR_VERIFICATION;
        }
    } else {
        msg->data = NULL;
        msg->data_len = 0;
    }
    
    return HDKEM_SUCCESS;
}

/* ===== IEC 61850 MMS Serialization ===== */

int serialize_iec61850_message(const iec61850_msg_t *msg, uint8_t *buffer, size_t *len) {
    if (!msg || !buffer || !len) return HDKEM_ERROR_INVALID_PARAM;
    
    size_t offset = 0;
    
    /* Service type */
    buffer[offset++] = msg->service_type;
    
    /* Invoke ID */
    buffer[offset++] = msg->invoke_id;
    
    /* Domain name length */
    uint8_t domain_len = strlen((char*)msg->domain_name);
    buffer[offset++] = domain_len;
    memcpy(buffer + offset, msg->domain_name, domain_len);
    offset += domain_len;
    
    /* Item name length */
    uint8_t item_len = strlen((char*)msg->item_name);
    buffer[offset++] = item_len;
    memcpy(buffer + offset, msg->item_name, item_len);
    offset += item_len;
    
    /* Data length (2 bytes, big-endian) */
    uint16_t data_len = htons(msg->data_len);
    memcpy(buffer + offset, &data_len, 2);
    offset += 2;
    
    /* MMS PDU data */
    if (msg->data && msg->data_len > 0) {
        memcpy(buffer + offset, msg->data, msg->data_len);
        offset += msg->data_len;
    }
    
    *len = offset;
    return HDKEM_SUCCESS;
}

int deserialize_iec61850_message(const uint8_t *buffer, size_t len, iec61850_msg_t *msg) {
    if (!buffer || !msg || len < 6) return HDKEM_ERROR_INVALID_PARAM;
    
    size_t offset = 0;
    
    /* Service type */
    msg->service_type = buffer[offset++];
    
    /* Invoke ID */
    msg->invoke_id = buffer[offset++];
    
    /* Domain name */
    uint8_t domain_len = buffer[offset++];
    if (offset + domain_len > len) return HDKEM_ERROR_INVALID_PARAM;
    memcpy(msg->domain_name, buffer + offset, domain_len);
    msg->domain_name[domain_len] = '\0';
    offset += domain_len;
    
    /* Item name */
    uint8_t item_len = buffer[offset++];
    if (offset + item_len + 2 > len) return HDKEM_ERROR_INVALID_PARAM;
    memcpy(msg->item_name, buffer + offset, item_len);
    msg->item_name[item_len] = '\0';
    offset += item_len;
    
    /* Data length */
    uint16_t data_len;
    memcpy(&data_len, buffer + offset, 2);
    msg->data_len = ntohs(data_len);
    offset += 2;
    
    /* Verify buffer size */
    if (offset + msg->data_len > len) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    /* MMS PDU data */
    if (msg->data_len > 0) {
        msg->data = malloc(msg->data_len);
        if (!msg->data) return HDKEM_ERROR_INVALID_PARAM;
        memcpy(msg->data, buffer + offset, msg->data_len);
    } else {
        msg->data = NULL;
    }
    
    return HDKEM_SUCCESS;
}

/* ===== IEEE C37.118.2 Serialization ===== */

int serialize_c37118_message(const c37118_msg_t *msg, uint8_t *buffer, size_t *len) {
    if (!msg || !buffer || !len) return HDKEM_ERROR_INVALID_PARAM;
    
    size_t offset = 0;
    
    /* SYNC byte (0xAA for data frames) */
    buffer[offset++] = msg->sync;
    
    /* Frame type and version */
    buffer[offset++] = msg->frame_type;
    
    /* Frame size (2 bytes, big-endian) */
    uint16_t frame_size = htons(msg->frame_size);
    memcpy(buffer + offset, &frame_size, 2);
    offset += 2;
    
    /* ID Code (2 bytes, big-endian) */
    uint16_t idcode = htons(msg->idcode);
    memcpy(buffer + offset, &idcode, 2);
    offset += 2;
    
    /* SOC - Second of Century (4 bytes, big-endian) */
    uint32_t soc = htonl(msg->soc);
    memcpy(buffer + offset, &soc, 4);
    offset += 4;
    
    /* FRACSEC - Fraction of second (4 bytes, big-endian) */
    uint32_t fracsec = htonl(msg->fracsec);
    memcpy(buffer + offset, &fracsec, 4);
    offset += 4;
    
    /* PMU data */
    if (msg->data && msg->data_len > 0) {
        memcpy(buffer + offset, msg->data, msg->data_len);
        offset += msg->data_len;
    }
    
    /* CHK - CRC-CCITT (2 bytes, big-endian) */
    uint16_t crc = calculate_crc_ccitt(buffer, offset);
    crc = htons(crc);
    memcpy(buffer + offset, &crc, 2);
    offset += 2;
    
    *len = offset;
    return HDKEM_SUCCESS;
}

int deserialize_c37118_message(const uint8_t *buffer, size_t len, c37118_msg_t *msg) {
    if (!buffer || !msg || len < 18) return HDKEM_ERROR_INVALID_PARAM;
    
    size_t offset = 0;
    
    /* SYNC byte */
    msg->sync = buffer[offset++];
    
    /* Frame type */
    msg->frame_type = buffer[offset++];
    
    /* Frame size */
    uint16_t frame_size;
    memcpy(&frame_size, buffer + offset, 2);
    msg->frame_size = ntohs(frame_size);
    offset += 2;
    
    /* Verify frame size matches buffer */
    if (msg->frame_size != len) {
        return HDKEM_ERROR_INVALID_PARAM;
    }
    
    /* ID Code */
    uint16_t idcode;
    memcpy(&idcode, buffer + offset, 2);
    msg->idcode = ntohs(idcode);
    offset += 2;
    
    /* SOC */
    uint32_t soc;
    memcpy(&soc, buffer + offset, 4);
    msg->soc = ntohl(soc);
    offset += 4;
    
    /* FRACSEC */
    uint32_t fracsec;
    memcpy(&fracsec, buffer + offset, 4);
    msg->fracsec = ntohl(fracsec);
    offset += 4;
    
    /* PMU data */
    msg->data_len = len - offset - 2;
    if (msg->data_len > 0) {
        msg->data = malloc(msg->data_len);
        if (!msg->data) return HDKEM_ERROR_INVALID_PARAM;
        memcpy(msg->data, buffer + offset, msg->data_len);
        offset += msg->data_len;
    } else {
        msg->data = NULL;
    }
    
    /* Verify CRC-CCITT */
    uint16_t received_crc;
    memcpy(&received_crc, buffer + offset, 2);
    received_crc = ntohs(received_crc);
    
    uint16_t computed_crc = calculate_crc_ccitt(buffer, offset);
    if (received_crc != computed_crc) {
        if (msg->data) free(msg->data);
        return HDKEM_ERROR_VERIFICATION;
    }
    msg->chk = received_crc;
    
    return HDKEM_SUCCESS;
}
