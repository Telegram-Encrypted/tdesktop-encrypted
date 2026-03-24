#pragma once

#include "mtproto/mtproto_auth_key.h"

#include <QByteArray>
#include <QString>
#include <cstdint>

namespace Data::SecretChats {

struct SecretChatState {
	int64_t chat_id = 0;            // encryptedChat.id
	uint64_t access_hash = 0;       // encryptedChat.access_hash
	uint64_t admin_id = 0;          // encryptedChat.admin_id
	uint64_t participant_id = 0;    // encryptedChat.participant_id
	bool is_creator = false;        // true if we initiated the secret chat
	int32_t layer = 73;             // current secret chat layer
	int32_t incoming_sequence = 0;  // count of content-related messages received
	int32_t outgoing_sequence = 0;  // count of content-related messages sent
	uint64_t key_fingerprint = 0;   // low 64 bits of SHA1(auth_key)
	MTP::AuthKey::Data auth_key;    // 256-byte shared key
	QByteArray pending_random_power; // creator-side DH secret until encryptedChat arrives
};

QString FormatUint64(uint64_t value);
QString FormatUint32Hex(uint32_t value);

} // namespace Data::SecretChats