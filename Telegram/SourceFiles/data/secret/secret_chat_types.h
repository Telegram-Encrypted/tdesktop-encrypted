#pragma once

#include "base/basic_types.h"

#include <QString>
#include <QVector>

#include <cstdint>
#include <variant>

namespace Data::SecretChats {

struct SecretParsedEnvelope {
	int32_t layer = 0;
	int32_t inSeqNo = 0;
	int32_t outSeqNo = 0;
	bool outgoing = false;
	TimeId date = 0;
};

struct SecretChatDescriptor {
	int64_t chatId = 0;
	uint64_t accessHash = 0;
	uint64_t adminId = 0;
	uint64_t participantId = 0;
	bool isCreator = false;
};

struct SecretParsedEntity {
	uint32_t constructor = 0;
	int32_t offset = 0;
	int32_t length = 0;
	QString data;
};

struct SecretParsedTextMessage {
	int64_t chatId = 0;
	SecretParsedEnvelope envelope;
	uint64_t randomId = 0;
	uint64_t replyToRandomId = 0;
	uint32_t flags = 0;
	int32_t ttl = 0;
	QString text;
	QVector<SecretParsedEntity> entities;
};

struct SecretParsedServiceMessage {
	int64_t chatId = 0;
	SecretParsedEnvelope envelope;
	uint64_t randomId = 0;
	uint32_t actionConstructor = 0;
};

struct SecretParsedUnsupportedMessage {
	int64_t chatId = 0;
	SecretParsedEnvelope envelope;
	uint32_t constructor = 0;
	QString description;
};

using SecretParsedMessage = std::variant<
	SecretParsedTextMessage,
	SecretParsedServiceMessage,
	SecretParsedUnsupportedMessage>;

} // namespace Data::SecretChats