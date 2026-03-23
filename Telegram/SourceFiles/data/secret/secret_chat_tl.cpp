#include "data/secret/secret_chat_tl.h"
#include "data/secret/secret_chat_state.h"

namespace Data::SecretChats {

uint32_t ReadLE32(const char *data) {
	uint32_t value = 0;
	std::memcpy(&value, data, sizeof(value));
	return value;
}

uint64_t ReadLE64(const char *data) {
	uint64_t value = 0;
	std::memcpy(&value, data, sizeof(value));
	return value;
}

QString BytesToHex(const QByteArray &data, int maxBytes) {
	const auto slice = (maxBytes >= 0) ? data.left(maxBytes) : data;
	return QString::fromLatin1(slice.toHex());
}

bool SecretTlReader::CanRead(int bytes) const {
	return (bytes >= 0) && (offset >= 0) && (offset + bytes <= limit);
}

std::optional<uint32_t> SecretTlReader::ReadUInt32() {
	if (!CanRead(4)) {
		return std::nullopt;
	}
	const auto value = ReadLE32(data.constData() + offset);
	offset += 4;
	return value;
}

std::optional<int32_t> SecretTlReader::ReadInt32() {
	const auto value = ReadUInt32();
	if (!value.has_value()) {
		return std::nullopt;
	}
	return static_cast<int32_t>(*value);
}

std::optional<uint64_t> SecretTlReader::ReadUInt64() {
	if (!CanRead(8)) {
		return std::nullopt;
	}
	const auto value = ReadLE64(data.constData() + offset);
	offset += 8;
	return value;
}

std::optional<QByteArray> SecretTlReader::ReadTLBytes() {
	if (!CanRead(1)) {
		return std::nullopt;
	}

	const auto first = static_cast<uchar>(data[offset]);
	int length = 0;
	int headerSize = 0;

	if (first < 254) {
		length = first;
		headerSize = 1;
	} else {
		if (!CanRead(4)) {
			return std::nullopt;
		}
		length = static_cast<uchar>(data[offset + 1])
			| (static_cast<uchar>(data[offset + 2]) << 8)
			| (static_cast<uchar>(data[offset + 3]) << 16);
		headerSize = 4;
	}

	const auto padded = ((headerSize + length) + 3) & ~3;
	if (!CanRead(padded)) {
		return std::nullopt;
	}

	const auto result = data.mid(offset + headerSize, length);
	offset += padded;
	return result;
}

std::optional<QString> SecretTlReader::ReadTLString() {
	const auto bytes = ReadTLBytes();
	if (!bytes.has_value()) {
		return std::nullopt;
	}
	return QString::fromUtf8(bytes->constData(), bytes->size());
}

QString SecretMessageEntityName(uint32_t constructor) {
	switch (constructor) {
	case 0xfa04579d: return QStringLiteral("mention");
	case 0x6f635b0d: return QStringLiteral("hashtag");
	case 0x6cef8ac7: return QStringLiteral("bot_command");
	case 0x6ed02538: return QStringLiteral("url");
	case 0x64e475c2: return QStringLiteral("email");
	case 0xbd610bc9: return QStringLiteral("bold");
	case 0x826f8b60: return QStringLiteral("italic");
	case 0x28a20571: return QStringLiteral("code");
	case 0x73924be0: return QStringLiteral("pre");
	case 0x32ca960f: return QStringLiteral("spoiler");
	case 0x76a6d327: return QStringLiteral("text_url");
	case 0x9c4e7e8b: return QStringLiteral("underline");
	case 0xbf0693d4: return QStringLiteral("strike");
	case 0x020df5d0: return QStringLiteral("blockquote");
	case 0xc8cf05f8: return QStringLiteral("custom_emoji");
	default: return QString("unknown(%1)").arg(FormatUint32Hex(constructor));
	}
}

QString SecretMediaConstructorName(uint32_t constructor) {
	switch (constructor) {
	case 0x089f5c4a: return QStringLiteral("decryptedMessageMediaEmpty");
	case 0xf1fa8d78: return QStringLiteral("decryptedMessageMediaPhoto");
	case 0x970c8c0e: return QStringLiteral("decryptedMessageMediaVideo");
	case 0x7afe8ae2: return QStringLiteral("decryptedMessageMediaDocument");
	case 0x6abd9782: return QStringLiteral("decryptedMessageMediaDocument(layer143+)");
	case 0x57e0a9cb: return QStringLiteral("decryptedMessageMediaAudio");
	case 0xfa95b0dd: return QStringLiteral("decryptedMessageMediaExternalDocument");
	case 0x8a0df56f: return QStringLiteral("decryptedMessageMediaVenue");
	case 0xe50511d8: return QStringLiteral("decryptedMessageMediaWebPage");
	default: return QString("unknown(%1)").arg(FormatUint32Hex(constructor));
	}
}

QString SecretServiceActionName(uint32_t constructor) {
	switch (constructor) {
	case 0xa1733aec: return QStringLiteral("set_ttl");
	case 0x0c4f40be: return QStringLiteral("read_messages");
	case 0x65614304: return QStringLiteral("delete_messages");
	case 0x8ac1f475: return QStringLiteral("screenshot_messages");
	case 0x6719e45c: return QStringLiteral("flush_history");
	case 0x511110b0: return QStringLiteral("resend");
	case 0xf3048883: return QStringLiteral("notify_layer");
	case 0xccb27641: return QStringLiteral("typing");
	case 0xf3c9611b: return QStringLiteral("request_key");
	case 0x6fe1735b: return QStringLiteral("accept_key");
	case 0xdd05ec6b: return QStringLiteral("abort_key");
	case 0xec2e0b9b: return QStringLiteral("commit_key");
	case 0xa82fdd63: return QStringLiteral("noop");
	default: return QString("unknown(%1)").arg(FormatUint32Hex(constructor));
	}
}

// Append a little-endian uint32 TL field.
void AppendUInt32(QByteArray &data, uint32_t value) {
	data.append(reinterpret_cast<const char*>(&value), sizeof(value));
}

// Append a little-endian int32 TL field.
void AppendInt32(QByteArray &data, int32_t value) {
	AppendUInt32(data, static_cast<uint32_t>(value));
}

// Append a little-endian uint64 TL field.
void AppendUInt64(QByteArray &data, uint64_t value) {
	data.append(reinterpret_cast<const char*>(&value), sizeof(value));
}

// Append a TL bytes field with 4-byte padding.
void AppendTLBytes(QByteArray &data, const QByteArray &value) {
	const auto size = value.size();
	if (size < 254) {
		data.push_back(char(size));
	} else {
		data.push_back(char(254));
		data.push_back(char(size & 0xFF));
		data.push_back(char((size >> 8) & 0xFF));
		data.push_back(char((size >> 16) & 0xFF));
	}
	data.append(value);
	const auto header = (size < 254) ? 1 : 4;
	const auto padded = ((header + size) + 3) & ~3;
	for (auto i = header + size; i != padded; ++i) {
		data.push_back(char(0));
	}
}

// Append a UTF-8 TL string field.
void AppendTLString(QByteArray &data, const QString &value) {
	AppendTLBytes(data, value.toUtf8());
}

} // namespace Data::SecretChats