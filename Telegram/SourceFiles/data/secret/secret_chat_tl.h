#pragma once

#include <QByteArray>
#include <QString>
#include <optional>
#include <cstdint>

namespace Data::SecretChats {

constexpr uint32_t kSecretOuterLayerConstructor = 0x1be31789; // decryptedMessageLayer
constexpr uint32_t kSecretInnerMessageV73 = 0x91cc4674;       // decryptedMessage
constexpr uint32_t kSecretInnerServiceV17 = 0x73164160;       // decryptedMessageService
constexpr uint32_t kTlVectorConstructor = 0x1cb5c415;         // vector

constexpr int kMinSecretRandomBytes = 15;
constexpr int kMinMtproto2Padding = 12;
constexpr int kMaxMtproto2Padding = 1024;

uint32_t ReadLE32(const char *data);
uint64_t ReadLE64(const char *data);
QString BytesToHex(const QByteArray &data, int maxBytes = -1);
QString SecretMessageEntityName(uint32_t constructor);
QString SecretMediaConstructorName(uint32_t constructor);
QString SecretServiceActionName(uint32_t constructor);

void AppendUInt32(QByteArray &data, uint32_t value);
void AppendInt32(QByteArray &data, int32_t value);
void AppendUInt64(QByteArray &data, uint64_t value);
void AppendTLBytes(QByteArray &data, const QByteArray &value);
void AppendTLString(QByteArray &data, const QString &value);

struct SecretTlReader {
	const QByteArray &data;
	int offset = 0;
	int limit = 0;

	[[nodiscard]] bool CanRead(int bytes) const;
	[[nodiscard]] std::optional<uint32_t> ReadUInt32();
	[[nodiscard]] std::optional<int32_t> ReadInt32();
	[[nodiscard]] std::optional<uint64_t> ReadUInt64();
	[[nodiscard]] std::optional<QByteArray> ReadTLBytes();
	[[nodiscard]] std::optional<QString> ReadTLString();
};

} // namespace Data::SecretChats