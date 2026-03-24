#include "data/secret/secret_chat_storage.h"

#include "logs.h"
#include "main/main_session.h"
#include "storage/storage_account.h"

#include <QBuffer>
#include <QMap>

#include <cstring>

namespace Data::SecretChats {
namespace {

constexpr auto kSecretStorageBlobKey = "secret-chat-storage-v1";
constexpr auto kSecretStorageMagic = quint32(0x53434331);
constexpr auto kSecretStorageVersion = quint32(3);

enum class MessageKind : quint32 {
	Text = 1,
	Service = 2,
	Unsupported = 3,
};

struct SecretStore {
	QMap<int64_t, SecretChatState> states;
	QMap<int64_t, QVector<SecretParsedMessage>> messages;
};

SecretChatDescriptor ToDescriptor(const SecretChatState &state) {
	return SecretChatDescriptor{
		.chatId = state.chat_id,
		.accessHash = state.access_hash,
		.adminId = state.admin_id,
		.participantId = state.participant_id,
		.isCreator = state.is_creator,
	};
}

void SerializeEnvelope(QDataStream &stream, const SecretParsedEnvelope &envelope) {
	stream
		<< qint32(envelope.layer)
		<< qint32(envelope.inSeqNo)
		<< qint32(envelope.outSeqNo)
		<< bool(envelope.outgoing)
		<< qint32(envelope.date);
}

bool DeserializeEnvelope(QDataStream &stream, SecretParsedEnvelope &envelope) {
	auto layer = qint32();
	auto inSeqNo = qint32();
	auto outSeqNo = qint32();
	auto outgoing = false;
	auto date = qint32();
	stream >> layer >> inSeqNo >> outSeqNo >> outgoing >> date;
	if (stream.status() != QDataStream::Ok) {
		return false;
	}
	envelope.layer = layer;
	envelope.inSeqNo = inSeqNo;
	envelope.outSeqNo = outSeqNo;
	envelope.outgoing = outgoing;
	envelope.date = date;
	return true;
}

void SerializeMessage(QDataStream &stream, const SecretParsedMessage &message) {
	if (const auto text = std::get_if<SecretParsedTextMessage>(&message)) {
		stream << quint32(MessageKind::Text) << qint64(text->chatId);
		SerializeEnvelope(stream, text->envelope);
		stream
			<< quint64(text->randomId)
			<< quint64(text->replyToRandomId)
			<< quint32(text->flags)
			<< qint32(text->ttl);
		stream << text->text;
		stream << quint32(text->entities.size());
		for (const auto &entity : text->entities) {
			stream
				<< quint32(entity.constructor)
				<< qint32(entity.offset)
				<< qint32(entity.length)
				<< entity.data;
		}
		return;
	}
	if (const auto service = std::get_if<SecretParsedServiceMessage>(&message)) {
		stream << quint32(MessageKind::Service) << qint64(service->chatId);
		SerializeEnvelope(stream, service->envelope);
		stream << quint64(service->randomId) << quint32(service->actionConstructor);
		return;
	}
	const auto unsupported = std::get_if<SecretParsedUnsupportedMessage>(&message);
	if (!unsupported) {
		return;
	}
	stream << quint32(MessageKind::Unsupported) << qint64(unsupported->chatId);
	SerializeEnvelope(stream, unsupported->envelope);
	stream << quint32(unsupported->constructor) << unsupported->description;
}

std::optional<SecretParsedMessage> DeserializeMessage(
		QDataStream &stream,
		quint32 version) {
	auto kind = quint32();
	auto chatId = qint64();
	stream >> kind >> chatId;
	if (stream.status() != QDataStream::Ok) {
		return std::nullopt;
	}

	auto envelope = SecretParsedEnvelope();
	if (!DeserializeEnvelope(stream, envelope)) {
		return std::nullopt;
	}

	switch (MessageKind(kind)) {
	case MessageKind::Text: {
		auto randomId = quint64();
		auto replyToRandomId = quint64();
		auto flags = quint32();
		auto ttl = qint32();
		auto text = QString();
		auto count = quint32();
		stream >> randomId;
		if (version >= 2) {
			stream >> replyToRandomId;
		}
		stream >> flags >> ttl >> text >> count;
		if (stream.status() != QDataStream::Ok) {
			return std::nullopt;
		}
		auto entities = QVector<SecretParsedEntity>();
		entities.reserve(int(count));
		for (auto i = quint32(); i != count; ++i) {
			auto constructor = quint32();
			auto offset = qint32();
			auto length = qint32();
			auto data = QString();
			stream >> constructor >> offset >> length;
			if (version >= 2) {
				stream >> data;
			}
			if (stream.status() != QDataStream::Ok) {
				return std::nullopt;
			}
			entities.push_back(SecretParsedEntity{
				.constructor = uint32_t(constructor),
				.offset = int32_t(offset),
				.length = int32_t(length),
				.data = std::move(data),
			});
		}
		return SecretParsedTextMessage{
			.chatId = chatId,
			.envelope = envelope,
			.randomId = randomId,
			.replyToRandomId = replyToRandomId,
			.flags = flags,
			.ttl = ttl,
			.text = std::move(text),
			.entities = std::move(entities),
		};
	}
	case MessageKind::Service: {
		auto randomId = quint64();
		auto actionConstructor = quint32();
		stream >> randomId >> actionConstructor;
		if (stream.status() != QDataStream::Ok) {
			return std::nullopt;
		}
		return SecretParsedServiceMessage{
			.chatId = chatId,
			.envelope = envelope,
			.randomId = randomId,
			.actionConstructor = actionConstructor,
		};
	}
	case MessageKind::Unsupported: {
		auto constructor = quint32();
		auto description = QString();
		stream >> constructor >> description;
		if (stream.status() != QDataStream::Ok) {
			return std::nullopt;
		}
		return SecretParsedUnsupportedMessage{
			.chatId = chatId,
			.envelope = envelope,
			.constructor = constructor,
			.description = std::move(description),
		};
	}
	}

	return std::nullopt;
}

QByteArray SerializeStore(const SecretStore &store) {
	auto bytes = QByteArray();
	auto buffer = QBuffer(&bytes);
	buffer.open(QIODevice::WriteOnly);
	auto stream = QDataStream(&buffer);

	// The secret-chat blob is versioned so later migrations can stay explicit.
	stream << kSecretStorageMagic << kSecretStorageVersion;
	stream << quint32(store.states.size());
	for (auto i = store.states.cbegin(); i != store.states.cend(); ++i) {
		const auto &state = i.value();
		const auto authKey = QByteArray(
			reinterpret_cast<const char*>(state.auth_key.data()),
			int(state.auth_key.size()));
		stream
			<< qint64(i.key())
			<< qint64(state.chat_id)
			<< quint64(state.access_hash)
			<< quint64(state.admin_id)
			<< quint64(state.participant_id)
			<< bool(state.is_creator)
			<< qint32(state.layer)
			<< qint32(state.incoming_sequence)
			<< qint32(state.outgoing_sequence)
			<< quint64(state.key_fingerprint)
			<< authKey
			<< state.pending_random_power;
	}
	stream << quint32(store.messages.size());
	for (auto i = store.messages.cbegin(); i != store.messages.cend(); ++i) {
		stream << qint64(i.key()) << quint32(i.value().size());
		for (const auto &message : i.value()) {
			SerializeMessage(stream, message);
		}
	}
	return bytes;
}

std::optional<SecretStore> DeserializeStore(const QByteArray &bytes) {
	auto buffer = QBuffer();
	buffer.setData(bytes);
	if (!buffer.open(QIODevice::ReadOnly)) {
		return std::nullopt;
	}
	auto stream = QDataStream(&buffer);
	auto magic = quint32();
	auto version = quint32();
	stream >> magic >> version;
	if (stream.status() != QDataStream::Ok
		|| magic != kSecretStorageMagic
		|| (version != 1 && version != 2 && version != kSecretStorageVersion)) {
		return std::nullopt;
	}

	auto result = SecretStore();
	auto stateCount = quint32();
	stream >> stateCount;
	for (auto i = quint32(); i != stateCount; ++i) {
		auto key = qint64();
		auto chatId = qint64();
		auto accessHash = quint64();
		auto adminId = quint64();
		auto participantId = quint64();
		auto isCreator = false;
		auto layer = qint32();
		auto incomingSequence = qint32();
		auto outgoingSequence = qint32();
		auto keyFingerprint = quint64();
		auto authKey = QByteArray();
		auto pendingRandomPower = QByteArray();
		stream
			>> key
			>> chatId
			>> accessHash
			>> adminId
			>> participantId
			>> isCreator
			>> layer
			>> incomingSequence
			>> outgoingSequence
			>> keyFingerprint
			>> authKey;
		if (version >= 3) {
			stream >> pendingRandomPower;
		}
		if (stream.status() != QDataStream::Ok
			|| authKey.size() != int(MTP::AuthKey::kSize)) {
			return std::nullopt;
		}
		auto state = SecretChatState{
			.chat_id = chatId,
			.access_hash = accessHash,
			.admin_id = adminId,
			.participant_id = participantId,
			.is_creator = isCreator,
			.layer = layer,
			.incoming_sequence = incomingSequence,
			.outgoing_sequence = outgoingSequence,
			.key_fingerprint = keyFingerprint,
			.pending_random_power = std::move(pendingRandomPower),
		};
		std::memcpy(state.auth_key.data(), authKey.constData(), size_t(authKey.size()));
		result.states.insert(key, state);
	}

	auto messagesCount = quint32();
	stream >> messagesCount;
	for (auto i = quint32(); i != messagesCount; ++i) {
		auto chatId = qint64();
		auto count = quint32();
		stream >> chatId >> count;
		if (stream.status() != QDataStream::Ok) {
			return std::nullopt;
		}
		auto messages = QVector<SecretParsedMessage>();
		messages.reserve(int(count));
		for (auto j = quint32(); j != count; ++j) {
			const auto message = DeserializeMessage(stream, version);
			if (!message.has_value()) {
				return std::nullopt;
			}
			messages.push_back(*message);
		}
		result.messages.insert(chatId, std::move(messages));
	}

	if (stream.status() != QDataStream::Ok) {
		return std::nullopt;
	}
	return result;
}

SecretStore ReadStore(Main::Session *session) {
	if (!session) {
		return {};
	}
	const auto bytes = session->local().readBlob(kSecretStorageBlobKey);
	if (!bytes.isEmpty()) {
		if (const auto store = DeserializeStore(bytes); store.has_value()) {
			return *store;
		}
		LOG(("1337 SecretChat: encrypted storage blob is unreadable, starting from empty store"));
		return {};
	}
	return {};
}

bool WriteStore(Main::Session *session, const SecretStore &store) {
	if (!session) {
		return false;
	}
	session->local().writeBlob(kSecretStorageBlobKey, SerializeStore(store));
	return true;
}

} // namespace

bool SaveSecretChatState(Main::Session *session, const SecretChatState &state) {
	auto store = ReadStore(session);
	store.states.insert(state.chat_id, state);
	LOG(("1337 SecretChat: saved encrypted state chat_id=%1 key_fingerprint=%2 layer=%3 in_seq=%4 out_seq=%5")
		.arg(state.chat_id)
		.arg(FormatUint64(state.key_fingerprint))
		.arg(state.layer)
		.arg(state.incoming_sequence)
		.arg(state.outgoing_sequence));
	return WriteStore(session, store);
}

std::optional<SecretChatState> LoadSecretChatState(Main::Session *session, int64_t chatId) {
	const auto store = ReadStore(session);
	const auto i = store.states.find(chatId);
	if (i == store.states.end()) {
		LOG(("1337 SecretChat: no encrypted state for chat_id=%1").arg(chatId));
		return std::nullopt;
	}
	const auto &state = i.value();
	LOG(("1337 SecretChat: loaded encrypted state for chat_id=%1 key_fingerprint=%2 is_creator=%3 layer=%4 in_seq=%5 out_seq=%6")
		.arg(state.chat_id)
		.arg(FormatUint64(state.key_fingerprint))
		.arg(state.is_creator ? 1 : 0)
		.arg(state.layer)
		.arg(state.incoming_sequence)
		.arg(state.outgoing_sequence));
	return state;
}

QVector<SecretChatDescriptor> LoadAllSecretChats(Main::Session *session) {
	auto result = QVector<SecretChatDescriptor>();
	const auto store = ReadStore(session);
	result.reserve(store.states.size());
	for (auto i = store.states.cbegin(); i != store.states.cend(); ++i) {
		result.push_back(ToDescriptor(i.value()));
	}
	LOG(("1337 SecretChat: enumerated encrypted secret chats count=%1")
		.arg(result.size()));
	return result;
}

bool SaveSecretChatMessages(
		Main::Session *session,
		int64_t chatId,
		const QVector<SecretParsedMessage> &messages) {
	auto store = ReadStore(session);
	store.messages.insert(chatId, messages);
	LOG(("1337 SecretChat: saved encrypted message history chat_id=%1 count=%2")
		.arg(chatId)
		.arg(messages.size()));
	return WriteStore(session, store);
}

QVector<SecretParsedMessage> LoadSecretChatMessages(
		Main::Session *session,
		int64_t chatId) {
	const auto store = ReadStore(session);
	const auto i = store.messages.find(chatId);
	if (i == store.messages.end()) {
		return {};
	}
	LOG(("1337 SecretChat: loaded encrypted message history chat_id=%1 count=%2")
		.arg(chatId)
		.arg(i.value().size()));
	return i.value();
}

bool DeleteSecretChat(Main::Session *session, int64_t chatId) {
	auto store = ReadStore(session);
	const auto removedState = store.states.remove(chatId);
	const auto removedMessages = store.messages.remove(chatId);
	LOG(("1337 SecretChat: deleted encrypted secret chat chat_id=%1 removed_state=%2 removed_messages=%3")
		.arg(chatId)
		.arg(removedState)
		.arg(removedMessages));
	return WriteStore(session, store);
}

} // namespace Data::SecretChats