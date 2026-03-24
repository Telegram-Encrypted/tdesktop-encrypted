#include "data/secret/secret_chat_manager.h"
#include "data/secret/secret_chat_crypto.h"
#include "data/secret/secret_chat_parser.h"
#include "data/secret/secret_chat_storage.h"
#include "data/secret/secret_chat_tl.h"
#include "data/secret/secret_chat_types.h"
#include "data/data_peer.h"
#include "data/data_changes.h"
#include "data/data_peer_values.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "dialogs/dialogs_key.h"
#include "dialogs/secret_chat_entry.h"
#include "history/history.h"
#include "history/history_item.h"
#include "ui/text/text_entity.h"

#include "base/unixtime.h"
#include "base/random.h"
#include "base/timer.h"
#include "logs.h"
#include "main/main_session.h"
#include "mtproto/mtproto_dh_utils.h"
#include "apiwrap.h"

#include "base/openssl_help.h"

#include <lang_auto.h>

#include <map>

namespace Data::SecretChats {

namespace {

constexpr auto kSecretTypingTimeout = 6 * crl::time(1000);
constexpr auto kSecretTypingCancelTimeout = 5 * crl::time(1000);
constexpr auto kSecretSendMyTypingInterval = 5 * crl::time(1000);
constexpr auto kSecretLayer = 73;

} // namespace

struct SecretChatManager::RenderState {
	PeerId peerId = 0;
	not_null<History*> history;
	std::vector<FullMsgId> ids;
	std::map<uint64_t, FullMsgId> randomIds;
	std::map<FullMsgId, uint64_t> reverseRandomIds;
};

namespace {

// Transform a raw incoming counter into the protected seq_no form.
[[nodiscard]] int32_t SecretInSeqNo(
		const SecretChatState &state,
		int32_t raw) {
	const auto parity = state.is_creator ? 0 : 1;
	return (raw * 2) + parity;
}

// Transform a raw outgoing counter into the protected seq_no form.
[[nodiscard]] int32_t SecretOutSeqNo(
		const SecretChatState &state,
		int32_t raw) {
	const auto parity = state.is_creator ? 1 : 0;
	return (raw * 2) + parity;
}

// Recover the raw incoming counter from a received out_seq_no.
[[nodiscard]] std::optional<int32_t> RawIncomingSequence(
		const SecretChatState &state,
		int32_t outSeqNo) {
	const auto parity = state.is_creator ? 0 : 1;
	if ((outSeqNo < parity) || (((outSeqNo - parity) % 2) != 0)) {
		return std::nullopt;
	}
	return (outSeqNo - parity) / 2;
}

// Read the common envelope metadata from any parsed secret message.
[[nodiscard]] const SecretParsedEnvelope &MessageEnvelope(
		const SecretParsedMessage &message) {
	return std::visit([](const auto &value) -> const SecretParsedEnvelope& {
		return value.envelope;
	}, message);
}

[[nodiscard]] std::optional<UserId> RemoteUserIdForState(
		not_null<Main::Session*> session,
		const SecretChatState &state) {
	const auto selfId = session->userId();
	const auto adminId = UserId(state.admin_id);
	const auto participantId = UserId(state.participant_id);
	if (adminId == selfId) {
		return participantId;
	} else if (participantId == selfId) {
		return adminId;
	}
	const auto resolved = state.is_creator ? participantId : adminId;
	return resolved ? std::optional<UserId>(resolved) : std::nullopt;
}

[[nodiscard]] SecretChatDescriptor DescriptorFromState(
		const SecretChatState &state) {
	return SecretChatDescriptor{
		.chatId = state.chat_id,
		.accessHash = state.access_hash,
		.adminId = state.admin_id,
		.participantId = state.participant_id,
		.isCreator = state.is_creator,
	};
}

[[nodiscard]] TextWithEntities RenderMessageText(
		const SecretParsedMessage &message) {
	auto result = TextWithEntities();
	std::visit([&](const auto &value) {
		using T = std::decay_t<decltype(value)>;
		if constexpr (std::is_same_v<T, SecretParsedTextMessage>) {
			result.text = value.text;
			result.entities.reserve(value.entities.size());
			for (const auto &entity : value.entities) {
				if ((entity.offset < 0)
					|| (entity.length <= 0)
					|| (entity.offset + entity.length > result.text.size())) {
					continue;
				}
				auto mapped = std::optional<EntityInText>();
				switch (entity.constructor) {
				case 0xfa04579d:
					mapped = EntityInText(EntityType::Mention, entity.offset, entity.length);
				break;
				case 0x6f635b0d:
					mapped = EntityInText(EntityType::Hashtag, entity.offset, entity.length);
				break;
				case 0x6cef8ac7:
					mapped = EntityInText(EntityType::BotCommand, entity.offset, entity.length);
				break;
				case 0x6ed02538:
					mapped = EntityInText(EntityType::Url, entity.offset, entity.length);
				break;
				case 0x64e475c2:
					mapped = EntityInText(EntityType::Email, entity.offset, entity.length);
				break;
				case 0xbd610bc9:
					mapped = EntityInText(EntityType::Bold, entity.offset, entity.length);
				break;
				case 0x826f8b60:
					mapped = EntityInText(EntityType::Italic, entity.offset, entity.length);
				break;
				case 0x28a20571:
					mapped = EntityInText(EntityType::Code, entity.offset, entity.length);
				break;
				case 0x73924be0:
					mapped = EntityInText(EntityType::Pre, entity.offset, entity.length, entity.data);
				break;
				case 0x76a6d327:
					mapped = EntityInText(EntityType::CustomUrl, entity.offset, entity.length, entity.data);
				break;
				case 0x9c4e7e8b:
					mapped = EntityInText(EntityType::Underline, entity.offset, entity.length);
				break;
				case 0xbf0693d4:
					mapped = EntityInText(EntityType::StrikeOut, entity.offset, entity.length);
				break;
				case 0x020df5d0:
					mapped = EntityInText(EntityType::Blockquote, entity.offset, entity.length);
				break;
				case 0x32ca960f:
					mapped = EntityInText(EntityType::Spoiler, entity.offset, entity.length);
				break;
				}
				if (mapped.has_value()) {
					result.entities.push_back(*mapped);
				}
			}
		} else if constexpr (std::is_same_v<T, SecretParsedServiceMessage>) {
			result.text = QString("[secret chat: %1]").arg(
				SecretServiceActionName(value.actionConstructor));
		} else if constexpr (std::is_same_v<T, SecretParsedUnsupportedMessage>) {
			result.text = QString("[unsupported %1]").arg(value.description);
		}
	}, message);
	return result;
}

[[nodiscard]] uint64_t MessageRandomId(const SecretParsedMessage &message) {
	return std::visit([](const auto &value) -> uint64_t {
		using T = std::decay_t<decltype(value)>;
		if constexpr (std::is_same_v<T, SecretParsedUnsupportedMessage>) {
			return 0;
		} else {
			return value.randomId;
		}
	}, message);
}

[[nodiscard]] std::optional<SecretParsedEntity> SecretEntityFromTextEntity(
		const EntityInText &entity) {
	auto result = SecretParsedEntity{
		.offset = entity.offset(),
		.length = entity.length(),
		.data = entity.data(),
	};
	switch (entity.type()) {
	case EntityType::Mention:
		result.constructor = 0xfa04579d;
	break;
	case EntityType::Hashtag:
		result.constructor = 0x6f635b0d;
	break;
	case EntityType::BotCommand:
		result.constructor = 0x6cef8ac7;
	break;
	case EntityType::Url:
		result.constructor = 0x6ed02538;
	break;
	case EntityType::Email:
		result.constructor = 0x64e475c2;
	break;
	case EntityType::Bold:
		result.constructor = 0xbd610bc9;
	break;
	case EntityType::Italic:
		result.constructor = 0x826f8b60;
	break;
	case EntityType::Code:
		result.constructor = 0x28a20571;
	break;
	case EntityType::Pre:
		result.constructor = 0x73924be0;
	break;
	case EntityType::CustomUrl:
		result.constructor = 0x76a6d327;
	break;
	case EntityType::Underline:
		result.constructor = 0x9c4e7e8b;
	break;
	case EntityType::StrikeOut:
		result.constructor = 0xbf0693d4;
	break;
	case EntityType::Blockquote:
		result.constructor = 0x020df5d0;
	break;
	case EntityType::Spoiler:
		result.constructor = 0x32ca960f;
	break;
	default:
		return std::nullopt;
	}
	if ((result.offset < 0) || (result.length <= 0)) {
		return std::nullopt;
	}
	return result;
}

[[nodiscard]] QVector<SecretParsedEntity> SecretEntitiesFromText(
		const TextWithEntities &textWithEntities) {
	auto result = QVector<SecretParsedEntity>();
	result.reserve(textWithEntities.entities.size());
	for (const auto &entity : textWithEntities.entities) {
		const auto mapped = SecretEntityFromTextEntity(entity);
		if (!mapped.has_value()) {
			continue;
		}
		if (mapped->offset + mapped->length > textWithEntities.text.size()) {
			continue;
		}
		result.push_back(*mapped);
	}
	return result;
}

void AppendSecretMessageEntities(
		QByteArray &body,
		const QVector<SecretParsedEntity> &entities) {
	AppendUInt32(body, kTlVectorConstructor);
	AppendInt32(body, entities.size());
	for (const auto &entity : entities) {
		AppendUInt32(body, entity.constructor);
		AppendInt32(body, entity.offset);
		AppendInt32(body, entity.length);
		switch (entity.constructor) {
		case 0x73924be0:
		case 0x76a6d327:
			AppendTLString(body, entity.data);
		break;
		case 0xc8cf05f8:
			AppendUInt64(body, entity.data.toULongLong());
		break;
		}
	}
}

[[nodiscard]] QByteArray SerializeSecretTextBody(
		const SecretChatState &state,
		uint64_t randomId,
		const TextWithEntities &textWithEntities,
		uint32_t flags,
		const QVector<SecretParsedEntity> &entities,
		uint64_t replyToRandomId) {
	auto body = QByteArray();
	AppendUInt32(body, kSecretOuterLayerConstructor);

	auto randomBytes = QByteArray(kMinSecretRandomBytes, Qt::Uninitialized);
	for (auto i = 0; i != randomBytes.size(); ++i) {
		randomBytes[i] = char(base::RandomValue<uchar>());
	}
	AppendTLBytes(body, randomBytes);
	AppendInt32(body, state.layer);
	AppendInt32(body, SecretInSeqNo(state, state.incoming_sequence));
	AppendInt32(body, SecretOutSeqNo(state, state.outgoing_sequence));
	AppendUInt32(body, kSecretInnerMessageV73);
	AppendUInt32(body, flags);
	AppendUInt64(body, randomId);
	AppendInt32(body, 0);
	AppendTLString(body, textWithEntities.text);
	if (!entities.isEmpty()) {
		AppendSecretMessageEntities(body, entities);
	}
	if (replyToRandomId) {
		AppendUInt64(body, replyToRandomId);
	}
	return body;
}

[[nodiscard]] PeerId EnsureFakeSecretPeer(
		not_null<Data::Session*> owner,
		int64_t chatId,
		const QString &displayName) {
	const auto seedName = QString("Secret Chat %1").arg(chatId);
	const auto peerId = Data::FakePeerIdForJustName(seedName);
	const auto name = displayName.isEmpty() ? seedName : displayName;
	owner->processUser(MTP_user(
		MTP_flags(MTPDuser::Flag::f_first_name | MTPDuser::Flag::f_min),
		peerToBareMTPInt(peerId),
		MTP_long(0),
		MTP_string(name),
		MTPstring(),
		MTPstring(),
		MTPstring(),
		MTPUserProfilePhoto(),
		MTPUserStatus(),
		MTP_int(0),
		MTPVector<MTPRestrictionReason>(),
		MTPstring(),
		MTPstring(),
		MTPEmojiStatus(),
		MTPVector<MTPUsername>(),
		MTPRecentStory(),
		MTPPeerColor(),
		MTPPeerColor(),
		MTPint(),
		MTPlong(),
		MTPlong()));
	return peerId;
}

} // namespace

SecretChatManager::SecretChatManager(not_null<Main::Session*> session)
: _session(session) {
	RefreshKnownChats();
	RestoreMessagesFromStorage();
	_session->changes().peerUpdates(
		Data::PeerUpdate::Flag::Name
		| Data::PeerUpdate::Flag::Username
		| Data::PeerUpdate::Flag::Usernames
		| Data::PeerUpdate::Flag::PhoneNumber
		| Data::PeerUpdate::Flag::Photo
		| Data::PeerUpdate::Flag::OnlineStatus
	) | rpl::on_next([=](const Data::PeerUpdate &update) {
		const auto user = update.peer->asUser();
		if (!user) {
			return;
		}
		for (const auto &[chatId, state] : _states) {
			const auto remoteUserId = RemoteUserIdForState(_session, state);
			if (!remoteUserId || (*remoteUserId != user->id)) {
				continue;
			}
			RefreshPresentation(chatId);
		}
	}, _lifetime);
	// Chat-list entry creation is deferred until after Manager() inserts this
	// instance into the static map, otherwise entry refresh can re-enter
	// Manager() during construction and recurse indefinitely.
}

void SecretChatManager::FinishInitialization() {
	EnsureEntriesFromKnownChats();
}

void SecretChatManager::RefreshKnownChats() {
	_knownChats = LoadAllSecretChats(_session);
	_states.clear();
	for (const auto &descriptor : _knownChats) {
		if (const auto state = LoadSecretChatState(_session, descriptor.chatId)) {
			_states.emplace(descriptor.chatId, *state);
		}
	}
}

void SecretChatManager::RestoreMessagesFromStorage() {
	for (const auto &descriptor : _knownChats) {
		const auto messages = LoadSecretChatMessages(_session, descriptor.chatId);
		if (!messages.isEmpty()) {
			_messages.insert(descriptor.chatId, messages);
		}
	}
}

void SecretChatManager::EnsureEntriesFromKnownChats() {
	for (const auto &descriptor : _knownChats) {
		EnsureEntryForChat(descriptor);
	}
}

void SecretChatManager::EnsureEntryForChat(
		const SecretChatDescriptor &descriptor) {
	if (_entries.find(descriptor.chatId) != end(_entries)) {
		return;
	}
	auto entry = std::make_unique<Dialogs::SecretChatEntry>(
		&_session->data(),
		descriptor.chatId);
	RefreshChatListEntry(entry.get());
	_entries.emplace(descriptor.chatId, std::move(entry));
}

void SecretChatManager::UpsertKnownChat(const SecretChatState &state) {
	const auto descriptor = DescriptorFromState(state);
	const auto i = ranges::find(
		_knownChats,
		state.chat_id,
		&SecretChatDescriptor::chatId);
	if (i == _knownChats.end()) {
		_knownChats.push_back(descriptor);
	} else {
		*i = descriptor;
	}
}

auto SecretChatManager::EnsureRenderState(int64_t chatId) -> RenderState& {
	if (const auto i = _rendered.find(chatId); i != end(_rendered)) {
		return *i->second;
	}
	const auto peerId = EnsureFakeSecretPeer(
		&_session->data(),
		chatId,
		DisplayNameForChat(chatId));
	auto state = std::make_unique<RenderState>(RenderState{
		.peerId = peerId,
		.history = _session->data().history(peerId),
	});
	state->history->getReadyFor(ShowAtTheEndMsgId);
	if (const auto i = _messages.find(chatId); i != _messages.end()) {
		for (const auto &message : i.value()) {
			AppendRenderedMessage(*state, message, true);
		}
	}
	auto raw = state.get();
	_rendered.emplace(chatId, std::move(state));
	return *raw;
}

void SecretChatManager::AppendRenderedMessage(
		RenderState &state,
		const SecretParsedMessage &message,
		bool restored) {
	const auto &envelope = MessageEnvelope(message);
	const auto chatId = std::visit([](const auto &value) {
		return value.chatId;
	}, message);
	const auto remotePeerId = [&] {
		const auto loaded = DisplayUserForChat(chatId);
		return loaded ? loaded->id : state.peerId;
	}();
	const auto activityUser = restored && !envelope.outgoing
		? DisplayUserForChat(chatId)
		: nullptr;
	const auto previousLastseen = activityUser
		? std::optional(activityUser->lastseen())
		: std::nullopt;
	auto fields = HistoryItemCommonFields{
		.id = state.history->nextNonHistoryEntryId(),
		.flags = (MessageFlag::HasFromId
			| (envelope.outgoing ? MessageFlag::Outgoing : MessageFlag())),
		.from = envelope.outgoing
			? _session->userPeerId()
			: remotePeerId,
		.date = envelope.date ? envelope.date : base::unixtime::now(),
	};
	if (const auto text = std::get_if<SecretParsedTextMessage>(&message);
		text && text->replyToRandomId) {
		const auto i = state.randomIds.find(text->replyToRandomId);
		if (i != end(state.randomIds)) {
			fields.flags |= MessageFlag::HasReplyInfo;
			fields.replyTo = FullReplyTo{ i->second };
		}
	}
	const auto item = state.history->addNewLocalMessage(
		std::move(fields),
		RenderMessageText(message),
		MTP_messageMediaEmpty());
	if (activityUser && previousLastseen
		&& activityUser->updateLastseen(*previousLastseen)) {
		_session->data().maybeStopWatchForOffline(activityUser);
		_session->changes().peerUpdated(
			activityUser,
			Data::PeerUpdate::Flag::OnlineStatus);
	}
	state.ids.push_back(item->fullId());
	if (const auto randomId = MessageRandomId(message)) {
		state.randomIds.emplace(randomId, item->fullId());
		state.reverseRandomIds.emplace(item->fullId(), randomId);
	}
	_session->changes().messageUpdated(
		item,
		Data::MessageUpdate::Flag::NewAdded);
	_session->changes().historyUpdated(
		state.history,
		Data::HistoryUpdate::Flag::ClientSideMessages);
}

// Update the persisted incoming sequence counters from an inbound message.
void SecretChatManager::AdvanceIncomingState(const SecretParsedMessage &message) {
	const auto &envelope = MessageEnvelope(message);
	if (envelope.outgoing) {
		return;
	}
	const auto chatId = std::visit([](const auto &value) {
		return value.chatId;
	}, message);
	auto state = LoadState(chatId);
	if (!state.has_value()) {
		return;
	}
	if (envelope.layer > state->layer) {
		state->layer = envelope.layer;
	}
	const auto incomingSequence = RawIncomingSequence(*state, envelope.outSeqNo);
	if (incomingSequence.has_value()
		&& (*incomingSequence > state->incoming_sequence)) {
		state->incoming_sequence = *incomingSequence;
	}
	SaveState(*state);
}

void SecretChatManager::RefreshChatListEntry(
		not_null<Dialogs::SecretChatEntry*> entry) {
	_session->data().refreshChatListEntry(
		Dialogs::Key(static_cast<Dialogs::Entry*>(entry.get())));
}

void SecretChatManager::RefreshPresentation(int64_t chatId) {
	if (const auto i = _entries.find(chatId); i != end(_entries)) {
		RefreshChatListEntry(i->second.get());
		i->second->updateChatListEntry();
	}
	_presentationUpdates.fire_copy(chatId);
}

void SecretChatManager::ClearTyping(int64_t chatId) {
	if (_typingUntil.erase(chatId) > 0) {
		RefreshPresentation(chatId);
	}
}

void SecretChatManager::HandleEncryptedMessage(
		int64_t chatId,
		const QByteArray &payload,
		const char *tag) {
	const auto state = LoadState(chatId);
	if (!state.has_value()) {
		LOG(("1335 SecretChat: no state found for %1 chat_id=%2")
			.arg(QString::fromLatin1(tag))
			.arg(chatId));
		return;
	}

	if (payload.size() < 24) {
		LOG(("1335 SecretChat: payload too short for %1 chat_id=%2 size=%3")
			.arg(QString::fromLatin1(tag))
			.arg(chatId)
			.arg(payload.size()));
		return;
	}

	uint64_t receivedFingerprint = 0;
	std::memcpy(&receivedFingerprint, payload.constData(), 8);

	const auto msgKeyHex = payload.mid(8, 16).toHex();
	const auto encryptedSize = payload.size() - 24;

	LOG(("1335 SecretChat: %1 envelope chat_id=%2 stored_fingerprint=%3 received_fingerprint=%4 msg_key=%5 encrypted_size=%6")
		.arg(QString::fromLatin1(tag))
		.arg(chatId)
		.arg(FormatUint64(state->key_fingerprint))
		.arg(FormatUint64(receivedFingerprint))
		.arg(QString::fromLatin1(msgKeyHex))
		.arg(encryptedSize));

	if (receivedFingerprint != state->key_fingerprint) {
		LOG(("1335 SecretChat: fingerprint mismatch for %1 chat_id=%2")
			.arg(QString::fromLatin1(tag))
			.arg(chatId));
		return;
	}

	const auto decrypted = DecryptSecretChatPayloadMtproto2(*state, payload);
	if (!decrypted.has_value()) {
		LOG(("1335 SecretChat: failed to decrypt %1 chat_id=%2")
			.arg(QString::fromLatin1(tag))
			.arg(chatId));
		return;
	}

	const auto parsed = ParseDecryptedSecretChatPayload(chatId, *decrypted, tag);
	if (!parsed.has_value()) {
		LOG(("1335 SecretChat: failed to parse %1 chat_id=%2")
			.arg(QString::fromLatin1(tag))
			.arg(chatId));
		return;
	}

	StoreParsedMessage(chatId, *parsed);
}

void SecretChatManager::HandleEncryptedChatRequested(
		int32 requestedChatId,
		uint64 requestedAccessHash,
		uint64 requestedAdminId,
		uint64 requestedParticipantId,
		const QByteArray &requestedGA,
		int32 requestDate) {
	LOG(("1337 SecretChat: updateEncryption -> encryptedChatRequested "
		"id=%1 access_hash=%2 admin_id=%3 participant_id=%4 date=%5 g_a_size=%6")
		.arg(requestedChatId)
		.arg(requestedAccessHash)
		.arg(requestedAdminId)
		.arg(requestedParticipantId)
		.arg(requestDate)
		.arg(requestedGA.size()));

	_session->api().request(MTPmessages_GetDhConfig(
		MTP_int(0),
		MTP_int(MTP::ModExpFirst::kRandomPowerSize)
	)).done([=](const MTPmessages_DhConfig &result) {
		result.match([&](const MTPDmessages_dhConfig &data) {
			LOG(("1337 SecretChat: getDhConfig -> dhConfig "
				"g=%1 p_size=%2 version=%3 random_size=%4")
				.arg(data.vg().v)
				.arg(data.vp().v.size())
				.arg(data.vversion().v)
				.arg(data.vrandom().v.size()));

			auto primeBytes = bytes::make_vector(data.vp().v);
			if (!MTP::IsPrimeAndGood(primeBytes, data.vg().v)) {
				LOG(("1337 SecretChat: bad p/g in dhConfig"));
				return;
			}

			const auto modexp = MTP::CreateModExp(
				data.vg().v,
				primeBytes,
				bytes::make_span(data.vrandom().v));

			if (modexp.modexp.empty()) {
				LOG(("1337 SecretChat: CreateModExp failed"));
				return;
			}

			const auto computedAuthKey = MTP::CreateAuthKey(
				bytes::make_span(requestedGA),
				modexp.randomPower,
				primeBytes);

			if (computedAuthKey.empty()) {
				LOG(("1337 SecretChat: CreateAuthKey failed"));
				return;
			}

			MTP::AuthKey::Data paddedAuthKey = {};
			MTP::AuthKey::FillData(paddedAuthKey, computedAuthKey);

			const auto authKeySha1 = openssl::Sha1(bytes::make_span(paddedAuthKey));

			uint64 keyFingerprint = 0;
			std::memcpy(&keyFingerprint, authKeySha1.data() + 12, 8);

			LOG(("1337 SecretChat: computed incoming accept values "
				"g_b_size=%1 shared_key_size=%2 padded_key_size=%3 key_fingerprint=%4")
				.arg(modexp.modexp.size())
				.arg(computedAuthKey.size())
				.arg(int(MTP::AuthKey::kSize))
				.arg(FormatUint64(keyFingerprint)));

			_session->api().request(MTPmessages_AcceptEncryption(
				MTP_inputEncryptedChat(
					MTP_int(requestedChatId),
					MTP_long(requestedAccessHash)
				),
				MTP_bytes(modexp.modexp),
				MTP_long(static_cast<uint64>(keyFingerprint))
			)).done([=](const MTPEncryptedChat &result) {
				switch (result.type()) {
				case mtpc_encryptedChat: {
					const auto &accepted = result.c_encryptedChat();

					LOG(("1337 SecretChat: acceptEncryption done -> encryptedChat "
						"id=%1 access_hash=%2 admin_id=%3 participant_id=%4 date=%5 key_fingerprint=%6 g_a_or_b_size=%7")
						.arg(accepted.vid().v)
						.arg(accepted.vaccess_hash().v)
						.arg(accepted.vadmin_id().v)
						.arg(accepted.vparticipant_id().v)
						.arg(accepted.vdate().v)
						.arg(accepted.vkey_fingerprint().v)
						.arg(accepted.vg_a_or_b().v.size()));

					SecretChatState state;
					state.chat_id = accepted.vid().v;
					state.access_hash = static_cast<uint64>(accepted.vaccess_hash().v);
					state.admin_id = static_cast<uint64>(accepted.vadmin_id().v);
					state.participant_id = static_cast<uint64>(accepted.vparticipant_id().v);
					state.is_creator = false; // The remote side requested this chat; we are the acceptor.
					state.layer = kSecretLayer;
					state.key_fingerprint = keyFingerprint;
					state.auth_key = paddedAuthKey;

					if (!SaveState(state)) {
						LOG(("1337 SecretChat: state save failed after acceptEncryption"));
					}
				} break;

				case mtpc_encryptedChatDiscarded: {
					const auto &discarded = result.c_encryptedChatDiscarded();
					LOG(("1337 SecretChat: acceptEncryption done -> encryptedChatDiscarded id=%1")
						.arg(discarded.vid().v));
				} break;

				case mtpc_encryptedChatWaiting: {
					const auto &waiting = result.c_encryptedChatWaiting();
					LOG(("1337 SecretChat: acceptEncryption done -> encryptedChatWaiting id=%1")
						.arg(waiting.vid().v));
				} break;

				default:
					LOG(("1337 SecretChat: acceptEncryption done -> unexpected result.type=%1")
						.arg(int(result.type())));
					break;
				}
			}).fail([=] {
				LOG(("1337 SecretChat: acceptEncryption failed"));
			}).send();

		}, [&](const MTPDmessages_dhConfigNotModified &data) {
			LOG(("1337 SecretChat: getDhConfig -> dhConfigNotModified random_size=%1")
				.arg(data.vrandom().v.size()));
		});
	}).fail([=] {
		LOG(("1337 SecretChat: getDhConfig failed"));
	}).send();
}

void SecretChatManager::LogEncryptionChat(const MTPEncryptedChat &chat, const char *tag) const {
	switch (chat.type()) {
	case mtpc_encryptedChatRequested: {
		const auto &c = chat.c_encryptedChatRequested();
		LOG(("1337 SecretChat: %1 -> encryptedChatRequested "
			"id=%2 access_hash=%3 admin_id=%4 participant_id=%5 date=%6 g_a_size=%7")
			.arg(QString::fromLatin1(tag))
			.arg(c.vid().v)
			.arg(c.vaccess_hash().v)
			.arg(c.vadmin_id().v)
			.arg(c.vparticipant_id().v)
			.arg(c.vdate().v)
			.arg(c.vg_a().v.size()));
	} break;

	case mtpc_encryptedChatDiscarded: {
		const auto &c = chat.c_encryptedChatDiscarded();
		LOG(("1337 SecretChat: %1 -> encryptedChatDiscarded id=%2")
			.arg(QString::fromLatin1(tag))
			.arg(c.vid().v));
	} break;

	case mtpc_encryptedChatWaiting: {
		const auto &c = chat.c_encryptedChatWaiting();
		LOG(("1337 SecretChat: %1 -> encryptedChatWaiting "
			"id=%2 access_hash=%3 admin_id=%4 participant_id=%5 date=%6")
			.arg(QString::fromLatin1(tag))
			.arg(c.vid().v)
			.arg(c.vaccess_hash().v)
			.arg(c.vadmin_id().v)
			.arg(c.vparticipant_id().v)
			.arg(c.vdate().v));
	} break;

	case mtpc_encryptedChat: {
		const auto &c = chat.c_encryptedChat();
		LOG(("1337 SecretChat: %1 -> encryptedChat "
			"id=%2 access_hash=%3 admin_id=%4 participant_id=%5 date=%6 key_fingerprint=%7 g_a_or_b_size=%8")
			.arg(QString::fromLatin1(tag))
			.arg(c.vid().v)
			.arg(c.vaccess_hash().v)
			.arg(c.vadmin_id().v)
			.arg(c.vparticipant_id().v)
			.arg(c.vdate().v)
			.arg(c.vkey_fingerprint().v)
			.arg(c.vg_a_or_b().v.size()));
	} break;

	case mtpc_encryptedChatEmpty: {
		const auto &c = chat.c_encryptedChatEmpty();
		LOG(("1337 SecretChat: %1 -> encryptedChatEmpty id=%2")
			.arg(QString::fromLatin1(tag))
			.arg(c.vid().v));
	} break;

	default:
		LOG(("1337 SecretChat: %1 -> unknown chat.type=%2")
			.arg(QString::fromLatin1(tag))
			.arg(int(chat.type())));
		break;
	}
}

void SecretChatManager::HandleEncryptedChatWaiting(const MTPEncryptedChat &chat) {
	if (chat.type() != mtpc_encryptedChatWaiting) {
		return;
	}
	const auto &waiting = chat.c_encryptedChatWaiting();
	auto existing = LoadState(waiting.vid().v);
	if (!existing.has_value()) {
		LOG(("1337 SecretChat: encryptedChatWaiting ignored, missing local creator state id=%1")
			.arg(waiting.vid().v));
		return;
	}
	auto state = *existing;
	state.chat_id = waiting.vid().v;
	state.access_hash = static_cast<uint64>(waiting.vaccess_hash().v);
	state.admin_id = static_cast<uint64>(waiting.vadmin_id().v);
	state.participant_id = static_cast<uint64>(waiting.vparticipant_id().v);
	state.is_creator = true;
	if (!SaveState(state)) {
		LOG(("1337 SecretChat: failed to save waiting creator state id=%1")
			.arg(waiting.vid().v));
	}
}

void SecretChatManager::HandleEncryptedChatEstablished(const MTPEncryptedChat &chat) {
	if (chat.type() != mtpc_encryptedChat) {
		return;
	}
	const auto &established = chat.c_encryptedChat();
	const auto chatId = int64_t(established.vid().v);
	const auto accessHash = static_cast<uint64>(established.vaccess_hash().v);
	const auto adminId = static_cast<uint64>(established.vadmin_id().v);
	const auto participantId = static_cast<uint64>(established.vparticipant_id().v);
	const auto gAOrB = established.vg_a_or_b().v;
	const auto remoteFingerprint = static_cast<uint64>(established.vkey_fingerprint().v);
	auto state = LoadState(chatId);
	if (!state.has_value()) {
		LOG(("1337 SecretChat: encryptedChat ignored, missing local state id=%1")
			.arg(chatId));
		return;
	}
	if (!state->is_creator || state->pending_random_power.isEmpty()) {
		return;
	}
	const auto randomPower = state->pending_random_power;
	_session->api().request(MTPmessages_GetDhConfig(
		MTP_int(0),
		MTP_int(MTP::ModExpFirst::kRandomPowerSize)
	)).done([=](const MTPmessages_DhConfig &result) {
		result.match([&](const MTPDmessages_dhConfig &data) {
			auto primeBytes = bytes::make_vector(data.vp().v);
			if (!MTP::IsPrimeAndGood(primeBytes, data.vg().v)) {
				LOG(("1337 SecretChat: bad p/g while finalizing outgoing secret chat id=%1")
					.arg(chatId));
				return;
			}
			const auto computedAuthKey = MTP::CreateAuthKey(
				bytes::make_span(gAOrB),
				bytes::make_span(
					reinterpret_cast<const uchar*>(randomPower.constData()),
					size_t(randomPower.size())),
				primeBytes);
			if (computedAuthKey.empty()) {
				LOG(("1337 SecretChat: CreateAuthKey failed while finalizing outgoing secret chat id=%1")
					.arg(chatId));
				return;
			}
			MTP::AuthKey::Data paddedAuthKey = {};
			MTP::AuthKey::FillData(paddedAuthKey, computedAuthKey);
			const auto authKeySha1 = openssl::Sha1(bytes::make_span(paddedAuthKey));
			auto keyFingerprint = uint64_t(0);
			std::memcpy(&keyFingerprint, authKeySha1.data() + 12, 8);
			if (keyFingerprint != remoteFingerprint) {
				LOG(("1337 SecretChat: key fingerprint mismatch while finalizing outgoing secret chat id=%1 local=%2 remote=%3")
					.arg(chatId)
					.arg(FormatUint64(keyFingerprint))
					.arg(FormatUint64(remoteFingerprint)));
				return;
			}
			auto ready = *state;
			ready.chat_id = chatId;
			ready.access_hash = accessHash;
			ready.admin_id = adminId;
			ready.participant_id = participantId;
			ready.is_creator = true;
			ready.layer = kSecretLayer;
			ready.key_fingerprint = keyFingerprint;
			ready.auth_key = paddedAuthKey;
			ready.pending_random_power = QByteArray();
			if (!SaveState(ready)) {
				LOG(("1337 SecretChat: failed to save finalized outgoing secret chat id=%1")
					.arg(chatId));
				return;
			}
			RefreshPresentation(chatId);
			LOG(("1337 SecretChat: finalized outgoing secret chat id=%1 key_fingerprint=%2")
				.arg(chatId)
				.arg(FormatUint64(keyFingerprint)));
		}, [&](const MTPDmessages_dhConfigNotModified &data) {
			LOG(("1337 SecretChat: getDhConfig not modified while finalizing outgoing secret chat id=%1 random_size=%2")
				.arg(chatId)
				.arg(data.vrandom().v.size()));
		});
	}).fail([=](const MTP::Error &error) {
		LOG(("1337 SecretChat: getDhConfig failed while finalizing outgoing secret chat id=%1")
			.arg(chatId));
	}).send();
}

bool SecretChatManager::SaveState(const SecretChatState &state) const {
	const auto saved = SaveSecretChatState(_session, state);
	if (saved) {
		auto that = const_cast<SecretChatManager*>(this);
		that->_states[state.chat_id] = state;
		that->UpsertKnownChat(state);
		that->EnsureEntryForChat(DescriptorFromState(state));
	}
	return saved;
}

const QVector<SecretChatDescriptor> &SecretChatManager::KnownChats() const {
	return _knownChats;
}

std::optional<int64_t> SecretChatManager::ChatIdForUser(UserId userId) const {
	for (const auto &[chatId, state] : _states) {
		const auto remoteUserId = RemoteUserIdForState(_session, state);
		if (remoteUserId && (*remoteUserId == userId)) {
			return chatId;
		}
	}
	return std::nullopt;
}

std::optional<SecretChatState> SecretChatManager::LoadState(int64_t chatId) const {
	if (const auto i = _states.find(chatId); i != _states.end()) {
		return i->second;
	}
	return std::nullopt;
}

SecretChatManager &Manager(not_null<Main::Session*> session) {
	static auto managers = std::map<Main::Session*, std::unique_ptr<SecretChatManager>>();
	const auto i = managers.find(session.get());
	if (i != managers.end()) {
		return *i->second;
	}
	auto manager = std::make_unique<SecretChatManager>(session);
	auto result = manager.get();
	managers.emplace(session.get(), std::move(manager));
	result->FinishInitialization();
	return *result;
}

void SecretChatManager::StoreParsedMessage(
		int64_t chatId,
		SecretParsedMessage message) {
	if (!MessageEnvelope(message).outgoing) {
		ClearTyping(chatId);
	}
	AdvanceIncomingState(message);
	if (const auto state = LoadState(chatId); state.has_value()) {
		EnsureEntryForChat(DescriptorFromState(*state));
	}
	auto &list = _messages[chatId];
	list.push_back(std::move(message));
	SaveSecretChatMessages(_session, chatId, list);
	LOG(("1335 SecretChat: stored parsed message chat_id=%1 total=%2")
		.arg(chatId)
		.arg(list.size()));
	if (const auto i = _rendered.find(chatId); i != _rendered.end()) {
		AppendRenderedMessage(*i->second, list.back());
	}
	if (const auto i = _entries.find(chatId); i != _entries.end()) {
		i->second->setChatListTimeId(base::unixtime::now());
		i->second->updateChatListSortPosition();
		RefreshChatListEntry(i->second.get());
	}
	_messageUpdates.fire_copy(chatId);
}

bool SecretChatManager::SendText(
		int64_t chatId,
		const ::TextWithEntities &textWithEntities,
		const FullReplyTo &replyTo) {
	if (textWithEntities.text.trimmed().isEmpty()) {
		return false;
	}
	auto state = LoadState(chatId);
	if (!state.has_value()) {
		LOG(("1338 SecretChat: send skipped, missing state chat_id=%1")
			.arg(chatId));
		return false;
	}
	if (!state->pending_random_power.isEmpty() || !state->key_fingerprint) {
		LOG(("1338 SecretChat: send skipped, secret chat not ready chat_id=%1")
			.arg(chatId));
		return false;
	}

	const auto randomId = base::RandomValue<uint64>();
	const auto entities = SecretEntitiesFromText(textWithEntities);
	auto replyToRandomId = uint64_t(0);
	if (replyTo.messageId) {
		const auto &render = EnsureRenderState(chatId);
		if (const auto i = render.reverseRandomIds.find(replyTo.messageId)
			; i != end(render.reverseRandomIds)) {
			replyToRandomId = i->second;
		}
	}
	auto flags = uint32_t(entities.isEmpty() ? 0 : (1 << 7));
	if (replyToRandomId) {
		flags |= (1 << 3);
	}
	const auto body = SerializeSecretTextBody(
		*state,
		randomId,
		textWithEntities,
		flags,
		entities,
		replyToRandomId);
	const auto payload = EncryptSecretChatPayloadMtproto2(*state, body);
	if (!payload.has_value()) {
		LOG(("1338 SecretChat: send encryption failed chat_id=%1 random_id=%2")
			.arg(chatId)
			.arg(FormatUint64(randomId)));
		return false;
	}

	++state->outgoing_sequence;
	SaveState(*state);

	LOG(("1338 SecretChat: sending encrypted text chat_id=%1 random_id=%2 text=%3 out_seq=%4")
		.arg(chatId)
		.arg(FormatUint64(randomId))
		.arg(textWithEntities.text)
		.arg(state->outgoing_sequence));

	_session->api().request(MTPmessages_SendEncrypted(
		MTP_flags(0),
		MTP_inputEncryptedChat(
			MTP_int(chatId),
			MTP_long(state->access_hash)),
		MTP_long(randomId),
		MTP_bytes(*payload)
	)).done([=](const MTPmessages_SentEncryptedMessage &result) {
		auto message = SecretParsedTextMessage{
			.chatId = chatId,
			.envelope = SecretParsedEnvelope{
				.layer = state->layer,
				.inSeqNo = SecretInSeqNo(*state, state->incoming_sequence),
				.outSeqNo = SecretOutSeqNo(*state, state->outgoing_sequence - 1),
				.outgoing = true,
			},
			.randomId = randomId,
			.replyToRandomId = replyToRandomId,
			.flags = flags,
			.text = textWithEntities.text,
			.entities = entities,
		};
		result.match([&](const MTPDmessages_sentEncryptedMessage &data) {
			message.envelope.date = data.vdate().v;
		}, [&](const MTPDmessages_sentEncryptedFile &data) {
			message.envelope.date = data.vdate().v;
		});
		StoreParsedMessage(chatId, std::move(message));
	}).fail([=](const MTP::Error &error) {
		LOG(("1338 SecretChat: sendEncrypted failed chat_id=%1 random_id=%2 error=%3")
			.arg(chatId)
			.arg(FormatUint64(randomId))
			.arg(error.type()));
	}).send();

	return true;
}

bool SecretChatManager::StartChat(
		not_null<UserData*> user,
		Fn<void(int64_t)> onReady) {
	if (user->isSelf() || user->isBot() || user->isServiceUser()) {
		LOG(("1337 SecretChat: start skipped for unsupported userId=%1")
			.arg(user->id.value));
		return false;
	}
	if (const auto existing = ChatIdForUser(peerToUser(user->id))) {
		if (onReady) {
			onReady(*existing);
		}
		return true;
	}
	const auto inputUser = user->inputUser();
	const auto randomId = base::RandomValue<int32>();
	_session->api().request(MTPmessages_GetDhConfig(
		MTP_int(0),
		MTP_int(MTP::ModExpFirst::kRandomPowerSize)
	)).done([=](const MTPmessages_DhConfig &result) {
		result.match([&](const MTPDmessages_dhConfig &data) {
			auto primeBytes = bytes::make_vector(data.vp().v);
			if (!MTP::IsPrimeAndGood(primeBytes, data.vg().v)) {
				LOG(("1337 SecretChat: bad p/g while requesting outgoing secret chat userId=%1")
					.arg(user->id.value));
				return;
			}
			const auto modexp = MTP::CreateModExp(
				data.vg().v,
				primeBytes,
				bytes::make_span(data.vrandom().v));
			if (modexp.modexp.empty()) {
				LOG(("1337 SecretChat: CreateModExp failed while requesting outgoing secret chat userId=%1")
					.arg(user->id.value));
				return;
			}
			const auto randomPower = QByteArray(
				reinterpret_cast<const char*>(modexp.randomPower.data()),
				int(modexp.randomPower.size()));
			_session->api().request(MTPmessages_RequestEncryption(
				inputUser,
				MTP_int(randomId),
				MTP_bytes(modexp.modexp)
			)).done([=](const MTPEncryptedChat &chat) {
				switch (chat.type()) {
				case mtpc_encryptedChatWaiting: {
					const auto &waiting = chat.c_encryptedChatWaiting();
					auto state = SecretChatState();
					state.chat_id = waiting.vid().v;
					state.access_hash = static_cast<uint64>(waiting.vaccess_hash().v);
					state.admin_id = static_cast<uint64>(waiting.vadmin_id().v);
					state.participant_id = static_cast<uint64>(waiting.vparticipant_id().v);
					state.is_creator = true;
					state.layer = kSecretLayer;
					state.pending_random_power = randomPower;
					if (SaveState(state) && onReady) {
						onReady(waiting.vid().v);
					}
					LOG(("1337 SecretChat: requestEncryption done -> encryptedChatWaiting id=%1 userId=%2")
						.arg(waiting.vid().v)
						.arg(user->id.value));
				} break;
				case mtpc_encryptedChat: {
					const auto &established = chat.c_encryptedChat();
					auto state = SecretChatState();
					state.chat_id = established.vid().v;
					state.access_hash = static_cast<uint64>(established.vaccess_hash().v);
					state.admin_id = static_cast<uint64>(established.vadmin_id().v);
					state.participant_id = static_cast<uint64>(established.vparticipant_id().v);
					state.is_creator = true;
					state.layer = kSecretLayer;
					state.pending_random_power = randomPower;
					if (!SaveState(state)) {
						LOG(("1337 SecretChat: failed to save direct encryptedChat creator state id=%1")
							.arg(established.vid().v));
						return;
					}
					HandleEncryptedChatEstablished(chat);
					if (onReady) {
						onReady(established.vid().v);
					}
				} break;
				case mtpc_encryptedChatDiscarded: {
					LOG(("1337 SecretChat: requestEncryption done -> encryptedChatDiscarded userId=%1")
						.arg(user->id.value));
				} break;
				default:
					LOG(("1337 SecretChat: requestEncryption done -> unexpected result.type=%1")
						.arg(int(chat.type())));
				break;
				}
			}).fail([=](const MTP::Error &error) {
				LOG(("1337 SecretChat: requestEncryption failed userId=%1 error=%2")
					.arg(user->id.value)
					.arg(error.type()));
			}).send();
		}, [&](const MTPDmessages_dhConfigNotModified &data) {
			LOG(("1337 SecretChat: getDhConfig not modified while requesting outgoing secret chat userId=%1 random_size=%2")
				.arg(user->id.value)
				.arg(data.vrandom().v.size()));
		});
	}).fail([=](const MTP::Error &error) {
		LOG(("1337 SecretChat: getDhConfig failed while requesting outgoing secret chat userId=%1 error=%2")
			.arg(user->id.value)
			.arg(error.type()));
	}).send();
	return true;
}

bool SecretChatManager::DeleteChat(int64_t chatId) {
	const auto removed = DeleteSecretChat(_session, chatId);
	_states.erase(chatId);
	_messages.remove(chatId);
	_rendered.erase(chatId);
	if (const auto i = _entries.find(chatId); i != end(_entries)) {
		_session->data().removeChatListEntry(Dialogs::Key(
			static_cast<Dialogs::Entry*>(i->second.get())));
		_entries.erase(i);
	}
	auto filtered = QVector<SecretChatDescriptor>();
	filtered.reserve(_knownChats.size());
	for (const auto &descriptor : _knownChats) {
		if (descriptor.chatId != chatId) {
			filtered.push_back(descriptor);
		}
	}
	_knownChats = std::move(filtered);
	LOG(("1337 SecretChat: manager deleted secret chat chat_id=%1")
		.arg(chatId));
	return removed;
}

const QVector<SecretParsedMessage> &SecretChatManager::Messages(int64_t chatId) const {
	static const QVector<SecretParsedMessage> kEmpty;
	const auto i = _messages.find(chatId);
	return (i == _messages.end()) ? kEmpty : i.value();
}

Dialogs::Entry *SecretChatManager::EntryForChat(int64_t chatId) const {
	const auto i = _entries.find(chatId);
	return (i == _entries.end()) ? nullptr : i->second.get();
}

not_null<History*> SecretChatManager::ViewHistoryForChat(int64_t chatId) {
	return EnsureRenderState(chatId).history;
}

const std::vector<FullMsgId> &SecretChatManager::ViewMessageIds(int64_t chatId) {
	return EnsureRenderState(chatId).ids;
}

std::optional<int64_t> SecretChatManager::ChatIdForHistory(
		not_null<const History*> history) const {
	for (const auto &[chatId, render] : _rendered) {
		if (render->history == history) {
			return chatId;
		}
	}
	return std::nullopt;
}

std::optional<int64_t> SecretChatManager::ChatIdForPeer(PeerId peerId) const {
	for (const auto &[chatId, render] : _rendered) {
		if (render->peerId == peerId) {
			return chatId;
		}
	}
	return std::nullopt;
}

rpl::producer<int64_t> SecretChatManager::messageUpdates() const {
	return _messageUpdates.events();
}

rpl::producer<int64_t> SecretChatManager::presentationUpdates() const {
	return _presentationUpdates.events();
}

UserData *SecretChatManager::DisplayUserForChat(int64_t chatId) const {
	const auto state = LoadState(chatId);
	if (!state.has_value()) {
		return nullptr;
	}
	const auto remoteUserId = RemoteUserIdForState(_session, *state);
	return remoteUserId.has_value()
		? _session->data().userLoaded(*remoteUserId)
		: nullptr;
}

QString SecretChatManager::DisplayNameForChat(int64_t chatId) const {
	if (const auto user = DisplayUserForChat(chatId)) {
		return user->name();
	}
	return QString("Secret Chat %1").arg(chatId);
}

QString SecretChatManager::DisplayStatusForChat(int64_t chatId) const {
	if (!IsChatReady(chatId)) {
		return WaitingStatusForChat(chatId);
	}
	if (const auto i = _typingUntil.find(chatId); (i != end(_typingUntil)) && (i->second > crl::now())) {
		return tr::lng_typing(tr::now);
	}
	if (const auto user = DisplayUserForChat(chatId)) {
		const auto now = base::unixtime::now();
		if (Data::IsUserOnline(user, now)) {
			_session->data().watchForOffline(user, now);
		}
		return Data::OnlineText(user, now);
	}
	return QString("Secret chat");
}

QString SecretChatManager::WaitingStatusForChat(int64_t chatId) const {
	if (const auto user = DisplayUserForChat(chatId)) {
		return QString("Waiting for %1 to come online.").arg(user->name());
	}
	return QString("Waiting for the other device to come online.");
}

bool SecretChatManager::IsChatReady(int64_t chatId) const {
	const auto state = LoadState(chatId);
	return state.has_value()
		&& state->pending_random_power.isEmpty()
		&& (state->key_fingerprint != 0);
}

void SecretChatManager::UpdateTyping(int64_t chatId) {
	const auto state = LoadState(chatId);
	if (!state.has_value()) {
		return;
	}
	auto &timer = _outgoingTypingTimers[chatId];
	if (!timer) {
		timer = std::make_unique<base::Timer>();
		timer->setCallback([=, this] {
			CancelTyping(chatId);
		});
	}
	timer->callOnce(kSecretTypingCancelTimeout);
	_outgoingTypingActive[chatId] = true;

	const auto now = crl::now();
	if (const auto i = _outgoingTypingUpdated.find(chatId);
			(i != end(_outgoingTypingUpdated)) && (i->second > now)) {
		return;
	}
	_outgoingTypingUpdated[chatId] = now + kSecretSendMyTypingInterval;
	LOG(("1336 SecretChat: sending setEncryptedTyping chat_id=%1 typing=1")
		.arg(chatId));
	_session->api().request(MTPmessages_SetEncryptedTyping(
		MTP_inputEncryptedChat(
			MTP_int(chatId),
			MTP_long(state->access_hash)),
		MTP_bool(true)
	)).done([=](const MTPBool &) {
		LOG(("1336 SecretChat: setEncryptedTyping done chat_id=%1 typing=1")
			.arg(chatId));
	}).fail([=](const MTP::Error &error) {
		LOG(("1336 SecretChat: setEncryptedTyping failed chat_id=%1 typing=1 error=%2")
			.arg(chatId)
			.arg(error.type()));
	}).send();
}

void SecretChatManager::CancelTyping(int64_t chatId) {
	if (const auto i = _outgoingTypingTimers.find(chatId); i != end(_outgoingTypingTimers)) {
		i->second->cancel();
	}
	const auto active = _outgoingTypingActive.find(chatId);
	if ((active == end(_outgoingTypingActive)) || !active->second) {
		return;
	}
	active->second = false;
	const auto state = LoadState(chatId);
	if (!state.has_value()) {
		return;
	}
	LOG(("1336 SecretChat: sending setEncryptedTyping chat_id=%1 typing=0")
		.arg(chatId));
	_session->api().request(MTPmessages_SetEncryptedTyping(
		MTP_inputEncryptedChat(
			MTP_int(chatId),
			MTP_long(state->access_hash)),
		MTP_bool(false)
	)).done([=](const MTPBool &) {
		LOG(("1336 SecretChat: setEncryptedTyping done chat_id=%1 typing=0")
			.arg(chatId));
	}).fail([=](const MTP::Error &error) {
		LOG(("1336 SecretChat: setEncryptedTyping failed chat_id=%1 typing=0 error=%2")
			.arg(chatId)
			.arg(error.type()));
	}).send();
}

void SecretChatManager::HandleEncryptedTyping(int64_t chatId) {
	auto &timer = _typingTimers[chatId];
	if (!timer) {
		timer = std::make_unique<base::Timer>();
		timer->setCallback([=, this] {
			const auto i = _typingUntil.find(chatId);
			if ((i == end(_typingUntil)) || (i->second <= crl::now())) {
				ClearTyping(chatId);
				return;
			}
			if (const auto j = _typingTimers.find(chatId); j != end(_typingTimers)) {
				j->second->callOnce(std::max(i->second - crl::now(), crl::time(1)));
			}
		});
	}
	_typingUntil[chatId] = crl::now() + kSecretTypingTimeout;
	timer->callOnce(kSecretTypingTimeout);
	LOG(("1336 SecretChat: typing active chat_id=%1 timeout_ms=%2")
		.arg(chatId)
		.arg(kSecretTypingTimeout));
	RefreshPresentation(chatId);
}

void SecretChatManager::HandleEncryptedMessagesRead(int64_t chatId, TimeId maxDate) {
	if (!maxDate) {
		return;
	}
	auto &render = EnsureRenderState(chatId);
	const auto &messages = Messages(chatId);
	const auto limit = std::min(size_t(messages.size()), render.ids.size());
	auto upTo = MsgId();
	for (auto i = size_t(0); i != limit; ++i) {
		const auto &message = messages[int(i)];
		const auto &envelope = MessageEnvelope(message);
		if (!envelope.outgoing || !envelope.date || (envelope.date > maxDate)) {
			continue;
		}
		upTo = render.ids[i].msg;
	}
	if (!upTo) {
		LOG(("1338 SecretChat: read update had no matching outgoing message chat_id=%1 max_date=%2")
			.arg(chatId)
			.arg(maxDate));
		return;
	}
	render.history->outboxRead(upTo);
	LOG(("1338 SecretChat: marked outgoing read chat_id=%1 max_date=%2 msg_id=%3")
		.arg(chatId)
		.arg(maxDate)
		.arg(upTo.bare));
}

void SecretChatManager::MarkReadTill(int64_t chatId, TimeId maxDate) {
	if (!maxDate) {
		return;
	}
	if (const auto i = _readTillSent.find(chatId); (i != end(_readTillSent)) && (i->second >= maxDate)) {
		return;
	}
	const auto state = LoadState(chatId);
	if (!state.has_value()) {
		return;
	}
	_readTillSent[chatId] = maxDate;
	LOG(("1338 SecretChat: sending readEncryptedHistory chat_id=%1 max_date=%2")
		.arg(chatId)
		.arg(maxDate));
	_session->api().request(MTPmessages_ReadEncryptedHistory(
		MTP_inputEncryptedChat(
			MTP_int(chatId),
			MTP_long(state->access_hash)),
		MTP_int(maxDate)
	)).done([=](const MTPBool &) {
		LOG(("1338 SecretChat: readEncryptedHistory done chat_id=%1 max_date=%2")
			.arg(chatId)
			.arg(maxDate));
	}).fail([=](const MTP::Error &error) {
		LOG(("1338 SecretChat: readEncryptedHistory failed chat_id=%1 max_date=%2 error=%3")
			.arg(chatId)
			.arg(maxDate)
			.arg(error.type()));
	}).send();
}

} // namespace Data::SecretChats