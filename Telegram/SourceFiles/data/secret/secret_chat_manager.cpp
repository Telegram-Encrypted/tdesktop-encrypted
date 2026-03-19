#include "data/secret/secret_chat_manager.h"
#include "data/secret/secret_chat_crypto.h"
#include "data/secret/secret_chat_parser.h"
#include "data/secret/secret_chat_storage.h"
#include "data/secret/secret_chat_tl.h"
#include "data/secret/secret_chat_types.h"
#include "data/data_peer.h"
#include "data/data_peer_values.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "dialogs/dialogs_key.h"
#include "dialogs/secret_chat_entry.h"
#include "history/history.h"
#include "history/history_item.h"

#include "base/unixtime.h"
#include "base/random.h"
#include "logs.h"
#include "main/main_session.h"
#include "mtproto/mtproto_dh_utils.h"
#include "apiwrap.h"

#include "base/openssl_help.h"

#include <map>

namespace Data::SecretChats {

struct SecretChatManager::RenderState {
	PeerId peerId = 0;
	not_null<History*> history;
	std::vector<FullMsgId> ids;
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

[[nodiscard]] QString RenderMessageText(const SecretParsedMessage &message) {
	QString line;
	std::visit([&](const auto &value) {
		using T = std::decay_t<decltype(value)>;
		if constexpr (std::is_same_v<T, SecretParsedTextMessage>) {
			line = value.text;
		} else if constexpr (std::is_same_v<T, SecretParsedServiceMessage>) {
			line = QString("[service 0x%1]").arg(
				value.actionConstructor,
				8,
				16,
				QLatin1Char('0'));
		} else if constexpr (std::is_same_v<T, SecretParsedUnsupportedMessage>) {
			line = QString("[unsupported %1]").arg(value.description);
		}
	}, message);
	return line;
}

// Serialize a minimal decrypted secret text message body.
[[nodiscard]] QByteArray SerializeSecretTextBody(
		const SecretChatState &state,
		uint64_t randomId,
		const QString &text) {
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
	AppendUInt32(body, 0);
	AppendUInt64(body, randomId);
	AppendInt32(body, 0);
	AppendTLString(body, text);
	return body;
}

[[nodiscard]] PeerId EnsureFakeSecretPeer(
		not_null<Data::Session*> owner,
		int64_t chatId) {
	const auto name = QString("Secret Chat %1").arg(chatId);
	const auto peerId = Data::FakePeerIdForJustName(name);
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
	// Chat-list entry creation is deferred until after Manager() inserts this
	// instance into the static map, otherwise entry refresh can re-enter
	// Manager() during construction and recurse indefinitely.
}

void SecretChatManager::FinishInitialization() {
	EnsureEntriesFromKnownChats();
}

void SecretChatManager::RefreshKnownChats() {
	_knownChats = LoadAllSecretChats(_session);
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

auto SecretChatManager::EnsureRenderState(int64_t chatId) -> RenderState& {
	if (const auto i = _rendered.find(chatId); i != end(_rendered)) {
		return *i->second;
	}
	const auto peerId = EnsureFakeSecretPeer(&_session->data(), chatId);
	auto state = std::make_unique<RenderState>(RenderState{
		.peerId = peerId,
		.history = _session->data().history(peerId),
	});
	if (const auto i = _messages.find(chatId); i != _messages.end()) {
		for (const auto &message : i.value()) {
			AppendRenderedMessage(*state, message);
		}
	}
	auto raw = state.get();
	_rendered.emplace(chatId, std::move(state));
	return *raw;
}

void SecretChatManager::AppendRenderedMessage(
		RenderState &state,
		const SecretParsedMessage &message) {
	const auto &envelope = MessageEnvelope(message);
	auto fields = HistoryItemCommonFields{
		.id = state.history->nextNonHistoryEntryId(),
		.flags = (MessageFlag::FakeHistoryItem
			| MessageFlag::HasFromId
			| (envelope.outgoing ? MessageFlag::Outgoing : MessageFlag())),
		.from = envelope.outgoing
			? _session->userPeerId()
			: state.peerId,
		.date = envelope.date ? envelope.date : base::unixtime::now(),
	};
	const auto item = state.history->addNewLocalMessage(
		std::move(fields),
		TextWithEntities{ .text = RenderMessageText(message) },
		MTP_messageMediaEmpty());
	state.ids.push_back(item->fullId());
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
					state.layer = 73;
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

bool SecretChatManager::SaveState(const SecretChatState &state) const {
	const auto saved = SaveSecretChatState(_session, state);
	if (saved) {
		auto that = const_cast<SecretChatManager*>(this);
		that->RefreshKnownChats();
		for (const auto &descriptor : that->_knownChats) {
			if (descriptor.chatId == state.chat_id) {
				that->EnsureEntryForChat(descriptor);
				break;
			}
		}
	}
	return saved;
}

const QVector<SecretChatDescriptor> &SecretChatManager::KnownChats() const {
	return _knownChats;
}

std::optional<SecretChatState> SecretChatManager::LoadState(int64_t chatId) const {
	return LoadSecretChatState(_session, chatId);
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
	AdvanceIncomingState(message);
	if (const auto state = LoadState(chatId); state.has_value()) {
		EnsureEntryForChat(SecretChatDescriptor{
			.chatId = state->chat_id,
			.accessHash = state->access_hash,
			.adminId = state->admin_id,
			.participantId = state->participant_id,
			.isCreator = state->is_creator,
		});
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

// Encrypt and send a plain-text secret message through messages.sendEncrypted.
bool SecretChatManager::SendText(int64_t chatId, const QString &text) {
	if (text.trimmed().isEmpty()) {
		return false;
	}
	auto state = LoadState(chatId);
	if (!state.has_value()) {
		LOG(("1338 SecretChat: send skipped, missing state chat_id=%1")
			.arg(chatId));
		return false;
	}

	const auto randomId = base::RandomValue<uint64>();
	const auto body = SerializeSecretTextBody(*state, randomId, text);
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
		.arg(text)
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
			.text = text,
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

bool SecretChatManager::DeleteChat(int64_t chatId) {
	const auto removed = DeleteSecretChat(_session, chatId);
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

rpl::producer<int64_t> SecretChatManager::messageUpdates() const {
	return _messageUpdates.events();
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
	if (const auto user = DisplayUserForChat(chatId)) {
		if (Data::IsUserOnline(user, base::unixtime::now())) {
			return QString("online");
		}
		if (const auto username = user->username(); !username.isEmpty()) {
			return '@' + username;
		}
		if (!user->phone().isEmpty()) {
			return '+' + user->phone();
		}
	}
	return QString("Secret chat");
}

} // namespace Data::SecretChats