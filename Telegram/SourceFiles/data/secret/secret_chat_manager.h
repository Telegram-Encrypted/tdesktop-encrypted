#pragma once

#include "base/timer.h"
#include "data/secret/secret_chat_state.h"
#include "data/secret/secret_chat_types.h"
#include "rpl/event_stream.h"
#include "rpl/lifetime.h"
#include "ui/text/text_entity.h"

#include <QMap>
#include <QVector>
#include <map>
#include <memory>
#include <optional>
#include <vector>

namespace Dialogs {
class Entry;
class SecretChatEntry;
} // namespace Dialogs

namespace Main {
class Session;
} // namespace Main

class History;
class UserData;

namespace Data::SecretChats {

class SecretChatManager {
public:
	explicit SecretChatManager(not_null<Main::Session*> session);
	void FinishInitialization();

	void HandleEncryptedMessage(
		int64_t chatId,
		const QByteArray &payload,
		const char *tag);

	void HandleEncryptedChatRequested(
		int32 requestedChatId,
		uint64 requestedAccessHash,
		uint64 requestedAdminId,
		uint64 requestedParticipantId,
		const QByteArray &requestedGA,
		int32 requestDate);

	void LogEncryptionChat(const MTPEncryptedChat &chat, const char *tag) const;

	bool SaveState(const SecretChatState &state) const;
	std::optional<SecretChatState> LoadState(int64_t chatId) const;
	const QVector<SecretParsedMessage> &Messages(int64_t chatId) const;
	const QVector<SecretChatDescriptor> &KnownChats() const;
	[[nodiscard]] Dialogs::Entry *EntryForChat(int64_t chatId) const;
	[[nodiscard]] not_null<History*> ViewHistoryForChat(int64_t chatId);
	[[nodiscard]] const std::vector<FullMsgId> &ViewMessageIds(int64_t chatId);
	[[nodiscard]] std::optional<int64_t> ChatIdForUser(UserId userId) const;
	[[nodiscard]] std::optional<int64_t> ChatIdForHistory(
		not_null<const History*> history) const;
	[[nodiscard]] std::optional<int64_t> ChatIdForPeer(PeerId peerId) const;
	[[nodiscard]] rpl::producer<int64_t> messageUpdates() const;
	[[nodiscard]] rpl::producer<int64_t> presentationUpdates() const;
	[[nodiscard]] bool SendText(
		int64_t chatId,
		const ::TextWithEntities &textWithEntities,
		const FullReplyTo &replyTo = FullReplyTo());
	[[nodiscard]] bool DeleteChat(int64_t chatId);
	[[nodiscard]] UserData *DisplayUserForChat(int64_t chatId) const;
	[[nodiscard]] QString DisplayNameForChat(int64_t chatId) const;
	[[nodiscard]] QString DisplayStatusForChat(int64_t chatId) const;
	[[nodiscard]] QString WaitingStatusForChat(int64_t chatId) const;
	[[nodiscard]] bool IsChatReady(int64_t chatId) const;
	[[nodiscard]] bool StartChat(
		not_null<UserData*> user,
		Fn<void(int64_t)> onReady = nullptr);
	void UpdateTyping(int64_t chatId);
	void CancelTyping(int64_t chatId);
	void HandleEncryptedChatWaiting(const MTPEncryptedChat &chat);
	void HandleEncryptedChatEstablished(const MTPEncryptedChat &chat);
	void HandleEncryptedTyping(int64_t chatId);
	void HandleEncryptedMessagesRead(int64_t chatId, TimeId maxDate);
	void MarkReadTill(int64_t chatId, TimeId maxDate);


private:
	struct RenderState;
	using States = std::map<int64_t, SecretChatState>;

	void EnsureEntriesFromKnownChats();
	void RestoreMessagesFromStorage();
	void EnsureEntryForChat(const SecretChatDescriptor &descriptor);
	void UpsertKnownChat(const SecretChatState &state);
	[[nodiscard]] RenderState &EnsureRenderState(int64_t chatId);
	void AppendRenderedMessage(
		RenderState &state,
		const SecretParsedMessage &message,
		bool restored = false);
	void AdvanceIncomingState(const SecretParsedMessage &message);
	void RefreshChatListEntry(not_null<Dialogs::SecretChatEntry*> entry);
	void StoreParsedMessage(int64_t chatId, SecretParsedMessage message);
	void RefreshKnownChats();
	void RefreshPresentation(int64_t chatId);
	void ClearTyping(int64_t chatId);
	not_null<Main::Session*> _session;
	States _states;
	QMap<int64_t, QVector<SecretParsedMessage>> _messages;
	QVector<SecretChatDescriptor> _knownChats;
	std::map<int64_t, std::unique_ptr<Dialogs::SecretChatEntry>> _entries;
	std::map<int64_t, std::unique_ptr<RenderState>> _rendered;
	std::map<int64_t, std::unique_ptr<base::Timer>> _typingTimers;
	std::map<int64_t, crl::time> _typingUntil;
	std::map<int64_t, std::unique_ptr<base::Timer>> _outgoingTypingTimers;
	std::map<int64_t, crl::time> _outgoingTypingUpdated;
	std::map<int64_t, bool> _outgoingTypingActive;
	std::map<int64_t, TimeId> _readTillSent;
	rpl::event_stream<int64_t> _messageUpdates;
	rpl::event_stream<int64_t> _presentationUpdates;
	rpl::lifetime _lifetime;
};

SecretChatManager &Manager(not_null<Main::Session*> session);

} // namespace Data::SecretChats