#pragma once

#include "data/secret/secret_chat_state.h"
#include "data/secret/secret_chat_types.h"
#include "rpl/event_stream.h"

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
	[[nodiscard]] rpl::producer<int64_t> messageUpdates() const;
	[[nodiscard]] bool SendText(int64_t chatId, const QString &text);
	[[nodiscard]] bool DeleteChat(int64_t chatId);
	[[nodiscard]] UserData *DisplayUserForChat(int64_t chatId) const;
	[[nodiscard]] QString DisplayNameForChat(int64_t chatId) const;
	[[nodiscard]] QString DisplayStatusForChat(int64_t chatId) const;


private:
	struct RenderState;

	void EnsureEntriesFromKnownChats();
	void RestoreMessagesFromStorage();
	void EnsureEntryForChat(const SecretChatDescriptor &descriptor);
	[[nodiscard]] RenderState &EnsureRenderState(int64_t chatId);
	void AppendRenderedMessage(RenderState &state, const SecretParsedMessage &message);
	void AdvanceIncomingState(const SecretParsedMessage &message);
	void RefreshChatListEntry(not_null<Dialogs::SecretChatEntry*> entry);
	void StoreParsedMessage(int64_t chatId, SecretParsedMessage message);
	void RefreshKnownChats();
	not_null<Main::Session*> _session;
	QMap<int64_t, QVector<SecretParsedMessage>> _messages;
	QVector<SecretChatDescriptor> _knownChats;
	std::map<int64_t, std::unique_ptr<Dialogs::SecretChatEntry>> _entries;
	std::map<int64_t, std::unique_ptr<RenderState>> _rendered;
	rpl::event_stream<int64_t> _messageUpdates;
};

SecretChatManager &Manager(not_null<Main::Session*> session);

} // namespace Data::SecretChats