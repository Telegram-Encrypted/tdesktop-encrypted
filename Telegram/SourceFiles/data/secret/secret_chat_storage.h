#pragma once

#include "data/secret/secret_chat_state.h"
#include "data/secret/secret_chat_types.h"

#include <QVector>
#include <optional>

namespace Main {
class Session;
} // namespace Main

namespace Data::SecretChats {

bool SaveSecretChatState(
	Main::Session *session,
	const SecretChatState &state);
std::optional<SecretChatState> LoadSecretChatState(
	Main::Session *session,
	int64_t chatId);
QVector<SecretChatDescriptor> LoadAllSecretChats(
	Main::Session *session);
bool SaveSecretChatMessages(
	Main::Session *session,
	int64_t chatId,
	const QVector<SecretParsedMessage> &messages);
QVector<SecretParsedMessage> LoadSecretChatMessages(
	Main::Session *session,
	int64_t chatId);
bool DeleteSecretChat(
	Main::Session *session,
	int64_t chatId);

} // namespace Data::SecretChats