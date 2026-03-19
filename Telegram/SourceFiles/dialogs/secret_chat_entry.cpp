#include "dialogs/secret_chat_entry.h"

#include "data/secret/secret_chat_manager.h"
#include "data/data_user.h"
#include "dialogs/ui/dialogs_layout.h"
#include "styles/style_dialogs.h"
#include "ui/empty_userpic.h"
#include "ui/painter.h"
#include "ui/text/text_utilities.h"

namespace Dialogs {

SecretChatEntry::SecretChatEntry(not_null<Data::Session*> owner, int64_t chatId)
: Entry(owner, Type::SecretChat)
, _chatId(chatId)
, _name(QString("Secret Chat %1").arg(chatId)) {
	indexNameParts();
}

int SecretChatEntry::fixedOnTopIndex() const {
	return 0;
}

bool SecretChatEntry::shouldBeInChatList() const {
	return true;
}

UnreadState SecretChatEntry::chatListUnreadState() const {
	return {};
}

BadgesState SecretChatEntry::chatListBadgesState() const {
	return {};
}

HistoryItem *SecretChatEntry::chatListMessage() const {
	return nullptr;
}

bool SecretChatEntry::chatListMessageKnown() const {
	return true;
}

const QString &SecretChatEntry::chatListName() const {
	refreshPresentation();
	return _name;
}

const QString &SecretChatEntry::chatListNameSortKey() const {
	refreshPresentation();
	static const auto empty = QString();
	return empty;
}

int SecretChatEntry::chatListNameVersion() const {
	refreshPresentation();
	return _nameVersion;
}

const base::flat_set<QString> &SecretChatEntry::chatListNameWords() const {
	refreshPresentation();
	return _nameWords;
}

const base::flat_set<QChar> &SecretChatEntry::chatListFirstLetters() const {
	refreshPresentation();
	return _nameFirstLetters;
}

void SecretChatEntry::chatListPreloadData() {
}

void SecretChatEntry::paintUserpic(
		Painter &p,
		Ui::PeerUserpicView &view,
		const Dialogs::Ui::PaintContext &context) const {
	refreshPresentation();
	if (const auto user = Data::SecretChats::Manager(&session()).DisplayUserForChat(_chatId)) {
		user->paintUserpic(
			p,
			view,
			context.st->padding.left(),
			context.st->padding.top(),
			context.st->photoSize,
			true);
		return;
	}
	Ui::EmptyUserpic(
		Ui::EmptyUserpic::UserpicColor(Ui::EmptyUserpic::ColorIndex(_chatId)),
		_name).paintCircle(
			p,
			context.st->padding.left(),
			context.st->padding.top(),
			context.st->photoSize,
			context.st->photoSize);
}

void SecretChatEntry::refreshPresentation() const {
	const auto resolved = Data::SecretChats::Manager(&session()).DisplayNameForChat(_chatId);
	if (_name == resolved) {
		return;
	}
	_name = resolved;
	indexNameParts();
	++_nameVersion;
}

void SecretChatEntry::indexNameParts() const {
	_nameWords.clear();
	_nameFirstLetters.clear();
	const auto prepared = TextUtilities::PrepareSearchWords(_name);
	for (const auto &part : prepared) {
		if (part.isEmpty()) {
			continue;
		}
		_nameWords.insert(part);
		_nameFirstLetters.insert(part[0]);
	}
}

} // namespace Dialogs