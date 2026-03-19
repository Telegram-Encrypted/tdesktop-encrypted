#pragma once

#include "dialogs/dialogs_entry.h"

#include "base/flat_set.h"

namespace Dialogs {

class SecretChatEntry final : public Entry {
public:
	SecretChatEntry(not_null<Data::Session*> owner, int64_t chatId);

	[[nodiscard]] int64_t chatId() const {
		return _chatId;
	}

	[[nodiscard]] int fixedOnTopIndex() const override;
	[[nodiscard]] bool shouldBeInChatList() const override;
	[[nodiscard]] UnreadState chatListUnreadState() const override;
	[[nodiscard]] BadgesState chatListBadgesState() const override;
	[[nodiscard]] HistoryItem *chatListMessage() const override;
	[[nodiscard]] bool chatListMessageKnown() const override;
	[[nodiscard]] const QString &chatListName() const override;
	[[nodiscard]] const QString &chatListNameSortKey() const override;
	[[nodiscard]] int chatListNameVersion() const override;
	[[nodiscard]] const base::flat_set<QString> &chatListNameWords() const override;
	[[nodiscard]] const base::flat_set<QChar> &chatListFirstLetters() const override;

	void chatListPreloadData() override;
	void paintUserpic(
		Painter &p,
		Ui::PeerUserpicView &view,
		const Dialogs::Ui::PaintContext &context) const override;

private:
	void indexNameParts() const;
	void refreshPresentation() const;

	const int64_t _chatId = 0;
	mutable QString _name;
	mutable base::flat_set<QString> _nameWords;
	mutable base::flat_set<QChar> _nameFirstLetters;
	mutable int _nameVersion = 1;
};

} // namespace Dialogs