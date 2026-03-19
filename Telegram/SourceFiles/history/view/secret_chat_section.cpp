#include "history/view/secret_chat_section.h"

#include "data/secret/secret_chat_manager.h"
#include "dialogs/dialogs_key.h"
#include "chat_helpers/message_field.h"
#include "history/history.h"
#include "history/history_item.h"
#include "ui/chat/chat_theme.h"
#include "ui/controls/send_button.h"
#include "ui/painter.h"
#include "ui/widgets/elastic_scroll.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "window/themes/window_theme.h"

#include "styles/style_chat.h"
#include "styles/style_chat_helpers.h"
#include "styles/style_dialogs.h"
#include "styles/style_settings.h"

#include "rpl/filter.h"

#include <algorithm>
#include <lang_auto.h>

namespace HistoryView {

namespace {

const auto kSecretChatNameColor = QColor(0x4E, 0xAD, 0x41);

void PaintTintedIcon(
		Painter &p,
		const style::icon &icon,
		QPoint position,
		const QColor &color) {
	const auto ratio = style::DevicePixelRatio();
	auto image = QImage(
		QSize(icon.width() * ratio, icon.height() * ratio),
		QImage::Format_ARGB32_Premultiplied);
	image.fill(Qt::transparent);
	image.setDevicePixelRatio(ratio);
	{
		Painter q(&image);
		icon.paint(q, QPoint(0, 0), icon.width());
		q.setCompositionMode(QPainter::CompositionMode_SourceIn);
		q.fillRect(QRect(QPoint(0, 0), QSize(icon.width(), icon.height())), color);
	}
	p.drawImage(position, image);
}

} // namespace

SecretChatMemento::SecretChatMemento(int64_t chatId)
: _chatId(chatId) {
}

object_ptr<Window::SectionWidget> SecretChatMemento::createWidget(
		QWidget *parent,
		not_null<Window::SessionController*> controller,
		Window::Column column,
		const QRect &geometry) {
	if (column == Window::Column::Third) {
		return nullptr;
	}
	auto result = object_ptr<SecretChatWidget>(parent, controller, _chatId);
	result->setGeometry(geometry);
	return result;
}

SecretChatWidget::SecretChatWidget(
		QWidget *parent,
		not_null<Window::SessionController*> controller,
		int64_t chatId)
: SectionWidget(parent, controller)
, WindowListDelegate(controller)
, _chatId(chatId)
, _history(Data::SecretChats::Manager(&session()).ViewHistoryForChat(chatId))
, _theme(Window::Theme::DefaultChatThemeOn(lifetime()))
, _title(std::make_unique<Ui::FlatLabel>(
		this,
		rpl::single(Data::SecretChats::Manager(&session()).DisplayNameForChat(chatId)),
		st::previewName))
, _status(std::make_unique<Ui::FlatLabel>(
		this,
		rpl::single(Data::SecretChats::Manager(&session()).DisplayStatusForChat(chatId)),
		st::previewStatus))
, _scroll(std::make_unique<Ui::ElasticScroll>(this))
, _field(object_ptr<Ui::InputField>(
		this,
		st::historyComposeField,
		Ui::InputField::Mode::MultiLine,
		tr::lng_message_ph()))
, _send(std::make_shared<Ui::SendButton>(this, st::historySend)) {
	_title->setAttribute(Qt::WA_TransparentForMouseEvents);
	_title->setTextColorOverride(kSecretChatNameColor);
	_status->setAttribute(Qt::WA_TransparentForMouseEvents);
	InitMessageField(controller, _field, nullptr);
	_send->show();
	_inner = _scroll->setOwnedWidget(object_ptr<ListWidget>(
		this,
		&session(),
		static_cast<ListDelegate*>(this)));
	_scroll->setOverscrollBg(QColor(0, 0, 0, 0));
	using Type = Ui::ElasticScroll::OverscrollType;
	_scroll->setOverscrollTypes(Type::Real, Type::Real);
	_scroll->scrolls() | rpl::on_next([=] {
		updateInnerVisibleArea();
	}, lifetime());
	_inner->scrollKeyEvents() | rpl::on_next([=](not_null<QKeyEvent*> e) {
		_scroll->keyPressEvent(e);
	}, lifetime());
	_inner->refreshViewer();
	crl::on_main(this, [=] {
		_field->setFocusFast();
	});
	_field->submits() | rpl::on_next([=] {
		submitField();
	}, lifetime());
	_send->clicks() | rpl::on_next([=] {
		submitField();
	}, lifetime());
	Data::SecretChats::Manager(&session()).messageUpdates(
	) | rpl::filter([=](int64_t updatedChatId) {
		return updatedChatId == _chatId;
	}) | rpl::on_next([=](int64_t) {
		_inner->refreshViewer();
		updateInnerVisibleArea();
	}, lifetime());
}

SecretChatWidget::~SecretChatWidget() = default;

Dialogs::RowDescriptor SecretChatWidget::activeChat() const {
	if (const auto entry = Data::SecretChats::Manager(&session()).EntryForChat(_chatId)) {
		return { Dialogs::Key(entry), FullMsgId() };
	}
	return {};
}

bool SecretChatWidget::showInternal(
		not_null<Window::SectionMemento*> memento,
		const Window::SectionShow &params) {
	if (const auto secret = dynamic_cast<SecretChatMemento*>(memento.get())) {
		return (secret->chatId() == _chatId);
	}
	return false;
}

bool SecretChatWidget::sameTypeAs(not_null<Window::SectionMemento*> memento) {
	return (dynamic_cast<SecretChatMemento*>(memento.get()) != nullptr);
}

std::shared_ptr<Window::SectionMemento> SecretChatWidget::createMemento() {
	return std::make_shared<SecretChatMemento>(_chatId);
}

bool SecretChatWidget::hasTopBarShadow() const {
	return true;
}

bool SecretChatWidget::floatPlayerHandleWheelEvent(QEvent *e) {
	return false;
}

QRect SecretChatWidget::floatPlayerAvailableRect() {
	return rect().marginsRemoved({ 0, st::previewTop.height, 0, 0 });
}

void SecretChatWidget::checkActivation() {
	_inner->checkActivation();
}

void SecretChatWidget::resizeEvent(QResizeEvent *e) {
	SectionWidget::resizeEvent(e);
	const auto titleLeft = st::previewTop.namePosition.x()
		+ st::dialogsUnlockIcon.width()
		+ st::dialogsChatTypeSkip;
	_title->resizeToNaturalWidth(width() - titleLeft);
	_title->move(titleLeft, st::previewTop.namePosition.y());
	_status->resizeToNaturalWidth(width() - st::previewTop.statusPosition.x());
	_status->move(st::previewTop.statusPosition);
	const auto composeHeight = _field->height() + 2 * st::historySendPadding;
	_scroll->setGeometry(rect().marginsRemoved({ 0, st::previewTop.height, 0, composeHeight }));
	_inner->resizeToWidth(_scroll->width(), _scroll->height());
	const auto fieldWidth = width() - st::historySendRight - _send->width();
	_field->resizeToWidth(fieldWidth);
	_field->moveToLeft(
		st::historySendPadding,
		height() - composeHeight + st::historySendPadding,
		width());
	_send->moveToRight(0, height() - st::historySendSize.height(), width());
	updateInnerVisibleArea();
}

void SecretChatWidget::paintEvent(QPaintEvent *e) {
	Painter p(this);
	Window::SectionWidget::PaintBackground(
		p,
		_theme.get(),
		QSize(width(), height() * 2),
		e->rect());
	p.fillRect(0, height() - st::historySendSize.height(), width(), st::historySendSize.height(), st::historyComposeAreaBg);
	p.fillRect(0, 0, width(), st::previewTop.height, st::topBarBg);
	PaintTintedIcon(
		p,
		st::dialogsUnlockIcon,
		st::previewTop.namePosition,
		kSecretChatNameColor);
	p.fillRect(0, st::previewTop.height, width(), st::lineWidth, st::shadowFg);
	p.fillRect(0, height() - st::historySendSize.height() - st::lineWidth, width(), st::lineWidth, st::shadowFg);
}

void SecretChatWidget::doSetInnerFocus() {
	_field->setFocusFast();
}

// Submit the current plain-text field content into the secret-chat manager.
void SecretChatWidget::submitField() {
	if (!HasSendText(_field)) {
		return;
	}
	const auto text = _field->getTextWithAppliedMarkdown().text;
	if (Data::SecretChats::Manager(&session()).SendText(_chatId, text)) {
		_field->setText(QString());
	}
}

void SecretChatWidget::updateInnerVisibleArea() {
	const auto scrollTop = _scroll->scrollTop();
	_inner->setVisibleTopBottom(scrollTop, scrollTop + _scroll->height());
}

Context SecretChatWidget::listContext() {
	return Context::ChatPreview;
}

bool SecretChatWidget::listScrollTo(int top, bool syntetic) {
	top = std::clamp(top, 0, _scroll->scrollTopMax());
	if (_scroll->scrollTop() == top) {
		updateInnerVisibleArea();
		return false;
	}
	_scroll->scrollToY(top);
	return true;
}

void SecretChatWidget::listCancelRequest() {
}

void SecretChatWidget::listDeleteRequest() {
}

void SecretChatWidget::listTryProcessKeyInput(not_null<QKeyEvent*> e) {
}

rpl::producer<Data::MessagesSlice> SecretChatWidget::listSource(
		Data::MessagePosition aroundId,
		int limitBefore,
		int limitAfter) {
	auto result = Data::MessagesSlice();
	result.ids = Data::SecretChats::Manager(&session()).ViewMessageIds(_chatId);
	result.nearestToAround = result.ids.empty() ? FullMsgId() : result.ids.back();
	return rpl::single(std::move(result));
}

bool SecretChatWidget::listAllowsMultiSelect() {
	return false;
}

bool SecretChatWidget::listIsItemGoodForSelection(not_null<HistoryItem*> item) {
	return false;
}

bool SecretChatWidget::listIsLessInOrder(
		not_null<HistoryItem*> first,
		not_null<HistoryItem*> second) {
	if (first->isRegular() && second->isRegular()) {
		const auto firstPeer = first->history()->peer;
		const auto secondPeer = second->history()->peer;
		if (firstPeer == secondPeer) {
			return first->id < second->id;
		}
	}
	return first->id < second->id;
}

void SecretChatWidget::listSelectionChanged(SelectedItems &&items) {
}

void SecretChatWidget::listMarkReadTill(not_null<HistoryItem*> item) {
}

void SecretChatWidget::listMarkContentsRead(
		const base::flat_set<not_null<HistoryItem*>> &items) {
}

MessagesBarData SecretChatWidget::listMessagesBar(
		const std::vector<not_null<Element*>> &elements) {
	return {};
}

void SecretChatWidget::listContentRefreshed() {
}

void SecretChatWidget::listUpdateDateLink(
		ClickHandlerPtr &link,
		not_null<Element*> view) {
}

bool SecretChatWidget::listElementHideReply(not_null<const Element*> view) {
	return false;
}

bool SecretChatWidget::listElementShownUnread(not_null<const Element*> view) {
	return false;
}

bool SecretChatWidget::listIsGoodForAroundPosition(not_null<const Element*> view) {
	return view->data()->isRegular();
}

void SecretChatWidget::listSendBotCommand(
		const QString &command,
		const FullMsgId &context) {
}

void SecretChatWidget::listSearch(
		const QString &query,
		const FullMsgId &context) {
}

void SecretChatWidget::listHandleViaClick(not_null<UserData*> bot) {
}

not_null<Ui::ChatTheme*> SecretChatWidget::listChatTheme() {
	return _theme.get();
}

CopyRestrictionType SecretChatWidget::listCopyRestrictionType(HistoryItem *item) {
	return CopyRestrictionType::None;
}

CopyRestrictionType SecretChatWidget::listCopyMediaRestrictionType(
		not_null<HistoryItem*> item) {
	return CopyRestrictionType::None;
}

CopyRestrictionType SecretChatWidget::listSelectRestrictionType() {
	return CopyRestrictionType::None;
}

auto SecretChatWidget::listAllowedReactionsValue()
		-> rpl::producer<Data::AllowedReactions> {
	return rpl::single(Data::AllowedReactions());
}

void SecretChatWidget::listShowPremiumToast(not_null<DocumentData*> document) {
}

void SecretChatWidget::listOpenPhoto(
		not_null<PhotoData*> photo,
		FullMsgId context) {
}

void SecretChatWidget::listOpenDocument(
		not_null<DocumentData*> document,
		FullMsgId context,
		bool showInMediaView) {
}

void SecretChatWidget::listPaintEmpty(
		Painter &p,
		const Ui::ChatPaintContext &context) {
}

QString SecretChatWidget::listElementAuthorRank(not_null<const Element*> view) {
	return {};
}

bool SecretChatWidget::listElementHideTopicButton(not_null<const Element*> view) {
	return true;
}

History *SecretChatWidget::listTranslateHistory() {
	return nullptr;
}

void SecretChatWidget::listAddTranslatedItems(
		not_null<TranslateTracker*> tracker) {
}

} // namespace HistoryView