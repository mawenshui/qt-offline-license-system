#ifndef QTLIC_UI_THEME_H
#define QTLIC_UI_THEME_H

#include <QApplication>
#include <QBoxLayout>
#include <QFont>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QStyle>
#include <QVBoxLayout>
#include <QWidget>

namespace qtlic {
namespace ui {

inline QString styleSheet()
{
    return QStringLiteral(R"QSS(
QWidget {
    color: #263642;
    font-family: "Microsoft YaHei UI", "Noto Sans CJK SC";
    font-size: 10pt;
}
QMainWindow, QWidget#AppShell {
    background: #f3f1ec;
}
QScrollArea, QScrollArea > QWidget > QWidget {
    background: #f3f1ec;
}
QWidget#HeroPanel {
    background: #173247;
    border: 1px solid #294a60;
    border-radius: 10px;
}
QLabel[role="eyebrow"] {
    color: #c9903d;
    font-size: 9pt;
    font-weight: 700;
}
QLabel[role="appTitle"] {
    color: #ffffff;
    font-size: 22pt;
    font-weight: 700;
}
QLabel[role="appDescription"] {
    color: #cdd8df;
    font-size: 10pt;
}
QLabel[role="badge"] {
    color: #f8dfb4;
    background: #28485d;
    border: 1px solid #49677a;
    border-radius: 12px;
    padding: 6px 11px;
    font-size: 9pt;
    font-weight: 600;
}
QLabel[role="pageTitle"] {
    color: #173247;
    font-size: 16pt;
    font-weight: 700;
}
QLabel[role="pageDescription"], QLabel[role="helper"] {
    color: #677782;
}
QLabel[role="counter"] {
    color: #8b3530;
    font-size: 9pt;
}
QLabel[role="counter"][state="valid"] {
    color: #28704e;
}
QLabel[role="countdown"] {
    color: #526873;
    font-size: 9pt;
    font-weight: 600;
}
QLabel[role="countdown"][state="warning"] {
    color: #9a5316;
}
QLabel[role="warning"] {
    color: #70420f;
    background: #fff6e5;
    border: 1px solid #e9c98e;
    border-radius: 7px;
    padding: 10px 12px;
}
QLabel[role="status"] {
    border-radius: 7px;
    padding: 10px 12px;
    font-weight: 600;
}
QLabel[role="status"][state="info"] {
    color: #31536a;
    background: #eaf2f6;
    border: 1px solid #b9cfda;
}
QLabel[role="status"][state="success"] {
    color: #235d43;
    background: #e9f5ee;
    border: 1px solid #afd3bd;
}
QLabel[role="status"][state="error"] {
    color: #8b3530;
    background: #fbeceb;
    border: 1px solid #e0b4b0;
}
QLabel[role="status"][state="warning"] {
    color: #70420f;
    background: #fff6e5;
    border: 1px solid #e9c98e;
}
QGroupBox {
    background: #ffffff;
    border: 1px solid #d9d5cc;
    border-radius: 9px;
    margin-top: 14px;
    padding: 17px 14px 14px 14px;
    font-weight: 600;
    color: #173247;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 13px;
    padding: 0 6px;
    background: #f3f1ec;
}
QLineEdit, QComboBox, QSpinBox, QDateTimeEdit, QTextEdit {
    color: #263642;
    background: #ffffff;
    border: 1px solid #c9c5bc;
    border-radius: 6px;
    padding: 7px 9px;
    selection-background-color: #2f617c;
    selection-color: #ffffff;
}
QLineEdit, QComboBox, QSpinBox, QDateTimeEdit {
    min-height: 22px;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus,
QDateTimeEdit:focus, QTextEdit:focus {
    border: 2px solid #b97828;
    padding: 6px 8px;
}
QLineEdit[invalid="true"], QComboBox[invalid="true"],
QSpinBox[invalid="true"], QDateTimeEdit[invalid="true"],
QTableWidget[invalid="true"] {
    border: 2px solid #b94b43;
}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled,
QDateTimeEdit:disabled, QTextEdit:disabled {
    color: #8a969d;
    background: #eceae5;
}
QComboBox::drop-down {
    border: 0;
    width: 26px;
}
QPushButton {
    color: #25475c;
    background: #ffffff;
    border: 1px solid #9db0bc;
    border-radius: 6px;
    padding: 7px 15px;
    min-height: 22px;
    font-weight: 600;
}
QPushButton:hover {
    background: #edf3f6;
    border-color: #55788d;
}
QPushButton:pressed {
    background: #dde9ee;
}
QPushButton:focus {
    border: 2px solid #c58a38;
    padding: 6px 14px;
}
QPushButton[role="primary"] {
    color: #ffffff;
    background: #173f58;
    border-color: #173f58;
}
QPushButton[role="primary"]:hover {
    background: #245873;
    border-color: #245873;
}
QPushButton[role="accent"] {
    color: #ffffff;
    background: #a65f18;
    border-color: #a65f18;
}
QPushButton[role="accent"]:hover {
    background: #bd7124;
    border-color: #bd7124;
}
QPushButton[role="danger"] {
    color: #963c35;
    background: #fffafa;
    border-color: #d2a39f;
}
QPushButton:disabled {
    color: #8d979c;
    background: #e7e5e0;
    border-color: #d1cdc4;
}
QTabWidget::pane {
    border: 0;
    top: 7px;
}
QTabBar::tab {
    color: #526774;
    background: #e2dfd8;
    border: 1px solid #d2cec5;
    border-bottom: 0;
    padding: 9px 18px;
    margin-right: 3px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 600;
}
QTabBar::tab:hover {
    color: #173247;
    background: #ece9e3;
}
QTabBar::tab:selected {
    color: #ffffff;
    background: #315b72;
    border-color: #315b72;
}
QTableView {
    color: #263642;
    background: #ffffff;
    alternate-background-color: #f7f6f2;
    border: 1px solid #d6d2c9;
    border-radius: 7px;
    gridline-color: #ebe8e1;
    selection-background-color: #dce9ef;
    selection-color: #173247;
}
QTableView::item {
    padding: 6px;
}
QHeaderView::section {
    color: #3a5261;
    background: #e9e6df;
    border: 0;
    border-right: 1px solid #d3cfc6;
    border-bottom: 1px solid #cbc6bc;
    padding: 8px 7px;
    font-weight: 700;
}
QCheckBox {
    spacing: 7px;
}
QStatusBar {
    color: #536873;
    background: #e8e5de;
    border-top: 1px solid #d4d0c7;
}
QToolTip {
    color: #f7f7f4;
    background: #203744;
    border: 1px solid #557080;
    padding: 6px;
}
)QSS");
}

inline void applyTheme(QApplication &app)
{
    QFont font(QStringLiteral("Microsoft YaHei UI"));
    font.setPointSize(10);
    app.setFont(font);
    app.setStyleSheet(styleSheet());
}

inline QLabel *label(const QString &text, const char *role, bool wordWrap = false)
{
    QLabel *result = new QLabel(text);
    result->setProperty("role", role);
    result->setWordWrap(wordWrap);
    return result;
}

inline void addApplicationHeader(QBoxLayout *layout, const QString &eyebrow,
                                 const QString &title, const QString &description,
                                 const QString &badge)
{
    QWidget *panel = new QWidget;
    panel->setObjectName(QStringLiteral("HeroPanel"));
    QHBoxLayout *row = new QHBoxLayout(panel);
    row->setContentsMargins(22, 18, 22, 18);
    row->setSpacing(18);
    QVBoxLayout *copy = new QVBoxLayout;
    copy->setSpacing(4);
    copy->addWidget(label(eyebrow, "eyebrow"));
    copy->addWidget(label(title, "appTitle"));
    copy->addWidget(label(description, "appDescription", true));
    row->addLayout(copy, 1);
    row->addWidget(label(badge, "badge"), 0, Qt::AlignTop);
    layout->addWidget(panel);
}

inline void addPageHeader(QBoxLayout *layout, const QString &eyebrow,
                          const QString &title, const QString &description)
{
    layout->addWidget(label(eyebrow, "eyebrow"));
    layout->addWidget(label(title, "pageTitle"));
    layout->addWidget(label(description, "pageDescription", true));
    layout->addSpacing(5);
}

inline void setButtonRole(QPushButton *button, const char *role)
{
    button->setProperty("role", role);
}

inline void setStatus(QLabel *status, const QString &text, const char *state)
{
    status->setText(text);
    status->setProperty("role", "status");
    status->setProperty("state", state);
    status->style()->unpolish(status);
    status->style()->polish(status);
    status->update();
}

} // namespace ui
} // namespace qtlic

#endif
