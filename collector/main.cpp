#include <QApplication>
#include <QFileDialog>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSaveFile>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QWidget>

#include "hardware_fingerprint.h"

class CollectorWindow final : public QWidget
{
public:
    CollectorWindow()
    {
        setWindowTitle(QStringLiteral("Qt 离线授权硬件采集器"));
        resize(760, 480);

        QVBoxLayout *layout = new QVBoxLayout(this);
        QFormLayout *form = new QFormLayout;
        m_productId = new QLineEdit;
        m_productId->setPlaceholderText(QStringLiteral("必须与目标应用中的产品标识一致"));
        m_productId->setToolTip(QStringLiteral(
            "用于确认硬件请求属于哪个应用。专业字段名：product_id"));
        form->addRow(QStringLiteral("产品标识"), m_productId);
        layout->addLayout(form);

        m_table = new QTableWidget(0, 3);
        m_table->setHorizontalHeaderLabels(QStringList()
                                           << QStringLiteral("硬件项目")
                                           << QStringLiteral("匿名指纹")
                                           << QStringLiteral("识别提示"));
        m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_table->setToolTip(QStringLiteral(
            "表格仅显示便于识别的名称。悬浮硬件项目可查看专业字段名；保存时仍使用原始配置键。"));
        layout->addWidget(m_table, 1);

        m_status = new QLabel(QStringLiteral("尚未采集"));
        m_status->setWordWrap(true);
        layout->addWidget(m_status);

        QHBoxLayout *buttons = new QHBoxLayout;
        QPushButton *collectButton = new QPushButton(QStringLiteral("重新采集"));
        QPushButton *saveButton = new QPushButton(QStringLiteral("保存硬件请求"));
        saveButton->setToolTip(QStringLiteral("保存为 .qreq 硬件请求文件"));
        buttons->addWidget(collectButton);
        buttons->addWidget(saveButton);
        buttons->addStretch();
        layout->addLayout(buttons);

        connect(collectButton, &QPushButton::clicked, this, [this]() { collect(); });
        connect(saveButton, &QPushButton::clicked, this, [this]() { save(); });
        collect();
    }

private:
    void collect()
    {
        QStringList warnings;
        m_hardware = qtlic::HardwareFingerprint::collect(&warnings);
        m_table->setRowCount(0);
        for (const qtlic::HardwareValue &value : m_hardware) {
            const int row = m_table->rowCount();
            m_table->insertRow(row);
            QTableWidgetItem *name = new QTableWidgetItem(
                        qtlic::HardwareFingerprint::slotDisplayName(value.slot));
            name->setToolTip(QStringLiteral("专业字段名：%1\n硬件类型：%2")
                             .arg(value.slot, value.type));
            QTableWidgetItem *fingerprint = new QTableWidgetItem(value.hash);
            fingerprint->setToolTip(QStringLiteral(
                "由硬件值生成的 SHA-256 匿名指纹；请求文件不会保存原始硬件值。"));
            m_table->setItem(row, 0, name);
            m_table->setItem(row, 1, fingerprint);
            m_table->setItem(row, 2, new QTableWidgetItem(value.displayHint));
        }
        QString status = QStringLiteral("已采集 %1 项。请求文件只保存散列指纹，不保存原始序列号。")
                .arg(m_hardware.size());
        if (!warnings.isEmpty()) status += QStringLiteral("\n警告：") + warnings.join(QStringLiteral("；"));
        m_status->setText(status);
    }

    void save()
    {
        const QString productId = m_productId->text().trimmed();
        if (productId.isEmpty() || m_hardware.isEmpty()) {
            QMessageBox::warning(this, QStringLiteral("不能保存"),
                                 QStringLiteral("请填写产品标识，并确保至少采集到一个硬件项。"));
            return;
        }
        const QString path = QFileDialog::getSaveFileName(
                    this, QStringLiteral("保存硬件请求"), QStringLiteral("device.qreq"),
                    QStringLiteral("硬件请求文件 (*.qreq)"));
        if (path.isEmpty()) return;
        QSaveFile file(path);
        const QByteArray bytes = QJsonDocument(
                    qtlic::HardwareFingerprint::requestToJson(productId, m_hardware))
                .toJson(QJsonDocument::Indented);
        if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit()) {
            QMessageBox::critical(this, QStringLiteral("保存失败"), file.errorString());
            return;
        }
        QMessageBox::information(this, QStringLiteral("保存成功"), path);
    }

    QLineEdit *m_productId = nullptr;
    QTableWidget *m_table = nullptr;
    QLabel *m_status = nullptr;
    QVector<qtlic::HardwareValue> m_hardware;
};

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QApplication::setOrganizationName(QStringLiteral("QtLicenseSystem"));
    QApplication::setApplicationName(QStringLiteral("QtHardwareCollector"));
    CollectorWindow window;
    window.show();
    return app.exec();
}
