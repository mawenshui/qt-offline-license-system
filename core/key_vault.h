#ifndef QTLIC_KEY_VAULT_H
#define QTLIC_KEY_VAULT_H

#include "license_types.h"

namespace qtlic {

class KeyVault
{
public:
    static bool create(const QString &path, const QByteArray &password,
                       const QString &productId, KeyVaultMaterial *material,
                       QString *error = nullptr);
    static bool open(const QString &path, const QByteArray &password,
                     KeyVaultMaterial *material, QString *error = nullptr);
    static bool save(const QString &path, const QByteArray &password,
                     const KeyVaultMaterial &material, QString *error = nullptr);
    static bool exportRuntimeJson(const QString &path, const KeyVaultMaterial &material,
                                  QString *error = nullptr);
    static bool exportRuntimeHeader(const QString &path, const KeyVaultMaterial &material,
                                    QString *error = nullptr);
};

} // namespace qtlic

#endif
