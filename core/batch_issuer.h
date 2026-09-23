#ifndef QTLIC_BATCH_ISSUER_H
#define QTLIC_BATCH_ISSUER_H

#include "license_types.h"

namespace qtlic {

struct BatchIssueResult {
    QString batchId;
    int issuedCount = 0;
    QString outputDirectory;
};

class BatchIssuer
{
public:
    static bool issueFile(const QString &inputPath,
                          const QString &outputDirectory,
                          const KeyVaultMaterial &keys,
                          BatchIssueResult *result,
                          QString *error = nullptr);
};

} // namespace qtlic

#endif
