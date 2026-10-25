#pragma once
#include <QList>
#include <QJsonObject>
#include <QString>
#include <memory>

class QWidget;

namespace Configs_network {
    struct WarpIdentity {
        QString deviceId, token, privateKey, peerPublicKey, endpoint, ipv4, ipv6;
        QList<int> reserved;
    };

    QJsonObject WarpIdentityToBeanJson(const QString &transport, const WarpIdentity &identity);
    bool IsWarpIdentityConfig(const QJsonObject &config, const QString &transport);

    // Public, non-account-specific camouflage; identities still come from RegisterWarp.
    QString GenerateWarpCamouflage();

    // Blocking (RPC); never call on the UI thread. tunnelType: "wireguard" | "masque".
    std::shared_ptr<WarpIdentity> RegisterWarp(const QString &tunnelType, QString *error);
    // Asks once (persisted in settings warp_tos_accepted) whether the user accepts Cloudflare's WARP terms; UI thread only. Without a QApplication it returns the stored answer.
    bool ConfirmWarpTerms(QWidget *parent);
}
