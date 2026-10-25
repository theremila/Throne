#include <include/configs/sub/warp.h>
#include <include/api/RPC.h>
#include <include/global/Configs.hpp>
#include <include/global/HTTPRequestHelper.hpp>
#include <include/global/LocalNetwork.hpp>
#include <include/configs/generate.h>
#include <include/configs/sub/WarpCpsPresets.h>
#include <include/database/ProfilesRepo.h>
#include <QMessageBox>
#include <QObject>
#include <QUrl>
#include <QRandomGenerator>

namespace Configs_network {
    namespace {
        QStringList warpAddresses(const Configs_network::WarpIdentity &identity) {
            QStringList addresses;
            if (!identity.ipv4.isEmpty()) addresses << identity.ipv4 + "/32";
            if (!identity.ipv6.isEmpty()) addresses << identity.ipv6 + "/128";
            return addresses;
        }

        QString warpProxy(QString *error) {
            if (!RequestUsesMixedInbound(false, error)) return {};
            const auto &settings = Configs::dataManager->settingsRepo;
            QString host = LocalNetwork::InboundConnectHost();
            if (host.contains(':')) host = "[" + host + "]";
            QString credentials;
            if (settings->inbound_auth) {
                credentials = QString::fromLatin1(QUrl::toPercentEncoding(settings->inbound_user)) + ":" +
                              QString::fromLatin1(QUrl::toPercentEncoding(settings->inbound_pass)) + "@";
            }
            return "http://" + credentials + host + ":" + QString::number(settings->inbound_socks_port);
        }
    }

    std::shared_ptr<WarpIdentity> RegisterWarp(const QString &tunnelType, QString *error) {
        const auto proxy = warpProxy(error);
        if (!error->isEmpty()) return nullptr;

        bool rpcOK = false;
        const auto reply = API::defaultClient->WarpRegister(&rpcOK, tunnelType, proxy,
                                                            Configs::dataManager->settingsRepo->warp_api_hosts);
        if (!rpcOK) {
            *error = QObject::tr("Failed to reach the core.");
            return nullptr;
        }
        if (const auto coreError = reply.error.value_or(""); !coreError.empty()) {
            *error = QString::fromStdString(coreError);
            return nullptr;
        }

        auto identity = std::make_shared<WarpIdentity>();
        identity->deviceId = QString::fromStdString(reply.device_id.value_or(""));
        identity->token = QString::fromStdString(reply.token.value_or(""));
        identity->privateKey = QString::fromStdString(reply.private_key.value_or(""));
        identity->peerPublicKey = QString::fromStdString(reply.peer_public_key.value_or(""));
        identity->endpoint = QString::fromStdString(reply.endpoint.value_or(""));
        identity->ipv4 = QString::fromStdString(reply.ipv4.value_or(""));
        identity->ipv6 = QString::fromStdString(reply.ipv6.value_or(""));
        for (const auto byte : reply.reserved) identity->reserved << byte;
        return identity;
    }

    QJsonObject WarpIdentityToBeanJson(const QString &transport, const Configs_network::WarpIdentity &identity) {
        QString host;
        int port = 0;
        if (transport == QLatin1String("masque")) {
            auto profile = Configs::ProfilesRepo::NewProfile(QStringLiteral("masque"));
            auto *masque = profile->Masque();
            masque->private_key = identity.privateKey;
            masque->peer_public_key = identity.peerPublicKey;
            masque->address = warpAddresses(identity);
            masque->mtu = 1280;
            Configs::SplitWarpEndpoint(identity.endpoint, 443, host, port);
            masque->server = host;
            masque->server_port = port;
            return masque->ExportToJson();
        }
        auto profile = Configs::ProfilesRepo::NewProfile(QStringLiteral("wireguard"));
        auto *wireguard = profile->Wireguard();
        wireguard->private_key = identity.privateKey;
        wireguard->address = warpAddresses(identity);
        wireguard->mtu = 1280;
        wireguard->peer->public_key = identity.peerPublicKey;
        wireguard->peer->reserved = identity.reserved;
        wireguard->peer->persistent_keepalive = "10";
        Configs::SplitWarpEndpoint(identity.endpoint, 2408, host, port);
        wireguard->SetAddress(host);
        wireguard->SetPort(port);
        return wireguard->ExportToJson();
    }

    bool IsWarpIdentityConfig(const QJsonObject &config, const QString &transport) {
        const bool masque = transport == "masque";
        if (config["type"].toString() != (masque ? "masque" : "wireguard")
            || config["private_key"].toString().isEmpty() || config["address"].toArray().isEmpty()) return false;
        return masque ? !config["peer_public_key"].toString().isEmpty()
                      : !config["peers"].toArray().isEmpty()
                        && !config["peers"].toArray().first().toObject()["public_key"].toString().isEmpty();
    }

    QString GenerateWarpCamouflage() {
        const auto packet = warpCpsPresets[QRandomGenerator::global()->bounded(int(warpCpsPresets.size()))];
        return QString::fromLatin1(packet.data(), qsizetype(packet.size()));
    }

    bool ConfirmWarpTerms(QWidget *parent) {
        const auto &settings = Configs::dataManager->settingsRepo;
        if (settings->warp_tos_accepted) return true;
        if (!IsGuiApp()) {
            LogHeadlessDialog(QStringLiteral("ConfirmWarpTerms"), QStringLiteral("Cloudflare WARP"),
                              QStringLiteral("Accept the Cloudflare WARP terms of service?"), QStringLiteral("false"));
            return settings->warp_tos_accepted;
        }

        QMessageBox box(QMessageBox::Question, QObject::tr("Cloudflare WARP"),
                        QObject::tr("Generating a WARP identity registers a new device with Cloudflare.<br><br>"
                                    "Do you accept the <a href=\"%1\">Cloudflare WARP terms of service</a>?")
                            .arg(QStringLiteral("https://www.cloudflare.com/application/terms/")),
                        QMessageBox::Yes | QMessageBox::No, parent);
        box.setTextFormat(Qt::RichText);
        box.setTextInteractionFlags(Qt::TextBrowserInteraction);
        if (box.exec() != QMessageBox::Yes) return false;

        settings->warp_tos_accepted = true;
        settings->Save();
        return true;
    }
}
