#include "include/global/Configs.hpp"
#include "include/configs/generate.h"
#include "include/configs/outbounds/autoselector.h"
#include "include/configs/outbounds/vless.h"
#include "include/configs/outbounds/xrayVless.h"
#include "include/database/GroupsRepo.h"
#include "include/database/ProfilesRepo.h"
#include "include/database/RoutesRepo.h"
#include "include/database/OtpProfilesRepo.h"
#include "include/database/TrafficStatsRepo.h"
#include "include/database/MarkersRepo.h"
#include "include/database/IpListsRepo.h"
#include "include/database/IpScansRepo.h"
#include "include/api/RPC.h"
#include "include/ui/setting/dialog_manage_routes.h"

#include <QApplication>
#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QLocalServer>
#include <QProcess>
#include <QSet>
#include <QTemporaryDir>
#include <iostream>
#include <stdexcept>

using namespace Configs;

namespace {
void require(bool condition, const QString &message) {
    if (!condition) throw std::runtime_error(message.toStdString());
}

std::shared_ptr<Profile> makeProfile(const QString &type, const QString &server, int gid) {
    auto profile = ProfilesRepo::NewProfile(type);
    profile->name = server;
    profile->outbound->server = server;
    profile->outbound->server_port = 443;
    const QString uuid = "00000000-0000-4000-8000-000000000001";
    if (auto *vless = profile->VLESS()) vless->uuid = uuid;
    if (auto *vless = profile->XrayVLESS()) vless->uuid = uuid;
    require(dataManager->profilesRepo->AddProfile(profile, gid), "Save fixture profile");
    return profile;
}

QJsonObject warpEndpoint(const QJsonObject &config) {
    for (const auto value : config["endpoints"].toArray()) {
        const auto endpoint = value.toObject();
        if (endpoint["type"] == "wireguard") return endpoint;
    }
    throw std::runtime_error("Missing WARP endpoint");
}
}

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    QTemporaryDir temp;
    QProcess core;
    try {
        require(temp.isValid() && QDir::setCurrent(temp.path()), "Temporary data directory");
        initDB((temp.path() + "/throne.db").toStdString());
        auto &settings = *dataManager->settingsRepo;
        settings.current_group = dataManager->groupsRepo->GetAllGroupIds().first();
        settings.current_route_id = dataManager->routesRepo->GetAllRouteProfileIds().first();
        auto route = dataManager->routesRepo->GetRouteProfile(settings.current_route_id);
        route->Rules.clear();
        require(dataManager->routesRepo->Save(route), "Save fixture routing profile");
        settings.spmode_vpn = false;
        settings.enable_ntp = false;
        settings.enable_warp = true;
        settings.warp_mode = "amnezia";
        settings.warp_ep = "162.159.192.1:2408";
        // Synthetic, unregistered client key and Cloudflare's public server key.
        settings.warp_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=";
        settings.warp_public_key = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
        settings.warp_ifc_addrs = {"172.16.0.2/32"};

        QLocalServer server;
        const QString socket = temp.filePath("core.sock");
        require(server.listen(socket), server.errorString());
        auto env = QProcessEnvironment::systemEnvironment();
        env.insert("THRONE_CORE_SOCKET", socket);
        core.setProcessEnvironment(env);
        core.setStandardOutputFile(temp.filePath("core.stdout"));
        core.setStandardErrorFile(temp.filePath("core.stderr"));
        core.start(QCoreApplication::applicationDirPath() + "/ThroneCore");
        require(core.waitForStarted(), "Start core");
        if (!server.waitForNewConnection(10000)) {
            QFile errors(temp.filePath("core.stderr"));
            require(false, "Core connection: " + (errors.open(QIODevice::ReadOnly)
                ? QString::fromUtf8(errors.readAll()) : errors.errorString()));
        }
        API::Client client;
        API::defaultClient = &client;
        client.Reconnect(server.nextPendingConnection());

        const auto group = dataManager->groupsRepo->GetGroup(settings.current_group);
        const auto profile = makeProfile("vless", "192.0.2.1", group->id);
        const auto front = makeProfile("vless", "192.0.2.2", group->id);
        const auto landing = makeProfile("vless", "192.0.2.3", group->id);
        const auto xray = makeProfile("xrayvless", "192.0.2.4", group->id);
        auto selector = ProfilesRepo::NewProfile("autoselector");
        selector->AutoSelector()->gids = {group->id};
        selector->AutoSelector()->pool = {profile->id, front->id};
        selector->AutoSelector()->buildLimit = 2;
        require(dataManager->profilesRepo->AddProfile(selector, group->id), "Save fixture selector");

        int checked = 0;
        auto check = [&](const std::shared_ptr<Profile> &selected) {
            auto result = BuildSingBoxConfig(selected);
            require(result->error.isEmpty(), result->error);
            bool ok = false;
            auto error = client.CheckConfig(&ok, QString::fromUtf8(QJsonDocument(result->coreConfig).toJson()));
            require(ok && error.isEmpty(), "Core validation: " + error);
            if (result->isXrayNeeded) {
                error = client.CheckConfig(&ok, QString::fromUtf8(QJsonDocument(result->xrayConfig).toJson()), true);
                require(ok && error.isEmpty(), "Xray validation: " + error);
            }
            ++checked;
            return result;
        };

        QSet<QString> flights;
        for (int build = 0; build < 4; ++build) {
            const auto endpoint = warpEndpoint(check(profile)->coreConfig);
            require(endpoint["private_key"] == settings.warp_private_key, "Preserve WARP client identity");
            const auto awg = endpoint["amnezia_wg"].toObject();
            require(awg["jc"].toInt() == 4 && awg["jmin"].toInt() == 40 && awg["jmax"].toInt() == 70,
                    "WARP-compatible junk parameters");
            for (int header = 1; header <= 4; ++header)
                require(awg[QString("h%1").arg(header)].toString() == QString::number(header), "Standard WireGuard headers");
            const auto packet = awg["i1"].toString();
            require(packet.startsWith("<b 0x") && packet.endsWith('>') && packet.size() > 2400, "QUIC first flight");
            require(!flights.contains(packet), "Fresh QUIC signature on every build");
            flights.insert(packet);
        }
        check(selector);
        check(xray);
        group->front_proxy_id = front->id;
        group->landing_proxy_id = landing->id;
        require(dataManager->groupsRepo->Save(group), "Save group hops");
        check(profile);
        check(selector);
        group->front_proxy_id = group->landing_proxy_id = -1;
        require(dataManager->groupsRepo->Save(group), "Reset group hops");

        API::defaultClient = nullptr;
        std::shared_ptr<BuildConfigResult> failed, failedSelector, disabled;
        {
            const ScopedOfflineValidation offline;
            failed = BuildSingBoxConfig(profile);
            failedSelector = BuildSingBoxConfig(selector);
            settings.enable_warp = false;
            disabled = BuildSingBoxConfig(profile);
        }
        API::defaultClient = &client;
        require(failed->error.contains("WARP QUIC signature"), "Propagate generator failure");
        require(failedSelector->error.contains("WARP QUIC signature"), "Propagate selector generator failure");
        require(disabled->error.isEmpty(), "Disabled WARP does not need the generator");
        settings.enable_warp = true;
        settings.warp_mode = "wireguard";
        require(!warpEndpoint(check(profile)->coreConfig).contains("amnezia_wg"), "Plain WireGuard unchanged");

        settings.warp_mode = "amnezia";
        require(settings.Save(), "Save mode");
        SettingsRepo reloaded(dataManager->getDatabase());
        require(reloaded.warp_mode == "amnezia", "Persist AmneziaWG mode");
        settings.enable_warp = false;
        int previousIndex = 2;
        for (const auto index : {2, 0, 1, 2}) {
            DialogManageRoutes dialog;
            auto *mode = dialog.findChild<QComboBox *>("warp_mode");
            require(mode && mode->currentIndex() == previousIndex, "Load protocol UI");
            if (previousIndex == 2) require(mode->currentText() == "AmneziaWG", "Protocol label");
            mode->setCurrentIndex(index);
            dialog.accept();
            require(settings.warp_mode == (index == 2 ? "amnezia" : index == 1 ? "masque" : "wireguard"), "Save protocol UI");
            previousIndex = index;
        }

        API::defaultClient = nullptr;
        core.terminate();
        core.waitForFinished(5000);
        delete dataManager;
        dataManager = nullptr;
        std::cout << "Validated " << checked << " configurations, fresh QUIC flights, failure handling and mode persistence/UI\n";
        return 0;
    } catch (const std::exception &error) {
        API::defaultClient = nullptr;
        core.kill();
        core.waitForFinished(5000);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
