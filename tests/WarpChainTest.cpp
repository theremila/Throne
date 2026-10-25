#include "include/global/Configs.hpp"
#include "include/configs/generate.h"
#include "include/configs/outbounds/chain.h"
#include "include/configs/outbounds/vless.h"
#include "include/configs/outbounds/autoselector.h"
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
#include "include/configs/sub/warp.h"

#include <QApplication>
#include <QComboBox>
#include <QCheckBox>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QLocalServer>
#include <QLocalSocket>
#include <QProcess>
#include <QTemporaryDir>
#include <QTabWidget>
#include "include/configs/outbounds/xrayVless.h"
#include "include/configs/outbounds/hysteria.h"
#include "include/configs/outbounds/trojan.h"
#include <iostream>
#include <stdexcept>
#ifdef Q_OS_LINUX
#include <sys/stat.h>
#endif

using namespace Configs;

namespace {
void require(bool condition, const QString &message) {
    if (!condition) throw std::runtime_error(message.toStdString());
}

QMap<QString, QJsonObject> nodes(const QJsonObject &config) {
    QMap<QString, QJsonObject> result;
    for (const auto *section : {"outbounds", "endpoints"}) {
        for (const auto value : config[section].toArray()) {
            const auto object = value.toObject();
            const auto tag = object["tag"].toString();
            require(!result.contains(tag), "Duplicate tag: " + tag);
            result[tag] = object;
        }
    }
    return result;
}

QString bridgeTarget(const QJsonObject &config, int port, bool xray) {
    QString inboundTag;
    for (const auto value : config["inbounds"].toArray()) {
        const auto inbound = value.toObject();
        if (inbound[xray ? "port" : "listen_port"].toInt() == port)
            inboundTag = inbound["tag"].toString();
    }
    require(!inboundTag.isEmpty(), "Missing bridge inbound");
    for (const auto value : config[xray ? "routing" : "route"].toObject()["rules"].toArray()) {
        const auto rule = value.toObject();
        auto inbounds = rule[xray ? "inboundTag" : "inbound"];
        if (inbounds.toArray().contains(inboundTag) || inbounds.toString() == inboundTag)
            return rule[xray ? "outboundTag" : "outbound"].toString();
    }
    throw std::runtime_error("Missing bridge routing rule");
}

// Follow dialers across core bridges, then reverse to get the physical PC-to-exit path.
QStringList path(const BuildConfigResult &result, QString tag) {
    const auto sing = nodes(result.coreConfig);
    const auto xray = nodes(result.xrayConfig);
    bool inXray = false;
    QStringList exitFirst;
    QSet<QString> seen;
    while (!tag.isEmpty()) {
        const auto &graph = inXray ? xray : sing;
        const auto key = (inXray ? "xray:" : "sing:") + tag;
        require(graph.contains(tag), "Missing dialer: " + key);
        require(!seen.contains(key), "Dialer loop: " + key);
        seen.insert(key);
        const auto object = graph[tag];
        const auto type = object[inXray ? "protocol" : "type"].toString();
        if (type == "selector" || type == "auto-selector") {
            tag = object["outbounds"].toArray().first().toString();
            continue;
        }
        const auto settings = object["settings"].toObject();
        const auto server = inXray ? settings["address"].toString() : object["server"].toString();
        if (type == "socks" && server == "127.0.0.1") {
            const auto port = inXray ? settings["port"].toInt() : object["server_port"].toInt();
            tag = bridgeTarget(inXray ? result.coreConfig : result.xrayConfig, port, !inXray);
            inXray = !inXray;
            continue;
        }
        exitFirst << (type == "wireguard" || type == "masque" ? "WARP" : server);
        tag = inXray ? object["streamSettings"].toObject()["sockopt"].toObject()["dialerProxy"].toString()
                     : object["detour"].toString();
    }
    return {exitFirst.crbegin(), exitFirst.crend()};
}

std::shared_ptr<Profile> makeProxy(const QString &server, int gid, const QString &type = "vless") {
    auto profile = ProfilesRepo::NewProfile(type);
    profile->name = server;
    profile->outbound->server = server;
    profile->outbound->server_port = 443;
    const QString uuid = "00000000-0000-4000-8000-000000000001";
    if (auto *vless = profile->VLESS()) vless->uuid = uuid;
    if (auto *xray = profile->XrayVLESS()) xray->uuid = uuid;
    if (auto *hysteria = profile->Hysteria()) {
        hysteria->protocol_version = "2";
        hysteria->password = "fixture";
        hysteria->tls->enabled = true;
    }
    if (auto *trojan = profile->Trojan()) {
        trojan->password = "fixture";
        trojan->tls->enabled = true;
    }
    require(dataManager->profilesRepo->AddProfile(profile, gid), "Save profile");
    return profile;
}
}

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    QTemporaryDir temp;
    QProcess core;
    try {
        require(temp.isValid(), "Temporary data directory");
        require(QDir::setCurrent(temp.path()), "Set temporary working directory");
        initDB((temp.path() + "/throne.db").toStdString());
        auto &settings = *dataManager->settingsRepo;
        settings.current_group = dataManager->groupsRepo->GetAllGroupIds().first();
        settings.current_route_id = dataManager->routesRepo->GetAllRouteProfileIds().first();
        auto route = dataManager->routesRepo->GetRouteProfile(settings.current_route_id);
        route->Rules.clear();
        require(dataManager->routesRepo->Save(route), "Save empty routing profile");
        settings.spmode_vpn = false;
        settings.enable_ntp = false;
        settings.warp_ep = "162.159.192.1:2408";
        // Synthetic test identities; these keys are not registered WARP accounts.
        settings.warp_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=";
        settings.warp_public_key = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
        settings.warp_ifc_addrs = {"172.16.0.2/32"};
        settings.warp_masque_ep = "162.159.198.1:443";
        settings.warp_masque_private_key = "MHcCAQEEIHP9jXjilW4myjYttIKvgnTxAUlQq7if1TBPNGZ0JOemoAoGCCqGSM49AwEHoUQDQgAEC0EFNFYIqrTo79uos4Ty5s8Em7Fzntpvr1pRGQWJhnkJ3W7Zd9CnUcwjmTjYOlENBZRYmcDN6YbfepycTCpX2Q==";
        settings.warp_masque_peer_public_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC0EFNFYIqrTo79uos4Ty5s8Em7Fzntpvr1pRGQWJhnkJ3W7Zd9CnUcwjmTjYOlENBZRYmcDN6YbfepycTCpX2Q==";
        settings.warp_masque_ifc_addrs = settings.warp_ifc_addrs;

        QLocalServer server;
        const QString socket = temp.path() + "/core.sock";
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
            const auto detail = errors.open(QIODevice::ReadOnly)
                ? QString::fromUtf8(errors.readAll()) : errors.errorString();
            require(false, "Core connection: " + detail);
        }
        API::Client client;
        API::defaultClient = &client;
        client.Reconnect(server.nextPendingConnection());

        if (argc == 3 && QString::fromLocal8Bit(argv[1]) == "--live-db") {
            delete dataManager;
            initDB(argv[2]);
            auto &live = *dataManager->settingsRepo;
            if (const auto transport = qEnvironmentVariable("THRONE_LIVE_TRANSPORT"); !transport.isEmpty()) live.warp_mode = transport;
            if (const auto http = qEnvironmentVariable("THRONE_LIVE_MASQUE_HTTP"); !http.isEmpty()) live.warp_masque_http_mode = http.toInt();
            if (const auto order = qEnvironmentVariable("THRONE_LIVE_ORDER"); !order.isEmpty()) live.warp_chain_order = order;
            if (qEnvironmentVariableIsSet("THRONE_LIVE_REGISTER")) {
                require(live.warp_tos_accepted, "Live WARP registration requires previously accepted terms");
                bool ok = false;
                const auto identity = client.WarpRegister(&ok, live.warp_mode == "masque" ? "masque" : "wireguard", qEnvironmentVariable("THRONE_LIVE_REGISTER_PROXY"), live.warp_api_hosts);
                if (const auto logPath = qEnvironmentVariable("THRONE_LIVE_LOG"); !logPath.isEmpty()) {
                    QFile log(logPath);
                    require(log.open(QIODevice::WriteOnly | QIODevice::Append), "Open private registration diagnostic");
                    log.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
                    log.write(ok ? "REGISTRATION RPC OK\n" : "REGISTRATION RPC FAILED\n");
                    log.write(QString::fromStdString(identity.error.value_or("")).toUtf8() + "\n");
                }
                require(ok && identity.error.value_or("").empty(), "Register fresh test WARP identity");
                QStringList addresses;
                if (!identity.ipv4.value_or("").empty()) addresses << QString::fromStdString(*identity.ipv4) + "/32";
                if (!identity.ipv6.value_or("").empty()) addresses << QString::fromStdString(*identity.ipv6) + "/128";
                if (live.warp_mode == "masque") {
                    live.warp_masque_private_key = QString::fromStdString(identity.private_key.value_or(""));
                    live.warp_masque_peer_public_key = QString::fromStdString(identity.peer_public_key.value_or(""));
                    live.warp_masque_ep = QString::fromStdString(identity.endpoint.value_or(""));
                    live.warp_masque_ifc_addrs = addresses;
                } else {
                    live.warp_private_key = QString::fromStdString(identity.private_key.value_or(""));
                    live.warp_public_key = QString::fromStdString(identity.peer_public_key.value_or(""));
                    live.warp_ep = QString::fromStdString(identity.endpoint.value_or(""));
                    live.warp_ifc_addrs = addresses;
                    live.warp_reserved.clear();
                    for (const auto byte : identity.reserved) live.warp_reserved << QString::number(byte);
                }
                require(live.Save(), "Save fresh test identity in copied DB");
            }
            if (qEnvironmentVariableIsSet("THRONE_LIVE_REGISTER") && live.warp_chain_order == "warp-both") {
                bool ok = false;
                const auto entry = client.WarpRegister(&ok, live.warp_mode == "masque" ? "masque" : "wireguard", {}, live.warp_api_hosts);
                require(ok && entry.error.value_or("").empty(), "Register independent entry WARP identity");
                Configs_network::WarpIdentity identity;
                identity.privateKey = QString::fromStdString(entry.private_key.value_or(""));
                identity.peerPublicKey = QString::fromStdString(entry.peer_public_key.value_or(""));
                identity.endpoint = QString::fromStdString(entry.endpoint.value_or(""));
                identity.ipv4 = QString::fromStdString(entry.ipv4.value_or(""));
                identity.ipv6 = QString::fromStdString(entry.ipv6.value_or(""));
                for (const auto byte : entry.reserved) identity.reserved << byte;
                live.warp_entry_config = QJsonObject2QString(Configs_network::WarpIdentityToBeanJson(live.warp_mode, identity), true);
                require(live.Save(), "Save entry identity in copied DB");
            }
            if (const auto endpoint = qEnvironmentVariable("THRONE_LIVE_WARP_ENDPOINT"); !endpoint.isEmpty()) {
                if (live.warp_mode == "masque") live.warp_masque_ep = endpoint;
                else live.warp_ep = endpoint;
            }
            const bool tunTest = qEnvironmentVariableIsSet("THRONE_LIVE_TUN");
            if (tunTest) {
#ifdef Q_OS_LINUX
                struct stat currentNamespace{}, hostNamespace{};
                bool validFD = false;
                const int hostFD = qEnvironmentVariable("THRONE_TEST_HOST_NETNS_FD").toInt(&validFD);
                require(qEnvironmentVariable("THRONE_TEST_NETNS") == "isolated"
                    && stat("/proc/self/ns/net", &currentNamespace) == 0
                    && validFD && hostFD >= 3 && fstat(hostFD, &hostNamespace) == 0
                    && currentNamespace.st_dev == hostNamespace.st_dev
                    && currentNamespace.st_ino != hostNamespace.st_ino,
                    "TUN live tests require an isolated network namespace");
#else
                require(false, "TUN live tests require a Linux network namespace");
#endif
            }
            live.spmode_vpn = tunTest;
            live.disable_mixed_inbound = false;
            live.inbound_address = "127.0.0.1";
            const auto ports = MkManyPorts(2);
            live.inbound_socks_port = ports[0];
            live.core_dns_in_port = ports[1];
            live.core_box_clash_api = 0;
            live.core_box_api_port = 0;
            live.custom_inbound.clear();
            if (qEnvironmentVariableIsSet("THRONE_LIVE_LOG")) {
                live.log_level = "debug";
                live.xray_log_level = "debug";
            }
            live.vpn_auto_redirect = false;
            live.inbound_auth = false;
            live.enable_ntp = false;
            live.adblock_enable = false;
            auto liveRoute = dataManager->routesRepo->GetRouteProfile(live.current_route_id);
            liveRoute->Rules.clear();
            liveRoute->defaultOutboundID = proxyID;
            liveRoute->isRaw = false;
            require(dataManager->routesRepo->Save(liveRoute), "Temporary routing profile");
            const auto ids = dataManager->profilesRepo->GetAllProfileIds();
            bool allPassed = true;
            for (const QString order : {"proxy-first", "warp-first", "warp-both"}) {
                if (const auto requested = qEnvironmentVariable("THRONE_LIVE_ORDER"); !requested.isEmpty() && requested != order) continue;
                live.warp_chain_order = order;
                live.enable_warp = true;
                bool connected = false;
                for (const int id : ids) {
                    const auto profile = dataManager->profilesRepo->GetProfile(id);
                    if (const auto requested = qEnvironmentVariable("THRONE_LIVE_PROFILE"); !requested.isEmpty() && requested.toInt() != id) continue;
                    if (profile->type != "hysteria" && profile->type != "trojan" && profile->type != "xrayvless") continue;
                    const auto result = BuildSingBoxConfig(profile);
                    if (!result->error.isEmpty()) {
                        std::cout << order.toStdString() << " profile " << id << ": build failed\n";
                        continue;
                    }
                    // Bind only physical endpoint dialers; detoured endpoints must keep their proxy path.
                    if (const auto interface = qEnvironmentVariable("THRONE_LIVE_INTERFACE"); !interface.isEmpty()) {
                        auto endpoints = result->coreConfig["endpoints"].toArray();
                        for (qsizetype i = 0; i < endpoints.size(); ++i) {
                            auto endpoint = endpoints[i].toObject();
                            if (!endpoint.contains("detour")) endpoint["bind_interface"] = interface;
                            endpoints[i] = endpoint;
                        }
                        result->coreConfig["endpoints"] = endpoints;
                    }
                    libcore::LoadConfigReq request;
                    request.core_config = QJsonDocument(result->coreConfig).toJson(QJsonDocument::Compact).toStdString();
                    request.need_xray = result->isXrayNeeded;
                    request.xray_outbound_dns_strategy = getXrayOutboundDomainStrategy().toStdString();
                    request.xray_config = QJsonDocument(result->xrayConfig).toJson(QJsonDocument::Compact).toStdString();
                    bool ok = false;
                    const auto startError = client.Start(&ok, request);
                    if (ok && startError.isEmpty()) {
                        QProcess curl;
                        QStringList curlArgs{"--silent", "--show-error", "--max-time", "20", "--noproxy", tunTest ? "*" : ""};
                        if (!tunTest) curlArgs << "--proxy" << "socks5h://127.0.0.1:" + QString::number(live.inbound_socks_port);
                        curlArgs << "https://1.1.1.1/cdn-cgi/trace";
                        curl.start("curl", curlArgs);
                        const bool finished = curl.waitForFinished(25000);
                        if (!finished) { curl.kill(); curl.waitForFinished(); }
                        const auto trace = curl.readAllStandardOutput();
                        const bool warp = trace.contains("warp=on") || trace.contains("warp=plus");
                        connected = finished && curl.exitCode() == 0 && trace.contains("ip=")
                            && (order != "warp-first" ? warp : !warp);
                        std::cout << order.toStdString() << " profile " << id << " (" << profile->type.toStdString()
                                  << "): HTTPS=" << (curl.exitCode() == 0 ? "ok" : "failed")
                                  << ", curl_exit=" << curl.exitCode()
                                  << ", exit_warp=" << (warp ? "on" : "off") << std::endl;
                    } else {
                        std::cout << order.toStdString() << " profile " << id << ": core start failed" << std::endl;
                        if (const auto logPath = qEnvironmentVariable("THRONE_LIVE_LOG"); !logPath.isEmpty()) {
                            QFile log(logPath);
                            require(log.open(QIODevice::WriteOnly | QIODevice::Append), "Open private start diagnostic");
                            log.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
                            log.write("START ERROR: " + startError.toUtf8() + "\n");
                        }
                    }
                    client.Stop(&ok);
                    if (const auto logPath = qEnvironmentVariable("THRONE_LIVE_LOG"); !logPath.isEmpty()) {
                        QFile log(logPath);
                        require(log.open(QIODevice::WriteOnly | QIODevice::Append), "Open private diagnostic log");
                        log.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
                        log.write(order.toUtf8() + "\n");
                        for (const auto &name : {"core.stdout", "core.stderr"}) {
                            QFile source(temp.filePath(name));
                            require(source.open(QIODevice::ReadOnly), "Read core diagnostic log");
                            log.write(source.readAll());
                        }
                    }
                    if (connected) break;
                }
                allPassed = allPassed && connected;
            }
            core.terminate();
            core.waitForFinished(5000);
            delete dataManager;
            dataManager = nullptr;
            API::defaultClient = nullptr;
            return allPassed ? 0 : 1;
        }

        Configs_network::WarpIdentity entryIdentity;
        entryIdentity.privateKey = QString::fromLatin1(QByteArray(32, char(0x11)).toBase64());
        entryIdentity.peerPublicKey = settings.warp_public_key;
        entryIdentity.endpoint = settings.warp_ep;
        entryIdentity.ipv4 = "172.16.0.3";
        auto wgEntry = Configs_network::WarpIdentityToBeanJson("wireguard", entryIdentity);
        entryIdentity.privateKey = "MDECAQEEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACoAoGCCqGSM49AwEH";
        entryIdentity.peerPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC0EFNFYIqrTo79uos4Ty5s8Em7Fzntpvr1pRGQWJhnkJ3W7Zd9CnUcwjmTjYOlENBZRYmcDN6YbfepycTCpX2Q==";
        entryIdentity.endpoint = settings.warp_masque_ep;
        auto masqueEntry = Configs_network::WarpIdentityToBeanJson("masque", entryIdentity);
        const auto setEntry = [&] {
            settings.warp_entry_config = QJsonObject2QString(settings.warp_mode == "masque" ? masqueEntry : wgEntry, true);
        };
        const auto wrapped = [&](QStringList hops) {
            if (settings.warp_chain_order != "proxy-first") hops.prepend("WARP");
            if (settings.warp_chain_order != "warp-first") hops.append("WARP");
            return hops;
        };

        auto group = dataManager->groupsRepo->GetGroup(settings.current_group);
        auto vps = makeProxy("192.0.2.1", group->id);
        auto front = makeProxy("192.0.2.2", group->id);
        auto landing = makeProxy("192.0.2.3", group->id);
        auto chain = ProfilesRepo::NewProfile("chain");
        chain->Chain()->list = {front->id, vps->id};
        require(dataManager->profilesRepo->AddProfile(chain, group->id), "Save chain");
        auto selector = ProfilesRepo::NewProfile("autoselector");
        selector->AutoSelector()->gids = {group->id};
        selector->AutoSelector()->pool = {vps->id, front->id};
        selector->AutoSelector()->buildLimit = 2;
        require(dataManager->profilesRepo->AddProfile(selector, group->id), "Save selector");

        int passed = 0;
        auto check = [&](const std::shared_ptr<Profile> &profile, const QStringList &expected, const QStringList &bypass) {
            const auto result = BuildSingBoxConfig(profile);
            require(result->error.isEmpty(), result->error);
            require(path(*result, "proxy") == expected, "Wrong physical path: " + path(*result, "proxy").join(" -> "));
            if (settings.enable_warp)
                require(path(*result, "warp-bypass") == bypass, "WARP bypass must retain the VPS path");
            bool ok = false;
            const auto error = client.CheckConfig(&ok, QString::fromUtf8(QJsonDocument(result->coreConfig).toJson()));
            require(ok && error.isEmpty(), "Core rejected generated config: " + error);
            if (result->isXrayNeeded) {
                const auto xrayError = client.CheckConfig(&ok, QString::fromUtf8(QJsonDocument(result->xrayConfig).toJson()), true);
                require(ok && xrayError.isEmpty(), "Core rejected Xray config: " + xrayError);
            }
            if (profile->type == "autoselector") {
                require(result->autoSelectors.size() == 1, "Track only the primary auto selector");
                for (const auto &member : result->autoSelectors.first().members) {
                    const auto memberProfile = member.second;
                    require(memberProfile != nullptr, "Selector member exists");
                    auto memberPath = path(*result, member.first);
                    if (settings.enable_warp && settings.warp_chain_order != "warp-first") memberPath.append("WARP");
                    require(memberPath == wrapped({memberProfile->outbound->server}), "Every selector member follows the WARP path");
                }
                const auto tag = result->autoSelectors.first().groupTag;
                require(tag == (settings.enable_warp && settings.warp_chain_order != "warp-first"
                    ? settings.warp_chain_order == "warp-both" ? "warp-main" : "warp-bypass" : "proxy"), "Track primary selector tag");
            }
            if (settings.enable_warp && settings.warp_chain_order == "warp-both") {
                QSet<QString> keys;
                int count = 0;
                for (const auto endpoint : result->coreConfig["endpoints"].toArray()) {
                    const auto object = endpoint.toObject();
                    if (object["type"] != "wireguard" && object["type"] != "masque") continue;
                    keys.insert(object["private_key"].toString());
                    ++count;
                }
                require(count == 2 && keys.size() == 2, "Use independent entry and exit WARP identities");
            }
            ++passed;
        };
        for (const QString transport : {"wireguard", "masque", "amnezia"}) {
            settings.warp_mode = transport;
            setEntry();
            for (const QString order : {"proxy-first", "warp-first", "warp-both"}) {
                settings.warp_chain_order = order;
                settings.enable_warp = true;
                check(vps, wrapped({"192.0.2.1"}), {"192.0.2.1"});
                check(chain, wrapped({"192.0.2.2", "192.0.2.1"}), {"192.0.2.2", "192.0.2.1"});
                check(selector, wrapped({"192.0.2.1"}), {"192.0.2.1"});
                group->front_proxy_id = front->id;
                group->landing_proxy_id = landing->id;
                check(vps, wrapped({"192.0.2.2", "192.0.2.1", "192.0.2.3"}), {"192.0.2.2", "192.0.2.1", "192.0.2.3"});
                group->front_proxy_id = -1;
                group->landing_proxy_id = -1;
                settings.enable_warp = false;
                check(vps, {"192.0.2.1"}, {});
            }
        }
        for (const QString type : {"hysteria", "trojan", "xrayvless"}) {
            auto profile = makeProxy("192.0.2.4", group->id, type);
            for (const QString transport : {"wireguard", "masque", "amnezia"}) {
                settings.warp_mode = transport;
                setEntry();
                for (const QString order : {"proxy-first", "warp-first", "warp-both"}) {
                    settings.enable_warp = true;
                    settings.warp_chain_order = order;
                    const auto expected = wrapped({"192.0.2.4"});
                    check(profile, expected, {"192.0.2.4"});
                    if (type == "xrayvless") {
                        selector->AutoSelector()->pool = {profile->id, vps->id};
                        selector->AutoSelector()->buildLimit = 2;
                        check(selector, expected, {"192.0.2.4"});
                    }
                }
            }
        }
        settings.warp_mode = "amnezia";
        settings.warp_chain_order = "warp-first";
        const auto amneziaConfig = BuildSingBoxConfig(vps);
        require(amneziaConfig->error.isEmpty(), amneziaConfig->error);
        bool awgFound = false;
        for (const auto endpoint : amneziaConfig->coreConfig["endpoints"].toArray()) {
            const auto object = endpoint.toObject();
            if (object["type"] != "wireguard") continue;
            const auto awg = object["amnezia_wg"].toObject();
            require(awg["jc"] == 4 && awg["jmin"] == 40 && awg["jmax"] == 70, "Generate WARP junk parameters");
            require(awg["h1"] == "1" && awg["h2"] == "2" && awg["h3"] == "3" && awg["h4"] == "4", "Retain standard WARP headers");
            const auto i1 = awg["i1"].toString();
            require(i1.startsWith("<b 0x") && i1.endsWith('>') && i1.size() > 2400, "Generate public QUIC camouflage");
            require(object["private_key"] == settings.warp_private_key, "Use registered identity, not an imported profile");
            awgFound = true;
        }
        require(awgFound, "Generate AWG endpoint");
        settings.warp_chain_order = "warp-both";
        settings.warp_entry_config.clear();
        require(!BuildSingBoxConfig(vps)->error.isEmpty(), "Reject missing entry identity");
        auto duplicate = wgEntry;
        duplicate["private_key"] = settings.warp_private_key;
        settings.warp_entry_config = QJsonObject2QString(duplicate, true);
        require(!BuildSingBoxConfig(vps)->error.isEmpty(), "Reject shared entry/exit key");
        settings.warp_entry_config = QJsonObject2QString(masqueEntry, true);
        require(!BuildSingBoxConfig(vps)->error.isEmpty(), "Reject mismatched entry transport");
        setEntry();
        settings.warp_mode = "invalid";
        require(!BuildSingBoxConfig(vps)->error.isEmpty(), "Reject unknown transport");
        settings.warp_mode = "masque";
        settings.warp_chain_order = "invalid";
        require(!BuildSingBoxConfig(vps)->error.isEmpty(), "Reject unknown chain order");
        settings.warp_chain_order = "warp-first";
        const auto savedKey = settings.warp_masque_private_key;
        settings.warp_masque_private_key.clear();
        require(!BuildSingBoxConfig(vps)->error.isEmpty(), "Reject missing WARP credentials");
        settings.warp_masque_private_key = savedKey;
        settings.warp_mode = "amnezia";
        settings.warp_chain_order = "warp-both";
        setEntry();
        require(settings.Save(), "Persist settings");
        settings.warp_chain_order = "proxy-first";
        SettingsRepo reloaded(dataManager->getDatabase());
        settings.warp_chain_order = reloaded.warp_chain_order;
        require(settings.warp_chain_order == "warp-both", "Persist WARP order");
        require(reloaded.warp_mode == "amnezia", "Persist AmneziaWG mode");
        require(reloaded.warp_entry_config == settings.warp_entry_config, "Persist independent entry identity");
        {
            DialogManageRoutes dialog;
            auto *order = dialog.findChild<QComboBox *>("warp_chain_order");
            require(order != nullptr && order->currentData() == "warp-both", "Load WARP order in UI");
            auto *mode = dialog.findChild<QComboBox *>("warp_mode");
            require(mode != nullptr && mode->currentIndex() == 2, "Load AmneziaWG in UI");
            require(mode->currentText() == "AmneziaWG", "Show the plain protocol name: " + mode->currentText());
            if (const auto screenshot = qEnvironmentVariable("THRONE_TEST_SCREENSHOT"); !screenshot.isEmpty()) {
                dialog.findChild<QTabWidget *>()->setCurrentWidget(dialog.findChild<QWidget *>("tab_5"));
                dialog.show();
                app.processEvents();
                require(dialog.grab().save(screenshot), "Save UI preview");
            }
            order->setCurrentIndex(order->findData("proxy-first"));
            mode->setCurrentIndex(0);
            dialog.accept();
            require(settings.warp_chain_order == "proxy-first", "Save WARP order from UI");
            require(settings.warp_mode == "wireguard", "Save transport from UI");
        }
        core.terminate();
        core.waitForFinished(5000);
        delete dataManager;
        dataManager = nullptr;
        API::defaultClient = nullptr;
        std::cout << passed << " generated configs passed topology and core validation; settings/UI round-trip passed\n";
        return 0;
    } catch (const std::exception &error) {
        core.kill();
        core.waitForFinished(5000);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
