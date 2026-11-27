package dev.proxyroute;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.InetAddresses;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;

import dev.proxyroute.nativecore.tunnel.Engine;
import dev.proxyroute.nativecore.tunnel.Hooks;
import dev.proxyroute.nativecore.tunnel.PerformanceHooks;
import dev.proxyroute.nativecore.tunnel.Tunnel;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public final class RouteService extends VpnService {
    static final String CONNECT = "dev.proxyroute.CONNECT";
    static final String DISCONNECT = "dev.proxyroute.DISCONNECT";
    private static final String CHANNEL = "tunnel";
    private static final int NOTIFICATION = 42;
    private static final int SAMPLE_SECONDS = 3;
    private static final long SPEED_TIMEOUT_MS = 4500;
    static volatile RouteService instance;
    static volatile Session session = new Session();
    static final class Session {
        final long started = android.os.SystemClock.elapsedRealtime();
        final java.util.concurrent.atomic.AtomicLong up = new java.util.concurrent.atomic.AtomicLong();
        final java.util.concurrent.atomic.AtomicLong down = new java.util.concurrent.atomic.AtomicLong();
    }
    static volatile Status status = new Status(false, false, "VPN выключен");
    record Status(boolean connected, boolean busy, String message) {}

    private final Handler main = new Handler(Looper.getMainLooper());
    private final ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor();
    private volatile boolean wanted;
    private Engine engine;
    private ParcelFileDescriptor tun;
    private ScheduledFuture<?> pending;
    private int failures;
    private int latestStart;
    private Config config;
    private History history;
    private ConnectivityManager networks;
    private Network tunnelNetwork;
    private boolean tunnelValidated;
    private ScheduledFuture<?> networkRefresh;
    private volatile ActiveDiagnostics diagnostics;

    private record ActiveDiagnostics(String profileId, Engine engine) {}

    String diagnostics(String profileId) {
        ActiveDiagnostics active = diagnostics;
        if (active == null || (profileId != null && !profileId.equals(active.profileId()))) return "";
        return active.engine().diagnostics();
    }
    private boolean wifiFallback;
    private boolean observingNetwork;
    private boolean observingPhysical;
    private String noticeSpeed = "";
    private final Runnable resetNoticeSpeed = () -> showRate(0, 0);
    private final ConnectivityManager.NetworkCallback networkChanges = new ConnectivityManager.NetworkCallback() {
        @Override public void onAvailable(Network network) { refreshNetwork(); }
        @Override public void onLost(Network network) { refreshNetwork(); }
        @Override public void onCapabilitiesChanged(Network network,NetworkCapabilities capabilities) { refreshNetwork(); }
    };

    private final ConnectivityManager.NetworkCallback physicalChanges = new ConnectivityManager.NetworkCallback() {
        @Override public void onAvailable(Network network) { refreshNetwork(); }
        @Override public void onLost(Network network) { refreshNetwork(); }
        @Override public void onCapabilitiesChanged(Network network,NetworkCapabilities capabilities) { refreshNetwork(); }
    };

    private void refreshNetwork() {
        if (!wanted || worker.isShutdown()) return;
        try {
            worker.execute(() -> {
                if (networkRefresh != null) networkRefresh.cancel(false);
                networkRefresh = worker.schedule(this::recoverNetwork, 350, TimeUnit.MILLISECONDS);
            });
        } catch (java.util.concurrent.RejectedExecutionException ignored) { }
    }

    private void recoverNetwork() {
        if (!wanted) return;
        try {
            Network network = Config.physicalNetwork(networks);
            boolean fallback = config.enabled("wifiOnly", false) && network != null
                    && !isWifi(network) && config.read().active() != null;
            boolean validationRestored = validated(network) && !tunnelValidated;
            boolean changed = !java.util.Objects.equals(network, tunnelNetwork);
            if (changed || validationRestored || wifiFallback != fallback || (engine == null && network != null)) {
                if (pending != null) pending.cancel(false);
                if (changed || validationRestored) history.serviceEvent("Изменилась физическая сеть", "NETWORK_CHANGED");
                establishTunnel();
            } else {
                tunnelValidated = validated(network);
            }
        } catch (Config.ReadFailure | SecurityException e) {
            reportFailure(e instanceof Config.ReadFailure ? "config_read" : "vpn_permission", false);
        }
    }

    private boolean validated(Network network) {
        NetworkCapabilities caps = network == null ? null : networks.getNetworkCapabilities(network);
        return caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
    }

    private String networkType(Network network) {
        NetworkCapabilities caps = network == null ? null : networks.getNetworkCapabilities(network);
        if (caps == null) return "none";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "wifi";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return "cellular";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return "ethernet";
        return "other";
    }

    private boolean isWifi(Network network) {
        NetworkCapabilities caps=network==null?null:networks.getNetworkCapabilities(network);
        return caps!=null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
    }

    @Override public void onCreate() {
        super.onCreate();
        config = new Config(this);
        history = History.get(this);
        networks = getSystemService(ConnectivityManager.class);
        instance = this;
        try { networks.registerDefaultNetworkCallback(networkChanges); observingNetwork=true; }
        catch(RuntimeException e) { android.util.Log.w("ProxyRoute","Network listener unavailable",e); }
        try {
            networks.registerNetworkCallback(new NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), physicalChanges);
            observingPhysical = true;
        } catch (RuntimeException e) { android.util.Log.w("ProxyRoute", "Physical network listener unavailable"); }
        NotificationChannel channel = new NotificationChannel(CHANNEL, "VPN", NotificationManager.IMPORTANCE_LOW);
        channel.setShowBadge(false);
        getSystemService(NotificationManager.class).createNotificationChannel(channel);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        latestStart = startId;
        if (intent != null && DISCONNECT.equals(intent.getAction())) {
            if (isAlwaysOn()) return START_STICKY;
            wanted = false;
            updateStatus(new Status(status.connected(),true,"Отключение VPN…"));
            worker.execute(() -> {
                if (pending != null) pending.cancel(false);
                closeTunnel();
                main.post(() -> {
                    if (wanted || latestStart != startId) return;
                    updateStatus(new Status(false, false, "VPN выключен"));
                    history.serviceEvent("VPN отключён","closed");
                    stopForeground(STOP_FOREGROUND_REMOVE);
                    stopSelfResult(startId);
                });
            });
            return START_NOT_STICKY;
        }
        wanted = true;
        Notification notification = notification("Подключение VPN…");
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(NOTIFICATION, notification);
            }
        } catch (IllegalStateException | SecurityException e) {
            wanted = false;
            var detail=NetworkErrors.describe("foreground_start");
            updateStatus(new Status(false,false,"Ошибка VPN · "+detail.title()));
            history.serviceEvent(detail.title(),detail.code());
            stopSelfResult(startId);
            return START_NOT_STICKY;
        }
        worker.execute(() -> {
            if (pending != null) pending.cancel(false);
            failures = 0;
            establishTunnel();
        });
        return START_STICKY;
    }

    private void establishTunnel() {
        if (!wanted) return;
        update(new Status(engine != null, true, "Подключение VPN…"));
        ParcelFileDescriptor next = null;
        Engine started = null;
        try {
            Config.Settings settings = config.read();
            Config.Profile profile = settings.active();
            boolean wifiOnly=config.enabled("wifiOnly",false);
            Network physical = Config.physicalNetwork(networks);
            boolean fallback = wifiOnly && physical != null && !isWifi(physical) && profile != null;
            boolean firewall = Config.FIREWALL.equals(settings.selected());
            if (!firewall && profile == null) {reportFailure("profile_missing",false); return;}
            if (physical == null && engine != null) {
                // Retain the capture routes while the old bound sockets are unavailable.
                tunnelNetwork = null;
                tunnelValidated = false;
                wifiFallback = false;
                setUnderlyingNetworks(new Network[0]);
                update(new Status(true, false, "VPN · ожидание сети"));
                return;
            }
            Config.Credentials auth = fallback ? new Config.Credentials("","") : Config.credentials(profile);
            String ip = "";
            if (profile != null && !fallback) {
                if (physical != null || InetAddresses.isNumericAddress(profile.host()))
                    ip = String.join(",", Config.addresses(physical, profile.host()));
            }
            if (!wanted) return;

            Config.AppScope scope=config.appScope();
            Policy policy = policy(settings.rules(),scope.exclusionsEnabled());
            Builder builder = new Builder().setSession("ProxyRoute")
                    .setMtu(1500).setBlocking(false)
                    .addAddress("10.99.0.1", 30).addAddress("fd72:6f75:7465::1", 64)
                    .addRoute("0.0.0.0", 0).addRoute("::", 0)
                    .addDnsServer("10.99.0.2").addDnsServer("fd72:6f75:7465::2")
                    .setMetered(false)
                    .setConfigureIntent(openApp());
            if(scope.selectedOnly()) {
                Set<String> allowed=new HashSet<>(config.included());
                allowed.removeAll(policy.excluded());
                settings.rules().forEach((pkg,rule)->{if(Config.BLOCK.equals(rule))allowed.add(pkg);});
                int count=0;
                for(String pkg:allowed) {
                    if(pkg.equals(getPackageName()))continue;
                    try { builder.addAllowedApplication(pkg); count++; }
                    catch(PackageManager.NameNotFoundException ignored) { }
                }
                if(count==0) {reportFailure("app_scope",false); return;}
            } else {
                builder.addDisallowedApplication(getPackageName());
                for (String pkg : policy.excluded()) {
                    try { builder.addDisallowedApplication(pkg); }
                    catch (PackageManager.NameNotFoundException ignored) { }
                }
            }
            builder.setUnderlyingNetworks(physical == null ? new Network[0] : new Network[]{physical});
            next = builder.establish();
            if (next == null) {reportFailure("vpn_permission",false); return;}
            Session nextSession = engine == null ? new Session() : session;
            boolean direct=firewall||fallback;
            DnsOptions dns=DnsOptions.selected(config);
            String profileId = profile == null ? "" : profile.id();
            started=Tunnel.startPerformance(next.getFd(),
                    new FlowHooks(policy,UUID.randomUUID().toString(),nextSession,physical,profileId),
                    direct?"direct":profile.protocol(),direct?"":profile.host(),ip,
                    direct?0:profile.port(),auth.user(),auth.password(),direct,dns.url(),dns.bootstrap(),
                    config.enabled("ads",false),config.enabled("trackers",false),config.enabled("dnsDirect",false),
                    config.option("ipMode","auto"),config.option("quicMode","auto"),config.enabled("dnsCache",true));
            closeTunnel();
            tun = next;
            next = null;
            engine = started;
            diagnostics = direct ? null : new ActiveDiagnostics(profileId, engine);
            started = null;
            session = nextSession;
            failures = 0;
            tunnelNetwork=physical;
            tunnelValidated=validated(physical);
            wifiFallback=fallback;
            String message=firewall?"Брандмауэр активен":fallback?"Прямой доступ · прокси только по Wi-Fi":"VPN активен · "+profile.label();
            if (physical == null) message = "VPN · ожидание сети";
            update(new Status(true,false,message));
            history.serviceEvent(message,"closed");
        } catch (Exception | LinkageError e) {
            if (next != null) {
                stopEngine(started);
                try { next.close(); } catch (Exception ignored) { }
                closeTunnel();
            }
            if (e instanceof Config.ReadFailure) reportFailure("config_read",false);
            else if (e instanceof Config.CredentialsFailure) reportFailure("credentials_read",false);
            else if (e instanceof LinkageError) reportFailure("native_start",false);
            else if (e instanceof SecurityException) reportFailure("vpn_permission",false);
            else reportFailure(e.getMessage()==null?e.getClass().getSimpleName():e.getMessage(),true);
        }
    }

    private void reportFailure(String reason,boolean retry) {
        if (!wanted) return;
        NetworkErrors.Detail detail=NetworkErrors.describe(reason);
        String message="Ошибка VPN · "+detail.title();
        if (!message.equals(status.message()) && failures==0) history.serviceEvent(message,detail.code());
        update(new Status(engine != null,false,message));
        if (retry && !worker.isShutdown()) {
            int delay=Math.min(120,5 << Math.min(failures++,5));
            pending=worker.schedule(this::establishTunnel,delay,TimeUnit.SECONDS);
        }
    }

    private static void stopEngine(Engine engine) {
        if (engine==null)return;
        try { engine.stop(); }
        catch (RuntimeException | LinkageError e) { android.util.Log.w("ProxyRoute","Could not stop native VPN engine"); }
    }

    private void closeTunnel() {
        diagnostics = null;
        stopEngine(engine);
        engine = null;
        if (tun != null) {
            try { tun.close(); } catch (Exception ignored) { }
            tun = null;
        }
    }

    @Override public void onRevoke() {
        wanted = false;
        updateStatus(new Status(false,false,"Android отключил VPN"));
        main.post(this::stopSelf);
    }

    @Override public void onDestroy() {
        wanted = false;
        main.removeCallbacks(resetNoticeSpeed);
        if(observingNetwork) {
            try { networks.unregisterNetworkCallback(networkChanges); }
            catch (IllegalArgumentException | SecurityException e) {
                android.util.Log.w("ProxyRoute","Could not unregister network listener");
            }
        }
        if (observingPhysical) {
            try { networks.unregisterNetworkCallback(physicalChanges); }
            catch (IllegalArgumentException | SecurityException e) {
                android.util.Log.w("ProxyRoute", "Could not unregister physical network listener");
            }
        }
        if (instance == this) instance = null;
        worker.execute(() -> {
            if (pending != null) pending.cancel(false);
            if (networkRefresh != null) networkRefresh.cancel(false);
            closeTunnel();
        });
        worker.shutdown();
        Status current = status;
        if (current.connected() || current.busy()) updateStatus(new Status(false, false, "VPN выключен"));
        super.onDestroy();
    }

    private void update(Status change) {
        if (!wanted) return;
        updateStatus(change);
        main.post(() -> {
            if (!wanted || instance != this || status != change) return;
            noticeSpeed = "";
            main.removeCallbacks(resetNoticeSpeed);
            refreshNotification(change, change.connected() && !change.busy() ? speedText(0, 0) : "");
        });
    }

    private void trafficSample(Session counters, long sent, long received) {
        main.post(() -> {
            if (!wanted || instance != this || !status.connected() || status.busy() || session != counters) return;
            showRate(sent / (double) SAMPLE_SECONDS, received / (double) SAMPLE_SECONDS);
            main.removeCallbacks(resetNoticeSpeed);
            main.postDelayed(resetNoticeSpeed, SPEED_TIMEOUT_MS);
        });
    }

    private void showRate(double up, double down) {
        Status current = status;
        if (!wanted || instance != this || !current.connected() || current.busy()) return;
        String speed = speedText(up, down);
        if (!speed.equals(noticeSpeed)) refreshNotification(current, speed);
    }

    private void refreshNotification(Status current, String speed) {
        noticeSpeed = speed;
        try { getSystemService(NotificationManager.class).notify(NOTIFICATION, notification(current.message(), speed)); }
        catch (SecurityException e) { android.util.Log.w("ProxyRoute","VPN notification unavailable"); }
    }

    private static String speedText(double up, double down) {
        return "↓ " + rate(down) + "   ↑ " + rate(up);
    }

    private static String rate(double value) {
        if (value < 1024) return String.format(java.util.Locale.getDefault(), "%.0f Б/с", value);
        if (value < 1024 * 1024) return String.format(java.util.Locale.getDefault(), "%.1f КиБ/с", value / 1024);
        return String.format(java.util.Locale.getDefault(), "%.1f МиБ/с", value / (1024 * 1024));
    }

    static final String STATUS_CHANGED="dev.proxyroute.STATUS_CHANGED";

    private void updateStatus(Status change) {
        status=change;
        main.post(()->sendBroadcast(new Intent(STATUS_CHANGED).setPackage(getPackageName())));
    }

    private boolean protectSocket(long fd,Network network) {
        if(!protect((int)fd))return false;
        if(network==null)return false;
        try(ParcelFileDescriptor socket=ParcelFileDescriptor.fromFd((int)fd)) {
            network.bindSocket(socket.getFileDescriptor());
            return true;
        } catch(java.io.IOException e) { return false; }
    }

    private PendingIntent openApp() {
        return PendingIntent.getActivity(this, 1, new Intent(this, MainActivity.class),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }

    private Notification notification(String message) {
        return notification(message, "");
    }

    private Notification notification(String message, String speed) {
        Notification.Builder builder = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_route).setContentTitle("ProxyRoute")
                .setContentText(speed.isEmpty() ? message : speed).setContentIntent(openApp()).setOngoing(true)
                .setOnlyAlertOnce(true).setCategory(Notification.CATEGORY_SERVICE);
        if (!speed.isEmpty()) builder.setStyle(new Notification.BigTextStyle().bigText(speed + "\n" + message));
        if (!isAlwaysOn()) {
            builder.addAction(new Notification.Action.Builder(null, "Отключить",
                    PendingIntent.getService(this, 2, new Intent(this, RouteService.class).setAction(DISCONNECT),
                            PendingIntent.FLAG_IMMUTABLE)).build());
        }
        return builder.build();
    }

    private record Policy(Map<Integer,String> rules, Set<String> excluded, boolean hasBlock) {}

    private Policy policy(Map<String,String> values,boolean exclusionsEnabled) {
        PackageManager pm = getPackageManager();
        Map<Integer,String> rules = new HashMap<>();
        Set<String> excluded = new HashSet<>();
        for (Map.Entry<String,String> value : values.entrySet()) {
            try {
                int uid = pm.getPackageUid(value.getKey(), 0);
                if (uid == getApplicationInfo().uid) continue;
                if (Config.BYPASS.equals(value.getValue())) {
                    String[] shared = pm.getPackagesForUid(uid);
                    if (exclusionsEnabled && shared != null && shared.length == 1) excluded.add(value.getKey());
                    else mergeRule(rules,uid,Config.DIRECT);
                } else {
                    mergeRule(rules,uid,value.getValue());
                }
            } catch (PackageManager.NameNotFoundException ignored) { }
        }
        return new Policy(rules, excluded, rules.containsValue(Config.BLOCK));
    }

    private static void mergeRule(Map<Integer,String> rules, int uid, String candidate) {
        if (Config.BLOCK.equals(candidate)) rules.put(uid, Config.BLOCK);
        else if (Config.DIRECT.equals(candidate)) rules.putIfAbsent(uid, Config.DIRECT);
    }

    static class ProbeHooks implements Hooks {
        @Override public boolean protect(long fd) {
            RouteService service = instance;
            return service == null || service.protect((int) fd);
        }
        @Override public long owner(long protocol, String source, long sourcePort, String target, long targetPort) { return -1; }
        @Override public String route(long uid) { return Config.PROXY; }
        @Override public void opened(long id, long uid, String protocol, String target, String route) { }
        @Override public void closed(long id, String result, long sent, long received) { }
        @Override public void traffic(long sent, long received) { }
    }

    private final class FlowHooks extends ProbeHooks implements PerformanceHooks {
        private final Policy policy;
        private final String sessionId;
        private final Session counters;
        private final Network network;
        private final String profileId, networkType;
        private final Map<Integer,String> labels = new java.util.concurrent.ConcurrentHashMap<>();

        FlowHooks(Policy policy, String sessionId, Session counters,Network network,String profileId) {
            this.policy = policy;
            this.sessionId = sessionId;
            this.counters = counters;
            this.network=network;
            this.profileId=profileId;
            this.networkType=networkType(network);
        }

        @Override public boolean protect(long fd) { return protectSocket(fd,network); }

        @Override public long owner(long protocol, String source, long sourcePort, String target, long targetPort) {
            try {
                return networks.getConnectionOwnerUid(protocol == 6 ? OsConstants.IPPROTO_TCP : OsConstants.IPPROTO_UDP,
                        new InetSocketAddress(InetAddresses.parseNumericAddress(source), (int) sourcePort),
                        new InetSocketAddress(InetAddresses.parseNumericAddress(target), (int) targetPort));
            } catch (IllegalArgumentException | SecurityException e) {
                return -1;
            }
        }

        @Override public String route(long uid) {
            if (uid < 0 && policy.hasBlock) return Config.BLOCK;
            return policy.rules.getOrDefault((int) uid, Config.PROXY);
        }

        @Override public void opened(long id, long uid, String protocol, String target, String route) {
            String label = uid < 0 ? "Неопределённое приложение" : labels.computeIfAbsent((int) uid, this::label);
            history.open(sessionId + "/" + id, label, protocol, target, route, profileId, networkType);
        }

        private String label(int uid) {
            PackageManager pm = getPackageManager();
            String[] packages = pm.getPackagesForUid(uid);
            if (packages == null || packages.length == 0) return "UID " + uid;
            if (packages.length != 1) return String.join(", ", packages);
            try {
                return pm.getApplicationLabel(pm.getApplicationInfo(packages[0], 0)) + " · " + packages[0];
            } catch (PackageManager.NameNotFoundException ignored) {
                return packages[0];
            }
        }

        @Override public void finished(long id, String result, long sent, long received, long tcpMillis, long handshakeMillis, long firstByteMillis, long dnsMillis, String stage) {
            history.close(sessionId + "/" + id, result, sent, received,
                    new History.Metrics(tcpMillis,handshakeMillis,firstByteMillis,dnsMillis,stage));
        }

        @Override public void closed(long id, String result, long sent, long received) {
            history.close(sessionId + "/" + id, result, sent, received);
        }

        @Override public void traffic(long sent, long received) {
            counters.up.addAndGet(sent);
            counters.down.addAndGet(received);
            history.traffic(sent, received);
            trafficSample(counters, sent, received);
        }
    }
}
