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
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;

import dev.proxyroute.nativecore.tunnel.Engine;
import dev.proxyroute.nativecore.tunnel.Hooks;
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
    private boolean wifiFallback;
    private boolean observingNetwork;
    private final ConnectivityManager.NetworkCallback networkChanges = new ConnectivityManager.NetworkCallback() {
        @Override public void onAvailable(Network network) { refreshNetwork(); }
        @Override public void onLost(Network network) { refreshNetwork(); }
        @Override public void onCapabilitiesChanged(Network network,NetworkCapabilities capabilities) { refreshNetwork(); }
    };

    private void refreshNetwork() {
        if(!wanted || !config.enabled("wifiOnly",false) || worker.isShutdown()) return;
        try {
            worker.execute(()->{
                Network network=networks.getActiveNetwork();
                boolean fallback=config.read().active()!=null && !isWifi(network);
                if(engine!=null && (!java.util.Objects.equals(network,tunnelNetwork) || wifiFallback!=fallback)) {
                    if(pending!=null)pending.cancel(false);
                    establishTunnel();
                }
            });
        } catch(java.util.concurrent.RejectedExecutionException ignored) { }
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
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION, notification);
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
        try {
            Config.Settings settings = config.read();
            Config.Profile profile = settings.active();
            boolean wifiOnly=config.enabled("wifiOnly",false);
            Network physical=wifiOnly?networks.getActiveNetwork():null;
            boolean fallback=wifiOnly && !isWifi(physical) && profile!=null;
            boolean firewall = Config.FIREWALL.equals(settings.selected());
            if (!firewall && profile == null) throw new IllegalStateException("Выбранный прокси удалён");
            Config.Credentials auth = Config.credentials(profile);
            String ip = "";
            if (profile != null && !fallback) {
                // Choose the first responsive address when a name has multiple
                // records. A single address can still start with an offline proxy.
                var addresses = Config.addresses(this, profile.host());
                ip = addresses.get(0);
                if (addresses.size() > 1) {
                    for (String candidate : addresses) {
                        try {
                            Tunnel.check(new ProbeHooks(){ @Override public boolean protect(long fd) { return protectSocket(fd,physical); } },profile.protocol(),profile.host(),candidate,
                                    profile.port(),auth.user(),auth.password());
                            ip = candidate;
                            break;
                        } catch (Exception ignored) { }
                        if (!wanted) return;
                    }
                }
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
                if(count==0)throw new IllegalStateException("Выбери установленные приложения в брандмауэре");
            } else {
                builder.addDisallowedApplication(getPackageName());
                for (String pkg : policy.excluded()) {
                    try { builder.addDisallowedApplication(pkg); }
                    catch (PackageManager.NameNotFoundException ignored) { }
                }
            }
            if(physical!=null)builder.setUnderlyingNetworks(new Network[]{physical});
            next = builder.establish();
            if (next == null) throw new IllegalStateException("Android отозвал разрешение VPN");
            Session nextSession = engine == null ? new Session() : session;
            boolean direct=firewall||fallback;
            DnsOptions dns=DnsOptions.selected(config);
            Engine started=Tunnel.startConfigured(next.getFd(),
                    new FlowHooks(policy,UUID.randomUUID().toString(),nextSession,physical),
                    direct?"direct":profile.protocol(),direct?"":profile.host(),ip,
                    direct?0:profile.port(),auth.user(),auth.password(),direct,dns.url(),dns.bootstrap(),
                    config.enabled("ads",false),config.enabled("trackers",false),config.enabled("dnsDirect",false));
            closeTunnel();
            tun = next;
            next = null;
            engine = started;
            session = nextSession;
            failures = 0;
            tunnelNetwork=physical;
            wifiFallback=fallback;
            String message=firewall?"Брандмауэр активен":fallback?"Прямой доступ · прокси только по Wi-Fi":"VPN активен · "+profile.label();
            update(new Status(true,false,message));
            history.serviceEvent(message,"closed");
        } catch (Exception | LinkageError e) {
            if (next != null) {
                try { next.close(); } catch (Exception ignored) { }
                closeTunnel();
            }
            if (!wanted) return;
            String error = e.getMessage();
            if (error == null || error.isEmpty()) error = e.getClass().getSimpleName();
            NetworkErrors.Detail detail=NetworkErrors.describe(error);
            String userError=error.startsWith("Выбери")?error:detail.title();
            update(new Status(engine != null,false,"Ошибка VPN · "+userError));
            if(failures==0)history.serviceEvent("Ошибка VPN · "+userError,detail.code());
            if (wanted) {
                int delay = Math.min(120, 5 << Math.min(failures++, 5));
                pending = worker.schedule(this::establishTunnel, delay, TimeUnit.SECONDS);
            }
        }
    }

    private void closeTunnel() {
        if (engine != null) {
            engine.stop();
            engine = null;
        }
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
        if(observingNetwork)networks.unregisterNetworkCallback(networkChanges);
        if (instance == this) instance = null;
        worker.execute(() -> {
            if (pending != null) pending.cancel(false);
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
            if (wanted && instance == this) {
                getSystemService(NotificationManager.class).notify(NOTIFICATION, notification(change.message()));
            }
        });
    }

    static final String STATUS_CHANGED="dev.proxyroute.STATUS_CHANGED";

    private void updateStatus(Status change) {
        status=change;
        main.post(()->sendBroadcast(new Intent(STATUS_CHANGED).setPackage(getPackageName())));
    }

    private boolean protectSocket(long fd,Network network) {
        if(!protect((int)fd))return false;
        if(network==null)return true;
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
        Notification.Builder builder = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_route).setContentTitle("ProxyRoute")
                .setContentText(message).setContentIntent(openApp()).setOngoing(true)
                .setOnlyAlertOnce(true).setCategory(Notification.CATEGORY_SERVICE);
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

    private final class FlowHooks extends ProbeHooks {
        private final Policy policy;
        private final String sessionId;
        private final Session counters;
        private final Network network;
        private final Map<Integer,String> labels = new java.util.concurrent.ConcurrentHashMap<>();

        FlowHooks(Policy policy, String sessionId, Session counters,Network network) {
            this.policy = policy;
            this.sessionId = sessionId;
            this.counters = counters;
            this.network=network;
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
            history.open(sessionId + "/" + id, label, protocol, target, route);
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

        @Override public void closed(long id, String result, long sent, long received) {
            history.close(sessionId + "/" + id, result, sent, received);
        }

        @Override public void traffic(long sent, long received) {
            counters.up.addAndGet(sent);
            counters.down.addAndGet(received);
            history.traffic(sent, received);
        }
    }
}
