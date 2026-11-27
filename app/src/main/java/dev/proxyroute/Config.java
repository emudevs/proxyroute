package dev.proxyroute;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.InetAddresses;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.IDN;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class Config {
    static final String PROXY = "proxy", BLOCK = "block", DIRECT = "direct", BYPASS = "bypass";
    static final String FIREWALL = "firewall";
    private static final String KEY = "proxyroute.credentials.v1";

    record Profile(String id, String title, String protocol, String host, int port, String secret) {
        String label() { return title.trim().isEmpty() ? host + ":" + port : title; }
    }

    record Credentials(String user, String password) {}
    record Settings(List<Profile> profiles, String selected, Map<String,String> rules) {
        Profile active() {
            return profiles.stream().filter(p -> p.id.equals(selected)).findFirst().orElse(null);
        }
    }

    private final SharedPreferences preferences;

    Config(Context context) {
        preferences = context.getSharedPreferences("route-config", Context.MODE_PRIVATE);
    }

    boolean enabled(String name,boolean fallback) { return preferences.getBoolean(name,fallback); }
    void setEnabled(String name,boolean value) { preferences.edit().putBoolean(name,value).apply(); }
    String option(String name,String fallback) { return preferences.getString(name,fallback); }
    void setDns(DnsOptions options) {
        preferences.edit().putString("dnsUrl",options.url()).putString("dnsIp",options.bootstrap()).apply();
    }
    record AppScope(boolean selectedOnly, boolean exclusionsEnabled) {}

    AppScope appScope() {
        var saved=preferences.getAll();
        boolean enabled=!Boolean.FALSE.equals(saved.get("splitEnabled"));
        return new AppScope(enabled&&Boolean.TRUE.equals(saved.get("splitInclude")),enabled);
    }

    void setAppScope(boolean selectedOnly) {
        preferences.edit().putBoolean("splitEnabled",true).putBoolean("splitInclude",selectedOnly).apply();
    }

    java.util.Set<String> included() {
        return new java.util.HashSet<>(preferences.getStringSet("splitIncluded",Collections.emptySet()));
    }
    void include(String pkg,boolean on) {
        var next=included();
        if(on)next.add(pkg); else next.remove(pkg);
        preferences.edit().putStringSet("splitIncluded",next).apply();
    }

    Settings read() {
        try {
            JSONObject data = new JSONObject(preferences.getString("settings", "{}"));
            JSONArray profiles = data.optJSONArray("profiles");
            List<Profile> result = new ArrayList<>();
            if (profiles != null) {
                for (int i = 0; i < profiles.length(); i++) {
                    JSONObject p = profiles.getJSONObject(i);
                    result.add(new Profile(p.getString("id"), p.getString("title"), p.getString("protocol"),
                            p.getString("host"), p.getInt("port"), p.getString("secret")));
                }
            }
            Map<String,String> rules = new LinkedHashMap<>();
            JSONObject entries = data.optJSONObject("rules");
            if (entries != null) entries.keys().forEachRemaining(pkg -> rules.put(pkg, entries.optString(pkg)));
            return new Settings(Collections.unmodifiableList(result), data.optString("selected", FIREWALL), Collections.unmodifiableMap(rules));
        } catch (JSONException e) {
            throw new IllegalStateException("Не удалось прочитать настройки VPN", e);
        }
    }

    void write(Settings settings) {
        try {
            JSONArray profiles = new JSONArray();
            for (Profile p : settings.profiles) {
                profiles.put(new JSONObject().put("id", p.id).put("title", p.title)
                        .put("protocol", p.protocol).put("host", p.host).put("port", p.port)
                        .put("secret", p.secret));
            }
            JSONObject data = new JSONObject().put("profiles", profiles).put("selected", settings.selected)
                    .put("rules", new JSONObject(settings.rules));
            if (!preferences.edit().putString("settings", data.toString()).commit()) {
                throw new IllegalStateException("Не удалось сохранить настройки");
            }
        } catch (JSONException e) {
            throw new IllegalStateException(e);
        }
    }

    static Profile create(Profile previous, String title, String protocol, String host, int port,
                          String user, String password) throws Exception {
        host = host.trim();
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length()-1);
        if (!InetAddresses.isNumericAddress(host)) host = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES);
        if (host.isEmpty() || host.length() > 253 || host.indexOf('%') != -1 || port < 1 || port > 65535) {
            throw new IllegalArgumentException("Укажи корректный адрес и порт");
        }
        if (protocol.equals("socks5") && (!user.isEmpty() || !password.isEmpty())
                && (user.isEmpty() || password.isEmpty() || bytes(user).length > 255 || bytes(password).length > 255)) {
            throw new IllegalArgumentException("SOCKS5 требует логин и пароль длиной 1–255 байт");
        }
        if (!protocol.equals("socks5") && user.contains(":")) {
            throw new IllegalArgumentException("В логине HTTP-прокси нельзя использовать двоеточие");
        }
        String secret = user.isEmpty() && password.isEmpty() ? "" : encrypt(new JSONArray().put(user).put(password).toString());
        return new Profile(previous == null ? UUID.randomUUID().toString() : previous.id,
                title.trim(), protocol, host, port, secret);
    }

    static Credentials credentials(Profile profile) throws Exception {
        if (profile == null || profile.secret.isEmpty()) return new Credentials("", "");
        String[] parts = profile.secret.split("\\.", 2);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, decode(parts[0])));
        JSONArray values = new JSONArray(new String(cipher.doFinal(decode(parts[1])), StandardCharsets.UTF_8));
        return new Credentials(values.getString(0), values.getString(1));
    }

    static List<String> addresses(Context context, String host) throws Exception {
        if (InetAddresses.isNumericAddress(host)) return Collections.singletonList(host);
        ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
        Network selected = manager.getActiveNetwork();
        if (!physical(manager, selected)) {
            selected = null;
            for (Network candidate : manager.getAllNetworks()) {
                if (!physical(manager, candidate)) continue;
                if (selected == null || manager.getNetworkCapabilities(candidate).hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                    selected = candidate;
                }
            }
        }
        if (selected == null) throw new IllegalStateException("Сеть недоступна");
        List<String> result = new ArrayList<>();
        for (InetAddress address : selected.getAllByName(host)) result.add(address.getHostAddress());
        if (result.isEmpty()) throw new IllegalArgumentException("У прокси нет IP-адреса");
        return result;
    }

    private static boolean physical(ConnectivityManager manager, Network network) {
        NetworkCapabilities caps = network == null ? null : manager.getNetworkCapabilities(network);
        return caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
    }

    private static String encrypt(String secret) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key());
        return encode(cipher.getIV()) + "." + encode(cipher.doFinal(bytes(secret)));
    }

    private static synchronized SecretKey key() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (store.containsAlias(KEY)) return (SecretKey) store.getKey(KEY, null);
        KeyGenerator gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        gen.init(new KeyGenParameterSpec.Builder(KEY, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).build());
        return gen.generateKey();
    }

    private static byte[] bytes(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    private static String encode(byte[] b) { return Base64.encodeToString(b, Base64.NO_WRAP); }
    private static byte[] decode(String s) { return Base64.decode(s, Base64.NO_WRAP); }
}
