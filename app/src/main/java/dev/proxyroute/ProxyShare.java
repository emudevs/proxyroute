package dev.proxyroute;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class ProxyShare {
    private static final String PREFIX = "proxyroute://import/v1";
    private static final byte[] CONTEXT = PREFIX.getBytes(StandardCharsets.US_ASCII);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int KEY_BYTES = 16, NONCE_BYTES = 12, MAX_PAYLOAD = 1600;

    record Import(String mode, byte[] payload) {
        boolean encrypted() { return mode.equals("sealed"); }
        boolean hot() { return mode.equals("hot"); }

        ProxyLink open(String code) {
            if (!encrypted() && !hot()) {
                ProxyLink profile = decodeProfile(payload);
                if (!profile.user().isEmpty() || !profile.password().isEmpty()) throw invalid();
                return profile;
            }
            try {
                byte[] key = hot() ? Arrays.copyOf(payload, KEY_BYTES) : Base64.getUrlDecoder().decode(code.trim());
                if (key.length != KEY_BYTES) throw invalid();
                int start = hot() ? KEY_BYTES : 0;
                int offset = start + NONCE_BYTES;
                Cipher cipher = cipher(Cipher.DECRYPT_MODE, key, Arrays.copyOfRange(payload, start, offset));
                return decodeProfile(cipher.doFinal(payload, offset, payload.length - offset));
            } catch (GeneralSecurityException | IllegalArgumentException e) {
                throw new IllegalArgumentException("Неверный ключ или повреждённая ссылка");
            }
        }
    }

    static String create(ProxyLink profile, boolean includeCredentials) throws GeneralSecurityException {
        String endpoint;
        try {
            URI address = new URI(profile.protocol(), null, profile.host(), profile.port(), null, null, null);
            String auth = includeCredentials ? encodeUserInfo(profile.user()) + ":" +
                    encodeUserInfo(profile.password()) + "@" : "";
            endpoint = address.getScheme() + "://" + auth + address.getRawAuthority();
        } catch (java.net.URISyntaxException e) {
            throw invalid();
        }
        byte[] bytes = endpoint.getBytes(StandardCharsets.US_ASCII);
        if (!includeCredentials) return link("endpoint", bytes);
        byte[] nonce = new byte[NONCE_BYTES];
        byte[] key = new byte[KEY_BYTES];
        RANDOM.nextBytes(nonce);
        RANDOM.nextBytes(key);
        byte[] sealed = cipher(Cipher.ENCRYPT_MODE, key, nonce).doFinal(bytes);
        // Self-contained bearer link. The bundled key lets every recipient open the profile.
        byte[] payload = Arrays.copyOf(key, KEY_BYTES + NONCE_BYTES + sealed.length);
        System.arraycopy(nonce, 0, payload, KEY_BYTES, NONCE_BYTES);
        System.arraycopy(sealed, 0, payload, KEY_BYTES + NONCE_BYTES, sealed.length);
        return link("hot", payload);
    }

    static boolean matches(String value) {
        return value.trim().regionMatches(true, 0, "proxyroute:", 0, "proxyroute:".length());
    }

    static Import parse(String value) {
        value = value.trim();
        if (value.length() > 2200 || !value.startsWith(PREFIX + "?")) throw invalid();
        String[] fields = value.substring(PREFIX.length() + 1).split("=", 2);
        if (fields.length != 2 || !fields[1].matches("[A-Za-z0-9_-]+")
                || !(fields[0].equals("endpoint") || fields[0].equals("sealed") || fields[0].equals("hot"))) throw invalid();
        byte[] payload;
        try { payload = Base64.getUrlDecoder().decode(fields[1]); }
        catch (IllegalArgumentException e) { throw invalid(); }
        if (payload.length > MAX_PAYLOAD || (fields[0].equals("sealed") && payload.length <= NONCE_BYTES + 16)
                || (fields[0].equals("hot") && payload.length <= KEY_BYTES + NONCE_BYTES + 16)) throw invalid();
        return new Import(fields[0], payload);
    }

    private static ProxyLink decodeProfile(byte[] data) {
        ProxyLink profile = ProxyLink.parse(new String(data, StandardCharsets.US_ASCII));
        if (profile.protocol() == null) throw invalid();
        return profile;
    }

    private static String encodeUserInfo(String value) throws java.net.URISyntaxException {
        String authority = new URI(null, value, "example.invalid", -1, null, null, null).toASCIIString();
        return URI.create(authority).getRawUserInfo().replace(":", "%3A");
    }

    private static Cipher cipher(int mode, byte[] key, byte[] nonce) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(CONTEXT);
        return cipher;
    }

    private static String link(String mode, byte[] data) {
        if (data.length > MAX_PAYLOAD) throw new IllegalArgumentException("Профиль слишком длинный для QR-кода");
        return PREFIX + "?" + mode + "=" + encode(data);
    }

    private static String encode(byte[] data) { return Base64.getUrlEncoder().withoutPadding().encodeToString(data); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Некорректная ссылка ProxyRoute"); }
}
