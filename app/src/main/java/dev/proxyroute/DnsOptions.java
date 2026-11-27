package dev.proxyroute;

import java.net.URI;
import java.util.List;

record DnsOptions(String name,String url,String bootstrap) {
    static final List<DnsOptions> PRESETS=java.util.Arrays.asList(
            new DnsOptions("Cloudflare","https://cloudflare-dns.com/dns-query","1.1.1.1"),
            new DnsOptions("Google","https://dns.google/dns-query","8.8.8.8"),
            new DnsOptions("Quad9","https://dns.quad9.net/dns-query","9.9.9.9"),
            new DnsOptions("AdGuard","https://dns.adguard-dns.com/dns-query","94.140.14.14"));

    static DnsOptions selected(Config config) {
        String url=config.option("dnsUrl",""), ip=config.option("dnsIp","");
        if(url.isEmpty())return PRESETS.get(0);
        for(DnsOptions preset:PRESETS) if(preset.url.equals(url) && preset.bootstrap.equals(ip))return preset;
        return new DnsOptions("Свой сервер",url,ip);
    }

    static DnsOptions custom(String url,String ip) {
        try {
            URI uri=URI.create(url.trim());
            if(!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost()==null || uri.getUserInfo()!=null
                    || uri.getRawQuery()!=null || uri.getRawFragment()!=null || !android.net.InetAddresses.isNumericAddress(ip.trim()))
                throw new IllegalArgumentException();
            return new DnsOptions("Свой сервер",uri.toASCIIString(),ip.trim());
        } catch(IllegalArgumentException e) {
            throw new IllegalArgumentException("Укажи HTTPS-адрес DoH и IP-адрес сервера");
        }
    }
}
