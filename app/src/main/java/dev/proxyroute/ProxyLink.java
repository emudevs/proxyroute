package dev.proxyroute;

import java.net.URI;
import java.util.Locale;

record ProxyLink(String protocol,String host,int port,String user,String password) {
    static ProxyLink parse(String input) {
        String value=input.trim();
        if(value.isEmpty()) throw new IllegalArgumentException("Вставь адрес прокси");
        if(value.contains("://")) {
            URI uri;
            try { uri=URI.create(value); }
            catch(IllegalArgumentException e) { throw format(); }
            String protocol=uri.getScheme().toLowerCase(Locale.ROOT);
            int defaultPort=switch(protocol) {
                case "http" -> 8080;
                case "https" -> 443;
                case "socks5" -> 1080;
                default -> throw new IllegalArgumentException("Протокол должен быть HTTP, HTTPS или SOCKS5");
            };
            if(uri.getHost()==null || uri.getRawQuery()!=null || uri.getRawFragment()!=null
                    || !(uri.getPath().isEmpty() || uri.getPath().equals("/"))) throw format();
            String[] auth=uri.getRawUserInfo()==null?new String[0]:uri.getRawUserInfo().split(":",2);
            return new ProxyLink(protocol,uri.getHost(),uri.getPort()==-1?defaultPort:port(Integer.toString(uri.getPort())),
                    auth.length>0?decode(auth[0]):"",auth.length>1?decode(auth[1]):"");
        }
        String host,tail;
        if(value.startsWith("[")) {
            int close=value.indexOf("]:");
            if(close<0)throw format();
            host=value.substring(0,close+1); tail=value.substring(close+2);
        } else {
            int colon=value.indexOf(':');
            if(colon<1)throw format();
            host=value.substring(0,colon); tail=value.substring(colon+1);
        }
        if(host.matches(".*[\\s/@].*"))throw format();
        int separator=0;
        while(separator<tail.length() && tail.charAt(separator)>='0' && tail.charAt(separator)<='9')separator++;
        int port=port(tail.substring(0,separator));
        if(separator==tail.length())return new ProxyLink(null,host,port,"","");
        if(tail.charAt(separator)!=':' && tail.charAt(separator)!='@')throw format();
        String[] auth=tail.substring(separator+1).split(":",2);
        if(auth.length!=2 || auth[0].isEmpty())throw format();
        return new ProxyLink(null,host,port,auth[0],auth[1]);
    }

    private static String decode(String value) {
        try { return java.net.URLDecoder.decode(value.replace("+","%2B"),"UTF-8"); }
        catch(java.io.UnsupportedEncodingException e) { throw new AssertionError(e); }
        catch(IllegalArgumentException e) { throw format(); }
    }
    private static int port(String value) {
        try {
            int port=Integer.parseInt(value);
            if(port>0 && port<=65535)return port;
        } catch(NumberFormatException ignored) { }
        throw new IllegalArgumentException("Порт должен быть от 1 до 65535");
    }
    private static IllegalArgumentException format() {
        return new IllegalArgumentException("Проверь формат адреса, логина и пароля");
    }
}
