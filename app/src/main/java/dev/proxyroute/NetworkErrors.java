package dev.proxyroute;

import java.util.Locale;

final class NetworkErrors {
    record Detail(String code,String title,String hint) {}
    static Detail describe(String message) {
        String value=message==null?"":message.toLowerCase(Locale.ROOT);
        if(value.equals("proxy_auth")) value="authentication";
        if(value.equals("vpn_permission")) value="permission";
        if(value.contains("407") || value.contains("authentication"))
            return new Detail("PROXY_AUTH","Прокси отклонил авторизацию","Проверь логин, пароль и выбранный протокол.");
        if(value.contains("x509") || value.contains("certificate") || value.contains("tls:"))
            return new Detail("TLS","Не удалось проверить TLS","Проверь имя сервера, протокол HTTPS и время на телефоне.");
        if(value.contains("unknownhost") || value.contains("unknown host") || value.contains("не удалось найти") || value.contains("нет ip"))
            return new Detail("DNS_LOOKUP","Имя сервера не разрешается","Проверь адрес сервера и попробуй IP.");
        if(value.contains("dns"))
            return new Detail("DNS","DNS-сервер не ответил корректно","Проверь настройки DNS и доступность выбранного сервера по текущему маршруту.");
        if(value.contains("timeout") || value.contains("timed out"))
            return new Detail("TIMEOUT","Сервер не ответил вовремя","Проверь подключение и доступность прокси.");
        if(value.contains("udp") && value.contains("connect"))
            return new Detail("UDP_UNSUPPORTED","UDP недоступен через этот прокси","Используй SOCKS5 с поддержкой UDP или прямой маршрут.");
        if(value.contains("refused") || value.contains("rejected") || value.contains("no route"))
            return new Detail("CONNECT","Соединение отклонено","Проверь порт, протокол и разрешённые направления на прокси.");
        if(value.contains("разрешение") || value.contains("permission") || value.contains("protect"))
            return new Detail("VPN_PERMISSION","Не удалось открыть VPN","Проверь разрешение VPN и какой VPN выбран в Android.");
        if(value.contains("сеть") || value.contains("network"))
            return new Detail("NETWORK","Нет доступной сети","Подключись к Wi-Fi или мобильной сети и повтори.");
        return new Detail("CONNECTION","Не удалось подключиться","Проверь маршрут, адрес и протокол. Код ошибки есть в выгрузке журнала.");
    }
    static boolean failed(String result) {
        return switch(result) {
            case "active","closed","VPN stopped","process stopped","blocked by application rule","blocked by DNS filter" -> false;
            default -> true;
        };
    }
}
