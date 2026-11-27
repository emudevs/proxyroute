package dev.proxyroute;

import android.app.LocaleManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.os.Build;
import android.os.LocaleList;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

final class AppLanguage {
    record Option(String tag, String name) {}

    static final List<Option> OPTIONS = Collections.unmodifiableList(Arrays.asList(
            new Option("de", "Deutsch"), new Option("en", "English"),
            new Option("es", "Español"), new Option("fr", "Français"),
            new Option("hi", "हिन्दी"), new Option("id", "Bahasa Indonesia"),
            new Option("it", "Italiano"), new Option("ja", "日本語"),
            new Option("ko", "한국어"), new Option("nl", "Nederlands"),
            new Option("pl", "Polski"), new Option("pt-BR", "Português (Brasil)"),
            new Option("ru", "Русский"), new Option("tr", "Türkçe"),
            new Option("zh-CN", "简体中文"), new Option("zh-TW", "繁體中文")));

    private AppLanguage() {}

    static String selected(Context context) {
        if (Build.VERSION.SDK_INT >= 33) {
            LocaleList locales = context.getSystemService(LocaleManager.class).getApplicationLocales();
            return locales.isEmpty() ? "" : locales.get(0).toLanguageTag();
        }
        return preferences(context).getString("language", "");
    }

    static boolean select(Context context, String tag) {
        if (tag.equals(selected(context))) return false;
        if (Build.VERSION.SDK_INT >= 33) {
            context.getSystemService(LocaleManager.class).setApplicationLocales(LocaleList.forLanguageTags(tag));
        } else {
            preferences(context).edit().putString("language", tag).apply();
        }
        return true;
    }

    static Context localized(Context base) {
        if (Build.VERSION.SDK_INT >= 33) return base;
        String tag = selected(base);
        if (tag.isEmpty()) return base;
        Configuration configuration = new Configuration(base.getResources().getConfiguration());
        configuration.setLocales(new LocaleList(Locale.forLanguageTag(tag)));
        return base.createConfigurationContext(configuration);
    }

    static String label(Context context) {
        String tag = selected(context);
        if (tag.isEmpty()) return context.getString(R.string.l10n_settings_system_language);
        for (Option option : OPTIONS) {
            if (option.tag().equalsIgnoreCase(tag)) return option.name();
        }
        Locale locale = Locale.forLanguageTag(tag);
        return locale.getDisplayName(locale);
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences("app-language", Context.MODE_PRIVATE);
    }
}
