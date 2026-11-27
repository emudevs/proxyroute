package dev.proxyroute;

import android.Manifest;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.IntentFilter;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.ImageDecoder;
import android.graphics.Paint;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.text.Editable;
import android.text.InputType;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.PasswordTransformationMethod;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.common.HybridBinarizer;

import dev.proxyroute.nativecore.tunnel.Tunnel;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static dev.proxyroute.FigmaUi.*;

public final class MainActivity extends Activity {
    private static final int VPN_REQUEST=201, EXPORT_REQUEST=203, QR_IMAGE_REQUEST=204;
    private static final String[] TABS={"Серверы","Журнал","Брандмауэр","Настройки"};
    private static final int[] TAB_ICONS={R.drawable.fig_servers,R.drawable.fig_log,R.drawable.fig_firewall,R.drawable.fig_settings};
    private static final String[] PROTOCOLS={"http","https","socks5"};
    private static final String[] FILTERS={"",Config.PROXY,Config.BLOCK,"errors"};
    private final Handler ui=new Handler(Looper.getMainLooper());
    private final ExecutorService data=Executors.newSingleThreadExecutor();
    private final ExecutorService appLoader=Executors.newSingleThreadExecutor();
    private final ExecutorService probes=Executors.newFixedThreadPool(3);
    private final Map<String,Probe> checks=new HashMap<>();
    private final Map<String,TextView> checkViews=new HashMap<>();
    private List<InstalledApp> installed=Collections.emptyList();

    private Config config;
    private History history;
    private FigmaUi design;
    private FrameLayout frame;
    private LinearLayout editPage;
    private Runnable returnToEdit;
    private Runnable fromLinkAction;
    private EditText importField;
    private JournalAdapter journalAdapter;
    private final Map<String,CachedReport> journalCache=new java.util.LinkedHashMap<>();
    private final android.util.LruCache<String,android.graphics.Bitmap> appIcons=new android.util.LruCache<>(96);
    private final BroadcastReceiver vpnChanges=new BroadcastReceiver() {
        @Override public void onReceive(Context context,Intent intent) {
            refreshVpnUi();
        }
    };
    private LinearLayout page, nav, hero, serverRows, stats;
    private TextView serverHeading, graphTotal, firewallTitle, firewallCount;
    private FigmaUi.Toggle firewallToggle;
    private FrameLayout firewallBadge;
    private boolean firewallActive;
    private AppsAdapter activeApps;
    private ListView firewallList;
    private final TextView[] sessionValues=new TextView[3];
    private ChartView chart;
    private int heroColor=PANEL;
    private String heroKey="", section="", query="", eventQuery="";
    private String firewallSearch="";
    private boolean choosingApps;
    private int firewallPosition,firewallTop;
    private boolean resumed, loadingJournal, searching, searchingHistory, appScan, appsReady;
    private boolean appScanFailed;
    private long retryJournalAt;
    private int tab, screenVersion, chartPeriod, filter, offset;
    private long lastHistoryRevision=-1;
    private InstalledApp runningRule;
    private Report displayedReport;
    private record CachedReport(long revision,Report report) {}
    private record Probe(Config.Profile profile, boolean ok, String detail) {}
    private record InstalledApp(String pkg,String name,String searchKey) {}
    private record Report(History.Chart graph,History.Totals totals,List<History.Connection> rows,long chartBase,int chartSpan) {}

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        if(state!=null) { tab=state.getInt("tab"); chartPeriod=state.getInt("period"); }
        config=new Config(this); history=History.get(this); design=new FigmaUi(this);
        LinearLayout root=design.column();
        root.setBackgroundColor(BG);
        root.setOnApplyWindowInsetsListener((view,insets)-> {
            if(Build.VERSION.SDK_INT>=30) {
                var safe=insets.getInsets(android.view.WindowInsets.Type.systemBars() | android.view.WindowInsets.Type.displayCutout() | android.view.WindowInsets.Type.ime());
                root.setPadding(safe.left,safe.top,safe.right,safe.bottom);
            } else {
                root.setPadding(insets.getSystemWindowInsetLeft(),insets.getSystemWindowInsetTop(),insets.getSystemWindowInsetRight(),insets.getSystemWindowInsetBottom());
            }
            return insets;
        });
        frame=new FrameLayout(this);
        root.addView(frame,new LinearLayout.LayoutParams(-1,0,1));
        nav=design.row();
        nav.setBackgroundColor(PANEL);
        root.addView(nav,new LinearLayout.LayoutParams(-1,dp(76)));
        setContentView(root);
        render();
        if(state==null) consumeProxyLink(getIntent());
        frame.post(this::fetchApps);
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        consumeProxyLink(intent);
    }

    private void consumeProxyLink(Intent intent) {
        if(intent==null || !Intent.ACTION_VIEW.equals(intent.getAction()) || intent.getData()==null)return;
        String value=intent.getDataString();
        if(!ProxyShare.matches(value))return;
        try { ProxyShare.parse(value); }
        catch(IllegalArgumentException e) {
            Toast.makeText(this,"Некорректная ссылка ProxyRoute",Toast.LENGTH_SHORT).show();
            return;
        }
        Runnable open=()->{
            tab=0;
            edit(null);
            if(fromLinkAction!=null)fromLinkAction.run();
            if(importField!=null)importField.setText(value);
        };
        if(section.equals("edit") || section.equals("import") || section.equals("qr")) {
            new AlertDialog.Builder(this).setTitle("Импорт нового прокси")
                    .setMessage("Текущие несохранённые изменения будут сброшены.")
                    .setNegativeButton("Отмена",null).setPositiveButton("Импортировать",(d,w)->open.run()).show();
        } else open.run();
    }
    @Override protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        state.putInt("tab",tab); state.putInt("period",chartPeriod);
    }
    @Override protected void onStart() {
        super.onStart();
        IntentFilter filter=new IntentFilter(RouteService.STATUS_CHANGED);
        if(Build.VERSION.SDK_INT>=33)registerReceiver(vpnChanges,filter,Context.RECEIVER_NOT_EXPORTED);
        else registerReceiver(vpnChanges,filter);
        if(getPreferences(MODE_PRIVATE).getBoolean("autoCheck",true))checkAll();
    }
    @Override protected void onResume() {
        super.onResume();
        resumed=true;
        if(tab==3 && section.isEmpty()) render();
        refresh.run();
    }
    @Override protected void onPause() {
        resumed=false; ui.removeCallbacks(refresh);
        super.onPause();
    }
    @Override protected void onStop() {
        unregisterReceiver(vpnChanges);
        super.onStop();
    }
    @Override protected void onDestroy() {
        ui.removeCallbacksAndMessages(null);
        data.shutdownNow(); probes.shutdownNow(); appLoader.shutdownNow();
        super.onDestroy();
    }
    @Override public void onBackPressed() {
        if(section.equals("dnsCustom")) {openPage("dns"); return;}
        if(returnToEdit!=null) { returnToEdit.run(); return; }
        if (!section.isEmpty()) { closePage(); return; }
        if (tab==1 && searchingHistory) { searchingHistory=false; eventQuery=""; offset=0; render(); return; }
        if (tab==0 && searching) { searching=false; query=""; render(); return; }
        if (tab==0) { super.onBackPressed(); return; }
        switchTab(0);
    }
    private final Runnable refresh=new Runnable() {
        @Override public void run() {
            refreshVpnUi();
            if (tab==1) loadHistory(false);
            if(resumed) ui.postDelayed(this,1000);
        }
    };

    private void refreshVpnUi() {
        try { updateHero(); updateFirewallStatus(); }
        catch(Config.ReadFailure e) { showConfigError(); }
    }

    private void render() {
        try { renderContent(); }
        catch(Config.ReadFailure e) { showConfigError(); }
    }

    private void showConfigError() {
        screenVersion++;
        section=""; editPage=null; returnToEdit=null; importField=null; fromLinkAction=null;
        frame.removeAllViews();
        nav.setVisibility(View.GONE);
        hero=null; chart=null; activeApps=null; firewallToggle=null;
        page=design.column();
        design.pad(page,16,24);
        frame.addView(page,new FrameLayout.LayoutParams(-1,-1));
        add(page,t("Не удалось прочитать настройки ProxyRoute",21,TEXT,600),-2,0);
        add(page,t("Профили и правила сохранены на устройстве.",14,MUTED,400),-2,10);
        add(page,design.pill("Повторить",14,BG,LIME,48,this::render),48,16);
    }

    private void renderContent() {
        screenVersion++;
        loadingJournal=false; lastHistoryRevision=-1;
        frame.removeAllViews(); nav.removeAllViews(); checkViews.clear();
        hero=null; heroKey=""; chart=null;
        displayedReport=null; journalAdapter=null;
        activeApps=null; firewallList=null;
        firewallToggle=null;
        page=design.column();
        frame.addView(page,new FrameLayout.LayoutParams(-1,-1));
        nav.setVisibility(section.isEmpty()?View.VISIBLE:View.GONE);
        if (!section.isEmpty()) {
            switch(section) {
                case "app" -> appRule();
                case "vpn" -> externalVpn();
                case "dns" -> dnsPage();
                case "dnsCustom" -> customDns();
                case "language" -> languagePage();
                default -> throw new IllegalStateException(section);
            }
            return;
        }
        for(int i=0;i<TABS.length;i++) {
            int index=i;
            LinearLayout item=design.column();
            item.setGravity(Gravity.CENTER);
            FrameLayout indicator=design.iconBox(TAB_ICONS[i],i==tab?LIME:MUTED, i==tab?0x33bbf451:0,32,20,100,null,null);
            item.addView(indicator,new LinearLayout.LayoutParams(dp(64),dp(32)));
            design.gap(item,4);
            TextView caption=design.text(TABS[i],11,i==tab?TEXT:FAINT,i==tab?600:400);
            caption.setGravity(Gravity.CENTER);
            item.addView(caption,new LinearLayout.LayoutParams(-1,-2));
            item.setContentDescription(TABS[i]);
            item.setSelected(i==tab);
            design.action(item,0,16,0,()->switchTab(index));
            nav.addView(item,new LinearLayout.LayoutParams(0,-1,1));
        }
        switch(tab) {
            case 0 -> servers();
            case 1 -> journal();
            case 2 -> firewall();
            case 3 -> settings();
            default -> throw new IllegalStateException("Unknown tab");
        }
    }

    private void switchTab(int next) {
        if(tab==next)return;
        rememberFirewallPosition();
        int direction=next>tab?1:-1;
        tab=next;
        render();
        animatePage(dp(14)*direction,0,190);
        if(ValueAnimator.areAnimatorsEnabled()) {
            View indicator=((ViewGroup)nav.getChildAt(next)).getChildAt(0);
            indicator.setScaleX(.78f);
            indicator.setScaleY(.9f);
            indicator.animate().scaleX(1f).scaleY(1f).setDuration(240).setInterpolator(EASE_OUT).start();
        }
    }

    private void animatePage(float x,float y,long duration) {
        if(!ValueAnimator.areAnimatorsEnabled())return;
        page.setTranslationX(x);
        page.setTranslationY(y);
        page.animate().translationX(0).translationY(0)
                .setDuration(duration).setInterpolator(EASE_OUT).start();
    }
    private void toggle() {
        try { toggleVpn(); }
        catch(IllegalStateException | SecurityException | android.content.ActivityNotFoundException e) {
            showMessage("Android не разрешил изменить состояние VPN. Проверь системные настройки VPN.");
        }
    }

    private void toggleVpn() {
        if (RouteService.instance != null) {
            if(RouteService.instance.isAlwaysOn()) { openSettings(Settings.ACTION_VPN_SETTINGS); return; }
            startService(new Intent(this, RouteService.class).setAction(RouteService.DISCONNECT));
            return;
        }
        Intent consent = VpnService.prepare(this);
        if (consent != null) startActivityForResult(consent, VPN_REQUEST);
        else connect();
    }

    @Override protected void onActivityResult(int request, int result, Intent payload) {
        super.onActivityResult(request, result, payload);
        if(request==QR_IMAGE_REQUEST && result==RESULT_OK && payload!=null && payload.getData()!=null) {
            readQr(payload.getData());
            return;
        }
        if (request == VPN_REQUEST) {
            if(result == RESULT_OK) connect();
            else showMessage("Подключение отменено. Разреши VPN, чтобы включить туннель.");
        }
        if (request == EXPORT_REQUEST && result == RESULT_OK && payload!=null && payload.getData()!=null) {
            var uri=payload.getData();
            appLoader.execute(()->{
                try(var out=getContentResolver().openOutputStream(uri,"wt")) {
                    if(out==null)throw new java.io.IOException();
                    history.export(out);
                    ui.post(()->Toast.makeText(this,"Журнал выгружен",Toast.LENGTH_SHORT).show());
                } catch(History.Unavailable e) {
                    ui.post(()->showMessage("Журнал недоступен. Повтори экспорт позже."));
                } catch(Exception e) {
                    ui.post(()->Toast.makeText(this,"Не удалось записать файл журнала. Выбери другой каталог.",Toast.LENGTH_LONG).show());
                }
            });
        }
    }

    private void readQr(android.net.Uri uri) {
        EditText destination=importField;
        if(destination==null)return;
        appLoader.execute(()->{
            String decoded;
            try {
                Bitmap bitmap=ImageDecoder.decodeBitmap(ImageDecoder.createSource(getContentResolver(),uri),
                        (decoder,info,source)->{
                            decoder.setAllocator(ImageDecoder.ALLOCATOR_SOFTWARE);
                            int width=info.getSize().getWidth(), height=info.getSize().getHeight();
                            double ratio=Math.min(1,1800.0/Math.max(width,height));
                            decoder.setTargetSize(Math.max(1,(int)(width*ratio)),Math.max(1,(int)(height*ratio)));
                        });
                int width=bitmap.getWidth(),height=bitmap.getHeight();
                int[] pixels=new int[width*height];
                bitmap.getPixels(pixels,0,width,0,0,width,height);
                bitmap.recycle();
                var binary=new BinaryBitmap(new HybridBinarizer(new RGBLuminanceSource(width,height,pixels)));
                decoded=new MultiFormatReader().decode(binary,Map.of(DecodeHintType.POSSIBLE_FORMATS,
                        List.of(BarcodeFormat.QR_CODE),DecodeHintType.TRY_HARDER,true)).getText();
            } catch(com.google.zxing.ReaderException e) {
                ui.post(()->{if(importField==destination)destination.setError("QR-код на изображении не найден");});
                return;
            } catch(java.io.IOException | RuntimeException e) {
                ui.post(()->{if(importField==destination)destination.setError("Не удалось открыть изображение. Выбери другой файл.");});
                return;
            }
            ui.post(()->{
                if(importField==destination) {
                    destination.setError(null);
                    destination.setText(decoded);
                }
            });
        });
    }

    private void connect() {
        if(!requestTunnelStart())return;
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                && !getPreferences(MODE_PRIVATE).getBoolean("notificationAsked", false)) {
            getPreferences(MODE_PRIVATE).edit().putBoolean("notificationAsked", true).apply();
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 202);
        }
    }

    private void reconfigure() {
        if (RouteService.instance != null) requestTunnelStart();
    }

    private boolean requestTunnelStart() {
        try {
            startForegroundService(new Intent(this, RouteService.class).setAction(RouteService.CONNECT));
            return true;
        } catch(IllegalStateException | SecurityException e) {
            showMessage("Не удалось запустить VPN. Открой ProxyRoute и повтори подключение.");
            return false;
        }
    }

    private void showMessage(String message) {
        if(!isDestroyed()) Toast.makeText(this,message,Toast.LENGTH_LONG).show();
    }

    private void select(String id) {
        Config.Settings current;
        try { current=config.read(); }
        catch(Config.ReadFailure e) { showConfigError(); return; }
        if (id.equals(current.selected())) return;
        if (save(new Config.Settings(current.profiles(), id, current.rules()))) {
            reconfigure();
            render();
        }
    }

    private boolean save(Config.Settings settings) {
        try {
            config.write(settings);
            return true;
        } catch (IllegalStateException e) {
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
            return false;
        }
    }

    private void delete(Config.Profile profile) {
        new AlertDialog.Builder(this).setTitle("Удалить прокси " + profile.label() + "?")
                .setNegativeButton("Отмена", null).setPositiveButton("Удалить", (d, which) -> {
                    Config.Settings settings;
                    try { settings=config.read(); }
                    catch(Config.ReadFailure e) { showConfigError(); return; }
                    boolean active = profile.id().equals(settings.selected());
                    if (active && RouteService.instance != null) {
                        Toast.makeText(this, "Сначала выбери другой прокси или отключи VPN", Toast.LENGTH_LONG).show();
                        return;
                    }
                    List<Config.Profile> profiles = new ArrayList<>(settings.profiles());
                    profiles.remove(profile);
                    if (save(new Config.Settings(profiles, active ? Config.FIREWALL : settings.selected(), settings.rules()))) {
                        checks.remove(profile.id());
                        closePage();
                    }
                }).show();
    }

    private void checkAll() {
        try { for (Config.Profile p : config.read().profiles()) check(p, false); }
        catch(Config.ReadFailure e) { showConfigError(); }
    }

    private void check(Config.Profile p, boolean force) {
        if (!force && checks.containsKey(p.id()) && checks.get(p.id()).profile().equals(p)
                && checks.get(p.id()).detail().equals("Проверяем…")) return;
        Probe pending = new Probe(p, false, "Проверяем…");
        checks.put(p.id(), pending);
        showProbe(p);
        updateServerHeading();
        probes.execute(() -> {
            Probe finalResult=probe(p);
            ui.post(() -> {
                if (isDestroyed() || checks.get(p.id()) != pending) return;
                checks.put(p.id(),finalResult);
                showProbe(p);
                refreshVpnUi();
            });
        });
    }

    private void listen(EditText field, java.util.function.Consumer<String> change) {
        field.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s,int start,int count,int after) {}
            @Override public void onTextChanged(CharSequence s,int start,int before,int count) { change.accept(s.toString()); }
            @Override public void afterTextChanged(Editable e) {}
        });
    }

    private static String size(long bytes) {
        if (bytes < 1024) return bytes + " Б";
        String[] units = {"КиБ","МиБ","ГиБ","ТиБ","ПиБ"};
        double value = bytes/1024.0;
        int index = 0;
        while (value >= 1024 && index < units.length-1) {
            value /= 1024;
            index++;
        }
        return String.format(Locale.getDefault(),"%.1f %s",value,units[index]);
    }

    private int dp(float value) { return design.dp(value); }
    private TextView t(CharSequence text,int size,int color,int weight) { return design.text(text,size,color,weight); }
    private void add(LinearLayout parent,View child,int h,int top) { design.add(parent,child,-1,h,top); }
    private void gap(LinearLayout parent,int size) { design.gap(parent,size); }
    private FrameLayout icon(int glyph,int color,int fill,int size,int inner,int radius,String name,Runnable click) {
        return design.iconBox(glyph,color,fill,size,inner,radius,name,click);
    }
    private void ellipsize(TextView view) {
        view.setSingleLine(true);
        view.setEllipsize(TextUtils.TruncateAt.END);
    }
    private void header(String title, View right) {
        LinearLayout row=design.row();
        design.pad(row,20,0);
        TextView name=t(title,26,TEXT,600);
        name.setLetterSpacing(-.025f);
        design.weight(row,name);
        if(right!=null) row.addView(right);
        add(page,row,64,0);
    }
    private void pageHeader(String title,boolean close, View right,Runnable back) {
        LinearLayout row=design.row();
        design.pad(row,12,0);
        FrameLayout button=icon(close?R.drawable.fig_close:R.drawable.fig_chevron,LIGHT,TILE,40,20,100,
                close?"Закрыть":"Назад",back);
        if(!close) button.getChildAt(0).setRotation(180);
        row.addView(button); gap(row,12);
        TextView name=t(title,20,TEXT,600);
        ellipsize(name);
        design.weight(row,name);
        if(right!=null) row.addView(right);
        add(page,row,52,4);
    }
    private LinearLayout scrollContent(int top,int bottom) {
        ScrollView scroll=new ScrollView(this);
        scroll.setVerticalScrollBarEnabled(false);
        scroll.setClipToPadding(false);
        LinearLayout content=design.column();
        content.setFocusableInTouchMode(true);
        content.setPadding(dp(16),dp(top),dp(16),dp(bottom));
        scroll.addView(content,new ScrollView.LayoutParams(-1,-2));
        page.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        return content;
    }
    private TextView heading(String text) {
        TextView view=t(text,14,MUTED,500);
        design.pad(view,4,0);
        return view;
    }
    private LinearLayout panel(int radius) {
        LinearLayout box=design.column();
        design.surface(box,PANEL,radius);
        box.setClipToOutline(true);
        return box;
    }
    private void openPage(String name) {
        rememberFirewallPosition();
        section=name;
        render();
        animatePage(dp(22),0,220);
    }
    private void closePage() {
        if(getCurrentFocus()!=null)hideKeyboard(getCurrentFocus());
        editPage=null; returnToEdit=null; importField=null; fromLinkAction=null;
        section="";
        runningRule=null;
        render();
        getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
        animatePage(-dp(14),0,195);
    }
    private void hideKeyboard(View view) {
        getSystemService(android.view.inputmethod.InputMethodManager.class).hideSoftInputFromWindow(view.getWindowToken(),0);
    }

    private void openSettings(String action) {
        try { startActivity(new Intent(action)); }
        catch(android.content.ActivityNotFoundException | SecurityException e) {
            openActivity(new Intent(Settings.ACTION_SETTINGS),"Системные настройки недоступны");
        }
    }
    private void openActivity(Intent intent,String failure) {
        try { startActivity(intent); }
        catch(android.content.ActivityNotFoundException | SecurityException e) { showMessage(failure); }
    }

    private void servers() {
        if(searching) {
            LinearLayout searchBar=design.row();
            design.pad(searchBar,16,0);
            EditText field=searchField("Имя, адрес или протокол",query,value->{query=value; renderRows();});
            design.weight(searchBar,field);
            field.setMinimumHeight(dp(48));
            gap(searchBar,8);
            searchBar.addView(icon(R.drawable.fig_close,LIGHT,TILE,40,20,100,"Закрыть поиск",()-> {
                hideKeyboard(field);
                searching=false; query=""; render();
            }));
            add(page,searchBar,64,0);
            if(query.isEmpty()) {
                field.requestFocus();
                field.post(()->{if(field.isAttachedToWindow() && field.hasFocus())
                    getSystemService(android.view.inputmethod.InputMethodManager.class)
                            .showSoftInput(field,android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT);});
            }
        } else {
            header("Серверы",icon(R.drawable.fig_search,LIGHT,TILE,40,20,100,"Поиск серверов",()->{
                searching=true; render();
            }));
        }
        LinearLayout content=scrollContent(0,92);
        hero=design.column();
        add(content,hero,-2,0);
        LinearLayout sectionRow=design.row();
        design.pad(sectionRow,4,0);
        serverHeading=t("",14,MUTED,500);
        design.weight(sectionRow,serverHeading);
        LinearLayout verify=design.row();
        design.action(verify,0,14,0,this::checkAll);
        verify.addView(design.icon(R.drawable.fig_bolt,LIME),new LinearLayout.LayoutParams(dp(16),dp(16)));
        gap(verify,4);
        verify.addView(t("Проверить",14,LIME,500));
        sectionRow.addView(verify);
        add(content,sectionRow,26,20);
        serverRows=design.column();
        add(content,serverRows,-2,4);
        updateHero();
        renderRows();
        if(searching) return;
        FrameLayout fab=icon(R.drawable.fig_plus,BG,LIME,56,24,100,"Добавить сервер",()->edit(null));
        fab.setElevation(dp(7));
        FrameLayout.LayoutParams fabPosition=new FrameLayout.LayoutParams(dp(56),dp(56),Gravity.BOTTOM|Gravity.RIGHT);
        fabPosition.rightMargin=dp(16);
        fabPosition.bottomMargin=dp(20);
        frame.addView(fab,fabPosition);
    }
    private EditText searchField(String hint,String value,java.util.function.Consumer<String> changed) {
        EditText field=design.field(hint,value,InputType.TYPE_CLASS_TEXT);
        design.pad(field,16,0);
        field.setBackground(design.background(PANEL,100,0));
        field.setOnFocusChangeListener((v,focus)->v.setBackground(design.background(PANEL,100,focus?LIME:0)));
        listen(field,changed);
        return field;
    }
    private void updateHero() {
        if(hero==null) return;
        Config.Settings state=config.read();
        Config.Profile profile=state.active();
        RouteService.Status vpn=RouteService.status;
        boolean fallback=vpn.message().startsWith("Прямой доступ");
        boolean firewall=profile==null || fallback;
        int accent=firewall?SKY:LIME;
        boolean on=vpn.connected();
        Probe lastProbe=profile==null?null:checks.get(profile.id());
        boolean proxyFailed=on&&!fallback&&lastProbe!=null&&!lastProbe.ok()&&lastProbe.detail().startsWith("Недоступен");
        String id=(profile==null?"firewall":profile.id())+"/"+vpn.message()+"/"+on+"/"+proxyFailed;
        if(!id.equals(heroKey)) {
            boolean transition=!heroKey.isEmpty();
            heroKey=id;
            hero.removeAllViews();
            design.pad(hero,20,20);
            int fill=on?accent:PANEL;
            var surface=design.background(fill,28,0);
            hero.setBackground(surface);
            if(transition && heroColor!=fill && ValueAnimator.areAnimatorsEnabled()) {
                var color=ValueAnimator.ofArgb(heroColor,fill);
                color.setDuration(360);
                color.setInterpolator(EASE_OUT);
                color.addUpdateListener(step->surface.setColor((int)step.getAnimatedValue()));
                color.start();
            }
            heroColor=fill;
            int primary=on?BG:TEXT;
            int secondary=on?0xb309090b:MUTED;
            LinearLayout top=design.row();
            top.setGravity(Gravity.TOP);
            LinearLayout titles=design.column();
            LinearLayout stateRow=design.row();
            View dot=new View(this);
            design.surface(dot,on?BG:FAINT,100);
            stateRow.addView(dot,new LinearLayout.LayoutParams(dp(8),dp(8)));
            gap(stateRow,8);
            boolean error=vpn.message().startsWith("Ошибка");
            boolean stopping=vpn.busy() && vpn.message().startsWith("Отключение");
            TextView statusText=t(vpn.busy()?(stopping?"ОТКЛЮЧЕНИЕ":"ПОДКЛЮЧЕНИЕ"):error?"ОШИБКА VPN":proxyFailed?"ПРОКСИ НЕДОСТУПЕН":on?(firewall?"ТОЛЬКО ФИЛЬТРАЦИЯ":"ЗАЩИЩЕНО"):"ОТКЛЮЧЕНО",
                    12,error&&!on?ROSE:secondary,500);
            statusText.setLetterSpacing(.1f);
            stateRow.addView(statusText);
            titles.addView(stateRow);
            TextView heroName=t(profile==null?"Только брандмауэр":profile.label(),24,primary,600);
            ellipsize(heroName);
            add(titles,heroName,-2,8);
            TextView heroAddress=design.terminal(error||fallback?vpn.message():proxyFailed?NetworkErrors.describe(lastProbe.detail()).title():firewall?(on?"Прямое соединение · фильтры активны":"Прямое соединение · без прокси"):
                    profile.protocol().toUpperCase(Locale.ROOT)+" · "+address(profile),12,secondary);
            heroAddress.setMaxLines(2);
            add(titles,heroAddress,-2,2);
            design.weight(top,titles); gap(top,12);
            FrameLayout power=icon(R.drawable.fig_power,on?accent:BG,on?BG:LIME,64,28,100,
                    RouteService.instance==null?"Подключить VPN":"Отключить VPN",this::toggle);
            power.setEnabled(!vpn.busy());
            if(vpn.busy() || transition)power.addView(new PowerMotion(this,on?accent:BG,vpn.busy(),stopping,on),
                    new FrameLayout.LayoutParams(-1,-1));
            top.addView(power);
            hero.addView(top);
            LinearLayout metrics=design.row();
            design.pad(metrics,12,12);
            design.surface(metrics,on?0x1909090b:0x9927272a,16);
            String[] labels={"Время","Загрузка","Отдача"};
            for(int i=0;i<labels.length;i++) {
                LinearLayout stat=design.column();
                stat.addView(t(labels[i],11,secondary,400));
                sessionValues[i]=design.terminal("—",14,primary);
                add(stat,sessionValues[i],-2,2);
                design.weight(metrics,stat);
                if(i<labels.length-1) gap(metrics,8);
            }
            add(hero,metrics,-2,20);
        }
        RouteService.Session session=RouteService.session;
        long seconds=Math.max(0,(SystemClock.elapsedRealtime()-session.started)/1000);
        sessionValues[0].setText(on?String.format(Locale.ROOT,"%02d:%02d:%02d",seconds/3600,seconds/60%60,seconds%60):"—");
        sessionValues[1].setText(on?size(session.down.get()):"—");
        sessionValues[2].setText(on?size(session.up.get()):"—");
    }
    private static String address(Config.Profile p) {
        return (p.host().contains(":")?"["+p.host()+"]":p.host())+":"+p.port();
    }
    private boolean matches(String value,String text) { return value.toLowerCase(Locale.ROOT).contains(text.trim().toLowerCase(Locale.ROOT)); }
    private void renderRows() {
        if(serverRows==null) return;
        Config.Settings state=config.read();
        serverRows.removeAllViews();
        checkViews.clear();
        if(matches("Только брандмауэр direct",query)) serverRow(null,state.selected());
        for(Config.Profile profile:state.profiles()) {
            if(java.util.Arrays.stream(query.trim().toLowerCase(Locale.ROOT).split("\\s+")).allMatch(term->matches(profile.label()+" "+address(profile)+" "+profile.protocol(),term))) serverRow(profile,state.selected());
        }
        if(serverRows.getChildCount()==0) {
            TextView empty=t("Ничего не найдено по запросу «"+query+"»",14,FAINT,400);
            empty.setGravity(Gravity.CENTER);
            add(serverRows,empty,100,0);
        }
        updateServerHeading();
    }
    private void serverRow(Config.Profile profile,String selection) {
        boolean fw=profile==null;
        String id=fw?Config.FIREWALL:profile.id();
        boolean selected=id.equals(selection);
        LinearLayout row=design.row();
        design.pad(row,12,12);
        design.action(row,selected?(fw?0x1a00bcff:0x1abbf451):PANEL,16,selected?(fw?0x9900bcff:0x99bbf451):0,()->select(id));
        if(fw) row.addView(icon(R.drawable.fig_firewall,BG,SKY,44,24,12,null,null));
        else {
            String name=profile.label();
            String letters=name.substring(0,name.offsetByCodePoints(0,Math.min(2,name.codePointCount(0,name.length())))).toUpperCase(Locale.ROOT);
            TextView stamp=design.terminal(letters,14,LIGHT);
            stamp.setGravity(Gravity.CENTER);
            design.surface(stamp,TILE,12);
            row.addView(stamp,new LinearLayout.LayoutParams(dp(44),dp(44)));
            row.setOnLongClickListener(v->{edit(profile); return true;});
        }
        gap(row,12);
        LinearLayout info=design.column();
        TextView name=t(fw?"Только брандмауэр":profile.label(),16,TEXT,500);
        ellipsize(name); info.addView(name);
        LinearLayout detail=design.row();
        String protocol=fw?"DIRECT":profile.protocol().toUpperCase(Locale.ROOT);
        LinearLayout badge=design.row();
        design.pad(badge,6,2); design.surface(badge,fw?0x2600bcff:TILE,4);
        if(!fw&&!profile.secret().isEmpty()) {
            badge.addView(design.icon(R.drawable.fig_lock,LIGHT),new LinearLayout.LayoutParams(dp(12),dp(12)));
            gap(badge,4);
        }
        badge.addView(t(protocol,12,fw?0xff7cd3ff:LIGHT,500));
        detail.addView(badge); gap(detail,8);
        TextView host=fw?t("Без прокси · только фильтры",12,FAINT,400):design.terminal(address(profile),12,FAINT);
        ellipsize(host); design.weight(detail,host);
        add(info,detail,-2,2); design.weight(row,info); gap(row,8);
        if(fw) row.addView(design.pill("Встроенный",11,LIGHT,TILE,24,null));
        else {
            TextView check=design.terminal("",12,FAINT);
            row.addView(check);
            checkViews.put(id,check);
            showProbe(profile);
            FrameLayout edit=icon(R.drawable.fig_chevron,FAINT,0,26,14,100,"Настроить "+profile.label(),()->edit(profile));
            row.addView(edit);
        }
        add(serverRows,row,-2,serverRows.getChildCount()==0?0:8);
    }
    private void updateServerHeading() {
        if(serverHeading==null || tab!=0 || !section.isEmpty()) return;
        boolean pending=checks.values().stream().anyMatch(probe->probe.detail().equals("Проверяем…"));
        serverHeading.setText(pending?"Проверка статуса…":"Серверы · "+(config.read().profiles().size()+1));
    }
    private void showProbe(Config.Profile p) {
        TextView view=checkViews.get(p.id());
        if(view!=null) {
            Probe probe=checks.get(p.id());
            view.setOnClickListener(null); view.setClickable(false);
            if(probe==null || !probe.profile().equals(p)) { view.setText("—"); view.setTextColor(FAINT); }
            else if(probe.detail().equals("Проверяем…")) { view.setText("···"); view.setTextColor(MUTED); }
            else if(!probe.ok()) {
                view.setText("Офлайн");
                view.setTextColor(ROSE);
                view.setOnClickListener(v->showNetworkError(probe.detail(),()->check(p,true)));
            }
            else {
                String value=probe.detail().replace("Доступен · ","");
                long ms=Long.parseLong(value.replace(" мс",""));
                view.setText(value);
                view.setTextColor(ms<70?LIME:ms<150?AMBER:ROSE);
            }
            if(probe!=null) view.setContentDescription(probe.ok()?probe.detail():NetworkErrors.describe(probe.detail()).title());
        }
        updateServerHeading();
    }

    private void showNetworkError(String error,Runnable retry) {
        NetworkErrors.Detail detail=NetworkErrors.describe(error);
        new AlertDialog.Builder(this).setTitle(detail.title()).setMessage(detail.hint()+"\nКод: "+detail.code())
                .setNegativeButton("Закрыть",null).setPositiveButton("Повторить",(dialog,which)->retry.run()).show();
    }

    private void fieldGroup(LinearLayout parent,String label,View field,int height,int top) {
        TextView caption=t(label,12,MUTED,500);
        design.pad(caption,4,0);
        add(parent,caption,-2,top);
        add(parent,field,height,6);
    }
    private LinearLayout segment(String[] labels,int selected,java.util.function.IntConsumer change,int height) {
        LinearLayout row=design.row();
        design.pad(row,4,4);
        design.surface(row,TILE,100);
        for(int i=0;i<labels.length;i++) {
            int index=i;
            TextView view=design.pill(labels[i],height>40?14:12,i==selected?BG:MUTED,i==selected?LIME:0,height,()->change.accept(index));
            design.weight(row,view);
            if(i<labels.length-1) gap(row,4);
        }
        return row;
    }
    private void edit(Config.Profile previous) {
        edit(previous,null);
    }
    private void edit(Config.Profile previous,String localHost) {
        section="edit";
        hero=null;
        activeApps=null;
        checkViews.clear();
        frame.removeAllViews(); nav.setVisibility(View.GONE);
        page=design.column();
        frame.addView(page,new FrameLayout.LayoutParams(-1,-1));
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        animatePage(0,dp(22),230);
        LinearLayout fromLink=design.row();
        design.pad(fromLink,14,0);
        design.surface(fromLink,TILE,100);
        fromLink.addView(design.icon(R.drawable.fig_link,LIME),new LinearLayout.LayoutParams(dp(16),dp(16)));
        gap(fromLink,6);
        fromLink.addView(t("Из ссылки",14,LIME,500));
        fromLink.setMinimumHeight(dp(40));
        LinearLayout actions=design.row();
        actions.addView(fromLink);
        gap(actions,6);
        FrameLayout qr=icon(R.drawable.fig_qr,LIME,TILE,40,20,100,null,null);
        qr.setContentDescription("QR-код подключения");
        actions.addView(qr);
        pageHeader(previous==null?"Новый сервер":"Настройки сервера",true,actions,this::closePage);
        LinearLayout body=scrollContent(8,24);
        int[] protocol={previous==null?2:java.util.Arrays.asList(PROTOCOLS).indexOf(previous.protocol())};
        String[] ports={"8080","443","1080"};
        EditText name=design.field("Например, Frankfurt-02",previous==null?"":previous.title(),InputType.TYPE_CLASS_TEXT);
        EditText host=design.field("proxy.example.com",previous==null?(localHost==null?"":localHost):previous.host(),InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_URI);
        EditText port=design.field("Порт",previous==null?ports[protocol[0]]:Integer.toString(previous.port()),InputType.TYPE_CLASS_NUMBER);
        host.setTypeface(getResources().getFont(R.font.jetbrains_mono));
        port.setTypeface(getResources().getFont(R.font.jetbrains_mono));
        LinearLayout protocolBox=design.column();
        add(body,protocolBox,-2,0);
        Runnable[] fillProtocol=new Runnable[1];
        fillProtocol[0]=()-> {
            protocolBox.removeAllViews();
            LinearLayout choices=segment(new String[]{"HTTP","HTTPS","SOCKS5"},protocol[0],choice-> {
                protocol[0]=choice; port.setText(ports[choice]); fillProtocol[0].run();
            },44);
            fieldGroup(protocolBox,"Протокол",choices,-2,0);
        };
        fillProtocol[0].run();
        fieldGroup(body,"Название",name,56,20);
        LinearLayout endpoints=design.row();
        LinearLayout hostField=design.column(),portField=design.column();
        fieldGroup(hostField,"Адрес сервера",host,56,0);
        fieldGroup(portField,"Порт",port,56,0);
        design.weight(endpoints,hostField); gap(endpoints,12);
        endpoints.addView(portField,new LinearLayout.LayoutParams(dp(112),-2));
        add(body,endpoints,-2,20);

        Config.Credentials credentials;
        boolean unreadableCredentials;
        try { credentials=Config.credentials(previous); unreadableCredentials=false; }
        catch(Config.CredentialsFailure e) { credentials=new Config.Credentials("",""); unreadableCredentials=true; }
        boolean[] auth={previous==null||!previous.secret().isEmpty()};
        EditText user=design.field("Логин",credentials.user(),InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        EditText pass=design.field("Пароль",credentials.password(),InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);
        LinearLayout authCard=panel(24);
        design.pad(authCard,16,16);
        LinearLayout authRow=design.row();
        authRow.addView(icon(R.drawable.fig_lock,LIME,TILE,40,20,12,null,null)); gap(authRow,12);
        LinearLayout names=design.column(); names.addView(t("Авторизация",14,TEXT,500)); add(names,t("Логин и пароль прокси",12,FAINT,400),-2,2);
        design.weight(authRow,names);
        LinearLayout switchBox=design.row();
        authRow.addView(switchBox);
        authCard.addView(authRow);
        LinearLayout inputs=design.column();
        add(inputs,user,48,0);
        FrameLayout password=new FrameLayout(this);
        pass.setPadding(dp(16),0,dp(44),0);
        password.addView(pass,new FrameLayout.LayoutParams(-1,-1));
        FrameLayout eye=icon(R.drawable.fig_eye,FAINT,0,40,20,100,"Показать или скрыть пароль",()-> {
            pass.setTransformationMethod(pass.getTransformationMethod()==null?PasswordTransformationMethod.getInstance():null);
            pass.setSelection(pass.length());
        });
        password.addView(eye,new FrameLayout.LayoutParams(dp(40),-1,Gravity.RIGHT));
        add(inputs,password,48,12);
        add(authCard,inputs,-2,16);
        FigmaUi.Toggle authToggle=design.toggle("Авторизация",auth[0],null);
        Runnable refreshAuth=()-> {
            inputs.setVisibility(auth[0]?View.VISIBLE:View.GONE);
            authToggle.setChecked(auth[0]);
        };
        authToggle.setAction(()->{auth[0]=!auth[0]; refreshAuth.run();});
        switchBox.addView(authToggle);
        refreshAuth.run();
        add(body,authCard,-2,20);

        LinearLayout verify=design.row();
        verify.setBackground(design.background(PANEL,16,TILE));
        design.pad(verify,14,14);
        verify.addView(icon(R.drawable.fig_bolt,MUTED,TILE,40,20,12,null,null)); gap(verify,12);
        LinearLayout copy=design.column();
        TextView testState=t("Проверка соединения",14,TEXT,500);
        TextView testDetail=t("Подключение и авторизация",12,FAINT,400);
        copy.addView(testState); add(copy,testDetail,-2,2); design.weight(verify,copy);
        TextView error=t("",13,ROSE,400);
        error.setVisibility(View.GONE);
        java.util.function.Consumer<String> showError=message->{ error.setText(message); error.setVisibility(View.VISIBLE); };
        if(unreadableCredentials) showError.accept("Не удалось открыть сохранённый логин и пароль. Введи их заново.");
        final boolean needsCredentials=unreadableCredentials;
        java.util.concurrent.Callable<Config.Profile> profile=()-> {
            if(needsCredentials && auth[0] && user.length()==0 && pass.length()==0)
                throw new IllegalArgumentException("Введи данные для входа заново или отключи авторизацию.");
            return Config.create(previous,name.getText().toString(),PROTOCOLS[protocol[0]],
                    host.getText().toString(),Integer.parseInt(port.getText().toString()),
                    auth[0]?user.getText().toString():"",auth[0]?pass.getText().toString():"");
        };
        design.action(qr,TILE,100,0,()->{
            try {
                boolean encrypted=auth[0] && (user.length()>0 || pass.length()>0);
                Config.Profile endpoint=profile.call();
                showShareCode(endpoint,encrypted);
            } catch(NumberFormatException e) { showError.accept("Укажи порт от 1 до 65535"); }
            catch(IllegalArgumentException e) { showError.accept(e.getMessage()); }
            catch(Exception e) { showError.accept("Не удалось подготовить профиль для QR-кода"); }
        });
        TextView test=design.pill("Тест",14,LIME,TILE,36,null);
        design.action(test,TILE,100,0,()-> {
            Config.Profile candidate;
            try { candidate=profile.call(); }
            catch(NumberFormatException e) { showError.accept("Укажи порт от 1 до 65535"); return; }
            catch(IllegalArgumentException e) { showError.accept(e.getMessage()); return; }
            catch(Exception e) { showError.accept("Проверь адрес, порт и данные авторизации"); return; }
            error.setVisibility(View.GONE);
            test.setEnabled(false);
            testState.setText("Проверка соединения…");
            testDetail.setText("Подключение и авторизация");
            probes.execute(()->{
                Probe result=probe(candidate);
                ui.post(()->{
                    if(isDestroyed()||!test.isAttachedToWindow()) return;
                    test.setEnabled(true);
                    testState.setText(result.ok()?"Сервер доступен":"Сервер недоступен");
                    testDetail.setText(result.ok()?result.detail():NetworkErrors.describe(result.detail()).title());
                    if(!result.ok())showError.accept(NetworkErrors.describe(result.detail()).hint());
                    verify.setBackground(design.background(result.ok()?0x1abbf451:PANEL,16,result.ok()?0x80bbf451:TILE));
                });
            });
        });
        verify.addView(test);
        add(body,verify,-2,20);
        add(body,error,-2,10);

        LinearLayout footer=design.column();
        design.pad(footer,16,12);
        TextView save=design.pill("Сохранить сервер",16,BG,LIME,56,()->{
            try {
                Config.Profile next=profile.call();
                Config.Settings settings=config.read();
                List<Config.Profile> profiles=new ArrayList<>(settings.profiles());
                if(previous==null) profiles.add(next);
                else {
                    int index=profiles.indexOf(previous);
                    if(index<0) {showError.accept("Профиль изменился. Открой его из списка серверов заново."); return;}
                    profiles.set(index,next);
                }
                String selected=settings.profiles().isEmpty()?next.id():settings.selected();
                if(save(new Config.Settings(profiles,selected,settings.rules()))) {
                    if(selected.equals(next.id())) reconfigure();
                    check(next,true); closePage();
                }
            } catch(NumberFormatException e) { showError.accept("Укажи порт от 1 до 65535"); }
            catch(IllegalArgumentException e) { showError.accept(e.getMessage()); }
            catch(Config.ReadFailure e) { showError.accept(e.getMessage()); }
            catch(Exception e) { showError.accept("Не удалось сохранить профиль"); }
        });
        add(footer,save,56,0);
        if(previous!=null) add(footer,design.pill("Удалить сервер",14,ROSE,PANEL,40,()->delete(previous)),40,8);
        add(page,footer,-2,0);
        fromLinkAction=()->importPage((parsed,choice)-> {
            protocol[0]=choice;
            fillProtocol[0].run();
            host.setText(parsed.host());
            port.setText(Integer.toString(parsed.port()));
            user.setText(parsed.user());
            pass.setText(parsed.password());
            auth[0]=!parsed.user().isEmpty() || !parsed.password().isEmpty();
            refreshAuth.run();
        });
        design.action(fromLink,TILE,100,0,fromLinkAction);
    }

    private void showShareCode(Config.Profile endpoint,boolean encrypted) {
        LinearLayout editor=page;
        appLoader.execute(()->{
            try {
                Config.Credentials auth=Config.credentials(endpoint);
                String link=ProxyShare.create(new ProxyLink(endpoint.protocol(),endpoint.host(),endpoint.port(),
                        auth.user(),auth.password()),encrypted);
                var logo=getDrawable(R.drawable.ic_launcher_foreground);
                Bitmap bitmap=ShareQr.render(link,logo);
                ui.post(()->{
                    if(page!=editor || !section.equals("edit") || isDestroyed()) {
                        bitmap.recycle();
                        return;
                    }
                    renderShareCode(endpoint,encrypted,link,bitmap);
                });
            } catch(Exception e) {
                ui.post(()->{
                    if(page==editor && section.equals("edit") && !isDestroyed())
                        Toast.makeText(this,e instanceof IllegalArgumentException?e.getMessage():
                                "Не удалось создать читаемый QR-код. Проверь длину данных сервера.",Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void renderShareCode(Config.Profile endpoint,boolean encrypted,String link,Bitmap bitmap) {
        openEditorScreen("qr");
        pageHeader("QR-код подключения",false,null,()->returnToEdit.run());
        LinearLayout body=scrollContent(12,20);
        LinearLayout card=panel(28);
        design.pad(card,18,18);
        LinearLayout titleRow=design.row();
        titleRow.addView(icon(encrypted?R.drawable.fig_lock:R.drawable.fig_servers,LIME,TILE,40,20,12,null,null));
        gap(titleRow,12);
        LinearLayout labels=design.column();
        String protocol=endpoint.protocol().toUpperCase(Locale.ROOT);
        TextView title=t(endpoint.title().isEmpty()?protocol:endpoint.title(),17,TEXT,600);
        ellipsize(title);
        add(labels,title,-2,0);
        String host=endpoint.host().contains(":")?"["+endpoint.host()+"]":endpoint.host();
        TextView address=design.terminal(host+":"+endpoint.port(),12,MUTED);
        ellipsize(address);
        add(labels,address,-2,4);
        design.weight(titleRow,labels);
        gap(titleRow,8);
        titleRow.addView(design.pill(protocol,11,LIME,TILE,28,null));
        add(card,titleRow,-2,0);

        ImageView image=new ImageView(this);
        image.setAdjustViewBounds(true);
        image.setImageBitmap(bitmap);
        image.setScaleType(ImageView.ScaleType.FIT_CENTER);
        if(image.getDrawable() instanceof android.graphics.drawable.BitmapDrawable d) d.setFilterBitmap(false);
        image.setContentDescription("QR-код подключения");
        FrameLayout plate=new FrameLayout(this);
        design.surface(plate,Color.WHITE,22);
        plate.setClipToOutline(true);
        int qrSide=Math.min(320,Math.max(1,getResources().getConfiguration().screenWidthDp-68));
        plate.addView(image,new FrameLayout.LayoutParams(-1,-1));
        LinearLayout.LayoutParams plateLayout=new LinearLayout.LayoutParams(dp(qrSide),dp(qrSide));
        plateLayout.gravity=Gravity.CENTER_HORIZONTAL;
        plateLayout.topMargin=dp(18);
        card.addView(plate,plateLayout);
        add(body,card,-2,0);

        LinearLayout guide=panel(22);
        design.pad(guide,16,14);
        add(guide,t(encrypted?"Содержит данные для входа":"Профиль без авторизации",14,TEXT,600),-2,0);
        add(guide,t(encrypted?"QR и ссылка дают доступ к прокси. Отправляй их только тем, с кем хочешь поделиться доступом."
                :"Отсканируй QR или открой ссылку, чтобы заполнить профиль в ProxyRoute.",13,MUTED,400),-2,6);
        add(body,guide,-2,14);
        add(body,design.pill("Скопировать ссылку",15,BG,LIME,52,
                ()->copyShareValue(link,encrypted)),52,16);
        animatePage(dp(20),0,220);
    }

    private void copyShareValue(String value,boolean sensitive) {
        ClipData clip=ClipData.newPlainText("ProxyRoute",value);
        if(sensitive) {
            android.os.PersistableBundle extras=new android.os.PersistableBundle();
            extras.putBoolean("android.content.extra.IS_SENSITIVE",true);
            clip.getDescription().setExtras(extras);
        }
        getSystemService(ClipboardManager.class).setPrimaryClip(clip);
        if(Build.VERSION.SDK_INT<33) Toast.makeText(this,"Скопировано",Toast.LENGTH_SHORT).show();
    }

    private void openEditorScreen(String screen) {
        if(getCurrentFocus()!=null)hideKeyboard(getCurrentFocus());
        editPage=page;
        section=screen;
        returnToEdit=()->{
            if(getCurrentFocus()!=null)hideKeyboard(getCurrentFocus());
            frame.removeAllViews();
            page=editPage;
            editPage=null; returnToEdit=null; importField=null;
            section="edit";
            frame.addView(page,new FrameLayout.LayoutParams(-1,-1));
            animatePage(-dp(14),0,180);
        };
        frame.removeAllViews();
        page=design.column();
        frame.addView(page,new FrameLayout.LayoutParams(-1,-1));
    }

    private void importPage(java.util.function.BiConsumer<ProxyLink,Integer> apply) {
        openEditorScreen("import");
        pageHeader("Импорт прокси",false,null,()->returnToEdit.run());
        LinearLayout body=scrollContent(10,20);
        LinearLayout help=panel(24);
        design.pad(help,16,16);
        add(help,t("Поддерживаемые форматы",16,TEXT,600),-2,0);
        for(String example:new String[]{"proxyroute://import/v1?…","socks5://логин:пароль@ip:порт","ip:port:login:password","ip:port@login:password"})
            add(help,design.terminal(example,12,LIGHT),-2,8);
        add(help,t("Если в ссылке нет протокола, выбери его вручную. Для IPv6 заключи адрес в квадратные скобки.",13,MUTED,400),-2,10);
        add(body,help,-2,0);
        EditText link=design.field("Вставь ссылку или адрес прокси","",InputType.TYPE_CLASS_TEXT
                |InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD|InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        importField=link;
        add(body,link,56,20);
        add(body,design.pill("Вставить из буфера",14,LIME,TILE,42,()->{
            var clipboard=getSystemService(android.content.ClipboardManager.class);
            var clip=clipboard==null?null:clipboard.getPrimaryClip();
            if(clip!=null && clip.getItemCount()>0 && clip.getItemAt(0).getText()!=null)
                link.setText(clip.getItemAt(0).getText());
            else link.setError("В буфере нет текста");
        }),42,8);
        add(body,design.pill("Открыть QR из изображения",14,LIME,TILE,42,()->{
            Intent picker=new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("image/*").addCategory(Intent.CATEGORY_OPENABLE);
            try { startActivityForResult(picker,QR_IMAGE_REQUEST); }
            catch(android.content.ActivityNotFoundException | SecurityException e) { link.setError("Не удалось открыть выбор изображения"); }
        }),42,8);
        EditText key=design.field("Отдельный ключ", "", InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);
        key.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        add(body,key,48,12);
        key.setVisibility(View.GONE);
        LinearLayout choices=design.column();
        add(body,choices,-2,16);
        TextView feedback=t("",13,MUTED,400);
        add(body,feedback,-2,10);
        int[] chosen={-1};
        ProxyLink[] parsed={null};
        ProxyShare.Import[] protectedLink={null};
        LinearLayout footer=design.column();
        design.pad(footer,16,12);
        TextView use=design.pill("Заполнить профиль",16,BG,LIME,56,()->{
            if(protectedLink[0]!=null) {
                try {
                    ProxyLink opened=protectedLink[0].open(key.getText().toString());
                    apply.accept(opened,Arrays.asList(PROTOCOLS).indexOf(opened.protocol()));
                    returnToEdit.run();
                } catch(IllegalArgumentException e) { key.setError(e.getMessage()); }
                return;
            }
            if(parsed[0]==null || chosen[0]<0)return;
            apply.accept(parsed[0],chosen[0]);
            returnToEdit.run();
        });
        add(footer,use,56,0);
        add(page,footer,-2,0);
        Runnable[] renderChoices=new Runnable[1];
        renderChoices[0]=()-> {
            choices.removeAllViews();
            if(parsed[0]!=null && parsed[0].protocol()==null)
                fieldGroup(choices,"Протокол",segment(new String[]{"HTTP","HTTPS","SOCKS5"},chosen[0],index-> {
                    chosen[0]=index; renderChoices[0].run();
                },44),-2,0);
            boolean ready=(parsed[0]!=null && chosen[0]>=0) || (protectedLink[0]!=null && key.length()>0);
            use.setEnabled(ready);
            use.setAlpha(ready?1f:.45f);
        };
        listen(link,value-> {
            chosen[0]=-1;
            parsed[0]=null;
            protectedLink[0]=null;
            key.setText("");
            key.setVisibility(View.GONE);
            key.setError(null);
            try {
                if(ProxyShare.matches(value)) {
                    ProxyShare.Import incoming=ProxyShare.parse(value);
                    if(incoming.encrypted()) {
                        protectedLink[0]=incoming;
                        key.setVisibility(View.VISIBLE);
                        feedback.setTextColor(MUTED);
                        feedback.setText("Введи ключ, полученный отдельно от ссылки");
                        renderChoices[0].run();
                        return;
                    }
                    parsed[0]=incoming.open("");
                } else parsed[0]=ProxyLink.parse(value);
                String protocol=parsed[0].protocol();
                if(protocol!=null)chosen[0]=Arrays.asList(PROTOCOLS).indexOf(protocol);
                feedback.setTextColor(MUTED);
                feedback.setText(protocol==null?"Выбери протокол прокси":"Определён протокол "+protocol.toUpperCase(Locale.ROOT));
            } catch(IllegalArgumentException e) {
                parsed[0]=null;
                feedback.setTextColor(ROSE);
                feedback.setText(value.trim().isEmpty()?"":e.getMessage());
            }
            renderChoices[0].run();
        });
        listen(key,value->renderChoices[0].run());
        renderChoices[0].run();
        animatePage(dp(20),0,200);
    }

    private Probe probe(Config.Profile p) {
        try {
            Config.Credentials auth=Config.credentials(p);
            Exception failure=null;
            for(String ip:Config.addresses(this,p.host())) {
                try {
                    long latency=Tunnel.check(new RouteService.ProbeHooks(),p.protocol(),p.host(),ip,p.port(),auth.user(),auth.password());
                    return new Probe(p,true,"Доступен · "+latency+" мс");
                } catch(Exception e) { failure=e; }
            }
            if(failure!=null) throw failure;
            throw new IllegalStateException("Нет ответа");
        } catch(Exception | LinkageError e) {
            if(e instanceof Config.CredentialsFailure) return new Probe(p,false,"credentials_read");
            if(e instanceof LinkageError) return new Probe(p,false,"native_start");
            return new Probe(p,false,"Недоступен · "+(e.getMessage()==null?e.getClass().getSimpleName():e.getMessage()));
        }
    }

    private void journal() {
        LinearLayout actions=design.row();
        actions.addView(icon(R.drawable.fig_down,LIME,TILE,40,20,100,"Выгрузить журнал",()->{
            Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.putExtra(Intent.EXTRA_TITLE,"ProxyRoute-"+java.time.LocalDate.now()+".json");
            try { startActivityForResult(intent,EXPORT_REQUEST); }
            catch(android.content.ActivityNotFoundException | SecurityException e) { showMessage("Не удалось открыть выбор папки для экспорта"); }
        }));
        gap(actions,8);
        actions.addView(icon(R.drawable.fig_trash,LIGHT,TILE,40,20,100,"Очистить журнал",this::confirmClear));
        header("Журнал",actions);
        LinearLayout filters=design.row();
        design.pad(filters,16,0);
        String[] captions={"Все","Прокси","Блок","Ошибки"};
        for(int i=0;i<captions.length;i++) {
            int index=i;
            filters.addView(design.pill(captions[i],14,i==filter?BG:LIGHT,i==filter?LIME:PANEL,36,()->{
                if(filter==index) return;
                filter=index; offset=0; render();
            }));
            gap(filters,8);
        }
        filters.addView(icon(searchingHistory?R.drawable.fig_close:R.drawable.fig_search,LIGHT,PANEL,36,18,100,
                searchingHistory?"Закрыть поиск":"Поиск в журнале",()-> {
                    searchingHistory=!searchingHistory;
                    if(!searchingHistory) { eventQuery=""; offset=0; }
                    render();
                }));
        android.widget.HorizontalScrollView horizontal=new android.widget.HorizontalScrollView(this);
        horizontal.setHorizontalScrollBarEnabled(false);
        horizontal.addView(filters);
        add(page,horizontal,36,0);
        if(searchingHistory) {
            LinearLayout queryRow=design.column();
            design.pad(queryRow,16,0);
            EditText search=searchField("Приложение или адрес",eventQuery,value->{eventQuery=value; offset=0; loadHistory(true);});
            add(queryRow,search,44,0);
            add(page,queryRow,44,8);
        }
        LinearLayout body=design.column();
        LinearLayout graph=panel(24);
        design.pad(graph,16,16);
        LinearLayout head=design.row(); head.setGravity(Gravity.TOP);
        LinearLayout total=design.column();
        total.addView(t(chartPeriod==0?"Трафик за сутки":"Трафик за неделю",12,FAINT,400));
        graphTotal=design.terminal("0 Б",24,TEXT);
        add(total,graphTotal,-2,3);
        design.weight(head,total);
        LinearLayout period=design.row(); design.pad(period,4,4); design.surface(period,TILE,100);
        for(int i=0;i<2;i++) {
            int index=i;
            period.addView(design.pill(i==0?"День":"Неделя",12,chartPeriod==i?BG:MUTED,chartPeriod==i?LIME:0,28,()-> {
                if(chartPeriod==index) return;
                chartPeriod=index; render();
            }));
            if(i==0) gap(period,4);
        }
        head.addView(period); graph.addView(head);
        chart=new ChartView();
        add(graph,chart,133,16);
        LinearLayout legend=design.row();
        legend(legend,"Загрузка",LIME); gap(legend,16); legend(legend,"Отдача",SKY);
        add(graph,legend,-2,10);
        add(body,graph,-2,0);
        stats=design.row();
        add(body,stats,-2,8);
        LinearLayout paging=design.row();
        design.weight(paging,design.pill("← Новее",12,LIME,PANEL,36,()-> {
            if(offset>0) {offset=Math.max(0,offset-100); loadHistory(true);}
        }));
        gap(paging,8);
        design.weight(paging,design.pill("Старее →",12,LIME,PANEL,36,()-> {
            if(displayedReport!=null && displayedReport.rows().size()==100) {offset+=100; loadHistory(true);}
        }));
        ListView log=new ListView(this);
        log.setVerticalScrollBarEnabled(false);
        log.setPadding(dp(16),dp(12),dp(16),dp(12));
        log.setDivider(new android.graphics.drawable.ColorDrawable(BG));
        log.setDividerHeight(dp(1));
        gap(body,12);
        log.addHeaderView(body,null,false);
        log.addFooterView(paging,null,false);
        journalAdapter=new JournalAdapter();
        log.setAdapter(journalAdapter);
        page.addView(log,new LinearLayout.LayoutParams(-1,0,1));
        loadHistory(true);
    }
    private void legend(LinearLayout row,String label,int color) {
        View dot=new View(this);
        design.surface(dot,color,12);
        row.addView(dot,new LinearLayout.LayoutParams(dp(8),dp(8)));
        gap(row,6);
        row.addView(t(label,12,MUTED,400));
    }
    private void confirmClear() {
        android.app.Dialog dialog=new android.app.Dialog(this);
        LinearLayout body=panel(28);
        design.pad(body,24,24);
        body.addView(icon(R.drawable.fig_trash,ROSE,0x26ff2056,48,24,100,null,null));
        add(body,t("Очистить журнал?",20,TEXT,600),-2,16);
        add(body,t("Записи о соединениях будут удалены. График трафика сохранится.",14,MUTED,400),-2,8);
        LinearLayout options=design.row(); options.setGravity(Gravity.RIGHT);
        options.addView(design.pill("Отмена",14,LIGHT,0,44,dialog::dismiss)); gap(options,8);
        options.addView(design.pill("Очистить",14,TEXT,RED,44,()-> {
            dialog.dismiss();
            history.clear(()->ui.post(()->{offset=0; loadHistory(true);}),
                    ()->ui.post(()->showMessage("Не удалось очистить журнал. Повтори попытку позже.")));
        }));
        add(body,options,-2,24);
        dialog.setContentView(body);
        dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        dialog.getWindow().setDimAmount(.7f);
        dialog.show();
        dialog.getWindow().setLayout(Math.min(getResources().getDisplayMetrics().widthPixels-dp(64),dp(420)),-2);
    }
    private long journalRequest;
    private void loadHistory(boolean force) {
        if(tab!=1 || chart==null || isDestroyed()) return;
        long revision=history.revision();
        if(!force&&(loadingJournal||lastHistoryRevision==revision||SystemClock.elapsedRealtime()<retryJournalAt))return;
        int version=screenVersion, period=chartPeriod, selection=filter, currentOffset=offset;
        String search=eventQuery;
        String key=period+"/"+selection+"/"+currentOffset+"/"+search;
        CachedReport cached=journalCache.get(key);
        if(displayedReport==null && cached!=null)applyReport(cached.report());
        if(cached!=null && cached.revision()==revision
                && cached.report()==displayedReport) {
            ++journalRequest;
            loadingJournal=false; lastHistoryRevision=revision;
            return;
        }
        long request=++journalRequest;
        loadingJournal=true;
        data.execute(()->{
            try {
                java.time.ZonedDateTime now=java.time.ZonedDateTime.now();
                var start=now.toLocalDate().atStartOfDay(now.getZone());
                long base=(period==0?start:start.minusDays(6)).toEpochSecond()/60;
                int span=period==0?180:1440;
                Report report=new Report(history.chartFrom(base,span,period==0?8:7),history.totals(0),
                        history.recent(FILTERS[selection],search,currentOffset),base,span);
                ui.post(()->{
                    if(isDestroyed()||screenVersion!=version||request!=journalRequest)return;
                    loadingJournal=false; lastHistoryRevision=revision;
                    retryJournalAt=0;
                    journalCache.put(key,new CachedReport(revision,report));
                    if(journalCache.size()>8)journalCache.remove(journalCache.keySet().iterator().next());
                    applyReport(report);
                });
            } catch(RuntimeException e) {
                android.util.Log.e("ProxyRoute","Could not read history",e);
                ui.post(()->{
                    if(!isDestroyed() && journalAdapter!=null && screenVersion==version && request==journalRequest) {
                        loadingJournal=false;
                        retryJournalAt=SystemClock.elapsedRealtime()+5000;
                        journalAdapter.error=true;
                        journalAdapter.notifyDataSetChanged();
                    }
                });
            }
        });
    }
    private void applyReport(Report report) {
        if(chart==null)return;
        Report previous=displayedReport;
        displayedReport=report;
        graphTotal.setText(size(report.graph().totalUp()+report.graph().totalDown()));
        chart.show(report);
        if(previous==null || !previous.totals().equals(report.totals())) {
            stats.removeAllViews();
            String[] captions={"Запросов","Заблок.","Ошибок"};
            long[] values={report.totals().all(),report.totals().blocked(),report.totals().errors()};
            for(int i=0;i<captions.length;i++) {
                LinearLayout metric=panel(16);
                design.pad(metric,12,12);
                metric.addView(t(captions[i],11,FAINT,400));
                add(metric,design.terminal(Long.toString(values[i]),18,TEXT),-2,2);
                design.weight(stats,metric); if(i<2)gap(stats,8);
            }
        }
        if(previous!=null && !journalAdapter.error && previous.rows().equals(report.rows())
                && (previous.totals().all()==0)==(report.totals().all()==0))return;
        journalAdapter.error=false;
        journalAdapter.notifyDataSetChanged();
    }

    private final class JournalAdapter extends BaseAdapter {
        private final DateFormat time=DateFormat.getTimeInstance(DateFormat.MEDIUM,new Locale("ru","RU"));
        private boolean error;
        @Override public int getCount() { return displayedReport==null?1:Math.max(1,displayedReport.rows().size()); }
        @Override public History.Connection getItem(int position) {
            return displayedReport==null||displayedReport.rows().isEmpty()?null:displayedReport.rows().get(position);
        }
        @Override public long getItemId(int position) { return position; }
        @Override public int getViewTypeCount() { return 2; }
        @Override public int getItemViewType(int position) { return getItem(position)==null?0:1; }
        @Override public View getView(int position,View recycled,ViewGroup parent) {
            History.Connection event=getItem(position);
            if(event==null) {
                TextView empty=recycled==null?t("",14,FAINT,400):(TextView)recycled;
                empty.setText(error?"Не удалось загрузить журнал":displayedReport==null?"Загрузка журнала…":
                        displayedReport.totals().all()==0?"Журнал пуст":"Подключения не найдены");
                empty.setGravity(Gravity.CENTER);
                empty.setMinimumHeight(dp(64));
                return empty;
            }
            JournalRow row=recycled==null?new JournalRow():(JournalRow)recycled;
            row.bind(event);
            return row;
        }
        private final class JournalRow extends LinearLayout {
            private final View dot;
            private final TextView title,subtitle,stamp;
            private History.Connection event;
            JournalRow() {
                super(MainActivity.this);
                setGravity(Gravity.CENTER_VERTICAL);
                design.pad(this,14,12);
                dot=new View(MainActivity.this);
                addView(dot,new LinearLayout.LayoutParams(dp(8),dp(8)));
                gap(this,12);
                LinearLayout copy=design.column();
                title=t("",14,TEXT,400);
                subtitle=t("",12,FAINT,400);
                ellipsize(title); ellipsize(subtitle);
                copy.addView(title);
                add(copy,subtitle,-2,2);
                design.weight(this,copy);
                gap(this,8);
                stamp=design.terminal("",11,FAINT);
                addView(stamp);
                design.action(this,PANEL,12,0,()->showLogEntry(event));
                setFocusable(false);
            }
            void bind(History.Connection item) {
                event=item;
                boolean block=Config.BLOCK.equals(item.route());
                boolean failed=NetworkErrors.failed(item.result());
                design.surface(dot,block?PINK:failed?RED:Config.PROXY.equals(item.route())?LIME:SKY,10);
                title.setText((block?"Заблокировано: ":"")+item.target());
                subtitle.setText(failed?NetworkErrors.describe(item.result()).title()+" · "+item.app():item.app()+" · "+item.protocol());
                stamp.setText(time.format(item.time()));
            }
        }
    }

    private void showLogEntry(History.Connection entry) {
        String info=entry.app()+"\n"+entry.protocol()+" · "+routeLabel(entry.route())
                +"\n↓ "+size(entry.down())+"    ↑ "+size(entry.up());
        if(NetworkErrors.failed(entry.result())) {
            NetworkErrors.Detail detail=NetworkErrors.describe(entry.result());
            info+="\n\n"+detail.title()+"\n"+detail.hint()+"\nКод: "+detail.code();
        }
        new AlertDialog.Builder(this).setTitle(entry.target()).setMessage(info).setPositiveButton("Закрыть",null).show();
    }

    private class ChartView extends View {
        private final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);
        private Report report;
        private float[] fromUp,fromDown,toUp,toDown;
        private String[] labels;
        private float progress=1f;
        private ValueAnimator motion;

        ChartView() {
            super(MainActivity.this);
            paint.setTypeface(getResources().getFont(R.font.jetbrains_mono));
            paint.setTextSize(dp(10)); paint.setTextAlign(Paint.Align.CENTER);
        }
        void show(Report next) {
            long[] up=next.graph().up(),down=next.graph().down();
            if(report==null || report.chartBase()!=next.chartBase() || report.chartSpan()!=next.chartSpan()) {
                SimpleDateFormat format=new SimpleDateFormat(next.chartSpan()==180?"HH":"EE",new Locale("ru","RU"));
                labels=new String[up.length];
                for(int i=0;i<labels.length;i++)labels[i]=format.format((next.chartBase()+i*(long)next.chartSpan())*60_000);
                invalidate();
            }
            if(report!=null && Arrays.equals(up,report.graph().up()) && Arrays.equals(down,report.graph().down())) {
                report=next;
                return;
            }
            report=next;
            if(motion!=null)motion.cancel();
            float[] startUp=new float[up.length],startDown=new float[down.length];
            if(toUp!=null && toUp.length==up.length) {
                for(int i=0;i<up.length;i++) {
                    startUp[i]=interpolate(fromUp[i],toUp[i]);
                    startDown[i]=interpolate(fromDown[i],toDown[i]);
                }
            }
            fromUp=startUp; fromDown=startDown;
            toUp=new float[up.length]; toDown=new float[down.length];
            long peak=1;
            for(int i=0;i<up.length;i++)peak=Math.max(peak,up[i]+down[i]);
            boolean changed=false;
            for(int i=0;i<up.length;i++) {
                toUp[i]=(float)up[i]/peak;
                toDown[i]=(float)down[i]/peak;
                changed|=fromUp[i]!=toUp[i]||fromDown[i]!=toDown[i];
            }
            if(!changed||!ValueAnimator.areAnimatorsEnabled()) {
                progress=1f;
                invalidate();
                return;
            }
            progress=0f;
            motion=ValueAnimator.ofFloat(0f,1f);
            motion.setDuration(280);
            motion.setInterpolator(EASE_OUT);
            motion.addUpdateListener(animator-> {
                progress=(float)animator.getAnimatedValue();
                invalidate();
            });
            motion.start();
        }

        private float interpolate(float from,float to) { return from+(to-from)*progress; }
        @Override protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            if(labels==null)return;
            float space=dp(8),bar=(getWidth()-space*(labels.length-1))/labels.length, baseline=dp(111);
            for(int i=0;i<labels.length;i++) {
                float x=i*(bar+space), y=baseline;
                float bottom=baseline*interpolate(fromDown[i],toDown[i]), top=baseline*interpolate(fromUp[i],toUp[i]);
                if(bottom>0){ paint.setColor(LIME); canvas.drawRoundRect(x,y-bottom,x+bar,y,dp(3),dp(3),paint); y-=bottom; }
                if(top>0){ paint.setColor(SKY); canvas.drawRoundRect(x,y-top,x+bar,y,dp(6),dp(6),paint); }
                paint.setColor(FAINT);
                canvas.drawText(labels[i],x+bar/2,dp(130),paint);
            }
        }
        @Override protected void onDetachedFromWindow() {
            if(motion!=null)motion.cancel();
            super.onDetachedFromWindow();
        }
    }

    private String routeLabel(String mode) {
        return switch(mode) {
            case Config.PROXY -> "Прокси";
            case "service" -> "Событие VPN";
            case Config.DIRECT -> "Напрямую";
            case Config.BYPASS -> "Вне VPN";
            case Config.BLOCK -> "Блок";
            default -> "По умолчанию";
        };
    }
    private int routeColor(String mode) {
        return switch(mode) {
            case Config.BLOCK -> RED;
            case Config.DIRECT -> SKY;
            case Config.BYPASS -> RIM;
            default -> LIME;
        };
    }
    private ImageView appIcon(InstalledApp app,int size) {
        ImageView view=new ImageView(this);
        view.setScaleType(ImageView.ScaleType.FIT_CENTER);
        view.setLayoutParams(new LinearLayout.LayoutParams(dp(size),dp(size)));
        bindAppIcon(view,app);
        return view;
    }
    private void bindAppIcon(ImageView view,InstalledApp app) {
        String pkg=app.pkg();
        if(pkg.equals(view.getTag()))return;
        view.setTag(pkg);
        var cached=appIcons.get(pkg);
        if(cached!=null) { view.setImageBitmap(cached); return; }
        view.setImageResource(R.drawable.fig_servers);
        appLoader.execute(()->{
            try {
                var drawable=getPackageManager().getApplicationIcon(pkg);
                int size=dp(44);
                var bitmap=android.graphics.Bitmap.createBitmap(size,size,android.graphics.Bitmap.Config.ARGB_8888);
                drawable.setBounds(0,0,size,size);
                drawable.draw(new Canvas(bitmap));
                appIcons.put(pkg,bitmap);
                ui.post(()->{if(!isDestroyed() && pkg.equals(view.getTag()))view.setImageBitmap(bitmap);});
            } catch(PackageManager.NameNotFoundException | RuntimeException ignored) { }
        });
    }
    private void fetchApps() {
        if(appsReady||appScan||isDestroyed())return;
        appScan=true;
        appLoader.execute(()-> {
            PackageManager pm=getPackageManager();
            List<InstalledApp> apps=new ArrayList<>();
            try {
                for(ApplicationInfo app:pm.getInstalledApplications(0)) {
                    if(app.packageName.equals(getPackageName())
                            ||pm.checkPermission(Manifest.permission.INTERNET,app.packageName)!=PackageManager.PERMISSION_GRANTED)continue;
                    String label;
                    try { label=pm.getApplicationLabel(app).toString().trim(); }
                    catch(RuntimeException e) { label=app.packageName; }
                    String name=label.isEmpty()?app.packageName:label;
                    apps.add(new InstalledApp(app.packageName,name,(name+" "+app.packageName).toLowerCase(Locale.ROOT)));
                }
            } catch (RuntimeException e) {
                ui.post(()->{
                    if(isDestroyed())return;
                    appScan=false; appScanFailed=true;
                    if(activeApps!=null) activeApps.notifyDataSetChanged();
                });
                return;
            }
            apps.sort(Comparator.comparing(InstalledApp::name,String.CASE_INSENSITIVE_ORDER).thenComparing(InstalledApp::pkg));
            ui.post(()-> {
                if(isDestroyed())return;
                installed=apps;
                appsReady=true;
                appScan=false;
                appScanFailed=false;
                if(activeApps!=null) activeApps.update();
            });
        });
    }
    private String appRuleText(String value) {
        return switch(value) {
            case Config.DIRECT -> "Прямой доступ · с журналом";
            case Config.BLOCK -> "Доступ в интернет запрещён";
            case Config.BYPASS -> "Вне VPN · напрямую";
            default -> "Маршрут активного профиля";
        };
    }
    private void firewall() {
        if(appScanFailed)fetchApps();
        firewallActive=RouteService.status.connected();
        firewallToggle=design.toggle("VPN и фильтрация",firewallActive,this::toggle);
        header("Брандмауэр",firewallToggle);
        LinearLayout body=design.column();
        LinearLayout rulesHeader=design.column();
        LinearLayout banner=design.row(); design.pad(banner,16,16); design.surface(banner,PANEL,28);
        firewallBadge=icon(R.drawable.fig_firewall,BG,TILE,56,28,16,null,null);
        banner.addView(firewallBadge); gap(banner,16);
        LinearLayout text=design.column();
        firewallTitle=t("",16,TEXT,600);
        firewallCount=t("",14,FAINT,400);
        text.addView(firewallTitle);
        add(text,firewallCount,-2,3); design.weight(banner,text);
        add(rulesHeader,banner,-2,0);
        renderFirewallStatus();
        add(rulesHeader,heading("Глобальные правила"),-2,24);
        LinearLayout global=panel(16);
        preferenceSwitch(global,"Блокировать трекеры","DNS-фильтр известных доменов аналитики","trackers",false);
        preferenceSwitch(global,"Блокировать рекламу","DNS-фильтр известных рекламных сетей","ads",false);
        preferenceSwitch(global,"Только Wi-Fi для прокси","Мобильная сеть — напрямую, правила остаются активны","wifiOnly",false);
        add(rulesHeader,global,-2,8);
        add(body,rulesHeader,-2,0);
        rulesHeader.setVisibility(firewallSearch.trim().isEmpty()?View.VISIBLE:View.GONE);
        TextView count=heading("");
        add(body,count,-2,24);
        Config.AppScope scope=config.appScope();
        boolean picking=choosingApps||scope.selectedOnly();
        add(body,segment(new String[]{"Все приложения","Только выбранные"},picking?1:0,index->{
            if(index==0) {
                if(!picking)return;
                choosingApps=false;
                if(scope.selectedOnly()) {config.setAppScope(false); reconfigure();}
            } else {
                if(picking)return;
                choosingApps=true;
            }
            rememberFirewallPosition();
            render();
        },36),44,8);
        String note=picking
                ?"В туннеле остаются отмеченные приложения и приложения с правилом «Блок»."
                :"Все приложения используют VPN по своим правилам. Правило «Вне VPN» исключает приложение из туннеля и журнала.";
        add(body,t(note,12,FAINT,400),-2,8);
        if(!scope.exclusionsEnabled() && !scope.selectedOnly()) {
            add(body,design.pill("Включить сохранённые исключения",13,LIME,PANEL,44,()->{
                config.setAppScope(false);
                rememberFirewallPosition();
                reconfigure();
                render();
            }),44,8);
        }
        TextView apply=picking&&choosingApps&&!scope.selectedOnly()
                ?design.pill("Применить выбранные",13,BG,LIME,44,()->{
                    if(!hasScopedApps(config.included(),config.read().rules()))return;
                    config.setAppScope(true);
                    choosingApps=false;
                    rememberFirewallPosition();
                    reconfigure();
                    render();
                }):null;
        if(apply!=null)add(body,apply,44,8);
        AppsAdapter adapter=new AppsAdapter(count,firewallSearch,picking,scope,apply);
        EditText search=searchField("Поиск приложений",firewallSearch,value->{
            firewallSearch=value;
            rulesHeader.setVisibility(value.trim().isEmpty()?View.VISIBLE:View.GONE);
            adapter.filter(value);
            if(firewallList!=null)firewallList.setSelectionFromTop(0,0);
        });
        pinAppSearch(search);
        firewallList=installAppList(body,adapter);
        if(firewallPosition>0 || firewallTop!=0) firewallList.setSelectionFromTop(firewallPosition,firewallTop);
    }
    private void updateFirewallStatus() {
        if(firewallToggle==null || firewallActive==RouteService.status.connected())return;
        firewallActive=RouteService.status.connected();
        renderFirewallStatus();
    }
    private void renderFirewallStatus() {
        boolean active=firewallActive;
        firewallToggle.setChecked(active);
        design.surface(firewallBadge,active?LIME:TILE,16);
        ((ImageView)firewallBadge.getChildAt(0)).setImageTintList(ColorStateList.valueOf(active?BG:FAINT));
        firewallTitle.setText(active?"Фильтрация включена":"Фильтрация выключена");
        firewallCount.setText("Правила применяются при включённом VPN");
        if(!active)return;
        int version=screenVersion;
        data.execute(()->{
            long day=java.time.LocalDate.now().atStartOfDay(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli();
            String caption;
            try { caption="Заблокировано сегодня: "+history.totals(day).blocked(); }
            catch(android.database.sqlite.SQLiteException e) { caption="Статистика журнала недоступна"; }
            String result=caption;
            ui.post(()->{
                if(screenVersion==version && firewallToggle!=null && firewallActive)
                    firewallCount.setText(result);
            });
        });
    }
    private void rememberFirewallPosition() {
        if(firewallList==null)return;
        firewallPosition=firewallList.getFirstVisiblePosition();
        View first=firewallList.getChildAt(0);
        firewallTop=first==null?0:first.getTop()-firewallList.getPaddingTop();
    }
    private void pinAppSearch(EditText search) {
        LinearLayout searchBar=design.column();
        searchBar.setPadding(dp(16),0,dp(16),dp(8));
        add(searchBar,search,44,0);
        add(page,searchBar,-2,0);
    }
    private ListView installAppList(LinearLayout header,AppsAdapter adapter) {
        ListView list=new ListView(this);
        list.setVerticalScrollBarEnabled(false);
        list.setClipToPadding(false);
        list.setPadding(dp(16),0,dp(16),dp(20));
        list.setDivider(new android.graphics.drawable.ColorDrawable(android.graphics.Color.TRANSPARENT));
        list.setDividerHeight(dp(8));
        list.setSelector(android.R.color.transparent);
        list.setItemsCanFocus(true);
        header.setFocusableInTouchMode(true);
        list.addHeaderView(header,null,false);
        list.setAdapter(adapter);
        page.addView(list,new LinearLayout.LayoutParams(-1,0,1));
        activeApps=adapter;
        adapter.update();
        fetchApps();
        return list;
    }

    private boolean hasScopedApps(java.util.Set<String> selected, Map<String,String> rules) {
        if(!appsReady) return false;
        for(InstalledApp app:installed) {
            String rule=rules.getOrDefault(app.pkg(),Config.PROXY);
            if(Config.BLOCK.equals(rule) || (selected.contains(app.pkg()) && !Config.BYPASS.equals(rule)))return true;
        }
        return false;
    }

    private final class AppsAdapter extends BaseAdapter {
        private final TextView count,apply;
        private final boolean picking;
        private final Config.AppScope scope;
        private final List<InstalledApp> matched=new ArrayList<>();
        private final Map<String,String> rules;
        private String query;
        private java.util.Set<String> included=java.util.Collections.emptySet();

        AppsAdapter(TextView count,String search,boolean picking,Config.AppScope scope,TextView apply) {
            this.count=count;
            this.picking=picking;
            this.scope=scope;
            this.apply=apply;
            rules=config.read().rules();
            query=search.trim().toLowerCase(Locale.ROOT);
        }

        void filter(String search) {
            String next=search.trim().toLowerCase(Locale.ROOT);
            if(next.equals(query))return;
            query=next;
            update();
        }

        void update() {
            if(picking)included=config.included();
            matched.clear();
            if(query.isEmpty())matched.addAll(installed);
            else for(InstalledApp app:installed) if(app.searchKey().contains(query))matched.add(app);
            if(picking) {
                long chosen=installed.stream().filter(app->included.contains(app.pkg())).count();
                count.setText("Приложения · выбрано "+chosen+" из "+installed.size());
            } else count.setText("Приложения · "+installed.size());
            if(apply!=null) {
                boolean ready=hasScopedApps(included,rules);
                apply.setEnabled(ready);
                apply.setAlpha(ready?1f:.5f);
            }
            notifyDataSetChanged();
        }

        @Override public int getCount() { return Math.max(1,matched.size()); }
        @Override public InstalledApp getItem(int position) { return matched.isEmpty()?null:matched.get(position); }
        @Override public long getItemId(int position) { return position; }
        @Override public boolean areAllItemsEnabled() { return false; }
        @Override public boolean isEnabled(int position) { return !matched.isEmpty(); }
        @Override public int getViewTypeCount() { return 2; }
        @Override public int getItemViewType(int position) { return matched.isEmpty()?0:1; }

        @Override public View getView(int position,View recycled,ViewGroup parent) {
            InstalledApp app=getItem(position);
            if(app==null) {
                TextView empty=recycled==null?t("",14,FAINT,400):(TextView)recycled;
                empty.setText(appsReady?"Приложения не найдены":appScanFailed?
                        "Не удалось загрузить приложения. Открой брандмауэр заново.":"Загрузка приложений…");
                empty.setGravity(Gravity.CENTER);
                empty.setLayoutParams(new android.widget.AbsListView.LayoutParams(-1,dp(68)));
                return empty;
            }
            AppRow row=recycled==null?new AppRow():(AppRow)recycled;
            row.bind(app,rules.getOrDefault(app.pkg(),Config.PROXY));
            return row;
        }

        private final class AppRow extends LinearLayout {
            private final ImageView stamp;
            private final TextView title, detail;
            private final TextView badge;
            private final FrameLayout check;
            private InstalledApp app;
            private String rule;

            AppRow() {
                super(MainActivity.this);
                setGravity(Gravity.CENTER_VERTICAL);
                design.pad(this,12,12);
                int size=40;
                stamp=new ImageView(MainActivity.this);
                stamp.setScaleType(ImageView.ScaleType.FIT_CENTER);
                addView(stamp,new LinearLayout.LayoutParams(dp(size),dp(size)));
                gap(this,12);
                LinearLayout info=design.column(),name=design.row();
                title=t("",14,TEXT,500);
                ellipsize(title);
                design.weight(name,title);
                badge=design.pill("",10,BG,LIME,20,null);
                gap(name,8);
                name.addView(badge);
                info.addView(name);
                detail=t("",12,FAINT,400);
                ellipsize(detail);
                add(info,detail,-2,2);
                design.weight(this,info);
                gap(this,12);
                check=picking?icon(R.drawable.fig_check,BG,TILE,38,18,8,"Выбрать приложение",this::toggleIncluded):null;
                if(check!=null) {
                    addView(check);
                    gap(this,8);
                }
                addView(design.icon(R.drawable.fig_chevron,FAINT),new LinearLayout.LayoutParams(dp(16),dp(16)));
                design.action(this,PANEL,16,0,()->{
                    runningRule=app;
                    openPage("app");
                });
                setFocusable(false);
            }

            void bind(InstalledApp value,String mode) {
                app=value;
                rule=mode;
                bindAppIcon(stamp,app);
                title.setText(app.name());
                boolean blocked=Config.BLOCK.equals(rule);
                boolean bypass=Config.BYPASS.equals(rule);
                boolean checked=included.contains(app.pkg());
                String effective=rule;
                if(!blocked && scope.selectedOnly() && !checked)effective=Config.BYPASS;
                if(!scope.exclusionsEnabled() && bypass)effective=Config.DIRECT;
                detail.setText(appRuleText(effective));
                int color=routeColor(effective);
                badge.setText(routeLabel(effective));
                badge.setTextColor(color==RED||color==RIM?TEXT:BG);
                design.surface(badge,color,100);
                if(check!=null) {
                    boolean visibleCheck=blocked||checked;
                    design.surface(check,visibleCheck?LIME:TILE,8);
                    check.getChildAt(0).setVisibility(visibleCheck?View.VISIBLE:View.INVISIBLE);
                    check.setEnabled(!blocked&&!bypass);
                    check.setAlpha(blocked||bypass?.5f:1f);
                    check.setContentDescription((blocked?"Остаётся под блокировкой: ":bypass?"Исключено правилом: ":
                            checked?"Исключить из выбранных: ":"Добавить в выбранные: ")+app.name());
                }
            }

            private void toggleIncluded() {
                var next=new java.util.HashSet<>(included);
                boolean add=next.add(app.pkg());
                if(!add)next.remove(app.pkg());
                if(scope.selectedOnly()&&!hasScopedApps(next,rules)) {
                    Toast.makeText(MainActivity.this,"Выбери другое приложение или переключись на «Все приложения»",Toast.LENGTH_SHORT).show();
                    return;
                }
                config.include(app.pkg(),add);
                if(scope.selectedOnly())reconfigure();
                update();
            }
        }
    }
    private boolean writeRule(InstalledApp app,String mode) {
        Config.Settings settings;
        try { settings=config.read(); }
        catch(Config.ReadFailure e) { showConfigError(); return false; }
        Map<String,String> rules=new HashMap<>(settings.rules());
        if(mode.equals(Config.PROXY)) rules.remove(app.pkg()); else rules.put(app.pkg(),mode);
        if(config.appScope().selectedOnly() && !hasScopedApps(config.included(),rules)) {
            Toast.makeText(this,"В туннеле должно остаться хотя бы одно приложение",Toast.LENGTH_SHORT).show();
            return false;
        }
        if(!save(new Config.Settings(settings.profiles(),settings.selected(),rules)))return false;
        reconfigure(); return true;
    }
    private void appRule() {
        InstalledApp app=runningRule;
        pageHeader(app.name(),false,appIcon(app,36),this::closePage);
        LinearLayout body=scrollContent(8,32);
        String mode=config.read().rules().getOrDefault(app.pkg(),Config.PROXY);
        String[] modes={Config.PROXY,Config.DIRECT,Config.BLOCK,Config.BYPASS};
        add(body,heading("Маршрут трафика"),-2,0);
        LinearLayout selector=design.row();
        design.pad(selector,4,4); design.surface(selector,TILE,100);
        for(String route:modes) {
            int fill=route.equals(mode)?routeColor(route):0;
            int ink=fill==0?MUTED:fill==RED||fill==RIM?TEXT:BG;
            TextView pill=design.pill(routeLabel(route),11,ink,fill,36,()->{if(writeRule(app,route))render();});
            design.pad(pill,2,0); design.weight(selector,pill);
        }
        add(body,selector,44,8);
        add(body,t(appRuleText(mode),12,FAINT,400),-2,8);
        add(body,heading("Приложение"),-2,20);
        LinearLayout details=panel(16);
        settingRow(details,"Пакет Android",app.pkg(),null,null);
        design.separator(details);
        Config.AppScope scope=config.appScope();
        boolean outside=scope.selectedOnly()&&!Config.BLOCK.equals(mode)&&!config.included().contains(app.pkg())
                ||scope.exclusionsEnabled()&&Config.BYPASS.equals(mode);
        settingRow(details,"Журнал",outside?"Трафик вне туннеля не виден":"Соединения этого приложения",
                design.toggle("Журнал",!outside,null),null);
        add(body,details,-2,8);
        add(body,design.pill("Сбросить правила",14,ROSE,PANEL,48,()->{if(writeRule(app,Config.PROXY))render();}),48,20);
    }
    private void settingRow(LinearLayout parent,String title,String subtitle,View accessory,Runnable click) {
        LinearLayout row=design.row();
        design.pad(row,16,16);
        LinearLayout text=design.column();
        text.addView(t(title,14,TEXT,500));
        if(subtitle!=null) add(text,t(subtitle,12,FAINT,400),-2,3);
        design.weight(row,text);
        if(accessory!=null) {gap(row,12);row.addView(accessory);}
        if(click!=null) design.action(row,PANEL,0,0,click);
        parent.addView(row);
    }
    private void settingToggle(LinearLayout parent,String title,String subtitle,boolean on,Runnable click) {
        if(parent.getChildCount()>0) design.separator(parent);
        settingRow(parent,title,subtitle,design.toggle(title,on,click),null);
    }
    private void preferenceSwitch(LinearLayout parent,String label,String sub,String key,boolean fallback) {
        if(parent.getChildCount()>0)design.separator(parent);
        FigmaUi.Toggle toggle=design.toggle(label,config.enabled(key,fallback),null);
        toggle.setAction(()-> {
            boolean next=!config.enabled(key,fallback);
            config.setEnabled(key,next);
            toggle.setChecked(next);
            reconfigure();
        });
        settingRow(parent,label,sub,toggle,null);
    }
    private void settingLink(LinearLayout parent,String title,String value,Runnable click) {
        if(parent.getChildCount()>0) design.separator(parent);
        LinearLayout end=design.row();
        end.addView(t(value,14,FAINT,400));
        gap(end,8);
        end.addView(design.icon(R.drawable.fig_chevron,FAINT),new LinearLayout.LayoutParams(dp(16),dp(16)));
        settingRow(parent,title,null,end,click);
    }
    private void settings() {
        header("Настройки",null);
        LinearLayout body=scrollContent(0,20);
        LinearLayout controls=panel(16);
        RouteService active=RouteService.instance;
        boolean auto=getPreferences(MODE_PRIVATE).getBoolean("autoCheck",true);
        settingToggle(controls,"Постоянный VPN","Always-on VPN · системные настройки",active!=null&&active.isAlwaysOn(),
                ()->openSettings(Settings.ACTION_VPN_SETTINGS));
        settingToggle(controls,"Блок без VPN","Запретить трафик вне VPN",active!=null&&active.isLockdownEnabled(),
                ()->openSettings(Settings.ACTION_VPN_SETTINGS));
        settingToggle(controls,"Экономия батареи","Фоновый режим без опроса прокси",true,null);
        FigmaUi.Toggle autoToggle=design.toggle("Проверка при входе",auto,null);
        autoToggle.setAction(()->{
            var prefs=getPreferences(MODE_PRIVATE);
            boolean next=!prefs.getBoolean("autoCheck",true);
            prefs.edit().putBoolean("autoCheck",next).apply();
            autoToggle.setChecked(next);
            if(next)checkAll();
        });
        design.separator(controls);
        settingRow(controls,"Проверка при входе","Статус серверов при открытии",autoToggle,null);
        boolean notifications=getSystemService(android.app.NotificationManager.class).areNotificationsEnabled();
        settingToggle(controls,"Уведомление в шторке","Статус подключения",notifications,()-> {
            Intent intent=new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                    .putExtra(Settings.EXTRA_APP_PACKAGE,getPackageName());
            openActivity(intent,"Настройки уведомлений недоступны");
        });
        settingToggle(controls,"DNS через прокси","Шифрованные запросы по маршруту приложения",!config.enabled("dnsDirect",false),()->openPage("dns"));
        add(body,controls,-2,0);
        LinearLayout pages=panel(16);
        settingLink(pages,"Сторонний VPN","Android",()->openPage("vpn"));
        settingLink(pages,"DNS-сервер",DnsOptions.selected(config).name(),()->openPage("dns"));
        settingLink(pages,"Язык","Русский",()->openPage("language"));
        add(body,pages,-2,16);
        LinearLayout privateDns=panel(16);
        settingLink(privateDns,"Частный DNS","Android",()->openSettings("android.settings.PRIVATE_DNS_SETTINGS"));
        add(body,privateDns,-2,16);
        LinearLayout usage=design.row(); design.pad(usage,16,16); design.surface(usage,PANEL,16);
        TextView down=design.terminal("—",18,TEXT),up=design.terminal("—",18,TEXT);
        design.weight(usage,trafficStat("За неделю",R.drawable.fig_down,LIME,down)); gap(usage,12);
        design.weight(usage,trafficStat("Отдано",R.drawable.fig_up,SKY,up));
        add(body,usage,-2,16);
        data.execute(()->{
            try {
                History.Chart week=history.chart(1440,7);
                ui.post(()->{down.setText(size(week.totalDown())); up.setText(size(week.totalUp()));});
            } catch(android.database.sqlite.SQLiteException e) {
                ui.post(()->{down.setText("Недоступно"); up.setText("Недоступно");});
            }
        });
        TextView version=t("ProxyRoute · версия " + BuildConfig.VERSION_NAME,12,FAINT,400); version.setGravity(Gravity.CENTER);
        add(body,version,-2,24);
    }
    private LinearLayout trafficStat(String title,int glyph,int tint,TextView total) {
        LinearLayout stat=design.column(),tag=design.row();
        tag.addView(design.icon(glyph,tint),new LinearLayout.LayoutParams(dp(14),dp(14)));
        gap(tag,4);tag.addView(t(title,12,FAINT,400));
        stat.addView(tag);add(stat,total,-2,4);return stat;
    }
    private void externalVpn() {
        pageHeader("Сторонний VPN",false,null,this::closePage);
        LinearLayout body=scrollContent(8,32),details=panel(16);
        settingRow(details,"Локальный прокси","Укажи HTTP или SOCKS5, который предоставляет другое приложение. Для локального входа используй 127.0.0.1 и порт из настроек этого приложения.",
                null,null);
        add(body,details,-2,0);
        add(body,design.pill("Добавить локальный сервер",14,BG,LIME,48,()->edit(null,"127.0.0.1")),48,12);
        LinearLayout apps=panel(16);
        add(body,heading("VPN-приложения"),-2,22);
        var pm=getPackageManager();
        java.util.Set<String> seen=new java.util.HashSet<>();
        for(var resolve:pm.queryIntentServices(new Intent("android.net.VpnService"),0)) {
            String pkg=resolve.serviceInfo.packageName;
            if(pkg.equals(getPackageName())||!seen.add(pkg))continue;
            String label=resolve.serviceInfo.applicationInfo.loadLabel(pm).toString();
            Intent launch=pm.getLaunchIntentForPackage(pkg);
            if(apps.getChildCount()>0)design.separator(apps);
            settingRow(apps,label,pkg,null,launch==null?null:()->openActivity(launch,"Не удалось открыть VPN-приложение"));
        }
        if(apps.getChildCount()==0)settingRow(apps,"Открыть настройки Android","Установленные VPN и рабочие профили",null,
                ()->openSettings(Settings.ACTION_VPN_SETTINGS));
        add(body,apps,-2,8);
        add(body,t("В одном профиле Android разрешён один системный VPN. Если сторонний клиент требует собственный VPN, запусти его в отдельном рабочем профиле.",13,FAINT,400),-2,14);
        add(body,design.pill("Системные настройки VPN",14,LIME,PANEL,48,()->openSettings(Settings.ACTION_VPN_SETTINGS)),48,20);
    }
    private void languagePage() {
        pageHeader("Язык",false,null,this::closePage);
        LinearLayout body=scrollContent(8,32),details=panel(16);
        settingRow(details,"Русский","Язык интерфейса ProxyRoute",
                icon(R.drawable.fig_check,BG,LIME,24,16,100,null,null),null);
        add(body,details,-2,0);
    }
    private void dnsPage() {
        pageHeader("DNS-сервер",false,null,this::closePage);
        LinearLayout body=scrollContent(8,32),details=panel(16);
        DnsOptions current=DnsOptions.selected(config);
        for(DnsOptions preset:DnsOptions.PRESETS) {
            if(details.getChildCount()>0)design.separator(details);
            settingRow(details,preset.name(),preset.bootstrap()+" · DNS-over-HTTPS",
                    preset.equals(current)?icon(R.drawable.fig_check,BG,LIME,24,16,100,null,null):null,
                    ()->{config.setDns(preset); reconfigure(); render();});
        }
        design.separator(details);
        settingRow(details,"Свой сервер","HTTPS-адрес DoH и IP для подключения",
                current.name().equals("Свой сервер")?icon(R.drawable.fig_check,BG,LIME,24,16,100,null,null):null,
                ()->openPage("dnsCustom"));
        add(body,details,-2,0);
        LinearLayout routing=panel(16);
        FigmaUi.Toggle toggle=design.toggle("DNS через прокси",!config.enabled("dnsDirect",false),null);
        toggle.setAction(()->{
            boolean next=!config.enabled("dnsDirect",false);
            config.setEnabled("dnsDirect",next);
            toggle.setChecked(!next); reconfigure();
        });
        settingRow(routing,"Запросы через прокси","Для приложений, использующих прокси",toggle,null);
        add(body,routing,-2,16);
        add(body,t("Правила фильтруют обычные DNS-запросы в туннеле. Приложения со своим зашифрованным DNS могут обходить DNS-фильтр.",13,FAINT,400),-2,12);
    }

    private void customDns() {
        pageHeader("Свой DNS-сервер",false,null,()->openPage("dns"));
        LinearLayout body=scrollContent(10,32);
        DnsOptions current=DnsOptions.selected(config);
        boolean custom=current.name().equals("Свой сервер");
        EditText url=design.field("https://dns.example.com/dns-query",custom?current.url():"",InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_URI);
        EditText ip=design.field("IP сервера",custom?current.bootstrap():"",InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_URI);
        fieldGroup(body,"HTTPS-адрес",url,56,0);
        fieldGroup(body,"IP сервера",ip,56,16);
        TextView error=t("",13,ROSE,400);
        add(body,error,-2,8);
        add(body,design.pill("Сохранить",14,BG,LIME,48,()->{
            try {
                config.setDns(DnsOptions.custom(url.getText().toString(),ip.getText().toString()));
                hideKeyboard(url); reconfigure(); openPage("dns");
            } catch(IllegalArgumentException e) {error.setText(e.getMessage());}
        }),48,12);
    }
}
