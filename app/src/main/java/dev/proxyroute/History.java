package dev.proxyroute;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

final class History extends SQLiteOpenHelper {
    private static final long DAY = 86_400_000L;
    private static final int EVENTS_PER_BATCH = 2048;
    private static History instance;
    private final ScheduledExecutorService writer = Executors.newSingleThreadScheduledExecutor();
    private final ConcurrentLinkedQueue<Event> events = new ConcurrentLinkedQueue<>();
    private final AtomicInteger count = new AtomicInteger();
    private final AtomicBoolean scheduled = new AtomicBoolean();
    private final AtomicLong pendingUp = new AtomicLong(), pendingDown = new AtomicLong();
    private final AtomicLong revision = new AtomicLong();
    private long lastTrim;

    record Connection(long time, String app, String protocol, String target, String route,
                      String result, long up, long down) {}
    record Metrics(long tcpMillis,long handshakeMillis,long firstByteMillis,long dnsMillis,String stage) {}
    record Totals(long all, long blocked, long errors) {}
    record Chart(long[] up, long[] down, long totalUp, long totalDown) {}
    private interface Event { void apply(SQLiteDatabase db); }
    static final class Unavailable extends java.io.IOException {
        Unavailable(Throwable cause) { super("Journal unavailable",cause); }
    }

    static synchronized History get(Context context) {
        if (instance == null) instance = new History(context.getApplicationContext());
        return instance;
    }

    private History(Context context) {
        super(context, "connections.db", null, 1);
        setWriteAheadLoggingEnabled(true);
        writer.execute(() -> {
            try {
                SQLiteDatabase db = getWritableDatabase();
                db.execSQL("UPDATE connections SET result='process stopped' WHERE result='active'");
                trim(db, System.currentTimeMillis());
            } catch (RuntimeException e) {
                Log.w("ProxyRoute", "Journal initialization failed");
            }
        });
    }

    @Override public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE connections(row INTEGER PRIMARY KEY,key TEXT UNIQUE,ts INTEGER,app TEXT,"
                + "protocol TEXT,target TEXT,route TEXT,result TEXT,up INTEGER DEFAULT 0,down INTEGER DEFAULT 0,"
                + "ended INTEGER,profile TEXT,network TEXT,family INTEGER,tcpMs INTEGER,handshakeMs INTEGER,"
                + "firstByteMs INTEGER,dnsMs INTEGER,stage TEXT)");
        db.execSQL("CREATE TABLE traffic(minute INTEGER PRIMARY KEY,up INTEGER,down INTEGER)");
    }

    @Override public void onUpgrade(SQLiteDatabase db, int from, int to) {
        throw new IllegalStateException("Unknown database version " + from);
    }

    @Override public void onOpen(SQLiteDatabase db) {
        super.onOpen(db);
        if (db.isReadOnly()) return;
        // The new fields are additive. Older APKs can continue to use the same journal.
        var columns = new java.util.HashSet<String>();
        try (Cursor cursor = db.rawQuery("PRAGMA table_info(connections)", null)) {
            while (cursor.moveToNext()) columns.add(cursor.getString(1));
        }
        if (columns.contains("stage")) return;
        db.beginTransaction();
        try {
            for (String column : new String[]{"ended INTEGER","profile TEXT","network TEXT","family INTEGER",
                    "tcpMs INTEGER","handshakeMs INTEGER","firstByteMs INTEGER","dnsMs INTEGER","stage TEXT"}) {
                if (!columns.contains(column.substring(0,column.indexOf(' '))))
                    db.execSQL("ALTER TABLE connections ADD COLUMN " + column);
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    void open(String id, String app, String protocol, String target, String route) {
        open(id,app,protocol,target,route,"","");
    }

    void open(String id, String app, String protocol, String target, String route, String profile, String network) {
        long now = System.currentTimeMillis();
        push(db -> {
            ContentValues row = new ContentValues();
            row.put("key", id);
            row.put("ts", now);
            row.put("app", app);
            row.put("protocol", protocol);
            row.put("target", target);
            row.put("route", route);
            row.put("profile", profile);
            row.put("network", network);
            if ((protocol.equals("TCP") || protocol.equals("UDP") || protocol.startsWith("DNS/")) && target.indexOf(':') >= 0)
                row.put("family", target.startsWith("[") ? 6 : 4);
            row.put("result", "active");
            db.insertOrThrow("connections", null, row);
        });
    }

    void serviceEvent(String title,String result) {
        String key="service/"+java.util.UUID.randomUUID();
        open(key,"ProxyRoute","VPN",title,"service");
        close(key,result,0,0);
    }

    void export(java.io.OutputStream stream, boolean anonymous, String snapshot) throws java.io.IOException {
        try {
            if (!writer.submit(this::flush).get(5,TimeUnit.SECONDS)) throw new Unavailable(null);
        } catch(java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException e) {
            throw new Unavailable(e);
        } catch(InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new java.io.IOException("Journal export interrupted",e);
        }
        java.io.Writer output=new java.io.BufferedWriter(new java.io.OutputStreamWriter(stream,java.nio.charset.StandardCharsets.UTF_8));
        android.util.JsonWriter json=new android.util.JsonWriter(output);
        json.beginObject();
        json.name("format").value(anonymous ? "proxyroute-diagnostics-v1" : "proxyroute-log-v1");
        if (!snapshot.isEmpty()) {
            json.name("performance").beginObject();
            for (String item : snapshot.split(";")) {
                int split = item.indexOf('=');
                if (split > 0) json.name(item.substring(0,split)).value(item.substring(split+1));
            }
            json.endObject();
        }
        var sessions = new java.util.HashMap<String,Integer>();
        var profiles = new java.util.HashMap<String,Integer>();
        if (!anonymous) json.name("exportedAt").value(java.time.Instant.now().toString());
        json.name("connections").beginArray();
        try(Cursor c=getReadableDatabase().rawQuery(
                "SELECT ts,app,protocol,target,route,result,up,down,key,ended,profile,network,family,"
                + "tcpMs,handshakeMs,firstByteMs,dnsMs,stage FROM connections ORDER BY row DESC",null)) {
            while(c.moveToNext()) {
                String result=c.getString(5);
                json.beginObject();
                if (!anonymous) {
                    json.name("time").value(java.time.Instant.ofEpochMilli(c.getLong(0)).toString());
                    json.name("app").value(c.getString(1));
                    json.name("target").value(c.getString(3));
                }
                json.name("protocol").value(c.getString(2));
                json.name("route").value(c.getString(4));
                json.name("result").value(NetworkErrors.failed(result)?NetworkErrors.describe(result).code():result);
                json.name("sent").value(c.getLong(6));
                json.name("received").value(c.getLong(7));
                String session = c.getString(8).split("/",2)[0];
                if (!session.equals("service")) json.name("session").value(anonymous
                        ? Integer.toString(sessions.computeIfAbsent(session,key -> sessions.size()+1)) : session);
                if (!c.isNull(9)) {
                    if (!anonymous) json.name("endedAt").value(java.time.Instant.ofEpochMilli(c.getLong(9)).toString());
                    json.name("durationMs").value(Math.max(0,c.getLong(9)-c.getLong(0)));
                }
                String profile = c.getString(10);
                if (profile != null && !profile.isEmpty()) json.name("profile").value(anonymous
                        ? Integer.toString(profiles.computeIfAbsent(profile,key -> profiles.size()+1)) : profile);
                if (!c.isNull(11) && !c.getString(11).isEmpty()) json.name("network").value(c.getString(11));
                if (!c.isNull(12)) json.name("ipVersion").value(c.getInt(12));
                String[] timings = {"tcpMs","proxyHandshakeMs","firstByteMs","dnsMs"};
                for (int i=0;i<timings.length;i++)
                    if (!c.isNull(13+i)) json.name(timings[i]).value(c.getLong(13+i));
                String stage = c.getString(17);
                if (stage != null && !stage.isEmpty()) json.name("stage").value(stage);
                json.endObject();
            }
        } catch (android.database.sqlite.SQLiteException e) { throw new Unavailable(e); }
        json.endArray();
        json.endObject();
        json.flush();
    }

    void close(String id, String result, long up, long down) {
        close(id,result,up,down,null);
    }

    void close(String id, String result, long up, long down, Metrics metrics) {
        long ended = System.currentTimeMillis();
        push(db -> {
            ContentValues values = new ContentValues();
            values.put("result", result);
            values.put("up", up);
            values.put("down", down);
            values.put("ended", ended);
            if (metrics != null) {
                if (metrics.tcpMillis() > 0) values.put("tcpMs", metrics.tcpMillis());
                if (metrics.handshakeMillis() > 0) values.put("handshakeMs", metrics.handshakeMillis());
                if (metrics.firstByteMillis() > 0) values.put("firstByteMs", metrics.firstByteMillis());
                if (metrics.dnsMillis() > 0) values.put("dnsMs", metrics.dnsMillis());
                values.put("stage", metrics.stage());
            }
            db.update("connections", values, "key=?", new String[]{id});
        });
    }

    void traffic(long up, long down) {
        pendingUp.addAndGet(up);
        pendingDown.addAndGet(down);
        schedule();
    }

    long revision() { return revision.get(); }

    private void push(Event event) {
        if (count.incrementAndGet() > EVENTS_PER_BATCH) {
            count.decrementAndGet();
            return;
        }
        events.add(event);
        schedule();
    }

    private void schedule() {
        if (scheduled.compareAndSet(false, true)) writer.schedule(this::flush, 350, TimeUnit.MILLISECONDS);
    }

    private boolean flush() {
        long up = pendingUp.getAndSet(0), down = pendingDown.getAndSet(0);
        try {
            SQLiteDatabase db = getWritableDatabase();
            db.beginTransaction();
            try {
                for (int i = 0; i < EVENTS_PER_BATCH; i++) {
                    Event e = events.poll();
                    if (e == null) break;
                    count.decrementAndGet();
                    e.apply(db);
                }
                long now = System.currentTimeMillis();
                if (up != 0 || down != 0) {
                    long minute = now / 60_000;
                    db.execSQL("INSERT OR IGNORE INTO traffic VALUES (?,0,0)", new Object[]{minute});
                    db.execSQL("UPDATE traffic SET up=up+?,down=down+? WHERE minute=?", new Object[]{up, down, minute});
                }
                if (now - lastTrim > 60_000) trim(db, now);
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
            revision.incrementAndGet();
            return true;
        } catch (RuntimeException e) {
            Log.w("ProxyRoute", "Could not write connection history");
            return false;
        } finally {
            scheduled.set(false);
            if (!events.isEmpty() || pendingUp.get() != 0 || pendingDown.get() != 0) schedule();
        }
    }

    private void trim(SQLiteDatabase db, long now) {
        db.execSQL("DELETE FROM connections WHERE ts<? OR row<=(SELECT COALESCE(MAX(row),0)-10000 FROM connections)",
                new Object[]{now - 7 * DAY});
        db.execSQL("DELETE FROM traffic WHERE minute<?", new Object[]{(now - 7 * DAY) / 60_000});
        lastTrim = now;
    }

    List<Connection> recent(String route, String text, int offset) {
        List<Connection> result = new ArrayList<>();
        String condition = switch (route) {
            case "proxy" -> "route='proxy'";
            case "block" -> "route='block'";
            case "errors" -> "route<>'block' AND " + ERROR;
            default -> "1";
        };
        String search = "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%";
        try (Cursor c = getReadableDatabase().rawQuery(
                "SELECT ts,app,protocol,target,route,result,up,down FROM connections "
                + "WHERE (" + condition + ") AND (app LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\') "
                + "ORDER BY row DESC LIMIT 100 OFFSET ?",
                new String[]{search,search,Integer.toString(offset)})) {
            while (c.moveToNext()) {
                result.add(new Connection(c.getLong(0),c.getString(1),c.getString(2),c.getString(3),
                        c.getString(4),c.getString(5),c.getLong(6),c.getLong(7)));
            }
        }
        return result;
    }

    private static final String ERROR = "result NOT IN ('active','closed','process stopped','VPN stopped','blocked by application rule','blocked by DNS filter','NETWORK_CHANGED')";

    Totals totals(long since) {
        try (Cursor cursor = getReadableDatabase().rawQuery(
                "SELECT COUNT(*), SUM(CASE WHEN route='block' THEN 1 ELSE 0 END), "
                + "SUM(CASE WHEN route<>'block' AND " + ERROR + " THEN 1 ELSE 0 END) FROM connections WHERE ts>=?",
                new String[]{Long.toString(since)})) {
            return cursor.moveToFirst() ? new Totals(cursor.getLong(0),cursor.getLong(1),cursor.getLong(2)) : new Totals(0,0,0);
        }
    }

    Chart chart(int widthMinutes, int columns) {
        long latest = System.currentTimeMillis() / 60_000 / widthMinutes;
        return chartFrom((latest - columns + 1) * widthMinutes, widthMinutes, columns);
    }

    Chart chartFrom(long firstMinute, int widthMinutes, int columns) {
        long[] up = new long[columns], down = new long[columns];
        long totalUp = 0, totalDown = 0;
        try (Cursor c = getReadableDatabase().rawQuery(
                "SELECT minute,up,down FROM traffic WHERE minute>=? ORDER BY minute",
                new String[]{Long.toString(firstMinute)})) {
            while (c.moveToNext()) {
                int i = (int)((c.getLong(0) - firstMinute) / widthMinutes);
                if (i >= 0 && i < columns) {
                    up[i] += c.getLong(1);
                    down[i] += c.getLong(2);
                    totalUp += c.getLong(1);
                    totalDown += c.getLong(2);
                }
            }
        }
        return new Chart(up, down, totalUp, totalDown);
    }

    void clear(Runnable finished,Runnable failed) {
        writer.execute(() -> {
            try {
                if (!flush()) { failed.run(); return; }
                getWritableDatabase().delete("connections", null, null);
                revision.incrementAndGet();
                finished.run();
            } catch (RuntimeException e) {
                Log.w("ProxyRoute", "Could not clear connection history");
                failed.run();
            }
        });
    }
}
