package dev.proxyroute;

import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.animation.PathInterpolator;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

final class FigmaUi {
    static final int BG=0xff09090b, PANEL=0xff18181b, TILE=0xff27272a, RIM=0xff3f3f46;
    static final int TEXT=0xfff4f4f5, LIGHT=0xffd4d4d8, MUTED=0xffa1a1aa, FAINT=0xff71717a;
    static final int LIME=0xffbbf451, SKY=0xff00bcff, RED=0xffff2056, ROSE=0xffff637e;
    static final int AMBER=0xffffd230, PINK=0xffed6bff;
    static final PathInterpolator EASE_OUT=new PathInterpolator(.2f,0f,0f,1f);
    private final Context context;
    private final Typeface regular, medium, semibold, mono;

    FigmaUi(Context context) {
        this.context = context;
        var resources = context.getResources();
        regular = resources.getFont(R.font.inter_regular);
        medium = resources.getFont(R.font.inter_medium);
        semibold = resources.getFont(R.font.inter_semibold);
        mono = resources.getFont(R.font.jetbrains_mono);
    }

    int dp(float value) { return Math.round(value * context.getResources().getDisplayMetrics().density); }
    LinearLayout column() { var result=new LinearLayout(context); result.setOrientation(LinearLayout.VERTICAL); return result; }
    LinearLayout row() { var result=new LinearLayout(context); result.setGravity(Gravity.CENTER_VERTICAL); return result; }
    TextView text(CharSequence value, int size, int color, int weight) {
        TextView view=new TextView(context);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setTypeface(weight>=600 ? semibold : weight>=500 ? medium : regular);
        view.setIncludeFontPadding(false);
        view.setLineSpacing(dp(2), 1);
        return view;
    }
    TextView terminal(CharSequence value,int size,int color) {
        TextView view=text(value,size,color,400);
        view.setTypeface(mono);
        return view;
    }
    void pad(View v,int x,int y) { v.setPadding(dp(x),dp(y),dp(x),dp(y)); }
    void add(LinearLayout root,View child,int width,int height,int top) {
        LinearLayout.LayoutParams params=new LinearLayout.LayoutParams(width < 0 ? width : dp(width), height < 0 ? height : dp(height));
        params.topMargin=dp(top);
        root.addView(child,params);
    }
    void gap(LinearLayout parent,int length) {
        boolean horizontal=parent.getOrientation()==LinearLayout.HORIZONTAL;
        add(parent,new View(context),horizontal?length:1,horizontal?1:length,0);
    }
    void weight(LinearLayout row,View view) { row.addView(view,new LinearLayout.LayoutParams(0,-2,1)); }

    GradientDrawable background(int color,int radius,int border) {
        GradientDrawable drawable=new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(radius));
        if(border!=0) drawable.setStroke(dp(1),border);
        return drawable;
    }
    void action(View view,int fill,int radius,int border,Runnable run) {
        view.setBackground(new RippleDrawable(ColorStateList.valueOf(0x2a9f9fa8),background(fill,radius,border),null));
        view.setOnClickListener(v->run.run());
        pressMotion(view);
    }
    private void pressMotion(View view) {
        view.setOnTouchListener((target,event)->{
            if(!ValueAnimator.areAnimatorsEnabled())return false;
            float scale;
            int duration;
            switch(event.getActionMasked()) {
                case MotionEvent.ACTION_DOWN -> {scale=.975f; duration=80;}
                case MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {scale=1f; duration=150;}
                default -> {return false;}
            }
            target.animate().scaleX(scale).scaleY(scale).setDuration(duration)
                    .setInterpolator(EASE_OUT).start();
            return false;
        });
    }
    void surface(View view,int fill,int radius) { view.setBackground(background(fill,radius,0)); }
    TextView pill(String title,int font,int color,int fill,int height,Runnable click) {
        TextView view=text(title,font,color,600);
        view.setGravity(Gravity.CENTER);
        view.setMinHeight(dp(height));
        pad(view,12,0);
        if(click==null) surface(view,fill,100);
        else action(view,fill,100,0,click);
        return view;
    }
    ImageView icon(int asset,int color) {
        ImageView view=new ImageView(context);
        view.setImageResource(asset);
        view.setImageTintList(ColorStateList.valueOf(color));
        view.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        return view;
    }
    FrameLayout iconBox(int asset,int color,int fill,int dimension,int glyph,int radius,String name,Runnable click) {
        FrameLayout box=new FrameLayout(context);
        FrameLayout.LayoutParams params=new FrameLayout.LayoutParams(dp(glyph),dp(glyph),Gravity.CENTER);
        box.addView(icon(asset,color),params);
        box.setLayoutParams(new ViewGroup.LayoutParams(dp(dimension),dp(dimension)));
        if(click == null) surface(box,fill,radius);
        else {
            box.setContentDescription(name);
            action(box,fill,radius,0,click);
        }
        return box;
    }
    EditText field(String hint,String value,int type) {
        EditText view=new EditText(context);
        view.setTextColor(TEXT);
        view.setHintTextColor(FAINT);
        view.setTextSize(15);
        view.setTypeface(regular);
        view.setInputType(type);
        view.setSingleLine(true);
        view.setTypeface(regular);
        view.setHint(hint);
        view.setText(value);
        view.setIncludeFontPadding(false);
        pad(view,16,0);
        view.setBackground(background(PANEL,16,TILE));
        view.setOnFocusChangeListener((v, focused)->v.setBackground(background(PANEL,16,focused?LIME:TILE)));
        return view;
    }
    void separator(LinearLayout parent) {
        View rule=new View(context);
        rule.setBackgroundColor(TILE);
        parent.addView(rule,new LinearLayout.LayoutParams(-1,dp(1)));
    }
    Toggle toggle(String name,boolean checked,Runnable click) {
        return new Toggle(name,checked,click);
    }

    final class Toggle extends View {
        private final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);
        private final ArgbEvaluator colors=new ArgbEvaluator();
        private final String name;
        private ValueAnimator motion;
        private boolean checked;
        private float fraction;

        Toggle(String name,boolean checked,Runnable click) {
            super(context);
            this.name=name;
            this.checked=checked;
            fraction=checked?1f:0f;
            setContentDescription(name+(checked?", включено":", выключено"));
            setLayoutParams(new LinearLayout.LayoutParams(dp(52),dp(32)));
            if(click!=null)setAction(click);
        }

        void setAction(Runnable click) {
            setForeground(new RippleDrawable(ColorStateList.valueOf(0x339f9fa8),null,background(0xffffffff,100,0)));
            setOnClickListener(view->click.run());
            pressMotion(this);
        }

        void setChecked(boolean value) {
            if(checked==value)return;
            checked=value;
            setContentDescription(name+(checked?", включено":", выключено"));
            if(motion!=null)motion.cancel();
            float target=value?1f:0f;
            if(!isShown()||!ValueAnimator.areAnimatorsEnabled()) {
                fraction=target;
                invalidate();
                return;
            }
            motion=ValueAnimator.ofFloat(fraction,target);
            motion.setDuration(190);
            motion.setInterpolator(EASE_OUT);
            motion.addUpdateListener(animator-> {
                fraction=(float)animator.getAnimatedValue();
                invalidate();
            });
            motion.start();
        }

        @Override public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setClassName(android.widget.Switch.class.getName());
            info.setCheckable(true);
            info.setChecked(checked);
        }

        @Override protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            float width=getWidth(),height=getHeight(),radius=height/2f;
            paint.setColor((int)colors.evaluate(fraction,RIM,LIME));
            canvas.drawRoundRect(0,0,width,height,radius,radius,paint);
            float border=dp(1);
            paint.setColor((int)colors.evaluate(fraction,TILE,LIME));
            canvas.drawRoundRect(border,border,width-border,height-border,radius,radius,paint);
            float x=dp(14)+(width-dp(30))*fraction;
            paint.setColor((int)colors.evaluate(fraction,MUTED,BG));
            canvas.drawCircle(x,radius,dp(8)+dp(4)*fraction,paint);
        }

        @Override protected void onDetachedFromWindow() {
            if(motion!=null)motion.cancel();
            fraction=checked?1f:0f;
            super.onDetachedFromWindow();
        }
    }
}
