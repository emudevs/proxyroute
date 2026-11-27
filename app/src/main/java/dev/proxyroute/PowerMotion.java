package dev.proxyroute;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.view.View;
import android.view.animation.LinearInterpolator;

final class PowerMotion extends View {
    private final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);
    private final int color;
    private final boolean busy,stopping,active;
    private float progress;
    private ValueAnimator animator;

    PowerMotion(Context context,int color,boolean busy,boolean stopping,boolean active) {
        super(context);
        this.color=color;
        this.busy=busy;
        this.stopping=stopping;
        this.active=active;
        setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO);
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeCap(Paint.Cap.ROUND);
    }
    @Override protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        if(!ValueAnimator.areAnimatorsEnabled())return;
        animator=ValueAnimator.ofFloat(0f,1f);
        animator.setDuration(busy?920:510);
        animator.setInterpolator(busy?new LinearInterpolator():FigmaUi.EASE_OUT);
        if(busy)animator.setRepeatCount(ValueAnimator.INFINITE);
        animator.addUpdateListener(value-> {
            progress=(float)value.getAnimatedValue();
            invalidate();
        });
        animator.start();
    }
    @Override protected void onDetachedFromWindow() {
        if(animator!=null)animator.cancel();
        super.onDetachedFromWindow();
    }
    @Override protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if(animator==null || (!busy && progress>=1))return;
        float width=getWidth(),center=width/2f;
        float radius=busy?width*.425f:width*(active?.30f+.15f*progress:.45f-.15f*progress);
        paint.setStrokeWidth(width*(busy?.035f:.045f));
        paint.setColor(color);
        paint.setAlpha(busy?240:(int)(165*(1-progress)));
        if(busy)canvas.drawArc(center-radius,center-radius,center+radius,center+radius,
                -90+(stopping?-1:1)*progress*360,stopping?90:115,false,paint);
        else canvas.drawCircle(center,center,radius,paint);
    }
}
