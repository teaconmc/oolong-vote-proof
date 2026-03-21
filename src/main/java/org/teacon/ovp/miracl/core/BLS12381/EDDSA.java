/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* EDDSA API Functions */

package org.teacon.ovp.miracl.core.BLS12381;

public final class EDDSA {
    public static final int INVALID_PUBLIC_KEY = -2;
    public static final int ERROR = -3;

// Transform a point multiplier to RFC7748 form
    private static void RFC7748(BIG r)
    {
        int c,lg=0;
        BIG t=new BIG(1);
        c=ROM.CURVE_Cof_I;
        while (c!=1) {
            lg++;
            c/=2;
        }
        int n=8*CONFIG_BIG.MODBYTES-lg+1;
        r.mod2m(n);
        t.shl(n);
        r.add(t);
        c=r.lastbits(lg);
        r.dec(c);
    }

    // reverse first n bytes of buff - for little endian
    private static void reverse(int n,byte[] buff) {
        for (int i=0;i<n/2;i++) { 
            byte ch = buff[i]; 
            buff[i] = buff[n - i - 1]; 
            buff[n - i - 1] = ch; 
        }    
    }

    // dom - domain function
    private static byte[] dom(String pp,boolean ph,byte cl) {
        byte[] PP = pp.getBytes();
        int len=PP.length;
        byte[] dom = new byte[len+2];
        for (int i=0;i<len;i++ )
            dom[i]=PP[i];
        if (ph) dom[len]=1;
        else dom[len]=0;
        dom[len+1]=cl;
        return dom;
    }

// encode integer (little endian)
    private static int encode_int(BIG x,byte[] w) {
        int b,index=0;
        if (8*CONFIG_BIG.MODBYTES==CONFIG_FIELD.MODBITS) index=1; // extra byte needed for compression        
        b=CONFIG_BIG.MODBYTES+index;

        w[0]=0;
        x.tobytearray(w,index);
        reverse(b,w);
        return b;
    }

// encode point
    private static void encode(ECP P,byte[] w) {
        int b,index=0;
        if (8*CONFIG_BIG.MODBYTES==CONFIG_FIELD.MODBITS) index=1; // extra byte needed for compression        
        b=CONFIG_BIG.MODBYTES+index;

        BIG x=P.getX();
        BIG y=P.getY();
        encode_int(y,w);
        w[b-1]|=x.parity()<<7;
    }

// get sign
    private static int getsign(byte[] x) {
        int b,index=0;
        if (8*CONFIG_BIG.MODBYTES==CONFIG_FIELD.MODBITS) index=1; // extra byte needed for compression        
        b=CONFIG_BIG.MODBYTES+index;  
        if ((x[b-1]&0x80)!=0)
            return 1;
        else 
            return 0;
    }

// decode integer (little endian)
    private static BIG decode_int(boolean strip_sign,byte[] ei) {
        int b,index=0;

        if (8*CONFIG_BIG.MODBYTES==CONFIG_FIELD.MODBITS) index=1; // extra byte needed for compression        
        b=CONFIG_BIG.MODBYTES+index;

        byte[] r=new byte[b];

        for (int i=0;i<b;i++)
            r[i]=ei[i];
        reverse(b,r);

        if (strip_sign)
            r[0]&=0x7f;

        return BIG.frombytearray(r,index);
    }

// decode compressed point
    private static ECP decode(byte[] W) {
        ECP P=new ECP();
        int sign=getsign(W); // lsb of x
        BIG y=decode_int(true,W);
        FP one=new FP(1);
        FP hint=new FP();
        FP x=new FP(y); x.sqr(); 
        FP d=new FP(x); 
        x.sub(one);
        x.norm();
        FP t=new FP(new BIG(ROM.CURVE_B));
        d.mul(t);
        if (CONFIG_CURVE.CURVE_A==1) d.sub(one);
        if (CONFIG_CURVE.CURVE_A==-1) d.add(one);
        d.norm();
// inverse square root trick for sqrt(x/d)
        t.copy(x);
        t.sqr();
        x.mul(t);
        x.mul(d);
        if (x.qr(hint)!=1)
        {
            P.inf();
            return P;
        }
        d.copy(x.sqrt(hint));
        x.inverse(hint);
        x.mul(d);
        x.mul(t);
        x.reduce();
        if (x.redc().parity()!=sign)
            x.neg();
        x.norm();
        return new ECP(x.redc(),y);
    }
}
