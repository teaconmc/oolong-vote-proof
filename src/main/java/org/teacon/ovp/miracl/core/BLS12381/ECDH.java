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

/* ECDH/ECIES/ECDSA API Functions */

package org.teacon.ovp.miracl.core.BLS12381;

public final class ECDH {
    public static final int INVALID_PUBLIC_KEY = -2;
    public static final int ERROR = -3;
    //public static final int INVALID = -4;
    public static final int EFS = CONFIG_BIG.MODBYTES;
    public static final int EGS = CONFIG_BIG.MODBYTES;

// Transform a point multiplier to RFC7748 form
    public static void RFC7748(BIG r)
    {
        int c,lg=0;
        BIG t=new BIG(1);
        c=ROM.CURVE_Cof_I;
        while (c!=1)
        {
            lg++;
            c/=2;
        }
        int n=8*EGS-lg+1;
        r.mod2m(n);
        t.shl(n);
        r.add(t);
        c=r.lastbits(lg);
        r.dec(c);
    }

    /* return true if S is in ranger 0 < S < order , else return false */
    public static boolean IN_RANGE(byte[] S) {
        BIG r, s;
        r = new BIG(ROM.CURVE_Order);
        s = BIG.fromBytes(S);
        if (s.iszilch()) return false;
        if (BIG.comp(s,r)>=0) return false;
        return true;
    }

    /* validate public key. */
    public static int PUBLIC_KEY_VALIDATE(byte[] W) {
        BIG r, q, k;
        ECP WP = ECP.fromBytes(W);
        int nb, res = 0;

        r = new BIG(ROM.CURVE_Order);

        if (WP.is_infinity()) res = INVALID_PUBLIC_KEY;

        if (res == 0) {

            q = new BIG(ROM.Modulus);
            nb = q.nbits();
            k = new BIG(1); k.shl((nb + 4) / 2);
            k.add(q);
            k.div(r);

            while (k.parity() == 0) {
                k.shr(1);
                WP.dbl();
            }

            if (!k.isunity()) WP = WP.mul(k);
            if (WP.is_infinity()) res = INVALID_PUBLIC_KEY;
        }
        return res;
    }

    /* IEEE-1363 Diffie-Hellman online calculation Z=S.WD */
    // type = 0 is just x coordinate output
    // type = 1 for standard compressed output
    // type = 2 for standard uncompress output 04|x|y
    public static int SVDP_DH(byte[] S, byte[] WD, byte[] Z, int type) {
        BIG r, s;
        int res = 0;

        s = BIG.fromBytes(S);
        ECP W = ECP.fromBytes(WD);
        if (W.is_infinity()) res = ERROR;

        if (res == 0) {
            r = new BIG(ROM.CURVE_Order);
            W = W.clmul(s,r);
            if (W.is_infinity()) res = ERROR;
            else {
		        if (CONFIG_CURVE.CURVETYPE!=CONFIG_CURVE.MONTGOMERY)
		        {
                    if (type>0) {
                        if (type==1)
                            W.toBytes(Z,true);
                        else 
                            W.toBytes(Z,false);
                    } else {
                        W.getX().toBytes(Z);
                    }
                    return res;
                } else {
                    W.getX().toBytes(Z);
                }
            }
        }
        return res;
    }

    /* constant time n-byte compare */
    static boolean ncomp(byte[] T1, byte[] T2, int n) {
        int res = 0;
        for (int i = 0; i < n; i++) {
            res |= (int)(T1[i] ^ T2[i]);
        }
        if (res == 0) return true;
        return false;
    }
}
