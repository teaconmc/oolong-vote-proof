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

/* Boneh-Lynn-Shacham signature 128-bit API Functions */

/* Loosely (for now) following https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-02 */

// Minimal-signature-size variant

package org.teacon.ovp.miracl.core.BLS12381;

public class BLS {
    public static final int BFS = CONFIG_BIG.MODBYTES;
    public static final int BGS = CONFIG_BIG.MODBYTES;
    public static final int BLS_OK = 0;
    public static final int BLS_FAIL = -1;

    public static int ceil(int a,int b) {
        return (((a)-1)/(b)+1);
    }
}
