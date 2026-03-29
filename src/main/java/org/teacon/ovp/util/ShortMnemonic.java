package org.teacon.ovp.util;

import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.random.RandomGenerator;
import java.util.zip.GZIPInputStream;

public final class ShortMnemonic {
    private final char[] mnemonicChars;

    public ShortMnemonic(RandomGenerator randomGenerator) {
        var entropy = new byte[16];
        randomGenerator.nextBytes(entropy);
        var hash = Hashing.sha256().hashBytes(entropy).asInt();
        var bits = new boolean[132];
        for (var i = 0; i < 16; ++i) {
            for (var j = 0; j < 8; ++j) {
                bits[i * 8 + j] = (entropy[i] & (1 << (7 - j))) != 0;
            }
        }
        for (var i = 0; i < 4; ++i) {
            bits[128 + i] = (hash & (1 << (7 - i))) != 0;
        }
        var sb = new StringBuilder();
        for (var i = 0; i < 132; i += 11) {
            var index = 0;
            for (var j = 0; j < 11; ++j) {
                index = (index << 1) | (bits[i + j] ? 1 : 0);
            }
            if (i > 0) {
                sb.append(" ");
            }
            sb.append(WORDS.get(index));
        }
        var chars = new char[sb.length()];
        sb.getChars(0, sb.length(), chars, 0);
        this.mnemonicChars = Arrays.copyOf(chars, chars.length);
    }

    public ShortMnemonic(char[] mnemonic) {
        var sb = new StringBuilder(mnemonic.length).append(mnemonic);
        var words = SPLITTER.splitToList(sb);
        if (words.size() != 12) {
            throw new IllegalArgumentException("Must be 12 words");
        }
        sb.setLength(0);
        var bits = new boolean[132];
        for (var i = 0; i < 12; ++i) {
            var word = words.get(i).toLowerCase(Locale.ROOT);
            var index = WORDS.indexOf(word);
            if (index == -1) {
                throw new IllegalArgumentException("Unknown word: " + word);
            }
            for (var j = 0; j < 11; ++j) {
                bits[i * 11 + j] = (index & (1 << (10 - j))) != 0;
            }
            if (i > 0) {
                sb.append(" ");
            }
            sb.append(word);
        }
        var entropy = new byte[16];
        for (var i = 0; i < 16; ++i) {
            for (var j = 0; j < 8; ++j) {
                if (bits[i * 8 + j]) {
                    entropy[i] |= (byte) (1 << (7 - j));
                }
            }
        }
        var hash = Hashing.sha256().hashBytes(entropy).asInt();
        for (var i = 0; i < 4; ++i) {
            var expected = (hash & (1 << (7 - i))) != 0;
            if (bits[128 + i] != expected) {
                throw new IllegalArgumentException("Checksum failed");
            }
        }
        var chars = new char[sb.length()];
        sb.getChars(0, sb.length(), chars, 0);
        this.mnemonicChars = Arrays.copyOf(chars, chars.length);
    }

    public char[] chars() {
        return this.mnemonicChars.clone();
    }

    private static final List<String> WORDS;
    private static final Splitter SPLITTER = Splitter.on(CharMatcher.whitespace()).trimResults().omitEmptyStrings();
    private static final String WORDS_GZIP_BASE64 = "H4sIAAAAAAACAy2baZa0rBKE/99V1NYcUOlS8GMou3r1N57gPX0qEhURkiQn6Gme" +
            "0prTa5rjGdtX9AyC3Bv4oVxD4qLmMkNamRZf97KK9Ko6yxJqhcTVlZcl90HH4yMGmtJjQe61xUWF/3os3C3ZL1O/RfqytFzAMlptfTpf" +
            "0zrdqrGu/OLi4ni+/qhBkSuC/QQ/U1oCNEJCyTNf3LYpFkim61uZ6M8+RX1yD/zo816CykeY9CxeL78Ry52LnsUKd86p6P45d3DJR1bv" +
            "zsDzMwa1dXJ9hi+YH+GV6eCZEy/fxyQsap8KNQta0DfOZ/pqNNfUQi/Qv5h20TzQ/LzETnUrTeeXFtNywKi0RPc87bSTdvqY9qLmU7xg" +
            "XXr7VlIjiwtmaMrt8Av1MWkhpQka/+vU+o0BgUj63ROju/OZd67uMBUIrd53sZjcJarNshyA51dDBGiz7LQI18rFAMpFv8ulxoo6xZ1C" +
            "96GBkZUSP76Cf3y7tLBZREqLrtCeXN6vqfK7A09qnTz5tQaj69XaLzVU23GpH+04Q9Nly+pKa9PyhgQ60FpsfeXZPwHv/4Sxr8hV3y1k" +
            "noXezPbeMtAvVfqEYhH65GVaMxTReqZ3AItRg31CzXTn2bqY9bz1SNV+Y33N0/wVLEc41bYK+vQ8rWpznnb9Tgv0jLwlKkrG5umacxZJ" +
            "+oOkwJv+hZNKxbI9w1SqVxqomhrhWzyaNVZN4Rz0WTABXXM+h2Vi4YrS3TmETaBVQ3mnyXBoyJAo3s3h9PoW1XQJ1XRIbjOFLXJVATGW" +
            "thviLvKEQEvfTBNx+S70JVJ+U/DdIXFzLFyUpibjeP1k7oSaMeFlTB7UOfGxM0w8R0HMp9s6czZWTQHUAzy7gQZ7VeuZCRGqhaz1OWcJ" +
            "9ZyvWaDFK+hqL+c3wGekSOhNLqxVEeR1Rp3NuSFk81hyc/7VT+1JtNzJ4omRzK8g9YsZiloAwx8XkTGWaCkokUkocT943Z8rsfI8S9ue" +
            "kcIbhpac/HLm82WscdGHRx5jn9Hxc18ZYFfjarBLNZ6SpR5Pfb+fM/AGTj9Oq18Rh9WYFD8f6mUfVzACvvQakxneKy2Piepf49/fa5nm" +
            "mUUiqsEvtjQL2r2K+P4bkGQLLsGlRQW5BbwgtQcuwUS9X9BpfpJ5M30mmkpf37v/feCOze/dbfJnC7/ZVTTXgj2Dt8YpUmi1UKy8LH4J" +
            "YqJKbW6vdjdHFTWcd+hCtRb27NfbqNiZqrGQhFYmC5O8BJlazZ/GEagfLrT3ElKFEyp335UonJDR7QM7JNSkCK/brR3WmSK5gjcMFy3j" +
            "ZjWqZdmyG1x4NwTflzAJPNyD1SkTvSA+mGoeIQfCKwVqZMyoSPa7kjApkeXoC3ZFNNFwL3o77vA3ypBcdDAWFvUSW/yjbRyMJX60ppYT" +
            "2yq8gRK3L/QBKKGLhFLwwg+jOlkLy2lDJ7JtoNal0J05Iy1lV2JOTnf1lPiDfQUfGu2805EprXgz7OyevzwNhBlZWrZDpV6WvG0BQrcz" +
            "c5G1KBaeoqqFWAApSkk11S7Dhr8gSt/yZWbk68aYqmlmFbp2N5O2KNMoutuhUSGN9lONqBcVWsl8PX0i6mRBAwm4JWNMjZuGCxKDlhbw" +
            "Qel9t+MhSR9xr3uUsmNMfe7YcJFSTaqHZ4bnb5alXFBYIOtfZGvgBSTfYIGUyXws03OCf2pYwkulgO0UCbQRNL2oNBZaibBJCuwGcRfk" +
            "BVJGdwrdSyktzVvpS2RcpQdjpKulX17dpSfX7O4HH5ZjRO0+66ncgQ43+s1vKPell5hZaF3cQZj6vxXWC2tTDXlpSTakP5cOD2yZVinm" +
            "VV7ZTlHis9ogr8PpWidr5BV2rF74vimBWyXPKyt5DTK3AaJRiyyYLpFwzdQNuM6QEykSzWVUh5WVgmtt0hJcbKPWRuN2WNdw+ktn/Lji" +
            "hWkRia6eonuQ7DuJUtM+nUhwxTvX6EstGCFegEQPJ2wNVVM0uxD8So17gryBG8UkKgnlFfGSLzUEb9XSPTWrougPEURqjXKxJR2r+xRR" +
            "FCtUs7e6WtR3eCI5WbXQGU7crcRFEzpkjWe45M+t0T6PSJbvR8ECLwLU4cqrMERahcHKyCzFKt5U6LDhKtxmoVg0phZO0s7HMxM/ufju" +
            "n+R7zQ5RRLqV9yqVs0otALd8ItFrMkmexSzDyVvJLxnoSO4I8Yr/vHptCXdJnwij0+piZYg+AlbUiHhW6UvqRj4owXuDN+CG4LjWh0Cf" +
            "lI4WSFGuHYnpQ07xZVervdUzLT90e61faW19L0yItFB9k6MvT1KYAMmGOBh9Ry0IVJJZEAxHTTRlefUBl8WLP6gHsCBs1ohh31/BPkyI" +
            "9kzCOctlCufqsmav0IMz7IpDoGavqKKmUfhMcF5yTqOnuKgFNMlQiOCxiUhlcTdgBsOVbXjDdZ+Zp3cm2BHVsBWawH8RCQ3LIODmiMGi" +
            "GY0o95XBSMYYW9osASHtKAER1mBIh6UlpB/aTycrLCjS2sWrpMGYIBrY90JFdANLcVwU3vI60eUtaZSwhf/wMYSaVXwg/ehN8TOpSI9I" +
            "vqbaKV1RsVboxOuKgL5gcI8kx/BIn8NxCk0WXkNDmv0YM6wV+aaYT0lO+DUffqXd4MqvY3qR4WWoYJb/yl6upjg24TdYR4qWJfrGMSFd" +
            "onFm/n+jGzNbfn0jI9Th90ZDiQR/9DY7frUEtWxEs9u6y+iDQzQRePEN/PBoX9uEjyyi8Qik7r+iKxdR0iKUxG54lILK7cuABG/E1FUk" +
            "8Vu4kRoCvRGnbtOwA9tEM+geIfIqEglmN8eamwK9Alu2MNnUbOpYR5VtQRLNa4GbinkFXCke5wYzsGmG4sd1WImbHZ1NVnKLmIQtjgB0" +
            "i1odwt3tw03BBTTXYnI3IhzbBME+bqPltuh3GFDETd+kC13dz7hu9ti3+PvaTgWam2MpIRVOBn8yRBHGcXrlbvha25n9FI9L6CpeWtvZ" +
            "FcNtDqc2+JyltzYpSn1FWnLDjdoyI8rOjmyEZQI15uVFlFl9QWCyEeSjOdBeop22isPmTa6C27IXtzmNsCnO2qRDzaXioRQtI3SICvRI" +
            "YRT1UIM8pEdyZ3mMl7Q5ThLirm7yNXQLt2PriZ/s5iY31+KGk751T/o+OYhysL0rUv/9Quzc7/Rhl5crvxitITL/o8RQInJsIdZzu+IX" +
            "/ajdqGOJ2+VPcKGgbkcVaf5Eo/gpUnyTeEOkIwC7uOdOHQxoj6jNHXuxxx2Nvg8B2aMMzsZlUXsYjl3BNIBoihSjZGM/sX/C667QPBvl" +
            "HQkZ4pn9tuZyJ5zeEYw9ryuCtTPTO1O8O3hQhCSrNYnWW3zdmUMNF/ssbsB8+QYzQC8cJQsZQkHD7Y6VhR/cAJl3PlXII+wKkwEFL0Lu" +
            "5sUTIF/yBtW7QvZm7wiPljANdQ9NQS/35WKIL5rp/Xu9jgnt5ahLQdcmuGRRIBa3A+WliEtu90E0yZ3CnSIhE36QYYIv50mO6XkL/lyF" +
            "CF9wSjUd2FTwo2awmYfk8Rj28QhaHuAVfHELkn5FN+OK8ByqJ5B2O9B2hxh5sN4P6Vom5sjzDC74HgcTIQhAxCs9xvo7CFiOnFwnU+fm" +
            "WtNxZJuYw6ZQ0jQCaYvVIUeOYucxautQWHUgp0eX5wliWUVoQCtTkQCUpOTBLChaXF2h+A5c6HU2U79kPF54gpEkmGZoejmtTJAYeUte" +
            "IEEOI9dProKpFVm0gx6vaNsXNWf4y6LoD0kwFk4k++bIXIp2jEMkkhDYvInCF5Hhfku/hl8w2ptRAZUnIlunEcSE9YCcpKYjrsIlcqDt" +
            "RQIiKZXc8Hlj+gmu9NP96jVaxJMVZjIAKsgFF5Iip04l3BIZLxIWQmw0RRsmTjLg0eFfIH0qZMFnlD/RHxmWPhYYW0/4LY/jdAdq1eJV" +
            "LfX7g/j8jFTVz8SKEeH39/f6kehiOEUTeErH/4RH4vCTZ/20Yn9wKn4kHAgVbtEPWSYhk/pD7P3TnaUWiWLjDwkEJ/HfcjWmkvPrzZoW" +
            "3AIZxw79vt4kAd6SDv2SrxPltMvdFtX8v8Vn/RbWypshv8kXUn7i651kxN4pbiCGS/i8Tukb/TQAoXojNYgzepKfP0lJnYR74pX4sHN1" +
            "t8x18UVz1aZRn8R9YMLxltmcXmQ0TqJAQcWYKMBwfYUQp/QA5TBtgNabUHODD4z+PoN0toT7NQRciOE6Q6zjKSmFc9xKu3SJSBXkGyWD" +
            "F+vnzsGRQlELCrEEci2kOkULborE1SvkhCknZmLY+JMcrBMsJ4tJqCk6cUfO+B8G3n6unHBMDzGnwOpNboFBFfNsVSkXgf7Db8UIsnbs" +
            "g0hoTjY2ZEfEy0w3udN5t2OabVTksvOqYhg97Lv97rM7YD57moxatGf/ZSWd34KHe7HdpNVyqSPSBvqgMEmSL7Z7LuJTx2bX9KPZvpjh" +
            "S8p94jZ3E18hfGZViO4ZtM8t2l0PB/mS3h9EXRDubrOMT5e3P1hKHK0pVr4wXQJ4cjllyMIv0Q02XxW5YdfURo3feMnbubD7l2RFknqR" +
            "FhNYAi5s3xXwzhliWGlHIdckPImELvLw10gviLCkcTI8DvkKgrJwCzm+rKAu5wMv/KSLWMIPmttth0zDJbvDiLX4LCTyo9+A5eKKxI4X" +
            "K1Iw+h6Jd4VECJccjsVv26qQmOBjLNqLkJtpYPjxN9DCrxfBlWdcuUuBzwliAi6tdf3QkloDkWjwGvG1yOCuHDoNIdMr58Su7LZKIvi9" +
            "cpUESzdeIzf+L0IUcUuyTpYO7w9cSKEgCklJXX3beNjplAKAeEuQr149ML3AoOX4OveuAgxBrV3dW5jXtwa5EiIW9+urXqaJxZNwE9N0" +
            "S5eJeBchSVK+Qncujegise+WyOMmQookzdD8etidkUz/guqkcFlxhCyKH1ae+Oc9sxR6gyvJAUcKTxX86jnqecxsyoh2ykR0CugjijPJ" +
            "O/DNwloRoffZFdo0qjfDAZcTUR6XqB7UbOqkdfW9sX6TU44kWfP0fsmn/ApsF/XpKMmT9lgYs6iHkWfPS54/Tt/lRU+FLAmSMbSZFbW/" +
            "8rbxCy7RhbxhAAg78ltuD35QtsbK5/e6NUUZBUdS9sUej0RKDM/JeTgRvXHz/k0gnu84Ht92IfLt2clj7zIXXEYFMXYFR1ZJqABNk61w" +
            "hp4WJ7BFdsdtuZDXeMmlcqZgCGTuzd6F6LjCFRCx1c8EjGJqetnvwmPWj9Lvd+euheuV/xiL3Z178qq9Wc5O1t0KURbKiiIJwidQs3Rb" +
            "kwjdi3u6jYV4+p6cK71JtNzIp8uSzxuldlub3SgxQRw1nbG+rcySKKvpxr7d09dr9w7uhOav+6IAdfITWSVxBbbrNxHViy6awVv2jbEE" +
            "Z73125AYUaZQBKPHRs59ePhyU7PQ2ZP7+Go9inm3QiLdjYtHG4e1vWOgN3HnF2gF71LASLF9bLiQgr3jTT152Dz2uOPfn1g4eCo3gc+f" +
            "I3N327NyWlHddi9Op8ZubBq4AwjPneV4CfRyxpu/5ZUVkEdYaRGp1pvd35vM/53ltrpKsRA6gfuvUOPs9yrtyBPOEOucG6mBn/lBPEc2" +
            "7GbD259QwEUnydvD1xI2PyZX7Ns+CiLaaKJIf/hyvIp0Ci+kXXQ8ITviS89MiR8zpMQ/ECVzQZ1pEl27W8qkJkScJha1WhC9sl/OeQPv" +
            "MZBCJEknc/tXTU4Enr3702fi67uvK0pJHDuB+zVc/lu+KCr3thtx9xsR6wR1dy9jB00Fj6AXr/jbausmucGqvPvfH5z+qqdyLkjbUVs0" +
            "NdkC0cJq/K+T6hEHZHg075gf4E/AkBTxojkKx2ZUybGv91209jTDwpiF6pwD4jFJ0uDSTQXftHAQBMQNHrpI0bL6U5g27yOUkUtgk5kG" +
            "Hv3+pGLGKRTvNBLn8PGAJyz0TnAJ3o8VCWhMUcS/sDvhh94ZKcHzJmGxESrBwY8Ia76EPbpZhek82y20JfyMquf0C3ptFI4RbC+fXSjB" +
            "PprIcGBUwLMQye5HWn1TxutlzVSCtTSSGnlw4x2JeFWKknsmE0TAJDFeuklwlKoCzqyIQhZXr1pm7lAlyaeOj9daGa02tjpL6GmM7DPY" +
            "JyeBzjg3VQ7ZdvEgzvzYbPYisZL3Qhmb+iVufN8mF5OgFxFTLRuufb7Ge/wSQfyH4mxh8Q5Pwc8u3q3UOsrG7gtHbVosTuR4sQje0WV1" +
            "CSku2eFxcZZ6HMApWBshDnfps3lOIFykogruTumJH8dYSsd9qOpAHbZFxNF3nTYuIg9PPz4JUypHn8AG8J2Kv1NHorkShVbZjSrnTjTX" +
            "I4oiUkJ7oRXDQW6b7GUAE1BctLtcFcZwdYTLBA1ZORZFK4uczFzUPYmtN85V0OKti1YJSKzJHtfte31+1TDxw7GvY1lUZr6yvbFCkGVi" +
            "cTcWlqEjKj5ZZa+zht02rnpHA6LeIMESfalQYt7qsAt9OvooBzxUiLfKqrg52naAJaIIuKJvX/VwLCCiYE3oJI4ozDjowOGvkXKQJyRe" +
            "kj0WcW18mkqiSIAUVbJDILfJwQp5yHIRdm/LVFI8Qul2niER9ZAjTMcODTvOPs5QUW32UWoMTJrF2nuFVU487CBeEJy8dPr7ChrQB6IW" +
            "Be9u19FaYbDR3kxF/hEbBQgV21HfvnRuQCTyY9QocwG9f6PrK8G94BKQTKjn0BzVFrU6s1lHxCtCrYybVjH71Yx1HrteaEEhDV9EJPUi" +
            "xyHkgEFNKGshtxIylcx73N6auZa3ylezd7KreZ7ld9XMrNjSC9foOuoUOA6MVOdrODSGQ1MJmWv2fUK16nnSNAFIJrnOf1pMhK7dKMBq" +
            "+11xzvj+TUpCVlOON0fnxj0L723Z8ZZwVQjhl8yp2wcRRN6+4PVIyFjv04h7ba2JaN/uoXWuEODgl5DUZ72t46qMbMU+BojPOxGW+aRa" +
            "HfGEyBplRUXhZrMmUBDASm7YPTZqV5APWaMJ1WzzyFpwU4EGmHrSYvmFX8ZDi0tzT5rno2USB1AY3axAnEYVMgUNO7pzKX3B94p5ITfX" +
            "bWhV7O5z9wlYUfd55EEVyYF9BDiiuKsiKNPax+HZSnxZuzO7tTuAqZ3TNEJy+i8nkGp3Grp2KrEfIeS4Y+23b98EpCLFehDPVuD9scpx" +
            "LRBnzIWh+CvnHnhnnKIUdZxVn3+a5TGnn8kgu14ffHUhX32sVh5WzmNePnaJ64N/UL/XDBcVZXGWon4L0vn1lIwZ5gCmyf7yuYE2WU80" +
            "TjlpboGbx94KaiRRGvkTYdMEifzGV/PpxcbueEN6Cfb0I5DgQGusEMqFCpWSYt12uHky9M02o5ExFDDjzZIvpMiwhGrmyD7R1Q5OFQjx" +
            "iETEpEa+G7RyaeOMS0O5tLj7zsm1PZnGyRcJntqWHsazWIVOvraIsm826opocQdFydULZWf1cua5uHH4InI4r/nYH+LbqH6NQ4gWYwF7" +
            "lSJWcRbqZpVFClM/+cbC21/F2gkT51dFm4P/xnmclkkCNemV6J7ZxWkOHRoBaMvqoR3W5mixsbVE08Xpt2avVZgqUt2wus0nhxr+6Pny" +
            "udDhXDXzFv9OiGJqPnrSfBRSuJudskQAzWTFdRCfpNAqdLXu4skDefjwqOAbCRk6M8zxoNZHwPRvkbaeJoBQWB4eCSU7egJPyxNQxSJJ" +
            "tr49qEVhAmj7Ede+SOv3dpjZd31fLUuhndOrj6MGIj4NrHjDV+NgyhAbYRb4iLoIeYqexhaTPE371KIczRZpgN6tXJHGTqLOsfYkaRN2" +
            "n1Ps6RO4vJ3N7PfuCeq3t4O6FLYAzdFvtEgvs6yfFcVwvPDgfeRcwJHljkcjifjXeBv/M/CZFpabSJe6/kzInDxV2bHPOAcv8uFW4sfe" +
            "82eSdRCOo1gfBP7jDfVPOCKs+cBsLjmJAXGULkrTocwAyUBYwBx+CG4/HH04RbTY+VY0zz+kuuleXMbX4mK9ToCYX/baP+xJ7lRNbVBZ" +
            "YRoo9rtF/V6dgEhTddxvxg8jdZb744OSPvz9ySfnUqGcQPfRp4/cazX//AP1+5nU3IO+Q98CpEMe+suZHGTFWvchlSxOPCybhy3ix5rw" +
            "8QbEg3+MMXnGvqIIU2tN/RBbnRArjSfM+o1wWDr8zUp7AuerJd/e83pQko+Y/3j36kFHPkcYSEtoyscq8sGVFDgCf9B3Ar7PbsJDAPlg" +
            "Z1klD1tmD4QnfJysyjO2vR5vWonQZqyEsQ/a50FWnn9nFJ58bgKS9E/2innYr3xQarY3Tm4KThc1w49zlA/65ilkTR82xhiTFdnjkxuP" +
            "DfgXlfaFX99gu/fNnR+P7Ej9BUmRsOSXU2t/Of/v/1AW+M48MwAA";

    static {
        var compressed = BaseEncoding.base64().decode(WORDS_GZIP_BASE64);
        try (var input = new GZIPInputStream(new ByteArrayInputStream(compressed))) {
            WORDS = SPLITTER.splitToList(new String(input.readAllBytes(), StandardCharsets.US_ASCII));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
