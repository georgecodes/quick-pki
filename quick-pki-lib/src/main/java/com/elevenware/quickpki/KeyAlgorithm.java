package com.elevenware.quickpki;

import java.util.Objects;

public sealed interface KeyAlgorithm permits KeyAlgorithm.Rsa, KeyAlgorithm.Ec {

    static KeyAlgorithm rsa(int bits) {
        return new Rsa(bits);
    }

    static KeyAlgorithm ec(String curve) {
        return new Ec(curve);
    }

    String defaultSignatureAlgorithm();

    record Rsa(int bits) implements KeyAlgorithm {
        public Rsa {
            if (bits < 2048) {
                throw new IllegalArgumentException(
                        "RSA key size must be at least 2048 bits, got " + bits);
            }
        }

        @Override
        public String defaultSignatureAlgorithm() {
            return "SHA256withRSA";
        }
    }

    record Ec(String curve) implements KeyAlgorithm {
        public Ec {
            Objects.requireNonNull(curve, "curve must not be null");
        }

        @Override
        public String defaultSignatureAlgorithm() {
            return "SHA256withECDSA";
        }
    }
}
