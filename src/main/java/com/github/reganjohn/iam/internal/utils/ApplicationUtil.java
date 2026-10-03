/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
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

package com.github.reganjohn.iam.internal.utils;

import com.github.adamorgan.jnt.internal.utils.IOUtil;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;

public final class ApplicationUtil
{
    public static final String DEFAULT_HASH_METHOD = "sha-256";

    private static final SecureRandom RANDOM = new SecureRandom();

    public static final Map<String, String> MODES;

    static
    {
        Map<String, String> modes = new CaseInsensitiveMap<>();
        modes.put("sha-256", MessageDigestAlgorithms.SHA_256);
        modes.put("sha-384", MessageDigestAlgorithms.SHA_384);
        modes.put("sha-512", MessageDigestAlgorithms.SHA_512);
        modes.put("sha3-256", MessageDigestAlgorithms.SHA3_256);
        modes.put("sha3-384", MessageDigestAlgorithms.SHA3_384);
        modes.put("sha3-512", MessageDigestAlgorithms.SHA3_512);
        MODES = Collections.unmodifiableMap(modes);
    }

    private ApplicationUtil() {}

    @Nonnull
    public static String randomToken()
    {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return IOUtil.encodeURL(bytes);
    }

    @Nonnull
    public static String digest(@Nonnull String mode, @Nonnull String value)
    {
        String algorithm = MODES.get(mode);
        if (algorithm == null)
            throw new IllegalArgumentException("Unsupported hash method");
        return IOUtil.encodeURL(new DigestUtils(algorithm).digest(value));
    }

    @Nonnull
    public static String digest(@Nonnull String value)
    {
        return digest(DEFAULT_HASH_METHOD, value);
    }

    @Nonnull
    public static String hash(@Nonnull String method, @Nonnull String clientNonce,
                              @Nonnull String finishNonce, @Nonnull String reference,
                              @Nonnull String uri)
    {
        return digest(method, clientNonce + "\n" + finishNonce + "\n" + reference + "\n" + uri);
    }
}
