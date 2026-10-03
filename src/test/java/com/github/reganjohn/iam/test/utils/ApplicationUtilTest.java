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

package com.github.reganjohn.iam.test.utils;

import com.github.adamorgan.jnt.internal.utils.IOUtil;
import com.github.reganjohn.iam.internal.utils.ApplicationUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

public class ApplicationUtilTest
{
    private static final String CLIENT_NONCE = "VJLO6A4CATR0KRO";
    private static final String FINISH_NONCE = "MBDOFXG4Y5CVJCX821LH";
    private static final String INTERACT_REF = "4IFWWIKYB2PQ6U56NL1";
    private static final String GRANT_URI = "https://server.example.com/tx";

    @Test
    void testHashVectorSha256()
    {
        assertThat(ApplicationUtil.hash("sha-256", CLIENT_NONCE, FINISH_NONCE, INTERACT_REF, GRANT_URI))
                .isEqualTo("x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY");
    }

    @Test
    void testHashVectorSha3512()
    {
        assertThat(ApplicationUtil.hash("sha3-512", CLIENT_NONCE, FINISH_NONCE, INTERACT_REF, GRANT_URI))
                .isEqualTo("pyUkVJSmpqSJMaDYsk5G8WCvgY91l-agUPe1wgn-cc5rUtN69gPI2-S_s-Eswed8iB4PJ_a5Hg6DNi7qGgKwSQ");
    }

    @Test
    void testHashBaseStringUsesNewlines()
    {
        assertThat(ApplicationUtil.hash("sha-256", "a", "b", "c", "d"))
                .isEqualTo(ApplicationUtil.digest("sha-256", "a\nb\nc\nd"))
                .isNotEqualTo(ApplicationUtil.digest("sha-256", "a\nb\nc\nd\n"))
                .isNotEqualTo(ApplicationUtil.digest("sha-256", "abcd"));
    }

    @ValueSource(strings = {"sha-256", "sha-384", "sha-512", "sha3-256", "sha3-384", "sha3-512", "SHA-256", "Sha3-512"})
    @ParameterizedTest
    void testSupportedHashMethods(String method)
    {
        assertThat(ApplicationUtil.MODES.containsKey(method)).isTrue();
        assertThat(ApplicationUtil.digest(method, "value")).matches("[A-Za-z0-9_-]+");
    }

    @ValueSource(strings = {"", "md5", "sha-1", "sha256", "unknown"})
    @ParameterizedTest
    void testUnsupportedHashMethods(String method)
    {
        assertThat(ApplicationUtil.MODES.containsKey(method)).isFalse();
        assertThatIllegalArgumentException().isThrownBy(() -> ApplicationUtil.digest(method, "value"));
    }

    @Test
    void testNullHashMethod()
    {
        assertThat(ApplicationUtil.MODES.containsKey(null)).isFalse();
    }

    @Test
    void testDefaultDigest()
    {
        assertThat(ApplicationUtil.digest("value")).isEqualTo(ApplicationUtil.digest("sha-256", "value"));
        assertThat(ApplicationUtil.DEFAULT_HASH_METHOD).isEqualTo("sha-256");
    }

    @Test
    void testRandomValue()
    {
        Set<String> values = new HashSet<>();
        for (int i = 0; i < 100; i++)
            values.add(ApplicationUtil.randomToken());

        assertThat(values).hasSize(100);
        assertThat(values).allSatisfy(value ->
        {
            assertThat(value).matches("[A-Za-z0-9_-]{43}");
            assertThat(IOUtil.decodeURL(value)).hasSize(32);
        });
    }
}
