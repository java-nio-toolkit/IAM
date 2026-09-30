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

package com.github.reganjohn.iam.internal.requests.restactions;

import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.internal.utils.IOUtil;
import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AbstractApplicationActionImplTest
{
    private static final String CLIENT_NONCE = "VJLO6A4CATR0KRO";
    private static final String FINISH_NONCE = "MBDOFXG4Y5CVJCX821LH";
    private static final String INTERACT_REF = "4IFWWIKYB2PQ6U56NL1";
    private static final String GRANT_URI = "https://server.example.com/tx";

    private static Request requestWith(String name, String value)
    {
        CaseInsensitiveMap<String, Collection<String>> headers = new CaseInsensitiveMap<>();
        if (name != null)
            headers.put(name, Collections.singletonList(value));
        Request request = mock(Request.class);
        when(request.getHeaders()).thenReturn(headers);
        return request;
    }

    static Stream<Arguments> testBaseUri()
    {
        return Stream.of(
                arguments("host_only", "Host", "iam.example", "https://iam.example/"),
                arguments("host_with_port", "Host", "iam.example:8443", "https://iam.example:8443/"),
                arguments("forwarded_proto_and_host", "Forwarded", "proto=http;host=edge.example", "http://edge.example/"),
                arguments("forwarded_quoted", "Forwarded", "host=\"edge.example\";proto=https", "https://edge.example/"),
                arguments("forwarded_proto_only", "Forwarded", "proto=http", null),
                arguments("forwarded_malformed", "Forwarded", "garbage", null),
                arguments("no_headers", null, null, null));
    }

    @Test
    void testHashVectorSha256()
    {
        assertThat(AbstractApplicationActionImpl.hash("sha-256", CLIENT_NONCE, FINISH_NONCE, INTERACT_REF, GRANT_URI))
                .isEqualTo("x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY");
    }

    @Test
    void testHashVectorSha3512()
    {
        assertThat(AbstractApplicationActionImpl.hash("sha3-512", CLIENT_NONCE, FINISH_NONCE, INTERACT_REF, GRANT_URI))
                .isEqualTo("pyUkVJSmpqSJMaDYsk5G8WCvgY91l-agUPe1wgn-cc5rUtN69gPI2-S_s-Eswed8iB4PJ_a5Hg6DNi7qGgKwSQ");
    }

    @Test
    void testHashBaseStringUsesNewlines()
    {
        assertThat(AbstractApplicationActionImpl.hash("sha-256", "a", "b", "c", "d"))
                .isEqualTo(AbstractApplicationActionImpl.digest("sha-256", "a\nb\nc\nd"))
                .isNotEqualTo(AbstractApplicationActionImpl.digest("sha-256", "a\nb\nc\nd\n"))
                .isNotEqualTo(AbstractApplicationActionImpl.digest("sha-256", "abcd"));
    }

    @ValueSource(strings = {"sha-256", "sha-384", "sha-512", "sha3-256", "sha3-384", "sha3-512"})
    @ParameterizedTest
    void testSupportedHashMethods(String method)
    {
        assertThat(AbstractApplicationActionImpl.hasMode(method)).isTrue();
        assertThat(AbstractApplicationActionImpl.digest(method, "value")).matches("[A-Za-z0-9_-]+");
    }

    @ValueSource(strings = {"", "md5", "sha-1", "SHA-256", "sha256", "unknown"})
    @ParameterizedTest
    void testUnsupportedHashMethods(String method)
    {
        assertThat(AbstractApplicationActionImpl.hasMode(method)).isFalse();
        assertThatIllegalArgumentException().isThrownBy(() -> AbstractApplicationActionImpl.digest(method, "value"));
    }

    @Test
    void testNullHashMethod()
    {
        assertThat(AbstractApplicationActionImpl.hasMode(null)).isFalse();
    }

    @Test
    void testDefaultDigest()
    {
        assertThat(AbstractApplicationActionImpl.digest("value")).isEqualTo(AbstractApplicationActionImpl.digest("sha-256", "value"));
        assertThat(AbstractApplicationActionImpl.DEFAULT_HASH_METHOD).isEqualTo("sha-256");
    }

    @Test
    void testRandomValue()
    {
        Set<String> values = new HashSet<>();
        for (int i = 0; i < 100; i++)
            values.add(AbstractApplicationActionImpl.randomToken());

        assertThat(values).hasSize(100);
        assertThat(values).allSatisfy(value ->
        {
            assertThat(value).matches("[A-Za-z0-9_-]{43}");
            assertThat(IOUtil.decodeURL(value)).hasSize(32);
        });
    }

    @MethodSource
    @ParameterizedTest(name = "{0}")
    void testBaseUri(String name, String header, String value, String expected)
    {
        assertThat(AbstractApplicationActionImpl.retrieveBaseUri(requestWith(header, value))).isEqualTo(expected);
    }
}
