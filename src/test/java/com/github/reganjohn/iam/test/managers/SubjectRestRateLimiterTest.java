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

package com.github.reganjohn.iam.test.managers;

import com.github.adamorgan.jnt.api.ConnectionType;
import com.github.adamorgan.jnt.api.exceptions.RateLimitedException;
import com.github.adamorgan.jnt.api.requests.Method;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.internal.JNTImpl;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.reganjohn.iam.internal.managers.SubjectRestRateLimiter;
import com.github.reganjohn.iam.test.IntegrationTest;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import com.github.adamorgan.jnt.api.utils.collection.CaseInsensitiveMap;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SubjectRestRateLimiterTest extends IntegrationTest
{
    private static final Route.CompiledRoute CLASSIC = new Route(Method.GET, "classic/{id}").compile("1");

    private final List<EmbeddedChannel> channels = new ArrayList<>();

    @AfterEach
    void close()
    {
        channels.forEach(EmbeddedChannel::finishAndReleaseAll);
    }

    private EmbeddedChannel newChannel(SubjectRestRateLimiter limiter, String thumbprint)
    {
        when(jnt.getConnectionType()).thenReturn(ConnectionType.SERVER);
        EmbeddedChannel channel = new EmbeddedChannel(limiter);
        channel.attr(JNTImpl.IDENTIFIER).set(jnt);
        channel.freezeTime();
        channels.add(channel);
        if (thumbprint != null)
            withThumbprint(channel, thumbprint);
        return channel;
    }

    private static AccessContextData withThumbprint(EmbeddedChannel channel, String thumbprint)
    {
        AccessContextData contextData = mock(AccessContextData.class);
        when(contextData.digest()).thenReturn(thumbprint);
        ProofObjectData data = mock(ProofObjectData.class);
        when(data.getContext(AccessContextType.SHA_256)).thenReturn(contextData);
        channel.attr(ProofObjectManagerImpl.CONTEXT).set(data);
        return contextData;
    }

    private static void withSubject(EmbeddedChannel channel, String subject)
    {
        AccessObjectData data = mock(AccessObjectData.class);
        when(data.getSubject()).thenReturn(subject);
        channel.attr(AccessOverrideManagerImpl.CONTEXT).set(data);
    }

    private static void roundTrip(SubjectRestRateLimiter limiter, EmbeddedChannel channel, Route.CompiledRoute route) throws Exception
    {
        ChannelHandlerContext context = channel.pipeline().firstContext();
        limiter.channelRead0(context, new Request(context, route, new CaseInsensitiveMap<>()));

        channel.attr(Request.IDENTIFIER).set(new Request(context, route, new CaseInsensitiveMap<>()));
        limiter.write0(context, new Response(context, 200, "status", new CaseInsensitiveMap<>(), null), channel.newPromise());
        channel.flush();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bucketsOf(SubjectRestRateLimiter limiter) throws ReflectiveOperationException
    {
        return (Map<String, Object>) FieldUtils.readField(limiter, "buckets", true);
    }

    @Test
    void testThumbprintIsolation() throws Exception
    {
        SubjectRestRateLimiter limiter = new SubjectRestRateLimiter(1, 5, 60, TimeUnit.SECONDS, "rest");
        EmbeddedChannel first = newChannel(limiter, "first");
        EmbeddedChannel second = newChannel(limiter, "second");

        roundTrip(limiter, first, CLASSIC);

        assertThatNoException().isThrownBy(() -> roundTrip(limiter, second, CLASSIC));
        assertThat(bucketsOf(limiter).keySet())
                .hasSize(2)
                .anyMatch(key -> key.endsWith(":{id=1}:first"))
                .anyMatch(key -> key.endsWith(":{id=1}:second"));
    }

    @Test
    void testThumbprintLimit() throws Exception
    {
        SubjectRestRateLimiter limiter = new SubjectRestRateLimiter(1, 5, 60, TimeUnit.SECONDS, "rest");
        EmbeddedChannel first = newChannel(limiter, "shared");
        EmbeddedChannel second = newChannel(limiter, "shared");

        roundTrip(limiter, first, CLASSIC);

        assertThatExceptionOfType(RateLimitedException.class).isThrownBy(() -> roundTrip(limiter, second, CLASSIC));
    }

    @Test
    void testSubjectThumbprint() throws Exception
    {
        SubjectRestRateLimiter limiter = new SubjectRestRateLimiter(1, 5, 60, TimeUnit.SECONDS, "rest");
        EmbeddedChannel first = newChannel(limiter, "shared");
        EmbeddedChannel second = newChannel(limiter, "shared");
        withSubject(first, "first");
        withSubject(second, "second");

        roundTrip(limiter, first, CLASSIC);

        assertThatNoException().isThrownBy(() -> roundTrip(limiter, second, CLASSIC));
        assertThat(bucketsOf(limiter).keySet())
                .anyMatch(key -> key.endsWith(":{id=1}:first:shared"))
                .anyMatch(key -> key.endsWith(":{id=1}:second:shared"));
    }

    @Test
    void testNoProof() throws Exception
    {
        SubjectRestRateLimiter limiter = new SubjectRestRateLimiter(1, 5, 60, TimeUnit.SECONDS, "rest");
        EmbeddedChannel first = newChannel(limiter, null);
        EmbeddedChannel second = newChannel(limiter, null);

        roundTrip(limiter, first, CLASSIC);

        assertThatExceptionOfType(RateLimitedException.class).isThrownBy(() -> roundTrip(limiter, second, CLASSIC));
        assertThat(bucketsOf(limiter).keySet()).singleElement().matches(key -> key.endsWith(":{id=1}"));
    }

    @Test
    void testNoProofSubject() throws Exception
    {
        SubjectRestRateLimiter limiter = new SubjectRestRateLimiter(1, 5, 60, TimeUnit.SECONDS, "rest");
        EmbeddedChannel channel = newChannel(limiter, null);
        withSubject(channel, "first");

        roundTrip(limiter, channel, CLASSIC);

        assertThat(bucketsOf(limiter).keySet()).singleElement().matches(key -> key.endsWith(":{id=1}:first"));
    }

    @Test
    void testCloseContext() throws Exception
    {
        SubjectRestRateLimiter limiter = new SubjectRestRateLimiter(1, 5, 60, TimeUnit.SECONDS, "rest");
        EmbeddedChannel channel = newChannel(limiter, null);
        AccessContextData contextData = withThumbprint(channel, "first");

        roundTrip(limiter, channel, CLASSIC);

        verify(contextData, atLeastOnce()).close();
    }

    @Test
    void testGlobalLimit() throws Exception
    {
        SubjectRestRateLimiter limiter = new SubjectRestRateLimiter(5, 1, 60, TimeUnit.SECONDS, "rest");
        EmbeddedChannel first = newChannel(limiter, "first");
        EmbeddedChannel second = newChannel(limiter, "second");
        Route route = new Route(Method.POST, "interaction/{id}", true);

        roundTrip(limiter, first, route.compile("1"));

        assertThatExceptionOfType(RateLimitedException.class).isThrownBy(() -> roundTrip(limiter, second, route.compile("2")));
    }

    @Test
    void testCleanup() throws Exception
    {
        SubjectRestRateLimiter limiter = new SubjectRestRateLimiter(5, 5, 60, TimeUnit.SECONDS, "rest");
        EmbeddedChannel first = newChannel(limiter, "first");
        EmbeddedChannel second = newChannel(limiter, "second");
        roundTrip(limiter, first, CLASSIC);
        roundTrip(limiter, second, CLASSIC);
        assertThat(bucketsOf(limiter)).hasSize(2);
        for (Object bucket : bucketsOf(limiter).values())
            FieldUtils.writeField(bucket, "reset", System.currentTimeMillis() - 1000, true);

        first.advanceTimeBy(1, TimeUnit.SECONDS);
        first.runPendingTasks();

        assertThat(bucketsOf(limiter)).isEmpty();
    }
}
