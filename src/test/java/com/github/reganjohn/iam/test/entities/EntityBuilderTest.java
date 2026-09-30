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

package com.github.reganjohn.iam.test.entities;

import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.reganjohn.c4j.api.utils.data.BufferObject;
import io.netty.util.HashedWheelTimer;
import io.netty.util.concurrent.DefaultThreadFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.time.Clock;
import java.time.Duration;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class EntityBuilderTest
{
    private static final Duration LIFETIME = Duration.ofMinutes(15);

    private final HashedWheelTimer timer = new HashedWheelTimer(new DefaultThreadFactory("iam-test-timer", true), 1, TimeUnit.SECONDS);

    @BeforeAll
    static void registerProvider()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterEach
    void stopTimer()
    {
        timer.stop();
    }

    private AccessEntryManagerImpl newManager(Clock clock)
    {
        return new AccessEntryManagerImpl(clock, timer, SignType.ED25519, 2, LIFETIME.toMinutes(), TimeUnit.MINUTES, Collections.singletonList("iam.test"));
    }

    private static Clock newClock(long millis)
    {
        Clock clock = mock(Clock.class);
        when(clock.millis()).thenReturn(millis);
        return clock;
    }

    private static AccessObjectData issue(AccessEntryManagerImpl manager, AccessEntryManagerImpl.AccessEntrySnapshot snapshot)
    {
        AccessContextData contextData = mock(AccessContextData.class);
        when(contextData.toData()).thenReturn(DataObject.empty().put("jkt", "thumbprint"));
        return EntityBuilder.createObjectData(UUID.randomUUID().toString(), "iam.test", UUID.randomUUID().toString(),
                manager, contextData, "application/dpop+jwt", snapshot);
    }

    @Test
    void testLifetimeFollowsTheManagerWindow()
    {
        AccessEntryManagerImpl manager = new AccessEntryManagerImpl(newClock(System.currentTimeMillis()), timer, SignType.ED25519, 2, 5, TimeUnit.MINUTES, Collections.singletonList("iam.test"));

        AccessObjectData token = issue(manager, manager.getCurrentOrder());

        assertThat(manager.getTimeoutDuration()).isEqualTo(Duration.ofMinutes(5));
        assertThat(token.getBody().getLong("exp") - token.getBody().getLong("iat")).isEqualTo(Duration.ofMinutes(5).getSeconds());
    }

    @ValueSource(longs = {0, 1, 60, 7 * 60, 15 * 60 - 1, 15 * 60, 15 * 60 + 1, 29 * 60, 30 * 60 - 1})
    @ParameterizedTest
    void testTokenLivesExactlyTheLifetime(long seconds)
    {
        long now = System.currentTimeMillis();
        AccessEntryManagerImpl manager = newManager(newClock(now + seconds * 1000));

        AccessObjectData token = issue(manager, manager.getCurrentOrder());

        long issuedAt = token.getBody().getLong("iat");
        long expiresAt = token.getBody().getLong("exp");
        assertThat(expiresAt - issuedAt).isEqualTo(LIFETIME.getSeconds());
        assertThat(token.getTimeExpiresAt().toEpochSecond()).isEqualTo(expiresAt);
    }

    @Test
    void testLifetimeDoesNotDependOnTheRemainingTimeOfTheKey()
    {
        long now = System.currentTimeMillis();
        Clock clock = mock(Clock.class);
        when(clock.millis()).thenReturn(now);
        AccessEntryManagerImpl manager = newManager(clock);
        AccessEntryManagerImpl.AccessEntrySnapshot snapshot = manager.getCurrentOrder();
        when(clock.millis()).thenReturn(now + Duration.ofMinutes(30).toMillis() - 1000);

        AccessObjectData token = issue(manager, snapshot);

        assertThat(token.getBody().getLong("exp") - token.getBody().getLong("iat")).isEqualTo(LIFETIME.getSeconds());
    }

    @ValueSource(longs = {0, 1, 60, 7 * 60, 15 * 60 - 1})
    @ParameterizedTest
    void testKeyOutlivesTheTokenInsideItsWindow(long seconds)
    {
        long window = LIFETIME.toMillis();
        long start = (System.currentTimeMillis() / window) * window;
        Clock clock = mock(Clock.class);
        when(clock.millis()).thenReturn(start);
        AccessEntryManagerImpl manager = newManager(clock);
        AccessEntryManagerImpl.AccessEntrySnapshot first = manager.getCurrentOrder();
        long issuedAt = start + seconds * 1000;
        when(clock.millis()).thenReturn(issuedAt);

        AccessEntryManagerImpl.AccessEntrySnapshot snapshot = manager.getCurrentOrder();

        assertThat(snapshot).isSameAs(first);
        assertThat(snapshot.getTimeExpiresAt().toInstant().toEpochMilli() - issuedAt).isGreaterThanOrEqualTo(LIFETIME.toMillis());
    }
    private static BufferObject newRow(String kid, byte[] publicKey)
    {
        BufferObject row = mock(BufferObject.class);
        when(row.getString("kid", null)).thenReturn(kid);
        if (kid == null)
            when(row.getString("kid")).thenThrow(new IllegalStateException("missing kid"));
        when(row.getBytes("public_key")).thenReturn(publicKey);
        when(row.getString("kty")).thenReturn("OKP");
        when(row.getString("alg")).thenReturn("Ed25519");
        when(row.getString("usage", null)).thenReturn(null);
        return row;
    }

    @Test
    void testAccessEntryWithoutKeyId() throws Exception
    {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();

        AccessEntryData entry = EntityBuilder.createAccessEntry(newRow(null, pair.getPublic().getEncoded()));

        assertThat(entry.getUniqueId()).isNull();
        assertThat(entry.getPublic().getEncoded()).isEqualTo(pair.getPublic().getEncoded());
    }

    @Test
    void testAccessEntryWithKeyId() throws Exception
    {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();

        AccessEntryData entry = EntityBuilder.createAccessEntry(newRow("key-id", pair.getPublic().getEncoded()));

        assertThat(entry.getUniqueId()).isEqualTo("key-id");
        assertThat(entry.getPublic().getEncoded()).isEqualTo(pair.getPublic().getEncoded());
    }
}
