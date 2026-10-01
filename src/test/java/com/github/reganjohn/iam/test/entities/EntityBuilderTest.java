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
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryArray;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.Webhook;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.entities.ApplicationImpl;
import com.github.reganjohn.iam.internal.entities.PermissionOverrideImpl;
import com.github.reganjohn.iam.internal.entities.SessionImpl;
import com.reganjohn.c4j.api.utils.data.BufferArray;
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
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
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
    void testWebhook()
    {
        UUID webhookId = UUID.randomUUID();
        UUID ownerId = UUID.randomUUID();
        Instant updatedAt = Instant.parse("2026-01-01T00:00:00Z");
        BufferObject row = mock(BufferObject.class);
        when(row.getUUID("webhook_id")).thenReturn(webhookId);
        when(row.getUUID("owner_id")).thenReturn(ownerId);
        when(row.getString("name")).thenReturn("hook");
        when(row.getString("avatar_id", null)).thenReturn(null);
        when(row.getString("endpoint")).thenReturn("https://example.org/hook");
        when(row.getTimestamp("updated_at")).thenReturn(updatedAt);
        when(row.getLong("flags")).thenReturn(2L);
        when(row.getLong("scopes")).thenReturn(1L);

        Webhook webhook = new EntityBuilder(mock(IAMImpl.class)).createWebhook(row);

        assertThat(webhook.getUniqueId()).isEqualTo(webhookId);
        assertThat(webhook.getOwnerId()).isEqualTo(ownerId);
        assertThat(webhook.getName()).isEqualTo("hook");
        assertThat(webhook.getAvatarId()).isNull();
        assertThat(webhook.getUrl()).isEqualTo("https://example.org/hook");
        assertThat(webhook.getTimeUpdated().toInstant()).isEqualTo(updatedAt);
        assertThat(webhook.getFlagsRaw()).isEqualTo(2L);
        assertThat(webhook.getScopesRaw()).isEqualTo(1L);
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

    private static BufferObject newWebhookRow(long flags)
    {
        BufferObject row = mock(BufferObject.class);
        when(row.getUUID("webhook_id")).thenReturn(UUID.randomUUID());
        when(row.getUUID("owner_id")).thenReturn(UUID.randomUUID());
        when(row.getString("name")).thenReturn("hook");
        when(row.getString("avatar_id", null)).thenReturn(null);
        when(row.getString("endpoint")).thenReturn("https://example.org/hook");
        when(row.getTimestamp("updated_at")).thenReturn(Instant.parse("2026-01-01T00:00:00Z"));
        when(row.getLong("flags")).thenReturn(flags);
        when(row.getLong("flags", 0)).thenReturn(flags);
        when(row.getLong("scopes")).thenReturn(1L);
        return row;
    }

    private static BufferArray newRows(BufferObject... rows)
    {
        BufferArray array = mock(BufferArray.class);
        when(array.isEmpty()).thenReturn(rows.length == 0);
        when(array.iterator()).thenAnswer(invocation -> Arrays.asList(rows).iterator());
        when(array.stream()).thenAnswer(invocation -> Arrays.stream(rows));
        return array;
    }

    @ValueSource(longs = {1L << 34, (1L << 34) | 2L, -1L})
    @ParameterizedTest
    void testDeletedRow(long flags)
    {
        assertThat(EntityBuilder.isDelete(newWebhookRow(flags))).isTrue();
    }

    @ValueSource(longs = {0L, 2L, 1L << 33, 1L << 35})
    @ParameterizedTest
    void testRowIsNotDeleted(long flags)
    {
        assertThat(EntityBuilder.isDelete(newWebhookRow(flags))).isFalse();
    }

    @Test
    void testDeletedArray()
    {
        assertThat(EntityBuilder.isDelete(newRows(newWebhookRow(0), newWebhookRow(1L << 34)))).isTrue();
        assertThat(EntityBuilder.isDelete(newRows(newWebhookRow(0), newWebhookRow(2)))).isFalse();
        assertThat(EntityBuilder.isDelete(newRows())).isFalse();
    }

    @Test
    void testDeletedWebhooksAreSkipped()
    {
        BufferObject kept = newWebhookRow(0);
        BufferObject deleted = newWebhookRow(1L << 34);

        List<Webhook> webhooks = new EntityBuilder(mock(IAMImpl.class)).createWebhooks(newRows(deleted, kept, deleted));

        assertThat(webhooks).hasSize(1);
        assertThat(webhooks.get(0).getUniqueId()).isEqualTo(kept.getUUID("webhook_id"));
    }

    @Test
    void testOnlyDeletedWebhooks()
    {
        assertThat(new EntityBuilder(mock(IAMImpl.class)).createWebhooks(newRows(newWebhookRow(1L << 34)))).isEmpty();
    }

    @Test
    void testDeletedSessionsAreSkipped()
    {
        EntityBuilder builder = spy(new EntityBuilder(mock(IAMImpl.class)));
        BufferObject kept = newWebhookRow(0);
        BufferObject deleted = newWebhookRow(1L << 34);
        SessionImpl session = mock(SessionImpl.class);
        doReturn(session).when(builder).createSession(kept);

        assertThat(builder.createSessions(newRows(deleted, kept))).containsExactly(session);
        verify(builder, never()).createSession(deleted);
    }

    @Test
    void testDeletedApplicationsAreSkipped()
    {
        EntityBuilder builder = spy(new EntityBuilder(mock(IAMImpl.class)));
        BufferObject kept = newWebhookRow(0);
        BufferObject deleted = newWebhookRow(1L << 34);
        ApplicationImpl application = mock(ApplicationImpl.class);
        doReturn(application).when(builder).createApplication(kept);

        assertThat(builder.createApplications(newRows(deleted, kept))).containsExactly(application);
        verify(builder, never()).createApplication(deleted);
    }

    @Test
    void testDeletedPermissionOverridesAreSkipped()
    {
        EntityBuilder builder = spy(new EntityBuilder(mock(IAMImpl.class)));
        BufferObject kept = newWebhookRow(0);
        BufferObject deleted = newWebhookRow(1L << 34);
        PermissionOverrideImpl override = mock(PermissionOverrideImpl.class);
        doReturn(override).when(builder).createPermissionOverride(kept);

        assertThat(builder.createPermissionOverrides(newRows(deleted, kept))).containsExactly(override);
        verify(builder, never()).createPermissionOverride(deleted);
    }

    @Test
    void testDeletedAccessEntriesAreSkipped() throws Exception
    {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();
        BufferObject kept = newRow("kept", pair.getPublic().getEncoded());
        BufferObject deleted = newRow("deleted", pair.getPublic().getEncoded());
        when(deleted.getLong("flags", 0)).thenReturn(1L << 34);

        AccessEntryArray entries = new EntityBuilder(mock(IAMImpl.class)).createAccessEntries(newRows(deleted, kept));

        assertThat(entries).hasSize(1);
    }

    @Test
    void testCount()
    {
        assertThat(EntityBuilder.count(newRows(newWebhookRow(0), newWebhookRow(1L << 34), newWebhookRow(2)))).isEqualTo(2);
        assertThat(EntityBuilder.count(newRows(newWebhookRow(1L << 34), newWebhookRow(1L << 34)))).isZero();
        assertThat(EntityBuilder.count(newRows())).isZero();
    }
}
