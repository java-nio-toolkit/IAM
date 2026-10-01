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

import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.PermissionOverride;
import com.github.reganjohn.iam.api.entities.Webhook;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.entities.UserImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.api.utils.data.BufferObject;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionContextActionImpl;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class UserImplTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");

    @SuppressWarnings("unchecked")
    private InteractionContextActionImpl<List<PermissionOverride>> retrieval()
    {
        withJCA();
        UserImpl user = new UserImpl(api, USER_ID, "alice", null, 0);
        return (InteractionContextActionImpl<List<PermissionOverride>>) user.retrieveEntitlements();
    }

    @Test
    void testEntitlementStatement()
    {
        InteractionContextActionImpl<List<PermissionOverride>> retrieval = retrieval();

        assertThat(retrieval.getContent()).contains("SELECT * FROM users.entitlements", "user_id = ?");
        assertThat(retrieval.getElements()).containsExactly(USER_ID);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testNoEntitlements() throws Exception
    {
        InteractionImpl<List<PermissionOverride>> interaction = mock(InteractionImpl.class);
        BufferArray rows = mock(BufferArray.class);
        when(rows.isEmpty()).thenReturn(true);

        retrieval().handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows);

        verify(interaction).onSuccess(Collections.emptyList());
    }

    @Test
    @SuppressWarnings("unchecked")
    void testEntitlements() throws Exception
    {
        InteractionImpl<List<PermissionOverride>> interaction = mock(InteractionImpl.class);
        BufferArray rows = mock(BufferArray.class);
        when(rows.isEmpty()).thenReturn(false);
        List<PermissionOverride> entitlements = Collections.singletonList(mock(PermissionOverride.class));
        EntityBuilder builder = mock(EntityBuilder.class);
        when(builder.createPermissionOverrides(rows)).thenReturn(entitlements);
        when(api.getEntityBuilder()).thenReturn(builder);

        retrieval().handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows);

        verify(interaction).onSuccess(entitlements);
    }

    private static BufferArray newRows(long... flags)
    {
        List<BufferObject> objects = new ArrayList<>();
        for (long flag : flags)
        {
            BufferObject row = mock(BufferObject.class);
            when(row.getLong("flags", 0)).thenReturn(flag);
            objects.add(row);
        }
        BufferArray rows = mock(BufferArray.class);
        when(rows.isEmpty()).thenReturn(false);
        when(rows.getObject(0)).thenReturn(objects.get(0));
        when(rows.iterator()).thenAnswer(invocation -> objects.iterator());
        when(rows.stream()).thenAnswer(invocation -> objects.stream());
        return rows;
    }

    @SuppressWarnings("unchecked")
    private <T> void assertFails(InteractionContextActionImpl<T> retrieval, BufferArray rows, ErrorResponse expected) throws Exception
    {
        InteractionImpl<T> interaction = mock(InteractionImpl.class);

        retrieval.handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows);

        ArgumentCaptor<Throwable> failure = ArgumentCaptor.forClass(Throwable.class);
        verify(interaction).onFailure(failure.capture());
        assertThat(failure.getValue()).isInstanceOf(ErrorResponseException.class);
        assertThat(((ErrorResponseException) failure.getValue()).getErrorCode()).isEqualTo(expected.getCode());
        verify(interaction, never()).onSuccess(any());
    }

    @Test
    @SuppressWarnings("unchecked")
    void testWebhookById() throws Exception
    {
        withJCA();
        UUID webhookId = UUID.randomUUID();
        BufferArray rows = newRows(0);
        Webhook webhook = mock(Webhook.class);
        EntityBuilder builder = mock(EntityBuilder.class);
        when(builder.createWebhook(rows.getObject(0))).thenReturn(webhook);
        when(api.getEntityBuilder()).thenReturn(builder);
        InteractionImpl<Webhook> interaction = mock(InteractionImpl.class);

        ((InteractionContextActionImpl<Webhook>) new UserImpl(api, USER_ID, "alice", null, 0).retrieveWebhookById(webhookId))
                .handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows);

        verify(interaction).onSuccess(webhook);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testDeletedWebhookById() throws Exception
    {
        withJCA();

        assertFails((InteractionContextActionImpl<Webhook>) new UserImpl(api, USER_ID, "alice", null, 0).retrieveWebhookById(UUID.randomUUID()),
                newRows(1L << 34), ErrorResponse.UNKNOWN_WEBHOOK);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testMissingWebhookById() throws Exception
    {
        withJCA();
        BufferArray rows = mock(BufferArray.class);
        when(rows.isEmpty()).thenReturn(true);

        assertFails((InteractionContextActionImpl<Webhook>) new UserImpl(api, USER_ID, "alice", null, 0).retrieveWebhookById(UUID.randomUUID()),
                rows, ErrorResponse.UNKNOWN_WEBHOOK);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testDeletedAccessById() throws Exception
    {
        withJCA();

        assertFails((InteractionContextActionImpl<AccessEntryData>) new UserImpl(api, USER_ID, "alice", null, 0).retrieveAccessById("thumbprint"),
                newRows(1L << 34), ErrorResponse.UNKNOWN_ACCESS);
    }

    @SuppressWarnings("unchecked")
    private void assertCount(InteractionContextActionImpl<Integer> retrieval, String table)
    {
        assertThat(retrieval.getContent()).contains("SELECT flags FROM " + table);
        assertThat(retrieval.getElements()).containsExactly(USER_ID);
        InteractionImpl<Integer> interaction = mock(InteractionImpl.class);

        try
        {
            retrieval.handleSuccess(mock(InteractionCallbackResponse.class), interaction, newRows(0, 1L << 34, 2, 1L << 34));
        }
        catch (Exception exception)
        {
            throw new IllegalStateException(exception);
        }

        verify(interaction).onSuccess(2);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testSessionCount()
    {
        withJCA();
        assertCount((InteractionContextActionImpl<Integer>) new UserImpl(api, USER_ID, "alice", null, 0).retrieveSessionCount(), "users.sessions");
    }

    @Test
    @SuppressWarnings("unchecked")
    void testWebhookCount()
    {
        withJCA();
        assertCount((InteractionContextActionImpl<Integer>) new UserImpl(api, USER_ID, "alice", null, 0).retrieveWebhookCount(), "users.webhooks");
    }

    @Test
    @SuppressWarnings("unchecked")
    void testApplicationCount()
    {
        withJCA();
        assertCount((InteractionContextActionImpl<Integer>) new UserImpl(api, USER_ID, "alice", null, 0).retrieveApplicationCount(), "integrations.applications");
    }
}
