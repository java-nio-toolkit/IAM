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

import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.PermissionOverride;
import com.github.reganjohn.iam.internal.entities.UserImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionContextActionImpl;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
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
}
