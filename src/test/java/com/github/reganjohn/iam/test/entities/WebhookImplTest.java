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

import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.entities.WebhookImpl;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class WebhookImplTest
{
    private static final UUID WEBHOOK_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");
    private static final UUID OWNER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final OffsetDateTime UPDATED_AT = OffsetDateTime.parse("2026-01-01T00:00:00Z");

    private static WebhookImpl newWebhook(String avatarId)
    {
        return new WebhookImpl(mock(IAMImpl.class), WEBHOOK_ID, "hook", OWNER_ID, avatarId, "https://example.org/hook", UPDATED_AT, 2L, 1L);
    }

    @Test
    void testData()
    {
        DataObject data = newWebhook("avatar-cid").toData();

        assertThat(data.getString("owner_id")).isEqualTo(OWNER_ID.toString());
        assertThat(data.getString("webhook_id")).isEqualTo(WEBHOOK_ID.toString());
        assertThat(data.getString("name")).isEqualTo("hook");
        assertThat(data.getString("avatar_id")).isEqualTo("avatar-cid");
        assertThat(data.getString("url")).isEqualTo("https://example.org/hook");
        assertThat(data.getLong("scopes")).isEqualTo(1L);
        assertThat(data.getLong("flags")).isEqualTo(2L);
        assertThat(data.getLong("updated_at")).isEqualTo(UPDATED_AT.toInstant().toEpochMilli());
    }

    @Test
    void testDataIsSerializable()
    {
        assertThat(DataObject.fromJson(newWebhook(null).toData().toString()).isNull("avatar_id")).isTrue();
    }
}
