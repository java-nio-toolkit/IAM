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

package com.github.reganjohn.iam.test.restaction.webhooks;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.requestbody.RequestBody;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.entities.Webhook;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.restactions.webhooks.WebhookCreateAction;
import com.github.reganjohn.iam.api.utils.webhooks.WebhookCreateBuilder;
import com.github.reganjohn.iam.api.utils.webhooks.WebhookCreateData;
import com.github.reganjohn.iam.internal.requests.restactions.webhooks.WebhookCreateActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import java.time.OffsetDateTime;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class WebhookCreateActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final String URL = "https://example.org/hook";
    private static final String VALID = body("name", "hook", "avatar_id", "avatar-cid", "url", URL, "scopes", 3);

    private WebhookCreateActionImpl newAction()
    {
        return new WebhookCreateActionImpl(api);
    }

    private WebhookCreateActionImpl newAction(ArgumentCaptor<WebhookCreateData> created)
    {
        WebhookCreateActionImpl action = spy(newAction());
        doReturn(completed(null)).when(action).create(created.capture());
        return action;
    }

    private void withStoredUser(int count)
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withWebhookCount(user, completed(count));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));
    }

    private static WebhookCreateData newData()
    {
        return new WebhookCreateBuilder()
                .setUniqueId(UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c"))
                .setName("hook")
                .setOwnerId(USER_ID)
                .setAvatarId("avatar-cid")
                .setUrl(URL)
                .setTimeUpdated(OffsetDateTime.parse("2026-01-01T00:00:00Z"))
                .setFlags(0)
                .setScopes(3)
                .build();
    }

    @SuppressWarnings("unchecked")
    private InteractionMappingActionImpl<Void> creation()
    {
        withJCA();
        return (InteractionMappingActionImpl<Void>) newAction().create(newData());
    }

    private static BufferArray rows(boolean empty)
    {
        BufferArray rows = mock(BufferArray.class);
        when(rows.isEmpty()).thenReturn(empty);
        return rows;
    }

    static Stream<Arguments> testInvalidInputs()
    {
        String longName = new String(new char[Webhook.MAX_NAME_LENGTH + 1]).replace('\0', 'a');
        String longAvatar = new String(new char[Webhook.ICON_CID_MAX_LENGTH + 1]).replace('\0', 'a');
        return Stream.of(
                arguments("empty_body", body()),
                arguments("missing_name", body("avatar_id", "cid", "url", URL, "scopes", 3)),
                arguments("name_not_string", body("name", 5, "avatar_id", "cid", "url", URL, "scopes", 3)),
                arguments("name_empty", body("name", "", "avatar_id", "cid", "url", URL, "scopes", 3)),
                arguments("name_too_long", body("name", longName, "avatar_id", "cid", "url", URL, "scopes", 3)),
                arguments("avatar_not_string", body("name", "hook", "avatar_id", 5, "url", URL, "scopes", 3)),
                arguments("avatar_too_long", body("name", "hook", "avatar_id", longAvatar, "url", URL, "scopes", 3)),
                arguments("missing_url", body("name", "hook", "avatar_id", "cid", "scopes", 3)),
                arguments("url_not_string", body("name", "hook", "avatar_id", "cid", "url", 5, "scopes", 3)),
                arguments("url_not_url", body("name", "hook", "avatar_id", "cid", "url", "not-a-url", "scopes", 3)),
                arguments("url_not_https", body("name", "hook", "avatar_id", "cid", "url", "http://example.org/hook", "scopes", 3)),
                arguments("url_localhost", body("name", "hook", "avatar_id", "cid", "url", "https://localhost/hook", "scopes", 3)),
                arguments("url_loopback", body("name", "hook", "avatar_id", "cid", "url", "https://127.0.0.1/hook", "scopes", 3)),
                arguments("url_private", body("name", "hook", "avatar_id", "cid", "url", "https://192.168.0.1/hook", "scopes", 3)),
                arguments("missing_scopes", body("name", "hook", "avatar_id", "cid", "url", URL)),
                arguments("scopes_not_number", body("name", "hook", "avatar_id", "cid", "url", URL, "scopes", "all")),
                arguments("everything_invalid", body("name", 5, "avatar_id", 5, "url", 5, "scopes", "all")));
    }

    static Stream<Arguments> testInvalidSubject()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "01a0f15f-ef22-7d1e-9a96"),
                arguments("without_dashes", "01a0f15fef227d1e9a96432acf9b644f"));
    }

    @Test
    void testNonObject()
    {
        assertThatRequestTo(newAction())
                .withBody(nonObjectBody())
                .hasFailureMatchingSnapshot()
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testForeignBody()
    {
        assertThatRequestTo(newAction())
                .withBody(mock(RequestBody.class))
                .hasFailureMatchingSnapshot()
                .hasNoResponse()
                .whenHandled();
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidInputs(String name, String json)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withJsonBody(json)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @ValueSource(strings = {
            "{\"name\":\"hook\",\"avatar_id\":\"\",\"url\":\"https://example.org/hook\",\"scopes\":0}",
            "{\"name\":\"h\",\"avatar_id\":\"c\",\"url\":\"https://example.org\",\"scopes\":1}",
            "{\"name\":\"hook\",\"avatar_id\":\"cid\",\"url\":\"https://example.org/hook\",\"scopes\":9223372036854775807}",
            "{\"name\":\"hook\",\"avatar_id\":\"cid\",\"url\":\"https://example.org/hook\",\"scopes\":3,\"unknown\":true}"})
    @ParameterizedTest
    void testValidInputs(String json)
    {
        ArgumentCaptor<WebhookCreateData> created = ArgumentCaptor.forClass(WebhookCreateData.class);
        withStoredUser(1);

        assertThatRequestTo(newAction(created))
                .withJsonBody(json)
                .hasStatus(StatusReason.CREATED.code)
                .hasNoBody()
                .whenHandled();

        assertThat(created.getAllValues()).hasSize(1);
    }

    @Test
    void testWithoutAvatar()
    {
        ArgumentCaptor<WebhookCreateData> created = ArgumentCaptor.forClass(WebhookCreateData.class);
        withStoredUser(1);

        assertThatRequestTo(newAction(created))
                .withJsonBody(body("name", "hook", "url", URL, "scopes", 3))
                .hasStatus(StatusReason.CREATED.code)
                .whenHandled();

        assertThat(created.getValue().getAvatarId()).isNull();
    }

    @Test
    void testValidWebhook()
    {
        ArgumentCaptor<WebhookCreateData> created = ArgumentCaptor.forClass(WebhookCreateData.class);
        withStoredUser(1);

        assertThatRequestTo(newAction(created))
                .withJsonBody(VALID)
                .hasStatus(StatusReason.CREATED.code)
                .whenHandled();

        WebhookCreateData webhook = created.getValue();
        assertThat(webhook.getOwnerId()).isEqualTo(USER_ID);
        assertThat(webhook.getUniqueId()).isNotNull();
        assertThat(webhook.getName()).isEqualTo("hook");
        assertThat(webhook.getAvatarId()).isEqualTo("avatar-cid");
        assertThat(webhook.getUrl()).isEqualTo(URL);
        assertThat(webhook.getScopesRaw()).isEqualTo(3);
        assertThat(webhook.getFlagsRaw()).isZero();
        assertThat(webhook.getTimeUpdated()).isNotNull();
    }

    @ValueSource(longs = {0, 1, 4, 1L << 34, (1L << 34) | 4, -1})
    @ParameterizedTest
    void testSystemFlagsAreIgnored(long flags)
    {
        ArgumentCaptor<WebhookCreateData> created = ArgumentCaptor.forClass(WebhookCreateData.class);
        withStoredUser(1);

        assertThatRequestTo(newAction(created))
                .withJsonBody(body("name", "hook", "avatar_id", "cid", "url", URL, "scopes", 3, "flags", flags))
                .hasStatus(StatusReason.CREATED.code)
                .whenHandled();

        assertThat(created.getValue().getFlagsRaw() & Webhook.WebhookFlag.SYSTEM).isZero();
    }

    @Test
    void testUserFlagsAreKept()
    {
        ArgumentCaptor<WebhookCreateData> created = ArgumentCaptor.forClass(WebhookCreateData.class);
        withStoredUser(1);

        assertThatRequestTo(newAction(created))
                .withJsonBody(body("name", "hook", "avatar_id", "cid", "url", URL, "scopes", 3, "flags", 4))
                .hasStatus(StatusReason.CREATED.code)
                .whenHandled();

        assertThat(created.getValue().getFlagsRaw()).isEqualTo(4);
    }

    @Test
    void testMaxWebhooks()
    {
        ArgumentCaptor<WebhookCreateData> created = ArgumentCaptor.forClass(WebhookCreateData.class);
        withStoredUser(WebhookCreateAction.MAX_WEBHOOK_COUNT);

        assertThatRequestTo(newAction(created))
                .withJsonBody(VALID)
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();

        assertThat(created.getAllValues()).isEmpty();
    }

    @Test
    void testLastAllowedWebhook()
    {
        ArgumentCaptor<WebhookCreateData> created = ArgumentCaptor.forClass(WebhookCreateData.class);
        withStoredUser(WebhookCreateAction.MAX_WEBHOOK_COUNT - 1);

        assertThatRequestTo(newAction(created))
                .withJsonBody(VALID)
                .hasStatus(StatusReason.CREATED.code)
                .whenHandled();

        assertThat(created.getAllValues()).hasSize(1);
    }

    @Test
    void testUnknownUser()
    {
        withAccess(USER_ID);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRequestTo(newAction())
                .withJsonBody(VALID)
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testCreateFailure()
    {
        withStoredUser(1);
        WebhookCreateActionImpl action = spy(newAction());
        doReturn(failed(new ErrorResponseException(ErrorResponse.ACCESS_ALREADY_EXISTS))).when(action).create(any(WebhookCreateData.class));

        assertThatRequestTo(action)
                .withJsonBody(VALID)
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testMissingAccess()
    {
        assertThatRequestTo(newAction())
                .withJsonBody(VALID)
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidSubject(String name, String subject)
    {
        withAccess(subject);

        assertThatRequestTo(newAction())
                .withJsonBody(VALID)
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testNullArguments()
    {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> newAction().create(null));
    }

    @Test
    void testCreateStatement()
    {
        InteractionMappingActionImpl<Void> creation = creation();

        assertThat(creation.getContent()).contains("INSERT INTO users.webhooks");
        assertThatStatementIsBound(creation);
    }

    @Test
    void testCreateParams()
    {
        assertThat(creation().getParams())
                .containsEntry("owner_id", USER_ID)
                .containsEntry("name", "hook")
                .containsEntry("avatar_id", "avatar-cid")
                .containsEntry("endpoint", URL)
                .containsEntry("scopes", 3L)
                .containsEntry("flags", 0L);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testCreateApplied() throws Exception
    {
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);

        creation().handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows(true));

        verify(interaction).onSuccess(null);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testCreateExisting() throws Exception
    {
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);

        creation().handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows(false));

        verify(interaction).onFailure(argThat(error ->
                error instanceof InvalidResponseException
                        && ((InvalidResponseException) error).getErrorCode() == ErrorResponse.ACCESS_ALREADY_EXISTS.getCode()));
    }
}
