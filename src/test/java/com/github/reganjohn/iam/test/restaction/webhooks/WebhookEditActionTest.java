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
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.requestbody.RequestBody;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.entities.Webhook;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.requests.restactions.webhooks.WebhookEditActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.api.utils.data.BufferObject;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

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

public class WebhookEditActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID WEBHOOK_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");
    private static final String URL = "https://example.org/hook";

    private WebhookEditActionImpl newAction()
    {
        return new WebhookEditActionImpl(api);
    }

    private Webhook withStoredWebhook()
    {
        Webhook webhook = withWebhook(WEBHOOK_ID, USER_ID, "hook", "avatar-cid", URL, 3, 0);
        User user = withUser(USER_ID, "alice", null, 0);
        withWebhook(user, WEBHOOK_ID, completed(webhook));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));
        return webhook;
    }

    private WebhookEditActionImpl newAction(ArgumentCaptor<DataObject> modified)
    {
        WebhookEditActionImpl action = spy(newAction());
        doReturn(completed(null)).when(action).modify(any(Webhook.class), modified.capture());
        return action;
    }

    @SuppressWarnings("unchecked")
    private InteractionMappingActionImpl<Void> modification(Webhook webhook, DataObject body)
    {
        withJCA();
        return (InteractionMappingActionImpl<Void>) newAction().modify(webhook, body);
    }

    private static BufferArray rows(boolean empty, boolean applied)
    {
        BufferObject row = mock(BufferObject.class);
        BufferArray rows = mock(BufferArray.class);
        when(row.getBoolean("[applied]")).thenReturn(applied);
        when(rows.isEmpty()).thenReturn(empty);
        when(rows.getObject(0)).thenReturn(row);
        return rows;
    }

    static Stream<Arguments> testInvalidInputs()
    {
        String longName = new String(new char[Webhook.MAX_NAME_LENGTH + 1]).replace('\0', 'a');
        String longAvatar = new String(new char[Webhook.ICON_CID_MAX_LENGTH + 1]).replace('\0', 'a');
        return Stream.of(
                arguments("name_not_string", body("name", 5), "name=STRING_TYPE_COERCE"),
                arguments("name_empty", body("name", ""), "name=STRING_TYPE_MIN"),
                arguments("name_too_long", body("name", longName), "name=STRING_TYPE_MAX"),
                arguments("avatar_not_string", body("avatar_id", 5), "avatar_id=STRING_TYPE_COERCE"),
                arguments("avatar_too_long", body("avatar_id", longAvatar), "avatar_id=STRING_TYPE_MAX"),
                arguments("url_not_string", body("url", 5), "url=STRING_TYPE_COERCE"),
                arguments("url_not_url", body("url", "not-a-url"), "url=BASE_TYPE_CHOICES"),
                arguments("url_not_https", body("url", "http://example.org/hook"), "url=BASE_TYPE_CHOICES"),
                arguments("url_localhost", body("url", "https://localhost/hook"), "url=BASE_TYPE_CHOICES"),
                arguments("url_loopback", body("url", "https://127.0.0.1/hook"), "url=BASE_TYPE_CHOICES"),
                arguments("url_private", body("url", "https://192.168.0.1/hook"), "url=BASE_TYPE_CHOICES"),
                arguments("scopes_not_number", body("scopes", "all"), "scopes=NUMBER_TYPE_COERCE"),
                arguments("everything_invalid", body("name", 5, "avatar_id", 5, "url", 5, "scopes", "all"), "name=STRING_TYPE_COERCE,avatar_id=STRING_TYPE_COERCE,url=STRING_TYPE_COERCE,scopes=NUMBER_TYPE_COERCE"));
    }

    static Stream<Arguments> testInvalidWebhookId()
    {
        return Stream.of(
                arguments("empty", "", "webhook_id=BASE_TYPE_REQUIRED"),
                arguments("not_uuid", "not-a-uuid", "webhook_id=UUID_TYPE_COERCE"),
                arguments("too_short", "04d3c48c-1255-7041-8dc9", "webhook_id=UUID_TYPE_COERCE"),
                arguments("bad_characters", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", "webhook_id=UUID_TYPE_COERCE"),
                arguments("without_dashes", "04d3c48c125570418dc9765df2ce977c", "webhook_id=UUID_TYPE_COERCE"));
    }

    static Stream<Arguments> testInvalidSubject()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "01a0f15f-ef22-7d1e-9a96"),
                arguments("without_dashes", "01a0f15fef227d1e9a96432acf9b644f"));
    }

    static Stream<Arguments> testModifyMissing()
    {
        return Stream.of(arguments(true, false), arguments(false, false));
    }

    @Test
    void testNonObject()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(WEBHOOK_ID.toString())
                .withBody(mock(RequestBody.class))
                .hasFailure(ErrorResponse.INVALID_FROM_OBJECT_BODY)
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testNonObjectBody()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(WEBHOOK_ID.toString())
                .withBody(nonObjectBody())
                .hasFailure(ErrorResponse.INVALID_FROM_OBJECT_BODY)
                .hasNoResponse()
                .whenHandled();
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidInputs(String name, String json, String errors)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(WEBHOOK_ID.toString())
                .withJsonBody(json)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFormErrors(errors.split("[=,]"))
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidWebhookId(String name, String webhookId, String errors)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(webhookId)
                .withJsonBody(body("name", "renamed"))
                .hasFailureOfType(ErrorResponseException.class)
                .hasFormErrors(errors.split("[=,]"))
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @ValueSource(strings = {
            "{}",
            "{\"unknown\":true}",
            "{\"name\":\"renamed\"}",
            "{\"avatar_id\":\"another-cid\"}",
            "{\"url\":\"https://example.net/hook\"}",
            "{\"scopes\":0}",
            "{\"name\":\"renamed\",\"avatar_id\":\"another-cid\",\"url\":\"https://example.net/hook\",\"scopes\":7}"})
    @ParameterizedTest
    void testValidInputs(String json)
    {
        Webhook webhook = withStoredWebhook();
        ArgumentCaptor<DataObject> modified = ArgumentCaptor.forClass(DataObject.class);

        assertThatRequestTo(newAction(modified))
                .withRouteParams(WEBHOOK_ID.toString())
                .withJsonBody(json)
                .hasStatus(StatusReason.NO_CONTENT.code)
                .hasNoBody()
                .whenHandled();

        verify(webhook, never()).delete();
        assertThat(modified.getValue().toString()).isEqualTo(DataObject.fromJson(json).toString());
    }

    @Test
    void testValidWebhook()
    {
        Webhook webhook = withStoredWebhook();
        ArgumentCaptor<DataObject> modified = ArgumentCaptor.forClass(DataObject.class);
        WebhookEditActionImpl action = newAction(modified);

        assertThatRequestTo(action)
                .withRouteParams(WEBHOOK_ID.toString())
                .withJsonBody(body("name", "renamed"))
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        verify(action).modify(webhook, modified.getValue());
    }

    @Test
    void testUnknownUser()
    {
        withAccess(USER_ID);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRequestTo(newAction())
                .withRouteParams(WEBHOOK_ID.toString())
                .withJsonBody(body("name", "renamed"))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.UNKNOWN_USER)
                .whenHandled();
    }

    @Test
    void testUnknownWebhook()
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withWebhook(user, WEBHOOK_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_WEBHOOK)));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));

        assertThatRequestTo(newAction())
                .withRouteParams(WEBHOOK_ID.toString())
                .withJsonBody(body("name", "renamed"))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.UNKNOWN_WEBHOOK)
                .whenHandled();
    }

    @Test
    void testModifyFailure()
    {
        withStoredWebhook();
        WebhookEditActionImpl action = spy(newAction());
        doReturn(failed(new ErrorResponseException(ErrorResponse.UNKNOWN_WEBHOOK))).when(action).modify(any(Webhook.class), any(DataObject.class));

        assertThatRequestTo(action)
                .withRouteParams(WEBHOOK_ID.toString())
                .withJsonBody(body("name", "renamed"))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.UNKNOWN_WEBHOOK)
                .whenHandled();
    }

    @Test
    void testMissingAccess()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(WEBHOOK_ID.toString())
                .withJsonBody(body("name", "renamed"))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.MISSING_ACCESS)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidSubject(String name, String subject)
    {
        withAccess(subject);

        assertThatRequestTo(newAction())
                .withRouteParams(WEBHOOK_ID.toString())
                .withJsonBody(body("name", "renamed"))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.INVALID_TOKEN)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testNullArguments()
    {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> newAction().modify(null, DataObject.empty()));
        assertThatIllegalArgumentException()
                .isThrownBy(() -> newAction().modify(withWebhook(WEBHOOK_ID, USER_ID, "hook", null, URL, 0, 0), null));
    }

    @Test
    void testModifyStatement()
    {
        InteractionMappingActionImpl<Void> modification = modification(withWebhook(WEBHOOK_ID, USER_ID, "hook", null, URL, 0, 0), DataObject.empty());

        assertThat(modification.getContent()).contains("name = :name", "avatar_id = :avatar_id", "endpoint = :endpoint",
                "scopes = :scopes", "updated_at = :updated_at", "owner_id = :owner_id", "webhook_id = :webhook_id");
        assertThatStatementIsBound(modification);
    }

    @Test
    void testModifyKeepsStoredValues()
    {
        InteractionMappingActionImpl<Void> modification = modification(withWebhook(WEBHOOK_ID, USER_ID, "hook", "avatar-cid", URL, 3, 4), DataObject.empty());

        assertThat(modification.getParams())
                .containsEntry("owner_id", USER_ID)
                .containsEntry("webhook_id", WEBHOOK_ID)
                .containsEntry("name", "hook")
                .containsEntry("avatar_id", "avatar-cid")
                .containsEntry("endpoint", URL)
                .containsEntry("scopes", 3L)
                .containsEntry("flags", 4L)
                .containsKey("updated_at");
    }

    @Test
    void testModifyOverridesStoredValues()
    {
        DataObject body = DataObject.empty()
                .put("name", "renamed")
                .put("avatar_id", "another-cid")
                .put("url", "https://example.net/hook")
                .put("scopes", 7);
        InteractionMappingActionImpl<Void> modification = modification(withWebhook(WEBHOOK_ID, USER_ID, "hook", "avatar-cid", URL, 3, 4), body);

        assertThat(modification.getParams())
                .containsEntry("name", "renamed")
                .containsEntry("avatar_id", "another-cid")
                .containsEntry("endpoint", "https://example.net/hook")
                .containsEntry("scopes", 7L)
                .containsEntry("flags", 4L);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testModifyApplied() throws Exception
    {
        InteractionMappingActionImpl<Void> modification = modification(withWebhook(WEBHOOK_ID, USER_ID, "hook", null, URL, 0, 0), DataObject.empty());
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);

        modification.handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows(false, true));

        verify(interaction).onSuccess(null);
    }

    @MethodSource
    @ParameterizedTest
    @SuppressWarnings("unchecked")
    void testModifyMissing(boolean empty, boolean applied) throws Exception
    {
        InteractionMappingActionImpl<Void> modification = modification(withWebhook(WEBHOOK_ID, USER_ID, "hook", null, URL, 0, 0), DataObject.empty());
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);

        modification.handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows(empty, applied));

        verify(interaction).onFailure(argThat(error ->
                error instanceof InvalidResponseException
                        && ((InvalidResponseException) error).getErrorCode() == ErrorResponse.UNKNOWN_WEBHOOK.getCode()));
    }
}
