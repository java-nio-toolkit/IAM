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

package com.github.reganjohn.iam.test.restaction.applications;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.requestbody.RequestBody;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.restactions.ApplicationAction;
import com.github.reganjohn.iam.api.utils.applications.ApplicationCreateBuilder;
import com.github.reganjohn.iam.api.utils.applications.ApplicationCreateData;
import com.github.reganjohn.iam.internal.requests.restactions.applications.ApplicationCreateActionImpl;
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

import java.util.Collections;
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

public class ApplicationCreateActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final String ORIGIN = "https://example.org";
    private static final String CALLBACK = "https://example.org/callback";
    private static final long DELETED = 1L << 34;

    private ApplicationCreateActionImpl newAction()
    {
        return new ApplicationCreateActionImpl(api);
    }

    private ApplicationCreateActionImpl newAction(ArgumentCaptor<ApplicationCreateData> created)
    {
        ApplicationCreateActionImpl action = spy(newAction());
        doReturn(completed(null)).when(action).create(created.capture());
        return action;
    }

    private void withStoredUser(int count)
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withApplicationCount(user, completed(count));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));
    }

    private static String valid(Object... extra)
    {
        Object[] fields = new Object[6 + extra.length];
        fields[0] = "name";
        fields[1] = "app";
        fields[2] = "origin";
        fields[3] = ORIGIN;
        fields[4] = "redirect_uris";
        fields[5] = uris(CALLBACK);
        System.arraycopy(extra, 0, fields, 6, extra.length);
        return body(fields);
    }

    private static ApplicationCreateData newData()
    {
        return new ApplicationCreateBuilder()
                .setOwnerId(USER_ID)
                .setUniqueId(UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c"))
                .setName("app")
                .setDescription("description")
                .setIconId("icon-cid")
                .setOrigin(ORIGIN)
                .setFlags(4)
                .setRedirectUris(Collections.singletonList(CALLBACK))
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

    private static String repeat(int length)
    {
        return new String(new char[length]).replace('\0', 'a');
    }

    private static DataArray uris(Object... values)
    {
        DataArray array = DataArray.empty();
        for (Object value : values)
            array.add(value);
        return array;
    }

    static Stream<Arguments> testInvalidInputs()
    {
        return Stream.of(
                arguments("empty_body", body()),
                arguments("missing_name", body("origin", ORIGIN, "redirect_uris", uris(CALLBACK))),
                arguments("name_not_string", valid().replace("\"app\"", "5")),
                arguments("name_empty", valid().replace("\"app\"", "\"\"")),
                arguments("name_too_long", valid().replace("\"app\"", "\"" + repeat(Application.MAX_NAME_LENGTH + 1) + "\"")),
                arguments("missing_origin", body("name", "app", "redirect_uris", uris(CALLBACK))),
                arguments("origin_not_string", body("name", "app", "origin", 5, "redirect_uris", uris(CALLBACK))),
                arguments("origin_empty", body("name", "app", "origin", "", "redirect_uris", uris(CALLBACK))),
                arguments("origin_not_url", body("name", "app", "origin", "not-a-url", "redirect_uris", uris(CALLBACK))),
                arguments("origin_not_https", body("name", "app", "origin", "http://example.org", "redirect_uris", uris(CALLBACK))),
                arguments("origin_localhost", body("name", "app", "origin", "https://localhost", "redirect_uris", uris(CALLBACK))),
                arguments("origin_loopback", body("name", "app", "origin", "https://127.0.0.1", "redirect_uris", uris(CALLBACK))),
                arguments("origin_private", body("name", "app", "origin", "https://192.168.0.1", "redirect_uris", uris(CALLBACK))),
                arguments("description_not_string", valid("description", 5)),
                arguments("description_too_long", valid("description", repeat(Application.MAX_DESCRIPTION_LENGTH + 1))),
                arguments("icon_not_string", valid("icon_id", 5)),
                arguments("icon_too_long", valid("icon_id", repeat(Application.ICON_CID_MAX_LENGTH + 1))),
                arguments("flags_not_number", valid("flags", "all")),
                arguments("flags_negative", valid("flags", -1)),
                arguments("missing_redirect_uris", body("name", "app", "origin", ORIGIN)),
                arguments("redirect_uris_not_array", body("name", "app", "origin", ORIGIN, "redirect_uris", CALLBACK)),
                arguments("redirect_uris_empty", body("name", "app", "origin", ORIGIN, "redirect_uris", uris())),
                arguments("redirect_uris_too_many", body("name", "app", "origin", ORIGIN, "redirect_uris", uris(CALLBACK, CALLBACK, CALLBACK, CALLBACK, CALLBACK, CALLBACK))),
                arguments("redirect_uris_not_string", body("name", "app", "origin", ORIGIN, "redirect_uris", uris(5))),
                arguments("redirect_uris_one_not_string", body("name", "app", "origin", ORIGIN, "redirect_uris", uris(CALLBACK, 5))),
                arguments("redirect_uris_too_long", body("name", "app", "origin", ORIGIN, "redirect_uris", uris("https://example.org/" + repeat(Application.MAX_URL_LENGTH)))),
                arguments("redirect_uris_one_too_long", body("name", "app", "origin", ORIGIN, "redirect_uris", uris(CALLBACK, "https://example.org/" + repeat(Application.MAX_URL_LENGTH)))),
                arguments("redirect_uris_not_url", body("name", "app", "origin", ORIGIN, "redirect_uris", uris("not-a-url"))),
                arguments("redirect_uris_one_not_url", body("name", "app", "origin", ORIGIN, "redirect_uris", uris(CALLBACK, "not-a-url"))),
                arguments("everything_invalid", body("name", 5, "origin", 5, "description", 5, "icon_id", 5, "flags", "all", "redirect_uris", "all")));
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
    @ParameterizedTest(name = "{0}")
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
            "{\"name\":\"a\",\"origin\":\"https://example.org\",\"redirect_uris\":[\"https://example.org/callback\"]}",
            "{\"name\":\"app\",\"origin\":\"https://example.org\",\"description\":\"\",\"redirect_uris\":[\"https://example.org/callback\"]}",
            "{\"name\":\"app\",\"origin\":\"https://example.org\",\"description\":null,\"redirect_uris\":[\"https://example.org/callback\"]}",
            "{\"name\":\"app\",\"origin\":\"https://example.org\",\"redirect_uris\":[\"https://example.org/1\",\"https://example.org/2\",\"https://example.org/3\",\"https://example.org/4\",\"https://example.org/5\"]}",
            "{\"name\":\"app\",\"origin\":\"https://example.org\",\"redirect_uris\":[\"https://example.org/callback\"],\"unknown\":true}",
            "{\"name\":\"app\",\"origin\":\"https://example.org\",\"description\":\"description\",\"icon_id\":\"icon-cid\",\"flags\":4,\"redirect_uris\":[\"https://example.org/callback\"]}"})
    @ParameterizedTest
    void testValidInputs(String json)
    {
        ArgumentCaptor<ApplicationCreateData> created = ArgumentCaptor.forClass(ApplicationCreateData.class);
        withStoredUser(1);

        assertThatRequestTo(newAction(created))
                .withJsonBody(json)
                .hasStatus(StatusReason.CREATED.code)
                .hasNoBody()
                .whenHandled();

        assertThat(created.getAllValues()).hasSize(1);
    }

    @Test
    void testMinimalApplication()
    {
        ArgumentCaptor<ApplicationCreateData> created = ArgumentCaptor.forClass(ApplicationCreateData.class);
        withStoredUser(1);

        assertThatRequestTo(newAction(created))
                .withJsonBody(valid())
                .hasStatus(StatusReason.CREATED.code)
                .whenHandled();

        ApplicationCreateData application = created.getValue();
        assertThat(application.getOwnerId()).isEqualTo(USER_ID);
        assertThat(application.getUniqueId()).isNotNull();
        assertThat(application.getName()).isEqualTo("app");
        assertThat(application.getOrigin()).isEqualTo(ORIGIN);
        assertThat(application.getDescription()).isNull();
        assertThat(application.getIconId()).isNull();
        assertThat(application.getFlagsRaw()).isZero();
        assertThat(application.getRedirectUris()).containsExactly(CALLBACK);
    }

    @Test
    void testValidApplication()
    {
        ArgumentCaptor<ApplicationCreateData> created = ArgumentCaptor.forClass(ApplicationCreateData.class);
        withStoredUser(1);

        assertThatRequestTo(newAction(created))
                .withJsonBody(valid("description", "description", "icon_id", "icon-cid", "flags", 4))
                .hasStatus(StatusReason.CREATED.code)
                .whenHandled();

        ApplicationCreateData application = created.getValue();
        assertThat(application.getDescription()).isEqualTo("description");
        assertThat(application.getIconId()).isEqualTo("icon-cid");
        assertThat(application.getFlagsRaw()).isEqualTo(4);
    }

    @ValueSource(longs = {0, 1, 4, DELETED, DELETED | 4})
    @ParameterizedTest
    void testSystemFlagsAreIgnored(long flags)
    {
        ArgumentCaptor<ApplicationCreateData> created = ArgumentCaptor.forClass(ApplicationCreateData.class);
        withStoredUser(1);

        assertThatRequestTo(newAction(created))
                .withJsonBody(valid("flags", flags))
                .hasStatus(StatusReason.CREATED.code)
                .whenHandled();

        assertThat(created.getValue().getFlagsRaw() & Application.ApplicationFlag.SYSTEM).isZero();
    }

    @Test
    void testMaxApplications()
    {
        ArgumentCaptor<ApplicationCreateData> created = ArgumentCaptor.forClass(ApplicationCreateData.class);
        withStoredUser(ApplicationAction.MAX_APPLICATION_COUNT);

        assertThatRequestTo(newAction(created))
                .withJsonBody(valid())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();

        assertThat(created.getAllValues()).isEmpty();
    }

    @Test
    void testLastAllowedApplication()
    {
        ArgumentCaptor<ApplicationCreateData> created = ArgumentCaptor.forClass(ApplicationCreateData.class);
        withStoredUser(ApplicationAction.MAX_APPLICATION_COUNT - 1);

        assertThatRequestTo(newAction(created))
                .withJsonBody(valid())
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
                .withJsonBody(valid())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testCreateFailure()
    {
        withStoredUser(1);
        ApplicationCreateActionImpl action = spy(newAction());
        doReturn(failed(new ErrorResponseException(ErrorResponse.APPLICATION_ALREADY_EXISTS))).when(action).create(any(ApplicationCreateData.class));

        assertThatRequestTo(action)
                .withJsonBody(valid())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testMissingAccess()
    {
        assertThatRequestTo(newAction())
                .withJsonBody(valid())
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
                .withJsonBody(valid())
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

        assertThat(creation.getContent()).contains("INSERT INTO integrations.applications");
        assertThatStatementIsBound(creation);
    }

    @Test
    void testCreateParams()
    {
        assertThat(creation().getParams())
                .containsEntry("user_id", USER_ID)
                .containsEntry("name", "app")
                .containsEntry("description", "description")
                .containsEntry("icon_id", "icon-cid")
                .containsEntry("origin", ORIGIN)
                .containsEntry("flags", 4L)
                .containsKeys("application_id", "redirect_uris");
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
                        && ((InvalidResponseException) error).getErrorCode() == ErrorResponse.APPLICATION_ALREADY_EXISTS.getCode()));
    }
}
