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
import com.github.reganjohn.iam.api.utils.applications.ApplicationEditBuilder;
import com.github.reganjohn.iam.api.utils.applications.ApplicationEditData;
import com.github.reganjohn.iam.internal.requests.restactions.applications.ApplicationEditActionImpl;
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

import java.util.Arrays;
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

public class ApplicationEditActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID APPLICATION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");
    private static final String ORIGIN = "https://example.org";
    private static final String CALLBACK = "https://example.org/callback";
    private static final long DELETED = 1L << 34;

    private ApplicationEditActionImpl newAction()
    {
        return new ApplicationEditActionImpl(api);
    }

    private ApplicationEditActionImpl newAction(ArgumentCaptor<ApplicationEditData> modified)
    {
        ApplicationEditActionImpl action = spy(newAction());
        doReturn(completed(null)).when(action).modify(modified.capture());
        return action;
    }

    private Application withStoredApplication(long flags)
    {
        Application application = withApplication(APPLICATION_ID, USER_ID, "app", "description", "icon-cid", ORIGIN, flags, CALLBACK);
        User user = withUser(USER_ID, "alice", null, 0);
        withApplication(user, APPLICATION_ID, completed(application));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));
        return application;
    }

    private static ApplicationEditData newData()
    {
        return new ApplicationEditBuilder()
                .setOwnerId(USER_ID)
                .setUniqueId(APPLICATION_ID)
                .setName("app")
                .setDescription("description")
                .setIconId("icon-cid")
                .setOrigin(ORIGIN)
                .setFlags(4)
                .setRedirectUris(Arrays.asList(CALLBACK))
                .setReplace(true)
                .build();
    }

    @SuppressWarnings("unchecked")
    private InteractionMappingActionImpl<Void> modification()
    {
        withJCA();
        return (InteractionMappingActionImpl<Void>) newAction().modify(newData());
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
                arguments("name_not_string", body("name", 5)),
                arguments("name_empty", body("name", "")),
                arguments("name_too_long", body("name", repeat(Application.MAX_NAME_LENGTH + 1))),
                arguments("description_not_string", body("description", 5)),
                arguments("description_too_long", body("description", repeat(Application.MAX_DESCRIPTION_LENGTH + 1))),
                arguments("icon_not_string", body("icon_id", 5)),
                arguments("icon_too_long", body("icon_id", repeat(Application.ICON_CID_MAX_LENGTH + 1))),
                arguments("flags_not_number", body("flags", "all")),
                arguments("flags_negative", body("flags", -1)),
                arguments("redirect_uris_not_array", body("redirect_uris", CALLBACK)),
                arguments("redirect_uris_empty", body("redirect_uris", uris())),
                arguments("redirect_uris_too_many", body("redirect_uris", uris(CALLBACK, CALLBACK, CALLBACK, CALLBACK, CALLBACK, CALLBACK))),
                arguments("redirect_uris_not_string", body("redirect_uris", uris(5))),
                arguments("redirect_uris_one_not_string", body("redirect_uris", uris(CALLBACK, 5))),
                arguments("redirect_uris_too_long", body("redirect_uris", uris("https://example.org/" + repeat(Application.MAX_URL_LENGTH)))),
                arguments("redirect_uris_one_too_long", body("redirect_uris", uris(CALLBACK, "https://example.org/" + repeat(Application.MAX_URL_LENGTH)))),
                arguments("redirect_uris_not_url", body("redirect_uris", uris("not-a-url"))),
                arguments("redirect_uris_one_not_url", body("redirect_uris", uris(CALLBACK, "not-a-url"))),
                arguments("everything_invalid", body("name", 5, "description", 5, "icon_id", 5, "flags", "all", "redirect_uris", "all")));
    }

    static Stream<Arguments> testInvalidApplicationId()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "04d3c48c-1255-7041-8dc9"),
                arguments("bad_characters", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"),
                arguments("without_dashes", "04d3c48c125570418dc9765df2ce977c"));
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
                .withRouteParams(APPLICATION_ID.toString())
                .withBody(nonObjectBody())
                .hasFailureMatchingSnapshot()
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testForeignBody()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
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
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(json)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidApplicationId(String name, String applicationId)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(applicationId)
                .withJsonBody(body("name", "renamed"))
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @ValueSource(strings = {
            "{}",
            "{\"unknown\":true}",
            "{\"name\":\"renamed\"}",
            "{\"description\":\"another\"}",
            "{\"description\":null}",
            "{\"icon_id\":\"another-cid\"}",
            "{\"flags\":0}",
            "{\"origin\":5}",
            "{\"origin\":\"https://other.example\"}",
            "{\"redirect_uris\":[\"https://example.net/callback\"]}",
            "{\"redirect_uris\":[\"https://example.net/callback\",\"https://example.org/other\"]}",
            "{\"name\":\"renamed\",\"description\":\"another\",\"icon_id\":\"another-cid\",\"flags\":8,\"redirect_uris\":[\"https://example.net/callback\"]}"})
    @ParameterizedTest
    void testValidInputs(String json)
    {
        withStoredApplication(0);
        ArgumentCaptor<ApplicationEditData> modified = ArgumentCaptor.forClass(ApplicationEditData.class);

        assertThatRequestTo(newAction(modified))
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(json)
                .hasStatus(StatusReason.NO_CONTENT.code)
                .hasNoBody()
                .whenHandled();

        assertThat(modified.getAllValues()).hasSize(1);
    }

    @Test
    void testKeepsStoredValues()
    {
        withStoredApplication(4);
        ArgumentCaptor<ApplicationEditData> modified = ArgumentCaptor.forClass(ApplicationEditData.class);

        assertThatRequestTo(newAction(modified))
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody("{}")
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        ApplicationEditData data = modified.getValue();
        assertThat(data.getOwnerId()).isEqualTo(USER_ID);
        assertThat(data.getUniqueId()).isEqualTo(APPLICATION_ID);
        assertThat(data.getName()).isEqualTo("app");
        assertThat(data.getDescription()).isEqualTo("description");
        assertThat(data.getIconId()).isEqualTo("icon-cid");
        assertThat(data.getOrigin()).isEqualTo(ORIGIN);
        assertThat(data.getFlagsRaw()).isEqualTo(4);
        assertThat(data.getRedirectUris()).containsExactly(CALLBACK);
    }

    @Test
    void testOriginIsImmutable()
    {
        withStoredApplication(0);
        ArgumentCaptor<ApplicationEditData> modified = ArgumentCaptor.forClass(ApplicationEditData.class);

        assertThatRequestTo(newAction(modified))
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(body("origin", "https://other.example"))
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        assertThat(modified.getValue().getOrigin()).isEqualTo(ORIGIN);
    }

    @Test
    void testOverridesStoredValues()
    {
        withStoredApplication(4);
        ArgumentCaptor<ApplicationEditData> modified = ArgumentCaptor.forClass(ApplicationEditData.class);

        assertThatRequestTo(newAction(modified))
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(body("name", "renamed", "description", "another", "icon_id", "another-cid", "flags", 8,
                        "redirect_uris", uris("https://example.net/callback", "https://example.org/other")))
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        ApplicationEditData data = modified.getValue();
        assertThat(data.getName()).isEqualTo("renamed");
        assertThat(data.getDescription()).isEqualTo("another");
        assertThat(data.getIconId()).isEqualTo("another-cid");
        assertThat(data.getFlagsRaw()).isEqualTo(8);
        assertThat(data.getRedirectUris()).containsExactly("https://example.net/callback", "https://example.org/other");
    }

    @ValueSource(longs = {0, 1, 8, DELETED, DELETED | 8})
    @ParameterizedTest
    void testSystemFlagsAreKept(long flags)
    {
        withStoredApplication(DELETED | 4);
        ArgumentCaptor<ApplicationEditData> modified = ArgumentCaptor.forClass(ApplicationEditData.class);

        assertThatRequestTo(newAction(modified))
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(body("flags", flags))
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        assertThat(modified.getValue().getFlagsRaw() & DELETED).isEqualTo(DELETED);
    }

    @Test
    void testSystemFlagsAreNotSet()
    {
        withStoredApplication(4);
        ArgumentCaptor<ApplicationEditData> modified = ArgumentCaptor.forClass(ApplicationEditData.class);

        assertThatRequestTo(newAction(modified))
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(body("flags", DELETED | 8))
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        assertThat(modified.getValue().getFlagsRaw()).isEqualTo(8);
    }

    @Test
    void testUnknownUser()
    {
        withAccess(USER_ID);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(body("name", "renamed"))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testUnknownApplication()
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withApplication(user, APPLICATION_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION)));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(body("name", "renamed"))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testModifyFailure()
    {
        withStoredApplication(0);
        ApplicationEditActionImpl action = spy(newAction());
        doReturn(failed(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION))).when(action).modify(any(ApplicationEditData.class));

        assertThatRequestTo(action)
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(body("name", "renamed"))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testMissingAccess()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(body("name", "renamed"))
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
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(body("name", "renamed"))
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
                .isThrownBy(() -> newAction().modify(null));
    }

    @Test
    void testModifyStatement()
    {
        InteractionMappingActionImpl<Void> modification = modification();

        assertThat(modification.getContent().replaceAll("\\s+", " ")).contains("name = :name", "flags = :flags", "description = :description",
                "redirect_uris = :redirect_uris", "icon_id = :icon_id", "owner_id = :user_id", "application_id = :application_id");
        assertThatStatementIsBound(modification);
    }

    @Test
    void testModifyParams()
    {
        assertThat(modification().getParams())
                .containsEntry("user_id", USER_ID)
                .containsEntry("application_id", APPLICATION_ID)
                .containsEntry("name", "app")
                .containsEntry("description", "description")
                .containsEntry("icon_id", "icon-cid")
                .containsEntry("flags", 4L)
                .containsKey("redirect_uris");
    }

    @Test
    @SuppressWarnings("unchecked")
    void testModifyApplied() throws Exception
    {
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);

        modification().handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows(false, true));

        verify(interaction).onSuccess(null);
    }

    @MethodSource
    @ParameterizedTest
    @SuppressWarnings("unchecked")
    void testModifyMissing(boolean empty, boolean applied) throws Exception
    {
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);

        modification().handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows(empty, applied));

        verify(interaction).onFailure(argThat(error ->
                error instanceof InvalidResponseException
                        && ((InvalidResponseException) error).getErrorCode() == ErrorResponse.UNKNOWN_APPLICATION.getCode()));
    }
}
