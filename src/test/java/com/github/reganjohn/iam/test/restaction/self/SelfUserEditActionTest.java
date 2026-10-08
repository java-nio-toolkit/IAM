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

package com.github.reganjohn.iam.test.restaction.self;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.requestbody.RequestBody;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.utils.users.UserEditBuilder;
import com.github.reganjohn.iam.api.utils.users.UserEditData;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserEditActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.api.utils.data.BufferObject;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import org.apache.commons.lang3.StringUtils;
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

public class SelfUserEditActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");

    private SelfUserEditActionImpl newAction()
    {
        return new SelfUserEditActionImpl(api);
    }

    private SelfUserEditActionImpl newAction(ArgumentCaptor<UserEditData> edited)
    {
        SelfUserEditActionImpl action = spy(newAction());
        doReturn(completed(null)).when(action).modify(edited.capture());
        return action;
    }

    static Stream<Arguments> testInvalidInputs()
    {
        String username = StringUtils.repeat('a', User.MAX_NAME_LENGTH + 1);
        String avatar = StringUtils.repeat('a', User.AVATAR_CID_MAX_LENGTH + 1);
        return Stream.of(
                arguments("username_not_string", body("username", 5), "username=STRING_TYPE_COERCE"),
                arguments("username_empty", body("username", ""), "username=STRING_TYPE_MIN"),
                arguments("username_too_long", body("username", username), "username=STRING_TYPE_MAX"),
                arguments("avatar_not_string", body("avatar_id", 5), "avatar_id=STRING_TYPE_COERCE"),
                arguments("avatar_too_long", body("avatar_id", avatar), "avatar_id=STRING_TYPE_MAX"),
                arguments("flags_not_number", body("flags", "x"), "flags=NUMBER_TYPE_COERCE"),
                arguments("flags_negative", body("flags", -1), "flags=NUMBER_TYPE_MIN"),
                arguments("every_field_invalid", body("username", 5, "avatar_id", 5, "flags", -1), "username=STRING_TYPE_COERCE,avatar_id=STRING_TYPE_COERCE,flags=NUMBER_TYPE_MIN"));
    }

    static Stream<String> testValidInputs()
    {
        return Stream.of(
                body(),
                body("username", "a"),
                body("username", StringUtils.repeat('a', User.MAX_NAME_LENGTH)),
                body("avatar_id", ""),
                body("avatar_id", StringUtils.repeat('a', User.AVATAR_CID_MAX_LENGTH)),
                body("flags", 0),
                body("username", "alice", "avatar_id", "cid", "flags", 1),
                body("session", session("flags", -1)),
                body("unknown", "field"));
    }

    static Stream<String> testParsingFailure()
    {
        return Stream.of(
                body("username", null),
                body("username", DataArray.empty()),
                body("username", DataObject.empty()),
                body("username", true),
                body("avatar_id", null),
                body("avatar_id", DataObject.empty()),
                body("avatar_id", DataArray.empty()),
                body("flags", null),
                body("flags", 1.5),
                body("flags", true),
                body("flags", DataArray.empty()));
    }

    @Test
    void testNonObject()
    {
        assertThatRequestTo(newAction())
                .withBody(nonObjectBody())
                .hasFailure(ErrorResponse.INVALID_FROM_OBJECT_BODY)
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testForeignBody()
    {
        assertThatRequestTo(newAction())
                .withBody(mock(RequestBody.class))
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
                .withJsonBody(json)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFormErrors(errors.split("[=,]"))
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest
    void testValidInputs(String json)
    {
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(withUser(USER_ID, "alice", "avatar-cid", 0)));

        assertThatRequestTo(newAction(ArgumentCaptor.forClass(UserEditData.class)))
                .withJsonBody(json)
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();
    }

    @MethodSource
    @ParameterizedTest
    void testParsingFailure(String json)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withJsonBody(json)
                .hasFailureMatching(failure -> failure instanceof ErrorResponseException)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testEmpty()
    {
        ArgumentCaptor<UserEditData> edited = ArgumentCaptor.forClass(UserEditData.class);
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(withUser(USER_ID, "alice", "avatar-cid", 6)));

        assertThatRequestTo(newAction(edited))
                .withJsonBody(body())
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        assertThat(edited.getValue().getUserId()).isEqualTo(USER_ID);
        assertThat(edited.getValue().getName()).isEqualTo("alice");
        assertThat(edited.getValue().getAvatarId()).isEqualTo("avatar-cid");
        assertThat(edited.getValue().getRawUserFlags()).isEqualTo(6);
    }

    @Test
    void testUsernameOnly()
    {
        ArgumentCaptor<UserEditData> edited = ArgumentCaptor.forClass(UserEditData.class);
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(withUser(USER_ID, "alice", "avatar-cid", 6)));

        assertThatRequestTo(newAction(edited))
                .withJsonBody(body("username", "bob"))
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        assertThat(edited.getValue().getName()).isEqualTo("bob");
        assertThat(edited.getValue().getAvatarId()).isEqualTo("avatar-cid");
        assertThat(edited.getValue().getRawUserFlags()).isEqualTo(6);
    }

    @Test
    void testAvatarOnly()
    {
        ArgumentCaptor<UserEditData> edited = ArgumentCaptor.forClass(UserEditData.class);
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(withUser(USER_ID, "alice", "avatar-cid", 6)));

        assertThatRequestTo(newAction(edited))
                .withJsonBody(body("avatar_id", "other-cid"))
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        assertThat(edited.getValue().getName()).isEqualTo("alice");
        assertThat(edited.getValue().getAvatarId()).isEqualTo("other-cid");
        assertThat(edited.getValue().getRawUserFlags()).isEqualTo(6);
    }

    @Test
    void testFlagsOnly()
    {
        ArgumentCaptor<UserEditData> edited = ArgumentCaptor.forClass(UserEditData.class);
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(withUser(USER_ID, "alice", "avatar-cid", 0)));

        assertThatRequestTo(newAction(edited))
                .withJsonBody(body("flags", 2))
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        assertThat(edited.getValue().getName()).isEqualTo("alice");
        assertThat(edited.getValue().getAvatarId()).isEqualTo("avatar-cid");
        assertThat(edited.getValue().getRawUserFlags()).isEqualTo(2L & ~User.UserFlag.SYSTEM);
    }

    @ValueSource(longs = {0, 1, 2, 3, 7, Integer.MAX_VALUE})
    @ParameterizedTest
    void testSystemFlags(long flags)
    {
        ArgumentCaptor<UserEditData> edited = ArgumentCaptor.forClass(UserEditData.class);
        long current = User.UserFlag.SYSTEM;
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(withUser(USER_ID, "alice", null, current)));

        assertThatRequestTo(newAction(edited))
                .withJsonBody(body("flags", flags))
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        assertThat(edited.getValue().getRawUserFlags() & User.UserFlag.SYSTEM).isEqualTo(current & User.UserFlag.SYSTEM);
        assertThat(edited.getValue().getRawUserFlags() & ~User.UserFlag.SYSTEM).isEqualTo(flags & ~User.UserFlag.SYSTEM);
    }

    @Test
    void testUnknownUser()
    {
        withAccess(USER_ID);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRequestTo(newAction())
                .withJsonBody(body("username", "bob"))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.UNKNOWN_USER)
                .whenHandled();
    }

    @Test
    void testNullArguments()
    {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> newAction().modify(null));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testModifyApplied() throws Exception
    {
        withJCA();
        InteractionMappingActionImpl<Void> modification = (InteractionMappingActionImpl<Void>) newAction().modify(mock(UserEditData.class));
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);
        BufferObject row = mock(BufferObject.class);
        BufferArray rows = mock(BufferArray.class);
        when(row.getBoolean("[applied]")).thenReturn(true);
        when(rows.isEmpty()).thenReturn(false);
        when(rows.getObject(0)).thenReturn(row);

        modification.handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows);

        verify(interaction).onSuccess(null);
    }

    @MethodSource("missingRows")
    @ParameterizedTest
    @SuppressWarnings("unchecked")
    void testModifyMissing(boolean empty, boolean applied) throws Exception
    {
        withJCA();
        InteractionMappingActionImpl<Void> modification = (InteractionMappingActionImpl<Void>) newAction().modify(mock(UserEditData.class));
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);
        BufferObject row = mock(BufferObject.class);
        BufferArray rows = mock(BufferArray.class);
        when(row.getBoolean("[applied]")).thenReturn(applied);
        when(rows.isEmpty()).thenReturn(empty);
        when(rows.getObject(0)).thenReturn(row);

        modification.handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows);

        verify(interaction).onFailure(argThat(error ->
                error instanceof InvalidResponseException
                        && ((InvalidResponseException) error).getErrorCode() == ErrorResponse.UNKNOWN_USER.getCode()));
    }

    static Stream<Arguments> missingRows()
    {
        return Stream.of(arguments(true, false), arguments(false, false));
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
    void testMissingAccess()
    {
        assertThatRequestTo(newAction())
                .withJsonBody(body("username", "bob"))
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
                .withJsonBody(body("username", "bob"))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.INVALID_TOKEN)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testModifyStatement()
    {
        withJCA();
        UserEditData data = new UserEditBuilder().setUserId(USER_ID).setName("alice").setAvatarId("avatar-cid").setUserFlags(0).build();
        InteractionMappingActionImpl<Void> modification = (InteractionMappingActionImpl<Void>) newAction().modify(data);

        assertThat(modification.getContent()).contains("username = :username", "avatar_id = :avatar_id", "flags = :flags", "user_id = :user_id");
    }
}
