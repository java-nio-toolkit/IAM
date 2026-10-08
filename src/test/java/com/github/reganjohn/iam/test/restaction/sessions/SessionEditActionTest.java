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

package com.github.reganjohn.iam.test.restaction.sessions;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.exceptions.ProofAccessException;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.requestbody.RequestBody;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.utils.sessions.SessionEditData;
import com.github.reganjohn.iam.internal.requests.restactions.sessions.SessionEditActionImpl;
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

public class SessionEditActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID SESSION_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");

    private SessionEditActionImpl newAction()
    {
        return new SessionEditActionImpl(api);
    }

    private SessionEditActionImpl newAction(ArgumentCaptor<SessionEditData> edited)
    {
        SessionEditActionImpl action = spy(newAction());
        doReturn(completed(null)).when(action).modify(edited.capture());
        return action;
    }

    private void withStoredSession(String userAgent, long flags)
    {
        withProof(SignType.ED25519);
        Session session = withSession(SESSION_ID, USER_ID, userAgent, flags, "thumbprint");
        User user = withUser(USER_ID, "alice", null, 0);
        withSession(user, SESSION_ID, completed(session));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));
    }

    static Stream<Arguments> testInvalidInputs()
    {
        return Stream.of(
                arguments("user_agent_not_string", body("user_agent", 5), "user_agent=STRING_TYPE_COERCE"),
                arguments("user_agent_empty", body("user_agent", ""), "user_agent=STRING_TYPE_MIN"),
                arguments("user_agent_too_long", body("user_agent", StringUtils.repeat('a', User.MAX_NAME_LENGTH + 1)), "user_agent=STRING_TYPE_MAX"),
                arguments("flags_not_number", body("flags", "x"), "flags=NUMBER_TYPE_COERCE"),
                arguments("flags_negative", body("flags", -1), "flags=NUMBER_TYPE_MIN"),
                arguments("every_field_invalid", body("user_agent", 5, "flags", -1), "user_agent=STRING_TYPE_COERCE,flags=NUMBER_TYPE_MIN"));
    }

    static Stream<Arguments> testInvalidSessionId()
    {
        return Stream.of(
                arguments("empty", "", "session_id=BASE_TYPE_REQUIRED"),
                arguments("not_uuid", "not-a-uuid", "session_id=UUID_TYPE_COERCE"),
                arguments("too_short", "02b1a26a-f033-7e2f-8ba7", "session_id=UUID_TYPE_COERCE"),
                arguments("bad_characters", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", "session_id=UUID_TYPE_COERCE"),
                arguments("without_dashes", "02b1a26af0337e2f8ba7543bd0ac755a", "session_id=UUID_TYPE_COERCE"));
    }

    static Stream<Arguments> testInvalidSubject()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "01a0f15f-ef22-7d1e-9a96"),
                arguments("without_dashes", "01a0f15fef227d1e9a96432acf9b644f"));
    }

    static Stream<String> testValidInputs()
    {
        return Stream.of(
                body(),
                body("user_agent", "a"),
                body("user_agent", StringUtils.repeat('a', User.MAX_NAME_LENGTH)),
                body("flags", 0),
                body("user_agent", "curl/8.0", "flags", 1),
                body("unknown", "field"));
    }

    static Stream<String> testParsingFailure()
    {
        return Stream.of(
                body("user_agent", null),
                body("user_agent", DataArray.empty()),
                body("user_agent", DataObject.empty()),
                body("user_agent", true),
                body("flags", null),
                body("flags", 1.5),
                body("flags", true),
                body("flags", DataArray.empty()));
    }

    @Test
    void testNonObject()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .withBody(nonObjectBody())
                .hasFailure(ErrorResponse.INVALID_FROM_OBJECT_BODY)
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testForeignBody()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .withBody(mock(RequestBody.class))
                .hasFailure(ErrorResponse.INVALID_FROM_OBJECT_BODY)
                .hasNoResponse()
                .whenHandled();
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidInputs(String name, String json, String errors)
    {
        withProof(SignType.ED25519);
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .withJsonBody(json)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFormErrors(errors.split("[=,]"))
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidSessionId(String name, String sessionId, String errors)
    {
        withProof(SignType.ED25519);
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(sessionId)
                .withJsonBody(body("user_agent", "curl/8.0"))
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
        withStoredSession("Mozilla/5.0", 0);

        assertThatRequestTo(newAction(ArgumentCaptor.forClass(SessionEditData.class)))
                .withRouteParams(SESSION_ID.toString())
                .withJsonBody(json)
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();
    }

    @MethodSource
    @ParameterizedTest
    void testParsingFailure(String json)
    {
        withProof(SignType.ED25519);
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .withJsonBody(json)
                .hasFailureMatching(failure -> failure instanceof ErrorResponseException)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testEmpty()
    {
        ArgumentCaptor<SessionEditData> edited = ArgumentCaptor.forClass(SessionEditData.class);
        withStoredSession("Mozilla/5.0", 6);

        assertThatRequestTo(newAction(edited))
                .withRouteParams(SESSION_ID.toString())
                .withJsonBody(body())
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        assertThat(edited.getValue().getUserId()).isEqualTo(USER_ID);
        assertThat(edited.getValue().getSessionId()).isEqualTo(SESSION_ID);
        assertThat(edited.getValue().getUserAgent()).isEqualTo("Mozilla/5.0");
        assertThat(edited.getValue().getRawSessionFlags()).isEqualTo(6);
    }

    @Test
    void testUserAgentOnly()
    {
        ArgumentCaptor<SessionEditData> edited = ArgumentCaptor.forClass(SessionEditData.class);
        withStoredSession("Mozilla/5.0", 6);

        assertThatRequestTo(newAction(edited))
                .withRouteParams(SESSION_ID.toString())
                .withJsonBody(body("user_agent", "curl/8.0"))
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        assertThat(edited.getValue().getUserAgent()).isEqualTo("curl/8.0");
        assertThat(edited.getValue().getRawSessionFlags()).isEqualTo(6);
    }

    @Test
    void testFlagsOnly()
    {
        ArgumentCaptor<SessionEditData> edited = ArgumentCaptor.forClass(SessionEditData.class);
        withStoredSession("Mozilla/5.0", 0);

        assertThatRequestTo(newAction(edited))
                .withRouteParams(SESSION_ID.toString())
                .withJsonBody(body("flags", 2))
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        assertThat(edited.getValue().getUserAgent()).isEqualTo("Mozilla/5.0");
        assertThat(edited.getValue().getRawSessionFlags()).isEqualTo(2L & ~Session.SessionFlag.SYSTEM);
    }

    @ValueSource(longs = {0, 1, 2, 3, 7, Integer.MAX_VALUE})
    @ParameterizedTest
    void testSystemFlags(long flags)
    {
        ArgumentCaptor<SessionEditData> edited = ArgumentCaptor.forClass(SessionEditData.class);
        long current = Session.SessionFlag.SYSTEM;
        withStoredSession("Mozilla/5.0", current);

        assertThatRequestTo(newAction(edited))
                .withRouteParams(SESSION_ID.toString())
                .withJsonBody(body("flags", flags))
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        assertThat(edited.getValue().getRawSessionFlags() & Session.SessionFlag.SYSTEM).isEqualTo(current & Session.SessionFlag.SYSTEM);
        assertThat(edited.getValue().getRawSessionFlags() & ~Session.SessionFlag.SYSTEM).isEqualTo(flags & ~Session.SessionFlag.SYSTEM);
    }

    @Test
    void testUnknownUser()
    {
        withProof(SignType.ED25519);
        withAccess(USER_ID);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .withJsonBody(body("user_agent", "curl/8.0"))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.UNKNOWN_USER)
                .whenHandled();
    }

    @Test
    void testUnknownSession()
    {
        withProof(SignType.ED25519);
        User user = withUser(USER_ID, "alice", null, 0);
        withSession(user, SESSION_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION)));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .withJsonBody(body("user_agent", "curl/8.0"))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.UNKNOWN_SESSION)
                .whenHandled();
    }

    @Test
    void testMissingProof()
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .withJsonBody(body("user_agent", "curl/8.0"))
                .hasNoResponse()
                .hasFailureOfType(ProofAccessException.class)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testMissingAccess()
    {
        withProof(SignType.ED25519);

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .withJsonBody(body("user_agent", "curl/8.0"))
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
        withProof(SignType.ED25519);
        withAccess(subject);

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .withJsonBody(body("user_agent", "curl/8.0"))
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
                .isThrownBy(() -> newAction().modify(null));
    }

    @Test
    void testModifyStatement()
    {
        withJCA();
        SessionEditData data = mock(SessionEditData.class);
        InteractionMappingActionImpl<?> modification = (InteractionMappingActionImpl<?>) newAction().modify(data);

        assertThat(modification.getContent()).contains("user_agent = :user_agent", "flags", ":user_id", ":session_id");
    }

    @Test
    @SuppressWarnings("unchecked")
    void testModifyApplied() throws Exception
    {
        withJCA();
        InteractionMappingActionImpl<Void> modification = (InteractionMappingActionImpl<Void>) newAction().modify(mock(SessionEditData.class));
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
        InteractionMappingActionImpl<Void> modification = (InteractionMappingActionImpl<Void>) newAction().modify(mock(SessionEditData.class));
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);
        BufferObject row = mock(BufferObject.class);
        BufferArray rows = mock(BufferArray.class);
        when(row.getBoolean("[applied]")).thenReturn(applied);
        when(rows.isEmpty()).thenReturn(empty);
        when(rows.getObject(0)).thenReturn(row);

        modification.handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows);

        verify(interaction).onFailure(argThat(error ->
                error instanceof InvalidResponseException
                        && ((InvalidResponseException) error).getErrorCode() == ErrorResponse.UNKNOWN_SESSION.getCode()));
    }

    static Stream<Arguments> missingRows()
    {
        return Stream.of(arguments(true, false), arguments(false, false));
    }
}
