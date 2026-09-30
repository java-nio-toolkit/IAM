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

import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.requests.restactions.sessions.SessionDeleteActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SessionDeleteActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID SESSION_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");

    private SessionDeleteActionImpl newAction()
    {
        return new SessionDeleteActionImpl(api);
    }

    private User withStoredUser(UUID sessionId, Session session, int count)
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withSession(user, sessionId, completed(session));
        withSessionCount(user, completed(count));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));
        return user;
    }

    static Stream<Arguments> testInvalidInputs()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "02b1a26a-f033-7e2f-8ba7"),
                arguments("bad_characters", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"),
                arguments("without_dashes", "02b1a26af0337e2f8ba7543bd0ac755a"));
    }

    static Stream<Arguments> testInvalidSubject()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "01a0f15f-ef22-7d1e-9a96"),
                arguments("without_dashes", "01a0f15fef227d1e9a96432acf9b644f"));
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidInputs(String name, String sessionId)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(sessionId)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @ValueSource(strings = {
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "02B1A26A-F033-7E2F-8BA7-543BD0AC755A",
            "02b1a26a-f033-7e2f-8ba7-543bd0ac755a"})
    @ParameterizedTest
    void testValidInputs(String sessionId)
    {
        UUID id = UUID.fromString(sessionId);
        User user = withStoredUser(id, withSession(id, USER_ID, null, 0, "thumbprint"), 2);

        assertThatRequestTo(newAction())
                .withRouteParams(sessionId)
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        verify(user).retrieveSessionById(id);
    }

    @Test
    void testValidSession()
    {
        Session session = withSession(SESSION_ID, USER_ID, "Mozilla/5.0", 0, "thumbprint");
        InteractionCallbackAction<Void> deletion = completed(null);
        when(session.delete()).thenReturn(deletion);
        withStoredUser(SESSION_ID, session, 2);

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .hasStatus(StatusReason.NO_CONTENT.code)
                .hasNoBody()
                .whenHandled();

        verify(session).delete();
        verify(deletion).queue(any(), any());
    }

    @Test
    void testSingleSession()
    {
        Session session = withSession(SESSION_ID, USER_ID, "Mozilla/5.0", 0, "thumbprint");
        withStoredUser(SESSION_ID, session, 1);

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();

        verify(session, never()).delete();
    }

    @Test
    void testUnknownUser()
    {
        withAccess(USER_ID);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testUnknownSession()
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withSession(user, SESSION_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION)));
        withSessionCount(user, completed(2));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testDeleteFailure()
    {
        Session session = withSession(SESSION_ID, USER_ID, "Mozilla/5.0", 0, "thumbprint");
        InteractionCallbackAction<Void> deletion = failed(new ErrorResponseException(ErrorResponse.MISSING_ACCESS));
        when(session.delete()).thenReturn(deletion);
        withStoredUser(SESSION_ID, session, 2);

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testMissingAccess()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
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
                .withRouteParams(SESSION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }
}
