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
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.requests.restactions.sessions.SessionRetrieveActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SessionRetrieveActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID SESSION_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");

    private SessionRetrieveActionImpl newAction()
    {
        return new SessionRetrieveActionImpl(api);
    }

    private User withStoredSession(String userAgent, long flags)
    {
        AccessEntryData entry = mock(AccessEntryData.class);
        when(entry.toData()).thenReturn(DataObject.empty().put("kty", "OKP").put("kid", "key-id"));
        Session session = withSession(SESSION_ID, USER_ID, userAgent, flags, "thumbprint");
        withAccessEntry(session, completed(entry));
        User user = withUser(USER_ID, "alice", null, 0);
        withSession(user, SESSION_ID, completed(session));
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
        AccessEntryData entry = mock(AccessEntryData.class);
        when(entry.toData()).thenReturn(DataObject.empty());
        Session session = withSession(id, USER_ID, null, 0, "thumbprint");
        withAccessEntry(session, completed(entry));
        User user = withUser(USER_ID, "alice", null, 0);
        withSession(user, id, completed(session));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));

        assertThatRequestTo(newAction())
                .withRouteParams(sessionId)
                .hasStatus(StatusReason.OK.code)
                .whenHandled();

        verify(user).retrieveSessionById(id);
    }

    @Test
    void testValidSession()
    {
        withStoredSession("Mozilla/5.0", 2);

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .hasStatus(StatusReason.OK.code)
                .hasContentType(SessionRetrieveActionImpl.MEDIA_TYPE_JSON)
                .hasBodyMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testMinimalSession()
    {
        withStoredSession(null, 0);

        assertThatRequestTo(newAction())
                .withRouteParams(SESSION_ID.toString())
                .hasStatus(StatusReason.OK.code)
                .hasBodyMatchingSnapshot()
                .whenHandled();
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
